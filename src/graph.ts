import { z } from "zod";
import { digest } from "./io.js";

const id = z.string().min(1).max(2048);
const evidence = z
  .object({
    source: z.string().min(1).max(512),
    pointer: z.string().min(1).max(512),
    collected_at: z.iso.datetime(),
    sha256: z.string().regex(/^[a-f0-9]{64}$/),
  })
  .strict();
const node = z
  .object({
    id,
    tenant: id,
    cloud: z.enum(["aws", "azure", "gcp"]),
    kind: z.enum(["identity", "group", "role", "resource"]),
    label: z.string().min(1).max(256),
  })
  .strict();
const edge = z
  .object({
    id,
    tenant: id,
    from: id,
    to: id,
    relation: z.enum(["member_of", "can_assume", "grant"]),
    effect: z.enum(["allow", "deny"]).default("allow"),
    actions: z.array(z.string().min(1).max(256)).max(1000).default([]),
    conditions: z.enum(["none", "unresolved"]).default("none"),
    constraints: z
      .object({
        resource_patterns: z.array(z.string().max(2048)).max(1000).optional(),
        excluded_actions: z.array(z.string().max(256)).max(1000).optional(),
        plane: z.enum(["control", "data"]).optional(),
      })
      .strict()
      .optional(),
    evidence,
  })
  .strict();
export const graphSchema = z
  .object({
    schema_version: z.literal("1.0"),
    tenant: id,
    nodes: z.array(node).max(5000),
    edges: z.array(edge).max(20000),
    collection: z
      .object({
        provider: z.enum(["aws", "azure", "gcp"]),
        scope: z.string().max(4096),
        collected_at: z.iso.datetime(),
        status: z.enum(["complete", "partial"]),
        issues: z.array(z.string().max(512)).max(1000),
        snapshot_sha256: z.string().regex(/^[a-f0-9]{64}$/),
        api_calls: z.number().int().nonnegative().max(200),
      })
      .strict()
      .optional(),
    query: z
      .object({
        principal: id,
        resource: id,
        action: z.string().min(1).max(256),
        plane: z.enum(["control", "data"]).optional(),
        max_depth: z.number().int().min(1).max(8).default(5),
      })
      .strict(),
  })
  .strict();
export type Graph = z.infer<typeof graphSchema>;
type Edge = z.infer<typeof edge>;

function matches(pattern: string, action: string, cloud: string): boolean {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`, cloud === "gcp" ? "" : "i").test(action);
}

export function analyze(value: unknown) {
  const graph = graphSchema.parse(value);
  const nodes = new Map(graph.nodes.map((n) => [n.id, n]));
  if (nodes.size !== graph.nodes.length) throw new Error("Duplicate node id");
  if (
    graph.nodes.some((n) => n.tenant !== graph.tenant) ||
    graph.edges.some((e) => e.tenant !== graph.tenant)
  )
    throw new Error("Cross-tenant graph");
  const principal = nodes.get(graph.query.principal);
  const target = nodes.get(graph.query.resource);
  if (
    !principal ||
    !target ||
    !["identity", "role"].includes(principal.kind) ||
    target.kind !== "resource" ||
    principal.cloud !== target.cloud
  )
    throw new Error("Invalid query endpoints");
  const ids = new Set<string>();
  const outgoing = new Map<string, Edge[]>();
  for (const e of graph.edges) {
    const from = nodes.get(e.from);
    const to = nodes.get(e.to);
    if (ids.has(e.id) || !from || !to || from.cloud !== to.cloud)
      throw new Error("Invalid edge identity or cloud boundary");
    ids.add(e.id);
    if (e.relation === "grant") {
      if (to.kind !== "resource" || from.kind === "resource" || !e.actions.length)
        throw new Error("Grant endpoints or actions invalid");
    } else {
      if (
        e.actions.length ||
        e.effect !== "allow" ||
        from.kind === "resource" ||
        !(e.relation === "member_of" ? to.kind === "group" : to.kind === "role")
      )
        throw new Error("Invalid relationship semantics");
    }
    outgoing.set(e.from, [...(outgoing.get(e.from) ?? []), e]);
  }
  const queue: { at: string; edges: Edge[]; visited: Set<string> }[] = [
    { at: principal.id, edges: [], visited: new Set([principal.id]) },
  ];
  const paths: {
    classification: string;
    summary: string;
    edge_ids: string[];
    evidence: z.infer<typeof evidence>[];
    unresolved: string[];
  }[] = [];
  let traversed = 0;
  let cost = 0;
  let truncated = false;
  while (queue.length) {
    const state = queue.shift();
    if (!state) break;
    if (++traversed > 10000) {
      truncated = true;
      break;
    }
    for (const e of outgoing.get(state.at) ?? []) {
      cost += Math.max(1, e.actions.length);
      if (cost > 50000 || paths.length >= 1000 || queue.length >= 10000) {
        truncated = true;
        queue.length = 0;
        break;
      }
      const next = [...state.edges, e];
      if (e.relation === "grant") {
        if (e.constraints?.plane && graph.query.plane === undefined)
          throw new Error("Azure permission plane must be explicit");
        if (e.constraints?.plane && e.constraints.plane !== graph.query.plane) continue;
        if (
          e.constraints?.excluded_actions?.some((pattern) =>
            matches(pattern, graph.query.action, principal.cloud),
          )
        )
          continue;
        if (
          e.to !== target.id ||
          !e.actions.some((a) => matches(a, graph.query.action, principal.cloud))
        )
          continue;
        const unresolved = [
          "Provider authorization was not evaluated",
          ...next
            .filter((x) => x.conditions === "unresolved")
            .map((x) => `Unresolved condition on ${x.id}`),
          ...next
            .filter((x) => x.relation === "can_assume")
            .map((x) => `Role trust and session constraints unverified on ${x.id}`),
        ];
        paths.push({
          classification: e.effect === "deny" ? "observed_deny" : "candidate_grant_path",
          summary: `${principal.label}: observed ${e.effect} for ${graph.query.action}`,
          edge_ids: next.map((x) => x.id),
          evidence: next.map((x) => x.evidence),
          unresolved,
        });
      } else if (!state.visited.has(e.to)) {
        if (next.length >= graph.query.max_depth) {
          truncated = true;
          continue;
        }
        queue.push({ at: e.to, edges: next, visited: new Set([...state.visited, e.to]) });
      }
    }
  }
  paths.sort((a, b) => a.edge_ids.join(":").localeCompare(b.edge_ids.join(":")));
  const recommendations = paths
    .filter((p) => p.classification === "candidate_grant_path")
    .map((p) => ({
      edge_ids: p.edge_ids,
      proposal: graph.edges
        .find((e) => e.id === p.edge_ids.at(-1))
        ?.actions.some((a) => /[?*]/.test(a))
        ? "The evidenced terminal grant has a wildcard. Ask the owner for required actions and simulate an explicit replacement before a staged change. This query alone is insufficient for a replacement policy."
        : "The evidenced terminal grant is explicit. This snapshot supplies no usage evidence that justifies removing it. Validate its scope and owner need.",
      evidence: p.evidence,
      automatic_removal_safe: false,
    }));
  return {
    schema_version: "1.0",
    status:
      truncated || graph.collection?.status === "partial" ? "incomplete" : "analysis_complete",
    collection: graph.collection,
    tenant: graph.tenant,
    query: graph.query,
    graph_sha256: digest(JSON.stringify(graph)),
    paths,
    recommendations,
    effective_permissions: {
      status: "not_proven",
      proven: [],
      reason:
        "Observed grant relationships do not establish effective access. Provider denies, boundaries, trust, conditions, sessions, hierarchy and resource policies require provider-specific evaluation.",
    },
    traversed_states: traversed,
    truncated,
  };
}
