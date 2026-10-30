import assert from "node:assert/strict";
import { test } from "node:test";
import { analyze, type Graph, graphSchema } from "../src/graph.js";
import { load } from "../src/io.js";

const sample = async (): Promise<Graph> => graphSchema.parse(await load("samples/aws.json"));
test("AWS, Azure and GCP evidence remains observed, never proven effective", async () => {
  for (const cloud of ["aws", "azure", "gcp"]) {
    const report = analyze(await load(`samples/${cloud}.json`));
    assert.ok(report.paths.length > 0);
    assert.equal(report.effective_permissions.status, "not_proven");
    assert.deepEqual(report.effective_permissions.proven, []);
    for (const path of report.paths) assert.equal(path.edge_ids.length, path.evidence.length);
  }
});
test("wildcards match actions but preserve unresolved conditions", async () => {
  const g = await sample();
  g.edges[g.edges.length - 1]!.actions = ["s3:Get*"];
  g.edges[g.edges.length - 1]!.conditions = "unresolved";
  assert.ok(analyze(g).paths.some((p) => p.unresolved.some((s) => s.includes("condition"))));
  g.query.action = "s3:DeleteBucket";
  assert.equal(analyze(g).paths.length, 0);
});
test("explicit deny appears as counterevidence", async () => {
  const g = await sample();
  g.edges[g.edges.length - 1]!.effect = "deny";
  assert.equal(analyze(g).paths[0]!.classification, "observed_deny");
  assert.equal(analyze(g).recommendations.length, 0);
});
test("tenant, duplicate id, dangling and cross-cloud edges reject", async () => {
  const mutations = [
    (g: Graph) => {
      g.nodes[0]!.tenant = "other";
    },
    (g: Graph) => {
      g.edges[0]!.tenant = "other";
    },
    (g: Graph) => {
      g.nodes.push(g.nodes[0]!);
    },
    (g: Graph) => {
      g.edges[0]!.to = "missing";
    },
    (g: Graph) => {
      g.nodes[1]!.cloud = "gcp";
    },
    (g: Graph) => {
      g.edges.push(g.edges[0]!);
    },
  ];
  for (const mutate of mutations) {
    const g = await sample();
    mutate(g);
    assert.throws(() => analyze(g));
  }
});
test("relationship semantics and query endpoints reject ambiguity", async () => {
  const a = await sample();
  a.edges[0]!.actions = ["*"];
  assert.throws(() => analyze(a));
  const b = await sample();
  b.query.principal = b.query.resource;
  assert.throws(() => analyze(b));
  const c = await sample();
  c.edges[c.edges.length - 1]!.actions = [];
  assert.throws(() => analyze(c));
});
test("cycles terminate, depth truncation is explicit", async () => {
  const g = await sample();
  g.edges.push({ ...g.edges[0]!, id: "cycle", from: g.edges[0]!.to, to: g.edges[0]!.to });
  assert.equal(analyze(g).status, "analysis_complete");
  g.query.max_depth = 1;
  assert.equal(analyze(g).status, "incomplete");
});
test("unknown schema properties and invalid bounds reject", async () => {
  const g = await sample();
  assert.throws(() => analyze({ ...g, proof: "effective" }));
  g.query.max_depth = 99;
  assert.throws(() => analyze(g));
});
