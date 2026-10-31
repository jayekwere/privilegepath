import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";
import { analyze } from "../src/graph.js";

const sample = () => JSON.parse(readFileSync("samples/aws.json", "utf8"));
test("adversarial grant and exclusion globs finish under an external deadline", () => {
  for (const excluded of [false, true]) {
    const result = spawnSync(
      process.execPath,
      [
        "--import",
        "tsx",
        "--input-type=module",
        "-e",
        `
      import fs from 'node:fs'; import {analyze} from './src/graph.ts';
      const g=JSON.parse(fs.readFileSync('samples/aws.json','utf8'));
      const grant=g.edges.at(-1); const toxic='*a'.repeat(35)+'b';
      grant.actions=[${excluded ? '"*"' : "toxic"}];
      ${excluded ? "grant.constraints={excluded_actions:[toxic]};" : ""}
      g.query.action='a'.repeat(70)+'c'; const report=analyze(g);
      console.log(JSON.stringify({paths:report.paths.length,status:report.status,proof:report.effective_permissions.status}));
    `,
      ],
      { encoding: "utf8", timeout: 4000 },
    );
    assert.equal(result.error, undefined, String(result.error));
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), {
      paths: excluded ? 1 : 0,
      status: "analysis_complete",
      proof: "not_proven",
    });
  }
});
test("bounded matching preserves literal syntax, UTF-16 and provider case behavior", () => {
  const patterns = [
    "s3:Get*",
    "*",
    "?",
    "??",
    "a*b?",
    "a**b",
    "[ab]",
    "a.b",
    "(a)",
    "a\\*",
    "K",
    "k",
    "é",
    "Σ",
    "😀",
    "a\nb",
  ];
  const values = [
    "s3:GetObject",
    "S3:GETOBJECT",
    "a",
    "ab",
    "aabx",
    "[ab]",
    "a.b",
    "axb",
    "(a)",
    "a\\x",
    "K",
    "k",
    "K",
    "É",
    "ς",
    "😀",
    "a\nb",
    "a\n",
    "\r",
    "\u2028",
  ];
  for (const cloud of ["aws", "azure", "gcp"])
    for (const pattern of patterns)
      for (const value of values) {
        const graph = sample();
        graph.nodes.forEach((n: { cloud: string }) => {
          n.cloud = cloud;
        });
        graph.edges.at(-1).actions = [pattern];
        graph.query.action = value;
        const escaped = pattern
          .replace(/[.+^${}()|[\]\\]/g, "\\$&")
          .replace(/\*/g, ".*")
          .replace(/\?/g, ".");
        const expected = new RegExp(`^${escaped}$`, cloud === "gcp" ? "" : "i").test(value);
        assert.equal(
          analyze(graph).paths.length,
          expected ? 1 : 0,
          JSON.stringify({ cloud, pattern, value }),
        );
      }
});
test("matching work includes exclusions and exhaustion remains incomplete", () => {
  const graph = sample();
  graph.query.action = "z".repeat(256);
  graph.edges.at(-1).actions = ["*"];
  graph.edges.at(-1).constraints = { excluded_actions: Array(1000).fill("a".repeat(256)) };
  const result = analyze(graph);
  assert.equal(result.status, "incomplete");
  assert.equal(result.truncated, true);
  assert.equal(result.effective_permissions.status, "not_proven");
});
