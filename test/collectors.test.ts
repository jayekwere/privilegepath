import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { analyze } from "../src/graph.js";

function native(provider: string) {
  return JSON.parse(
    execFileSync(
      "python3",
      [
        "-c",
        `import json; from collectors.fixtures import ${provider}_fixture; print(json.dumps(${provider}_fixture()[0]))`,
      ],
      { encoding: "utf8" },
    ),
  );
}
test("all native collector graphs satisfy the analysis schema and preserve incomplete scope", () => {
  for (const provider of ["aws", "azure", "gcp"]) {
    const graph = native(provider);
    const result = analyze(graph);
    assert.equal(result.effective_permissions.status, "not_proven");
    assert.equal(result.collection?.provider, provider);
    assert.ok(result.paths.length > 0);
  }
});
test("Azure NotActions subtract only that grant and data permissions require an explicit plane", () => {
  const graph = native("azure");
  graph.query.action = "Microsoft.Storage/storageAccounts/delete";
  assert.equal(analyze(graph).paths.length, 0);
  graph.query.action = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read";
  graph.query.plane = "data";
  assert.equal(analyze(graph).paths.length, 1);
  delete graph.query.plane;
  assert.throws(() => analyze(graph), /plane/i);
});

test("partial native collection has a nonzero CLI status and metadata cannot cross cloud boundaries", () => {
  const graph = native("gcp");
  assert.equal(analyze(graph).status, "incomplete");
  const directory = mkdtempSync(join(tmpdir(), "privilegepath-cli-"));
  try {
    const path = join(directory, "partial.json");
    writeFileSync(path, JSON.stringify(graph));
    const actual = spawnSync(
      process.execPath,
      ["--import", "tsx", "src/main.ts", "analyze", path],
      { encoding: "utf8" },
    );
    assert.equal(actual.status, 2, actual.stderr);
    assert.equal(JSON.parse(actual.stdout).status, "incomplete");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
  const mixed = native("aws");
  mixed.collection.provider = "azure";
  assert.throws(() => analyze(mixed), /provider/);
});
