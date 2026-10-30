import { analyze } from "./graph.js";
import { load, serve } from "./io.js";

async function main(): Promise<void> {
  const command = process.argv[2] ?? "serve";
  if (command === "serve") {
    await serve("PrivilegePath", await load("samples/aws.json"), async (i) => analyze(i));
    return;
  }
  if (!["demo", "analyze"].includes(command))
    throw new Error("Usage: privilegepath analyze GRAPH.json | demo | serve");
  const result = analyze(
    await load(command === "demo" ? "samples/aws.json" : (process.argv[3] ?? "")),
  );
  console.log(JSON.stringify(result, null, 2));
  if (result.status === "incomplete") process.exitCode = 2;
}
main().catch((error) => {
  console.error(error instanceof Error ? error.message : "Analysis failed");
  process.exitCode = 2;
});
