const element = <T extends HTMLElement>(id: string): T => {
  const e = document.getElementById(id);
  if (!e) throw new Error(id);
  return e as T;
};
const input = element<HTMLTextAreaElement>("input");
const decision = element("decision");
const findings = element("findings");
element("subtitle").textContent = "Follow a privilege path. Keep the proof boundary visible.";
element("description").textContent =
  "Explore observed grants and relationships across AWS, Azure, and GCP. Candidate paths retain their source evidence and unresolved authorization prerequisites.";
async function reset(): Promise<void> {
  const r = await fetch("/api/sample");
  input.value = JSON.stringify(await r.json(), null, 2);
}
element("reset").addEventListener("click", () => void reset());
element("evaluate").addEventListener("click", async () => {
  findings.replaceChildren();
  decision.textContent = "Evaluating...";
  try {
    const parsed: unknown = JSON.parse(input.value);
    const response = await fetch("/api/evaluate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(parsed),
    });
    const result = (await response.json()) as Record<string, unknown>;
    if (!response.ok) throw new Error(String(result.error));
    element("output").textContent = JSON.stringify(result, null, 2);
    drawGraph(parsed);
    decision.textContent = String(result.decision ?? result.status ?? "Analysis complete");
    decision.classList.toggle("bad", result.decision === "deny" || result.decision === "failure");
    const rows = (result.findings ?? result.paths ?? []) as Record<string, unknown>[];
    for (const row of rows) {
      const card = document.createElement("div");
      card.className = "evidence";
      const title = document.createElement("b");
      title.textContent = String(row.message ?? row.summary ?? row.rule ?? row.classification);
      const detail = document.createElement("small");
      detail.textContent = JSON.stringify(row, null, 2);
      card.append(title, detail);
      findings.append(card);
    }
  } catch (error) {
    decision.textContent = error instanceof Error ? error.message : "Evaluation failed";
    decision.classList.add("bad");
  }
});
void reset();

function drawGraph(value: unknown): void {
  const graph = value as {
    nodes: { id: string; label: string; kind: string }[];
    edges: { from: string; to: string; relation: string }[];
  };
  const svg = document.getElementById("graph");
  if (!svg) return;
  svg.replaceChildren();
  const make = (name: string) => document.createElementNS("http://www.w3.org/2000/svg", name);
  const shown = graph.nodes.slice(0, 5);
  const positions = new Map(shown.map((n, i) => [n.id, 40 + i * 110]));
  for (const edge of graph.edges) {
    const x1 = positions.get(edge.from),
      x2 = positions.get(edge.to);
    if (x1 === undefined || x2 === undefined) continue;
    const line = make("line");
    for (const [key, v] of Object.entries({
      x1,
      y1: 70,
      x2,
      y2: 70,
      stroke: "#94b4e5",
      "stroke-dasharray": "5 4",
    }))
      line.setAttribute(key, String(v));
    svg.append(line);
  }
  for (const node of shown) {
    const x = positions.get(node.id) ?? 0;
    const circle = make("circle");
    circle.setAttribute("cx", String(x));
    circle.setAttribute("cy", "70");
    circle.setAttribute("r", "23");
    circle.setAttribute("fill", node.kind === "resource" ? "#c7a9ff" : "#77e3c2");
    const label = make("text");
    label.setAttribute("x", String(x));
    label.setAttribute("y", "120");
    label.setAttribute("fill", "#dfe8f2");
    label.setAttribute("text-anchor", "middle");
    label.setAttribute("font-size", "11");
    label.textContent = node.label.slice(0, 20);
    svg.append(circle, label);
  }
}
