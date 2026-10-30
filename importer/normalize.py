"""Normalize explicit offline provider exports. No cloud credentials are accepted."""
import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any


def normalize(document: dict[str, Any]) -> dict[str, Any]:
    if set(document) != {"schema_version", "tenant", "cloud", "collected_at", "principals", "resources", "records", "query"} or document["schema_version"] != "1.0":
        raise ValueError("Invalid export envelope")
    cloud = document["cloud"]
    if cloud not in {"aws", "azure", "gcp"}:
        raise ValueError("Unsupported cloud")
    if datetime.fromisoformat(document["collected_at"].replace("Z", "+00:00")).tzinfo is None:
        raise ValueError("Timezone required")
    tenant = document["tenant"]
    nodes = [{**p, "cloud": cloud, "tenant": tenant} for p in document["principals"] + document["resources"]]
    edges: list[dict[str, Any]] = []
    for index, record in enumerate(document["records"]):
        evidence = {"source": f"offline-{cloud}-export", "pointer": f"/records/{index}", "collected_at": document["collected_at"], "sha256": hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()}
        if cloud == "aws":
            if set(record) != {"principal", "resource", "Statement"}:
                raise ValueError("Unsupported AWS record")
            for statement in record["Statement"]:
                if set(statement) - {"Sid", "Action", "Effect", "Condition"} or not {"Action", "Effect"} <= set(statement):
                    raise ValueError("Unsupported AWS statement: do not silently drop constraints")
                actions = statement["Action"] if isinstance(statement["Action"], list) else [statement["Action"]]
                if statement["Effect"] not in {"Allow", "Deny"}:
                    raise ValueError("Invalid AWS effect")
                edges.append({"id": f"e-{len(edges)}", "tenant": tenant, "from": record["principal"], "to": record["resource"], "relation": "grant", "actions": actions, "effect": statement["Effect"].lower(), "conditions": "unresolved" if "Condition" in statement else "none", "evidence": evidence})
        else:
            required = {"principalId", "resourceId", "actions", "condition"} if cloud == "azure" else {"member", "resource", "permissions", "condition"}
            if set(record) != required:
                raise ValueError("Unsupported role export: explicit resolved actions and scope required")
            edges.append({"id": f"e-{len(edges)}", "tenant": tenant, "from": record["principalId" if cloud == "azure" else "member"], "to": record["resourceId" if cloud == "azure" else "resource"], "relation": "grant", "actions": record["actions" if cloud == "azure" else "permissions"], "effect": "allow", "conditions": "unresolved" if record["condition"] else "none", "evidence": evidence})
    return {"schema_version": "1.0", "tenant": tenant, "nodes": nodes, "edges": edges, "query": document["query"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    text = args.source.read_text()
    if len(text.encode()) > 1_048_576:
        raise ValueError("Input too large")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(normalize(json.loads(text)), indent=2) + "\n")
