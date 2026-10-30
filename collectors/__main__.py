from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any

from collectors.core import AwsCli, Capture, CloudError, Rest, command_json, private_json
from collectors.providers import aws, azure, gcp


class AzureTokens:
    def __init__(self, directory: str, subscription: str):
        self.subscription = subscription
        self.tokens: dict[str, str] = {}
        info = command_json(
            ["az", "account", "show", "--subscription", subscription, "--output", "json"]
        )
        if (
            info.get("id", "").lower() != subscription.lower()
            or info.get("tenantId", "").lower() != directory.lower()
        ):
            raise CloudError(
                "Azure active credential context does not match the configured tenant and subscription"
            )

    def __call__(self, host: str) -> str:
        if host not in {"management.azure.com", "graph.microsoft.com"}:
            raise CloudError("Unexpected Azure token audience")
        if host not in self.tokens:
            resource = (
                "https://graph.microsoft.com/"
                if host == "graph.microsoft.com"
                else "https://management.azure.com/"
            )
            response = command_json(
                [
                    "az",
                    "account",
                    "get-access-token",
                    "--subscription",
                    self.subscription,
                    "--resource",
                    resource,
                    "--output",
                    "json",
                ]
            )
            self.tokens[host] = str(response["accessToken"])
        return self.tokens[host]


class GcpToken:
    def __init__(self, project: str):
        self.project, self.token = project, ""

    def __call__(self, host: str) -> str:
        if host not in {"cloudresourcemanager.googleapis.com", "iam.googleapis.com"}:
            raise CloudError("Unexpected GCP token audience")
        if not self.token:
            result = subprocess.run(
                ["gcloud", "auth", "print-access-token", "--project", self.project, "--quiet"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode or not result.stdout.strip() or len(result.stdout) > 16384:
                raise CloudError("GCP authentication failed")
            self.token = result.stdout.strip()
        return self.token


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Read-only live IAM collection with native evidence"
    )
    parser.add_argument("provider", choices=["aws", "azure", "gcp"])
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--principal", required=True)
    parser.add_argument("--action", required=True)
    parser.add_argument("--resource")
    parser.add_argument("--account")
    parser.add_argument("--profile")
    parser.add_argument("--subscription")
    parser.add_argument("--directory-tenant")
    parser.add_argument("--plane", choices=["control", "data"], default="control")
    parser.add_argument("--include-groups", action="store_true")
    parser.add_argument("--project")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[a-z0-9-]{1,64}", args.tenant):
        parser.error("Invalid application tenant")
    snapshot_path = args.out.with_name(args.out.stem + ".snapshot.json")
    if args.out.exists() or snapshot_path.exists():
        parser.error("Evidence paths already exist; use a new snapshot name")
    graph: dict[str, Any]
    if args.provider == "aws":
        if not args.account or not args.profile or not args.resource:
            parser.error("AWS requires --account, --profile and --resource")
        capture = Capture("aws", AwsCli(args.profile), source=snapshot_path.name)
        graph = aws(capture, args.tenant, args.account, args.principal, args.resource, args.action)
    elif args.provider == "azure":
        if not args.subscription or not args.directory_tenant or not args.resource:
            parser.error("Azure requires --directory-tenant, --subscription and --resource")
        capture = Capture(
            "azure",
            Rest(
                AzureTokens(args.directory_tenant, args.subscription),
                {"management.azure.com", "graph.microsoft.com"},
            ),
            source=snapshot_path.name,
        )
        graph = azure(
            capture,
            args.tenant,
            args.subscription,
            args.principal,
            args.resource,
            args.action,
            plane=args.plane,
            groups=args.include_groups,
        )
    else:
        if not args.project:
            parser.error("GCP requires --project")
        capture = Capture(
            "gcp",
            Rest(
                GcpToken(args.project),
                {"cloudresourcemanager.googleapis.com", "iam.googleapis.com"},
            ),
            source=snapshot_path.name,
        )
        graph = gcp(capture, args.tenant, args.project, args.principal, args.action)
    private_json(snapshot_path, capture.snapshot())
    private_json(args.out, graph)
    print(
        json.dumps(
            {
                "provider": args.provider,
                "status": graph["collection"]["status"],
                "api_calls": len(capture.calls),
                "nodes": len(graph["nodes"]),
                "edges": len(graph["edges"]),
                "issues": len(capture.issues),
                "evidence_mode": "private-files-0600",
            }
        )
    )

    if capture.issues:
        raise SystemExit(2)


if __name__ == "__main__":
    try:
        main()
    except (CloudError, OSError, KeyError, ValueError) as error:
        raise SystemExit(
            f"Collection failed: {type(error).__name__}. Check credentials and provider scope; no clean result is claimed."
        ) from None
