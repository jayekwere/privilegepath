from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

Json = dict[str, Any]
Call = Callable[[str, str, Json], Json]


class CloudError(RuntimeError):
    pass


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def command_json(arguments: list[str]) -> Json:
    result = subprocess.run(arguments, capture_output=True, timeout=45, check=False)
    if result.returncode != 0:
        raise CloudError(f"Credential or provider command failed (exit {result.returncode})")
    if len(result.stdout) > 8_388_608:
        raise CloudError("Provider response exceeds 8 MiB")
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise CloudError("Provider did not return a JSON object")
    return value


class AwsCli:
    def __init__(self, profile: str):
        self.profile = profile

    def __call__(self, service: str, operation: str, parameters: Json) -> Json:
        allowed = {
            ("sts", "get-caller-identity"),
            ("iam", "get-account-authorization-details"),
            ("iam", "get-policy"),
            ("iam", "get-policy-version"),
        }
        if (service, operation) not in allowed:
            raise CloudError("Collector operation is not read-only allowlisted")
        endpoint = (
            "https://iam.amazonaws.com"
            if service == "iam"
            else "https://sts.us-east-1.amazonaws.com"
        )
        return command_json(
            [
                "aws",
                service,
                operation,
                "--profile",
                self.profile,
                "--region",
                "us-east-1",
                "--endpoint-url",
                endpoint,
                "--cli-input-json",
                canonical(parameters),
                "--no-paginate",
                "--output",
                "json",
                "--no-cli-pager",
                "--no-cli-auto-prompt",
            ]
        )


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


class Rest:
    def __init__(self, tokens: Callable[[str], str], allowed_hosts: set[str]):
        self.tokens = tokens
        self.allowed_hosts = allowed_hosts
        self.opener = urllib.request.build_opener(NoRedirect())

    def __call__(self, method: str, url: str, payload: Json) -> Json:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in self.allowed_hosts
            or parsed.port not in {None, 443}
            or parsed.username
            or parsed.password
            or parsed.fragment
        ):
            raise CloudError("Provider URL is outside the configured HTTPS authority")
        if method != "GET" and not (method == "POST" and parsed.path.endswith(":getIamPolicy")):
            raise CloudError("Collector HTTP operation is not read-only allowlisted")
        request = urllib.request.Request(
            url,
            method=method,
            data=canonical(payload).encode() if method == "POST" else None,
            headers={
                "Authorization": f"Bearer {self.tokens(parsed.hostname)}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        try:
            with self.opener.open(request, timeout=20) as response:
                data = response.read(8_388_609)
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
            raise CloudError(f"Provider HTTP {status}") from None
        if len(data) > 8_388_608:
            raise CloudError("Provider response exceeds 8 MiB")
        value = json.loads(data)
        if not isinstance(value, dict):
            raise CloudError("Provider did not return a JSON object")
        return value


class Capture:
    def __init__(
        self, provider: str, call: Call, *, source: str = "snapshot.json", at: str | None = None
    ):
        self.provider = provider
        self.call = call
        self.at = at or now()
        self.source = source
        self.calls: list[Json] = []
        self.observations: list[Json] = []
        self.issues: list[str] = []
        self.bytes = 0

    def request(self, method: str, target: str, payload: Json | None = None) -> tuple[Json, int]:
        if len(self.calls) >= 200:
            raise CloudError("Collection exceeds 200 provider requests")
        parameters = payload or {}
        try:
            response = self.call(method, target, parameters)
        except CloudError as error:
            self.calls.append(
                {
                    "method": method,
                    "target": target,
                    "parameters": parameters,
                    "observed_at": self.at,
                    "error": str(error),
                }
            )
            raise
        self.bytes += len(canonical(response).encode())
        if self.bytes > 67_108_864:
            raise CloudError("Collection exceeds 64 MiB")
        index = len(self.calls)
        self.calls.append(
            {
                "method": method,
                "target": target,
                "parameters": parameters,
                "observed_at": self.at,
                "response": response,
            }
        )
        return response, index

    def issue(self, message: str) -> None:
        if message not in self.issues:
            if len(self.issues) >= 1000:
                raise CloudError("Too many collection issues")
            self.issues.append(message[:512])

    def observe(self, call: int, pointer: str, value: Json) -> Json:
        observation = {"call": call, "source_pointer": pointer, "value": value}
        self.bytes += len(canonical(observation).encode())
        if len(self.observations) >= 20000 or self.bytes > 67_108_864:
            raise CloudError("Evidence observation bound exceeded")
        index = len(self.observations)
        self.observations.append(observation)
        return {
            "source": self.source,
            "pointer": f"/observations/{index}",
            "collected_at": self.at,
            "sha256": sha(observation),
        }

    def snapshot(self) -> Json:
        return {
            "schema_version": "1.0",
            "provider": self.provider,
            "collected_at": self.at,
            "calls": self.calls,
            "observations": self.observations,
            "issues": self.issues,
        }


class Graph:
    def __init__(self, tenant: str, cloud: str, capture: Capture):
        self.tenant, self.cloud, self.capture = tenant, cloud, capture
        self.nodes: dict[str, Json] = {}
        self.edges: list[Json] = []

    def node(self, identifier: str, kind: str, label: str) -> str:
        if not identifier or len(identifier) > 2048:
            raise CloudError("Invalid cloud identity length")
        record = {
            "id": identifier,
            "tenant": self.tenant,
            "cloud": self.cloud,
            "kind": kind,
            "label": label[:256] or identifier[:256],
        }
        existing = self.nodes.get(identifier)
        if existing and existing["kind"] != kind:
            raise CloudError("Conflicting cloud identity kinds")
        if identifier not in self.nodes and len(self.nodes) >= 5000:
            raise CloudError("Graph exceeds 5000 nodes")
        self.nodes[identifier] = record
        return identifier

    def edge(
        self,
        source: str,
        target: str,
        relation: str,
        evidence: Json,
        *,
        actions: list[str] | None = None,
        effect: str = "allow",
        conditional: bool = False,
        constraints: Json | None = None,
    ) -> None:
        actions = actions or []
        if relation == "grant" and (
            not actions
            or not all(isinstance(action, str) and 0 < len(action) <= 256 for action in actions)
        ):
            raise CloudError("Invalid provider grant actions")
        for offset in range(0, max(1, len(actions)), 1000):
            if len(self.edges) >= 20000:
                raise CloudError("Graph exceeds 20000 edges")
            record: Json = {
                "id": f"edge-{len(self.edges)}",
                "tenant": self.tenant,
                "from": source,
                "to": target,
                "relation": relation,
                "effect": effect,
                "actions": actions[offset : offset + 1000],
                "conditions": "unresolved" if conditional else "none",
                "evidence": evidence,
            }
            if constraints:
                record["constraints"] = constraints
            self.edges.append(record)

    def finish(
        self, principal: str, resource: str, action: str, scope: str, *, plane: str | None = None
    ) -> Json:
        if principal not in self.nodes:
            raise CloudError("Selected principal is absent from the collected scope")
        query: Json = {
            "principal": principal,
            "resource": resource,
            "action": action,
            "max_depth": 5,
        }
        if plane:
            query["plane"] = plane
        return {
            "schema_version": "1.0",
            "tenant": self.tenant,
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
            "query": query,
            "collection": {
                "provider": self.cloud,
                "scope": scope,
                "collected_at": self.capture.at,
                "status": "partial" if self.capture.issues else "complete",
                "issues": self.capture.issues,
                "snapshot_sha256": sha(self.capture.snapshot()),
                "api_calls": len(self.capture.calls),
            },
        }


def private_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        raise CloudError("Evidence output already exists; choose a new snapshot path")
    descriptor, staging = tempfile.mkstemp(prefix=".snapshot-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as output:
            output.write(json.dumps(value, indent=2, allow_nan=False) + "\n")
        os.link(staging, path)
    finally:
        os.unlink(staging)
