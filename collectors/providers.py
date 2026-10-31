from __future__ import annotations

import fnmatch
import json
import re
from typing import Any
from urllib.parse import unquote, urlsplit

from collectors.core import Capture, CloudError, Graph, Json


def iam_matches(value: str, pattern: str) -> bool:
    """IAM wildcards are * and ?; brackets are literal resource characters."""
    return fnmatch.fnmatchcase(value, pattern.replace("[", "[[]"))


def strings(value: Any) -> list[str]:
    result = [value] if isinstance(value, str) else value
    if (
        not isinstance(result, list)
        or not result
        or not all(isinstance(item, str) and item and len(item) <= 2048 for item in result)
    ):
        raise CloudError("Invalid provider string collection")
    return list(result)


def policy_document(value: Any) -> Json:
    if isinstance(value, str):
        value = json.loads(unquote(value))
    if not isinstance(value, dict):
        raise CloudError("Invalid policy document")
    return value


def aws(
    capture: Capture, tenant: str, account: str, principal: str, resource: str, action: str
) -> Json:
    if not re.fullmatch(r"\d{12}", account) or not principal.startswith(f"arn:aws:iam::{account}:"):
        raise CloudError("An explicit commercial AWS account and IAM principal ARN are required")
    identity, _ = capture.request("sts", "get-caller-identity")
    if identity.get("Account") != account or not str(identity.get("Arn", "")).startswith(
        "arn:aws:"
    ):
        raise CloudError("AWS caller account does not match the configured account")
    graph = Graph(tenant, "aws", capture)
    target = graph.node(f"resource:{resource}", "resource", resource)
    entities: list[tuple[Json, str, int, str]] = []
    policies: dict[str, tuple[Json, int, str]] = {}
    marker: str | None = None
    seen: set[str] = set()
    while True:
        parameters: Json = {
            "Filter": ["User", "Role", "Group", "LocalManagedPolicy"],
            "MaxItems": 100,
        }
        if marker:
            parameters["Marker"] = marker
        page, call = capture.request("iam", "get-account-authorization-details", parameters)
        for key, kind in [
            ("UserDetailList", "identity"),
            ("RoleDetailList", "role"),
            ("GroupDetailList", "group"),
        ]:
            for index, entity in enumerate(page.get(key, [])):
                arn = entity.get("Arn", "")
                if not isinstance(arn, str) or not arn.startswith(f"arn:aws:iam::{account}:"):
                    raise CloudError("IAM inventory contains an unexpected account")
                identifier = graph.node(
                    f"principal:{arn}",
                    kind,
                    entity.get(
                        {"identity": "UserName", "role": "RoleName", "group": "GroupName"}[kind],
                        arn,
                    ),
                )
                entities.append((entity, identifier, call, f"/calls/{call}/response/{key}/{index}"))
        for index, item in enumerate(page.get("Policies", [])):
            policies[item["Arn"]] = (item, call, f"/calls/{call}/response/Policies/{index}")
        if page.get("IsTruncated") is False:
            break
        marker = page.get("Marker")
        if (
            page.get("IsTruncated") is not True
            or not isinstance(marker, str)
            or not marker
            or marker in seen
        ):
            capture.issue("AWS pagination is incomplete or repeats a marker")
            break
        seen.add(marker)
    groups = {
        entity["GroupName"]: identifier
        for entity, identifier, _, _ in entities
        if "GroupName" in entity
    }
    roles = {
        entity["Arn"]: identifier for entity, identifier, _, _ in entities if "RoleName" in entity
    }

    def statements(owner: str, raw: Any, call: int, pointer: str) -> None:
        try:
            document = policy_document(raw)
            items = document.get("Statement", [])
            items = [items] if isinstance(items, dict) else items
            if not isinstance(items, list):
                raise CloudError("Invalid statements")
            for statement in items:
                if (
                    not isinstance(statement, dict)
                    or statement.get("Effect") not in {"Allow", "Deny"}
                    or set(statement) - {"Sid", "Effect", "Action", "Resource", "Condition"}
                ):
                    capture.issue(
                        "AWS identity policy has an unsupported construct, including NotAction or NotResource"
                    )
                    continue
                actions, resources = (
                    strings(statement.get("Action")),
                    strings(statement.get("Resource")),
                )
                if any("${" in pattern for pattern in resources):
                    capture.issue(
                        "AWS resource policy variables require context and were not projected"
                    )
                    continue
                evidence = capture.observe(
                    call,
                    pointer,
                    {
                        "owner": owner,
                        "statement": statement,
                        "normalization": "IAM document decoded before statement projection",
                    },
                )
                constraints = {"resource_patterns": resources}
                conditional = bool(statement.get("Condition"))
                if any(iam_matches(resource, pattern) for pattern in resources):
                    graph.edge(
                        owner,
                        target,
                        "grant",
                        evidence,
                        actions=actions,
                        effect=statement["Effect"].lower(),
                        conditional=conditional,
                        constraints=constraints,
                    )
                if statement["Effect"] == "Allow" and any(
                    iam_matches("sts:assumerole", pattern.lower()) for pattern in actions
                ):
                    for role_arn, role_id in roles.items():
                        if any(iam_matches(role_arn, pattern) for pattern in resources):
                            graph.edge(
                                owner,
                                role_id,
                                "can_assume",
                                evidence,
                                conditional=True,
                                constraints=constraints,
                            )
        except (CloudError, ValueError, TypeError):
            capture.issue("AWS policy document could not be projected without losing semantics")

    for entity, owner, call, pointer in entities:
        if "UserName" in entity:
            for index, group in enumerate(entity.get("GroupList", [])):
                if group not in groups:
                    capture.issue("AWS group membership references a missing inventory group")
                    continue
                evidence = capture.observe(
                    call, f"{pointer}/GroupList/{index}", {"member": entity["Arn"], "group": group}
                )
                graph.edge(owner, groups[group], "member_of", evidence)
        for key in ["UserPolicyList", "RolePolicyList", "GroupPolicyList"]:
            for index, inline in enumerate(entity.get(key, [])):
                statements(
                    owner,
                    inline.get("PolicyDocument"),
                    call,
                    f"{pointer}/{key}/{index}/PolicyDocument",
                )
        for attachment in entity.get("AttachedManagedPolicies", []):
            arn = attachment.get("PolicyArn", "")
            if not isinstance(arn, str) or not (
                arn.startswith(f"arn:aws:iam::{account}:policy/")
                or arn.startswith("arn:aws:iam::aws:policy/")
            ):
                capture.issue(
                    "AWS managed policy reference is outside the configured account or AWS-managed namespace"
                )
                continue
            try:
                if arn not in policies:
                    metadata, _ = capture.request("iam", "get-policy", {"PolicyArn": arn})
                    if metadata["Policy"].get("Arn") != arn:
                        raise CloudError("Managed policy identity mismatch")
                    version = metadata["Policy"]["DefaultVersionId"]
                    response, version_call = capture.request(
                        "iam", "get-policy-version", {"PolicyArn": arn, "VersionId": version}
                    )
                    if response["PolicyVersion"].get("VersionId") != version:
                        raise CloudError("Managed policy version mismatch")
                    policies[arn] = (
                        {
                            "DefaultVersionId": version,
                            "PolicyVersionList": [
                                {**response["PolicyVersion"], "VersionId": version}
                            ],
                        },
                        version_call,
                        f"/calls/{version_call}/response/PolicyVersion",
                    )
                policy, version_call, version_pointer = policies[arn]
                versions = [
                    version
                    for version in policy.get("PolicyVersionList", [])
                    if version.get("VersionId") == policy.get("DefaultVersionId")
                ]
                if len(versions) != 1:
                    raise CloudError("Default policy version is missing or ambiguous")
                statements(owner, versions[0]["Document"], version_call, version_pointer)
            except (CloudError, KeyError, TypeError):
                capture.issue("An attached AWS managed policy version could not be collected")
    return graph.finish(
        f"principal:{principal}",
        target,
        action,
        f"IAM identity grants in account {account}, projected to {resource}; role trust, resource policies, SCPs, boundaries and sessions remain unevaluated",
    )


def rest_pages(
    capture: Capture,
    url: str,
    *,
    key: str = "value",
    next_key: str = "nextLink",
    allowed_prefix: str,
) -> list[tuple[Json, int, int]]:
    records: list[tuple[Json, int, int]] = []
    seen: set[str] = set()
    expected = urlsplit(url)
    while url:
        parsed = urlsplit(url)
        if (
            url in seen
            or parsed.scheme != "https"
            or parsed.netloc != expected.netloc
            or not parsed.path.lower().startswith(allowed_prefix.lower())
        ):
            raise CloudError("Pagination URL escapes the configured provider scope or repeats")
        seen.add(url)
        response, call = capture.request("GET", url)
        if not isinstance(response.get(key), list):
            raise CloudError("Provider list response is missing its result collection")
        for index, record in enumerate(response[key]):
            if not isinstance(record, dict):
                raise CloudError("Invalid provider list item")
            records.append((record, call, index))
        url = response.get(next_key, "")
        if not isinstance(url, str):
            raise CloudError("Invalid pagination link")
    return records


def azure(
    capture: Capture,
    tenant: str,
    subscription: str,
    principal: str,
    resource: str,
    action: str,
    *,
    plane: str = "control",
    groups: bool = False,
) -> Json:
    if (
        not re.fullmatch(r"[a-fA-F0-9-]{36}", subscription)
        or not re.fullmatch(r"[a-fA-F0-9-]{36}", principal)
        or plane not in {"control", "data"}
    ):
        raise CloudError(
            "Explicit Azure subscription, principal object ID and permission plane are required"
        )
    prefix = f"/subscriptions/{subscription}"
    if resource.lower() != prefix.lower() and not resource.lower().startswith(prefix.lower() + "/"):
        raise CloudError("Azure target resource escapes the configured subscription")
    subscription_info, _ = capture.request(
        "GET", f"https://management.azure.com{prefix}?api-version=2022-12-01"
    )
    if subscription_info.get("subscriptionId", "").lower() != subscription.lower():
        raise CloudError("Azure subscription identity mismatch")
    graph = Graph(tenant, "azure", capture)
    selected = graph.node(f"principal:{principal}", "identity", principal)
    target = graph.node(f"resource:{resource}", "resource", resource)
    assignments = rest_pages(
        capture,
        f"https://management.azure.com{resource}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&%24filter=atScope%28%29",
        allowed_prefix=prefix,
    )
    definitions: dict[str, tuple[Json, int]] = {}
    group_ids: set[str] = set()
    for assignment, call, index in assignments:
        properties = assignment["properties"]
        scope = properties["scope"]
        if not (
            resource.lower() == scope.lower()
            or resource.lower().startswith(scope.lower().rstrip("/") + "/")
        ):
            continue
        principal_id, role_id = properties["principalId"], properties["roleDefinitionId"]
        if not re.fullmatch(r"[a-fA-F0-9-]{36}", principal_id):
            raise CloudError("Invalid Azure principal object ID")
        kind = "group" if properties.get("principalType") == "Group" else "identity"
        owner = graph.node(f"principal:{principal_id}", kind, principal_id)
        if kind == "group":
            group_ids.add(principal_id)
        if not isinstance(role_id, str) or not re.fullmatch(
            r"(?:/subscriptions/[a-fA-F0-9-]{36})?/providers/Microsoft.Authorization/roleDefinitions/[a-fA-F0-9-]{36}",
            role_id,
            flags=re.IGNORECASE,
        ):
            capture.issue("Azure role definition scope is unsupported")
            continue
        if role_id.lower().startswith("/subscriptions/") and not role_id.lower().startswith(
            prefix.lower() + "/"
        ):
            capture.issue("Azure role definition references another subscription")
            continue
        try:
            if role_id not in definitions:
                definitions[role_id] = capture.request(
                    "GET", f"https://management.azure.com{role_id}?api-version=2022-04-01"
                )
            definition, definition_call = definitions[role_id]
            for permission in definition["properties"]["permissions"]:
                for permission_plane, allowed, excluded in [
                    ("control", "actions", "notActions"),
                    ("data", "dataActions", "notDataActions"),
                ]:
                    actions = permission.get(allowed, [])
                    exclusions = permission.get(excluded, [])
                    if not actions:
                        continue
                    evidence = capture.observe(
                        call,
                        f"/calls/{call}/response/value/{index}",
                        {
                            "assignment": assignment,
                            "definition_call": definition_call,
                            "permission": permission,
                            "plane": permission_plane,
                        },
                    )
                    graph.edge(
                        owner,
                        target,
                        "grant",
                        evidence,
                        actions=strings(actions),
                        conditional=bool(properties.get("condition")),
                        constraints={"plane": permission_plane, "excluded_actions": exclusions},
                    )
        except (CloudError, KeyError, TypeError):
            capture.issue("An Azure role definition could not be fully collected")
    for group_id in sorted(group_ids):
        if not groups:
            capture.issue("Azure directory group membership was not collected")
            continue
        try:
            members = rest_pages(
                capture,
                f"https://graph.microsoft.com/v1.0/groups/{group_id}/transitiveMembers?%24select=id",
                next_key="@odata.nextLink",
                allowed_prefix=f"/v1.0/groups/{group_id}/",
            )
            for member, call, index in members:
                member_id = member.get("id", "")
                if not re.fullmatch(r"[a-fA-F0-9-]{36}", member_id) or member_id == group_id:
                    continue
                kind = (
                    "group" if member.get("@odata.type") == "#microsoft.graph.group" else "identity"
                )
                member_node = graph.node(f"principal:{member_id}", kind, member_id)
                evidence = capture.observe(call, f"/calls/{call}/response/value/{index}", member)
                graph.edge(member_node, f"principal:{group_id}", "member_of", evidence)
        except CloudError:
            capture.issue("Azure transitive group membership was incomplete or unavailable")
    return graph.finish(
        selected,
        target,
        action,
        f"Azure inherited and direct RBAC assignments applicable to {resource}; deny assignments, PIM and effective authorization remain unevaluated",
        plane=plane,
    )


def gcp(
    capture: Capture,
    tenant: str,
    project: str,
    principal: str,
    action: str,
    *,
    ancestors: bool = True,
) -> Json:
    if not re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", project) or not re.fullmatch(
        r"(?:user|serviceAccount):[^\s/]+@[^\s/]+", principal
    ):
        raise CloudError("Explicit GCP project ID and user/serviceAccount member are required")
    info, _ = capture.request(
        "GET", f"https://cloudresourcemanager.googleapis.com/v3/projects/{project}"
    )
    if info.get("projectId") != project or not re.fullmatch(r"projects/\d+", info.get("name", "")):
        raise CloudError("GCP project identity mismatch")
    graph = Graph(tenant, "gcp", capture)
    selected = graph.node(f"principal:{principal}", "identity", principal)
    target = graph.node(
        f"resource://cloudresourcemanager.googleapis.com/{info['name']}", "resource", project
    )
    scopes: list[str] = [info["name"]]
    parent = info.get("parent")
    visited: set[str] = set()
    while parent:
        if not ancestors:
            capture.issue("GCP ancestor IAM policies were not collected")
            break
        if (
            not isinstance(parent, str)
            or not re.fullmatch(r"(?:folders|organizations)/\d+", parent)
            or parent in visited
            or len(visited) >= 20
        ):
            capture.issue("GCP project ancestry is invalid, cyclic or exceeds its bound")
            break
        visited.add(parent)
        scopes.append(parent)
        try:
            metadata, _ = capture.request(
                "GET", f"https://cloudresourcemanager.googleapis.com/v3/{parent}"
            )
            parent = metadata.get("parent")
        except CloudError:
            capture.issue("GCP ancestor metadata could not be collected")
            break
    roles: dict[str, tuple[Json, int]] = {}
    for scope in scopes:
        try:
            policy, call = capture.request(
                "POST",
                f"https://cloudresourcemanager.googleapis.com/v3/{scope}:getIamPolicy",
                {"options": {"requestedPolicyVersion": 3}},
            )
            if policy.get("version", 1) not in {1, 3}:
                raise CloudError("Unsupported GCP IAM policy version")
            for index, binding in enumerate(policy.get("bindings", [])):
                role = binding.get("role", "")
                if not re.fullmatch(
                    r"(?:roles/[A-Za-z0-9_.]+|projects/[a-z0-9-]+/roles/[A-Za-z0-9_.]+|organizations/\d+/roles/[A-Za-z0-9_.]+)",
                    role,
                ):
                    capture.issue("Unsupported GCP role name")
                    continue
                try:
                    if role not in roles:
                        roles[role] = capture.request(
                            "GET", f"https://iam.googleapis.com/v1/{role}"
                        )
                    definition, definition_call = roles[role]
                    if (
                        definition.get("deleted")
                        or definition.get("name") != role
                        or not isinstance(definition.get("includedPermissions"), list)
                    ):
                        raise CloudError("GCP role definition is missing or deleted")
                    actions = strings(definition["includedPermissions"])
                    for member in strings(binding.get("members")):
                        if member.startswith("deleted:"):
                            capture.issue("GCP binding contains a deleted principal")
                            continue
                        if member.startswith("group:"):
                            kind = "group"
                            capture.issue(
                                "GCP group directory membership requires separate Cloud Identity access and was not collected"
                            )
                        elif member.startswith(("user:", "serviceAccount:")):
                            kind = "identity"
                        else:
                            capture.issue(
                                "GCP public, domain or federated principal-set semantics were not projected"
                            )
                            continue
                        owner = graph.node(f"principal:{member}", kind, member)
                        evidence = capture.observe(
                            call,
                            f"/calls/{call}/response/bindings/{index}",
                            {
                                "binding": binding,
                                "definition_call": definition_call,
                                "scope": scope,
                                "included_permissions": actions,
                            },
                        )
                        graph.edge(
                            owner,
                            target,
                            "grant",
                            evidence,
                            actions=actions,
                            conditional=bool(binding.get("condition")),
                        )
                except (CloudError, KeyError, TypeError):
                    capture.issue(
                        "A GCP role definition or binding could not be collected completely"
                    )
        except CloudError:
            capture.issue("A GCP scoped IAM policy could not be read with version 3")
    return graph.finish(
        selected,
        target,
        action,
        f"GCP project {project} and readable ancestor allow bindings; group expansion, resource-specific policies, deny policies and principal access boundaries remain unevaluated",
    )
