"""Synthetic native provider responses for offline collector demonstrations."""

from __future__ import annotations

import copy
from typing import Any

from collectors.core import Capture, CloudError, private_json
from collectors.providers import aws, azure, gcp

ACCOUNT = "123456789012"
PRINCIPAL = f"arn:aws:iam::{ACCOUNT}:user/synthetic"
RESOURCE = "arn:aws:s3:::synthetic-archive/*"
SUB = "11111111-1111-1111-1111-111111111111"
OID = "22222222-2222-2222-2222-222222222222"
ROLE = f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/33333333-3333-3333-3333-333333333333"
AT = "2026-10-30T12:00:00Z"


class Native:
    def __init__(self, responses: dict[str, dict[str, Any]]):
        self.responses = responses

    def __call__(self, method: str, target: str, parameters: dict[str, Any]) -> dict[str, Any]:
        key = target.split("?", 1)[0]
        if key not in self.responses:
            raise CloudError("Access denied in synthetic provider")
        return copy.deepcopy(self.responses[key])


def aws_fixture(source: str = "native-fixture.json") -> tuple[dict[str, Any], Capture]:
    native = Native(
        {
            "get-caller-identity": {"Account": ACCOUNT, "Arn": PRINCIPAL},
            "get-account-authorization-details": {
                "IsTruncated": False,
                "UserDetailList": [
                    {
                        "Arn": PRINCIPAL,
                        "UserName": "synthetic",
                        "GroupList": ["readers"],
                        "UserPolicyList": [
                            {
                                "PolicyName": "conditional",
                                "PolicyDocument": {
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": "s3:GetObject",
                                            "Resource": RESOURCE,
                                            "Condition": {"Bool": {"aws:SecureTransport": "true"}},
                                        }
                                    ]
                                },
                            }
                        ],
                        "AttachedManagedPolicies": [
                            {"PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}
                        ],
                    }
                ],
                "GroupDetailList": [
                    {
                        "Arn": f"arn:aws:iam::{ACCOUNT}:group/readers",
                        "GroupName": "readers",
                        "GroupPolicyList": [
                            {
                                "PolicyName": "deny",
                                "PolicyDocument": {
                                    "Statement": {
                                        "Effect": "Deny",
                                        "Action": "s3:DeleteObject",
                                        "Resource": "*",
                                    }
                                },
                            }
                        ],
                    }
                ],
            },
            "get-policy": {
                "Policy": {
                    "Arn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                    "DefaultVersionId": "v1",
                }
            },
            "get-policy-version": {
                "PolicyVersion": {
                    "VersionId": "v1",
                    "Document": {
                        "Statement": {"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}
                    },
                }
            },
        }
    )
    cap = Capture("aws", native, source=source, at=AT)
    return aws(cap, "alder", ACCOUNT, PRINCIPAL, RESOURCE, "s3:GetObject"), cap


def azure_fixture(source: str = "native-fixture.json") -> tuple[dict[str, Any], Capture]:
    resource = f"/subscriptions/{SUB}"
    native = Native(
        {
            f"https://management.azure.com{resource}": {"subscriptionId": SUB},
            f"https://management.azure.com{resource}/providers/Microsoft.Authorization/roleAssignments": {
                "value": [
                    {
                        "id": resource
                        + "/providers/Microsoft.Authorization/roleAssignments/synthetic",
                        "properties": {
                            "scope": resource,
                            "principalId": OID,
                            "principalType": "User",
                            "roleDefinitionId": ROLE,
                        },
                    }
                ]
            },
            f"https://management.azure.com{ROLE}": {
                "id": ROLE,
                "properties": {
                    "permissions": [
                        {
                            "actions": ["Microsoft.Storage/*"],
                            "notActions": ["Microsoft.Storage/storageAccounts/delete"],
                            "dataActions": [
                                "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
                            ],
                            "notDataActions": [],
                        }
                    ]
                },
            },
        }
    )
    cap = Capture("azure", native, source=source, at=AT)
    return azure(cap, "alder", SUB, OID, resource, "Microsoft.Storage/storageAccounts/read"), cap


def gcp_fixture(source: str = "native-fixture.json") -> tuple[dict[str, Any], Capture]:
    native = Native(
        {
            "https://cloudresourcemanager.googleapis.com/v3/projects/synthetic-project": {
                "name": "projects/123",
                "projectId": "synthetic-project",
                "parent": "organizations/456",
            },
            "https://cloudresourcemanager.googleapis.com/v3/organizations/456": {
                "name": "organizations/456"
            },
            "https://cloudresourcemanager.googleapis.com/v3/projects/123:getIamPolicy": {
                "version": 3,
                "bindings": [{"role": "roles/viewer", "members": ["user:reader@example.invalid"]}],
            },
            "https://cloudresourcemanager.googleapis.com/v3/organizations/456:getIamPolicy": {
                "version": 3,
                "bindings": [
                    {
                        "role": "roles/viewer",
                        "members": ["group:readers@example.invalid"],
                        "condition": {"expression": "true"},
                    }
                ],
            },
            "https://iam.googleapis.com/v1/roles/viewer": {
                "name": "roles/viewer",
                "includedPermissions": ["resourcemanager.projects.get"],
            },
        }
    )
    cap = Capture("gcp", native, source=source, at=AT)
    return gcp(
        cap,
        "alder",
        "synthetic-project",
        "user:reader@example.invalid",
        "resourcemanager.projects.get",
    ), cap


def main() -> None:
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(
        description="Synthetic native IAM collector demo; makes no network calls"
    )
    parser.add_argument("provider", choices=["aws", "azure", "gcp"])
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    snapshot_path = args.out.with_suffix(".native.json")
    graph, cap = {"aws": aws_fixture, "azure": azure_fixture, "gcp": gcp_fixture}[args.provider](
        snapshot_path.name
    )
    private_json(snapshot_path, cap.snapshot())
    private_json(args.out, graph)
    print("Synthetic native collector demo written; effective access remains unproven")


if __name__ == "__main__":
    main()
