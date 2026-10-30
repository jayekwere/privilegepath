from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from collectors.core import AwsCli, Capture, CloudError, Rest, private_json, sha
from collectors.fixtures import (
    ACCOUNT,
    OID,
    PRINCIPAL,
    RESOURCE,
    SUB,
    Native,
    aws_fixture,
    azure_fixture,
    gcp_fixture,
)
from collectors.providers import aws, azure, gcp, rest_pages


class CollectionTests(unittest.TestCase):
    def test_aws_native_managed_inline_membership_and_evidence(self) -> None:
        graph, cap = aws_fixture()
        self.assertEqual(graph["collection"]["status"], "complete")
        self.assertEqual(len(cap.calls), 4)
        self.assertEqual(graph["collection"]["snapshot_sha256"], sha(cap.snapshot()))
        self.assertTrue(any(e["relation"] == "member_of" for e in graph["edges"]))
        self.assertTrue(any(e["effect"] == "deny" for e in graph["edges"]))
        self.assertTrue(any(e["conditions"] == "unresolved" for e in graph["edges"]))
        for edge in graph["edges"]:
            observation = cap.observations[int(edge["evidence"]["pointer"].rsplit("/", 1)[1])]
            self.assertEqual(sha(observation), edge["evidence"]["sha256"])

    def test_wrong_aws_account_fails_before_inventory(self) -> None:
        cap = Capture(
            "aws", Native({"get-caller-identity": {"Account": "999999999999", "Arn": PRINCIPAL}})
        )
        with self.assertRaises(CloudError):
            aws(cap, "alder", ACCOUNT, PRINCIPAL, RESOURCE, "s3:GetObject")
        self.assertEqual(len(cap.calls), 1)

    def test_repeated_pagination_marks_incomplete(self) -> None:
        cap = Capture(
            "aws",
            Native(
                {
                    "get-caller-identity": {"Account": ACCOUNT, "Arn": PRINCIPAL},
                    "get-account-authorization-details": {
                        "IsTruncated": True,
                        "Marker": "repeat",
                        "UserDetailList": [{"Arn": PRINCIPAL, "UserName": "synthetic"}],
                    },
                }
            ),
        )
        graph = aws(cap, "alder", ACCOUNT, PRINCIPAL, RESOURCE, "s3:GetObject")
        self.assertEqual(graph["collection"]["status"], "partial")

    def test_managed_version_mismatch_is_not_replaced_with_expected_version(self) -> None:
        _, cap = aws_fixture()
        native = cap.call
        assert isinstance(native, Native)
        native.responses["get-policy-version"]["PolicyVersion"]["VersionId"] = "v99"
        graph = aws(Capture("aws", native), "alder", ACCOUNT, PRINCIPAL, RESOURCE, "s3:GetObject")
        self.assertEqual(graph["collection"]["status"], "partial")
        self.assertFalse(any(e["actions"] == ["s3:Get*"] for e in graph["edges"]))

    def test_unsupported_notaction_is_partial(self) -> None:
        _, cap = aws_fixture()
        native = cap.call
        assert isinstance(native, Native)
        user = native.responses["get-account-authorization-details"]["UserDetailList"][0]
        user["UserPolicyList"][0]["PolicyDocument"]["Statement"][0]["NotAction"] = "iam:*"
        graph = aws(Capture("aws", native), "alder", ACCOUNT, PRINCIPAL, RESOURCE, "s3:GetObject")
        self.assertEqual(graph["collection"]["status"], "partial")

    def test_azure_exclusions_are_subtraction_and_planes_remain_distinct(self) -> None:
        graph, _ = azure_fixture()
        self.assertEqual(graph["collection"]["status"], "complete")
        self.assertEqual({e["constraints"]["plane"] for e in graph["edges"]}, {"control", "data"})
        self.assertTrue(all(e["effect"] == "allow" for e in graph["edges"]))
        self.assertEqual(
            graph["edges"][0]["constraints"]["excluded_actions"],
            ["Microsoft.Storage/storageAccounts/delete"],
        )

    def test_azure_scope_escape_and_untrusted_nextlink_rejected(self) -> None:
        with self.assertRaises(CloudError):
            azure(Capture("azure", Native({})), "alder", SUB, OID, "/subscriptions/other", "read")
        cap = Capture(
            "azure",
            Native(
                {
                    "https://management.azure.com/subscriptions/x": {
                        "value": [],
                        "nextLink": "https://evil.invalid/token",
                    }
                }
            ),
        )
        with self.assertRaises(CloudError):
            rest_pages(
                cap,
                "https://management.azure.com/subscriptions/x",
                allowed_prefix="/subscriptions/x",
            )
        self.assertEqual(len(cap.calls), 1)

    def test_gcp_ancestor_and_role_permissions_are_native_and_group_is_partial(self) -> None:
        graph, cap = gcp_fixture()
        self.assertEqual(graph["collection"]["status"], "partial")
        self.assertEqual(len(graph["edges"]), 2)
        self.assertTrue(
            all(e["actions"] == ["resourcemanager.projects.get"] for e in graph["edges"])
        )
        self.assertEqual(sum("iam.googleapis.com" in c["target"] for c in cap.calls), 1)

    def test_gcp_unreadable_parent_is_partial(self) -> None:
        _, cap = gcp_fixture()
        native = cap.call
        assert isinstance(native, Native)
        del native.responses["https://cloudresourcemanager.googleapis.com/v3/organizations/456"]
        graph = gcp(
            Capture("gcp", native),
            "alder",
            "synthetic-project",
            "user:reader@example.invalid",
            "resourcemanager.projects.get",
        )
        self.assertEqual(graph["collection"]["status"], "partial")

    def test_read_only_clients_reject_writes_or_wrong_authorities_before_credentials(self) -> None:
        with self.assertRaises(CloudError):
            AwsCli("test")("iam", "delete-user", {})
        rest = Rest(
            lambda host: self.fail("Credential must not be accessed"), {"management.azure.com"}
        )
        for method, url in [
            ("GET", "https://evil.invalid/"),
            ("PATCH", "https://management.azure.com/"),
            ("GET", "https://management.azure.com@evil.invalid/"),
        ]:
            with self.assertRaises(CloudError):
                rest(method, url, {})

    def test_snapshot_private_no_overwrite_and_bounded_requests(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "native.json"
            private_json(path, {"synthetic": True})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(CloudError):
                private_json(path, {})
        cap = Capture("aws", Native({"read": {}}))
        for _ in range(200):
            cap.request("GET", "read")
        with self.assertRaises(CloudError):
            cap.request("GET", "read")

    def test_cli_credentials_are_context_bound_and_never_in_snapshot(self) -> None:
        from collectors.__main__ import AzureTokens, GcpToken

        with patch("collectors.__main__.command_json", return_value={"id": SUB, "tenantId": OID}):
            token = AzureTokens(OID, SUB)
        with patch(
            "collectors.__main__.command_json", return_value={"accessToken": "private-token"}
        ):
            self.assertEqual(token("management.azure.com"), "private-token")
        with self.assertRaises(CloudError):
            token("evil.invalid")
        with self.assertRaises(CloudError):
            GcpToken("synthetic-project")("evil.invalid")
        with (
            patch(
                "collectors.__main__.command_json", return_value={"id": SUB, "tenantId": "other"}
            ),
            self.assertRaises(CloudError),
        ):
            AzureTokens(OID, SUB)


class BoundaryTests(unittest.TestCase):
    def test_each_cli_writes_private_native_evidence_and_rejects_overwrite(self) -> None:
        import contextlib
        import io
        import json

        from collectors.__main__ import main
        from collectors.fixtures import OID, SUB

        cases = [
            (
                "aws",
                aws_fixture,
                [
                    "--profile",
                    "synthetic",
                    "--account",
                    ACCOUNT,
                    "--principal",
                    PRINCIPAL,
                    "--resource",
                    RESOURCE,
                    "--action",
                    "s3:GetObject",
                ],
            ),
            (
                "azure",
                azure_fixture,
                [
                    "--directory-tenant",
                    OID,
                    "--subscription",
                    SUB,
                    "--principal",
                    OID,
                    "--resource",
                    f"/subscriptions/{SUB}",
                    "--action",
                    "Microsoft.Storage/storageAccounts/read",
                ],
            ),
            (
                "gcp",
                gcp_fixture,
                [
                    "--project",
                    "synthetic-project",
                    "--principal",
                    "user:reader@example.invalid",
                    "--action",
                    "resourcemanager.projects.get",
                ],
            ),
        ]
        for provider, fixture, args in cases:
            _, cap = fixture()
            with tempfile.TemporaryDirectory() as root, contextlib.ExitStack() as stack:
                if provider == "aws":
                    stack.enter_context(patch("collectors.__main__.AwsCli", return_value=cap.call))
                else:
                    stack.enter_context(patch("collectors.__main__.Rest", return_value=cap.call))
                    stack.enter_context(patch("collectors.__main__.AzureTokens"))
                out = Path(root) / "graph.json"
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    main([provider, "--tenant", "alder", "--out", str(out), *args])
                graph = json.loads(out.read_text())
                snapshot = json.loads(out.with_suffix(".snapshot.json").read_text())
                self.assertEqual(graph["collection"]["snapshot_sha256"], sha(snapshot))
                self.assertEqual(out.stat().st_mode & 0o777, 0o600)
                self.assertNotIn("reader@example", stdout.getvalue())
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    main([provider, "--tenant", "alder", "--out", str(out), *args])

    def test_missing_cli_provider_scope_and_tenant_are_rejected(self) -> None:
        import contextlib
        import io

        from collectors.__main__ import main

        for provider, extra in [
            ("aws", []),
            ("azure", []),
            ("gcp", []),
            ("aws", ["--tenant", "../other"]),
        ]:
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(
                    [
                        provider,
                        "--tenant",
                        "alder",
                        "--principal",
                        "synthetic",
                        "--action",
                        "read",
                        "--out",
                        "unused.json",
                        *extra,
                    ]
                )

    def test_provider_transport_parses_native_json_without_redirects(self) -> None:
        import json
        import urllib.error
        from unittest.mock import MagicMock

        rest = Rest(lambda host: "private-token", {"management.azure.com"})
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b'{"value":[]}'
        opener = MagicMock()
        opener.open.return_value = response
        rest.opener = opener
        self.assertEqual(
            rest("GET", "https://management.azure.com/subscriptions/synthetic", {}), {"value": []}
        )
        req = opener.open.call_args.args[0]
        self.assertEqual(req.get_header("Authorization"), "Bearer private-token")
        response.__enter__.return_value.read.return_value = json.dumps([]).encode()
        with self.assertRaises(CloudError):
            rest("GET", "https://management.azure.com/", {})
        opener.open.side_effect = urllib.error.HTTPError(
            "https://management.azure.com/",
            403,
            "sensitive detail",
            __import__("email.message", fromlist=["Message"]).Message(),
            None,
        )
        with self.assertRaisesRegex(CloudError, "^Provider HTTP 403$"):
            rest("GET", "https://management.azure.com/", {})

    def test_command_failure_or_nonobject_output_never_becomes_clean_evidence(self) -> None:
        from subprocess import CompletedProcess

        from collectors.core import command_json

        for result in [
            CompletedProcess([], 1, b"", b"private error"),
            CompletedProcess([], 0, b"[]", b""),
        ]:
            with (
                patch("collectors.core.subprocess.run", return_value=result),
                self.assertRaises(CloudError),
            ):
                command_json(["aws"])
        with patch(
            "collectors.core.subprocess.run",
            return_value=CompletedProcess([], 0, b'{"native":true}', b""),
        ):
            self.assertEqual(command_json(["aws"]), {"native": True})

    def test_aws_role_candidate_retains_unresolved_trust(self) -> None:
        from collectors.fixtures import ACCOUNT, PRINCIPAL, RESOURCE

        _, cap = aws_fixture()
        native = cap.call
        assert isinstance(native, Native)
        inventory = native.responses["get-account-authorization-details"]
        role = f"arn:aws:iam::{ACCOUNT}:role/synthetic"
        inventory["RoleDetailList"] = [{"Arn": role, "RoleName": "synthetic", "RolePolicyList": []}]
        inventory["UserDetailList"][0]["UserPolicyList"] = [
            {
                "PolicyName": "assume",
                "PolicyDocument": {
                    "Statement": {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": role}
                },
            }
        ]
        graph = aws(Capture("aws", native), "alder", ACCOUNT, PRINCIPAL, RESOURCE, "s3:GetObject")
        candidates = [e for e in graph["edges"] if e["relation"] == "can_assume"]
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["conditions"], "unresolved")

    def test_azure_transitive_membership_collects_directory_evidence(self) -> None:
        from collectors.fixtures import OID, SUB

        _, cap = azure_fixture()
        native = cap.call
        assert isinstance(native, Native)
        group = "55555555-5555-5555-5555-555555555555"
        assignment = native.responses[
            f"https://management.azure.com/subscriptions/{SUB}/providers/Microsoft.Authorization/roleAssignments"
        ]["value"][0]
        assignment["properties"].update(principalId=group, principalType="Group")
        native.responses[f"https://graph.microsoft.com/v1.0/groups/{group}/transitiveMembers"] = {
            "value": [{"id": OID, "@odata.type": "#microsoft.graph.user"}]
        }
        graph = azure(
            Capture("azure", native),
            "alder",
            SUB,
            OID,
            f"/subscriptions/{SUB}",
            "Microsoft.Storage/storageAccounts/read",
            groups=True,
        )
        self.assertEqual(graph["collection"]["status"], "complete")
        self.assertTrue(any(e["relation"] == "member_of" for e in graph["edges"]))
        del native.responses[f"https://graph.microsoft.com/v1.0/groups/{group}/transitiveMembers"]
        graph = azure(
            Capture("azure", native),
            "alder",
            SUB,
            OID,
            f"/subscriptions/{SUB}",
            "read",
            groups=True,
        )
        self.assertEqual(graph["collection"]["status"], "partial")

    def test_gcp_deleted_roles_and_unreadable_policies_cannot_prove_no_access(self) -> None:
        _, cap = gcp_fixture()
        native = cap.call
        assert isinstance(native, Native)
        native.responses["https://iam.googleapis.com/v1/roles/viewer"]["deleted"] = True
        graph = gcp(
            Capture("gcp", native),
            "alder",
            "synthetic-project",
            "user:reader@example.invalid",
            "read",
        )
        self.assertEqual(graph["collection"]["status"], "partial")
        self.assertEqual(graph["edges"], [])
        del native.responses[
            "https://cloudresourcemanager.googleapis.com/v3/projects/123:getIamPolicy"
        ]
        graph = gcp(
            Capture("gcp", native),
            "alder",
            "synthetic-project",
            "user:reader@example.invalid",
            "read",
            ancestors=False,
        )
        self.assertEqual(graph["collection"]["status"], "partial")


if __name__ == "__main__":
    unittest.main()
