import json
import unittest
from pathlib import Path
from typing import Any

from normalize import normalize


class ImportTests(unittest.TestCase):
    def source(self) -> dict[str, Any]:
        return dict(json.loads(Path("samples/aws-export.json").read_text()))

    def test_aws_effect_conditions_and_evidence(self) -> None:
        source = self.source()
        source["records"][0]["Statement"][0]["Condition"] = {"StringEquals": {"aws:PrincipalTag/team": "demo"}}
        source["records"][0]["Statement"][0]["Effect"] = "Deny"
        edge = normalize(source)["edges"][0]
        self.assertEqual(edge["effect"], "deny")
        self.assertEqual(edge["conditions"], "unresolved")
        self.assertEqual(len(edge["evidence"]["sha256"]), 64)

    def test_azure_and_gcp_require_explicit_resolved_actions_and_scope(self) -> None:
        for cloud, record in [("azure", {"principalId": "alex", "resourceId": "archive", "actions": ["Microsoft.Storage/storageAccounts/read"], "condition": None}), ("gcp", {"member": "alex", "resource": "archive", "permissions": ["storage.objects.get"], "condition": None})]:
            source = self.source()
            source["cloud"], source["records"] = cloud, [record]
            self.assertEqual(normalize(source)["edges"][0]["relation"], "grant")

    def test_unsupported_constraints_cannot_be_silently_dropped(self) -> None:
        source = self.source()
        source["records"][0]["Statement"][0]["NotAction"] = "iam:*"
        with self.assertRaises(ValueError):
            normalize(source)
        patches: list[dict[str, Any]] = [{"cloud": "unknown"}, {"collected_at": "2026-10-30"}, {"schema_version": "9"}, {"unexpected": True}]
        for patch in patches:
            with self.assertRaises(ValueError):
                changed=self.source()
                changed.update(patch)
                normalize(changed)


if __name__ == "__main__":
    unittest.main()
