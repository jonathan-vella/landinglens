import hashlib
import json
import shutil
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from alz_assessor.terraform import Analyzer

FIXTURE = Path(__file__).parent / "fixtures" / "alz-avm"
WORKSPACE = "module.platform.module.workspace.azurerm_log_analytics_workspace.this"


class AvmFixtureTests(unittest.TestCase):
    def test_unmodified_pinned_avm_snapshot_provenance(self):
        provenance = json.loads((FIXTURE / "provenance.json").read_text())
        self.assertEqual(provenance["revision"], "b4ffa3ff87ac09ff6de3b7014c44b4d213aa302b")
        self.assertEqual(provenance["tag"], "v0.5.1")
        self.assertEqual(provenance["license"], "MIT")
        self.assertEqual(len(provenance["files"]), 15)
        for file in provenance["files"]:
            with self.subTest(file=file["file"]):
                path = FIXTURE / "snapshots" / "workspace" / file["file"]
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), file["sha256"])
                self.assertIn(provenance["revision"], file["url"])
                self.assertTrue(file["retrieved_at"])

    def test_real_avm_supported_properties_resolve_without_execution(self):
        with (
            patch.object(socket.socket, "connect", side_effect=AssertionError("network")),
            patch("subprocess.run", side_effect=AssertionError("Terraform execution")),
        ):
            result = Analyzer(FIXTURE, manifest=FIXTURE / "snapshots.json").analyze()
        resources = {
            resource["address"]: resource["properties"] for resource in result["resources"]
        }
        workspace = resources[WORKSPACE]
        self.assertEqual(workspace["location"], "australiaeast")
        self.assertEqual(workspace["name"], "alz-platform-logs")
        self.assertEqual(workspace["resource_group_name"], "alz-management")
        self.assertEqual(workspace["retention_in_days"], 45)
        self.assertEqual(workspace["sku"], "PerGB2018")
        self.assertIs(workspace["local_authentication_enabled"], False)
        self.assertIsNone(workspace["daily_quota_gb"])  # No provider default is invented.
        self.assertIs(workspace["internet_ingestion_enabled"], False)
        self.assertIs(workspace["internet_query_enabled"], False)
        self.assertEqual(workspace["identity"], [])
        self.assertEqual(workspace["timeouts"], [])
        self.assertEqual(sum(address.endswith("[*]") for address in resources), 6)
        self.assertEqual(len(result["diagnostics"]), 6)
        self.assertFalse(any("telemetry" in address for address in resources))
        self.assertIn("module.platform.module.workspace:snapshot", result["input_sha256"])

    def test_same_root_missing_nested_avm_snapshot_reports_incomplete_coverage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "alz-avm"
            shutil.copytree(FIXTURE, root)
            manifest = root / "snapshots.json"
            data = json.loads(manifest.read_text())
            data["modules"] = data["modules"][:1]
            manifest.write_text(json.dumps(data))
            with patch.object(socket.socket, "connect", side_effect=AssertionError("network")):
                result = Analyzer(root, manifest=manifest).analyze()
        self.assertFalse(any(r["address"] == WORKSPACE for r in result["resources"]))
        self.assertEqual(
            result["diagnostics"],
            [
                {
                    "address": "module.platform.module.workspace",
                    "reason": "required module snapshot missing",
                }
            ],
        )
        self.assertEqual(len(result["resources"]), 3)


if __name__ == "__main__":
    unittest.main()
