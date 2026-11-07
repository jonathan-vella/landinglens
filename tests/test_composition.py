import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from alz_assessor.catalog import load_catalog
from alz_assessor.cli import main
from alz_assessor.composition import compose_evidence
from alz_assessor.contracts import document, validate
from alz_assessor.engine import assess
from alz_assessor.review_session import ReviewSession
from alz_assessor.terraform import InputError

SUB = "/subscriptions/00000000-0000-0000-0000-000000000001"
RG_LOGGING = SUB + "/resourcegroups/rg-logging"
RG_HUB = SUB + "/resourcegroups/rg-hub"
AT_OLD = "2026-11-04T00:00:00Z"
AT_NEW = "2026-11-05T00:00:00Z"


class CompositionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.catalog = load_catalog()

    def bundle(self, scope, resources, *, at=AT_NEW, complete=True, mode="planned", metadata=None):
        return document(
            "evidence",
            schema_version="1.1",
            mode=mode,
            source="arm",
            scope=scope,
            collected_at=at,
            inventory_complete=complete,
            artifact_hashes={"template": "a" * 64},
            diagnostics=[],
            resources=resources,
            metadata=metadata or {},
        )

    def test_composes_modular_bundles_resolves_cross_module_controls_and_opens_review_session(self):
        storage = {
            "logical_id": "root.main",
            "arm_id": RG_LOGGING + "/providers/microsoft.storage/storageaccounts/logs",
            "resource_type": "Microsoft.Storage/storageAccounts",
            "state": "known",
            "reason": "",
            "source_location": "logging.json#storage",
            "properties": {"supportsHttpsTrafficOnly": True},
        }
        firewall_policy = {
            "logical_id": "root.main",
            "arm_id": RG_HUB + "/providers/microsoft.network/firewallpolicies/hubpolicy",
            "resource_type": "Microsoft.Network/firewallPolicies",
            "state": "known",
            "reason": "",
            "source_location": "hub.json#policy",
            "properties": {
                "sku": {"tier": "Premium"},
                "threatIntelMode": "Deny",
                "intrusionDetection": {"mode": "Deny"},
                "dnsSettings": {"enableProxy": True},
            },
        }
        b1 = self.bundle(RG_LOGGING, [storage], at=AT_OLD)
        b2 = self.bundle(RG_HUB, [firewall_policy], at=AT_NEW)
        composed = compose_evidence([b1, b2], scope=SUB)
        validate(composed, "evidence")
        self.assertEqual(composed["scope"], SUB)
        self.assertEqual(composed["collected_at"], AT_OLD)
        self.assertTrue(composed["inventory_complete"])
        self.assertEqual(composed["metadata"]["scopes"], [RG_LOGGING, RG_HUB])
        self.assertEqual(len(composed["resources"]), 2)
        self.assertEqual(
            [r["logical_id"] for r in composed["resources"]],
            ["bundle-1:root.main", "bundle-2:root.main"],
        )
        report = assess(composed, self.catalog, at=AT_NEW, evidence_tiers=True)
        outcomes = {
            row["upstream_id"]: row["planned"]["outcome"]
            for row in report["results"]
            if row["upstream_id"] in {"G04.01", "D07.06", "D07.07", "D07.18"}
        }
        self.assertEqual(
            outcomes,
            {"G04.01": "pass", "D07.06": "pass", "D07.07": "pass", "D07.18": "pass"},
        )
        session = ReviewSession(
            composed, self.catalog, self.root / "reviews", clock=lambda: AT_NEW, evidence_tiers=True
        )
        self.assertEqual(session.scope, SUB)

    def test_identical_arm_id_deduplicates_while_conflicting_arm_id_becomes_unknown(self):
        res1 = {
            "logical_id": "storage",
            "arm_id": RG_LOGGING + "/providers/microsoft.storage/storageaccounts/shared",
            "resource_type": "Microsoft.Storage/storageAccounts",
            "state": "known",
            "reason": "",
            "source_location": "one.json#storage",
            "properties": {"supportsHttpsTrafficOnly": True},
        }
        res2 = copy.deepcopy(res1)
        res2["source_location"] = "two.json#storage"
        same = compose_evidence([self.bundle(SUB, [res1]), self.bundle(SUB, [res2])])
        self.assertEqual(len(same["resources"]), 1)
        self.assertEqual(same["resources"][0]["state"], "known")
        self.assertTrue(same["inventory_complete"])
        self.assertEqual(same["diagnostics"][0]["reason"], "duplicate_resource")

        conflict = copy.deepcopy(res2)
        conflict["properties"] = {"supportsHttpsTrafficOnly": False}
        diff = compose_evidence([self.bundle(SUB, [res1]), self.bundle(SUB, [conflict])])
        self.assertEqual(len(diff["resources"]), 1)
        self.assertIsNone(diff["resources"][0]["arm_id"])
        self.assertEqual(diff["resources"][0]["state"], "unknown")
        self.assertEqual(diff["resources"][0]["reason"], "duplicate_resource")
        self.assertFalse(diff["inventory_complete"])

    def test_rejects_mixed_modes_foreign_scopes_minimized_and_existing_output(self):
        b1 = self.bundle(RG_LOGGING, [])
        b2 = self.bundle(RG_HUB, [])
        with self.assertRaisesRegex(InputError, "explicit --scope"):
            compose_evidence([b1, b2])
        with self.assertRaisesRegex(InputError, "outside target scope"):
            compose_evidence([b1, b2], scope="/subscriptions/00000000-0000-0000-0000-000000000002")
        b_obs = self.bundle(RG_LOGGING, [], mode="observed")
        with self.assertRaisesRegex(InputError, "same mode"):
            compose_evidence([b1, b_obs], scope=SUB)
        with self.assertRaisesRegex(InputError, "Minimized"):
            compose_evidence([{**b1, "presentation_only": True}, b2], scope=SUB)

        p1 = self.root / "b1.json"
        p2 = self.root / "b2.json"
        out = self.root / "composed.json"
        p1.write_text(json.dumps(b1), encoding="utf-8")
        p2.write_text(json.dumps(b2), encoding="utf-8")
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch(
                "sys.argv",
                ["alz-assessor", "compose", str(p1), str(p2), "--scope", SUB, "--output", str(out)],
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(main(), 0)
        self.assertTrue(out.is_file())
        with (
            patch(
                "sys.argv",
                ["alz-assessor", "compose", str(p1), str(p2), "--scope", SUB, "--output", str(out)],
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(main(), 2)
