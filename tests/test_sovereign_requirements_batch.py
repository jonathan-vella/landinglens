import copy
import hashlib
import json
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

import test_sovereign_requirements_preparation as preparation
from test_sovereign_requirements_preparation import AT, IDS, PRIVATE, SCOPE, UNTIL

from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import control_digest, digest
from alz_assessor.crosswalk import load_crosswalk
from alz_assessor.engine import assess
from alz_assessor.interviews import BANK, BANK_VERSION, compile_interview, prepare_interview
from alz_assessor.replay import export_bundle, replay_bundle, semantic
from alz_assessor.review_session import ReviewSession
from alz_assessor.sources import tf_properties
from alz_assessor.terraform import InputError

REFERENCE = Path(__file__).resolve().parents[1] / "references/recommendation-batches"


class SovereignRequirementsBatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        data = files("alz_assessor").joinpath("data")
        self.catalog = load_catalog()
        self.previous = load_catalog(str(data.joinpath("catalog-2026-11-06.27.json")))
        self.matrix = json.loads((REFERENCE / "batch-28.json").read_text("utf-8"))
        self.fixture = preparation.SovereignRequirementsPreparationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.catalog = self.catalog
        self.fixture.matrix = self.matrix

    def test_exact_final_successor_nonown_objects_original_four_and_frozen_bytes(self):
        self.assertEqual(self.catalog["catalog_version"], "2026-11-06.28")
        self.assertEqual(self.matrix["catalog_version"], self.catalog["catalog_version"])
        self.assertEqual(
            self.matrix["activation_base_main"], "792e652f642eba7ace77a8f32861e6b9024d1bd6"
        )
        self.assertEqual({r["upstream_id"]: r["guid"] for r in self.matrix["recommendations"]}, IDS)
        before = {c["upstream_guid"]: c for c in self.previous["controls"]}
        for control in self.catalog["controls"]:
            previous = before[control["upstream_guid"]]
            if control["upstream_guid"] not in IDS.values():
                self.assertEqual(control, previous)
            for key in ("recommendation", "upstream_guid", "upstream_id", "inventory_flags"):
                self.assertEqual(control[key], previous[key])
            if control["upstream_guid"] in IDS.values():
                row = next(
                    r
                    for r in self.matrix["recommendations"]
                    if r["guid"] == control["upstream_guid"]
                )
                self.assertEqual(control["evidence_requirements"], row["evidence_requirements"])
                self.assertEqual(control["rationale"], row["limitations"])
                self.assertEqual(control["automation"], row["classification"])
                self.assertIsNone(control["rule"])
        data = files("alz_assessor").joinpath("data")
        original = load_catalog(str(data.joinpath("catalog-2026-11-04.2.json")))
        for control in original["controls"]:
            if control["automation"] == "automated":
                actual = next(
                    c for c in self.catalog["controls"] if c["control_id"] == control["control_id"]
                )
                self.assertEqual(actual, before[control["upstream_guid"]])
                self.assertEqual(control_digest(actual), control_digest(control))
        self.assertEqual(len(self.catalog["controls"]), 255)
        self.assertEqual(
            {
                key: sum(c["automation"] == key for c in self.catalog["controls"])
                for key in ("automated", "assisted", "manual")
            },
            {"automated": 12, "assisted": 200, "manual": 43},
        )
        for kind in ("catalog", "crosswalk"):
            raw = data.joinpath(f"{kind}-2026-11-06.27.json").read_bytes()
            self.assertEqual(
                hashlib.sha256(raw).hexdigest(),
                self.matrix[f"preserved_{kind}_bytes"]["2026-11-06.27"],
            )

    def test_all243_prior_rows29_receipts_fixed251_sources_and_final_matrix_chain(self):
        ledger = json.loads((REFERENCE / "ledger.json").read_text("utf-8"))
        earlier = set(self.matrix["preserved_delivery_batches"])
        rows = [r for r in ledger["recommendations"] if r["batch"] in earlier]
        receipts = {k: v for k, v in ledger["deliveries"].items() if k in earlier}
        self.assertEqual((len(rows), len(receipts)), (243, 29))
        self.assertEqual(digest(rows), self.matrix["preserved_merged_recommendations_sha256"])
        self.assertEqual(digest(receipts), self.matrix["preserved_delivery_receipts_sha256"])
        self.assertEqual(len(ledger["recommendations"]), 251)
        for row in rows:
            self.assertEqual(row["status"], "merged")
            self.assertEqual(row["pr"], receipts[row["batch"]]["pr"])
            self.assertEqual(row["merge_commit"], receipts[row["batch"]]["merge_commit"])
        own = [r for r in ledger["recommendations"] if r["batch"] == "28"]
        self.assertEqual({r["guid"] for r in own}, set(IDS.values()))
        for row in own:
            if row["status"] == "merged":
                self.assertEqual(row["pr"], ledger["deliveries"]["28"]["pr"])
                self.assertEqual(row["merge_commit"], ledger["deliveries"]["28"]["merge_commit"])
            else:
                self.assertEqual(row["status"], "implementation-in-progress")
                self.assertIsNone(row["merge_commit"])
        preparation_sources = json.loads(
            (REFERENCE / "preparation-28-sources.json").read_text("utf-8")
        )
        accepted = json.loads((REFERENCE / "batch-28-sources.json").read_text("utf-8"))
        self.assertEqual(len(preparation_sources["sources"]), 41)
        self.assertEqual(len(accepted["sources"]), 44)
        self.assertEqual(accepted["sources"][:41], preparation_sources["sources"])
        data = files("alz_assessor").joinpath("data")
        current = json.loads(data.joinpath("batch-matrix-2026-11-06.28.json").read_text("utf-8"))
        previous = json.loads(data.joinpath("batch-matrix-2026-11-06.27.json").read_text("utf-8"))
        self.assertEqual(current["batches"][:-1], previous["batches"])
        self.assertEqual(current["sources"][:-1], previous["sources"])
        self.assertEqual(current["batches"][-1], self.matrix)
        self.assertEqual(current["sources"][-1], accepted)

    def test_registered_eight_blank_decisions_and_all_prior_questions(self):
        question = self.matrix["interview"]
        self.assertEqual(question, {"id": question["id"], **BANK[question["id"]]})
        report = assess(self.fixture.bundle(), self.catalog, at=AT, evidence_tiers=True)
        response = prepare_interview(report, self.catalog, question["id"], SCOPE)
        self.assertEqual(response["bank_version"], BANK_VERSION)
        self.assertEqual(len(response["decisions"]), 8)
        self.assertTrue(all(r["outcome"] is None for r in response["decisions"]))
        for batch in self.matrix["preserved_delivery_batches"]:
            prior = json.loads((REFERENCE / f"batch-{batch}.json").read_text("utf-8"))
            if "interview" in prior:
                item = prior["interview"]
                self.assertEqual(item, {"id": item["id"], **BANK[item["id"]]})
        with self.assertRaises(InputError):
            compile_interview(response, self.catalog, at=AT)

    def test_actual21_storage_key_context_is_separate_from_location_or_jurisdiction(self):
        bundle = self.fixture.bundle()
        storage = bundle["resources"][4]
        storage["properties"]["storageEncryptionSummary"] = {
            "keySource": "Microsoft.Keyvault",
            "requireInfrastructureEncryption": True,
            "queueKeyType": "Account",
            "tableKeyType": "Service",
            "keyvaultproperties": {"keyvaulturi": PRIVATE},
        }
        context = self.fixture.context("E03.04", bundle)
        facts = context["resources"][1]["facts"]["storageEncryptionSummary"]
        self.assertEqual(
            facts,
            {
                "keySource": "Microsoft.Keyvault",
                "requireInfrastructureEncryption": True,
                "queueKeyType": "Account",
                "tableKeyType": "Service",
            },
        )
        self.assertNotIn(PRIVATE, json.dumps(context))
        projected = tf_properties(
            "azurerm_storage_account",
            {
                "account_tier": "Standard",
                "account_replication_type": "GZRS",
                "infrastructure_encryption_enabled": True,
                "queue_encryption_key_type": "Account",
                "table_encryption_key_type": "Service",
                "customer_managed_key": [{PRIVATE: PRIVATE}],
            },
        )
        self.assertIn("unknown", projected["storageEncryptionSummary"]["keySource"])
        self.assertNotIn(PRIVATE, json.dumps(projected))
        self.assertTrue(all(not r["subchecks"] for r in context["resources"]))
        report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        self.assertTrue(all(r["observed"]["outcome"] == "manual" for r in self.fixture.own(report)))

    def test_registered_adapters_tiers_privacy_decisions_outputs_and_cli(self):
        self.fixture.test_budget_reuses_merged_version_qualified_helper_not_two_mode_compliance()
        self.fixture.test_budget_api_alone_has_no_signal_and_other_tiers_use_strict_context()
        self.fixture.test_budget_notification_bounds_types_disabled_and_thresholds_are_not_evaluated()
        self.fixture.test_budget_raw_modules_plan_and_arm_preserve_source_version_and_privacy()
        self.fixture.test_eight_independent_blank_outcomes_and_exceptions_with_selection()
        self.fixture.test_attribution_scope_content_time_expiry_and_decision_binding()
        self.fixture.test_all_outputs_and_planned_observed_do_not_manufacture_verified()
        self.fixture.test_cli_saved_evidence_uses_same_candidate_without_network()

    def test_registered_session_atomicity_resume_and_original_time_accepted_replay(self):
        bundle = self.fixture.bundle()
        session = ReviewSession(
            bundle, self.catalog, self.root / "registered", clock=lambda: AT, evidence_tiers=True
        )
        question = next(
            q for q in session.state()["interviews"] if q["id"] == self.matrix["interview"]["id"]
        )
        response = self.fixture.filled(question["template"])
        invalid = copy.deepcopy(response)
        invalid["decisions"][-1]["outcome"] = None
        for payload in (invalid,):
            with self.assertRaises(InputError):
                session.save_interview({"revision": 0, "response": payload, "replace_existing": []})
        with patch.object(Path, "rename", side_effect=OSError("authored disk failure")):
            with self.assertRaises(OSError):
                session.save_interview(
                    {"revision": 0, "response": response, "replace_existing": []}
                )
        self.assertEqual(session.revision, 0)
        session.save_interview({"revision": 0, "response": response, "replace_existing": []})
        self.assertEqual(len(session.state()["records"]), 8)
        resumed = ReviewSession.resume(
            session.directory / "revision-0001", self.root / "resumed", clock=lambda: AT
        )
        self.assertEqual(semantic(session.report), semantic(resumed.report))
        export_bundle(
            self.root / "accepted",
            session.evidence,
            self.catalog,
            manual=session.reviews["manual"],
            at=AT,
            evidence_tiers=True,
        )
        self.assertEqual(semantic(replay_bundle(self.root / "accepted")), semantic(session.report))
        expired = assess(
            session.evidence,
            self.catalog,
            at=UNTIL,
            manual=session.reviews["manual"],
            evidence_tiers=True,
        )
        self.assertTrue(
            all(r["observed"]["outcome"] == "manual" for r in self.fixture.own(expired))
        )
        candidate = copy.deepcopy(self.catalog)
        next(c for c in candidate["controls"] if c["upstream_id"] == "E03.03")["rationale"] += (
            " Changed."
        )
        with self.assertRaises(InputError):
            export_bundle(self.root / "candidate", bundle, candidate, at=AT)
        export_bundle(self.root / "previous", bundle, self.previous, at=AT, evidence_tiers=True)
        self.assertEqual(
            semantic(replay_bundle(self.root / "previous")),
            semantic(assess(bundle, self.previous, at=AT, evidence_tiers=True)),
        )
        crosswalk = load_crosswalk(self.catalog)
        self.assertEqual(crosswalk["crosswalk_version"], self.catalog["catalog_version"])
