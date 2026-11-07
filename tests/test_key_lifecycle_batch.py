import copy
import hashlib
import json
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

import test_key_lifecycle_preparation as preparation
from test_key_lifecycle_preparation import AT, IDS, OWN, PRIVATE, SUB, UNTIL

from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import control_digest, digest
from alz_assessor.crosswalk import load_crosswalk
from alz_assessor.engine import assess
from alz_assessor.interviews import BANK, BANK_VERSION, compile_interview, prepare_interview
from alz_assessor.replay import export_bundle, replay_bundle, semantic
from alz_assessor.review_session import ReviewSession
from alz_assessor.terraform import InputError

REFERENCE = Path(__file__).resolve().parents[1] / "references" / "recommendation-batches"


class KeyLifecycleBatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        data = files("alz_assessor").joinpath("data")
        frozen = data.joinpath("catalog-2026-11-06.27.json")
        self.catalog = load_catalog(str(frozen)) if frozen.is_file() else load_catalog()
        self.previous = load_catalog(str(data.joinpath("catalog-2026-11-06.26.json")))
        self.matrix = json.loads((REFERENCE / "batch-21.json").read_text("utf-8"))
        self.fixture = preparation.KeyLifecyclePreparationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.catalog = self.catalog

    def test_exact_successor_nonown_full_objects_original_four_and_frozen_bytes(self):
        self.assertEqual(self.catalog["catalog_version"], "2026-11-06.27")
        self.assertEqual(self.matrix["catalog_version"], self.catalog["catalog_version"])
        self.assertEqual(
            self.matrix["activation_base_main"], "226caec2d4eb2f183d2cdbfa1fbde3c9d7698ec1"
        )
        own = {r["guid"]: r for r in self.matrix["recommendations"]}
        self.assertEqual(set(own), set(OWN.values()))
        before = {c["upstream_guid"]: c for c in self.previous["controls"]}
        for control in self.catalog["controls"]:
            previous = before[control["upstream_guid"]]
            if control["upstream_guid"] not in own:
                self.assertEqual(control, previous)
                continue
            row = own[control["upstream_guid"]]
            for key in ("recommendation", "upstream_guid", "upstream_id", "inventory_flags"):
                self.assertEqual(control[key], previous[key])
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
            raw = data.joinpath(f"{kind}-2026-11-06.26.json").read_bytes()
            self.assertEqual(
                hashlib.sha256(raw).hexdigest(),
                self.matrix[f"preserved_{kind}_bytes"]["2026-11-06.26"],
            )

    def test_all235_prior_rows28_receipts_fixed251_sources_and_matrix_chain(self):
        ledger = json.loads((REFERENCE / "ledger.json").read_text("utf-8"))
        earlier = set(self.matrix["preserved_delivery_batches"])
        rows = [r for r in ledger["recommendations"] if r["batch"] in earlier]
        receipts = {key: value for key, value in ledger["deliveries"].items() if key in earlier}
        self.assertEqual((len(rows), len(receipts)), (235, 28))
        self.assertEqual(digest(rows), self.matrix["preserved_merged_recommendations_sha256"])
        self.assertEqual(digest(receipts), self.matrix["preserved_delivery_receipts_sha256"])
        for row in rows:
            self.assertEqual(row["status"], "merged")
            self.assertEqual(row["pr"], receipts[row["batch"]]["pr"])
            self.assertEqual(row["merge_commit"], receipts[row["batch"]]["merge_commit"])
        self.assertEqual(len(ledger["recommendations"]), 251)
        own = [r for r in ledger["recommendations"] if r["batch"] == "21"]
        self.assertEqual({r["guid"] for r in own}, set(OWN.values()))
        for row in own:
            if row["status"] == "merged":
                self.assertEqual(row["pr"], ledger["deliveries"]["21"]["pr"])
                self.assertEqual(row["merge_commit"], ledger["deliveries"]["21"]["merge_commit"])
            else:
                self.assertEqual(row["status"], "implementation-in-progress")
                self.assertIsNone(row["merge_commit"])
        source = json.loads((REFERENCE / "preparation-21-sources.json").read_text("utf-8"))
        accepted = json.loads((REFERENCE / "batch-21-sources.json").read_text("utf-8"))
        self.assertEqual(len(source["sources"]), 27)
        self.assertEqual(accepted["sources"], source["sources"])
        data = files("alz_assessor").joinpath("data")
        current = json.loads(data.joinpath("batch-matrix-2026-11-06.27.json").read_text("utf-8"))
        previous = json.loads(data.joinpath("batch-matrix-2026-11-06.26.json").read_text("utf-8"))
        self.assertEqual(current["batches"][:-1], previous["batches"])
        self.assertEqual(current["sources"][:-1], previous["sources"])
        self.assertEqual(current["batches"][-1], self.matrix)
        self.assertEqual(current["sources"][-1], accepted)

    def test_registered_eight_independent_blank_decisions_and_every_prior_question(self):
        question = self.matrix["interview"]
        self.assertEqual(question, {"id": question["id"], **BANK[question["id"]]})
        report = self.fixture.report()
        response = prepare_interview(report, self.catalog, question["id"], SUB)
        self.assertEqual(response["bank_version"], BANK_VERSION)
        self.assertEqual(len(response["decisions"]), 8)
        self.assertTrue(all(d["outcome"] is None for d in response["decisions"]))
        for batch in self.matrix["preserved_delivery_batches"]:
            matrix = json.loads((REFERENCE / f"batch-{batch}.json").read_text("utf-8"))
            if "interview" in matrix:
                prior = matrix["interview"]
                self.assertEqual(prior, {"id": prior["id"], **BANK[prior["id"]]})
        with self.assertRaises(InputError):
            compile_interview(response, self.catalog, at=AT)

    def test_registered_scope_types_bounds_privacy_decisions_outputs_and_cli(self):
        self.fixture.test_explicit_storage_key_source_and_queue_table_types_without_defaults()
        self.fixture.test_selected_scope_unique_known_type_and_top_level_guards()
        self.fixture.test_over_bound_resources_and_wrong_kind_injected_facts_never_signal()
        self.fixture.test_policy_exact_supplied_join_uses_existing_interpreter_free_context()
        self.fixture.test_role_reference_not_effective_delegation_or_principal_retention()
        self.fixture.test_manual_assisted_tiers_stale_denied_unknown_never_verified()
        self.fixture.test_interview_selection_catalog_requirements_time_expiry_attribution_guards()
        self.fixture.test_all_outputs_trackers_human_confirmation_and_independent_exceptions()
        self.fixture.test_cli_candidate_and_local_session_atomic_save_privacy()

    def test_registered_session_atomicity_resume_expiry_and_injected_payload_minimization(self):
        bundle = self.fixture.bundle()
        for resource in bundle["resources"]:
            resource["properties"]["private_key_certificate_issuer_principal_incident"] = PRIVATE
        bundle["resources"][1]["properties"]["storageEncryptionSummary"]["keyvaulturi"] = PRIVATE
        session = ReviewSession(
            bundle, self.catalog, self.root / "registered", clock=lambda: AT, evidence_tiers=True
        )
        self.assertNotIn(PRIVATE, json.dumps(session.evidence))
        self.assertIn(PRIVATE, json.dumps(bundle))
        response = self.fixture.completed()
        partial = copy.deepcopy(response)
        partial["decisions"][-1]["outcome"] = None
        with self.assertRaises(InputError):
            session.save_interview({"revision": 0, "response": partial, "replace_existing": []})
        self.assertEqual(session.revision, 0)
        with patch.object(Path, "rename", side_effect=OSError("authored disk failure")):
            with self.assertRaisesRegex(OSError, "authored disk failure"):
                session.save_interview(
                    {"revision": 0, "response": response, "replace_existing": []}
                )
        self.assertEqual(session.revision, 0)
        session.save_interview({"revision": 0, "response": response, "replace_existing": []})
        for path in session.directory.rglob("*.json"):
            self.assertNotIn(PRIVATE, path.read_text("utf-8"))
        resumed = ReviewSession.resume(
            session.directory / "revision-0001", self.root / "resumed", clock=lambda: AT
        )
        self.assertEqual(semantic(resumed.report), semantic(session.report))
        self.assertNotIn(PRIVATE, json.dumps(resumed.state()))
        expired = assess(
            bundle, self.catalog, manual=session.reviews["manual"], at=UNTIL, evidence_tiers=True
        )
        self.assertTrue(
            all(
                r["observed"]["outcome"] == "manual"
                for r in expired["results"]
                if r["control_id"] in IDS
            )
        )

    def test_accepted_predecessor_private_original_time_replay_and_candidate_rejection(self):
        bundle = self.fixture.bundle()
        manual = compile_interview(self.fixture.completed(), self.catalog, at=AT)
        expected = assess(bundle, self.catalog, manual=manual, at=AT, evidence_tiers=True)
        export_bundle(
            self.root / "accepted", bundle, self.catalog, manual=manual, at=AT, evidence_tiers=True
        )
        replayed = replay_bundle(self.root / "accepted")
        self.assertEqual(semantic(replayed), semantic(expected))
        self.assertEqual(replayed["evidence"][0]["collected_at"], AT)
        for path in (self.root / "accepted").iterdir():
            self.assertNotIn(PRIVATE, path.read_text("utf-8"))
        export_bundle(self.root / "previous", bundle, self.previous, at=AT, evidence_tiers=True)
        self.assertEqual(
            semantic(replay_bundle(self.root / "previous")),
            semantic(assess(bundle, self.previous, at=AT, evidence_tiers=True)),
        )
        with self.assertRaises(InputError):
            compile_interview(self.fixture.completed(), self.previous, at=AT)
        changed = copy.deepcopy(self.catalog)
        next(c for c in changed["controls"] if c["upstream_id"] == "G02.05")[
            "evidence_requirements"
        ].append("Unaccepted changed requirement")
        with self.assertRaises(InputError):
            export_bundle(self.root / "changed", bundle, changed, at=AT)

    def test_crosswalk_exact_successor_binding_and_unchanged_query_execution_set(self):
        data = files("alz_assessor").joinpath("data")
        frozen = data.joinpath("crosswalk-2026-11-06.27.json")
        current = load_crosswalk(self.catalog, Path(str(frozen)) if frozen.is_file() else None)
        previous = load_crosswalk(
            self.previous, Path(str(data.joinpath("crosswalk-2026-11-06.26.json")))
        )
        self.assertEqual(current["crosswalk_version"], "2026-11-06.27")
        self.assertEqual(len(current["entries"]), 255)
        self.assertEqual(current["sources"], previous["sources"])
        self.assertEqual(current["entries"], previous["entries"])
        allowlist = json.loads(data.joinpath("query-allowlist.json").read_text("utf-8"))
        display = {c["upstream_guid"]: c["upstream_id"] for c in self.catalog["controls"]}
        self.assertEqual(
            {display[q["guid"]] for q in allowlist["queries"] if q["allowed"]},
            {"D07.06", "D07.07"},
        )


if __name__ == "__main__":
    unittest.main()
