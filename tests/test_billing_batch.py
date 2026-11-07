import copy
import hashlib
import json
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

import test_billing_preparation as preparation
from test_billing_preparation import AT, CONTROLS, OWN, PRIVATE, SUB, UNTIL

from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import control_digest, digest
from alz_assessor.crosswalk import load_crosswalk
from alz_assessor.engine import assess
from alz_assessor.interviews import BANK, BANK_VERSION, compile_interview, prepare_interview
from alz_assessor.replay import export_bundle, replay_bundle, semantic
from alz_assessor.review_session import ReviewSession
from alz_assessor.terraform import InputError

REFERENCE = Path(__file__).resolve().parents[1] / "references" / "recommendation-batches"


class BillingBatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        data = files("alz_assessor").joinpath("data")
        frozen = data.joinpath("catalog-2026-11-06.26.json")
        self.catalog = load_catalog(str(frozen)) if frozen.is_file() else load_catalog()
        self.previous = load_catalog(str(data.joinpath("catalog-2026-11-06.25.json")))
        self.matrix = json.loads((REFERENCE / "batch-03.json").read_text("utf-8"))
        self.fixture = preparation.BillingPreparationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.catalog = self.catalog

    def filled(self, response):
        response = copy.deepcopy(response)
        response.update(
            answer="Authored fixture only, not owner or financial assurance.",
            reviewer="Fixture",
            rationale="Independent source-specific decisions.",
            evidence="https://example.invalid/redacted",
            valid_from=AT,
            valid_until=UNTIL,
        )
        for i, decision in enumerate(response["decisions"]):
            decision["outcome"] = "pass" if i % 2 else "fail"
        return response

    def test_exact_successor_nonown_full_objects_original_four_and_frozen_bytes(self):
        self.assertEqual(self.catalog["catalog_version"], "2026-11-06.26")
        self.assertEqual(self.matrix["catalog_version"], self.catalog["catalog_version"])
        rows = {r["guid"]: r for r in self.matrix["recommendations"]}
        self.assertEqual(set(rows), set(OWN.values()))
        prior = {c["control_id"]: c for c in self.previous["controls"]}
        for control in self.catalog["controls"]:
            before = prior[control["control_id"]]
            if control["upstream_guid"] not in rows:
                self.assertEqual(control, before)
                continue
            row = rows[control["upstream_guid"]]
            for key in ("recommendation", "upstream_guid", "upstream_id", "inventory_flags"):
                self.assertEqual(control[key], before[key])
            self.assertEqual(control["evidence_requirements"], row["evidence_requirements"])
            self.assertEqual(control["rationale"], row["limitations"])
            self.assertEqual(control["automation"], row["classification"])
            self.assertIsNone(control["rule"])
        original = load_catalog(
            str(files("alz_assessor").joinpath("data", "catalog-2026-11-04.2.json"))
        )
        for control in original["controls"]:
            if control["automation"] == "automated":
                actual = next(
                    c for c in self.catalog["controls"] if c["control_id"] == control["control_id"]
                )
                self.assertEqual(actual, prior[actual["control_id"]])
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
            raw = files("alz_assessor").joinpath("data", f"{kind}-2026-11-06.25.json").read_bytes()
            self.assertEqual(
                hashlib.sha256(raw).hexdigest(),
                self.matrix[f"preserved_{kind}_bytes"]["2026-11-06.25"],
            )

    def test_all228_prior_rows27_receipts_fixed251_sources_and_matrix_chain(self):
        ledger = json.loads((REFERENCE / "ledger.json").read_text("utf-8"))
        earlier = set(self.matrix["preserved_delivery_batches"])
        rows = [r for r in ledger["recommendations"] if r["batch"] in earlier]
        receipts = {key: value for key, value in ledger["deliveries"].items() if key in earlier}
        self.assertEqual((len(rows), len(receipts)), (228, 27))
        self.assertEqual(digest(rows), self.matrix["preserved_merged_recommendations_sha256"])
        self.assertEqual(digest(receipts), self.matrix["preserved_delivery_receipts_sha256"])
        for row in rows:
            self.assertEqual(row["status"], "merged")
            self.assertEqual(row["pr"], receipts[row["batch"]]["pr"])
            self.assertEqual(row["merge_commit"], receipts[row["batch"]]["merge_commit"])
        self.assertEqual(len(ledger["recommendations"]), 251)
        own = [r for r in ledger["recommendations"] if r["batch"] == "03"]
        self.assertEqual({r["guid"] for r in own}, set(OWN.values()))
        for row in own:
            if row["status"] == "merged":
                self.assertEqual(row["pr"], ledger["deliveries"]["03"]["pr"])
                self.assertEqual(row["merge_commit"], ledger["deliveries"]["03"]["merge_commit"])
            else:
                self.assertEqual(row["status"], "implementation-in-progress")
                self.assertIsNone(row["merge_commit"])
        source = (REFERENCE.parent / "preparation" / "batch-03-sources.json").read_bytes()
        self.assertEqual(len(json.loads(source)["sources"]), 20)
        supplement = json.loads(
            (REFERENCE.parent / "preparation" / "batch-03-version-sources.json").read_text("utf-8")
        )
        self.assertEqual(len(supplement["sources"]), 3)
        accepted = json.loads((REFERENCE / "batch-03-sources.json").read_text("utf-8"))
        self.assertEqual(accepted["sources"], json.loads(source)["sources"] + supplement["sources"])
        data = files("alz_assessor").joinpath("data")
        current = json.loads(data.joinpath("batch-matrix-2026-11-06.26.json").read_text("utf-8"))
        previous = json.loads(data.joinpath("batch-matrix-2026-11-06.25.json").read_text("utf-8"))
        self.assertEqual(current["batches"][:-1], previous["batches"])
        self.assertEqual(current["sources"][:-1], previous["sources"])
        self.assertEqual(current["batches"][-1], self.matrix)
        self.assertEqual(current["sources"][-1], accepted)

    def test_registered_seven_blank_decisions_and_every_prior_question(self):
        question = self.matrix["interview"]
        self.assertEqual(question, {"id": question["id"], **BANK[question["id"]]})
        report = assess(self.fixture.bundle(), self.catalog, at=AT, evidence_tiers=True)
        response = prepare_interview(report, self.catalog, question["id"], SUB)
        self.assertEqual(response["bank_version"], BANK_VERSION)
        self.assertEqual(len(response["decisions"]), 7)
        self.assertTrue(all(d["outcome"] is None for d in response["decisions"]))
        for batch in self.matrix["preserved_delivery_batches"]:
            matrix = json.loads((REFERENCE / f"batch-{batch}.json").read_text("utf-8"))
            if "interview" in matrix:
                prior = matrix["interview"]
                self.assertEqual(prior, {"id": prior["id"], **BANK[prior["id"]]})
        with self.assertRaises(InputError):
            compile_interview(response, self.catalog, at=AT)

    def test_registered_scope_types_bounds_privacy_decisions_outputs_and_cli(self):
        self.fixture.test_explicit_metadata_only_no_defaults_financial_or_recipient_payload()
        self.fixture.test_notification_shapes_types_five_bound_and_no_threshold_predicate()
        self.fixture.test_api_version_qualification_provider_conflict_and_no_forecast_defaults()
        self.fixture.test_unique_known_typed_selected_scope_relationship_required()
        self.fixture.test_no_whole_pass_or_verified_or_other_six_machine_signals()
        self.fixture.test_interview_selection_binding_time_attribution_and_independent_exceptions()
        self.fixture.test_cli_saved_evidence_uses_same_seven_workflows()

    def test_registered_session_atomicity_resume_expiry_and_injected_privacy(self):
        bundle = self.fixture.bundle()
        session = ReviewSession(
            bundle, self.catalog, self.root / "registered", clock=lambda: AT, evidence_tiers=True
        )
        question = next(
            q for q in session.state()["interviews"] if q["id"] == self.matrix["interview"]["id"]
        )
        response = self.filled(question["template"])
        invalid = copy.deepcopy(response)
        invalid["decisions"][-1]["outcome"] = None
        with self.assertRaises(InputError):
            session.save_interview({"revision": 0, "response": invalid, "replace_existing": []})
        self.assertEqual(session.revision, 0)
        with patch.object(Path, "rename", side_effect=OSError("authored disk failure")):
            with self.assertRaisesRegex(OSError, "authored disk failure"):
                session.save_interview(
                    {"revision": 0, "response": response, "replace_existing": []}
                )
        self.assertEqual(session.revision, 0)
        session.save_interview({"revision": 0, "response": response, "replace_existing": []})
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
                if r["control_id"] in CONTROLS
            )
        )
        self.fixture.test_injected_budget_payload_is_minimized_before_session_persistence()

    def test_accepted_predecessor_private_original_time_replay_and_candidate_rejection(self):
        bundle = self.fixture.bundle()
        response = prepare_interview(
            assess(bundle, self.catalog, at=AT, evidence_tiers=True),
            self.catalog,
            self.matrix["interview"]["id"],
            SUB,
        )
        manual = compile_interview(self.filled(response), self.catalog, at=AT)
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
            compile_interview(response, self.previous, at=AT)
        changed = copy.deepcopy(self.catalog)
        next(c for c in changed["controls"] if c["upstream_id"] == "A03.03")[
            "evidence_requirements"
        ].append("Unaccepted changed requirement")
        with self.assertRaises(InputError):
            export_bundle(self.root / "changed", bundle, changed, at=AT)

    def test_crosswalk_exact_successor_binding_and_unchanged_query_execution_set(self):
        data = files("alz_assessor").joinpath("data")
        frozen = data.joinpath("crosswalk-2026-11-06.26.json")
        current = load_crosswalk(self.catalog, Path(str(frozen)) if frozen.is_file() else None)
        previous = load_crosswalk(
            self.previous, Path(str(data.joinpath("crosswalk-2026-11-06.25.json")))
        )
        self.assertEqual(current["crosswalk_version"], "2026-11-06.26")
        self.assertEqual(len(current["entries"]), 255)
        self.assertEqual(current["sources"], previous["sources"])
        self.assertEqual(current["entries"], previous["entries"])
        allowlist = json.loads(data.joinpath("query-allowlist.json").read_text("utf-8"))
        display = {c["upstream_guid"]: c["upstream_id"] for c in self.catalog["controls"]}
        self.assertEqual(
            {display[q["guid"]] for q in allowlist["queries"] if q["allowed"]}, {"D07.06", "D07.07"}
        )
