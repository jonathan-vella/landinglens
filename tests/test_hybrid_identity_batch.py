import contextlib
import copy
import hashlib
import json
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path

import test_hybrid_identity_preparation as preparation
from test_hybrid_identity_preparation import AT, OWN, PRIVATE, SUB

from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import control_digest, digest
from alz_assessor.crosswalk import load_crosswalk
from alz_assessor.engine import assess
from alz_assessor.interviews import BANK, BANK_VERSION, compile_interview, prepare_interview
from alz_assessor.replay import export_bundle, replay_bundle, semantic
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import validate_reviews
from alz_assessor.terraform import InputError

REFERENCE = preparation.ROOT / "references" / "recommendation-batches"
IDS = {"ALZ-" + guid for guid in OWN.values()}


class HybridIdentityBatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        frozen = files("alz_assessor").joinpath("data", "catalog-2026-11-06.19.json")
        self.catalog = load_catalog(str(frozen)) if frozen.is_file() else load_catalog()
        self.previous = load_catalog(
            str(files("alz_assessor").joinpath("data", "catalog-2026-11-06.18.json"))
        )
        self.matrix = json.loads((REFERENCE / "batch-06.json").read_text("utf-8"))
        self.fixture = preparation.HybridIdentityPreparationTests()
        self.fixture.root = self.root
        self.fixture.catalog = lambda: self.catalog
        self.fixture.matrix = lambda: self.matrix
        self.fixture.interview = lambda report, catalog: (
            contextlib.nullcontext(),
            self.matrix["interview"]["id"],
        )

    def completed(self):
        report = assess(self.fixture.bundle(), self.catalog, at=AT, evidence_tiers=True)
        response = prepare_interview(report, self.catalog, self.matrix["interview"]["id"], SUB)
        response.update(
            answer="Authored fixture, not owner approval.",
            reviewer="Authored fixture reviewer",
            rationale="Eight independent source-specific fixture decisions.",
            evidence="https://example.invalid/hybrid-review",
            valid_from=AT,
            valid_until=preparation.UNTIL,
        )
        for decision in response["decisions"]:
            decision["outcome"] = "fail"
        return response

    def test_exact_successor_controls_nonown_full_objects_and_original_four_unchanged(self):
        self.assertEqual(self.catalog["catalog_version"], "2026-11-06.19")
        self.assertEqual(self.matrix["catalog_version"], self.catalog["catalog_version"])
        self.assertEqual(self.matrix["review_state"], "owner-delegated-source-backed-matrix")
        updates = {r["guid"]: r for r in self.matrix["recommendations"]}
        self.assertEqual({r["upstream_id"]: r["guid"] for r in updates.values()}, OWN)
        before = {c["control_id"]: c for c in self.previous["controls"]}
        for control in self.catalog["controls"]:
            if control["control_id"] not in IDS:
                self.assertEqual(control, before[control["control_id"]])
                continue
            row = updates[control["upstream_guid"]]
            self.assertEqual(control["evidence_requirements"], row["evidence_requirements"])
            self.assertEqual(control["rationale"], row["limitations"])
            self.assertEqual(control["automation"], row["classification"])
            self.assertIsNone(control["rule"])
        baseline = load_catalog(
            str(files("alz_assessor").joinpath("data", "catalog-2026-11-04.2.json"))
        )
        for original in baseline["controls"]:
            if original["automation"] == "automated":
                actual = next(
                    c for c in self.catalog["controls"] if c["control_id"] == original["control_id"]
                )
                self.assertEqual(
                    actual,
                    next(
                        c
                        for c in self.previous["controls"]
                        if c["control_id"] == original["control_id"]
                    ),
                )
                self.assertEqual(control_digest(actual), control_digest(original))
        for kind in ("catalog", "crosswalk"):
            raw = files("alz_assessor").joinpath("data", kind + "-2026-11-06.18.json").read_bytes()
            self.assertEqual(
                hashlib.sha256(raw).hexdigest(),
                self.matrix["preserved_" + kind + "_bytes"]["2026-11-06.18"],
            )
        self.assertEqual(len(self.catalog["controls"]), 255)
        self.assertEqual(
            {
                key: sum(c["automation"] == key for c in self.catalog["controls"])
                for key in ("automated", "assisted", "manual")
            },
            {"automated": 12, "assisted": 200, "manual": 43},
        )

    def test_all169_prior_own_rows_twenty_receipts_and_original_sources_preserved(self):
        ledger = json.loads((REFERENCE / "ledger.json").read_text("utf-8"))
        earlier = set(self.matrix["preserved_delivery_batches"])
        rows = [r for r in ledger["recommendations"] if r["batch"] in earlier]
        receipts = {key: value for key, value in ledger["deliveries"].items() if key in earlier}
        self.assertEqual((len(rows), len(receipts)), (169, 20))
        self.assertEqual(digest(rows), self.matrix["preserved_merged_recommendations_sha256"])
        self.assertEqual(digest(receipts), self.matrix["preserved_delivery_receipts_sha256"])
        for row in rows:
            self.assertEqual(row["status"], "merged")
            self.assertEqual(row["pr"], receipts[row["batch"]]["pr"])
            self.assertEqual(row["merge_commit"], receipts[row["batch"]]["merge_commit"])
        self.assertEqual(len(ledger["recommendations"]), 251)
        source = (preparation.PREPARATION / "batch-06-sources.json").read_bytes()
        self.assertEqual(source, (REFERENCE / "batch-06-sources.json").read_bytes())
        self.assertEqual(len(json.loads(source)["sources"]), 20)
        current = json.loads(
            files("alz_assessor")
            .joinpath("data", "batch-matrix-2026-11-06.19.json")
            .read_text("utf-8")
        )
        previous = json.loads(
            files("alz_assessor")
            .joinpath("data", "batch-matrix-2026-11-06.18.json")
            .read_text("utf-8")
        )
        self.assertEqual(current["batches"][:-1], previous["batches"])
        self.assertEqual(current["sources"][:-1], previous["sources"])
        self.assertEqual(current["batches"][-1], self.matrix)
        self.assertEqual(current["sources"][-1], json.loads(source))

    def test_real_registered_bank_selection_eight_blank_decisions_and_bound_attribution(self):
        question = self.matrix["interview"]
        self.assertEqual(question, {"id": question["id"], **BANK[question["id"]]})
        report = assess(self.fixture.bundle(), self.catalog, at=AT, evidence_tiers=True)
        response = prepare_interview(report, self.catalog, question["id"], SUB)
        self.assertEqual(response["bank_version"], BANK_VERSION)
        self.assertEqual(len(response["decisions"]), 8)
        self.assertTrue(all(d["outcome"] is None for d in response["decisions"]))
        self.fixture.test_eight_independent_blank_interview_decisions_binding_and_attribution()
        self.fixture.test_interview_selection_and_expired_decisions_are_not_inferred()

    def test_real_source_specific_typed_context_all_outputs_and_never_technical_verified(self):
        self.fixture.test_review_selection_context_is_partial_and_does_not_designate_roles()
        self.fixture.test_one_engine_tiers_all_outputs_time_and_planned_observed_separation()
        self.fixture.test_peering_requires_both_unique_known_typed_in_boundary_vnets()
        self.fixture.test_vault_boolean_types_no_default_and_no_cross_kind_fact()
        self.fixture.test_missing_and_over_bound_population_not_absence()
        self.fixture.test_saved_mg_edges_are_required_not_bare_management_scope()

    def test_real_session_registered_preparation_independent_exceptions_atomicity_and_resume(self):
        session = ReviewSession(
            self.fixture.bundle(),
            self.catalog,
            self.root / "registered",
            clock=lambda: AT,
            evidence_tiers=True,
        )
        question = next(
            q for q in session.state()["interviews"] if q["id"] == self.matrix["interview"]["id"]
        )
        self.assertTrue(all(d["outcome"] is None for d in question["template"]["decisions"]))
        session.save_interview(
            {"revision": 0, "response": self.completed(), "replace_existing": []}
        )
        restored = ReviewSession.resume(
            session.directory / "revision-0001", self.root / "resumed", clock=lambda: AT
        )
        self.assertEqual(semantic(restored.report), semantic(session.report))
        self.fixture.test_session_exception_is_independent_and_replacement_atomic()
        self.fixture.test_session_disk_failure_preserves_eight_blank_decisions_and_prior_revision()

    def test_packaged_successor_replay_preserves_signals_bound_manual_decisions_and_original_time(
        self,
    ):
        bundle = self.fixture.bundle()
        manual = compile_interview(self.completed(), self.catalog, at=AT)
        expected = assess(bundle, self.catalog, manual=manual, at=AT, evidence_tiers=True)
        export_bundle(
            self.root / "accepted", bundle, self.catalog, manual=manual, at=AT, evidence_tiers=True
        )
        replayed = replay_bundle(self.root / "accepted")
        self.assertEqual(semantic(replayed), semantic(expected))
        self.assertEqual(replayed["evidence"][0]["collected_at"], AT)
        self.assertTrue(
            all(r["observed"]["evidence_tier"] != "verified" for r in self.fixture.own(replayed))
        )
        for path in (self.root / "accepted").iterdir():
            content = path.read_text("utf-8")
            self.assertNotIn(PRIVATE, content)
            self.assertNotIn("Authored fixture reviewer", content)
        changed = copy.deepcopy(self.catalog)
        next(c for c in changed["controls"] if c["control_id"] in IDS)["rationale"] += " Changed."
        with self.assertRaises(InputError):
            export_bundle(self.root / "unaccepted", bundle, changed, at=AT)

    def test_predecessor_replay_does_not_acquire_new_review_meaning(self):
        bundle = self.fixture.bundle()
        before = assess(bundle, self.previous, at=AT, evidence_tiers=True)
        export_bundle(self.root / "previous", bundle, self.previous, at=AT, evidence_tiers=True)
        self.assertEqual(semantic(replay_bundle(self.root / "previous")), semantic(before))
        self.assertTrue(
            all(
                r["observed"]["evidence_tier"] in {"needs_decision", "manual"}
                for r in self.fixture.own(before)
            )
        )
        manual = compile_interview(self.completed(), self.catalog, at=AT)
        self.assertFalse(validate_reviews(manual, self.previous, SUB, AT)["ready_to_apply"])

    def test_real_cli_and_crosswalk_associations_do_not_expand_query_execution(self):
        self.fixture.test_cli_preparation_uses_existing_engine_without_transport_or_query()
        frozen = files("alz_assessor").joinpath("data", "crosswalk-2026-11-06.19.json")
        crosswalk = load_crosswalk(
            catalog=self.catalog, path=Path(str(frozen)) if frozen.is_file() else None
        )
        own = [r for r in crosswalk["entries"] if r["guid"] in OWN.values()]
        self.assertEqual(len(own), 8)
        self.assertEqual(sum(bool(r["targets"]) for r in own), 2)
        self.assertTrue(all(t["strength"] != "equivalent" for r in own for t in r["targets"]))


if __name__ == "__main__":
    unittest.main()
