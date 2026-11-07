import copy
import hashlib
import json
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path

import test_platform_health_preparation as preparation
from test_platform_health_preparation import (
    AT,
    GUIDS,
    IDS,
    PRIVATE,
    REFERENCE,
    SCOPE,
)

from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import control_digest, digest
from alz_assessor.crosswalk import load_crosswalk
from alz_assessor.engine import assess
from alz_assessor.interviews import BANK, BANK_VERSION, compile_interview, prepare_interview
from alz_assessor.replay import export_bundle, replay_bundle, semantic
from alz_assessor.review_session import ReviewSession
from alz_assessor.terraform import InputError


class PlatformHealthBatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        frozen = files("alz_assessor").joinpath("data", "catalog-2026-11-06.21.json")
        self.catalog = load_catalog(str(frozen)) if frozen.is_file() else load_catalog()
        self.previous = load_catalog(
            str(files("alz_assessor").joinpath("data", "catalog-2026-11-06.20.json"))
        )
        self.matrix = json.loads((REFERENCE / "batch-25.json").read_text("utf-8"))
        self.fixture = preparation.PlatformHealthPreparationTests()
        self.fixture.root = self.root
        self.fixture.catalog = self.catalog
        self.fixture.accepted = self.previous
        self.fixture.matrix = self.matrix
        self.fixture.question = self.matrix["interview"]["id"]

    def test_successor_nine_guids_nonown_complete_objects_and_original_four(self):
        self.assertEqual(self.catalog["catalog_version"], "2026-11-06.21")
        self.assertEqual(self.matrix["catalog_version"], self.catalog["catalog_version"])
        self.assertEqual(self.matrix["review_state"], "owner-delegated-source-backed-matrix")
        rows = {r["guid"]: r for r in self.matrix["recommendations"]}
        self.assertEqual(set(rows), GUIDS)
        prior = {c["control_id"]: c for c in self.previous["controls"]}
        for control in self.catalog["controls"]:
            if control["control_id"] not in IDS:
                self.assertEqual(control, prior[control["control_id"]])
                continue
            row = rows[control["upstream_guid"]]
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
            raw = files("alz_assessor").joinpath("data", f"{kind}-2026-11-06.20.json").read_bytes()
            self.assertEqual(
                hashlib.sha256(raw).hexdigest(),
                self.matrix[f"preserved_{kind}_bytes"]["2026-11-06.20"],
            )

    def test_all187_prior_rows_22_receipts_fixed251_sources_and_matrix_chain_are_preserved(self):
        ledger = json.loads((REFERENCE / "ledger.json").read_text("utf-8"))
        earlier = set(self.matrix["preserved_delivery_batches"])
        rows = [r for r in ledger["recommendations"] if r["batch"] in earlier]
        receipts = {key: value for key, value in ledger["deliveries"].items() if key in earlier}
        self.assertEqual((len(rows), len(receipts)), (187, 22))
        self.assertEqual(digest(rows), self.matrix["preserved_merged_recommendations_sha256"])
        self.assertEqual(digest(receipts), self.matrix["preserved_delivery_receipts_sha256"])
        for row in rows:
            self.assertEqual(row["status"], "merged")
            self.assertEqual(row["pr"], receipts[row["batch"]]["pr"])
            self.assertEqual(row["merge_commit"], receipts[row["batch"]]["merge_commit"])
        self.assertEqual(len(ledger["recommendations"]), 251)
        own = [r for r in ledger["recommendations"] if r["batch"] == "25"]
        self.assertEqual({r["guid"] for r in own}, GUIDS)
        for row in own:
            if row["status"] == "merged":
                self.assertEqual(row["pr"], ledger["deliveries"]["25"]["pr"])
                self.assertEqual(row["merge_commit"], ledger["deliveries"]["25"]["merge_commit"])
            else:
                self.assertEqual(row["status"], "implementation-in-progress")
                self.assertIsNone(row["merge_commit"])
        source = (REFERENCE / "preparation-25-sources.json").read_bytes()
        self.assertEqual(source, (REFERENCE / "batch-25-sources.json").read_bytes())
        self.assertEqual(len(json.loads(source)["sources"]), 30)
        current = json.loads(
            files("alz_assessor")
            .joinpath("data", "batch-matrix-2026-11-06.21.json")
            .read_text("utf-8")
        )
        previous = json.loads(
            files("alz_assessor")
            .joinpath("data", "batch-matrix-2026-11-06.20.json")
            .read_text("utf-8")
        )
        self.assertEqual(current["batches"][:-1], previous["batches"])
        self.assertEqual(current["sources"][:-1], previous["sources"])
        self.assertEqual(current["batches"][-1], self.matrix)
        self.assertEqual(current["sources"][-1], json.loads(source))

    def test_registered_bank_nine_independent_blank_decisions_and_all_prior_questions(self):
        question = self.matrix["interview"]
        self.assertEqual(question, {"id": question["id"], **BANK[question["id"]]})
        report = self.fixture.report()
        response = prepare_interview(report, self.catalog, question["id"], SCOPE)
        self.assertEqual(response["bank_version"], BANK_VERSION)
        self.assertEqual(len(response["decisions"]), 9)
        self.assertTrue(all(d["outcome"] is None for d in response["decisions"]))
        with self.assertRaises(InputError):
            compile_interview(response, self.catalog, at=AT)
        for batch in self.matrix["preserved_delivery_batches"]:
            matrix = json.loads((REFERENCE / f"batch-{batch}.json").read_text("utf-8"))
            if "interview" in matrix:
                prior = matrix["interview"]
                self.assertEqual(prior, {"id": prior["id"], **BANK[prior["id"]]})

    def test_registered_outputs_exceptions_configuration_and_policy_are_not_operational_proof(self):
        self.fixture.test_all_outputs_human_confirmation_and_independent_exceptions()
        self.fixture.test_tiers_scope_partial_unknown_denied_stale_never_verified()
        self.fixture.test_amba_reuses_policy_joins_at_subscription_and_management_group_scope()
        self.fixture.test_wrong_kind_facts_truncation_and_no_coverage_from_absence()
        self.fixture.test_independent_selection_and_changed_requirements_cannot_rebind()

    def test_registered_session_atomic_interview_save_resume_and_expired_replay(self):
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
        response = self.fixture.completed()
        invalid = copy.deepcopy(response)
        invalid["decisions"][-1]["outcome"] = None
        with self.assertRaises(InputError):
            session.save_interview({"revision": 0, "response": invalid, "replace_existing": []})
        self.assertEqual(session.revision, 0)
        session.save_interview({"revision": 0, "response": response, "replace_existing": []})
        resumed = ReviewSession.resume(
            session.directory / "revision-0001", self.root / "resumed", clock=lambda: AT
        )
        self.assertEqual(semantic(resumed.report), semantic(session.report))
        self.assertNotIn(PRIVATE, json.dumps(resumed.state()))
        expired = copy.deepcopy(response)
        expired["valid_until"] = "2026-11-05T00:00:00Z"
        with self.assertRaises(InputError):
            compile_interview(expired, self.catalog, at=AT)

    def test_accepted_and_predecessor_private_original_time_replay_and_refused_rebinding(self):
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
            content = path.read_text("utf-8")
            self.assertNotIn(PRIVATE, content)
            self.assertNotIn("Authored test reviewer", content)
        export_bundle(self.root / "prior", bundle, self.previous, at=AT, evidence_tiers=True)
        self.assertEqual(
            semantic(replay_bundle(self.root / "prior")),
            semantic(assess(bundle, self.previous, at=AT, evidence_tiers=True)),
        )
        changed = copy.deepcopy(self.catalog)
        next(c for c in changed["controls"] if c["control_id"] in IDS)[
            "evidence_requirements"
        ].append("Changed requirement")
        with self.assertRaises(InputError):
            compile_interview(self.fixture.completed(), changed, at=AT)

    def test_crosswalk_binds_all255_without_broadening_query_execution(self):
        current = files("alz_assessor").joinpath("data", "crosswalk-2026-11-06.21.json")
        crosswalk = load_crosswalk(self.catalog, Path(str(current)) if current.is_file() else None)
        self.assertEqual(crosswalk["crosswalk_version"], "2026-11-06.21")
        self.assertEqual(len(crosswalk["entries"]), 255)
        self.assertEqual(crosswalk["catalog_sha256"], digest(self.catalog))
        before = load_crosswalk(
            self.previous,
            Path(str(files("alz_assessor").joinpath("data", "crosswalk-2026-11-06.20.json"))),
        )
        self.assertEqual(crosswalk["entries"], before["entries"])
