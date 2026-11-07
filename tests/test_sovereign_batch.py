import copy
import hashlib
import json
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path

import test_sovereign_preparation as preparation
from test_sovereign_preparation import AT, MG, OWN, PRIVATE, UNTIL

from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import control_digest, digest
from alz_assessor.crosswalk import load_crosswalk
from alz_assessor.engine import assess
from alz_assessor.interviews import BANK, BANK_VERSION, compile_interview, prepare_interview
from alz_assessor.replay import export_bundle, replay_bundle, semantic
from alz_assessor.review_session import ReviewSession
from alz_assessor.terraform import InputError

REFERENCE = Path(__file__).resolve().parents[1] / "references" / "recommendation-batches"


class SovereignBatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        frozen = files("alz_assessor").joinpath("data", "catalog-2026-11-06.22.json")
        self.catalog = load_catalog(str(frozen)) if frozen.is_file() else load_catalog()
        self.previous = load_catalog(
            str(files("alz_assessor").joinpath("data", "catalog-2026-11-06.21.json"))
        )
        self.matrix = json.loads((REFERENCE / "batch-09.json").read_text("utf-8"))
        self.fixture = preparation.SovereignPreparationTests()
        self.fixture.root = self.root
        self.fixture.catalog = lambda: self.catalog

    def test_exact_successor_seven_and_every_nonown_full_object_original_four(self):
        self.assertEqual(self.catalog["catalog_version"], "2026-11-06.22")
        self.assertEqual(self.matrix["catalog_version"], self.catalog["catalog_version"])
        self.assertEqual(self.matrix["review_state"], "owner-delegated-source-backed-matrix")
        rows = {r["guid"]: r for r in self.matrix["recommendations"]}
        self.assertEqual(set(rows), set(OWN.values()))
        prior = {c["control_id"]: c for c in self.previous["controls"]}
        for control in self.catalog["controls"]:
            if control["upstream_guid"] not in rows:
                self.assertEqual(control, prior[control["control_id"]])
                continue
            row = rows[control["upstream_guid"]]
            for key in ("recommendation", "upstream_guid", "upstream_id", "inventory_flags"):
                self.assertEqual(control[key], prior[control["control_id"]][key])
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
            raw = files("alz_assessor").joinpath("data", f"{kind}-2026-11-06.21.json").read_bytes()
            self.assertEqual(
                hashlib.sha256(raw).hexdigest(),
                self.matrix[f"preserved_{kind}_bytes"]["2026-11-06.21"],
            )

    def test_all196_prior_rows_23_receipts_fixed251_sources_and_matrix_chain(self):
        ledger = json.loads((REFERENCE / "ledger.json").read_text("utf-8"))
        earlier = set(self.matrix["preserved_delivery_batches"])
        rows = [r for r in ledger["recommendations"] if r["batch"] in earlier]
        receipts = {key: value for key, value in ledger["deliveries"].items() if key in earlier}
        self.assertEqual((len(rows), len(receipts)), (196, 23))
        self.assertEqual(digest(rows), self.matrix["preserved_merged_recommendations_sha256"])
        self.assertEqual(digest(receipts), self.matrix["preserved_delivery_receipts_sha256"])
        for row in rows:
            self.assertEqual(row["status"], "merged")
            self.assertEqual(row["pr"], receipts[row["batch"]]["pr"])
            self.assertEqual(row["merge_commit"], receipts[row["batch"]]["merge_commit"])
        self.assertEqual(len(ledger["recommendations"]), 251)
        own = [r for r in ledger["recommendations"] if r["batch"] == "09"]
        self.assertEqual({r["guid"] for r in own}, set(OWN.values()))
        for row in own:
            if row["status"] == "merged":
                self.assertEqual(row["pr"], ledger["deliveries"]["09"]["pr"])
                self.assertEqual(row["merge_commit"], ledger["deliveries"]["09"]["merge_commit"])
            else:
                self.assertEqual(row["status"], "implementation-in-progress")
                self.assertIsNone(row["merge_commit"])
        source = (REFERENCE.parent / "preparation" / "batch-09-sources.json").read_bytes()
        self.assertEqual(source, (REFERENCE / "batch-09-sources.json").read_bytes())
        self.assertEqual(len(json.loads(source)["sources"]), 17)
        current = json.loads(
            files("alz_assessor")
            .joinpath("data", "batch-matrix-2026-11-06.22.json")
            .read_text("utf-8")
        )
        previous = json.loads(
            files("alz_assessor")
            .joinpath("data", "batch-matrix-2026-11-06.21.json")
            .read_text("utf-8")
        )
        self.assertEqual(current["batches"][:-1], previous["batches"])
        self.assertEqual(current["sources"][:-1], previous["sources"])
        self.assertEqual(current["batches"][-1], self.matrix)
        self.assertEqual(current["sources"][-1], json.loads(source))

    def test_registered_blank_seven_decisions_and_every_prior_question(self):
        question = self.matrix["interview"]
        self.assertEqual(question, {"id": question["id"], **BANK[question["id"]]})
        report = assess(self.fixture.bundle(), self.catalog, at=AT, evidence_tiers=True)
        response = prepare_interview(report, self.catalog, question["id"], MG)
        self.assertEqual(response["bank_version"], BANK_VERSION)
        self.assertEqual(len(response["decisions"]), 7)
        self.assertTrue(all(d["outcome"] is None for d in response["decisions"]))
        self.assertTrue(
            all(
                response[k] is None
                for k in (
                    "answer",
                    "reviewer",
                    "rationale",
                    "evidence",
                    "valid_from",
                    "valid_until",
                )
            )
        )
        with self.assertRaises(InputError):
            compile_interview(response, self.catalog, at=AT)
        for batch in self.matrix["preserved_delivery_batches"]:
            matrix = json.loads((REFERENCE / f"batch-{batch}.json").read_text("utf-8"))
            if "interview" in matrix:
                prior = matrix["interview"]
                self.assertEqual(prior, {"id": prior["id"], **BANK[prior["id"]]})

    def test_registered_all_outputs_tiers_scope_unknowns_and_independent_exceptions(self):
        self.fixture.test_all_outputs_tiers_time_and_planned_observed_remain_separate()
        self.fixture.test_review_context_uses_same_strict_facts_and_only_requested_paths()
        self.fixture.test_denied_ambiguous_partial_and_over_bound_context_is_not_a_signal()
        self.fixture.test_session_exception_and_disk_failure_are_independent_and_atomic()
        self.fixture.test_cli_and_injected_collector_add_no_live_or_availability_transport()

    def test_registered_atomic_seven_decision_session_save_resume_and_expiry(self):
        bundle = self.fixture.bundle()
        session = ReviewSession(
            bundle, self.catalog, self.root / "registered", clock=lambda: AT, evidence_tiers=True
        )
        question = next(
            q for q in session.state()["interviews"] if q["id"] == self.matrix["interview"]["id"]
        )
        template = question["template"]
        self.assertEqual(len(template["decisions"]), 7)
        self.assertTrue(all(d["outcome"] is None for d in template["decisions"]))
        response = self.fixture.filled(template)
        invalid = copy.deepcopy(response)
        invalid["decisions"][-1]["outcome"] = None
        with self.assertRaises(InputError):
            session.save_interview({"revision": 0, "response": invalid, "replace_existing": []})
        self.assertEqual(session.revision, 0)
        with unittest.mock.patch.object(
            Path, "rename", side_effect=OSError("authored disk failure")
        ):
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
            all(r["observed"]["outcome"] == "manual" for r in self.fixture.own(expired))
        )
        self.assertTrue(
            all(
                r["observed"]["evidence_tier"] != "verified"
                for r in self.fixture.own(session.report)
            )
        )

    def test_accepted_and_predecessor_private_original_time_replay_rebinding_rejected(self):
        bundle = self.fixture.bundle()
        response = prepare_interview(
            assess(bundle, self.catalog, at=AT, evidence_tiers=True),
            self.catalog,
            self.matrix["interview"]["id"],
            MG,
        )
        manual = compile_interview(self.fixture.filled(response), self.catalog, at=AT)
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
            self.assertNotIn("Fixture", content)
        export_bundle(self.root / "prior", bundle, self.previous, at=AT, evidence_tiers=True)
        self.assertEqual(
            semantic(replay_bundle(self.root / "prior")),
            semantic(assess(bundle, self.previous, at=AT, evidence_tiers=True)),
        )
        old = assess(bundle, self.previous, manual=manual, at=AT, evidence_tiers=True)
        self.assertTrue(all(r["observed"]["outcome"] == "manual" for r in self.fixture.own(old)))
        with self.assertRaises(InputError):
            compile_interview(self.fixture.filled(response), self.previous, at=AT)
        changed = copy.deepcopy(self.catalog)
        next(c for c in changed["controls"] if c["upstream_guid"] in OWN.values())[
            "evidence_requirements"
        ].append("Changed requirement")
        with self.assertRaises(InputError):
            compile_interview(self.fixture.filled(response), changed, at=AT)

    def test_crosswalk_all255_unchanged_sources_and_exact_query_allowlist(self):
        frozen = files("alz_assessor").joinpath("data", "crosswalk-2026-11-06.22.json")
        current = load_crosswalk(self.catalog, Path(str(frozen)) if frozen.is_file() else None)
        prior = load_crosswalk(
            self.previous,
            Path(str(files("alz_assessor").joinpath("data", "crosswalk-2026-11-06.21.json"))),
        )
        self.assertEqual(current["crosswalk_version"], "2026-11-06.22")
        self.assertEqual(current["catalog_sha256"], digest(self.catalog))
        self.assertEqual(len(current["entries"]), 255)
        self.assertEqual(current["entries"], prior["entries"])
        self.assertEqual(current["sources"], prior["sources"])
        allowlist = json.loads(
            files("alz_assessor").joinpath("data", "query-allowlist.json").read_text("utf-8")
        )
        display = {c["upstream_guid"]: c["upstream_id"] for c in self.catalog["controls"]}
        self.assertEqual(
            {display[q["guid"]] for q in allowlist["queries"] if q["allowed"] is True},
            {"D07.06", "D07.07"},
        )

    def test_checked_delivery_receipt_binds_all_seven_to_actual_merged_implementation(self):
        ledger = json.loads((REFERENCE / "ledger.json").read_text("utf-8"))
        receipt = ledger["deliveries"]["09"]
        self.assertEqual(receipt["pr"], "https://github.com/jonathan-vella/landinglens/pull/152")
        self.assertEqual(receipt["checked_head"], "224090e0fc4e60d12080d800a01b40ad3fff536e")
        self.assertEqual(receipt["merge_commit"], "b5da05e9e3fb19873df201e66514be4b9114eadd")
        self.assertEqual(
            receipt["checks"],
            [
                "https://github.com/jonathan-vella/landinglens/actions/runs/42315872153",
                "https://github.com/jonathan-vella/landinglens/actions/runs/42315897641",
            ],
        )
        self.assertEqual(
            receipt["local_installed_suite"], {"tests": 747, "passed": 746, "skipped": 1}
        )
        self.assertEqual(
            receipt["wheel_sha256"],
            "6e3b14c0838ade2ab8c3bb6e318a5e90ed44befa162467a78899dcb33811c14c",
        )
        self.assertEqual(len(receipt["compiler_integration_cases"]), 20)
        prior_cases = ledger["deliveries"]["25"]["compiler_integration_cases"]
        self.assertEqual(receipt["compiler_integration_cases"][:-1], prior_cases)
        self.assertEqual(
            receipt["compiler_integration_cases"][-1],
            "test_sovereign_preparation.SovereignPreparationTests."
            "test_real_bicep_location_and_tag_configuration_without_restore",
        )
        earlier = set(self.matrix["preserved_delivery_batches"])
        historical_prefix = [r for r in ledger["recommendations"] if r["batch"] in earlier | {"09"}]
        self.assertEqual(len(historical_prefix), 203)
        self.assertTrue(all(r["status"] == "merged" for r in historical_prefix))
        own = [r for r in ledger["recommendations"] if r["batch"] == "09"]
        self.assertEqual({r["guid"] for r in own}, set(OWN.values()))
        for row in own:
            self.assertEqual(row["pr"], receipt["pr"])
            self.assertEqual(row["merge_commit"], receipt["merge_commit"])
            self.assertIn(
                "deliveries.09: all eight CI jobs and four compiler artifacts verified",
                row["runtime_evidence"],
            )


if __name__ == "__main__":
    unittest.main()
