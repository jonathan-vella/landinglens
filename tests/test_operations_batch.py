import copy
import hashlib
import json
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

import test_operations_preparation as preparation
from test_operations_preparation import AT, CONTROLS, PRIVATE, SCOPE

from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import control_digest, digest
from alz_assessor.crosswalk import load_crosswalk
from alz_assessor.engine import assess
from alz_assessor.interviews import BANK, BANK_VERSION, compile_interview, prepare_interview
from alz_assessor.operations_evidence import GUIDS
from alz_assessor.replay import export_bundle, replay_bundle, semantic
from alz_assessor.review_session import ReviewSession
from alz_assessor.terraform import InputError

REFERENCE = Path(__file__).resolve().parents[1] / "references/recommendation-batches"


class OperationsBatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        frozen = files("alz_assessor").joinpath("data", "catalog-2026-11-06.23.json")
        self.catalog = load_catalog(str(frozen)) if frozen.is_file() else load_catalog()
        self.previous = preparation.previous_catalog()
        self.matrix = json.loads((REFERENCE / "batch-24.json").read_text("utf-8"))
        self.fixture = preparation.OperationsPreparationTests()
        self.fixture.root = self.root
        self.fixture.catalog = self.catalog
        self.fixture.matrix = self.matrix

    def test_exact_nine_successor_nonown_full_objects_original_four_and_frozen_bytes(self):
        self.assertEqual(self.catalog["catalog_version"], "2026-11-06.23")
        self.assertEqual(self.matrix["catalog_version"], self.catalog["catalog_version"])
        self.assertEqual(self.matrix["review_state"], "owner-delegated-source-backed-matrix")
        rows = {r["guid"]: r for r in self.matrix["recommendations"]}
        self.assertEqual(set(rows), GUIDS)
        prior = {c["control_id"]: c for c in self.previous["controls"]}
        for control in self.catalog["controls"]:
            previous = prior[control["control_id"]]
            if control["upstream_guid"] not in GUIDS:
                self.assertEqual(control, previous)
                continue
            row = rows[control["upstream_guid"]]
            for key in ("recommendation", "upstream_guid", "upstream_id", "inventory_flags"):
                self.assertEqual(control[key], previous[key])
            for key in ("evidence_requirements", "review_resource_types", "review_fact_paths"):
                self.assertEqual(control[key], row[key])
            self.assertEqual(control["rationale"], row["limitations"])
            self.assertEqual(control["automation"], "assisted")
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
            raw = files("alz_assessor").joinpath("data", f"{kind}-2026-11-06.22.json").read_bytes()
            self.assertEqual(
                hashlib.sha256(raw).hexdigest(),
                self.matrix[f"preserved_{kind}_bytes"]["2026-11-06.22"],
            )

    def test_all203_prior_rows_24_receipts_fixed251_and_exact_preparation_sources(self):
        ledger = json.loads((REFERENCE / "ledger.json").read_text("utf-8"))
        earlier = set(self.matrix["preserved_delivery_batches"])
        rows = [r for r in ledger["recommendations"] if r["batch"] in earlier]
        receipts = {key: value for key, value in ledger["deliveries"].items() if key in earlier}
        self.assertEqual((len(rows), len(receipts)), (203, 24))
        self.assertEqual(digest(rows), self.matrix["preserved_merged_recommendations_sha256"])
        self.assertEqual(digest(receipts), self.matrix["preserved_delivery_receipts_sha256"])
        for row in rows:
            self.assertEqual(row["status"], "merged")
            self.assertEqual(row["pr"], receipts[row["batch"]]["pr"])
            self.assertEqual(row["merge_commit"], receipts[row["batch"]]["merge_commit"])
        self.assertEqual(len(ledger["recommendations"]), 251)
        own = [r for r in ledger["recommendations"] if r["batch"] == "24"]
        self.assertEqual({r["guid"] for r in own}, GUIDS)
        for row in own:
            if row["status"] == "merged":
                self.assertEqual(row["pr"], ledger["deliveries"]["24"]["pr"])
                self.assertEqual(row["merge_commit"], ledger["deliveries"]["24"]["merge_commit"])
            else:
                self.assertEqual(row["status"], "implementation-in-progress")
                self.assertIsNone(row["merge_commit"])
        source = (REFERENCE / "preparation-24-sources.json").read_bytes()
        self.assertEqual(source, (REFERENCE / "batch-24-sources.json").read_bytes())
        self.assertEqual(len(json.loads(source)["sources"]), 42)
        current = json.loads(
            files("alz_assessor")
            .joinpath("data", "batch-matrix-2026-11-06.23.json")
            .read_text("utf-8")
        )
        previous = json.loads(
            files("alz_assessor")
            .joinpath("data", "batch-matrix-2026-11-06.22.json")
            .read_text("utf-8")
        )
        self.assertEqual(current["batches"][:-1], previous["batches"])
        self.assertEqual(current["sources"][:-1], previous["sources"])
        self.assertEqual(current["batches"][-1], self.matrix)
        self.assertEqual(current["sources"][-1], json.loads(source))

    def test_registered_nine_independent_blank_decisions_and_all_prior_questions(self):
        question = self.matrix["interview"]
        self.assertEqual(question, {"id": question["id"], **BANK[question["id"]]})
        report = assess(self.fixture.bundle(), self.catalog, at=AT, evidence_tiers=True)
        response = prepare_interview(report, self.catalog, question["id"], SCOPE)
        self.assertEqual(response["bank_version"], BANK_VERSION)
        self.assertEqual(len(response["decisions"]), 9)
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

    def test_registered_source_qualified_facts_thresholds_scope_privacy_and_all_outputs(self):
        self.fixture.test_all_nine_workflows_are_signals_never_whole_passes()
        self.fixture.test_exact_retention_units_analytics_total_and_discrete_provider_boundaries()
        self.fixture.test_arc_os_type_profile_ambiguity_and_terraform_unsupported_no_fake_fields()
        self.fixture.test_missing_duplicate_wrong_kind_out_of_scope_denied_and_overbound_no_signal()
        self.fixture.test_typed_relationships_require_known_unique_machine_workspace_storage()
        self.fixture.test_review_binding_atomicity_time_expiry_outputs_and_session_resume()
        self.fixture.test_cli_saved_evidence_uses_same_workflows_without_accepted_activation()

    def filled(self, response):
        response = copy.deepcopy(response)
        response.update(
            answer="Authored fixture, not owner assurance.",
            reviewer="Fixture",
            rationale="Nine independent authored decisions.",
            evidence="https://example.invalid/redacted",
            valid_from=AT,
            valid_until="2026-11-07T23:30:00Z",
        )
        for index, decision in enumerate(response["decisions"]):
            decision["outcome"] = "pass" if index % 2 else "fail"
        return response

    def test_registered_session_atomic_disk_failure_and_original_time_resume(self):
        bundle = self.fixture.bundle()
        session = ReviewSession(
            bundle, self.catalog, self.root / "registered", clock=lambda: AT, evidence_tiers=True
        )
        question = next(
            q for q in session.state()["interviews"] if q["id"] == self.matrix["interview"]["id"]
        )
        self.assertTrue(all(d["outcome"] is None for d in question["template"]["decisions"]))
        response = self.filled(question["template"])
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
            bundle,
            self.catalog,
            manual=session.reviews["manual"],
            at="2026-11-08T23:30:00Z",
            evidence_tiers=True,
        )
        self.assertTrue(
            all(
                r["observed"]["evidence_tier"] != "verified"
                for r in expired["results"]
                if r["control_id"] in CONTROLS
            )
        )

    def test_accepted_and_predecessor_private_original_time_replay_rebinding_rejected(self):
        bundle = self.fixture.bundle()
        response = prepare_interview(
            assess(bundle, self.catalog, at=AT, evidence_tiers=True),
            self.catalog,
            self.matrix["interview"]["id"],
            SCOPE,
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
        export_bundle(self.root / "prior", bundle, self.previous, at=AT, evidence_tiers=True)
        self.assertEqual(
            semantic(replay_bundle(self.root / "prior")),
            semantic(assess(bundle, self.previous, at=AT, evidence_tiers=True)),
        )
        old = assess(bundle, self.previous, manual=manual, at=AT, evidence_tiers=True)
        self.assertTrue(
            all(
                r["observed"]["outcome"] == "manual"
                for r in old["results"]
                if r["control_id"] in CONTROLS
            )
        )
        with self.assertRaises(InputError):
            compile_interview(self.filled(response), self.previous, at=AT)
        changed = copy.deepcopy(self.catalog)
        next(c for c in changed["controls"] if c["upstream_guid"] in GUIDS)[
            "evidence_requirements"
        ].append("Changed requirement")
        with self.assertRaises(InputError):
            compile_interview(self.filled(response), changed, at=AT)

    def test_crosswalk_all255_unchanged_sources_and_exact_query_allowlist(self):
        frozen = files("alz_assessor").joinpath("data", "crosswalk-2026-11-06.23.json")
        current = load_crosswalk(self.catalog, Path(str(frozen)) if frozen.is_file() else None)
        prior = load_crosswalk(
            self.previous,
            Path(str(files("alz_assessor").joinpath("data", "crosswalk-2026-11-06.22.json"))),
        )
        self.assertEqual(current["crosswalk_version"], "2026-11-06.23")
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

    def test_checked_delivery_receipt_binds_all_nine_to_actual_merged_implementation(self):
        ledger = json.loads((REFERENCE / "ledger.json").read_text("utf-8"))
        receipt = ledger["deliveries"]["24"]
        self.assertEqual(receipt["pr"], "https://github.com/jonathan-vella/landinglens/pull/155")
        self.assertEqual(receipt["checked_head"], "cd2ebbf5445007d1c9c2542d92a98df25eba740b")
        self.assertEqual(receipt["merge_commit"], "09567810b28bd7d6e54f9f66d7a2808d053396c7")
        self.assertEqual(
            receipt["checks"],
            [
                "https://github.com/jonathan-vella/landinglens/actions/runs/42322775297",
                "https://github.com/jonathan-vella/landinglens/actions/runs/42322793806",
            ],
        )
        self.assertEqual(
            receipt["local_installed_suite"], {"tests": 771, "passed": 770, "skipped": 1}
        )
        self.assertEqual(
            receipt["wheel_sha256"],
            "95cc35a3e8a7ddd9f38c6098215a5fc3bdcab430fd1a32b413922c93587eacce",
        )
        self.assertEqual(len(receipt["compiler_integration_cases"]), 21)
        self.assertEqual(
            receipt["compiler_integration_cases"][:-1],
            ledger["deliveries"]["09"]["compiler_integration_cases"],
        )
        self.assertEqual(
            receipt["compiler_integration_cases"][-1],
            "test_operations_preparation.OperationsPreparationTests."
            "test_real_bicep_operations_configuration_without_restore",
        )
        own = [r for r in ledger["recommendations"] if r["batch"] == "24"]
        self.assertEqual({r["guid"] for r in own}, GUIDS)
        for row in own:
            self.assertEqual(row["status"], "merged")
            self.assertEqual(row["pr"], receipt["pr"])
            self.assertEqual(row["merge_commit"], receipt["merge_commit"])
            self.assertIn("deliveries.24", " ".join(row["runtime_evidence"]))
