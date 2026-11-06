import contextlib
import copy
import hashlib
import io
import json
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

import test_platform_delivery_preparation as preparation
from test_platform_delivery_preparation import AT, GUIDS, IDS, PRIVATE, REFERENCE, SCOPE

from alz_assessor.catalog import load_catalog
from alz_assessor.cli import main
from alz_assessor.contracts import control_digest, digest
from alz_assessor.crosswalk import load_crosswalk
from alz_assessor.engine import assess
from alz_assessor.interviews import BANK, BANK_VERSION, compile_interview
from alz_assessor.replay import export_bundle, replay_bundle, semantic
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import validate_reviews
from alz_assessor.terraform import InputError


class PlatformDeliveryBatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        frozen = files("alz_assessor").joinpath("data", "catalog-2026-11-06.18.json")
        self.catalog = load_catalog(str(frozen)) if frozen.is_file() else load_catalog()
        self.previous = load_catalog(
            str(files("alz_assessor").joinpath("data", "catalog-2026-11-06.17.json"))
        )
        self.matrix = json.loads((REFERENCE / "batch-29.json").read_text("utf-8"))
        self.fixture = preparation.PlatformDeliveryPreparationTests()
        self.fixture.root = self.root
        self.fixture.catalog = self.catalog
        self.fixture.accepted = self.previous
        self.fixture.matrix = self.matrix
        self.fixture.question = self.matrix["interview"]["id"]
        network = patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden"))
        network.start()
        self.addCleanup(network.stop)

    def test_exact_accepted_manual_controls_preserve_every_other_control_and_frozen_bytes(self):
        self.assertEqual(self.catalog["catalog_version"], "2026-11-06.18")
        self.assertEqual(self.matrix["catalog_version"], self.catalog["catalog_version"])
        self.assertEqual(self.matrix["review_state"], "owner-delegated-source-backed-matrix")
        self.assertEqual(
            {r["upstream_id"]: r["guid"] for r in self.matrix["recommendations"]}, GUIDS
        )
        updates = {r["guid"]: r for r in self.matrix["recommendations"]}
        before = {c["control_id"]: c for c in self.previous["controls"]}
        for control in self.catalog["controls"]:
            if control["control_id"] not in IDS:
                self.assertEqual(control, before[control["control_id"]])
            else:
                row = updates[control["upstream_guid"]]
                self.assertEqual(control["evidence_requirements"], row["evidence_requirements"])
                self.assertEqual(control["rationale"], row["limitations"])
                self.assertEqual(control["automation"], "manual")
                self.assertIsNone(control["rule"])
                self.assertFalse(control.get("review_resource_types"))
                self.assertFalse(control.get("review_fact_paths"))
        baseline = load_catalog(
            str(files("alz_assessor").joinpath("data", "catalog-2026-11-04.2.json"))
        )
        for original in baseline["controls"]:
            if original["automation"] == "automated":
                actual = next(
                    c for c in self.catalog["controls"] if c["control_id"] == original["control_id"]
                )
                self.assertEqual(control_digest(actual), control_digest(original))
        for kind in ("catalog", "crosswalk"):
            raw = files("alz_assessor").joinpath("data", kind + "-2026-11-06.17.json").read_bytes()
            self.assertEqual(
                hashlib.sha256(raw).hexdigest(),
                self.matrix["preserved_" + kind + "_bytes"]["2026-11-06.17"],
            )
        self.assertEqual(len(self.catalog["controls"]), 255)
        self.assertEqual(
            {
                k: sum(c["automation"] == k for c in self.catalog["controls"])
                for k in ("automated", "assisted", "manual")
            },
            {"automated": 12, "assisted": 200, "manual": 43},
        )

    def test_all162_earlier_own_rows_nineteen_receipts_and_sixteen_sources_preserved(self):
        ledger = json.loads((REFERENCE / "ledger.json").read_text("utf-8"))
        earlier = set(self.matrix["preserved_delivery_batches"])
        rows = [r for r in ledger["recommendations"] if r["batch"] in earlier]
        receipts = {key: value for key, value in ledger["deliveries"].items() if key in earlier}
        self.assertEqual((len(rows), len(receipts)), (162, 19))
        self.assertEqual(digest(rows), self.matrix["preserved_merged_recommendations_sha256"])
        self.assertEqual(digest(receipts), self.matrix["preserved_delivery_receipts_sha256"])
        for row in rows:
            self.assertEqual(row["status"], "merged")
            self.assertEqual(row["pr"], receipts[row["batch"]]["pr"])
            self.assertEqual(row["merge_commit"], receipts[row["batch"]]["merge_commit"])
        own = [r for r in ledger["recommendations"] if r["batch"] == "29"]
        self.assertEqual({r["upstream_id"]: r["guid"] for r in own}, GUIDS)
        self.assertTrue(all(r["status"] in {"implementation-in-progress", "merged"} for r in own))
        self.assertEqual(len(ledger["recommendations"]), 251)
        prepared = (REFERENCE / "preparation-29-sources.json").read_bytes()
        self.assertEqual(prepared, (REFERENCE / "batch-29-sources.json").read_bytes())
        self.assertEqual(len(json.loads(prepared)["sources"]), 16)
        packaged = json.loads(
            files("alz_assessor")
            .joinpath("data", "batch-matrix-2026-11-06.18.json")
            .read_text("utf-8")
        )
        predecessor = json.loads(
            files("alz_assessor")
            .joinpath("data", "batch-matrix-2026-11-06.17.json")
            .read_text("utf-8")
        )
        self.assertEqual(packaged["batches"][:-1], predecessor["batches"])
        self.assertEqual(packaged["sources"][:-1], predecessor["sources"])
        self.assertEqual(packaged["batches"][-1], self.matrix)
        self.assertEqual(packaged["sources"][-1], json.loads(prepared))

    def test_real_registered_bank_selection_binding_and_independent_blank_decisions(self):
        question = self.matrix["interview"]
        self.assertEqual(question, {"id": question["id"], **BANK[question["id"]]})
        self.assertEqual(self.fixture.prepared()["bank_version"], BANK_VERSION)
        self.fixture.test_seven_independently_blank_specific_reviews_and_grouped_template()
        self.fixture.test_selection_rejects_noncanonical_duplicate_foreign_and_wrong_scope()
        self.fixture.test_scope_content_time_expiry_attribution_and_privacy_bindings()

    def test_real_manual_atomic_decisions_exceptions_and_never_technical_verified(self):
        self.fixture.test_configuration_inventory_human_flag_and_denial_never_prove_process()
        self.fixture.test_atomic_explicit_decisions_and_no_manufactured_verified()
        self.fixture.test_independent_exceptions_do_not_confirm_human_decisions()

    def test_real_reports_trackers_cli_and_minimized_privacy(self):
        self.fixture.test_every_report_tracker_preserves_manual_tier_and_withheld_payloads()
        self.fixture.test_cli_blank_grouped_and_individual_apply_never_overwrites()

    def test_real_session_preparation_atomic_save_resume_and_failure_guards(self):
        self.fixture.test_local_session_blank_specific_preparation_save_and_resume()
        self.fixture.root = self.root / "atomic"
        self.fixture.root.mkdir()
        self.fixture.test_session_partial_conflict_and_disk_failure_publish_nothing()

    def test_packaged_successor_original_time_replay_preserves_manual_reviews_and_sessions(self):
        bundle = self.fixture.bundle()
        manual = compile_interview(self.fixture.completed(), self.catalog, at=AT)
        expected = assess(bundle, self.catalog, manual=manual, at=AT, evidence_tiers=True)
        export_bundle(
            self.root / "replay", bundle, self.catalog, manual=manual, at=AT, evidence_tiers=True
        )
        restored = replay_bundle(self.root / "replay")
        self.assertEqual(semantic(restored), semantic(expected))
        self.assertEqual(restored["evidence"][0]["collected_at"], AT)
        self.assertTrue(
            all(r["observed"]["evidence_tier"] == "manual" for r in self.fixture.rows(restored))
        )
        for path in (self.root / "replay").iterdir():
            self.assertNotIn(PRIVATE, path.read_text("utf-8"))
            self.assertNotIn("Authored fixture reviewer", path.read_text("utf-8"))
        session = ReviewSession(
            bundle,
            self.catalog,
            self.root / "replayed-session",
            manual=manual,
            clock=lambda: AT,
            evidence_tiers=True,
        )
        self.assertEqual(semantic(session.report), semantic(expected))
        changed = copy.deepcopy(self.catalog)
        next(c for c in changed["controls"] if c["control_id"] in IDS)["evidence_requirements"][
            0
        ] += " Authored unaccepted change."
        with self.assertRaises(InputError):
            export_bundle(self.root / "unaccepted", bundle, changed, at=AT)
        self.assertFalse((self.root / "unaccepted").exists())

    def test_predecessor_original_time_replay_does_not_acquire_new_review_meaning(self):
        bundle = self.fixture.bundle()
        export_bundle(self.root / "historical", bundle, self.previous, at=AT, evidence_tiers=True)
        expected = assess(bundle, self.previous, at=AT, evidence_tiers=True)
        self.assertEqual(semantic(replay_bundle(self.root / "historical")), semantic(expected))
        current_manual = compile_interview(self.fixture.completed(), self.catalog, at=AT)
        self.assertFalse(
            validate_reviews(current_manual, self.previous, SCOPE, AT)["ready_to_apply"]
        )
        before = next(c for c in self.previous["controls"] if c["control_id"] in IDS)
        after = next(c for c in self.catalog["controls"] if c["control_id"] == before["control_id"])
        self.assertNotEqual(before["evidence_requirements"], after["evidence_requirements"])

    def test_installed_cli_and_empty_crosswalk_do_not_execute_or_confirm_process(self):
        evidence = self.root / "saved.json"
        output = self.root / "assessment.json"
        evidence.write_text(json.dumps(self.fixture.bundle()), encoding="utf-8")
        with (
            patch(
                "sys.argv",
                [
                    "alz-assessor",
                    "assess",
                    str(evidence),
                    "--input",
                    "evidence",
                    "--at",
                    AT,
                    "--evidence-tiers",
                    "--output",
                    str(output),
                ],
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(main(), 0)
        report = json.loads(output.read_text("utf-8"))
        self.assertEqual({r["control_id"] for r in self.fixture.rows(report)}, IDS)
        self.assertTrue(
            all(r["observed"]["outcome"] == "manual" for r in self.fixture.rows(report))
        )
        self.assertNotIn("query_signals", report)
        frozen = files("alz_assessor").joinpath("data", "crosswalk-2026-11-06.18.json")
        crosswalk = load_crosswalk(
            catalog=self.catalog, path=Path(str(frozen)) if frozen.is_file() else None
        )
        mapped = [r for r in crosswalk["entries"] if r["guid"] in GUIDS.values()]
        self.assertEqual(len(mapped), 7)
        self.assertTrue(all(r["targets"] == [] for r in mapped))

    def test_actual_seven_own_receipts_bind_merged_head_runs_wheel_and_historical_count(self):
        ledger = json.loads((REFERENCE / "ledger.json").read_text("utf-8"))
        receipt = ledger["deliveries"]["29"]
        self.assertEqual(receipt["pr"], "https://github.com/jonathan-vella/landinglens/pull/140")
        self.assertEqual(receipt["checked_head"], "314fe23f8e130e88709173e59ff9ae4cf967adfb")
        self.assertEqual(receipt["merge_commit"], "0cda0635c4351592d381956cec30c9bf9cbbfb23")
        self.assertEqual(receipt["merged_at"], "2026-11-06T20:45:33Z")
        self.assertEqual(
            receipt["wheel_sha256"],
            "a5417cf6aff38c0a9ead56af3f0c2ed7d5253363b9d2f8691af4b1d6b3d6f5b3",
        )
        self.assertEqual(
            receipt["local_installed_suite"], {"tests": 635, "passed": 634, "skipped": 1}
        )
        self.assertEqual(
            receipt["checks"],
            [
                "https://github.com/jonathan-vella/landinglens/actions/runs/42289191950",
                "https://github.com/jonathan-vella/landinglens/actions/runs/42289226748",
            ],
        )
        self.assertEqual(len(receipt["compiler_integration_cases"]), 16)
        self.assertEqual(
            receipt["compiler_integration_cases"],
            ledger["deliveries"]["27"]["compiler_integration_cases"],
        )
        own = [r for r in ledger["recommendations"] if r["batch"] == "29"]
        self.assertEqual({r["upstream_id"]: r["guid"] for r in own}, GUIDS)
        for row in own:
            self.assertEqual(row["status"], "merged")
            self.assertEqual(row["pr"], receipt["pr"])
            self.assertEqual(row["merge_commit"], receipt["merge_commit"])
            self.assertIn("deliveries.29:", " ".join(row["runtime_evidence"]))
        prefix = set(self.matrix["preserved_delivery_batches"]) | {"29"}
        self.assertEqual(
            sum(r["status"] == "merged" for r in ledger["recommendations"] if r["batch"] in prefix),
            169,
        )
