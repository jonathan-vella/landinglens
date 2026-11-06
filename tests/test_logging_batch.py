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

import test_logging_preparation as preparation
from test_logging_preparation import AT, IDS, PRIVATE, REFERENCE, SCOPE

from alz_assessor.catalog import load_catalog
from alz_assessor.cli import main
from alz_assessor.contracts import control_digest, digest
from alz_assessor.crosswalk import load_crosswalk
from alz_assessor.engine import assess
from alz_assessor.interviews import BANK, BANK_VERSION, compile_interview, prepare_interview
from alz_assessor.logging_evidence import GUIDS
from alz_assessor.replay import export_bundle, known_catalog, replay_bundle, semantic
from alz_assessor.reports import render, render_xlsx
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import review_context
from alz_assessor.terraform import InputError


class LoggingBatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        frozen = files("alz_assessor").joinpath("data", "catalog-2026-11-06.15.json")
        self.catalog = load_catalog(str(frozen)) if frozen.is_file() else load_catalog()
        self.matrix = json.loads((REFERENCE / "batch-23.json").read_text("utf-8"))
        self.fixture = preparation.LoggingPreparationTests()
        self.fixture.root = self.root
        self.fixture.catalog = self.catalog
        self.fixture.question = self.matrix["interview"]["id"]
        network = patch("socket.socket.connect", side_effect=AssertionError("network forbidden"))
        network.start()
        self.addCleanup(network.stop)

    def test_exact_accepted_seven_preserve_every_other_control_and_frozen_bytes(self):
        predecessor = load_catalog(
            str(files("alz_assessor").joinpath("data", "catalog-2026-11-06.14.json"))
        )
        self.assertEqual(self.catalog["catalog_version"], "2026-11-06.15")
        self.assertEqual(self.matrix["catalog_version"], self.catalog["catalog_version"])
        self.assertEqual(self.matrix["review_state"], "owner-delegated-source-backed-matrix")
        self.assertEqual({row["guid"] for row in self.matrix["recommendations"]}, GUIDS)
        previous = {row["control_id"]: row for row in predecessor["controls"]}
        rows = {row["guid"]: row for row in self.matrix["recommendations"]}
        for control in self.catalog["controls"]:
            if control["control_id"] not in IDS:
                self.assertEqual(control, previous[control["control_id"]])
            else:
                row = rows[control["upstream_guid"]]
                self.assertEqual(control["evidence_requirements"], row["evidence_requirements"])
                self.assertEqual(control["rationale"], row["limitations"])
                self.assertEqual(control.get("review_fact_paths"), row.get("review_fact_paths"))
                self.assertEqual(control["automation"], row["classification"])
                self.assertIsNone(control["rule"])
        self.assertEqual(len(self.catalog["controls"]), 255)
        self.assertEqual(
            {
                kind: sum(row["automation"] == kind for row in self.catalog["controls"])
                for kind in ("automated", "assisted", "manual")
            },
            {"automated": 12, "assisted": 200, "manual": 43},
        )
        for kind, expected in (
            ("catalog", "cff4272bf75497cede26b9683feb21a78a4416f40bbae825998c04e3c5e19a41"),
            ("crosswalk", "34faf24ee323ead3c3cc6e5b7a0af2bedc71f67b84c58c18e7e397050a4db26a"),
        ):
            content = (
                files("alz_assessor").joinpath("data", kind + "-2026-11-06.14.json").read_bytes()
            )
            self.assertEqual(hashlib.sha256(content).hexdigest(), expected)
        baseline = load_catalog(
            str(files("alz_assessor").joinpath("data", "catalog-2026-11-04.2.json"))
        )
        for original in baseline["controls"]:
            if original["automation"] == "automated":
                current = next(
                    c for c in self.catalog["controls"] if c["control_id"] == original["control_id"]
                )
                self.assertEqual(current, previous[current["control_id"]])
                self.assertEqual(control_digest(current), control_digest(original))
        accepted = json.loads((REFERENCE / "batch-23-sources.json").read_text("utf-8"))
        preparation = json.loads((REFERENCE / "preparation-23-sources.json").read_text("utf-8"))
        self.assertEqual(accepted["sources"], preparation["sources"])

    def test_all139_original_receipt_objects_and_own_bindings_remain_exact(self):
        ledger = json.loads((REFERENCE / "ledger.json").read_text("utf-8"))
        batches = set(self.matrix["preserved_delivery_batches"])
        receipts = {key: value for key, value in ledger["deliveries"].items() if key in batches}
        rows = [row for row in ledger["recommendations"] if row["batch"] in batches]
        self.assertEqual(len(rows), 139)
        self.assertEqual(len(receipts), 16)
        self.assertEqual(digest(receipts), self.matrix["preserved_delivery_receipts_sha256"])
        self.assertEqual(digest(rows), self.matrix["preserved_merged_recommendations_sha256"])
        self.assertEqual(len(ledger["recommendations"]), 251)
        for row in rows:
            self.assertEqual(row["status"], "merged")
            self.assertEqual(row["pr"], receipts[row["batch"]]["pr"])
            self.assertEqual(row["merge_commit"], receipts[row["batch"]]["merge_commit"])
        own = [row for row in ledger["recommendations"] if row["batch"] == "23"]
        self.assertEqual({row["guid"] for row in own}, GUIDS)
        self.assertTrue(
            all(row["status"] in {"implementation-in-progress", "merged"} for row in own)
        )

    def test_real_registered_bank_keeps_all_seven_blank_bound_and_separate(self):
        question = self.matrix["interview"]
        self.assertEqual(question, {"id": question["id"], **BANK[question["id"]]})
        report = self.fixture.report()
        blank = prepare_interview(report, self.catalog, question["id"], SCOPE)
        self.assertEqual(blank["bank_version"], BANK_VERSION)
        self.assertEqual({row["control_id"] for row in blank["decisions"]}, IDS)
        self.assertTrue(all(row["outcome"] is None for row in blank["decisions"]))
        with self.assertRaises(InputError):
            compile_interview(blank, self.catalog, at=AT)
        response = self.fixture.completed()
        manual = compile_interview(response, self.catalog, at=AT)
        confirmed = self.fixture.report(manual=manual)
        for row in confirmed["results"]:
            if row["control_id"] in IDS:
                self.assertNotEqual(row["observed"]["evidence_tier"], "verified")
        for field in ("catalog_sha256", "requirements_sha256"):
            altered = copy.deepcopy(response)
            altered[field] = "0" * 64
            with self.assertRaises(InputError):
                compile_interview(altered, self.catalog, at=AT)

    def test_actual_packaged_successor_replay_all_formats_and_local_session(self):
        bundle = self.fixture.bundle()
        self.assertEqual(known_catalog(self.catalog), self.catalog)
        manual = compile_interview(self.fixture.completed(), self.catalog, at=AT)
        expected = assess(bundle, self.catalog, manual=manual, at=AT, evidence_tiers=True)
        export_bundle(
            self.root / "replay", bundle, self.catalog, manual=manual, at=AT, evidence_tiers=True
        )
        restored = replay_bundle(self.root / "replay")
        self.assertEqual(semantic(restored), semantic(expected))
        evidence = json.loads((self.root / "replay" / "evidence.json").read_text("utf-8"))
        self.assertEqual(evidence["collected_at"], AT)
        for control in self.catalog["controls"]:
            if control["control_id"] in IDS:
                self.assertEqual(review_context(control, bundle), review_context(control, evidence))
        for format in ("json", "markdown", "html", "csv", "sarif", "pr-summary"):
            for minimized in (False, True):
                self.assertNotIn(PRIVATE, render(expected, format, minimized))
        self.assertGreater(len(render_xlsx(expected)), 0)
        session = ReviewSession(
            bundle, self.catalog, self.root / "session", clock=lambda: AT, evidence_tiers=True
        )
        state = session.state()
        self.assertEqual(state["records"], [])
        question = next(
            row for row in state["interviews"] if row["id"] == self.matrix["interview"]["id"]
        )
        self.assertTrue(all(row["outcome"] is None for row in question["template"]["decisions"]))

    def test_installed_cli_and_static_crosswalk_never_execute_query_associations(self):
        evidence = self.fixture.write("saved.json", self.fixture.bundle())
        output = self.root / "assessment.json"
        with (
            contextlib.redirect_stdout(io.StringIO()),
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
        ):
            code = main()
        self.assertEqual(code, 0)
        report = json.loads(output.read_text("utf-8"))
        own = [row for row in report["results"] if row["control_id"] in IDS]
        self.assertEqual({row["control_id"] for row in own}, IDS)
        self.assertTrue(all(row["observed"]["evidence_tier"] != "verified" for row in own))
        crosswalk = load_crosswalk(catalog=self.catalog)
        mapped = [row for row in crosswalk["entries"] if row["guid"] in GUIDS]
        self.assertEqual(sum(bool(row["targets"]) for row in mapped), 1)
        self.assertTrue(
            all(target["strength"] == "related" for row in mapped for target in row["targets"])
        )
        self.assertNotIn("query_signals", report)

    def test_actual_own_seven_receipts_bind_merged_head_runs_wheel_and_original_suite(self):
        ledger = json.loads((REFERENCE / "ledger.json").read_text("utf-8"))
        receipt = ledger["deliveries"]["23"]
        self.assertEqual(receipt["pr"], "https://github.com/jonathan-vella/landinglens/pull/131")
        self.assertEqual(receipt["checked_head"], "aca60f824174c493f66f90e2c0b75426d878820c")
        self.assertEqual(receipt["merge_commit"], "32d40747b185921a27ab46f562ef4db35c4b804b")
        self.assertEqual(receipt["merged_at"], "2026-11-06T17:59:06Z")
        self.assertEqual(
            receipt["wheel_sha256"],
            "4e4b0b4f95f513cbb562339b584eac202a1457ebabe573f5ae06d6c52d364023",
        )
        self.assertEqual(
            receipt["local_installed_suite"], {"tests": 559, "passed": 558, "skipped": 1}
        )
        self.assertEqual(
            receipt["checks"],
            [
                "https://github.com/jonathan-vella/landinglens/actions/runs/42265371359",
                "https://github.com/jonathan-vella/landinglens/actions/runs/42265396588",
            ],
        )
        self.assertEqual(len(receipt["compiler_integration_cases"]), 14)
        self.assertEqual(
            receipt["compiler_integration_cases"][:-1],
            ledger["deliveries"]["16"]["compiler_integration_cases"],
        )
        own = [row for row in ledger["recommendations"] if row["batch"] == "23"]
        self.assertEqual({row["guid"] for row in own}, GUIDS)
        for row in own:
            self.assertEqual(row["status"], "merged")
            self.assertEqual(row["pr"], receipt["pr"])
            self.assertEqual(row["merge_commit"], receipt["merge_commit"])
            self.assertIn("deliveries.23:", " ".join(row["runtime_evidence"]))
