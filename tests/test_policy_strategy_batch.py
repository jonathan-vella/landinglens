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

import test_policy_strategy_preparation as preparation
from test_policy_strategy_preparation import AT, CONTROLS, IDS, PRIVATE, ROOT, SCOPE

from alz_assessor.catalog import load_catalog
from alz_assessor.cli import main
from alz_assessor.contracts import digest
from alz_assessor.crosswalk import load_crosswalk
from alz_assessor.engine import assess
from alz_assessor.interviews import BANK, BANK_VERSION, compile_interview, prepare_interview
from alz_assessor.policy_strategy_evidence import GUIDS
from alz_assessor.replay import export_bundle, replay_bundle, sanitize_evidence, semantic
from alz_assessor.reports import render, render_xlsx
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import review_context
from alz_assessor.terraform import InputError

REFERENCE = ROOT / "references" / "recommendation-batches"


class PolicyStrategyBatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        frozen = files("alz_assessor").joinpath("data", "catalog-2026-11-06.17.json")
        self.catalog = load_catalog(str(frozen)) if frozen.is_file() else load_catalog()
        self.matrix = json.loads((REFERENCE / "batch-27.json").read_text("utf-8"))
        self.fixture = preparation.PolicyStrategyPreparationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.catalog = self.catalog

    def completed(self):
        report = assess(self.fixture.bundle(), self.catalog, at=AT, evidence_tiers=True)
        response = prepare_interview(report, self.catalog, self.matrix["interview"]["id"], SCOPE)
        response.update(
            answer="Authored fixture, not an actual governance or regulatory decision.",
            reviewer="Fixture reviewer",
            rationale="Eight independent authored decisions.",
            evidence="https://example.invalid/redacted-policy",
            valid_from=AT,
            valid_until="2026-11-07T16:00:00Z",
        )
        for entry in response["decisions"]:
            entry["outcome"] = "fail"
        return response

    def test_exact_accepted_eight_preserve_all_other_controls_and_predecessor_bytes(self):
        self.assertEqual(self.catalog["catalog_version"], "2026-11-06.17")
        self.assertEqual(self.matrix["review_state"], "owner-delegated-source-backed-matrix")
        self.assertEqual(
            {row["upstream_id"]: row["guid"] for row in self.matrix["recommendations"]}, IDS
        )
        previous = load_catalog(
            str(files("alz_assessor").joinpath("data", "catalog-2026-11-06.16.json"))
        )
        before = {control["control_id"]: control for control in previous["controls"]}
        rows = {row["guid"]: row for row in self.matrix["recommendations"]}
        for control in self.catalog["controls"]:
            if control["control_id"] not in CONTROLS:
                self.assertEqual(control, before[control["control_id"]])
            else:
                row = rows[control["upstream_guid"]]
                for key in ("review_resource_types", "review_fact_paths", "evidence_requirements"):
                    self.assertEqual(control[key], row[key])
                self.assertEqual(control["rationale"], row["limitations"])
                self.assertEqual(control["automation"], "assisted")
                self.assertIsNone(control["rule"])
        baseline = load_catalog(
            str(files("alz_assessor").joinpath("data", "catalog-2026-11-04.2.json"))
        )
        for original in baseline["controls"]:
            if original["automation"] == "automated":
                actual = next(
                    c for c in self.catalog["controls"] if c["control_id"] == original["control_id"]
                )
                self.assertEqual(actual, before[actual["control_id"]])
        for kind in ("catalog", "crosswalk"):
            raw = files("alz_assessor").joinpath("data", kind + "-2026-11-06.16.json").read_bytes()
            self.assertEqual(
                hashlib.sha256(raw).hexdigest(),
                self.matrix["preserved_" + kind + "_bytes"]["2026-11-06.16"],
            )
        self.assertEqual(len(self.catalog["controls"]), 255)
        self.assertEqual(
            {
                k: sum(c["automation"] == k for c in self.catalog["controls"])
                for k in ("automated", "assisted", "manual")
            },
            {"automated": 12, "assisted": 200, "manual": 43},
        )

    def test_all154_prior_rows_eighteen_receipts_and_all22_source_captures_preserved(self):
        ledger = json.loads((REFERENCE / "ledger.json").read_text("utf-8"))
        batches = set(self.matrix["preserved_delivery_batches"])
        receipts = {key: value for key, value in ledger["deliveries"].items() if key in batches}
        rows = [row for row in ledger["recommendations"] if row["batch"] in batches]
        self.assertEqual((len(rows), len(receipts)), (154, 18))
        self.assertEqual(digest(receipts), self.matrix["preserved_delivery_receipts_sha256"])
        self.assertEqual(digest(rows), self.matrix["preserved_merged_recommendations_sha256"])
        for row in rows:
            self.assertEqual(row["status"], "merged")
            self.assertEqual(row["pr"], receipts[row["batch"]]["pr"])
            self.assertEqual(row["merge_commit"], receipts[row["batch"]]["merge_commit"])
        self.assertEqual(len(ledger["recommendations"]), 251)
        own = [row for row in ledger["recommendations"] if row["batch"] == "27"]
        self.assertEqual({row["guid"] for row in own}, GUIDS)
        self.assertTrue(
            all(row["status"] in {"implementation-in-progress", "merged"} for row in own)
        )
        accepted = json.loads((REFERENCE / "batch-27-sources.json").read_text())
        prepared = json.loads((REFERENCE / "preparation-27-sources.json").read_text())
        self.assertEqual(accepted["sources"], prepared["sources"])
        self.assertEqual(len(accepted["sources"]), 22)

    def test_registered_eight_blank_decisions_and_binding_are_independent(self):
        question = self.matrix["interview"]
        self.assertEqual(question, {"id": question["id"], **BANK[question["id"]]})
        report = assess(self.fixture.bundle(), self.catalog, at=AT, evidence_tiers=True)
        blank = prepare_interview(report, self.catalog, question["id"], SCOPE)
        self.assertEqual(blank["bank_version"], BANK_VERSION)
        self.assertEqual({d["control_id"] for d in blank["decisions"]}, CONTROLS)
        self.assertTrue(all(d["outcome"] is None for d in blank["decisions"]))
        with self.assertRaises(InputError):
            compile_interview(blank, self.catalog, at=AT)
        response = self.completed()
        self.assertEqual(len(compile_interview(response, self.catalog, at=AT)["entries"]), 8)
        for field, value in (
            ("scope", SCOPE + "/resourcegroups/foreign"),
            ("valid_until", AT),
            ("catalog_sha256", "0" * 64),
            ("requirements_sha256", "0" * 64),
        ):
            with self.assertRaises(InputError):
                compile_interview({**response, field: value}, self.catalog, at=AT)
        changed = copy.deepcopy(response)
        changed["decisions"][0]["outcome"] = None
        with self.assertRaises(InputError):
            compile_interview(changed, self.catalog, at=AT)

    def test_packaged_successor_replay_join_context_reports_and_real_session_resume(self):
        bundle = self.fixture.bundle()
        manual = compile_interview(self.completed(), self.catalog, at=AT)
        expected = assess(bundle, self.catalog, manual=manual, at=AT, evidence_tiers=True)
        export_bundle(
            self.root / "replay", bundle, self.catalog, manual=manual, at=AT, evidence_tiers=True
        )
        restored = replay_bundle(self.root / "replay")
        self.assertEqual(semantic(restored), semantic(expected))
        self.assertEqual(restored["evidence"][0]["collected_at"], AT)
        sanitized = sanitize_evidence(bundle)
        for control in self.catalog["controls"]:
            if control["control_id"] in CONTROLS:
                self.assertEqual(
                    review_context(control, bundle), review_context(control, sanitized)
                )
        for format in ("json", "markdown", "html", "csv", "sarif", "pr-summary"):
            for minimized in (False, True):
                self.assertNotIn(PRIVATE, render(expected, format, minimized))
        self.assertGreater(len(render_xlsx(expected)), 0)
        own = [r for r in expected["results"] if r["control_id"] in CONTROLS]
        self.assertTrue(all(r["observed"]["outcome"] == "fail" for r in own))
        self.assertTrue(all(r["observed"]["evidence_tier"] != "verified" for r in own))
        session = ReviewSession(
            bundle, self.catalog, self.root / "session", clock=lambda: AT, evidence_tiers=True
        )
        self.assertEqual(session.state()["records"], [])
        session.save_interview(
            {"revision": 0, "response": self.completed(), "replace_existing": []}
        )
        resumed = ReviewSession.resume(
            session.directory / "revision-0001", self.root / "resumed", clock=lambda: AT
        )
        self.assertEqual(semantic(session.report), semantic(resumed.report))

    def test_installed_cli_and_empty_crosswalk_do_not_execute_or_manufacture_verified(self):
        evidence = self.root / "saved.json"
        evidence.write_text(json.dumps(self.fixture.bundle()))
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
        report = json.loads(output.read_text())
        own = [row for row in report["results"] if row["control_id"] in CONTROLS]
        self.assertEqual({row["control_id"] for row in own}, CONTROLS)
        self.assertTrue(all(row["observed"]["outcome"] == "manual" for row in own))
        self.assertTrue(all(row["observed"]["evidence_tier"] != "verified" for row in own))
        crosswalk = load_crosswalk(catalog=self.catalog)
        mapped = [row for row in crosswalk["entries"] if row["guid"] in GUIDS]
        self.assertEqual(len(mapped), 8)
        self.assertTrue(all(row["targets"] == [] for row in mapped))
        self.assertNotIn("query_signals", report)

    def test_predecessor_original_time_replay_stays_distinct_from_new_review_meaning(self):
        previous = load_catalog(
            str(files("alz_assessor").joinpath("data", "catalog-2026-11-06.16.json"))
        )
        bundle = self.fixture.bundle()
        export_bundle(self.root / "historical", bundle, previous, at=AT, evidence_tiers=True)
        self.assertEqual(
            semantic(replay_bundle(self.root / "historical")),
            semantic(assess(bundle, previous, at=AT, evidence_tiers=True)),
        )
        before = next(c for c in previous["controls"] if c["upstream_id"] == "E01.01")
        after = next(c for c in self.catalog["controls"] if c["upstream_id"] == "E01.01")
        self.assertNotIn("supplied_policy_assignments", review_context(before, bundle))
        self.assertIn("supplied_policy_assignments", review_context(after, bundle))

    def test_actual_eight_own_receipts_bind_merged_head_runs_wheel_and_suite(self):
        ledger = json.loads((REFERENCE / "ledger.json").read_text("utf-8"))
        receipt = ledger["deliveries"]["27"]
        self.assertEqual(receipt["pr"], "https://github.com/jonathan-vella/landinglens/pull/137")
        self.assertEqual(receipt["checked_head"], "9e71de6b653abe1c7c3c3c7312cd81f01c46e84b")
        self.assertEqual(receipt["merge_commit"], "53e62bde5dd2460aa788fa00e9134e09838d5a05")
        self.assertEqual(receipt["merged_at"], "2026-11-06T19:36:56Z")
        self.assertEqual(
            receipt["wheel_sha256"],
            "aade6bd36d398b648127d46d539f3eb3bdd88a58bdfdff1038ab005c0dbd6599",
        )
        self.assertEqual(
            receipt["local_installed_suite"], {"tests": 610, "passed": 609, "skipped": 1}
        )
        self.assertEqual(
            receipt["checks"],
            [
                "https://github.com/jonathan-vella/landinglens/actions/runs/42279803185",
                "https://github.com/jonathan-vella/landinglens/actions/runs/42279835399",
            ],
        )
        self.assertEqual(len(receipt["compiler_integration_cases"]), 16)
        self.assertEqual(
            receipt["compiler_integration_cases"][:-1],
            ledger["deliveries"]["02"]["compiler_integration_cases"],
        )
        own = [row for row in ledger["recommendations"] if row["batch"] == "27"]
        self.assertEqual({row["guid"] for row in own}, GUIDS)
        for row in own:
            self.assertEqual(row["status"], "merged")
            self.assertEqual(row["pr"], receipt["pr"])
            self.assertEqual(row["merge_commit"], receipt["merge_commit"])
            self.assertIn("deliveries.27:", " ".join(row["runtime_evidence"]))
        prefix = set(self.matrix["preserved_delivery_batches"]) | {"27"}
        self.assertEqual(
            sum(
                row["status"] == "merged"
                for row in ledger["recommendations"]
                if row["batch"] in prefix
            ),
            162,
        )
