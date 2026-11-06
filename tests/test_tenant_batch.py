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

import test_tenant_preparation as preparation
from test_tenant_preparation import AT, OWN, PRINCIPAL, PRIVATE, SUB, TENANT, UNTIL

from alz_assessor.catalog import load_catalog
from alz_assessor.cli import main
from alz_assessor.contracts import control_digest, digest
from alz_assessor.crosswalk import load_crosswalk
from alz_assessor.engine import assess
from alz_assessor.interviews import BANK, BANK_VERSION, compile_interview, prepare_interview
from alz_assessor.replay import export_bundle, replay_bundle, sanitize_evidence, semantic
from alz_assessor.reports import render, render_xlsx
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import review_context
from alz_assessor.tenant_evidence import GUIDS
from alz_assessor.terraform import InputError

REFERENCE = preparation.ROOT / "references" / "recommendation-batches"
IDS = {"ALZ-" + guid for guid in GUIDS}


class TenantBatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        frozen = files("alz_assessor").joinpath("data", "catalog-2026-11-06.16.json")
        self.catalog = load_catalog(str(frozen)) if frozen.is_file() else load_catalog()
        self.matrix = json.loads((REFERENCE / "batch-02.json").read_text("utf-8"))
        self.fixture = preparation.TenantPreparationTests()
        self.fixture.root = self.root
        network = patch("socket.socket.connect", side_effect=AssertionError("network forbidden"))
        network.start()
        self.addCleanup(network.stop)

    def completed(self):
        report = assess(self.fixture.bundle(), self.catalog, at=AT, evidence_tiers=True)
        response = prepare_interview(report, self.catalog, self.matrix["interview"]["id"], SUB)
        response.update(
            answer="Authored fixture, not an actual tenant or financial decision.",
            reviewer="Fixture reviewer",
            rationale="Eight separately bound authored decisions.",
            evidence="https://example.invalid/tenant",
            valid_from=AT,
            valid_until=UNTIL,
        )
        for entry in response["decisions"]:
            entry["outcome"] = "fail"
        return response

    def test_exact_accepted_eight_preserve_all_other_controls_and_frozen_bytes(self):
        self.assertEqual(self.catalog["catalog_version"], "2026-11-06.16")
        self.assertEqual(self.matrix["catalog_version"], self.catalog["catalog_version"])
        self.assertEqual(self.matrix["review_state"], "owner-delegated-source-backed-matrix")
        self.assertEqual(
            {row["upstream_id"]: row["guid"] for row in self.matrix["recommendations"]}, OWN
        )
        previous = load_catalog(
            str(files("alz_assessor").joinpath("data", "catalog-2026-11-06.15.json"))
        )
        by_id = {c["control_id"]: c for c in previous["controls"]}
        rows = {r["guid"]: r for r in self.matrix["recommendations"]}
        for control in self.catalog["controls"]:
            if control["control_id"] not in IDS:
                self.assertEqual(control, by_id[control["control_id"]])
            else:
                row = rows[control["upstream_guid"]]
                self.assertEqual(control["evidence_requirements"], row["evidence_requirements"])
                self.assertEqual(control.get("review_fact_paths"), row.get("review_fact_paths"))
                self.assertEqual(control["rationale"], row["limitations"])
                self.assertEqual(control["automation"], row["classification"])
                self.assertIsNone(control["rule"])
        baseline = load_catalog(
            str(files("alz_assessor").joinpath("data", "catalog-2026-11-04.2.json"))
        )
        for original in baseline["controls"]:
            if original["automation"] == "automated":
                current = next(
                    c for c in self.catalog["controls"] if c["control_id"] == original["control_id"]
                )
                self.assertEqual(current, by_id[current["control_id"]])
                self.assertEqual(control_digest(current), control_digest(original))
        for kind in ("catalog", "crosswalk"):
            expected = self.matrix["preserved_" + kind + "_bytes"]["2026-11-06.15"]
            content = (
                files("alz_assessor").joinpath("data", kind + "-2026-11-06.15.json").read_bytes()
            )
            self.assertEqual(hashlib.sha256(content).hexdigest(), expected)
        self.assertEqual(len(self.catalog["controls"]), 255)
        self.assertEqual(
            {
                kind: sum(c["automation"] == kind for c in self.catalog["controls"])
                for kind in ("automated", "assisted", "manual")
            },
            {"automated": 12, "assisted": 200, "manual": 43},
        )

    def test_all146_prior_rows_seventeen_receipts_and_source_captures_preserved(self):
        ledger = json.loads((REFERENCE / "ledger.json").read_text("utf-8"))
        batches = set(self.matrix["preserved_delivery_batches"])
        receipts = {key: value for key, value in ledger["deliveries"].items() if key in batches}
        rows = [row for row in ledger["recommendations"] if row["batch"] in batches]
        self.assertEqual(len(rows), 146)
        self.assertEqual(len(receipts), 17)
        self.assertEqual(digest(receipts), self.matrix["preserved_delivery_receipts_sha256"])
        self.assertEqual(digest(rows), self.matrix["preserved_merged_recommendations_sha256"])
        for row in rows:
            self.assertEqual(row["status"], "merged")
            self.assertEqual(row["pr"], receipts[row["batch"]]["pr"])
            self.assertEqual(row["merge_commit"], receipts[row["batch"]]["merge_commit"])
        self.assertEqual(len(ledger["recommendations"]), 251)
        own = [row for row in ledger["recommendations"] if row["batch"] == "02"]
        self.assertEqual({row["guid"] for row in own}, GUIDS)
        self.assertTrue(
            all(row["status"] in {"implementation-in-progress", "merged"} for row in own)
        )
        accepted = json.loads((REFERENCE / "batch-02-sources.json").read_text("utf-8"))
        prepared = json.loads(
            (preparation.PREPARATION / "batch-02-sources.json").read_text("utf-8")
        )
        self.assertEqual(accepted["sources"], prepared["sources"])

    def test_registered_eight_blank_decisions_and_binding_are_independent(self):
        question = self.matrix["interview"]
        self.assertEqual(question, {"id": question["id"], **BANK[question["id"]]})
        report = assess(self.fixture.bundle(), self.catalog, at=AT, evidence_tiers=True)
        blank = prepare_interview(report, self.catalog, question["id"], SUB)
        self.assertEqual(blank["bank_version"], BANK_VERSION)
        self.assertEqual({d["control_id"] for d in blank["decisions"]}, IDS)
        self.assertTrue(all(d["outcome"] is None for d in blank["decisions"]))
        with self.assertRaises(InputError):
            compile_interview(blank, self.catalog, at=AT)
        response = self.completed()
        manual = compile_interview(response, self.catalog, at=AT)
        self.assertEqual(len(manual["entries"]), 8)
        for field, value in (
            ("scope", SUB + "/resourcegroups/foreign"),
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

    def test_actual_packaged_successor_replay_review_and_all_outputs_preserve_limits(self):
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
            if control["control_id"] in IDS:
                self.assertEqual(
                    review_context(control, bundle), review_context(control, sanitized)
                )
        for format in ("json", "markdown", "html", "csv", "sarif", "pr-summary"):
            for minimized in (False, True):
                text = render(expected, format, minimized)
                self.assertTrue(all(value not in text for value in (PRIVATE, PRINCIPAL, TENANT)))
        self.assertGreater(len(render_xlsx(expected)), 0)
        own = [r for r in expected["results"] if r["control_id"] in IDS]
        self.assertTrue(all(r["observed"]["outcome"] == "fail" for r in own))
        self.assertTrue(all(r["observed"]["evidence_tier"] != "verified" for r in own))
        session = ReviewSession(
            bundle, self.catalog, self.root / "session", clock=lambda: AT, evidence_tiers=True
        )
        self.assertEqual(session.state()["records"], [])
        question = next(
            q for q in session.state()["interviews"] if q["id"] == self.matrix["interview"]["id"]
        )
        self.assertTrue(all(d["outcome"] is None for d in question["template"]["decisions"]))

    def test_installed_cli_and_empty_crosswalk_do_not_execute_queries_or_decide_applicability(self):
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
        own = [r for r in report["results"] if r["control_id"] in IDS]
        self.assertEqual({r["control_id"] for r in own}, IDS)
        self.assertTrue(all(r["observed"]["outcome"] == "manual" for r in own))
        self.assertTrue(all(r["observed"]["evidence_tier"] != "verified" for r in own))
        crosswalk = load_crosswalk(catalog=self.catalog)
        mapped = [r for r in crosswalk["entries"] if r["guid"] in GUIDS]
        self.assertEqual(len(mapped), 8)
        self.assertTrue(all(r["targets"] == [] for r in mapped))
        self.assertNotIn("query_signals", report)

    def test_actual_eight_own_receipts_bind_merged_head_runs_wheel_and_suite(self):
        ledger = json.loads((REFERENCE / "ledger.json").read_text("utf-8"))
        receipt = ledger["deliveries"]["02"]
        self.assertEqual(receipt["pr"], "https://github.com/jonathan-vella/landinglens/pull/134")
        self.assertEqual(receipt["checked_head"], "67b7131f4a972da83675a9729f792489c8aa461d")
        self.assertEqual(receipt["merge_commit"], "8440e2e57b7598ece6205ce01d56460833709013")
        self.assertEqual(receipt["merged_at"], "2026-11-06T18:46:14Z")
        self.assertEqual(
            receipt["wheel_sha256"],
            "1f71423241ba5e0b56bec415299eabf915bbccf39f82a2c62780433868a53a86",
        )
        self.assertEqual(
            receipt["local_installed_suite"], {"tests": 583, "passed": 582, "skipped": 1}
        )
        self.assertEqual(
            receipt["checks"],
            [
                "https://github.com/jonathan-vella/landinglens/actions/runs/42272351636",
                "https://github.com/jonathan-vella/landinglens/actions/runs/42272382581",
            ],
        )
        self.assertEqual(len(receipt["compiler_integration_cases"]), 15)
        self.assertEqual(
            receipt["compiler_integration_cases"][:-1],
            ledger["deliveries"]["23"]["compiler_integration_cases"],
        )
        own = [row for row in ledger["recommendations"] if row["batch"] == "02"]
        self.assertEqual({row["guid"] for row in own}, GUIDS)
        for row in own:
            self.assertEqual(row["status"], "merged")
            self.assertEqual(row["pr"], receipt["pr"])
            self.assertEqual(row["merge_commit"], receipt["merge_commit"])
            self.assertIn("deliveries.02:", " ".join(row["runtime_evidence"]))
        prefix = set(self.matrix["preserved_delivery_batches"]) | {"02"}
        self.assertEqual(
            sum(
                row["status"] == "merged"
                for row in ledger["recommendations"]
                if row["batch"] in prefix
            ),
            154,
        )
