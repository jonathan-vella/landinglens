import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from alz_assessor.catalog import load_catalog
from alz_assessor.comparison import compare
from alz_assessor.contracts import document
from alz_assessor.engine import assess
from alz_assessor.reports import render
from alz_assessor.terraform import InputError

AT = "2026-11-05T00:00:00Z"
SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"


class CIReportTests(unittest.TestCase):
    def setUp(self):
        self.catalog = load_catalog()
        self.bundle = document(
            "evidence",
            mode="observed",
            source="saved",
            collected_at=AT,
            scope=SCOPE,
            inventory_complete=False,
            artifact_hashes={"fixture": "0" * 64},
            diagnostics=[],
            resources=[
                {
                    "logical_id": "storage",
                    "arm_id": SCOPE + "/providers/Microsoft.Storage/storageAccounts/store",
                    "resource_type": "Microsoft.Storage/storageAccounts",
                    "state": "known",
                    "reason": "",
                    "source_location": "fixture://private-path",
                    "properties": {"supportsHttpsTrafficOnly": False},
                }
            ],
        )
        self.report = assess(self.bundle, self.catalog, at=AT, evidence_tiers=True)

    def test_sarif_valid_structure_all_rules_modes_outcomes_and_no_invented_locations(self):
        data = json.loads(render(self.report, "sarif"))
        self.assertEqual(data["version"], "2.1.0")
        run = data["runs"][0]
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 255)
        self.assertEqual(len(run["results"]), len(self.report["results"]))
        self.assertIs(run["invocations"][0]["executionSuccessful"], True)
        self.assertEqual(run["properties"]["coverage"], self.report["coverage"])
        self.assertFalse(any("locations" in result for result in run["results"]))
        known = {row["control_id"] for row in self.report["results"]}
        self.assertTrue(all(result["ruleId"] in known for result in run["results"]))
        failure = next(row for row in run["results"] if row["properties"]["outcome"] == "fail")
        self.assertEqual((failure["kind"], failure["level"]), ("fail", "error"))
        self.assertIn("evidenceTier", failure["properties"])
        self.assertNotIn("private-path", json.dumps(data))

    def test_only_real_contained_file_location_without_fake_line(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "main.tf"
            path.write_text("# authored fixture", encoding="utf-8")
            report = copy.deepcopy(self.report)
            for row in report["results"]:
                row["observed"]["evidence_links"] = [str(path) + "#property"]
            data = json.loads(render(report, "sarif", sarif_base=root))
            physical = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
            self.assertEqual(physical["artifactLocation"]["uri"], "main.tf")
            self.assertNotIn("region", physical)
            for bad in (
                "../outside.tf",
                "https://example.invalid/path",
                "file:///private",
                "missing.tf",
                "%2e%2e/secret",
            ):
                for row in report["results"]:
                    row["observed"]["evidence_links"] = [bad]
                data = json.loads(render(report, "sarif", sarif_base=root))
                self.assertFalse(any("locations" in row for row in data["runs"][0]["results"]))
            report["results"][0]["observed"]["evidence_links"] = [str(path)]
            data = json.loads(render(report, "sarif", minimize=True, sarif_base=root))
            self.assertFalse(any("locations" in row for row in data["runs"][0]["results"]))
            with self.assertRaises((InputError, NotADirectoryError)):
                render(report, "sarif", sarif_base=path)

    def test_summary_separates_assessed_completion_subset_pass_and_unknowns(self):
        text = render(self.report, "pr-summary")
        for expected in (
            "Controls: 255",
            "Assessed instances",
            "Completion",
            "Pass rate among assessed",
            "incomplete/unverified",
            "Signals are not passes",
            "Evidence tiers",
        ):
            self.assertIn(expected, text)
        changed = copy.deepcopy(self.report)
        next(row for row in changed["results"] if row["observed"]["outcome"] == "fail")[
            "recommendation"
        ] = "<script>alert(1)</script>|[secret](javascript:bad)"
        for format in ("sarif", "pr-summary"):
            text = render(changed, format, minimize=True)
            if format == "pr-summary":
                self.assertNotIn("<script>", text)
            self.assertNotIn("private-path", text)
        empty = assess({**self.bundle, "resources": []}, self.catalog, at=AT, evidence_tiers=True)
        self.assertIn("unavailable", render(empty, "pr-summary"))

    def test_installed_assess_compare_and_render_formats_remain_advisory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            evidence = root / "evidence.json"
            evidence.write_text(json.dumps(self.bundle), encoding="utf-8")
            report = root / "report.json"
            report.write_text(json.dumps(self.report), encoding="utf-8")
            planned = root / "planned.json"
            planned_report = assess(
                {**self.bundle, "mode": "planned"}, self.catalog, at=AT, evidence_tiers=True
            )
            planned.write_text(json.dumps(planned_report), encoding="utf-8")
            for command in (
                ["assess", str(evidence), "--input", "evidence", "--at", AT, "--evidence-tiers"],
                ["render", str(report)],
                ["compare", str(planned), str(report), "--at", AT],
            ):
                for format in ("sarif", "pr-summary"):
                    result = subprocess.run(
                        [sys.executable, "-m", "alz_assessor.cli", *command, "--format", format],
                        cwd=root,
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "alz_assessor.cli",
                    "render",
                    str(report),
                    "--format",
                    "pr-summary",
                    "--sarif-base",
                    str(root),
                ],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 2)
            combined = compare(planned_report, self.report, at=AT)
            observations = json.loads(render(combined, "sarif"))["runs"][0]["results"]
            self.assertEqual(
                {row["properties"]["mode"] for row in observations}, {"planned", "observed"}
            )
