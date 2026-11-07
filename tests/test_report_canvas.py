import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from alz_assessor.arm import arm_source
from alz_assessor.catalog import load_catalog
from alz_assessor.comparison import compare
from alz_assessor.engine import assess
from alz_assessor.reports import report_model
from alz_assessor.reviews import prepare_reviews
from alz_assessor.terraform import InputError

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "tools" / "build_report_canvas.py"
SPEC = importlib.util.spec_from_file_location("report_canvas_builder", SCRIPT)
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


class ReportCanvasTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = load_catalog()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        template = self.root / "template.json"
        template.write_text(
            json.dumps(
                {
                    "resources": [
                        {
                            "type": "Microsoft.Storage/storageAccounts",
                            "apiVersion": "2023-05-01",
                            "name": "fictional",
                            "properties": {
                                "supportsHttpsTrafficOnly": False,
                                "minimumTlsVersion": "TLS1_0",
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        self.evidence = arm_source(
            template,
            scope="/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/test",
        )
        self.assessment = assess(self.evidence, self.catalog)
        self.source = self.write("assessment.json", self.assessment)

    def write(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def data(self, page):
        text = page.read_text(encoding="utf-8")
        payload = re.search(
            r'<script id="report-data" type="application/json">(.*?)</script>',
            text,
            re.S,
        )
        self.assertIsNotNone(payload)
        return json.loads(payload.group(1))

    def test_portable_sources_and_shared_model_without_machine_paths(self):
        output = self.root / "preview"
        page = BUILDER.build_preview(
            [("Primary", self.source), ("Second", self.source)], output, fictional=True
        )
        data = self.data(page)
        model = report_model(self.assessment, minimize=True)
        self.assertTrue(data["readOnly"])
        self.assertTrue(data["fictional"])
        self.assertEqual(len(data["reports"]), 2)
        for report in data["reports"].values():
            self.assertEqual(report["modeSummary"], "planned")
            self.assertEqual(report["coverage"], model["coverage"])
            self.assertEqual(report["presentation"], model)
            self.assertTrue(report["presentation"]["presentation_only"])
            self.assertEqual(report["declaredResources"], 1)
            self.assertEqual(len({row["control_id"] for row in report["rows"]}), 255)
            self.assertTrue((output / report["fullReport"]).is_file())
            self.assertNotIn("file://", report["fullReport"])
            for row in report["rows"]:
                self.assertEqual(
                    set(row["review_status"].keys()),
                    {"recorded", "active", "kind", "decision"},
                )
        self.assertNotIn(str(self.root), page.read_text(encoding="utf-8"))
        provenance = json.loads((output / "provenance.json").read_text(encoding="utf-8"))
        self.assertEqual(provenance["html_sha256"], hashlib.sha256(page.read_bytes()).hexdigest())
        self.assertEqual(
            provenance["sources"][0]["sha256"],
            hashlib.sha256(self.source.read_bytes()).hexdigest(),
        )

    def test_untrusted_labels_are_text_and_do_not_break_script_data(self):
        label = "</script><script>alert('not-executable')</script>"
        page = BUILDER.build_preview([(label, self.source)], self.root / "preview")
        text = page.read_text(encoding="utf-8")
        self.assertNotIn(label, text)
        self.assertEqual(self.data(page)["reports"]["report-1"]["label"], label)
        self.assertFalse(self.data(page)["fictional"])

    def test_invalid_labels_existing_outputs_and_wrong_modes_are_actionable(self):
        for reports in (
            [],
            [("", self.source)],
            [("A", self.source), ("a", self.source)],
            [("x" * 81, self.source)],
        ):
            with self.subTest(reports=reports), self.assertRaises(InputError):
                BUILDER.build_preview(reports, self.root / "invalid")
        self.assertFalse((self.root / "invalid").exists())
        output = self.root / "existing"
        output.mkdir()
        marker = output / "keep.txt"
        marker.write_text("preserve", encoding="utf-8")
        with self.assertRaisesRegex(InputError, "new output"):
            BUILDER.build_preview([("A", self.source)], output)
        self.assertEqual(marker.read_text(), "preserve")
        observed = json.loads(
            (ROOT / "tests" / "fixtures" / "slice" / "observed.json").read_text(encoding="utf-8")
        )
        observed_assessment = assess(observed, self.catalog, at=observed["collected_at"])
        source = self.write("observed.json", observed_assessment)
        planned_for_compare = assess(self.evidence, self.catalog, at=observed["collected_at"])
        compared = compare(planned_for_compare, observed_assessment, at=observed["collected_at"])
        compared_source = self.write("compared.json", compared)
        multi_page = BUILDER.build_preview(
            [("Planned", self.source), ("Observed", source), ("Compared", compared_source)],
            self.root / "observed-and-compared-preview",
        )
        multi_data = self.data(multi_page)
        self.assertEqual(len(multi_data["reports"]), 3)
        self.assertEqual(multi_data["reports"]["report-1"]["modeSummary"], "planned")
        self.assertEqual(multi_data["reports"]["report-2"]["modeSummary"], "observed")
        self.assertEqual(multi_data["reports"]["report-3"]["modeSummary"], "comparison")
        self.assertTrue(
            all(
                row.get("comparison") is not None
                for row in multi_data["reports"]["report-3"]["rows"]
            )
        )
        empty_evidence = dict(self.assessment, evidence=[])
        empty_source = self.write("empty-evidence.json", empty_evidence)
        with self.assertRaisesRegex(InputError, "evidence"):
            BUILDER.build_preview([("Empty", empty_source)], self.root / "empty-preview")
        self.assertFalse((self.root / "empty-preview").exists())
        minimized = self.write("presentation.json", report_model(self.assessment, minimize=True))
        with self.assertRaises(InputError):
            BUILDER.build_preview([("Minimized", minimized)], self.root / "minimized-preview")

    def test_review_status_whitelist_and_filter_controls_in_canvas(self):
        scope = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/test"
        manual_control = next(c for c in self.catalog["controls"] if not c.get("rule"))
        manual_record = prepare_reviews(
            self.assessment,
            self.catalog,
            [manual_control["control_id"]],
            scope,
            "manual",
        )
        manual_record.pop("is_template")
        manual_record["entries"][0].update(
            reviewer="secret-reviewer-name",
            evidence="https://internal.example.test/secret-evidence",
            rationale="secret-review-rationale",
            valid_from="2026-01-01T00:00:00Z",
            valid_until="2027-01-01T00:00:00Z",
            outcome="pass",
        )
        reviewed_assessment = assess(
            self.evidence,
            self.catalog,
            at=self.evidence["collected_at"],
            manual=manual_record,
        )
        reviewed_source = self.write("reviewed-assessment.json", reviewed_assessment)
        page = BUILDER.build_preview(
            [("Reviewed", reviewed_source)],
            self.root / "reviewed-preview",
        )
        html_text = page.read_text(encoding="utf-8")
        for forbidden in (
            "secret-reviewer-name",
            "secret-review-rationale",
            "https://internal.example.test/secret-evidence",
            "2026-01-01T00:00:00Z",
            "2027-01-01T00:00:00Z",
        ):
            self.assertNotIn(forbidden, html_text)
        data = self.data(page)
        report = data["reports"]["report-1"]
        reviewed_row = next(
            row for row in report["rows"] if row["control_id"] == manual_control["control_id"]
        )
        self.assertEqual(
            reviewed_row["review_status"],
            {
                "recorded": True,
                "active": True,
                "kind": "manual",
                "decision": "pass",
            },
        )
        for forbidden_key in ("reviewer", "rationale", "evidence", "valid_from", "valid_until"):
            self.assertNotIn(forbidden_key, reviewed_row["review_status"])
        template_text = (ROOT / "tools" / "report_canvas.html").read_text(encoding="utf-8")
        for select_id in ('id="severity"', 'id="tier"', 'id="comparison"'):
            self.assertIn(select_id, template_text)
            self.assertIn(select_id, html_text)

    def test_cli_success_and_invalid_input_exit_without_traceback(self):
        output = self.root / "cli-preview"
        command = [
            sys.executable,
            str(SCRIPT),
            "--report",
            "Saved report",
            str(self.source),
            "--output-directory",
            str(output),
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((output / "index.html").is_file())
        repeated = subprocess.run(command, capture_output=True, text=True, timeout=30)
        self.assertEqual(repeated.returncode, 2)
        self.assertIn("new output directory", repeated.stderr)
        self.assertNotIn("Traceback", repeated.stderr)


if __name__ == "__main__":
    unittest.main()
