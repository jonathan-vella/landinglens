import copy
import csv
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from xml.etree import ElementTree as ET
from zipfile import ZipFile

from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import document
from alz_assessor.engine import assess
from alz_assessor.reports import render, render_xlsx
from alz_assessor.terraform import InputError
from alz_assessor.tracker_exports import HEADERS, safe_text

AT = "2026-11-05T00:00:00Z"
SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
NS = {"s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}


class TrackerExportTests(unittest.TestCase):
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
                    "logical_id": "private-fixture",
                    "arm_id": SCOPE + "/providers/Microsoft.Storage/storageAccounts/store",
                    "resource_type": "Microsoft.Storage/storageAccounts",
                    "state": "known",
                    "reason": "",
                    "source_location": "fixture://private-evidence",
                    "properties": {"supportsHttpsTrafficOnly": False},
                }
            ],
        )
        self.report = assess(self.bundle, self.catalog, at=AT, evidence_tiers=True)

    def cells(self, data):
        with ZipFile(io.BytesIO(data)) as archive:
            root = ET.fromstring(archive.read("xl/worksheets/sheet1.xml"))
        return [
            [cell.find("s:is/s:t", NS).text or "" for cell in row.findall("s:c", NS)]
            for row in root.findall("s:sheetData/s:row", NS)
        ]

    def test_csv_and_xlsx_exact_text_parity_and_all_controls(self):
        csv_rows = list(csv.reader(io.StringIO(render(self.report, "csv"))))
        workbook_rows = self.cells(render_xlsx(self.report))
        self.assertEqual(csv_rows, workbook_rows)
        self.assertEqual(csv_rows[0], list(HEADERS))
        self.assertEqual(len({row[0] for row in csv_rows[1:]}), 255)
        self.assertEqual(len(csv_rows) - 1, len(self.report["results"]))
        self.assertIn("fail", {row[9] for row in csv_rows[1:]})
        self.assertIn("manual", {row[9] for row in csv_rows[1:]})

    def test_real_ooxml_parts_relationships_styles_and_no_formula_errors(self):
        content = render_xlsx(self.report)
        with ZipFile(io.BytesIO(content)) as archive:
            self.assertIsNone(archive.testzip())
            expected = {
                "[Content_Types].xml",
                "_rels/.rels",
                "xl/workbook.xml",
                "xl/_rels/workbook.xml.rels",
                "xl/styles.xml",
                "xl/worksheets/sheet1.xml",
                "xl/worksheets/sheet2.xml",
            }
            self.assertEqual(set(archive.namelist()), expected)
            for name in archive.namelist():
                root = ET.fromstring(archive.read(name))
                self.assertFalse(
                    any(element.tag.endswith("}f") or element.tag == "f" for element in root.iter())
                )
                self.assertFalse(any(element.get("t") == "e" for element in root.iter()))
                self.assertFalse(
                    any(element.get("TargetMode") == "External" for element in root.iter())
                )
            sheet = ET.fromstring(archive.read("xl/worksheets/sheet1.xml"))
            self.assertEqual(
                sheet.find("s:sheetViews/s:sheetView/s:pane", NS).get("state"), "frozen"
            )
            self.assertIsNotNone(sheet.find("s:autoFilter", NS))
            self.assertIn(b"Calibri", archive.read("xl/styles.xml"))
            self.assertNotIn(b"<f>", content)

    def test_spreadsheet_formula_injection_bounds_and_minimised_privacy(self):
        for value in (
            '=HYPERLINK("https://example.invalid","click")',
            "+cmd",
            "-1+2",
            "@SUM(A1)",
            " \t=1+1",
            "\ufeff=1+1",
        ):
            self.assertTrue(safe_text(value).startswith("'"))
            report = copy.deepcopy(self.report)
            report["results"][0]["recommendation"] = value
            csv_rows = list(csv.reader(io.StringIO(render(report, "csv"))))
            self.assertTrue(any(row[4].startswith("'") for row in csv_rows[1:]))
            self.assertEqual(csv_rows, self.cells(render_xlsx(report)))
        for value in ("bad\x00value", "x" * 32768):
            report = copy.deepcopy(self.report)
            report["results"][0]["recommendation"] = value
            with self.assertRaises(InputError):
                render_xlsx(report)
        for content in (
            render(self.report, "csv", minimize=True),
            json.dumps(self.cells(render_xlsx(self.report, minimize=True))),
        ):
            self.assertNotIn(SCOPE, content)
            self.assertNotIn("private-fixture", content)
            self.assertNotIn("private-evidence", content)

    def test_executive_summary_first_heat_map_text_and_shared_denominators(self):
        output = render(self.report, "html")
        self.assertLess(output.index("Executive summary"), output.index("Catalog</dt>"))
        self.assertLess(output.index("Top risks by severity"), output.index('id="findings"'))
        self.assertIn("Design-area heat map", output)
        self.assertIn("Result-instance counts with text labels", output)
        self.assertIn('aria-label="fail:', output)
        self.assertIn("Assessed instances", output)
        self.assertIn("subset_pass_rate", output)
        self.assertIn("Unknown/manual instances still require work", output)
        empty = assess({**self.bundle, "resources": []}, self.catalog, at=AT, evidence_tiers=True)
        self.assertIn("unavailable", render(empty, "html"))
        stale = assess(self.bundle, self.catalog, at="2026-11-07T00:00:00Z", evidence_tiers=True)
        self.assertIn("stale", render(stale, "csv"))
        self.assertIn("unknown", {row[9] for row in self.cells(render_xlsx(stale))[1:]})

    def test_installed_exports_require_binary_file_and_preserve_existing_workbooks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "report.json"
            source.write_text(json.dumps(self.report), encoding="utf-8")
            command = [
                sys.executable,
                "-m",
                "alz_assessor.cli",
                "render",
                str(source),
                "--format",
                "xlsx",
            ]
            result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 2)
            target = root / "tracker.xlsx"
            result = subprocess.run(
                [*command, "--output", str(target)],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            before = target.read_bytes()
            self.assertEqual(len(self.cells(before)) - 1, len(self.report["results"]))
            result = subprocess.run(
                [*command, "--output", str(target)],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(target.read_bytes(), before)

    def test_bound_review_rationale_columns_and_minimized_redaction(self):
        from alz_assessor.contracts import control_digest

        control = next(c for c in self.catalog["controls"] if not c.get("rule"))
        manual = document(
            "manual",
            schema_version="1.1",
            entries=[
                {
                    "control_id": control["control_id"],
                    "control_sha256": control_digest(control),
                    "scope": SCOPE,
                    "reviewer": "=ReviewerName",
                    "evidence": "https://example.invalid/private-doc",
                    "rationale": "+Architecture decision rationale",
                    "valid_from": "2026-11-01T00:00:00Z",
                    "valid_until": "2026-12-01T00:00:00Z",
                    "outcome": "pass",
                }
            ],
        )
        reviewed = assess(self.bundle, self.catalog, at=AT, manual=manual, evidence_tiers=True)
        full_rows = list(csv.reader(io.StringIO(render(reviewed, "csv"))))
        self.assertEqual(full_rows, self.cells(render_xlsx(reviewed)))
        row = next(r for r in full_rows[1:] if r[0] == control["control_id"])
        self.assertEqual(
            row[16:19],
            ["'=ReviewerName", "'+Architecture decision rationale", "2026-12-01T00:00:00Z"],
        )
        min_rows = list(csv.reader(io.StringIO(render(reviewed, "csv", minimize=True))))
        self.assertEqual(min_rows, self.cells(render_xlsx(reviewed, minimize=True)))
        min_row = next(r for r in min_rows[1:] if r[0] == control["control_id"])
        self.assertEqual(min_row[16:19], ["", "", ""])
        for text in (
            render(reviewed, "csv", minimize=True),
            render(reviewed, "markdown", minimize=True),
            render(reviewed, "html", minimize=True),
        ):
            self.assertNotIn("ReviewerName", text)
            self.assertNotIn("Architecture decision rationale", text)
            self.assertNotIn("private-doc", text)
