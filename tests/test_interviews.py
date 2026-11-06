import copy
import json
import re
import subprocess
import sys
import tempfile
import unittest
from collections import Counter, defaultdict
from pathlib import Path

from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import document
from alz_assessor.crosswalk import load_crosswalk
from alz_assessor.engine import assess
from alz_assessor.interviews import compile_interview, prepare_interview, question_bank
from alz_assessor.terraform import InputError

AT = "2026-11-05T00:00:00Z"
SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"


class InterviewTests(unittest.TestCase):
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
            resources=[],
        )
        self.report = assess(self.bundle, self.catalog, at=AT, evidence_tiers=True)
        self.response = prepare_interview(self.report, self.catalog, "private-service-paths", SCOPE)

    def completed(self):
        response = copy.deepcopy(self.response)
        response.update(
            answer="Authored fixture: explicit path evidence reviewed.",
            reviewer="Fixture reviewer",
            rationale="Separate decisions below.",
            evidence="https://example.invalid/evidence",
            valid_from=AT,
            valid_until="2026-11-06T00:00:00Z",
        )
        for i, decision in enumerate(response["decisions"]):
            decision["outcome"] = "pass" if i == 0 else "fail"
        return response

    def test_bank_specific_requirements_and_blank_explicit_decisions(self):
        bank = question_bank(self.catalog)
        self.assertEqual(len(bank["questions"]), 3)
        for question in bank["questions"]:
            self.assertTrue(question["question"])
            self.assertTrue(
                all(control["evidence_requirements"] for control in question["controls"])
            )
        self.assertEqual(len(self.response["decisions"]), 2)
        for field in ("answer", "reviewer", "rationale", "evidence", "valid_from", "valid_until"):
            self.assertIsNone(self.response[field])
        self.assertTrue(all(decision["outcome"] is None for decision in self.response["decisions"]))
        with self.assertRaises(InputError):
            compile_interview(self.response, self.catalog, at=AT)

    def test_one_narrative_compiles_separate_bound_decisions_without_technical_override(self):
        manual = compile_interview(self.completed(), self.catalog, at=AT)
        self.assertEqual(len(manual["entries"]), 2)
        self.assertEqual([entry["outcome"] for entry in manual["entries"]], ["pass", "fail"])
        report = assess(self.bundle, self.catalog, at=AT, evidence_tiers=True, manual=manual)
        for entry in manual["entries"]:
            row = next(row for row in report["results"] if row["control_id"] == entry["control_id"])
            self.assertEqual(row["observed"]["outcome"], entry["outcome"])
            self.assertNotEqual(row["observed"]["evidence_tier"], "verified")
        self.assertTrue(all(entry["reviewer"] == "Fixture reviewer" for entry in manual["entries"]))

    def test_answer_alone_expiry_duplicate_content_scope_and_partial_failure_guards(self):
        for field, value in (
            ("answer", " "),
            ("reviewer", None),
            ("evidence", ""),
            ("valid_until", "2000-01-01T00:00:00Z"),
            ("catalog_sha256", "0" * 64),
            ("bank_version", "unknown"),
            ("requirements_sha256", "0" * 64),
            ("scope", "name"),
        ):
            response = self.completed()
            response[field] = value
            with self.assertRaises(InputError):
                compile_interview(response, self.catalog, at=AT)
        for field, value in (
            ("outcome", None),
            ("control_sha256", "0" * 64),
            ("control_id", "ALZ-other"),
        ):
            response = self.completed()
            response["decisions"][1][field] = value
            with self.assertRaises(InputError):
                compile_interview(response, self.catalog, at=AT)
        response = self.completed()
        response["decisions"][1] = response["decisions"][0]
        with self.assertRaisesRegex(InputError, "duplicate"):
            compile_interview(response, self.catalog, at=AT)
        response = self.completed()
        response["raw"] = "PRIVATE-NOT-FOR-REPORTING"
        with self.assertRaisesRegex(InputError, "exact fields"):
            compile_interview(response, self.catalog, at=AT)

    def test_selection_and_installed_cli_no_overwrite(self):
        for selected in ([], ["unknown"], self.response["decisions"]):
            with self.assertRaises(InputError):
                prepare_interview(
                    self.report, self.catalog, "private-service-paths", SCOPE, selected
                )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            response = root / "response.json"
            response.write_text(json.dumps(self.completed()), encoding="utf-8")
            output = root / "manual.json"
            command = [
                sys.executable,
                "-m",
                "alz_assessor.cli",
                "interview",
                "apply",
                str(response),
                "--at",
                AT,
                "--output",
                str(output),
            ]
            result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(json.loads(output.read_text())["entries"]), 2)
            before = output.read_bytes()
            result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(output.read_bytes(), before)

    def test_backlog_priority_matches_fixed_pending_membership_and_sources(self):
        repository = Path(__file__).parents[1]
        ledger = json.loads(
            (repository / "references/recommendation-batches/ledger.json").read_text()
        )
        controls = {control["control_id"]: control for control in self.catalog["controls"]}
        mapped = {
            entry["control_id"]
            for entry in load_crosswalk(self.catalog)["entries"]
            if entry["targets"]
        }
        groups = defaultdict(list)
        for entry in ledger["recommendations"]:
            if entry["status"] != "merged":
                groups[entry["batch"]].append(entry)
        expected = []
        for batch, entries in sorted(
            groups.items(),
            key=lambda item: (
                -sum(controls[e["control_id"]]["severity"] == "High" for e in item[1]),
                -sum(e["control_id"] in mapped for e in item[1]),
                item[0],
            ),
        ):
            counts = Counter(controls[e["control_id"]]["severity"] for e in entries)
            expected.append(
                (
                    batch,
                    len(entries),
                    counts["High"],
                    counts["Medium"],
                    counts["Low"],
                    sum(e["control_id"] in mapped for e in entries),
                )
            )
        text = (repository / "docs/planning/backlog.md").read_text()
        actual = [
            (batch, *map(int, (total, high, medium, low, covered)))
            for batch, total, high, medium, low, covered in re.findall(
                r"\| (\d{2}) \| (\d+) \| (\d+) / (\d+) / (\d+) \| (\d+) \|", text
            )
        ]
        self.assertEqual(actual, expected)
        self.assertEqual(sum(row[1] for row in actual), 206)
