import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from alz_assessor.contracts import digest
from alz_assessor.terraform import InputError

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
spec = importlib.util.spec_from_file_location(
    "candidate_audit_for_tests", TOOLS / "audit_candidates.py"
)
audit_module = importlib.util.module_from_spec(spec)
with patch.object(sys, "path", [str(TOOLS), *sys.path]):
    spec.loader.exec_module(audit_module)


class CandidateAuditTests(unittest.TestCase):
    def test_exact_pinned_guid_population_review_and_reproducibility(self):
        baseline = ROOT / "references" / "2026-11-04"
        target = ROOT / "references" / "2026-11-04-wave1"
        checklist = json.loads((baseline / "alz-checklist.json").read_text("utf-8"))
        manifest = json.loads((target / "manifest.json").read_text("utf-8"))
        expected = json.loads((target / "candidate-audit.json").read_text("utf-8"))
        with patch("urllib.request.urlopen", side_effect=AssertionError("network")):
            actual = audit_module.build_audit(checklist, manifest)
        self.assertEqual(actual, expected)
        self.assertEqual(actual["source_manifest_sha256"], digest(manifest))
        queries = actual["query_audit"]
        self.assertEqual(len(queries), 49)
        self.assertEqual(len({entry["guid"] for entry in queries}), 49)
        self.assertEqual(
            {entry["guid"] for entry in queries},
            {entry["guid"] for entry in checklist["items"] if entry.get("graph")},
        )
        self.assertTrue(all(not entry["runtime_verified"] for entry in queries))
        self.assertTrue(all(len(entry["query_sha256"]) == 64 for entry in queries))
        self.assertEqual(set(actual["accepted_first_wave"]), {"D07.06", "D07.07"})
        self.assertEqual(
            {entry["display_id"] for entry in actual["nonquery_candidates"]},
            {"G02.03", "G04.02", "F01.08"},
        )
        original_guid = checklist["items"][0]["guid"]
        checklist["items"][0]["guid"] = "00000000-0000-0000-0000-000000000001"
        with self.assertRaisesRegex(InputError, "every GUID"):
            audit_module.build_audit(checklist, manifest)
        checklist["items"][0]["guid"] = original_guid
        checklist["items"] = [entry for entry in checklist["items"] if not entry.get("graph")]
        with self.assertRaisesRegex(InputError, "every GUID"):
            audit_module.build_audit(checklist, manifest)
