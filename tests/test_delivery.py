import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from alz_assessor.catalog import load_catalog

CORPUS = Path(__file__).parent / "fixtures" / "alz-avm"
SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"


class DeliveryTests(unittest.TestCase):
    def test_installed_licensed_corpus_review_replay_and_retirement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def run(*arguments):
                result = subprocess.run(
                    [sys.executable, "-m", "alz_assessor.cli", *map(str, arguments)],
                    cwd=root,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    timeout=90,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                return result.stdout

            options = [
                "--input",
                "terraform",
                "--provider-version",
                "4.50.0",
                "--scope",
                SCOPE,
                "--snapshots",
                CORPUS / "snapshots.json",
            ]
            doctor = json.loads(run("doctor", CORPUS, *options))
            self.assertEqual(doctor["readiness"], "partial")
            normalized = root / "evidence.json"
            original = json.loads(run("assess", CORPUS, *options, "--evidence-output", normalized))
            self.assertEqual(original["coverage"]["controls"], 255)
            self.assertFalse(original["coverage"]["inventory_complete"])
            automated = [r for r in original["results"] if r["automation"] == "automated"]
            self.assertEqual(len(automated), 8)
            self.assertTrue(all(r["planned"]["outcome"] == "unknown" for r in automated))
            evidence = json.loads(normalized.read_text())
            self.assertEqual(len(evidence["diagnostics"]), 6)
            instant = evidence["collected_at"]
            reason = evidence["diagnostics"][0]["reason"]
            self.assertTrue(run("explain", reason).strip())
            report_path = root / "assessment.json"
            report_path.write_text(json.dumps(original), encoding="utf-8")
            control = next(r for r in original["results"] if r["automation"] == "manual")
            review_path = root / "review.json"
            run(
                "review",
                "prepare",
                report_path,
                "--control",
                control["control_id"],
                "--scope",
                SCOPE,
                "--output",
                review_path,
            )
            review = json.loads(review_path.read_text())
            self.assertTrue(review.pop("is_template"))
            review["entries"][0].update(
                reviewer="synthetic-corpus-reviewer",
                outcome="pass",
                rationale="Authored workflow evidence, not live tenant acceptance",
                evidence="review://synthetic-workflow",
                valid_from="2026-01-01T00:00:00Z",
                valid_until="2099-01-01T00:00:00Z",
            )
            review_path.write_text(json.dumps(review), encoding="utf-8")
            run("review", "validate", review_path, "--scope", SCOPE, "--at", instant)
            reviewed = json.loads(
                run(
                    "assess",
                    normalized,
                    "--input",
                    "evidence",
                    "--manual",
                    review_path,
                    "--at",
                    instant,
                )
            )
            row = next(r for r in reviewed["results"] if r["control_id"] == control["control_id"])
            self.assertEqual(row["planned"]["outcome"], "pass")
            destination = root / "replay"
            run(
                "replay",
                "export",
                normalized,
                "--destination",
                destination,
                "--manual",
                review_path,
                "--at",
                instant,
            )
            replayed = json.loads(run("replay", "run", destination))
            self.assertEqual(replayed["coverage"], reviewed["coverage"])
            for format in ("markdown", "html"):
                result = run("replay", "run", destination, "--format", format)
                self.assertIn("manual_attestation", result)
                self.assertNotIn("synthetic-corpus-reviewer", result)
            candidate = copy.deepcopy(load_catalog())
            candidate["catalog_version"] = "synthetic-retirement-fixture"
            retired = next(
                c for c in candidate["controls"] if c["control_id"] == control["control_id"]
            )
            retired.update(
                lifecycle="retired",
                retired_at=instant,
                retirement_reason="Synthetic lifecycle acceptance",
            )
            candidate_path = root / "candidate.json"
            candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
            promoted = root / "reviewed-catalog.json"
            run(
                "catalog",
                "refresh",
                "--reviewed",
                candidate_path,
                "--accept-reviewed",
                "--output",
                promoted,
            )
            retired_report = json.loads(
                run(
                    "assess",
                    normalized,
                    "--input",
                    "evidence",
                    "--catalog",
                    promoted,
                    "--at",
                    instant,
                )
            )
            self.assertEqual(retired_report["coverage"]["controls"], 254)
            self.assertEqual(retired_report["coverage"]["retired_controls"], 1)
            self.assertEqual(
                retired_report["retired_controls"][0]["control_id"], control["control_id"]
            )
