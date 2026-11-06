import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import control_digest, document, validate
from alz_assessor.engine import assess
from alz_assessor.priorities import archetype_bindings, load_priorities, sort_key, suggestions
from alz_assessor.replay import export_bundle, replay_bundle, semantic
from alz_assessor.reports import render
from alz_assessor.review_session import ReviewSession
from alz_assessor.terraform import InputError

AT = "2026-11-05T00:00:00Z"
SCOPE = "/providers/Microsoft.Management/managementGroups/private-fixture"


class PriorityTests(unittest.TestCase):
    def setUp(self):
        self.catalog = load_catalog()
        self.bundle = document(
            "evidence",
            schema_version="1.1",
            mode="observed",
            source="saved",
            collected_at=AT,
            scope=SCOPE,
            inventory_complete=False,
            artifact_hashes={"fixture": "0" * 64},
            diagnostics=[],
            resources=[],
        )
        self.mapping = {
            "collected_at": AT,
            "entries": [{"scope": SCOPE, "group_id": "landingzones"}],
        }

    def bound(self, mapping=None):
        bundle = copy.deepcopy(self.bundle)
        bundle["metadata"] = {
            "archetype_bindings": archetype_bindings(mapping or self.mapping, bundle)
        }
        return bundle

    def test_exact_frozen_history_source_severity_and_control_meaning(self):
        data = files("alz_assessor").joinpath("data")
        priority_catalog = load_catalog(str(data.joinpath("catalog-2026-11-05.5.json")))
        previous = data.joinpath("catalog-2026-11-05.3.json").read_bytes()
        self.assertEqual(
            hashlib.sha256(previous).hexdigest(),
            "8fefb7c4c8c8e09224493db1dbb41b4a5710ad57c0735f50ac3338702735e7b5",
        )
        before = {c["control_id"]: c for c in json.loads(previous)["controls"]}
        self.assertEqual(priority_catalog["catalog_version"], "2026-11-05.5")
        self.assertEqual(
            Counter(c["severity"] for c in self.catalog["controls"]),
            {"High": 71, "Medium": 158, "Low": 26},
        )
        for control in priority_catalog["controls"]:
            self.assertEqual(control_digest(control), control_digest(before[control["control_id"]]))
        self.assertEqual(
            Counter(c["automation"] for c in priority_catalog["controls"]),
            {"automated": 7, "assisted": 205, "manual": 43},
        )
        for source in load_priorities()["sources"]:
            self.assertIn(source["revision"], source["url"])
            self.assertEqual(source["release"], "platform/alz/2026.10.0")
            self.assertEqual(len(source["sha256"]), 64)
            self.assertEqual(len(source["license_sha256"]), 64)

    def test_order_is_severity_first_stable_and_unknown_last(self):
        rows = [
            {"severity": value, "control_id": str(i)}
            for i, value in enumerate(("Low", "Unknown", "High", "Medium", "unexpected"))
        ]
        self.assertEqual(
            [x["severity"] for x in sorted(rows, key=sort_key)],
            ["High", "Medium", "Low", "Unknown", "unexpected"],
        )
        for value in ("Critical", None, [], {}, True):
            catalog = copy.deepcopy(self.catalog)
            catalog["controls"][0]["severity"] = value
            with self.assertRaisesRegex(InputError, "severity"):
                validate(catalog)

    def test_reports_and_queue_share_severity_without_outcome_changes(self):
        report = assess(self.bundle, self.catalog, at=AT, evidence_tiers=True)
        model = json.loads(render(report))
        ranks = [
            ("High", "Medium", "Low", "Unknown").index(row["severity"]) for row in model["results"]
        ]
        self.assertEqual(ranks, sorted(ranks))
        for format in ("markdown", "html"):
            output = render(report, format)
            self.assertLess(output.find("High"), output.find("Medium"))
            self.assertLess(output.find("Medium"), output.find("Low"))
        with tempfile.TemporaryDirectory() as temp:
            session = ReviewSession(
                self.bundle, self.catalog, Path(temp) / "reviews", clock=lambda: AT
            )
            ranks = [
                ("High", "Medium", "Low", "Unknown").index(c["severity"]) for c in session.controls
            ]
            self.assertEqual(ranks, sorted(ranks))
        old = load_catalog(str(files("alz_assessor").joinpath("data", "catalog-2026-11-05.3.json")))
        before = assess(self.bundle, old, at=AT)
        frozen = load_catalog(
            str(files("alz_assessor").joinpath("data", "catalog-2026-11-05.5.json"))
        )
        priority_only = assess(self.bundle, frozen, at=AT, evidence_tiers=True)
        self.assertEqual(
            [(r["control_id"], r["observed"]["outcome"]) for r in priority_only["results"]],
            [(r["control_id"], r["observed"]["outcome"]) for r in before["results"]],
        )
        self.assertNotIn("severity", before["results"][0])

    def test_explicit_suggestion_never_changes_applicability_or_outcome(self):
        report = assess(self.bound(), self.catalog, at=AT, evidence_tiers=True)
        proposal = report["applicability_suggestions"][0]
        self.assertEqual(
            proposal["suggested_controls"], ["ALZ-b03ed428-4617-4067-a787-85468b9ccf3f"]
        )
        self.assertIs(proposal["requires_confirmation"], True)
        row = next(r for r in report["results"] if r["upstream_id"] == "G04.01")
        self.assertEqual(row["observed"]["outcome"], "unknown")
        self.assertEqual(row["applicability"], ["platform", "application"])
        for format in ("json", "markdown", "html"):
            output = render(report, format, minimize=True)
            self.assertNotIn("private-fixture", output)
            self.assertIn("requires_confirmation", output)

    def test_missing_stale_and_unreviewed_archetypes_remain_explicit(self):
        self.assertEqual(suggestions([self.bundle], AT), [])
        mapping = copy.deepcopy(self.mapping)
        mapping["collected_at"] = "2000-01-01T00:00:00Z"
        proposal = suggestions([self.bound(mapping)], AT)[0]
        self.assertEqual(proposal["suggested_controls"], [])
        self.assertEqual(proposal["reason"], "stale_archetype_binding")
        mapping = copy.deepcopy(self.mapping)
        mapping["entries"][0]["group_id"] = "corp"
        proposal = suggestions([self.bound(mapping)], AT)[0]
        self.assertEqual(proposal["suggested_controls"], [])
        self.assertEqual(proposal["reason"], "archetype_mapping_not_reviewed")

    def test_binding_guards_and_no_raw_fields(self):
        for field, value in (
            ("scope", "landingzones"),
            ("scope", SCOPE + "-foreign"),
            ("scope", "/subscriptions/00000000-0000-0000-0000-000000000001"),
            ("group_id", "Private-Guess"),
            ("group_id", None),
        ):
            mapping = copy.deepcopy(self.mapping)
            mapping["entries"][0][field] = value
            with self.assertRaises(InputError):
                archetype_bindings(mapping, self.bundle)
        for entries in ([], self.mapping["entries"] * 2, self.mapping["entries"] * 101):
            with self.assertRaises(InputError):
                archetype_bindings({**self.mapping, "entries": entries}, self.bundle)
        mapping = copy.deepcopy(self.mapping)
        mapping["entries"][0]["raw"] = "PRIVATE-NOT-FOR-REPORTING"
        with self.assertRaises(InputError):
            archetype_bindings(mapping, self.bundle)
        with self.assertRaises(InputError):
            archetype_bindings(self.mapping, {**self.bundle, "scope": None})

    def test_suggestion_schema_requires_confirmation_and_safe_fields(self):
        report = assess(self.bound(), self.catalog, at=AT, evidence_tiers=True)
        for field, value in (
            ("requires_confirmation", False),
            ("requires_confirmation", "true"),
            ("archetypes", ["private-name"]),
            ("group_id", "private-name"),
            ("suggested_controls", ["all"]),
            ("source_sha256", "bad"),
        ):
            changed = copy.deepcopy(report)
            changed["applicability_suggestions"][0][field] = value
            with self.assertRaises(InputError):
                validate(changed)
        changed = copy.deepcopy(report)
        changed["applicability_suggestions"][0]["raw"] = "PRIVATE-NOT-FOR-REPORTING"
        with self.assertRaisesRegex(InputError, "Unexpected"):
            validate(changed)

    def test_replay_preserves_binding_time_and_suggestion_semantics(self):
        bundle = self.bound()
        report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "replay"
            with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
                export_bundle(destination, bundle, self.catalog, at=AT, evidence_tiers=True)
                replayed = replay_bundle(destination)
            self.assertEqual(semantic(replayed), semantic(report))
            self.assertEqual(replayed["applicability_suggestions"][0]["collected_at"], AT)

    def test_installed_cli_archetype_input_requires_explicit_tier_flag(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            evidence = root / "evidence.json"
            evidence.write_text(json.dumps(self.bundle), encoding="utf-8")
            bindings = root / "bindings.json"
            bindings.write_text(json.dumps(self.mapping), encoding="utf-8")
            command = [
                sys.executable,
                "-m",
                "alz_assessor.cli",
                "assess",
                str(evidence),
                "--input",
                "evidence",
                "--archetypes",
                str(bindings),
                "--at",
                AT,
            ]
            result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 2)
            self.assertIn("--evidence-tiers", result.stderr)
            result = subprocess.run(
                [*command, "--evidence-tiers"], cwd=root, capture_output=True, text=True, timeout=30
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIs(
                json.loads(result.stdout)["applicability_suggestions"][0]["requires_confirmation"],
                True,
            )
