import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from test_contracts import SCOPE, evidence, resource

from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import control_digest, document
from alz_assessor.engine import assess
from alz_assessor.replay import export_bundle, replay_bundle, sanitize_evidence, semantic
from alz_assessor.terraform import InputError

AT = "2026-11-04T00:00:00Z"
PRIVATE = "PRIVATE-REPLAY-SENTINEL"


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.destination = self.root / "bundle"
        self.catalog = load_catalog()
        item = resource(SCOPE + "/providers/Microsoft.Storage/storageAccounts/test")
        item["properties"] = {"supportsHttpsTrafficOnly": True, "raw-secret": PRIVATE}
        item["source_location"] = "C:\\" + PRIVATE + "\\source.tf"
        self.evidence = evidence(resources=[item], complete=False)
        self.evidence["metadata"] = {"private": PRIVATE, "scopes": [SCOPE]}
        self.evidence["diagnostics"] = [{"reason": PRIVATE, "payload": PRIVATE}]
        self.evidence["artifact_hashes"][PRIVATE] = "a" * 64
        control = next(c for c in self.catalog["controls"] if c["automation"] == "manual")
        self.manual = document(
            "manual",
            schema_version="1.1",
            entries=[
                {
                    "control_id": control["control_id"],
                    "control_sha256": control_digest(control),
                    "scope": SCOPE,
                    "reviewer": PRIVATE,
                    "evidence": "https://example.test/" + PRIVATE,
                    "rationale": PRIVATE,
                    "valid_from": "2026-01-01T00:00:00Z",
                    "valid_until": "2027-01-01T00:00:00Z",
                    "outcome": "pass",
                    "disposition": PRIVATE,
                    "unrecognized": PRIVATE,
                }
            ],
        )

    def export(self, **options):
        return export_bundle(
            self.destination, self.evidence, self.catalog, at=AT, manual=self.manual, **options
        )

    def rewrite(self, name, value):
        path = self.destination / name
        content = (json.dumps(value) + "\n").encode()
        path.write_bytes(content)
        if name != "manifest.json":
            manifest_path = self.destination / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["files"][name] = {
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    def test_sanitized_reviews_metadata_and_semantic_replay(self):
        with patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden")):
            result = self.export()
            replayed = replay_bundle(self.destination)
        expected = assess(self.evidence, self.catalog, manual=self.manual, at=AT)
        self.assertEqual(semantic(replayed), semantic(expected))
        self.assertFalse(replayed["coverage"]["inventory_complete"])
        self.assertIn("not anonymized", result["warning"])
        for path in self.destination.iterdir():
            self.assertNotIn(PRIVATE, path.read_text("utf-8"))
        with self.assertRaises(FileExistsError):
            self.export()

    def test_expired_review_and_explicit_attribution_opt_in(self):
        self.manual["entries"][0]["valid_until"] = "2026-03-01T00:00:00Z"
        self.export(retain_attribution=True)
        replayed = replay_bundle(self.destination)
        row = next(
            r
            for r in replayed["results"]
            if r["control_id"] == self.manual["entries"][0]["control_id"]
        )
        self.assertEqual(row["planned"]["outcome"], "manual")
        self.assertEqual(row["planned"]["reviews"][0]["reviewer"], PRIVATE)
        records = json.loads((self.destination / "reviews.json").read_text())
        self.assertNotIn(PRIVATE, records["manual"]["entries"][0]["rationale"])

    def test_hash_tampering_and_semantic_tampering_are_distinct(self):
        self.export()
        path = self.destination / "evidence.json"
        original = path.read_bytes()
        path.write_bytes(original + b" ")
        with self.assertRaisesRegex(InputError, "hash or size"):
            replay_bundle(self.destination)
        path.write_bytes(original)
        changed = json.loads(original)
        changed["resources"][0]["properties"]["supportsHttpsTrafficOnly"] = False
        self.rewrite("evidence.json", changed)
        with self.assertRaisesRegex(InputError, "semantic"):
            replay_bundle(self.destination)

    def test_manifest_paths_schema_bounds_and_unavailable_catalog(self):
        self.export()
        path = self.destination / "manifest.json"
        original = json.loads(path.read_text())
        for field, value in (
            ("files", {"../outside.json": {"sha256": "a" * 64, "size": 1}}),
            ("invocation", {"at": AT, "landing_zone": "platform", "max_age_hours": True}),
            ("schema_version", "99"),
        ):
            self.rewrite("manifest.json", {**original, field: value})
            with self.assertRaises(InputError):
                replay_bundle(self.destination)
        self.rewrite("manifest.json", original)
        (self.destination / "extra.json").write_text("{}")
        with self.assertRaisesRegex(InputError, "four fixed"):
            replay_bundle(self.destination)
        (self.destination / "extra.json").unlink()
        with patch("alz_assessor.replay.MAX_BYTES", 10):
            with self.assertRaisesRegex(InputError, "byte limit"):
                replay_bundle(self.destination)
        unknown = copy.deepcopy(self.catalog)
        unknown["catalog_version"] = "unavailable-historical-version"
        with self.assertRaisesRegex(InputError, "unavailable"):
            export_bundle(self.root / "unknown", self.evidence, unknown, at=AT)
        self.assertFalse((self.root / "unknown").exists())
        self.evidence["presentation_only"] = True
        with self.assertRaisesRegex(InputError, "not replayable"):
            export_bundle(self.root / "minimized", self.evidence, self.catalog, at=AT)

    def test_linked_member_cannot_read_or_overwrite_other_data(self):
        self.export()
        outside = self.root / "outside.json"
        outside.write_text("private outside data", encoding="utf-8")
        member = self.destination / "evidence.json"
        member.unlink()
        os.link(outside, member)
        with self.assertRaisesRegex(InputError, "without links"):
            replay_bundle(self.destination)
        self.assertEqual(outside.read_text(), "private outside data")

    def test_exact_byte_and_resource_limits_and_frozen_catalog_replay(self):
        historical = load_catalog(
            str(files("alz_assessor").joinpath("data").joinpath("catalog-2026-11-04.1.json"))
        )
        export_bundle(self.destination, self.evidence, historical, at=AT)
        path = self.destination / "evidence.json"
        original = path.read_bytes()
        limit = 8_000_000
        at_limit = original + b" " * (limit - len(original))
        path.write_bytes(at_limit)
        manifest_path = self.destination / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["files"]["evidence.json"] = {
            "size": limit,
            "sha256": hashlib.sha256(at_limit).hexdigest(),
        }
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertEqual(replay_bundle(self.destination)["coverage"]["automated_controls"], 2)
        with path.open("ab") as stream:
            stream.write(b" ")
        with self.assertRaisesRegex(InputError, "byte limit"):
            replay_bundle(self.destination)
        bundle = evidence()
        bundle["resources"] = [
            {**resource(), "logical_id": f"synthetic-{index}"} for index in range(10_000)
        ]
        self.assertEqual(len(sanitize_evidence(bundle)["resources"]), 10_000)
        bundle["resources"].append({**resource(), "logical_id": "over-limit"})
        with self.assertRaisesRegex(InputError, "resource limit"):
            sanitize_evidence(bundle)

    def test_installed_cli_export_and_replay_outside_checkout(self):
        source = self.root / "normalized.json"
        source.write_text(json.dumps(self.evidence), encoding="utf-8")

        def run(*arguments):
            result = subprocess.run(
                [sys.executable, "-m", "alz_assessor.cli", "replay", *map(str, arguments)],
                cwd=self.root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=60,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout

        run("export", source, "--destination", self.destination, "--at", AT)
        for format in ("json", "markdown", "html"):
            result = run("run", self.destination, "--format", format)
            self.assertIn("G04.01", result)
            self.assertIn("explicit_property_matches", result)
            self.assertNotIn(PRIVATE, result)
        replayed = replay_bundle(self.destination)
        self.assertEqual(semantic(replayed), semantic(assess(self.evidence, self.catalog, at=AT)))
