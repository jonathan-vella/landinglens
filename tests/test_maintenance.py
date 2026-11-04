import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from alz_assessor.maintenance import indexed_items, public_fetch, semantic_diff, sha256, taxonomy
from alz_assessor.terraform import InputError

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "references" / "2026-11-04"
TOOLS = ROOT / "tools"
spec = importlib.util.spec_from_file_location(
    "source_monitor_for_tests", TOOLS / "monitor_sources.py"
)
monitor_module = importlib.util.module_from_spec(spec)
with patch.object(sys, "path", [str(TOOLS), *sys.path]):
    spec.loader.exec_module(monitor_module)

AT = "2026-11-04T20:00:00Z"


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.before = json.loads((BASE / "alz-checklist.json").read_text("utf-8"))
        self.taxonomy = (BASE / "caf-design-areas.md").read_text("utf-8")

    def diff(self, after, **changes):
        arguments = {
            "before_taxonomy": self.taxonomy,
            "after_taxonomy": self.taxonomy,
            "before_licenses": {"source": "a"},
            "after_licenses": {"source": "a"},
            **changes,
        }
        return semantic_diff(self.before, after, **arguments)

    def test_guid_changes_every_item_field_and_display_collisions(self):
        after = copy.deepcopy(self.before)
        removed = after["items"].pop()
        item = after["items"][0]
        for field in ("text", "category", "link", "graph", "applicability"):
            item[field] = "changed"
        added = copy.deepcopy(item)
        added["guid"] = "00000000-0000-0000-0000-000000000001"
        after["items"].append(added)
        result = self.diff(after)
        self.assertIn(removed["guid"], result["removed_guids_require_retirement"])
        self.assertEqual(result["added_guids"], [added["guid"]])
        self.assertEqual(
            result["changed"][0]["fields"], ["applicability", "category", "graph", "link", "text"]
        )
        self.assertIn(item["id"], result["display_id_collisions"])
        self.assertTrue(result["changed"][0]["review_bindings_require_review"])
        self.assertEqual(result, self.diff(after))
        after["items"].append(copy.deepcopy(added))
        with self.assertRaisesRegex(InputError, "Conflicting"):
            indexed_items(after)

    def test_schema_metadata_taxonomy_license_and_malformed_inputs(self):
        self.assertEqual(len(taxonomy(self.taxonomy)), 8)
        after = copy.deepcopy(self.before)
        after["new_top_field"] = True
        after["metadata"] = {"changed": True}
        result = self.diff(
            after,
            after_taxonomy=self.taxonomy + "\n[New](./design-area/new)\n",
            after_licenses={"source": "changed"},
        )
        self.assertTrue(result["schema_changed"])
        self.assertTrue(result["metadata_changed"])
        self.assertTrue(result["taxonomy_changed"])
        self.assertEqual(result["license_changes"], ["source"])
        for invalid in (None, {}, {"items": [None]}, {"items": [{"guid": []}]}):
            with self.assertRaises(InputError):
                indexed_items(invalid)

    def fetch(self, url):
        if url.startswith("https://api.github.com/"):
            return json.dumps({"sha": "1" * 40}).encode()
        for name, (repo, _, path, _, _) in monitor_module.SOURCES.items():
            prefix = f"https://raw.githubusercontent.com/{repo}/{'1' * 40}/"
            if url == prefix + "LICENSE":
                return (BASE / (name + ".LICENSE")).read_bytes()
            if url == prefix + path:
                return (BASE / (name + (".json" if path.endswith(".json") else ".md"))).read_bytes()
        raise AssertionError("Unexpected source request: " + url)

    def test_poll_retains_immutable_bytes_and_separate_review_state(self):
        frozen = sha256((BASE / "manifest.json").read_bytes())
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "candidate"
            status = monitor_module.monitor(BASE, target, self.fetch, at=AT)
            self.assertIsNone(status["warning"])
            self.assertEqual(status["last_successful_poll"], AT)
            self.assertFalse(status["pending_changes"])
            self.assertFalse(status["promotion_allowed"])
            self.assertNotEqual(status["last_semantic_review"], AT)
            self.assertEqual(
                (target / "alz-checklist.json").read_bytes(),
                (BASE / "alz-checklist.json").read_bytes(),
            )
            with self.assertRaises(InputError):
                monitor_module.monitor(BASE, target, self.fetch, at=AT)
        self.assertEqual(frozen, sha256((BASE / "manifest.json").read_bytes()))

    def test_failed_or_malformed_poll_retains_previous_success_and_catalog(self):
        for corrupt in (False, True, "commit_array"):

            def failing(url, corrupt=corrupt):
                if corrupt == "commit_array" and url.startswith("https://api.github.com/"):
                    return b"[]"
                if corrupt and url.endswith("alz_checklist.en.json"):
                    return b'{"items": [null]}'
                if not corrupt:
                    raise OSError("network unavailable")
                return self.fetch(url)

            with tempfile.TemporaryDirectory() as temporary:
                status = monitor_module.monitor(
                    BASE,
                    Path(temporary) / "candidate",
                    failing,
                    at=AT,
                    previous_status={"last_successful_poll": "2026-10-01T00:00:00Z"},
                )
                self.assertIn("unchanged", status["warning"])
                self.assertEqual(status["last_successful_poll"], "2026-10-01T00:00:00Z")
                self.assertFalse(status["promotion_allowed"])

    def test_changed_license_withholds_source_and_unsafe_hosts_never_connect(self):
        def changed(url):
            return (
                b"Changed terms requiring review" if url.endswith("/LICENSE") else self.fetch(url)
            )

        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "candidate"
            status = monitor_module.monitor(BASE, target, changed, at=AT)
            self.assertTrue(status["pending_changes"])
            self.assertIn("license_review_required", status)
            self.assertFalse(any(target.glob("*.md")))
        with patch("urllib.request.build_opener", side_effect=AssertionError("network")):
            for url in (
                "http://api.github.com/test",
                "https://evil.example/x",
                "https://api.github.com@evil.example/x",
            ):
                with self.assertRaises(InputError):
                    public_fetch(url)
