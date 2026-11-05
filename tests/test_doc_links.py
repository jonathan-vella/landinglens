import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location(
    "check_links_for_tests", ROOT / "tools/check_links.py"
)
LINKS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LINKS)


class DocumentationLinkTests(unittest.TestCase):
    def test_all_authored_markdown_local_links_and_anchors_resolve(self):
        paths = [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]
        with patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden")):
            result = LINKS.check(ROOT, paths)
        self.assertEqual(result["broken"], [])
        self.assertGreater(result["links_checked"], 100)

    def test_missing_duplicate_headings_fences_and_public_origin_guards(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source.md"
            target = root / "target.md"
            target.write_text("# Heading\n## Heading\n", encoding="utf-8")
            source.write_text(
                "[Good](target.md#heading-1)\n```\n[Ignored](missing)\n```\n[Bad](target.md#absent)\n",
                encoding="utf-8",
            )
            result = LINKS.check(root, [source])
            self.assertEqual(len(result["broken"]), 1)
            self.assertIn("absent", result["broken"][0]["link"])
            (root / "alias").mkdir()
            aliased = root / "alias" / ".." / "source.md"
            normalised = LINKS.check(root, [aliased])
            self.assertEqual(normalised["broken"][0]["file"], "source.md")
        with patch("urllib.request.urlopen", side_effect=AssertionError("live origin forbidden")):
            for url in (
                "https://management.azure.com",
                "http://localhost",
                "https://example.invalid",
            ):
                self.assertEqual(LINKS.public_status(url)["status"], "not-checked")
