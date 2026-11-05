import copy
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from alz_assessor.catalog import catalog_lag, load_catalog
from alz_assessor.catalog_updates import candidate_catalog, pr_body
from alz_assessor.contracts import digest
from alz_assessor.engine import assess
from alz_assessor.maintenance import sha256
from alz_assessor.terraform import InputError

ROOT = Path(__file__).parents[1]
AT = "2026-11-05T11:30:15Z"


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / (name + ".py"))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class CatalogUpdateTests(unittest.TestCase):
    def setUp(self):
        self.catalog = load_catalog()
        self.checklist = json.loads((ROOT / "references/2026-11-04/alz-checklist.json").read_text())

    def update(self, after=None, external=None):
        return candidate_catalog(
            self.catalog, self.checklist, after or self.checklist, at=AT, external_changes=external
        )

    def test_unchanged_safe_links_and_ambiguous_wording_severity_queries(self):
        frozen = digest(self.catalog)
        self.assertEqual(self.update()["classification"], "unchanged")
        for field in ("link", "training", "text", "severity", "graph"):
            after = copy.deepcopy(self.checklist)
            after["items"][0][field] = (
                "https://learn.microsoft.com/verified"
                if field in ("link", "training")
                else ("Low" if field == "severity" else "changed")
            )
            result = self.update(after)
            self.assertEqual(
                result["classification"],
                "safe" if field in ("link", "training") else "needs-review",
            )
            self.assertTrue(
                next(row for row in result["changes"] if row["guid"] == after["items"][0]["guid"])[
                    "reviews_require_review"
                ]
            )
            self.assertIn("Actual checks", pr_body(result, "Authored fixture: unit tests passed"))
        after = copy.deepcopy(self.checklist)
        after["items"][0]["link"] = "javascript:alert(1)"
        self.assertEqual(self.update(after)["classification"], "needs-review")
        self.assertEqual(digest(self.catalog), frozen)
        with self.assertRaises(InputError):
            pr_body(self.update(), "")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "candidate.json"
            path.write_text(json.dumps(self.update()["candidate"]), encoding="utf-8")
            with self.assertRaisesRegex(InputError, "candidates"):
                load_catalog(str(path))
        evidence = json.loads((ROOT / "tests/fixtures/slice/observed.json").read_text())
        with self.assertRaisesRegex(InputError, "not accepted"):
            assess(evidence, self.update()["candidate"], at=evidence["collected_at"])

    def test_new_removed_guid_retirement_and_external_crosswalk_invalidate_reviews(self):
        after = copy.deepcopy(self.checklist)
        removed = after["items"].pop()
        added = copy.deepcopy(after["items"][0])
        added.update(guid="00000000-0000-0000-0000-000000000001", id="NEW.01")
        after["items"].append(added)
        result = self.update(after)
        candidate = result["candidate"]
        self.assertEqual(len(candidate["controls"]), 256)
        retired = next(c for c in candidate["controls"] if c["upstream_guid"] == removed["guid"])
        self.assertEqual(retired["lifecycle"], "retired")
        new = next(c for c in candidate["controls"] if c["upstream_guid"] == added["guid"])
        self.assertEqual(new["automation"], "assisted")
        self.assertIsNone(new["rule"])
        result = self.update(external=["builtin-definition-tree"])
        self.assertEqual(result["classification"], "needs-review")
        self.assertTrue(all(row["reviews_require_review"] for row in result["changes"]))
        duplicate = copy.deepcopy(after)
        duplicate["items"].append(duplicate["items"][0])
        with self.assertRaises(InputError):
            self.update(duplicate)

    def test_publication_settings_denial_keeps_artifacts_and_never_mutates_settings(self):
        publisher = module("publish_catalog_update")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            directory = root / "candidate"
            directory.mkdir()
            (directory / "catalog-update.json").write_text(json.dumps({"classification": "safe"}))
            commands = []

            def run(*args):
                commands.append(args)
                return subprocess.CompletedProcess(
                    args, 0, '{"can_approve_pull_request_reviews":false}', ""
                )

            with patch.object(publisher, "command", side_effect=run):
                result = publisher.publish(directory, "owner/repo", "123", workspace=root)
            self.assertFalse(result["published"])
            self.assertIn("disabled", result["blocker"])
            self.assertEqual(len(commands), 1)
            self.assertFalse((root / "references").exists())
            self.assertTrue((directory / "publication-status.json").is_file())
            self.assertFalse(any("--method" in command for command in commands))

    def test_safe_pr_never_requests_auto_merge_without_actual_platform_checks(self):
        publisher = module("publish_catalog_update")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            directory = root / "candidate"
            directory.mkdir()
            for name in (
                "candidate-catalog.json",
                "PR-BODY.md",
                "manifest.json",
                "extended-source-status.json",
            ):
                (directory / name).write_text("{}")
            (directory / "catalog-update.json").write_text(json.dumps({"classification": "safe"}))
            commands = []

            def run(*args):
                commands.append(args)
                output = ""
                if args[:2] == ("gh", "api"):
                    output = '{"can_approve_pull_request_reviews":true,"allow_auto_merge":true}'
                elif args[:3] == ("gh", "pr", "create"):
                    output = "https://github.com/owner/repo/pull/1"
                elif args[:3] == ("gh", "pr", "checks"):
                    output = "[]"
                return subprocess.CompletedProcess(args, 0, output, "")

            with patch.object(publisher, "command", side_effect=run):
                result = publisher.publish(directory, "owner/repo", "123", workspace=root)
            self.assertTrue(result["published"])
            self.assertFalse(result["auto_merge_requested"])
            self.assertIn("not all green", result["blocker"])
            self.assertFalse(any(command[:3] == ("gh", "pr", "merge") for command in commands))

    def test_only_safe_with_all_real_checks_can_request_auto_merge(self):
        publisher = module("publish_catalog_update")
        for classification in ("safe", "needs-review"):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                directory = root / "candidate"
                directory.mkdir()
                for name in (
                    "candidate-catalog.json",
                    "PR-BODY.md",
                    "manifest.json",
                    "extended-source-status.json",
                ):
                    (directory / name).write_text("{}")
                (directory / "catalog-update.json").write_text(
                    json.dumps({"classification": classification})
                )
                operations = []

                def run(*args, operations=operations):
                    operations.append(args)
                    output = ""
                    if args[:2] == ("gh", "api"):
                        output = '{"can_approve_pull_request_reviews":true,"allow_auto_merge":true}'
                    elif args[:3] == ("gh", "pr", "create"):
                        output = "https://github.com/owner/repo/pull/1"
                    elif args[:3] == ("gh", "pr", "checks"):
                        output = json.dumps(
                            [
                                {"name": f"checks ({os}, {version})", "state": "SUCCESS"}
                                for os in ("ubuntu-latest", "windows-latest")
                                for version in ("3.12", "3.13")
                            ]
                        )
                    elif args[:3] == ("gh", "pr", "view") or args[:2] == ("git", "rev-parse"):
                        output = "0" * 40
                    return subprocess.CompletedProcess(args, 0, output, "")

                with patch.object(publisher, "command", side_effect=run):
                    result = publisher.publish(directory, "owner/repo", "123", workspace=root)
                self.assertEqual(result["auto_merge_requested"], classification == "safe")
                self.assertEqual(
                    any(op[:3] == ("gh", "pr", "merge") for op in operations),
                    classification == "safe",
                )

    def test_local_known_version_lag_is_explicit_and_never_network_refresh(self):
        index = {
            "schema_version": "1.0",
            "kind": "accepted-catalog-index",
            "catalogs": [
                {"version": version, "sha256": "0" * 64}
                for version in ("2026-11-05.2", "2026-11-05.5", "2026-11-05.10")
            ],
        }
        status = catalog_lag("2026-11-05.5", index)
        self.assertEqual(status["versions_behind"], 1)
        self.assertEqual(status["known_latest"], "2026-11-05.10")
        self.assertIn("producer assertion", status["warning"])
        for value in ({}, {**index, "catalogs": []}, {**index, "catalogs": index["catalogs"] * 2}):
            with self.assertRaises(InputError):
                catalog_lag("2026-11-05.5", value)

    def test_release_publication_accepts_only_installed_catalog_and_never_overwrites(self):
        publisher = module("publish_accepted_catalog")
        with patch.object(
            publisher.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)
        ):
            result = publisher.publish("owner/repo", "0" * 40)
        self.assertFalse(result["published"])
        self.assertIn("not replaced", result["reason"])
        with patch.object(
            publisher.subprocess,
            "run",
            side_effect=[
                subprocess.CompletedProcess([], 1),
                subprocess.CompletedProcess([], 1, "", "denied"),
            ],
        ):
            with self.assertRaisesRegex(ValueError, "no publication"):
                publisher.publish("owner/repo", "0" * 40)

    def test_release_assets_are_exact_accepted_catalog_and_local_index_only(self):
        publisher = module("publish_accepted_catalog")
        created = []

        def run(args, **kwargs):
            if args[:3] == ["gh", "release", "view"]:
                return subprocess.CompletedProcess(args, 1)
            if args[:2] == ["gh", "api"]:
                return subprocess.CompletedProcess(args, 0, "", "")
            self.assertEqual(args[:3], ["gh", "release", "create"])
            catalog, index = Path(args[4]), Path(args[5])
            self.assertEqual(json.loads(catalog.read_text()), self.catalog)
            self.assertEqual(
                json.loads(index.read_text())["catalogs"][0]["sha256"], digest(self.catalog)
            )
            created.append(args)
            return subprocess.CompletedProcess(
                args, 0, "https://github.com/owner/repo/releases/tag/catalog-test", ""
            )

        with patch.object(publisher.subprocess, "run", side_effect=run):
            result = publisher.publish("owner/repo", "0" * 40)
        self.assertTrue(result["published"])
        self.assertEqual(len(created), 1)

    def test_extended_sources_license_guard_before_content_and_malformed_releases(self):
        extension = module("prepare_catalog_update")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "references/crosswalk").mkdir(parents=True)
            source = {
                "id": "alz-storage-assignment",
                "revision": "1" * 40,
                "url": "https://raw.githubusercontent.com/Azure/Azure-Landing-Zones-Library/"
                + "1" * 40
                + "/platform/alz/policy_assignments/test.json",
                "release": "platform/alz/2026.10.0",
                "license_sha256": sha256(b"MIT License"),
                "sha256": sha256(b"{}"),
            }
            (root / "references/crosswalk/sources.json").write_text(
                json.dumps({"sources": [source]})
            )
            requested = []

            def fetch(url):
                requested.append(url)
                if "/releases?" in url:
                    return json.dumps(
                        [{"tag_name": "platform/alz/2026.10.0", "draft": False}]
                    ).encode()
                if "/git/ref/" in url:
                    return json.dumps({"object": {"type": "commit", "sha": "2" * 40}}).encode()
                if url.endswith("/LICENSE"):
                    return b"Changed licence"
                self.fail("Content fetched after licence drift: " + url)

            with patch.object(extension, "ROOT", root):
                with self.assertRaisesRegex(InputError, "licence changed"):
                    extension.extended_sources(root, fetch)
            self.assertTrue(requested[-1].endswith("/LICENSE"))
