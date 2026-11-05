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


def completed_checks_run():
    return {
        "headSha": "0" * 40,
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "success",
        "jobs": [
            {"name": f"checks ({os}, {version})", "status": "completed", "conclusion": "success"}
            for os in ("ubuntu-latest", "windows-latest")
            for version in ("3.12", "3.13")
        ],
    }


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

    def test_pr_creation_denial_keeps_artifacts_and_never_mutates_settings(self):
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
                return subprocess.CompletedProcess(
                    args, 1 if args[:3] == ("gh", "pr", "create") else 0, "", ""
                )

            with patch.object(publisher, "command", side_effect=run):
                result = publisher.publish(directory, "owner/repo", "123", workspace=root)
            self.assertFalse(result["published"])
            self.assertIn("denied/failed", result["blocker"])
            self.assertTrue((root / "references/catalog-candidates/123").is_dir())
            self.assertFalse(any(command[:3] == ("gh", "workflow", "run") for command in commands))
            self.assertFalse(
                any(
                    "actions/permissions/workflow" in part
                    for command in commands
                    for part in command
                )
            )
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
                elif args[:2] == ("git", "rev-parse"):
                    output = "0" * 40
                return subprocess.CompletedProcess(args, 0, output, "")

            with patch.object(publisher, "command", side_effect=run):
                result = publisher.publish(
                    directory, "owner/repo", "123", workspace=root, sleep=lambda _: None
                )
            self.assertTrue(result["published"])
            self.assertTrue(result["checks_dispatched"])
            self.assertIn(
                (
                    "gh",
                    "workflow",
                    "run",
                    "checks.yml",
                    "--repo",
                    "owner/repo",
                    "--ref",
                    "catalog-update-123",
                ),
                commands,
            )
            self.assertFalse(result["auto_merge_requested"])
            self.assertIn("not all green", result["blocker"])
            self.assertFalse(any(command[:3] == ("gh", "pr", "merge") for command in commands))

    def test_only_safe_with_all_real_checks_can_request_auto_merge(self):
        publisher = module("publish_catalog_update")
        for scenario in (
            "safe",
            "needs-review",
            "wrong-run-sha",
            "pending-run",
            "live-check-failure",
            "missing-platform-job",
            "failed-platform-job",
            "wrong-detail-sha",
        ):
            classification = "needs-review" if scenario == "needs-review" else "safe"
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

                def run(*args, operations=operations, scenario=scenario):
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
                    elif args[:2] == ("git", "rev-parse"):
                        output = "0" * 40
                    elif args[:3] == ("gh", "pr", "view"):
                        output = json.dumps(
                            {
                                "headRefOid": "0" * 40,
                                "statusCheckRollup": [
                                    {
                                        "name": "CodeQL",
                                        "status": "COMPLETED",
                                        "conclusion": (
                                            "FAILURE"
                                            if scenario == "live-check-failure"
                                            else "SUCCESS"
                                        ),
                                    }
                                ],
                            }
                        )
                    elif args[:3] == ("gh", "run", "list"):
                        output = json.dumps(
                            [
                                {
                                    "databaseId": 1234,
                                    "headSha": ("1" if scenario == "wrong-run-sha" else "0") * 40,
                                    "status": (
                                        "in_progress" if scenario == "pending-run" else "completed"
                                    ),
                                    "conclusion": "success",
                                }
                            ]
                        )
                    elif args[:3] == ("gh", "run", "view"):
                        detail = completed_checks_run()
                        if scenario == "missing-platform-job":
                            detail["jobs"].pop()
                        elif scenario == "failed-platform-job":
                            detail["jobs"][0]["conclusion"] = "failure"
                        elif scenario == "wrong-detail-sha":
                            detail["headSha"] = "1" * 40
                        output = json.dumps(detail)
                    return subprocess.CompletedProcess(args, 0, output, "")

                with patch.object(publisher, "command", side_effect=run):
                    result = publisher.publish(
                        directory, "owner/repo", "123", workspace=root, sleep=lambda _: None
                    )
                self.assertEqual(result["auto_merge_requested"], scenario == "safe", scenario)
                self.assertTrue(result["checks_dispatched"])
                if scenario == "safe":
                    self.assertEqual(result["checks_run_id"], 1234)
                self.assertEqual(
                    any(op[:3] == ("gh", "pr", "merge") for op in operations),
                    scenario == "safe",
                )

    def test_denied_check_dispatch_never_requests_merge(self):
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
            operations = []

            def run(*args):
                operations.append(args)
                output = ""
                if args[:3] == ("gh", "pr", "create"):
                    output = "https://github.com/owner/repo/pull/1"
                elif args[:2] == ("git", "rev-parse"):
                    output = "0" * 40
                return subprocess.CompletedProcess(
                    args, 1 if args[:3] == ("gh", "workflow", "run") else 0, output, ""
                )

            with patch.object(publisher, "command", side_effect=run):
                result = publisher.publish(directory, "owner/repo", "123", workspace=root)
            self.assertFalse(result["checks_dispatched"])
            self.assertFalse(result["auto_merge_requested"])
            self.assertIn("actions: write", result["blocker"])
            self.assertFalse(
                any(operation[:3] == ("gh", "pr", "merge") for operation in operations)
            )

    def test_authored_validation_keeps_actual_poll_separate_and_catalog_unmodified(self):
        extension = module("prepare_catalog_update")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "status.json").write_text(json.dumps({"poll_attempted_at": AT}))
            original = self.update()
            for name, value in (
                ("catalog-update.json", original),
                ("candidate-catalog.json", original["candidate"]),
            ):
                (root / name).write_text(json.dumps(value))
            (root / "PR-BODY.md").write_text("Actual unchanged source poll.")
            before = digest(load_catalog())
            result = extension.prepare_validation(
                root, ROOT / "references/2026-11-04", "Authored fixture: unit tests passed"
            )
            self.assertTrue(result["validation_only"])
            self.assertEqual(result["classification"], "safe")
            observed = json.loads((root / "observed-catalog-update.json").read_text())
            self.assertEqual(observed, original)
            self.assertIn("not an upstream source-change claim", (root / "PR-BODY.md").read_text())
            self.assertEqual(digest(load_catalog()), before)

    def test_check_dispatch_permission_is_scoped_to_source_workflow(self):
        source = (ROOT / ".github/workflows/source-monitor.yml").read_text()
        checks = (ROOT / ".github/workflows/checks.yml").read_text()
        self.assertIn("  actions: write", source)
        self.assertNotIn("actions: write", checks)
        self.assertIn("  contents: read", checks)
        self.assertIn("validate_publication:", source)
        self.assertIn("Validation does not publish accepted catalog assets.", source)

    def test_head_changed_after_dispatch_cannot_merge_checked_different_commit(self):
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
            operations = []

            def run(*args):
                operations.append(args)
                output = ""
                if args[:2] == ("gh", "api"):
                    output = '{"allow_auto_merge":true}'
                elif args[:3] == ("gh", "pr", "create"):
                    output = "https://github.com/owner/repo/pull/1"
                elif args[:2] == ("git", "rev-parse"):
                    output = "0" * 40
                elif args[:3] == ("gh", "pr", "view"):
                    output = json.dumps({"headRefOid": "1" * 40, "statusCheckRollup": []})
                elif args[:3] == ("gh", "run", "view"):
                    output = json.dumps(completed_checks_run())
                elif args[:3] == ("gh", "run", "list"):
                    output = json.dumps(
                        [
                            {
                                "databaseId": 1234,
                                "headSha": "0" * 40,
                                "status": "completed",
                                "conclusion": "success",
                            }
                        ]
                    )
                elif args[:3] == ("gh", "pr", "checks"):
                    output = json.dumps(
                        [
                            {"name": f"checks ({os}, {version})", "state": "SUCCESS"}
                            for os in ("ubuntu-latest", "windows-latest")
                            for version in ("3.12", "3.13")
                        ]
                    )
                return subprocess.CompletedProcess(args, 0, output, "")

            with patch.object(publisher, "command", side_effect=run):
                result = publisher.publish(directory, "owner/repo", "123", workspace=root)
            self.assertTrue(result["checks_dispatched"])
            self.assertFalse(result["auto_merge_requested"])
            self.assertIn("head changed", result["blocker"])
            self.assertFalse(
                any(operation[:3] == ("gh", "pr", "merge") for operation in operations)
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
            notice = Path(args[6])
            self.assertEqual(notice.name, "reference.LICENSE")
            self.assertEqual(
                notice.read_bytes(), (ROOT / "src/alz_assessor/data/reference.LICENSE").read_bytes()
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
