import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from alz_assessor.contracts import digest


class BatchReceiptTests(unittest.TestCase):
    def setUp(self):
        repository = Path(__file__).parents[1]
        spec = importlib.util.spec_from_file_location(
            "record_batch_delivery", repository / "tools" / "record_batch_delivery.py"
        )
        self.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.tool)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.review = self.root / "references" / "recommendation-batches"
        self.review.mkdir(parents=True)
        self.targets = {"targets": [{"batch": "11", "guid": "fixture-guid"}]}
        self.ledger = {
            "fixed_targets_sha256": digest(self.targets),
            "deliveries": {},
            "recommendations": [
                {
                    "guid": "fixture-guid",
                    "batch": "11",
                    "status": "implementation-in-progress",
                    "pr": None,
                    "merge_commit": None,
                    "runtime_evidence": [],
                }
            ],
        }
        for name, value in (
            ("targets.json", self.targets),
            ("ledger.json", self.ledger),
            ("batch-11.json", {"recommendations": [{"guid": "fixture-guid"}]}),
        ):
            (self.review / name).write_text(json.dumps(value), encoding="utf-8")
        self.wheel = self.root / "own.whl"
        self.wheel.write_bytes(b"fixture-owned-wheel")
        self.api = {
            "merged": True,
            "state": "closed",
            "base": {"ref": "main"},
            "head": {"sha": "a" * 40},
            "merge_commit_sha": "b" * 40,
            "merged_at": "2026-11-06T08:11:21Z",
            "html_url": "https://github.com/jonathan-vella/landinglens/pull/93",
        }
        self.checks = {
            "headSha": "a" * 40,
            "status": "completed",
            "conclusion": "success",
            "workflowName": "Advisory CLI checks",
            "jobs": [
                {"name": name, "status": "completed", "conclusion": "success"}
                for name in sorted(self.tool.REQUIRED)
            ],
        }
        self.proof = {
            "exercised": True,
            "status": "exercised",
            "skipped": [],
            "integration_cases": ["test_existing_compiler"],
        }

    def command(self, args):
        if args[:2] == ["gh", "api"]:
            return self.api
        if args[:3] == ["gh", "run", "view"]:
            return {
                **self.checks,
                "event": "push" if args[3] == "1" else "pull_request",
                "url": "https://github.com/jonathan-vella/landinglens/actions/runs/" + args[3],
            }
        if args[:3] == ["gh", "run", "download"]:
            root = Path(args[-1])
            for os in ("ubuntu-latest", "windows-latest"):
                for version in ("3.12", "3.13"):
                    destination = root / f"compiler-coverage-{os}-{version}"
                    destination.mkdir()
                    (destination / "compiler-coverage.json").write_text(
                        json.dumps(self.proof), encoding="utf-8"
                    )
            return None
        raise AssertionError(args)

    def record(self):
        return self.tool.record(
            "11", 93, [1, 2], self.wheel, 320, 1, root=self.root, run=self.command
        )

    def unchanged_failure(self):
        path = self.review / "ledger.json"
        before = path.read_bytes()
        with self.assertRaises((ValueError, FileNotFoundError)):
            self.record()
        self.assertEqual(path.read_bytes(), before)

    def test_actual_own_cohort_receipt_and_idempotent_repeat(self):
        result = self.record()
        saved = json.loads((self.review / "ledger.json").read_text())
        self.assertEqual(saved["recommendations"][0]["merge_commit"], "b" * 40)
        self.assertEqual(saved["recommendations"][0]["status"], "merged")
        self.assertEqual(saved["deliveries"]["11"], result)
        before = (self.review / "ledger.json").read_bytes()
        self.assertEqual(self.record(), result)
        self.assertEqual((self.review / "ledger.json").read_bytes(), before)

    def test_unmerged_wrong_base_or_unchecked_head_cannot_record(self):
        original = copy.deepcopy(self.api)
        for changes in (
            {"merged": False},
            {"base": {"ref": "elsewhere"}},
            {"head": {"sha": "c" * 40}},
        ):
            self.api = {**original, **changes}
            self.unchanged_failure()

    def test_missing_failed_pending_or_other_workflow_job_cannot_record(self):
        original = copy.deepcopy(self.checks)
        for changes in (
            {"jobs": original["jobs"][:-1]},
            {"status": "in_progress"},
            {"conclusion": "failure"},
            {"workflowName": "Other workflow"},
        ):
            self.checks = {**original, **changes}
            self.unchanged_failure()

    def test_unexercised_skipped_or_missing_compiler_artifact_cannot_record(self):
        for changes in (
            {"exercised": False},
            {"skipped": ["unavailable"]},
            {"integration_cases": []},
        ):
            self.proof = {
                "exercised": True,
                "status": "exercised",
                "skipped": [],
                "integration_cases": ["test_existing_compiler"],
                **changes,
            }
            self.unchanged_failure()

    def test_fixed_target_membership_and_previous_receipt_are_guarded(self):
        path = self.review / "targets.json"
        changed = copy.deepcopy(self.targets)
        changed["targets"].append({"batch": "11", "guid": "unexpected"})
        path.write_text(json.dumps(changed))
        self.unchanged_failure()
        path.write_text(json.dumps(self.targets))
        self.record()
        self.api["merge_commit_sha"] = "c" * 40
        self.unchanged_failure()

    def test_concurrent_ledger_edit_is_preserved_and_temporary_file_removed(self):
        target = self.review / "ledger.json"
        external = target.read_bytes() + b"\n"
        original = self.command

        def concurrent(args):
            value = original(args)
            if args[:3] == ["gh", "run", "download"]:
                target.write_bytes(external)
            return value

        with self.assertRaisesRegex(ValueError, "changed during verification"):
            self.tool.record("11", 93, [1, 2], self.wheel, 320, 1, root=self.root, run=concurrent)
        self.assertEqual(target.read_bytes(), external)
        self.assertEqual(list(self.review.glob(".ledger-*.tmp")), [])
