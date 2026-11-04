import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_contracts import SCOPE, evidence, resource

from alz_assessor.cli import main
from alz_assessor.preflight import preflight

FIXTURES = Path(__file__).parent / "fixtures"


class PreflightTests(unittest.TestCase):
    def test_installed_module_cli_ready_partial_and_blocked_outside_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "evidence.json"
            source.write_text(
                json.dumps(
                    evidence(
                        resources=[
                            resource(SCOPE + "/providers/Microsoft.Storage/storageAccounts/test"),
                        ]
                    )
                ),
                encoding="utf-8",
            )
            for path, mode, extra, expected, code in (
                (source, "evidence", [], "ready", 0),
                (
                    FIXTURES / "slice",
                    "terraform",
                    ["--authorize-root", str(FIXTURES / "alz")],
                    "partial",
                    0,
                ),
                (root / "missing", "arm", [], "blocked", 2),
                (
                    FIXTURES / "slice" / "controls.bicep",
                    "bicep",
                    ["--compiler", str(root / "absent.exe")],
                    "blocked",
                    2,
                ),
            ):
                with self.subTest(mode=mode, expected=expected):
                    result = subprocess.run(
                        [
                            sys.executable,
                            "-m",
                            "alz_assessor.cli",
                            "doctor",
                            str(path.resolve()),
                            "--input",
                            mode,
                            *extra,
                        ],
                        cwd=root,
                        capture_output=True,
                        text=True,
                        timeout=30,
                        check=False,
                    )
                    self.assertEqual(result.returncode, code, result.stderr)
                    model = json.loads(result.stdout)
                    self.assertEqual(model["readiness"], expected)
                    self.assertIn("not complete interpretation", model["warning"])

    def test_no_compile_network_or_implicit_compiler_execution(self):
        def loader():
            return self.fail("Bicep must not compile")

        for probe in (False, True):
            with (
                patch("shutil.which", return_value="existing-bicep"),
                patch("subprocess.run") as run,
                patch("urllib.request.urlopen", side_effect=AssertionError("network")),
            ):
                run.return_value.returncode = 0
                result = preflight(
                    FIXTURES / "slice" / "controls.bicep",
                    "bicep",
                    loader,
                    scope=SCOPE,
                    provider_version=None,
                    compiler="existing-bicep",
                    probe_compiler=probe,
                )
                self.assertEqual(result["readiness"], "partial")
                if probe:
                    self.assertEqual(run.call_args.args[0], ["existing-bicep", "--version"])
                    self.assertEqual(run.call_args.kwargs["timeout"], 30)
                else:
                    run.assert_not_called()

    def test_snapshot_hash_failure_is_structured_without_source_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "main.tf").write_text('resource "azurerm_resource_group" "test" {}')
            manifest = root / "snapshots.json"
            manifest.write_text(
                json.dumps(
                    {
                        "modules": [
                            {
                                "source": "example.invalid/test",
                                "version": "1",
                                "subdirectory": "",
                                "path": ".",
                                "sha256": "0" * 64,
                            }
                        ]
                    }
                )
            )
            output = io.StringIO()
            with (
                patch(
                    "sys.argv",
                    [
                        "alz-assessor",
                        "doctor",
                        str(root),
                        "--input",
                        "terraform",
                        "--snapshots",
                        str(manifest),
                    ],
                ),
                contextlib.redirect_stdout(output),
            ):
                self.assertEqual(main(), 2)
            model = json.loads(output.getvalue())
            self.assertEqual(model["readiness"], "blocked")
            self.assertIn("snapshot_hash_mismatch", output.getvalue())

    def test_text_readiness_and_unknown_reason_cli(self):
        for args, expected in (
            (
                [
                    "doctor",
                    str(FIXTURES / "slice"),
                    "--input",
                    "terraform",
                    "--authorize-root",
                    str(FIXTURES / "alz"),
                    "--format",
                    "text",
                ],
                "partial",
            ),
            (["explain", "future_reason", "--format", "json"], "Unsupported explanation"),
        ):
            output = io.StringIO()
            with patch("sys.argv", ["alz-assessor", *args]), contextlib.redirect_stdout(output):
                self.assertEqual(main(), 0)
            self.assertIn(expected, output.getvalue())
