import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from alz_assessor.bicep import compile_bicep
from alz_assessor.terraform import InputError

FIXTURE = Path(__file__).parent / "fixtures" / "bicep"


class BicepTests(unittest.TestCase):
    def test_missing_tool_is_actionable_without_invocation(self):
        with patch("shutil.which", return_value=None), patch("subprocess.run") as run:
            with self.assertRaisesRegex(InputError, "not found.*already installed"):
                compile_bicep(FIXTURE / "local.bicep")
            run.assert_not_called()

    def test_failed_build_never_returns_evidence_and_disables_restore(self):
        responses = [
            subprocess.CompletedProcess([], 0, "Bicep 0.test", ""),
            subprocess.CompletedProcess([], 1, '{"resources":[{"fabricated":true}]}', "BCP190"),
        ]
        with (
            patch("shutil.which", return_value="bicep"),
            patch(
                "subprocess.run",
                side_effect=responses,
            ) as run,
        ):
            with self.assertRaisesRegex(InputError, "restoration disabled.*"):
                compile_bicep(FIXTURE / "unrestored.bicep")
            self.assertEqual(
                run.call_args_list[1].args[0],
                [
                    "bicep",
                    "build",
                    str((FIXTURE / "unrestored.bicep").resolve()),
                    "--no-restore",
                    "--stdout",
                ],
            )
            self.assertNotIn("shell", run.call_args.kwargs)

    def test_invalid_success_output_is_rejected(self):
        for output in ("not json", "[]", "{}"):
            responses = [
                subprocess.CompletedProcess([], 0, "Bicep 0.test", ""),
                subprocess.CompletedProcess([], 0, output, ""),
            ]
            with (
                self.subTest(output=output),
                patch("shutil.which", return_value="bicep"),
                patch(
                    "subprocess.run",
                    side_effect=responses,
                ),
                self.assertRaises(InputError),
            ):
                compile_bicep(FIXTURE / "local.bicep")

    def test_timeout_is_actionable(self):
        with (
            patch("shutil.which", return_value="bicep"),
            patch(
                "subprocess.run",
                side_effect=subprocess.TimeoutExpired("bicep", 30),
            ),
            self.assertRaisesRegex(InputError, "invocation failed"),
        ):
            compile_bicep(FIXTURE / "local.bicep")

    def test_actual_installed_compiler_local_success_and_unrestored_failure(self):
        compiler = os.environ.get("BICEP_COMPILER") or shutil.which("bicep")
        if not compiler:
            self.skipTest("Set BICEP_COMPILER to an existing standalone compiler for integration")
        result = compile_bicep(FIXTURE / "local.bicep", compiler)
        self.assertIn("Bicep CLI version", result["compiler_version"])
        self.assertEqual(
            result["template"]["resources"][0]["properties"]["retentionInDays"],
            30,
        )
        self.assertEqual(result["template"]["resources"][0]["location"], "[parameters('location')]")
        self.assertEqual(len(result["source_sha256"]), 64)
        with self.assertRaisesRegex(InputError, "BCP190"):
            compile_bicep(FIXTURE / "unrestored.bicep", compiler)
        self.assertNotIn("fabricated", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
