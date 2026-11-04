import contextlib
import io
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from alz_assessor.cli import main

FIXTURE = Path(__file__).parent / "fixtures"


class CliTests(unittest.TestCase):
    def run_cli(self, arguments):
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch("sys.argv", ["alz-assessor", *arguments]),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            code = main()
        return code, stdout.getvalue(), stderr.getvalue()

    def test_unknown_module_is_successful_bounded_analysis_not_assessment(self):
        code, stdout, stderr = self.run_cli(["spike-terraform", str(FIXTURE / "alz")])
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertTrue(json.loads(stdout)["spike"])
        self.assertTrue(json.loads(stdout)["diagnostics"])

    def test_ordered_cli_variable_values(self):
        root = FIXTURE / "alz"
        code, stdout, _ = self.run_cli(
            [
                "spike-terraform",
                str(root),
                "--snapshots",
                str(root / "snapshots.json"),
                "--var",
                'location="first"',
                "--var",
                'location="last"',
            ]
        )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout)["resources"][0]["properties"]["location"], "last")

    def test_missing_compiler_is_nonzero_and_never_json_output(self):
        with patch("shutil.which", return_value=None):
            code, stdout, stderr = self.run_cli(
                [
                    "spike-bicep",
                    str(FIXTURE / "bicep" / "local.bicep"),
                ]
            )
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("no installation or restore was attempted", stderr)

    def test_bad_variable_argument_is_usage_failure(self):
        with self.assertRaises(SystemExit) as result:
            self.run_cli(["spike-terraform", str(FIXTURE / "alz"), "--var", "invalid"])
        self.assertEqual(result.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
