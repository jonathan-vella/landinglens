import contextlib
import html
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from alz_assessor.arm import arm_source
from alz_assessor.catalog import load_catalog, reviewed_refresh
from alz_assessor.cli import main
from alz_assessor.comparison import compare
from alz_assessor.contracts import control_digest, digest, document, now, read_document, validate
from alz_assessor.engine import assess
from alz_assessor.plan import plan_source
from alz_assessor.reports import render
from alz_assessor.sources import file_hash, terraform_source
from alz_assessor.terraform import Analyzer, InputError, Limits

FIXTURES = Path(__file__).parent / "fixtures"
SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-management"


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.catalog = load_catalog()
        self.bundle = read_document(FIXTURES / "slice" / "observed.json")
        self.bundle["collected_at"] = now()

    def write(self, name, data):
        path = self.root / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def run_cli(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch("sys.argv", ["alz-assessor", *map(str, args)]),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            code = main()
        return code, stdout.getvalue(), stderr.getvalue()

    def test_inventory_guid_provenance_dispositions_and_no_matrix_downgrade(self):
        inventory = json.loads(
            (FIXTURES.parents[1] / "references" / "2026-11-04" / "inventory.json").read_text()
        )
        self.assertEqual(
            {row["upstream_guid"] for row in inventory["items"]},
            {row["upstream_guid"] for row in self.catalog["controls"]},
        )
        self.assertEqual(len({row["design_area"] for row in self.catalog["controls"]}), 8)
        self.assertEqual(
            {
                row["upstream_id"]
                for row in self.catalog["controls"]
                if row["automation"] == "automated"
            },
            {"G04.01", "D07.18", "D07.06", "D07.07", "G02.03", "G04.02", "D07.05", "D09.07"},
        )
        for control in self.catalog["controls"]:
            self.assertTrue(control["references"][0]["item_sha256"])
            self.assertTrue(control["evidence_requirements"])
            self.assertTrue(control["rationale"])
        candidate = json.loads(json.dumps(self.catalog))
        candidate["catalog_version"] = "next-reviewed-version"
        self.assertEqual(reviewed_refresh(candidate, self.catalog)["changed"], [])
        candidate["controls"].pop()
        with self.assertRaisesRegex(InputError, "remove"):
            reviewed_refresh(candidate, self.catalog)
        candidate = json.loads(json.dumps(self.catalog))
        candidate["catalog_version"] = "next"
        downgraded = next(row for row in candidate["controls"] if row["automation"] == "automated")
        downgraded["automation"] = "manual"
        downgraded["rule"] = None
        with self.assertRaisesRegex(InputError, "downgraded"):
            reviewed_refresh(candidate, self.catalog)

    def test_manual_validity_and_six_outcomes_and_exception_expiry(self):
        manual_control = next(
            row for row in self.catalog["controls"] if row["automation"] == "manual"
        )
        entry = {
            "control_id": manual_control["control_id"],
            "scope": SCOPE,
            "valid_from": "2020-01-01T00:00:00Z",
            "valid_until": "2099-01-01T00:00:00Z",
            "rationale": "reviewed evidence",
            "evidence": "review://record",
            "outcome": "pass",
            "reviewer": "test-reviewer",
            "control_sha256": control_digest(manual_control),
        }
        active = document("manual", schema_version="1.1", entries=[entry])
        report = assess(self.bundle, self.catalog, manual=active)
        result = next(row for row in report["results"] if row["control_id"] == entry["control_id"])
        self.assertEqual(result["observed"]["outcome"], "pass")
        entry["valid_until"] = "2021-01-01T00:00:00Z"
        result = next(
            row
            for row in assess(self.bundle, self.catalog, manual=active)["results"]
            if row["control_id"] == entry["control_id"]
        )
        self.assertEqual(result["observed"]["outcome"], "manual")
        self.assertEqual(
            result["observed"]["disposition_validity"]["manual"], "expired_or_not_yet_valid"
        )
        for state, outcome in (
            ("known", "pass"),
            ("unknown", "unknown"),
            ("inaccessible", "unknown"),
            ("error", "error"),
        ):
            self.bundle["resources"][0].update(
                state=state, reason="" if state == "known" else state
            )
            result = next(
                row
                for row in assess(self.bundle, self.catalog)["results"]
                if row["upstream_id"] == "G04.01"
            )
            self.assertEqual(result["observed"]["outcome"], outcome)

    def test_cross_format_counts_coverage_zero_denominators_and_redaction(self):
        self.bundle["inventory_complete"] = False
        self.bundle["resources"][0]["properties"] = {}
        self.bundle["diagnostics"] = [{"reason": "denied", "source_location": SCOPE}]
        self.bundle["metadata"] = {"unrecognized_raw_payload": "must-not-export"}
        report = assess(self.bundle, self.catalog)
        expected = report["coverage"]
        self.assertIsNone(expected["modes"]["observed"]["subset_pass_rate"])
        for format in ("json", "markdown", "html"):
            output = render(report, format)
            for value in ("manual", "unknown", "inventory_complete", "255", "denied"):
                self.assertIn(value, output)
            self.assertNotIn("100%", output)
            self.assertNotIn("must-not-export", output)
            minimized = render(report, format, minimize=True)
            self.assertNotIn(SCOPE, minimized)
            self.assertNotIn("authored://storage-fixture", minimized)
            if format == "html":
                for forbidden in ("<script>", "<img", "<iframe", "src=", "@import"):
                    self.assertNotIn(forbidden, output)
                self.assertEqual(output.count('<script type="text/javascript">'), 2)
        projected = json.loads(render(report))
        self.assertEqual(projected["coverage"], expected)
        for format in ("markdown", "html"):
            self.assertIn(
                json.dumps(expected, sort_keys=True), html.unescape(render(report, format))
            )

    def test_comparison_rechecks_staleness_and_minimized_data_cannot_compare(self):
        observed = assess(self.bundle, self.catalog)
        self.bundle["mode"] = "planned"
        planned = assess(self.bundle, self.catalog)
        result = compare(planned, observed, at="2099-01-01T00:00:00Z")
        target = next(row for row in result["results"] if row["upstream_id"] == "G04.01")
        self.assertEqual(target["comparison"], "not_comparable")
        self.assertEqual(target["observed"]["outcome"], "unknown")
        with self.assertRaisesRegex(InputError, "Minimized"):
            compare(json.loads(render(planned, minimize=True)), observed)
        self.assertEqual(
            assess(self.bundle, self.catalog, at="2099-01-01T00:00:00Z"),
            assess(self.bundle, self.catalog, at="2099-01-01T00:00:00Z"),
        )

    def test_plan_provenance_requires_matching_explicit_reviewed_binding(self):
        plan = {"format_version": "1.2", "planned_values": {"root_module": {"resources": []}}}
        path = self.write("plan.json", plan)
        self.bundle["mode"] = "planned"
        self.bundle["source"] = "terraform"
        with self.assertRaisesRegex(InputError, "hash binding"):
            plan_source(path, provider_version="4.50.0", source_binding=self.bundle)
        binding = {
            "review_state": "reviewed",
            "plan_sha256": file_hash(path),
            "source_artifact_hashes": self.bundle["artifact_hashes"],
        }
        result = plan_source(
            path, provider_version="4.50.0", source_binding=self.bundle, binding=binding
        )
        self.assertEqual(result["metadata"]["source_binding"], "reviewed-explicit-hash-binding")
        binding["plan_sha256"] = digest("unrelated-plan")
        with self.assertRaisesRegex(InputError, "hash binding"):
            plan_source(
                path, provider_version="4.50.0", source_binding=self.bundle, binding=binding
            )

    def test_nested_arm_scope_and_outer_expression_safety(self):
        child = {
            "resources": [
                {
                    "type": "Microsoft.Storage/storageAccounts",
                    "apiVersion": "2023-05-01",
                    "name": "nested",
                    "properties": {"supportsHttpsTrafficOnly": True},
                }
            ]
        }
        deployment = {
            "type": "Microsoft.Resources/deployments",
            "apiVersion": "2022-09-01",
            "name": "child",
            "resourceGroup": "child-group",
            "properties": {
                "expressionEvaluationOptions": {"scope": "inner"},
                "template": child,
            },
        }
        path = self.write("nested.json", {"resources": [deployment]})
        bundle = arm_source(path, scope=SCOPE)
        identity = bundle["resources"][0]["arm_id"]
        self.assertIn("/resourcegroups/child-group/", identity)
        deployment["properties"].pop("expressionEvaluationOptions")
        bundle = arm_source(self.write("nested.json", {"resources": [deployment]}), scope=SCOPE)
        self.assertEqual(bundle["resources"], [])
        self.assertFalse(bundle["inventory_complete"])
        self.assertIn("expression_scope", bundle["diagnostics"][0]["reason"])

    def test_provider_selectors_do_not_invent_identity(self):
        for declaration, selector, bound in (
            ('provider "azurerm" { subscription_id = "another-subscription" }', "", False),
            ("", "provider = azurerm.other", False),
            ("", "", True),
        ):
            (self.root / "main.tf").write_text(
                declaration + "\n"
                'resource "azurerm_storage_account" "test" {\n'
                'name = "logs"\nhttps_traffic_only_enabled = true\n' + selector + "\n}",
                encoding="utf-8",
            )
            bundle = terraform_source(self.root, scope=SCOPE, provider_version="4.50.0")
            self.assertEqual(bundle["resources"][0]["arm_id"] is not None, bound)
            self.assertIs(bundle["resources"][0]["properties"]["supportsHttpsTrafficOnly"], True)
        child = self.root / "child"
        child.mkdir()
        (child / "main.tf").write_text(
            'resource "azurerm_storage_account" "test" {\n'
            'name = "logs"\nhttps_traffic_only_enabled = true\n}',
            encoding="utf-8",
        )
        (self.root / "main.tf").write_text(
            'module "child" {\nsource = "./child"\nproviders = { azurerm = azurerm.other }\n}',
            encoding="utf-8",
        )
        bundle = terraform_source(self.root, scope=SCOPE, provider_version="4.50.0")
        self.assertIsNone(bundle["resources"][0]["arm_id"])

    def test_arm_to_observed_comparison_and_cli_plan_binding(self):
        template = self.write(
            "storage.json",
            {
                "resources": [
                    {
                        "type": "Microsoft.Storage/storageAccounts",
                        "apiVersion": "2023-05-01",
                        "name": "landinglenslogs",
                        "properties": {"supportsHttpsTrafficOnly": True},
                    }
                ]
            },
        )
        paired = compare(
            assess(arm_source(template, scope=SCOPE), self.catalog),
            assess(self.bundle, self.catalog),
        )
        row = next(item for item in paired["results"] if item["upstream_id"] == "G04.01")
        self.assertEqual(row["comparison"], "match")
        source = terraform_source(
            FIXTURES / "slice",
            snapshots=FIXTURES / "slice" / "snapshots.json",
            authorized_roots=[FIXTURES / "alz"],
            provider_version="4.50.0",
            scope=SCOPE,
        )
        source_path = self.write("source.json", source)
        plan = self.write(
            "plan.json",
            {"format_version": "1.2", "planned_values": {"root_module": {"resources": []}}},
        )
        binding = {
            "review_state": "reviewed",
            "plan_sha256": file_hash(plan),
            "source_artifact_hashes": source["artifact_hashes"],
        }
        binding_path = self.write("binding.json", binding)
        args = [
            "assess",
            plan,
            "--input",
            "terraform-plan",
            "--provider-version",
            "4.50.0",
            "--source-evidence",
            source_path,
            "--plan-binding",
            binding_path,
        ]
        code, stdout, stderr = self.run_cli(args)
        self.assertEqual((code, stderr), (0, ""))
        self.assertEqual(json.loads(stdout)["evidence"][0]["source"], "terraform-plan")
        binding["plan_sha256"] = digest("wrong")
        self.write("binding.json", binding)
        code, stdout, stderr = self.run_cli(args)
        self.assertEqual((code, stdout), (2, ""))
        self.assertIn("hash binding", stderr)

    def test_pure_expressions_dynamic_scope_and_expansion_limits(self):
        source = self.root / "main.tf"
        source.write_text(
            """
locals { values = [true, false] }
resource "test" "x" {
  sum = 1 + 2 * 3
  grouping = (1 + 2) * 3
  left = 10 - 3 - 2
  condition = !false && (1 < 2)
  length = length(local.values)
  denied = file("never-read")
  signed_remainder = -5 % 3
  mixed_numeric_equality = 1 == 1.0
  typed_membership = contains([1], true)
  nested_equality = [1] == [true]
  dynamic "rule" {
    for_each = local.values
    iterator = current
    content { enabled = current.value }
  }
}
""",
            encoding="utf-8",
        )
        result = Analyzer(self.root).analyze()["resources"][0]["properties"]
        self.assertEqual((result["sum"], result["grouping"], result["left"]), (7, 9, 5))
        self.assertIs(result["condition"], True)
        self.assertEqual(result["length"], 2)
        self.assertEqual(result["rule"], [{"enabled": True}, {"enabled": False}])
        self.assertIn("unknown", result["denied"])
        self.assertIn("unknown", result["signed_remainder"])
        self.assertIn("unknown", result["mixed_numeric_equality"])
        self.assertIs(result["typed_membership"], False)
        self.assertIs(result["nested_equality"], False)
        limited = Analyzer(self.root, limits=Limits(instances=1)).analyze()
        self.assertTrue(limited["diagnostics"])

    def test_contract_malformed_inputs_are_explicit_errors(self):
        path = self.root / "bad.json"
        for text in ('{"duplicate":1,"duplicate":2}', '{"number":NaN}', "[" * 1000):
            path.write_text(text, encoding="utf-8")
            with self.assertRaises(InputError):
                read_document(path)
        for field in ("mode", "source"):
            candidate = {**self.bundle, field: {}}
            with self.assertRaises(InputError):
                validate(candidate)
        candidate = json.loads(json.dumps(self.bundle))
        candidate["resources"].append(candidate["resources"][0])
        with self.assertRaises(InputError):
            validate(candidate)

    def test_cli_rejects_missing_catalog_fields_without_tracebacks(self):
        evidence = self.write("evidence.json", self.bundle)
        for field in ("upstream_id", "flags", "design_area"):
            with self.subTest(field=field):
                catalog = json.loads(json.dumps(self.catalog))
                catalog["controls"][0].pop(field)
                path = self.write("catalog.json", catalog)
                code, stdout, stderr = self.run_cli(
                    ["assess", evidence, "--input", "evidence", "--catalog", path]
                )
                self.assertEqual((code, stdout), (2, ""))
                self.assertIn("Input error:", stderr)

    def test_cli_rejects_malformed_report_rows_and_diagnostics_without_tracebacks(self):
        report = assess(self.bundle, self.catalog)
        for case in ("missing_upstream_id", "nonobject_diagnostic", "nonlist_diagnostics"):
            with self.subTest(case=case):
                candidate = json.loads(json.dumps(report))
                if case == "missing_upstream_id":
                    candidate["results"][0].pop("upstream_id")
                elif case == "nonobject_diagnostic":
                    candidate["evidence"][0]["diagnostics"] = ["invalid"]
                else:
                    candidate["evidence"][0]["diagnostics"] = {"reason": "invalid"}
                path = self.write("report.json", candidate)
                code, stdout, stderr = self.run_cli(
                    ["render", path, "--minimize", "--format", "markdown"]
                )
                self.assertEqual((code, stdout), (2, ""))
                self.assertIn("Input error:", stderr)

    def test_cli_catalog_collect_guards_and_irrelevant_options(self):
        code, stdout, stderr = self.run_cli(["catalog", "validate"])
        self.assertEqual((code, json.loads(stdout)["controls"], stderr), (0, 255, ""))
        with patch.dict(os.environ, {}, clear=True):
            code, stdout, stderr = self.run_cli(
                ["collect", "--subscription", "00000000-0000-0000-0000-000000000001"]
            )
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("no login", stderr)
        code, _, stderr = self.run_cli(
            [
                "assess",
                FIXTURES / "slice" / "observed.json",
                "--input",
                "evidence",
                "--snapshots",
                "not-used",
            ]
        )
        self.assertEqual(code, 2)
        self.assertIn("not valid", stderr)

    def test_installed_module_cli_all_modes_and_comparison_outside_checkout(self):
        executable = [sys.executable, "-m", "alz_assessor.cli"]

        def run(*arguments):
            result = subprocess.run(
                [*executable, *map(str, arguments)],
                cwd=self.root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=60,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout

        observed_path = self.write("observed.json", self.bundle)
        saved = self.root / "observed-report.json"
        saved.write_text(run("assess", observed_path, "--input", "evidence"), encoding="utf-8")
        planned = self.root / "planned-report.json"
        for format in ("json", "markdown", "html"):
            text = run(
                "assess",
                FIXTURES / "slice",
                "--input",
                "terraform",
                "--provider-version",
                "4.50.0",
                "--scope",
                SCOPE,
                "--authorize-root",
                FIXTURES / "alz",
                "--snapshots",
                FIXTURES / "slice" / "snapshots.json",
                "--format",
                format,
            )
            self.assertIn("G04.01", text)
            if format == "json":
                planned.write_text(text, encoding="utf-8")
            observed = run("assess", observed_path, "--input", "evidence", "--format", format)
            self.assertIn("explicit_property_matches", observed)
            paired = run("compare", planned, saved, "--format", format)
            self.assertIn("canonical_identity_and_explicit_fact", paired)
            rerendered = run("render", saved, "--format", format)
            self.assertIn("G04.01", rerendered)
            if os.environ.get("BICEP_COMPILER"):
                bicep = run(
                    "assess",
                    FIXTURES / "slice" / "controls.bicep",
                    "--input",
                    "bicep",
                    "--compiler",
                    os.environ["BICEP_COMPILER"],
                    "--scope",
                    SCOPE,
                    "--format",
                    format,
                )
                self.assertIn("D07.18", bicep)


if __name__ == "__main__":
    unittest.main()
