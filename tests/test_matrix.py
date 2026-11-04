import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from alz_assessor.arm import Expressions, arm_source
from alz_assessor.catalog import load_catalog
from alz_assessor.cli import main
from alz_assessor.contracts import digest
from alz_assessor.engine import assess
from alz_assessor.plan import plan_source
from alz_assessor.sources import terraform_source
from alz_assessor.terraform import InputError

FIXTURES = Path(__file__).parent / "fixtures"
SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-management"
ACCEPTED = {"G04.01", "D07.18"}


class MatrixTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.catalog = load_catalog()

    def write(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def template(self, value):
        return {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "parameters": {"secure": {"type": "bool", "defaultValue": value}},
            "resources": [
                {
                    "type": "Microsoft.Storage/storageAccounts",
                    "apiVersion": "2023-05-01",
                    "name": "landinglenslogs",
                    "properties": {
                        "supportsHttpsTrafficOnly": "[parameters('secure')]",
                    },
                },
                {
                    "type": "Microsoft.Network/firewallPolicies",
                    "apiVersion": "2024-05-01",
                    "name": "landinglenspolicy",
                    "properties": {
                        "dnsSettings": {"enableProxy": "[parameters('secure')]"},
                    },
                },
            ],
        }

    def assert_matrix(self, bundle, expected):
        report = assess(bundle, self.catalog)
        rows = [row for row in report["results"] if row["automation"] == "automated"]
        self.assertEqual({row["upstream_id"] for row in rows}, ACCEPTED)
        self.assertTrue(all(row[bundle["mode"]]["outcome"] == expected for row in rows))
        self.assertEqual(report["coverage"]["controls"], 255)
        self.assertEqual(len({row["design_area"] for row in report["results"]}), 8)
        path = self.write("normalized-evidence.json", bundle)
        reason = "explicit_property_matches" if expected == "pass" else "explicit_property_differs"
        if expected in {"pass", "fail"}:
            for format in ("json", "markdown", "html"):
                stdout, stderr = io.StringIO(), io.StringIO()
                with (
                    patch(
                        "sys.argv",
                        [
                            "alz-assessor",
                            "assess",
                            str(path),
                            "--input",
                            "evidence",
                            "--format",
                            format,
                        ],
                    ),
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    code = main()
                self.assertEqual((code, stderr.getvalue()), (0, ""))
                self.assertEqual(stdout.getvalue().count(reason), 2)

    def test_committed_positive_negative_matrix_raw_arm_and_observed(self):
        for value, outcome in ((True, "pass"), (False, "fail")):
            with (
                self.subTest(value=value),
                patch(
                    "urllib.request.urlopen",
                    side_effect=AssertionError("network forbidden"),
                ),
                patch("subprocess.run", side_effect=AssertionError("IaC execution forbidden")),
            ):
                raw = terraform_source(
                    FIXTURES / "slice",
                    scope=SCOPE,
                    provider_version="4.50.0",
                    snapshots=FIXTURES / "slice" / "snapshots.json",
                    authorized_roots=[FIXTURES / "alz"],
                    variable_inputs=[("var", {"secure": value, "dns_proxy": value})],
                )
                self.assert_matrix(raw, outcome)
                arm = arm_source(self.write("template.json", self.template(value)), scope=SCOPE)
                self.assert_matrix(arm, outcome)
                arm["mode"], arm["source"] = "observed", "saved"
                self.assert_matrix(arm, outcome)

    def test_installed_cli_accepted_matrix_in_each_source_mode(self):
        def run(*arguments):
            result = subprocess.run(
                [sys.executable, "-m", "alz_assessor.cli", *map(str, arguments)],
                cwd=self.root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=60,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout

        for value, outcome in ((True, "pass"), (False, "fail")):
            template = self.write("template.json", self.template(value))
            observed = arm_source(template, scope=SCOPE)
            observed["mode"], observed["source"] = "observed", "saved"
            saved = self.write("observed.json", observed)
            observed_report = self.root / "observed-report.json"
            observed_report.write_text(
                run("assess", saved, "--input", "evidence"), encoding="utf-8"
            )
            cases = [
                (
                    "terraform",
                    FIXTURES / "slice",
                    [
                        "--scope",
                        SCOPE,
                        "--provider-version",
                        "4.50.0",
                        "--snapshots",
                        FIXTURES / "slice" / "snapshots.json",
                        "--authorize-root",
                        FIXTURES / "alz",
                        "--var",
                        "secure=" + json.dumps(value),
                        "--var",
                        "dns_proxy=" + json.dumps(value),
                    ],
                ),
                ("arm", template, ["--scope", SCOPE]),
                ("evidence", saved, []),
            ]
            if os.environ.get("BICEP_COMPILER"):
                parameters = self.write(
                    "parameters.json",
                    {"parameters": {"secure": {"value": value}, "dnsProxy": {"value": value}}},
                )
                cases.append(
                    (
                        "bicep",
                        FIXTURES / "slice" / "controls.bicep",
                        [
                            "--scope",
                            SCOPE,
                            "--compiler",
                            os.environ["BICEP_COMPILER"],
                            "--parameters",
                            parameters,
                        ],
                    )
                )
            for mode, source, arguments in cases:
                with self.subTest(mode=mode, outcome=outcome):
                    report = json.loads(run("assess", source, "--input", mode, *arguments))
                    evidence_mode = "observed" if mode == "evidence" else "planned"
                    rows = [row for row in report["results"] if row["automation"] == "automated"]
                    self.assertEqual({row["upstream_id"] for row in rows}, ACCEPTED)
                    self.assertTrue(all(row[evidence_mode]["outcome"] == outcome for row in rows))
                    self.assertEqual(report["coverage"]["controls"], 255)
                    self.assertEqual(len({row["design_area"] for row in report["results"]}), 8)
                    path = self.write("report.json", report)
                    reason = (
                        "explicit_property_matches"
                        if outcome == "pass"
                        else "explicit_property_differs"
                    )
                    for format in ("json", "markdown", "html"):
                        self.assertEqual(run("render", path, "--format", format).count(reason), 2)
                        if mode != "evidence":
                            paired = run("compare", path, observed_report, "--format", format)
                            self.assertEqual(
                                paired.count("canonical_identity_and_explicit_fact"), 2
                            )
                            if format == "json":
                                compared = [
                                    row
                                    for row in json.loads(paired)["results"]
                                    if row["automation"] == "automated"
                                ]
                                self.assertTrue(
                                    all(row["comparison"] == "match" for row in compared)
                                )

    @unittest.skipUnless(os.environ.get("BICEP_COMPILER"), "Existing Bicep compiler not configured")
    def test_committed_positive_negative_bicep_matrix_actual_no_restore_compiler(self):
        for value, outcome in ((True, "pass"), (False, "fail")):
            parameters = self.write(
                "parameters.json",
                {
                    "parameters": {"secure": {"value": value}, "dnsProxy": {"value": value}},
                },
            )
            bundle = arm_source(
                FIXTURES / "slice" / "controls.bicep",
                scope=SCOPE,
                parameters=parameters,
                bicep=True,
                compiler=os.environ["BICEP_COMPILER"],
            )
            self.assert_matrix(bundle, outcome)
            self.assertIn("compiled-template", bundle["artifact_hashes"])
            self.assertTrue(bundle["metadata"]["compiler_version"])

    def test_arm_parameters_secure_unresolved_version_and_provenance(self):
        template = self.template(False)
        path = self.write("template.json", template)
        parameters = self.write("parameters.json", {"parameters": {"secure": {"value": True}}})
        bundle = arm_source(path, scope=SCOPE, parameters=parameters)
        self.assert_matrix(bundle, "pass")
        before = dict(bundle["artifact_hashes"])
        self.write("parameters.json", {"parameters": {"secure": {"value": False}}})
        self.assertNotEqual(
            before, arm_source(path, scope=SCOPE, parameters=parameters)["artifact_hashes"]
        )
        template["parameters"]["secure"]["type"] = "secureString"
        path = self.write("template.json", template)
        self.write(
            "parameters.json", {"parameters": {"secure": {"value": "never-export-this-secret"}}}
        )
        report = assess(arm_source(path, scope=SCOPE, parameters=parameters), self.catalog)
        self.assertNotIn("never-export-this-secret", json.dumps(report))
        self.assertTrue(
            all(
                row["planned"]["outcome"] == "unknown"
                for row in report["results"]
                if row["automation"] == "automated"
            )
        )
        template = self.template(True)
        for resource in template["resources"]:
            resource["apiVersion"] = "unreviewed-version"
        self.assert_matrix(
            arm_source(self.write("template.json", template), scope=SCOPE), "unknown"
        )

    def test_arm_copy_cycle_limits_unknown_condition_and_parameter_literals(self):
        context = Expressions(
            {"parameters": {"text": {"type": "string"}}},
            {
                "text": "[reference('must-not-execute')]",
            },
            SCOPE,
        )
        self.assertEqual(context.value("[parameters('text')]"), "[reference('must-not-execute')]")
        context = Expressions({"variables": {"x": "[variables('x')]"}}, {}, SCOPE)
        self.assertIn("unknown", context.value("[variables('x')]"))
        self.assertEqual(context.value("[concat('a','b')]"), "ab")
        self.assertIn("unknown", context.value("[reference('runtime')]"))
        template = self.template(True)
        storage = template["resources"][0]
        storage["copy"] = {"name": "accounts", "count": 2}
        storage["name"] = "[concat('account', 'a')]"
        with self.assertRaisesRegex(InputError, "Duplicate"):
            arm_source(self.write("copy.json", template), scope=SCOPE)
        storage["copy"]["count"] = 10000
        result = arm_source(self.write("copy.json", template), scope=SCOPE)
        self.assertFalse(result["inventory_complete"])
        self.assertEqual(result["resources"][0]["state"], "unknown")
        storage.pop("copy")
        storage["condition"] = "[reference('unknown')]"
        result = arm_source(self.write("copy.json", template), scope=SCOPE)
        self.assertFalse(result["inventory_complete"])
        unbound = arm_source(self.write("plain.json", self.template(True)))
        self.assertTrue(all(row["arm_id"] is None for row in unbound["resources"]))

    def test_arm_nested_equality_preserves_types_and_unknown_numeric_semantics(self):
        declarations = {"parameters": {"left": {"type": "object"}, "right": {"type": "object"}}}
        for left, right, expected in (
            ({"value": [1]}, {"value": [True]}, False),
            ({"value": [False]}, {"value": [0]}, False),
            ({"value": [True]}, {"value": [True]}, True),
            ({"value": [1]}, {"value": [1]}, True),
        ):
            with self.subTest(left=left, right=right):
                context = Expressions(declarations, {"left": left, "right": right}, SCOPE)
                self.assertIs(
                    context.value("[equals(parameters('left'), parameters('right'))]"), expected
                )
        context = Expressions(
            declarations, {"left": {"value": 1.0}, "right": {"value": 1.0}}, SCOPE
        )
        self.assertIn("unknown", context.value("[equals(parameters('left'), parameters('right'))]"))
        template = self.template(True)
        template["parameters"].update(
            {
                "left": {"type": "object", "defaultValue": {"value": [1]}},
                "right": {"type": "object", "defaultValue": {"value": [True]}},
            }
        )
        template["parameters"]["secure"]["defaultValue"] = (
            "[equals(parameters('left'), parameters('right'))]"
        )
        self.assert_matrix(
            arm_source(self.write("typed-equality.json", template), scope=SCOPE), "fail"
        )

    def test_plan_is_separate_and_sensitive_values_do_not_override_source(self):
        plan = {
            "format_version": "1.2",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "mode": "managed",
                            "type": "azurerm_storage_account",
                            "address": "azurerm_storage_account.logs",
                            "values": {
                                "name": "landinglenslogs",
                                "resource_group_name": "rg-management",
                                "https_traffic_only_enabled": False,
                            },
                            "sensitive_values": {},
                        }
                    ]
                }
            },
        }
        path = self.write("plan.json", plan)
        first = plan_source(path, scope=SCOPE, provider_version="4.50.0")
        row = next(
            row for row in assess(first, self.catalog)["results"] if row["upstream_id"] == "G04.01"
        )
        self.assertEqual(row["planned"]["outcome"], "fail")
        plan["planned_values"]["root_module"]["resources"][0]["sensitive_values"] = {
            "https_traffic_only_enabled": True,
        }
        second = plan_source(self.write("plan.json", plan), scope=SCOPE, provider_version="4.50.0")
        self.assertNotEqual(digest(first["artifact_hashes"]), digest(second["artifact_hashes"]))
        row = next(
            row for row in assess(second, self.catalog)["results"] if row["upstream_id"] == "G04.01"
        )
        self.assertEqual(row["planned"]["outcome"], "unknown")


if __name__ == "__main__":
    unittest.main()
