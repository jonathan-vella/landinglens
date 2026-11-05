import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path

from alz_assessor.arm import arm_source
from alz_assessor.catalog import load_catalog, reviewed_refresh
from alz_assessor.comparison import compare
from alz_assessor.contracts import digest, validate
from alz_assessor.engine import assess
from alz_assessor.plan import plan_source
from alz_assessor.sources import terraform_source
from alz_assessor.terraform import InputError

SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/wave"
IDENTITY = SCOPE + "/providers/Microsoft.Network/firewallPolicies/policy"
WAVE = {"D07.06", "D07.07"}


class ControlWaveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.catalog = load_catalog()

    def write(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def inputs(self, sku="Premium", mode="Deny", *, version="2024-05-01"):
        properties = {
            "sku": {"tier": sku},
            "threatIntelMode": mode,
            "intrusionDetection": {"mode": mode},
        }
        template = self.write(
            "template.json",
            {
                "resources": [
                    {
                        "type": "Microsoft.Network/firewallPolicies",
                        "apiVersion": version,
                        "name": "policy",
                        "properties": properties,
                    }
                ]
            },
        )
        values = {
            "id": IDENTITY,
            "name": "policy",
            "resource_group_name": "wave",
            "sku": sku,
            "threat_intelligence_mode": mode,
            "intrusion_detection": [{"mode": mode}],
        }
        source = self.root / "source"
        source.mkdir(exist_ok=True)
        (source / "main.tf.json").write_text(
            json.dumps(
                {
                    "resource": {"azurerm_firewall_policy": {"policy": values}},
                }
            ),
            encoding="utf-8",
        )
        plan = self.write(
            "plan.json",
            {
                "format_version": "1.2",
                "planned_values": {
                    "root_module": {
                        "resources": [
                            {
                                "mode": "managed",
                                "type": "azurerm_firewall_policy",
                                "address": "azurerm_firewall_policy.policy",
                                "values": values,
                            }
                        ]
                    }
                },
            },
        )
        return template, source, plan

    def outcomes(self, bundle):
        report = assess(bundle, self.catalog)
        self.assertEqual(report["coverage"]["controls"], 255)
        self.assertEqual(
            report["coverage"]["automated_controls"],
            sum(c["automation"] == "automated" for c in self.catalog["controls"]),
        )
        return {
            row["upstream_id"]: row[bundle["mode"]]["outcome"]
            for row in report["results"]
            if row["upstream_id"] in WAVE
        }

    def test_exact_promotion_preserves_historical_meaning_and_all_inventory(self):
        data = files("alz_assessor").joinpath("data")
        self.catalog = load_catalog(str(data.joinpath("catalog-2026-11-04.2.json")))
        previous = load_catalog(str(data.joinpath("catalog-2026-11-04.1.json")))
        original = {c["control_id"]: c for c in previous["controls"]}
        self.assertEqual(len(reviewed_refresh(self.catalog, previous)["changed"]), 2)
        for control in self.catalog["controls"]:
            if control["upstream_id"] not in WAVE:
                self.assertEqual(control, original[control["control_id"]])
        self.assertEqual(previous["schema_version"], "1.0")
        self.assertEqual(sum(c["automation"] == "automated" for c in previous["controls"]), 2)
        self.assertEqual(
            digest(json.loads(data.joinpath("accepted-matrix.json").read_text())),
            self.catalog["accepted_matrix_sha256"],
        )
        for expected, operation, skus in (
            (True, "enum-equals", ["Premium"]),
            ("Deny", "enum-equals", [True]),
            ("Deny", "unreviewed", ["Premium"]),
            ("Deny", "enum-equals", []),
        ):
            invalid = copy.deepcopy(self.catalog)
            rule = next(c["rule"] for c in invalid["controls"] if c["upstream_id"] == "D07.06")
            rule.update(expected=expected, operation=operation, applicable_skus=skus)
            with self.assertRaises(InputError):
                validate(invalid)

    def test_typed_matrix_raw_arm_optional_plan_and_saved_observed(self):
        for sku, mode, threat, intrusion in (
            ("Premium", "Deny", "pass", "pass"),
            ("Premium", "Alert", "fail", "fail"),
            ("Premium", "Off", "fail", "fail"),
            ("Standard", "Deny", "pass", "not_applicable"),
            ("Basic", "Deny", "not_applicable", "not_applicable"),
            (None, "Deny", "unknown", "unknown"),
            ("premium", "Deny", "unknown", "unknown"),
            ("Premium", None, "unknown", "unknown"),
            ("Premium", True, "unknown", "unknown"),
            ("Premium", "deny", "unknown", "unknown"),
        ):
            with self.subTest(sku=sku, mode=mode):
                template, source, plan = self.inputs(sku, mode)
                arm = arm_source(template, scope=SCOPE)
                observed = copy.deepcopy(arm)
                observed.update(mode="observed", source="saved", inventory_complete=False)
                bundles = [
                    arm,
                    observed,
                    terraform_source(source, scope=SCOPE, provider_version="4.50.0"),
                    plan_source(plan, scope=SCOPE, provider_version="4.50.0"),
                ]
                for bundle in bundles:
                    self.assertEqual(
                        self.outcomes(bundle),
                        {
                            "D07.06": threat,
                            "D07.07": intrusion,
                        },
                    )

    def test_error_stale_missing_unsupported_and_comparison_identity(self):
        template, source, plan = self.inputs()
        planned = arm_source(template, scope=SCOPE)
        for state, expected in (("error", "error"), ("inaccessible", "unknown")):
            bundle = copy.deepcopy(planned)
            bundle["resources"][0].update(state=state, reason="fixture_" + state)
            self.assertEqual(set(self.outcomes(bundle).values()), {expected})
        stale = copy.deepcopy(planned)
        stale["collected_at"] = "2000-01-01T00:00:00Z"
        self.assertEqual(set(self.outcomes(stale).values()), {"unknown"})
        for complete, expected in ((True, "not_applicable"), (False, "unknown")):
            missing = {**planned, "resources": [], "inventory_complete": complete}
            self.assertEqual(set(self.outcomes(missing).values()), {expected})
        template, _, _ = self.inputs(version="unreviewed")
        self.assertEqual(
            set(self.outcomes(arm_source(template, scope=SCOPE)).values()), {"unknown"}
        )
        self.assertEqual(
            set(self.outcomes(terraform_source(source, scope=SCOPE)).values()), {"unknown"}
        )
        self.assertEqual(set(self.outcomes(plan_source(plan, scope=SCOPE)).values()), {"unknown"})
        observed = copy.deepcopy(planned)
        observed.update(mode="observed", source="saved")
        for mode, expected in (("Deny", "match"), ("Alert", "drift")):
            observed["resources"][0]["properties"]["threatIntelMode"] = mode
            result = compare(assess(planned, self.catalog), assess(observed, self.catalog))
            row = next(r for r in result["results"] if r["upstream_id"] == "D07.06")
            self.assertEqual(row["comparison"], expected)
        observed["resources"][0]["arm_id"] = IDENTITY + "-other"
        observed["inventory_complete"] = False
        result = compare(assess(planned, self.catalog), assess(observed, self.catalog))
        self.assertTrue(
            all(
                r["comparison"] == "not_comparable"
                for r in result["results"]
                if r["upstream_id"] in WAVE
            )
        )

    def test_installed_cross_mode_formats_and_actual_no_restore_bicep(self):
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

        for mode, expected in (("Deny", "pass"), ("Off", "fail")):
            template, source, plan = self.inputs(mode=mode)
            observed = arm_source(template, scope=SCOPE)
            observed.update(mode="observed", source="saved")
            saved = self.write("observed.json", observed)
            cases = [
                (template, ["--input", "arm", "--scope", SCOPE]),
                (
                    source,
                    ["--input", "terraform", "--scope", SCOPE, "--provider-version", "4.50.0"],
                ),
                (
                    plan,
                    ["--input", "terraform-plan", "--scope", SCOPE, "--provider-version", "4.50.0"],
                ),
                (saved, ["--input", "evidence"]),
            ]
            if os.environ.get("BICEP_COMPILER"):
                bicep = self.root / "policy.bicep"
                bicep.write_text(
                    "resource policy 'Microsoft.Network/firewallPolicies@2024-05-01' = {\n"
                    " name: 'policy'\n location: 'westeurope'\n properties: {\n"
                    "  sku: { tier: 'Premium' }\n"
                    f"  threatIntelMode: '{mode}'\n"
                    f"  intrusionDetection: {{ mode: '{mode}' }}\n"
                    " }\n}\n",
                    encoding="utf-8",
                )
                cases.append(
                    (
                        bicep,
                        [
                            "--input",
                            "bicep",
                            "--scope",
                            SCOPE,
                            "--compiler",
                            os.environ["BICEP_COMPILER"],
                        ],
                    )
                )
            for path, arguments in cases:
                report = json.loads(run("assess", path, *arguments))
                rows = [r for r in report["results"] if r["upstream_id"] in WAVE]
                self.assertEqual(len(rows), 2)
                self.assertTrue(
                    all((r["observed"] or r["planned"])["outcome"] == expected for r in rows)
                )
                report_path = self.write("report.json", report)
                for format in ("json", "markdown", "html"):
                    rendered = run("render", report_path, "--format", format)
                    self.assertIn("D07.06", rendered)
                    self.assertIn("D07.07", rendered)
                    self.assertIn("Explicit local firewall-policy mode", rendered)
        template, _, _ = self.inputs()
        original = arm_source(template, scope=SCOPE)
        for case, expected in (
            ("missing-mode", "unknown"),
            ("partial-empty", "unknown"),
            ("error", "error"),
            ("stale", "unknown"),
            ("basic", "not_applicable"),
        ):
            bundle = copy.deepcopy(original)
            if case == "missing-mode":
                bundle["resources"][0]["properties"] = {"sku": {"tier": "Premium"}}
            elif case == "partial-empty":
                bundle.update(resources=[], inventory_complete=False)
            elif case == "error":
                bundle["resources"][0].update(state="error", reason="fixture_error")
            elif case == "stale":
                bundle["collected_at"] = "2000-01-01T00:00:00Z"
            else:
                bundle["resources"][0]["properties"]["sku"]["tier"] = "Basic"
            report = json.loads(
                run("assess", self.write("edge.json", bundle), "--input", "evidence")
            )
            self.assertEqual(
                {
                    row["planned"]["outcome"]
                    for row in report["results"]
                    if row["upstream_id"] in WAVE
                },
                {expected},
            )
