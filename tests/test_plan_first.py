import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from alz_assessor.catalog import load_catalog
from alz_assessor.engine import assess
from alz_assessor.plan import plan_source
from alz_assessor.preflight import preflight, render_preflight


class PlanFirstTests(unittest.TestCase):
    def test_guidance_preserves_ready_partial_blocked_readiness(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "plan.json"
            path.write_text("{}", encoding="utf-8")
            for mode in ("terraform", "terraform-plan"):
                for complete, expected in ((True, "ready"), (False, "partial")):
                    source = root if mode == "terraform" else path
                    with patch("subprocess.run", side_effect=AssertionError("execution forbidden")):
                        result = preflight(
                            source,
                            mode,
                            lambda complete=complete: {
                                "inventory_complete": complete,
                                "diagnostics": [],
                                "resources": [],
                            },
                            scope="/subscriptions/00000000-0000-0000-0000-000000000001",
                            provider_version="4.50.0",
                            compiler=None,
                            probe_compiler=False,
                        )
                    self.assertEqual(result["readiness"], expected)
                    for format in ("json", "text"):
                        text = render_preflight(result, format)
                        self.assertIn("terraform-plan", text)
                        self.assertIn("fallback", text)
                        self.assertIn("never generates plans", text)
                blocked = preflight(
                    root / "absent",
                    mode,
                    lambda: self.fail("must not load absent input"),
                    scope=None,
                    provider_version=None,
                    compiler=None,
                    probe_compiler=False,
                )
                self.assertEqual(blocked["readiness"], "blocked")
                self.assertIn("terraform_guidance", blocked)

    def test_installed_doctor_hints_for_raw_and_plan_do_not_execute_terraform(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            (source / "main.tf.json").write_text(json.dumps({"resource": {}}), encoding="utf-8")
            plan = root / "plan.json"
            plan.write_text(
                json.dumps(
                    {"format_version": "1.2", "planned_values": {"root_module": {"resources": []}}}
                ),
                encoding="utf-8",
            )
            for path, mode in ((source, "terraform"), (plan, "terraform-plan")):
                result = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "alz_assessor.cli",
                        "doctor",
                        str(path),
                        "--input",
                        mode,
                        "--provider-version",
                        "4.50.0",
                    ],
                    cwd=root,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(
                    "separately prepared", json.loads(result.stdout)["terraform_guidance"]
                )

    def test_large_terraform_plan_up_to_2500_resources_and_parameter_placeholder_preflight(self):
        scope = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-alz"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            plan_path = root / "large-plan.json"
            resources = [
                {
                    "address": f"azurerm_virtual_network.vnet_{i}",
                    "mode": "managed",
                    "type": "azurerm_virtual_network",
                    "values": {
                        "id": f"{scope}/providers/Microsoft.Network/virtualNetworks/vnet-{i}",
                        "name": f"vnet-{i}",
                        "resource_group_name": "rg-alz",
                        "address_space": ["10.0.0.0/16"],
                    },
                }
                for i in range(400)
            ]
            plan_path.write_text(
                json.dumps(
                    {
                        "format_version": "1.2",
                        "complete": True,
                        "planned_values": {"root_module": {"resources": resources}},
                    }
                ),
                encoding="utf-8",
            )
            bundle = plan_source(plan_path, scope=scope, provider_version="4.50.0")
            self.assertEqual(len(bundle["resources"]), 400)
            report = assess(bundle, load_catalog(), at="2026-11-05T00:00:00Z")
            self.assertEqual(report["kind"], "assessment")

            arm_file = root / "template.json"
            arm_file.write_text(json.dumps({"resources": []}), encoding="utf-8")
            params_file = root / "parameters.json"
            params_file.write_text(
                json.dumps(
                    {
                        "parameters": {
                            "subscriptionId": {"value": "{{ subscription_id_management }}"},
                        }
                    }
                ),
                encoding="utf-8",
            )
            for mode in ("arm", "bicep"):
                result = preflight(
                    arm_file,
                    mode,
                    lambda: {"inventory_complete": True, "diagnostics": [], "resources": []},
                    scope=scope,
                    provider_version=None,
                    compiler=None,
                    probe_compiler=False,
                    parameters=params_file,
                )
                reasons = [c["reason"] for c in result["checks"]]
                self.assertIn("accelerator_placeholder_unresolved", reasons)
