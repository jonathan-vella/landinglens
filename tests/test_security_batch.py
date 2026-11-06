import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from alz_assessor.arm import API_VERSIONS, properties
from alz_assessor.azure import Collector, Response
from alz_assessor.bicep import compile_bicep
from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import document
from alz_assessor.engine import assess
from alz_assessor.plan import plan_source
from alz_assessor.replay import sanitize_evidence
from alz_assessor.reports import render, render_xlsx
from alz_assessor.reviews import prepare_reviews, review_context
from alz_assessor.security_evidence import (
    extension_facts,
    patch_facts,
    pricing_facts,
    routing_facts,
)
from alz_assessor.sources import terraform_source, tf_properties, tf_resource_id
from alz_assessor.terraform import InputError

ROOT = Path(__file__).resolve().parents[1]
SUBSCRIPTION = "/subscriptions/00000000-0000-0000-0000-000000000001"
SCOPE = SUBSCRIPTION + "/resourceGroups/security"
WORKSPACE = SCOPE + "/providers/Microsoft.OperationalInsights/workspaces/logs"
STORAGE = SCOPE + "/providers/Microsoft.Storage/storageAccounts/archive"
AT = "2026-11-06T10:00:00Z"
PRIVATE = "PRIVATE-MUST-BE-WITHHELD"


class SecurityBatchTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        reviews = ROOT / "references" / "recommendation-batches"
        self.matrix = json.loads((reviews / "batch-22-preparation.json").read_text())
        self.catalog = load_catalog()

    def candidate(self):
        candidate = copy.deepcopy(self.catalog)
        rows = {row["guid"]: row for row in self.matrix["recommendations"]}
        for control in candidate["controls"]:
            if control["upstream_guid"] in rows:
                row = rows[control["upstream_guid"]]
                control.update(
                    evidence_requirements=row["evidence_requirements"],
                    rationale=row["limitations"],
                )
                if "review_fact_paths" in row:
                    control.update(
                        review_resource_types=row["review_resource_types"],
                        review_fact_paths=row["review_fact_paths"],
                    )
        return candidate

    def bundle(self):
        values = [
            (
                "Microsoft.Security/pricings",
                {"name": "VirtualMachines"},
                {
                    "pricingTier": "Standard",
                    "subPlan": "P2",
                    "extensions": [
                        {
                            "name": "AgentlessVmScanning",
                            "isEnabled": "True",
                            "additionalExtensionProperties": {"ExclusionTags": PRIVATE},
                        }
                    ],
                    "resourcesCoverageStatus": "FullyCovered",
                    "private": PRIVATE,
                },
            ),
            (
                "Microsoft.KeyVault/managedHSMs",
                {"name": "hsm"},
                {
                    "publicNetworkAccess": "Disabled",
                    "enablePurgeProtection": True,
                    "initialAdminObjectIds": [PRIVATE],
                    "securityDomain": PRIVATE,
                },
            ),
            (
                "Microsoft.Compute/virtualMachines",
                {"name": "vm"},
                {
                    "osProfile": {
                        "adminPassword": PRIVATE,
                        "customData": PRIVATE,
                        "linuxConfiguration": {
                            "provisionVMAgent": True,
                            "patchSettings": {
                                "assessmentMode": "AutomaticByPlatform",
                                "patchMode": "ImageDefault",
                            },
                            "ssh": PRIVATE,
                        },
                    },
                },
            ),
            (
                "Microsoft.Insights/diagnosticSettings",
                {"name": "activity"},
                {
                    "targetResourceId": SUBSCRIPTION,
                    "workspaceId": WORKSPACE,
                    "storageAccountId": STORAGE,
                    "logs": [
                        {
                            "category": "Administrative",
                            "enabled": True,
                            "retentionPolicy": {"enabled": True, "days": 365},
                        }
                    ],
                    "auditRecords": PRIVATE,
                },
            ),
        ]
        return document(
            "evidence",
            schema_version="1.1",
            mode="observed",
            source="saved",
            collected_at=AT,
            scope=SUBSCRIPTION,
            inventory_complete=False,
            artifact_hashes={"fixture": "0" * 64},
            diagnostics=[],
            resources=[
                {
                    "logical_id": root["name"],
                    "arm_id": (SUBSCRIPTION + "/providers/" + kind + "/" + root["name"]).lower(),
                    "resource_type": kind,
                    "state": "known",
                    "reason": "",
                    "source_location": "fixture://security",
                    "properties": properties(kind, body, root=root, observed=True),
                }
                for kind, root, body in values
            ],
        )

    def test_fixed_eight_guids_source_hashes_redirects_no_activation(self):
        targets = json.loads(
            (ROOT / "references" / "recommendation-batches" / "targets.json").read_text()
        )
        fixed = {r["guid"] for r in targets["targets"] if r["batch"] == "22"}
        self.assertEqual(len(fixed), 8)
        self.assertEqual(fixed, {r["guid"] for r in self.matrix["recommendations"]})
        self.assertNotIn("catalog_version", self.matrix)
        self.assertEqual(self.matrix["review_state"], "prepared-awaiting-coordinator-slot")
        sources = json.loads(
            (ROOT / "references" / "recommendation-batches" / "batch-22-sources.json").read_text()
        )["sources"]
        self.assertEqual(len(sources), 25)
        indexed = {r["id"]: r for r in sources}
        self.assertIn("/entra/", indexed["entra-audit-reporting"]["resolved_url"])
        self.assertTrue(
            indexed["legacy-security-center"]["resolved_url"].endswith("/defender-for-cloud/")
        )
        self.assertIn(
            "/azure/azure-sovereign-clouds/", indexed["sovereign-external-keys"]["resolved_url"]
        )
        for source in sources:
            self.assertRegex(source["sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(source["revision"], r"^[0-9a-f]{40}$")
            self.assertTrue(source["retrieved_at"])
            self.assertTrue(source["reuse"])
        for row in self.matrix["recommendations"]:
            self.assertEqual(row["classification"], "assisted")
            self.assertTrue(set(row["sources"]) <= indexed.keys())
            self.assertEqual(len(row["evidence_requirements"]), 3)
            actual = next(c for c in self.catalog["controls"] if c["upstream_guid"] == row["guid"])
            self.assertIsNone(actual["rule"])
            self.assertNotIn("review_fact_paths", actual)
        for kind in (
            "microsoft.security/pricings",
            "microsoft.keyvault/managedhsms",
            "microsoft.compute/virtualmachines",
        ):
            self.assertNotIn(kind, API_VERSIONS)

    def test_strict_pricing_types_missing_subplan_and_private_properties(self):
        bundle = self.bundle()
        pricing = bundle["resources"][0]["properties"]["defenderPricing"]
        self.assertEqual(pricing["pricingTier"], "Standard")
        self.assertEqual(pricing["subPlan"], "P2")
        self.assertNotIn("resourcesCoverageStatus", json.dumps(pricing))
        self.assertNotIn(PRIVATE, json.dumps(bundle))
        for value in (None, True, "true", "standard", 1, {}, []):
            self.assertIn("unknown", pricing_facts({"pricingTier": value})["pricingTier"])
            self.assertIn("unknown", pricing_facts({"enforce": value})["enforce"])
        self.assertIn("unknown", pricing_facts({"pricingTier": "Standard"})["subPlan"])
        self.assertIn("unknown", pricing_facts({"plan": PRIVATE})["plan"])
        self.assertIn("unknown", extension_facts([{"name": PRIVATE, "isEnabled": "True"}]))
        for value in (
            None,
            {},
            [None],
            [{"name": "AgentlessVmScanning"}] * 101,
            [{"name": "AgentlessVmScanning"}] * 2,
        ):
            self.assertIn("unknown", extension_facts(value))
        for value in (True, False, "true", 1, None):
            self.assertIn(
                "unknown",
                extension_facts([{"name": "AgentlessVmScanning", "isEnabled": value}])[0][
                    "isEnabled"
                ],
            )

    def test_activity_categories_destinations_and_no_retention_inference(self):
        summary = self.bundle()["resources"][-1]["properties"]["activityLogRouting"]
        self.assertEqual(summary["logs"], [{"category": "Administrative", "enabled": True}])
        self.assertEqual(summary["workspaceId"], WORKSPACE.lower())
        self.assertNotIn("retention", json.dumps(summary).lower())
        for logs in (
            None,
            {},
            [None],
            [{"category": PRIVATE, "enabled": True}],
            [{"category": "Administrative", "categoryGroup": "allLogs", "enabled": True}],
            [{"category": "Administrative", "enabled": True}] * 2,
            [{"category": "Administrative", "enabled": True}] * 101,
        ):
            self.assertIn("unknown", routing_facts({"logs": logs})["logs"])
        self.assertEqual(routing_facts({"logs": []})["logs"], [])
        self.assertEqual(
            routing_facts({"logs": [{"categoryGroup": "allLogs", "enabled": False}]})["logs"][0][
                "enabled"
            ],
            False,
        )
        for value in ("true", 1, None):
            self.assertIn(
                "unknown",
                routing_facts({"logs": [{"category": "Administrative", "enabled": value}]})["logs"][
                    0
                ]["enabled"],
            )
        self.assertIn("unknown", routing_facts({"workspaceId": STORAGE})["workspaceId"])
        self.assertIn("unknown", routing_facts({"storageAccountId": WORKSPACE})["storageAccountId"])

    def test_os_specific_patch_modes_and_ambiguous_profiles(self):
        for os_name, modes in (
            ("Linux", ("ImageDefault", "AutomaticByPlatform")),
            ("Windows", ("Manual", "AutomaticByOS", "AutomaticByPlatform")),
        ):
            for mode in modes:
                fact = patch_facts(
                    {
                        "os": os_name,
                        "patchMode": mode,
                        "assessmentMode": "AutomaticByPlatform",
                        "provisionVMAgent": False,
                    }
                )
                self.assertEqual(fact["patchMode"], mode)
                self.assertFalse(fact["provisionVMAgent"])
        for os_name, mode in (
            ("Linux", "Manual"),
            ("Windows", "ImageDefault"),
            ("Linux", True),
            ("Windows", "imageDefault"),
        ):
            self.assertIn("unknown", patch_facts({"os": os_name, "patchMode": mode})["patchMode"])
        for profile in (
            None,
            {},
            {"linuxConfiguration": {}, "windowsConfiguration": {}},
            {"linuxConfiguration": PRIVATE},
        ):
            self.assertIn(
                "unknown",
                properties("Microsoft.Compute/virtualMachines", {"osProfile": profile})[
                    "patchConfiguration"
                ],
            )
        self.assertIn("unknown", patch_facts({"os": PRIVATE}))

    def test_terraform_explicit_fields_defaults_scope_and_sensitive_plan(self):
        body = {
            "tier": "Standard",
            "resource_type": "CloudPosture",
            "extension": [
                {
                    "name": "AgentlessVmScanning",
                    "additional_extension_properties": {"ExclusionTags": PRIVATE},
                }
            ],
        }
        fact = tf_properties("azurerm_security_center_subscription_pricing", body)[
            "defenderPricing"
        ]
        self.assertEqual(fact["plan"], "CloudPosture")
        self.assertEqual(fact["extensions"][0]["isEnabled"], "True")
        self.assertIn("unknown", fact["subPlan"])
        self.assertNotIn(PRIVATE, json.dumps(fact))
        self.assertIsNone(
            tf_resource_id(SCOPE, "azurerm_security_center_subscription_pricing", body)
        )
        self.assertEqual(
            tf_resource_id(SUBSCRIPTION, "azurerm_security_center_subscription_pricing", body),
            (SUBSCRIPTION + "/providers/Microsoft.Security/pricings/CloudPosture").lower(),
        )
        self.assertIsNone(
            tf_resource_id(
                SUBSCRIPTION, "azurerm_security_center_subscription_pricing", {"tier": "Standard"}
            )
        )
        path = self.root / "plan.json"
        plan = {
            "format_version": "1.2",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "mode": "managed",
                            "type": "azurerm_security_center_subscription_pricing",
                            "address": "azurerm_security_center_subscription_pricing.posture",
                            "values": body,
                            "sensitive_values": {"extension": True},
                        }
                    ]
                }
            },
        }
        path.write_text(json.dumps(plan))
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            bundle = plan_source(path, scope=SUBSCRIPTION, provider_version="4.50.0")
        self.assertIn(
            "unknown", bundle["resources"][0]["properties"]["defenderPricing"]["extensions"]
        )
        self.assertNotIn(PRIVATE, json.dumps(bundle))
        for kind in ("azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine"):
            props = tf_properties(
                kind,
                {
                    "patch_assessment_mode": True,
                    "provision_vm_agent": "true",
                    "admin_password": PRIVATE,
                },
            )
            self.assertIn("unknown", props["patchConfiguration"]["assessmentMode"])
            self.assertIn("unknown", props["patchConfiguration"]["provisionVMAgent"])
            self.assertNotIn(PRIVATE, json.dumps(props))

    def test_raw_local_source_normalization_without_network(self):
        source = self.root / "source"
        source.mkdir()
        (source / "main.tf").write_text(
            'resource "azurerm_security_center_subscription_pricing" "posture" {\n'
            'tier = "Standard"\nresource_type = "CloudPosture"\n'
            'extension { name = "AgentlessVmScanning" }\n}\n'
            'resource "azurerm_linux_virtual_machine" "machine" {\n'
            'name = "machine"\nresource_group_name = "security"\n'
            'patch_assessment_mode = "AutomaticByPlatform"\n'
            'patch_mode = "ImageDefault"\nprovision_vm_agent = true\n}\n'
            'resource "azurerm_key_vault_managed_hardware_security_module" "keys" {\n'
            'name = "keys"\nresource_group_name = "security"\n'
            "public_network_access_enabled = false\npurge_protection_enabled = true\n}\n"
        )
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            bundle = terraform_source(source, scope=SUBSCRIPTION, provider_version="4.50.0")
        facts = [r["properties"] for r in bundle["resources"]]
        self.assertEqual(facts[0]["defenderPricing"]["plan"], "CloudPosture")
        self.assertEqual(facts[1]["patchConfiguration"]["assessmentMode"], "AutomaticByPlatform")
        self.assertEqual(facts[2]["hsmConfiguration"]["publicNetworkAccess"], "Disabled")

    def test_candidate_review_blank_decisions_tiers_and_all_outputs(self):
        bundle, candidate = self.bundle(), self.candidate()
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            assessment = assess(bundle, candidate, at=AT, evidence_tiers=True)
            selected = ["ALZ-" + r["guid"] for r in self.matrix["recommendations"]]
            prepared = prepare_reviews(assessment, candidate, selected, SUBSCRIPTION)
        self.assertEqual(len(prepared["entries"]), 8)
        for entry in prepared["entries"]:
            for field in (
                "reviewer",
                "evidence",
                "rationale",
                "valid_from",
                "valid_until",
                "outcome",
            ):
                self.assertIsNone(entry[field])
        rows = [r for r in assessment["results"] if r["control_id"] in selected]
        self.assertTrue(all(r["observed"]["outcome"] in ("manual", "unknown") for r in rows))
        self.assertTrue(all(r["observed"]["evidence_tier"] != "verified" for r in rows))
        for format in ("json", "markdown", "html", "csv", "sarif", "pr-summary"):
            self.assertNotIn(PRIVATE, render(assessment, format))
        self.assertGreater(len(render_xlsx(assessment)), 0)
        entra = next(c for c in candidate["controls"] if c["upstream_id"] == "G03.01")
        self.assertEqual(review_context(entra, bundle)["resources"], [])

    def test_unknown_denied_partial_stale_ambiguous_and_over_bound_context(self):
        candidate = self.candidate()
        control = next(c for c in candidate["controls"] if c["upstream_id"] == "G03.04")
        for state in ("unknown", "error"):
            bundle = self.bundle()
            bundle["resources"][0]["state"] = state
            bundle["resources"][0]["reason"] = "permission_denied"
            context = review_context(control, bundle)
            self.assertIn("unknown", context["resources"][0]["facts"]["defenderPricing"])
        bundle = self.bundle()
        context = review_context(control, bundle)
        self.assertFalse(context["inventory_complete"])
        self.assertEqual(context["collected_at"], AT)
        bundle["resources"] = [bundle["resources"][0]] * 2
        with self.assertRaises(InputError):
            review_context(control, bundle)
        original = bundle["resources"][0]
        bundle["resources"] = [
            {**copy.deepcopy(original), "arm_id": None, "logical_id": f"pricing-{index}"}
            for index in range(101)
        ]
        context = review_context(control, bundle)
        self.assertEqual(context["matching_resources"], 101)
        self.assertTrue(context["truncated"])
        stale = assess(self.bundle(), candidate, at="2026-11-09T10:00:00Z", evidence_tiers=True)
        row = next(r for r in stale["results"] if r["control_id"] == control["control_id"])
        self.assertEqual(row["observed"]["evidence_tier"], "needs_decision")
        self.assertNotEqual(row["observed"]["outcome"], "pass")

    def test_replay_projection_privacy_original_time_and_idempotence(self):
        bundle = self.bundle()
        bundle["resources"][0]["properties"]["defenderPricing"]["extensions"][0]["private"] = (
            PRIVATE
        )
        bundle["resources"][2]["properties"]["patchConfiguration"]["adminPassword"] = PRIVATE
        restored = sanitize_evidence(bundle)
        self.assertEqual(restored["collected_at"], AT)
        self.assertEqual(restored["inventory_complete"], bundle["inventory_complete"])
        self.assertNotIn(PRIVATE, json.dumps(restored))
        for left, right in zip(
            restored["resources"], sanitize_evidence(restored)["resources"], strict=True
        ):
            self.assertEqual(left["properties"], right["properties"])
        for control in self.candidate()["controls"]:
            if control["upstream_guid"] in {r["guid"] for r in self.matrix["recommendations"]}:
                before = review_context(control, bundle)["resources"]
                after = review_context(control, restored)["resources"]
                self.assertEqual(before, after)

    def test_new_kinds_do_not_enable_collector_requests(self):
        requests = []

        def transport(method, url, body=None):
            requests.append((method, url))
            if "/resources?" in url:
                return Response(
                    200,
                    {
                        "value": [
                            {
                                "id": SUBSCRIPTION
                                + "/providers/Microsoft.Security/pricings/CloudPosture",
                                "type": "Microsoft.Security/pricings",
                            }
                        ]
                    },
                    {},
                )
            if (
                "/providers/microsoft.authorization/policy" in url.lower()
                or "/providers/microsoft.policyinsights/policystates/latest/queryresults?"
                in url.lower()
            ):
                return Response(200, {"value": []}, {})
            self.fail("No new security detail route is authorized")

        bundle = Collector(transport).collect(
            subscriptions=["00000000-0000-0000-0000-000000000001"], inventory_authorized=True
        )
        self.assertEqual(sum("/resources?" in url for _, url in requests), 1)
        self.assertTrue(all("/pricings/" not in url for _, url in requests))
        self.assertEqual(bundle["resources"][0]["properties"], {})
        self.assertIsNone(bundle["resources"][0]["api_version"])
        report = assess(bundle, self.candidate(), at=bundle["collected_at"], evidence_tiers=True)
        row = next(
            row
            for row in report["results"]
            if row["control_id"] == "ALZ-09945bda-4333-44f2-9911-634182ba5275"
        )
        self.assertEqual(row["observed"]["evidence_tier"], "needs_decision")

    def test_real_bicep_security_configuration_without_restore(self):
        compiler = os.environ.get("BICEP_COMPILER")
        if not compiler:
            self.skipTest("Existing compiler unavailable; no acquisition or restore")
        fixture = ROOT / "tests" / "fixtures" / "security"
        compiled = []
        for name in ("controls.bicep", "subscription.bicep"):
            result = compile_bicep(fixture / name, compiler=compiler)
            self.assertRegex(result["template_sha256"], r"^[0-9a-f]{64}$")
            for resource in result["template"]["resources"]:
                compiled.append(properties(resource["type"], resource["properties"], root=resource))
        self.assertTrue(
            any(row.get("patchConfiguration", {}).get("os") == "Linux" for row in compiled)
        )
        self.assertTrue(
            any(
                row.get("hsmConfiguration", {}).get("publicNetworkAccess") == "Disabled"
                for row in compiled
            )
        )
        self.assertTrue(
            any(row.get("defenderPricing", {}).get("subPlan") == "P2" for row in compiled)
        )
        self.assertTrue(
            any(
                row.get("activityLogRouting", {}).get("logs")
                == [
                    {"category": "Administrative", "enabled": True},
                    {"category": "Security", "enabled": False},
                ]
                for row in compiled
            )
        )
        self.assertEqual(len(compiled), 5)
