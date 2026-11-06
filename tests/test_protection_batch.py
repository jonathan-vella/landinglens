import copy
import hashlib
import json
import os
import tempfile
import unittest
import zipfile
from importlib.resources import files
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from alz_assessor.arm import API_VERSIONS, arm_source, properties
from alz_assessor.azure import Collector, Response
from alz_assessor.catalog import load_catalog
from alz_assessor.comparison import compare
from alz_assessor.contracts import control_digest, document
from alz_assessor.engine import assess
from alz_assessor.interviews import compile_interview, prepare_interview
from alz_assessor.network_evidence import review_fact
from alz_assessor.plan import plan_source
from alz_assessor.policy_evidence import import_policy_export
from alz_assessor.protection_evidence import DDOS_CATEGORIES, PATHS
from alz_assessor.replay import export_bundle, replay_bundle, semantic
from alz_assessor.reports import render, render_xlsx
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import prepare_reviews, review_context
from alz_assessor.sources import TF_TYPES, terraform_source, tf_properties, tf_resource_id
from alz_assessor.terraform import InputError, tree_hash

SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/protection"
NETWORK = SCOPE + "/providers/Microsoft.Network/"
SUBNET = NETWORK + "virtualNetworks/workload/subnets/proxy"
IP = NETWORK + "publicIPAddresses/ip"
WAF = NETWORK + "FrontDoorWebApplicationFirewallPolicies/edge"
GW_WAF = NETWORK + "ApplicationGatewayWebApplicationFirewallPolicies/origin"
PROFILE = SCOPE + "/providers/Microsoft.Cdn/profiles/edge"
DOMAIN = PROFILE + "/customDomains/site"
AT = "2026-11-06T09:30:00Z"
SENTINEL = "PRIVATE-NOT-FOR-REPORTS"
GUIDS = (
    "1d7aa9b6-4704-4489-a804-2d88e79d17b7",
    "3b22a5a6-7e7a-48ed-9b30-e38c3f29812b",
    "2363cefe-179b-4599-be0d-5973cd4cd21b",
    "088137f5-e6c4-4cfd-9e50-4547c2447ec6",
    "b034c01e-110b-463a-b36e-e3346e57f225",
    "b1c82a3f-2320-4dfa-8972-7ae4823c8930",
    "3c5a808d-c695-4c14-a63c-c7ab7a510e41",
    "359c373e-7dd6-4162-9a36-4a907ecae48e",
    "f29812b2-363c-4efe-879b-599de0d5973c",
    "d4cd21b0-8813-47f5-b6c4-cfd3e504547c",
)


class ProtectionBatchTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.catalog = load_catalog()

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def record(self, kind, identity, values, root=None):
        return {
            "logical_id": identity.lower(),
            "arm_id": identity.lower(),
            "resource_type": kind,
            "state": "known",
            "reason": "",
            "source_location": "fixture://configuration",
            "properties": properties(kind, values, root=root, observed=True),
        }

    def details(self):
        return [
            (
                "Microsoft.Network/FrontDoorWebApplicationFirewallPolicies",
                WAF,
                {
                    "policySettings": {"enabledState": "Enabled", "mode": "Prevention"},
                    "managedRules": {
                        "managedRuleSets": [{"ruleSetType": "Microsoft_DefaultRuleSet"}]
                    },
                    "customRules": {"rules": []},
                },
                {"sku": {"name": "Premium_AzureFrontDoor"}},
            ),
            (
                "Microsoft.Cdn/profiles/securityPolicies",
                PROFILE + "/securityPolicies/waf",
                {
                    "parameters": {
                        "type": "WebApplicationFirewall",
                        "wafPolicy": {"id": WAF},
                        "associations": [{"domains": [{"id": DOMAIN}], "patternsToMatch": ["/*"]}],
                    },
                },
                None,
            ),
            (
                "Microsoft.Network/applicationGateways",
                NETWORK + "applicationGateways/proxy",
                {
                    "gatewayIPConfigurations": [{"properties": {"subnet": {"id": SUBNET}}}],
                    "firewallPolicy": {"id": GW_WAF},
                    "backendAddressPools": [
                        {
                            "properties": {
                                "backendAddresses": [{"fqdn": SENTINEL}, {"ipAddress": SENTINEL}],
                            }
                        }
                    ],
                },
                None,
            ),
            (
                "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies",
                GW_WAF,
                {
                    "policySettings": {"state": "Enabled", "mode": "Prevention"},
                    "managedRules": {"managedRuleSets": []},
                    "customRules": [
                        {
                            "priority": 1,
                            "state": "Enabled",
                            "action": "Block",
                            "matchConditions": [
                                {
                                    "matchVariables": [
                                        {
                                            "variableName": "RequestHeaders",
                                            "selector": "X-Azure-FDID",
                                        }
                                    ],
                                    "negationConditon": True,
                                    "operator": "Equal",
                                    "matchValues": [SENTINEL],
                                }
                            ],
                        }
                    ],
                },
                None,
            ),
            (
                "Microsoft.Network/publicIPAddresses",
                IP,
                {
                    "ddosSettings": {
                        "protectionMode": "Enabled",
                        "ddosProtectionPlan": {"id": NETWORK + "ddosProtectionPlans/plan"},
                    },
                    "ipConfiguration": {
                        "id": NETWORK + "networkInterfaces/nic/ipConfigurations/main"
                    },
                    "ipAddress": SENTINEL,
                    "dnsSettings": {"fqdn": SENTINEL},
                },
                None,
            ),
            (
                "Microsoft.Network/networkInterfaces",
                NETWORK + "networkInterfaces/nic",
                {
                    "virtualMachine": {
                        "id": SCOPE + "/providers/Microsoft.Compute/virtualMachines/vm"
                    },
                    "ipConfigurations": [
                        {
                            "properties": {
                                "subnet": {"id": SUBNET},
                                "publicIPAddress": {"id": IP},
                                "privateIPAddress": SENTINEL,
                            }
                        }
                    ],
                },
                None,
            ),
            (
                "Microsoft.Network/virtualNetworks/subnets",
                SUBNET,
                {
                    "addressPrefix": "10.0.0.0/24",
                    "defaultOutboundAccess": False,
                    "natGateway": {"id": NETWORK + "natGateways/nat"},
                    "networkSecurityGroup": {"id": NETWORK + "networkSecurityGroups/origin"},
                },
                None,
            ),
            (
                "Microsoft.Network/networkSecurityGroups",
                NETWORK + "networkSecurityGroups/origin",
                {
                    "provisioningState": "Succeeded",
                    "securityRules": [
                        {
                            "name": "frontdoor",
                            "properties": {
                                "priority": 100,
                                "direction": "Inbound",
                                "access": "Allow",
                                "protocol": "Tcp",
                                "sourceAddressPrefix": "AzureFrontDoor.Backend",
                                "destinationPortRanges": ["80", "443"],
                            },
                        }
                    ],
                },
                None,
            ),
            (
                "Microsoft.Insights/diagnosticSettings",
                IP + "/providers/Microsoft.Insights/diagnosticSettings/ddos",
                {
                    "logs": [
                        {"category": category, "enabled": True} for category in DDOS_CATEGORIES
                    ],
                    "workspaceId": SCOPE
                    + "/providers/Microsoft.OperationalInsights/workspaces/logs",
                    "storageAccountId": SCOPE + "/providers/Microsoft.Storage/storageAccounts/logs",
                },
                {"scope": IP},
            ),
            (
                "Microsoft.Network/connections",
                NETWORK + "connections/primary",
                {
                    "connectionType": "ExpressRoute",
                    "enableBgp": True,
                    "routingWeight": 32000,
                    "virtualNetworkGateway1": {"id": NETWORK + "virtualNetworkGateways/er"},
                    "peer": {"id": NETWORK + "expressRouteCircuits/circuit"},
                    "sharedKey": SENTINEL,
                    "authorizationKey": SENTINEL,
                },
                None,
            ),
            (
                "Microsoft.Network/virtualNetworkGateways",
                NETWORK + "virtualNetworkGateways/er",
                {
                    "gatewayType": "ExpressRoute",
                    "sku": {"name": "ErGw3Az"},
                    "enableBgp": True,
                    "activeActive": False,
                    "vpnGatewayGeneration": "None",
                    "ipConfigurations": [{"properties": {"subnet": {"id": SUBNET}}}],
                    "bgpSettings": {"bgpPeeringAddress": SENTINEL},
                    "vpnClientConfiguration": {"radiusServerSecret": SENTINEL},
                },
                None,
            ),
        ]

    def bundle(self):
        return document(
            "evidence",
            schema_version="1.1",
            mode="observed",
            source="saved",
            collected_at=AT,
            scope=SCOPE,
            inventory_complete=False,
            artifact_hashes={"fixture": "0" * 64},
            diagnostics=[],
            resources=[self.record(*entry) for entry in self.details()],
        )

    def control(self, guid):
        return next(c for c in self.catalog["controls"] if c["upstream_guid"] == guid)

    def test_exact_history_matrix_sources_manual_date_and_original_hashes(self):
        data = files("alz_assessor").joinpath("data")
        prior = data.joinpath("catalog-2026-11-06.3.json").read_bytes()
        self.assertEqual(
            hashlib.sha256(prior).hexdigest(),
            "9cb7425513ee5a2e94a3ad7f5b2d44729fdb455e15975974d1cd1d5ff319a5c2",
        )
        before = {c["upstream_guid"]: c for c in json.loads(prior)["controls"]}
        matrix = json.loads(data.joinpath("batch-matrix-2026-11-06.5.json").read_text())
        batch = matrix["batches"][-1]
        self.assertEqual(batch["batch"], "13")
        self.assertEqual({r["guid"] for r in batch["recommendations"]}, set(GUIDS))
        source_ids = {source["id"] for source in matrix["sources"][-1]["sources"]}
        for row in batch["recommendations"]:
            self.assertLessEqual(set(row["sources"]), source_ids)
        cohort13 = json.loads(data.joinpath("catalog-2026-11-06.5.json").read_text())
        for control in cohort13["controls"]:
            if control["upstream_guid"] not in GUIDS:
                self.assertEqual(
                    control_digest(control), control_digest(before[control["upstream_guid"]])
                )
        self.assertEqual(len(self.catalog["controls"]), 255)
        self.assertEqual(sum(c["automation"] == "automated" for c in self.catalog["controls"]), 10)
        manual = self.control(GUIDS[4])
        self.assertEqual(manual["automation"], "manual")
        self.assertEqual(manual["recommendation"], before[GUIDS[4]]["recommendation"])
        self.assertIn("September 30, 2025", manual["recommendation"])
        self.assertIn("March 31, 2026", " ".join(manual["evidence_requirements"]))
        old_crosswalk = json.loads(data.joinpath("crosswalk-2026-11-06.3.json").read_text())
        current = json.loads(data.joinpath("crosswalk.json").read_text())
        self.assertEqual(current["entries"], old_crosswalk["entries"])
        self.assertEqual(current["sources"], old_crosswalk["sources"])

    def test_frontdoor_and_gateway_preparation_never_become_protection_or_ownership(self):
        bundle = self.bundle()
        self.assertNotIn(SENTINEL, json.dumps(bundle))
        props = bundle["resources"][0]["properties"]
        self.assertEqual(props["wafMode"], "Prevention")
        self.assertIs(props["wafEnabled"], True)
        association = bundle["resources"][1]["properties"]
        self.assertEqual(association["wafPolicyId"], WAF.lower())
        self.assertEqual(
            association["wafAssociations"], [{"domainIds": [DOMAIN.lower()], "allPaths": True}]
        )
        header = bundle["resources"][3]["properties"]["fdidRuleSummary"][0]
        self.assertEqual(header["negatedEqualFdidConditions"], 1)
        self.assertEqual(header["fdidConditions"], 1)
        self.assertEqual(
            bundle["resources"][2]["properties"]["applicationBackendSummary"],
            [{"suppliedAddressCount": 2}],
        )
        report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        for row in report["results"]:
            if row["control_id"] in {"ALZ-" + guid for guid in GUIDS}:
                self.assertEqual(row["observed"]["outcome"], "manual")
                self.assertNotEqual(row["observed"]["evidence_tier"], "verified")

    def test_strict_missing_invalid_sensitive_types_bounds_and_relationships(self):
        bool_paths = ("wafEnabled", "defaultOutboundAccess", "enableBgp", "activeActive")
        for path in bool_paths:
            for value in (None, "true", 0, 1, [], {"unknown": "secret"}, 1.0):
                self.assertIn("unknown", review_fact({path: value}, path))
            self.assertIs(review_fact({path: False}, path), False)
        for path in ("customRuleCount", "managedRuleSetCount", "routingWeight"):
            bound = 32000 if path == "routingWeight" else 100
            for value in (True, "1", 1.0, -1, bound + 1, None, {}):
                self.assertIn("unknown", review_fact({path: value}, path))
            for value in (0, bound):
                self.assertEqual(review_fact({path: value}, path), value)
        for path in (
            "wafMode",
            "frontDoorSku",
            "gatewaySku",
            "vpnGatewayGeneration",
            "ddosProtectionMode",
        ):
            for value in (True, None, {}, SENTINEL):
                self.assertIn("unknown", review_fact({path: value}, path))
        for path in (
            "wafPolicyId",
            "virtualMachineId",
            "expressRouteCircuitId",
            "localNetworkGatewayId",
            "diagnosticStorageId",
            "ipConfigurationId",
        ):
            for value in (None, True, {}, "alias", IP):
                self.assertIn("unknown", review_fact({path: value}, path))
        for path, limit in (
            ("wafAssociations", 20),
            ("nicIpConfigurations", 20),
            ("fdidRuleSummary", 100),
            ("inboundRuleSummary", 100),
            ("applicationBackendSummary", 100),
        ):
            for value in (None, {}, [True], [{}] * (limit + 1)):
                self.assertIn("unknown", review_fact({path: value}, path))
        association = review_fact(
            {"wafAssociations": [{"domainIds": [IP], "allPaths": "true"}]}, "wafAssociations"
        )
        self.assertIn("unknown", association[0]["domainIds"][0])
        self.assertIn("unknown", association[0]["allPaths"])
        for kind in (
            "azurerm_cdn_frontdoor_firewall_policy",
            "azurerm_application_gateway",
            "azurerm_public_ip",
            "azurerm_network_interface",
        ):
            props = tf_properties(kind, {})
            self.assertNotIn(SENTINEL, json.dumps(props))
        for path in PATHS:
            self.assertNotEqual(review_fact({}, path), True)

    def test_origin_header_and_service_tag_summaries_are_candidates_only(self):
        kind, _, values, _ = self.details()[3]
        for key, value in (
            ("negationConditon", "true"),
            ("operator", "Contains"),
            ("matchValues", []),
            ("matchValues", [SENTINEL] * 2),
        ):
            changed = copy.deepcopy(values)
            changed["customRules"][0]["matchConditions"][0][key] = value
            summary = properties(kind, changed)["fdidRuleSummary"][0]
            self.assertEqual(summary["negatedEqualFdidConditions"], 0)
        changed = copy.deepcopy(values)
        changed["customRules"][0]["matchConditions"] = {}
        self.assertIn("unknown", properties(kind, changed)["fdidRuleSummary"][0]["fdidConditions"])
        nsg_kind, _, nsg, _ = self.details()[7]
        summary = properties(nsg_kind, nsg)["inboundRuleSummary"][0]
        self.assertEqual(summary["source"], "AzureFrontDoor.Backend")
        self.assertEqual(summary["destinationPorts"], "80,443")
        nsg["securityRules"][0]["properties"]["destinationPortRange"] = "*"
        self.assertIn(
            "unknown", properties(nsg_kind, nsg)["inboundRuleSummary"][0]["destinationPorts"]
        )
        missing = self.bundle()
        missing["resources"] = [
            r for r in missing["resources"] if not r["resource_type"].endswith("/subnets")
        ]
        context = review_context(self.control(GUIDS[1]), missing)
        proxy = next(
            r for r in context["resources"] if r["resource_type"].endswith("/applicationGateways")
        )
        self.assertIn("unknown", proxy["linked_subnets"][0])
        duplicated = self.bundle()
        duplicated["resources"].append(copy.deepcopy(duplicated["resources"][6]))
        # Contract validation prevents ambiguous duplicate identities before joining.
        with self.assertRaises(InputError):
            review_context(self.control(GUIDS[1]), duplicated)

    def test_ddos_modes_logging_targets_metrics_and_missing_are_not_coverage(self):
        bundle = self.bundle()
        ip = bundle["resources"][4]["properties"]
        self.assertEqual(ip["ddosProtectionMode"], "Enabled")
        diag = bundle["resources"][8]["properties"]
        self.assertEqual(diag["targetResourceId"], IP.lower())
        self.assertTrue(all(diag["ddosLogCategories"][c] is True for c in DDOS_CATEGORIES))
        for logs in (
            None,
            [],
            [{"category": "AllMetrics", "enabled": True}],
            [{"category": DDOS_CATEGORIES[0], "enabled": True}] * 2,
            [{"category": DDOS_CATEGORIES[0], "enabled": "true"}],
        ):
            props = properties("Microsoft.Insights/diagnosticSettings", {"logs": logs})
            self.assertIn("unknown", props["ddosLogCategories"][DDOS_CATEGORIES[0]])
        props = properties(
            "Microsoft.Insights/diagnosticSettings",
            {"logs": [{"category": DDOS_CATEGORIES[0], "enabled": False}]},
        )
        self.assertIs(props["ddosLogCategories"][DDOS_CATEGORIES[0]], False)
        props = properties(
            "Microsoft.Network/publicIPAddresses",
            {"ddosSettings": {"protectionMode": "VirtualNetworkInherited"}},
        )
        self.assertEqual(props["ddosProtectionMode"], "VirtualNetworkInherited")
        self.assertIn("unknown", props["ddosProtectionPlan"]["id"])

    def test_hybrid_weights_skus_and_types_never_establish_preference_or_demand(self):
        bundle = self.bundle()
        connection = bundle["resources"][-2]["properties"]
        self.assertEqual(connection["routingWeight"], 32000)
        self.assertEqual(
            connection["expressRouteCircuitId"], (NETWORK + "expressRouteCircuits/circuit").lower()
        )
        self.assertEqual(bundle["resources"][-1]["properties"]["gatewaySku"], "ErGw3AZ")
        for sku in ("ErGwScale", "ergw3az", {}, True):
            self.assertIn(
                "unknown",
                tf_properties("azurerm_virtual_network_gateway", {"sku": sku})["gatewaySku"],
            )
        props = tf_properties(
            "azurerm_virtual_network_gateway_connection",
            {
                "routing_weight": 0,
                "enable_bgp": False,
                "express_route_circuit_id": IP,
                "shared_key": SENTINEL,
            },
        )
        self.assertEqual(props["routingWeight"], 0)
        self.assertIs(props["enableBgp"], False)
        self.assertIn("unknown", props["expressRouteCircuitId"])
        self.assertNotIn(SENTINEL, json.dumps(props))

    def test_saved_actual_nic_policy_context_and_independent_exceptions_no_enforcement(self):
        assignment = SCOPE + "/providers/Microsoft.Authorization/policyAssignments/nic"
        definition = (
            "/providers/Microsoft.Authorization/policyDefinitions/"
            "83a86a26-fd1f-447c-b59d-e51f44264114"
        )
        export = {
            "schema_version": "1.0",
            "kind": "policy-export",
            "scope": SCOPE,
            "collected_at": AT,
            "assignments": [
                {
                    "id": assignment,
                    "properties": {
                        "scope": SCOPE,
                        "policyDefinitionId": definition,
                        "notScopes": [SUBNET],
                        "enforcementMode": "DoNotEnforce",
                        "parameters": {"secret": SENTINEL},
                    },
                }
            ],
            "states": [],
            "exemptions": [
                {
                    "id": SCOPE + "/providers/Microsoft.Authorization/policyExemptions/exception",
                    "properties": {
                        "policyAssignmentId": assignment,
                        "expiresOn": "2026-11-07T00:00:00Z",
                    },
                }
            ],
        }
        bundle = import_policy_export(self.bundle(), export)
        context = review_context(self.control(GUIDS[6]), bundle)["saved_nic_policy_context"]
        self.assertEqual(len(context["assignments"]), 1)
        self.assertEqual(len(context["exemptions"]), 1)
        self.assertEqual(context["assignments"][0]["not_scopes"], [SUBNET.lower()])
        self.assertNotIn(SENTINEL, json.dumps(context))
        self.assertNotIn("DoNotEnforce", json.dumps(context))
        report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        self.assertFalse(
            any(
                r["control_id"] == "ALZ-" + GUIDS[6]
                for r in report.get("policy_signals", {"records": []})["records"]
            )
        )
        absent = review_context(self.control(GUIDS[6]), self.bundle())["saved_nic_policy_context"]
        self.assertFalse(absent["assignments_available"])
        self.assertIsNone(absent["exemptions"])

    def test_all_outputs_replay_original_time_stale_and_blank_session(self):
        bundle = self.bundle()
        report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        self.assertEqual(
            report["evidence_tiers"]["counts"]["verified"], 1
        )  # Existing NSG predicate only.
        for format in ("json", "markdown", "html", "csv", "sarif", "pr-summary"):
            self.assertNotIn(SENTINEL, render(report, format))
        workbook = render_xlsx(report)
        with zipfile.ZipFile(BytesIO(workbook)) as archive:
            self.assertNotIn(
                SENTINEL, "".join(archive.read(n).decode() for n in archive.namelist())
            )
        export_bundle(self.root / "replay", bundle, self.catalog, at=AT, evidence_tiers=True)
        replay = replay_bundle(self.root / "replay")
        self.assertEqual(semantic(replay), semantic(report))
        self.assertEqual(replay["evidence"][0]["collected_at"], AT)
        self.assertNotIn(SENTINEL, json.dumps(replay))
        stale = copy.deepcopy(bundle)
        stale["collected_at"] = "2000-01-01T00:00:00Z"
        old = assess(stale, self.catalog, at=AT, evidence_tiers=True)
        self.assertEqual(old["evidence_tiers"]["counts"]["signal"], 0)
        for row in old["results"]:
            if row["control_id"] in {"ALZ-" + guid for guid in GUIDS}:
                self.assertEqual(row["observed"]["freshness"], "stale")
                self.assertNotEqual(row["observed"]["evidence_tier"], "verified")
        prepared = prepare_reviews(report, self.catalog, ["ALZ-" + guid for guid in GUIDS], SCOPE)
        self.assertTrue(all(e["outcome"] is None for e in prepared["entries"]))
        self.assertEqual(
            ReviewSession(bundle, self.catalog, self.root / "reviews").state()["records"], []
        )
        planned = copy.deepcopy(bundle)
        planned["mode"] = "planned"
        compared = compare(
            assess(planned, self.catalog, at=AT), assess(bundle, self.catalog, at=AT), at=AT
        )
        for row in compared["results"]:
            if row["control_id"] in {"ALZ-" + guid for guid in GUIDS}:
                self.assertEqual(row["comparison"], "not_comparable")

    def test_source_bound_ten_guid_interview_blank_then_explicit_atomic_decisions(self):
        report = assess(self.bundle(), self.catalog, at=AT, evidence_tiers=True)
        response = prepare_interview(report, self.catalog, "inbound-outbound-hybrid", SCOPE)
        self.assertEqual(len(response["decisions"]), 10)
        self.assertTrue(all(row["outcome"] is None for row in response["decisions"]))
        self.assertIsNone(response["answer"])
        with self.assertRaises(InputError):
            prepare_reviews(report, self.catalog, ["D05.08"], SCOPE)
        with self.assertRaises(InputError):
            compile_interview(response, self.catalog, at=AT)
        completed = copy.deepcopy(response)
        completed.update(
            answer="Authored acceptance fixture, not an owner decision.",
            reviewer="Fixture reviewer",
            rationale="Synthetic contract test.",
            evidence="fixture://redacted-decision",
            valid_from=AT,
            valid_until="2026-11-07T00:00:00Z",
        )
        for row in completed["decisions"]:
            row["outcome"] = "fail"
        record = compile_interview(completed, self.catalog, at=AT)
        self.assertEqual(len(record["entries"]), 10)
        for key, value in (
            ("scope", "/subscriptions/00000000-0000-0000-0000-000000000002"),
            ("bank_version", "old"),
            ("requirements_sha256", "0" * 64),
            ("valid_until", AT),
        ):
            altered = copy.deepcopy(completed)
            altered[key] = value
            with self.assertRaises(InputError):
                compile_interview(altered, self.catalog, at=AT)
        changed = copy.deepcopy(completed)
        changed["decisions"][1]["outcome"] = None
        with self.assertRaises(InputError):
            compile_interview(changed, self.catalog, at=AT)

    def tf_values(self):
        return {
            "azurerm_cdn_frontdoor_firewall_policy": {
                "name": "edge",
                "resource_group_name": "protection",
                "enabled": True,
                "mode": "Prevention",
                "sku_name": "Premium_AzureFrontDoor",
                "custom_rule": [],
                "managed_rule": [],
            },
            "azurerm_cdn_frontdoor_security_policy": {
                "name": "waf",
                "cdn_frontdoor_profile_id": PROFILE,
                "security_policies": [
                    {
                        "firewall": [
                            {
                                "cdn_frontdoor_firewall_policy_id": WAF,
                                "association": [
                                    {
                                        "domain": [{"cdn_frontdoor_domain_id": DOMAIN}],
                                        "patterns_to_match": ["/*"],
                                    }
                                ],
                            }
                        ]
                    }
                ],
            },
            "azurerm_application_gateway": {
                "name": "proxy",
                "resource_group_name": "protection",
                "gateway_ip_configuration": [{"name": "proxy", "subnet_id": SUBNET}],
                "firewall_policy_id": GW_WAF,
                "backend_address_pool": [{"fqdns": [SENTINEL], "ip_addresses": []}],
            },
            "azurerm_web_application_firewall_policy": {
                "name": "origin",
                "resource_group_name": "protection",
                "policy_settings": [{"mode": "Prevention", "enabled": True}],
                "custom_rules": [
                    {
                        "priority": 1,
                        "enabled": True,
                        "action": "Block",
                        "match_conditions": [
                            {
                                "match_variables": [
                                    {"variable_name": "RequestHeaders", "selector": "X-Azure-FDID"}
                                ],
                                "operator": "Equal",
                                "negation_condition": True,
                                "match_values": [SENTINEL],
                            }
                        ],
                    }
                ],
            },
            "azurerm_public_ip": {
                "name": "ip",
                "resource_group_name": "protection",
                "ddos_protection_mode": "Enabled",
            },
            "azurerm_network_interface": {
                "name": "nic",
                "resource_group_name": "protection",
                "ip_configuration": [
                    {
                        "subnet_id": SUBNET,
                        "public_ip_address_id": IP,
                        "private_ip_address": SENTINEL,
                    }
                ],
            },
            "azurerm_subnet": {
                "name": "proxy",
                "resource_group_name": "protection",
                "virtual_network_name": "workload",
                "address_prefixes": ["10.0.0.0/24"],
                "default_outbound_access_enabled": False,
            },
            "azurerm_virtual_network_gateway": {
                "name": "er",
                "resource_group_name": "protection",
                "type": "ExpressRoute",
                "sku": "ErGw3AZ",
                "enable_bgp": True,
                "active_active": False,
                "generation": "None",
                "ip_configuration": [{"subnet_id": SUBNET}],
            },
            "azurerm_virtual_network_gateway_connection": {
                "name": "primary",
                "resource_group_name": "protection",
                "type": "ExpressRoute",
                "routing_weight": 32000,
                "enable_bgp": True,
                "express_route_circuit_id": NETWORK + "expressRouteCircuits/circuit",
                "shared_key": SENTINEL,
            },
            "azurerm_monitor_diagnostic_setting": {
                "name": "ddos",
                "target_resource_id": IP,
                "enabled_log": [{"category": c} for c in DDOS_CATEGORIES],
            },
        }

    def test_supplied_module_raw_and_optional_plan_every_type_sensitive_scope_version(self):
        values = self.tf_values()
        module = self.root / "snapshots" / "protection"
        self.write(
            "snapshots/protection/main.tf.json",
            {"resource": {kind: {"test": body} for kind, body in values.items()}},
        )
        self.write(
            "source/main.tf.json",
            {
                "module": {
                    "protection": {
                        "source": "example.invalid/alz/protection/azurerm",
                        "version": "1.0.0",
                    }
                }
            },
        )
        manifest = self.write(
            "snapshots/snapshots.json",
            {
                "modules": [
                    {
                        "source": "example.invalid/alz/protection/azurerm",
                        "version": "1.0.0",
                        "subdirectory": "",
                        "path": "protection",
                        "sha256": tree_hash(module),
                    }
                ]
            },
        )
        plan = {
            "format_version": "1.2",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "mode": "managed",
                            "type": kind,
                            "address": kind + ".test",
                            "values": {**body, "id": tf_resource_id(SCOPE, kind, body)},
                        }
                        for kind, body in values.items()
                    ]
                }
            },
        }
        path = self.write("plan.json", plan)
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            raw = terraform_source(
                self.root / "source",
                scope=SCOPE,
                provider_version="4.50.0",
                snapshots=manifest,
                authorized_roots=[self.root],
            )
            planned = plan_source(path, scope=SCOPE, provider_version="4.50.0")
        for bundle in (raw, planned):
            self.assertNotIn(SENTINEL, json.dumps(bundle))
            by_type = {r["resource_type"]: r for r in bundle["resources"]}
            self.assertTrue(all(TF_TYPES[kind] in by_type for kind in values))
            self.assertEqual(
                by_type[TF_TYPES["azurerm_cdn_frontdoor_security_policy"]]["arm_id"],
                (PROFILE + "/securityPolicies/waf").lower(),
            )
            self.assertEqual(
                by_type[TF_TYPES["azurerm_application_gateway"]]["properties"][
                    "applicationBackendSummary"
                ],
                [{"suppliedAddressCount": 1}],
            )
        plan["planned_values"]["root_module"]["resources"][0]["sensitive_values"] = {"mode": True}
        path = self.write("sensitive.json", plan)
        hidden = plan_source(path, scope=SCOPE, provider_version="4.50.0")
        self.assertIn("unknown", hidden["resources"][0]["properties"]["wafMode"])
        unsupported = plan_source(path, scope=SCOPE, provider_version="4.49.0")
        self.assertTrue(all(r["state"] == "unknown" for r in unsupported["resources"]))
        for parent in (
            IP,
            "/subscriptions/00000000-0000-0000-0000-000000000002/providers/Microsoft.Cdn/profiles/edge",
        ):
            self.assertIsNone(
                tf_resource_id(
                    SCOPE,
                    "azurerm_cdn_frontdoor_security_policy",
                    {"name": "waf", "cdn_frontdoor_profile_id": parent},
                )
            )

    def test_arm_supported_versions_scope_and_no_defaults(self):
        resources = []
        for kind, identity, values, root in self.details():
            name = identity.split("/providers/")[1].split("/", 2)[2]
            scope = SCOPE
            if kind == "Microsoft.Insights/diagnosticSettings":
                name, scope = "ddos", IP
            resources.append(
                {
                    "type": kind,
                    "name": name,
                    "scope": scope,
                    "apiVersion": next(iter(API_VERSIONS[kind.lower()])),
                    "properties": values,
                    **({"sku": root["sku"]} if root and "sku" in root else {}),
                }
            )
        path = self.write("arm.json", {"resources": resources})
        bundle = arm_source(path, scope=SCOPE)
        self.assertNotIn(SENTINEL, json.dumps(bundle))
        self.assertTrue(all(r["state"] == "known" for r in bundle["resources"]))
        diag = next(
            r
            for r in bundle["resources"]
            if r["resource_type"] == "Microsoft.Insights/diagnosticSettings"
        )
        self.assertEqual(diag["properties"]["targetResourceId"], IP.lower())
        resources[0]["apiVersion"] = "2024-05-01"
        bundle = arm_source(self.write("wrong-api.json", {"resources": resources}), scope=SCOPE)
        self.assertEqual(bundle["resources"][0]["state"], "unknown")

    def test_injected_scoped_details_denied_partial_no_extra_operations(self):
        details = [
            {"type": kind, "id": identity, "properties": values, **(root or {})}
            for kind, identity, values, root in self.details()
        ]
        requests = []

        def transport(method, url):
            requests.append((method, url))
            self.assertTrue(
                method == "GET" or (method == "POST" and "/policyStates/latest/queryResults" in url)
            )
            self.assertTrue(url.startswith("https://management.azure.com/"))
            if "/resources?" in url:
                return Response(
                    200, {"value": [{"id": d["id"], "type": d["type"]} for d in details]}, {}
                )
            for detail in details:
                if url.split("?")[0].lower().endswith(detail["id"].lower()):
                    return Response(200, detail, {})
            return Response(200, {"value": []}, {})

        bundle = Collector(transport).collect(
            subscriptions=["00000000-0000-0000-0000-000000000001"], inventory_authorized=True
        )
        self.assertNotIn(SENTINEL, json.dumps(bundle))
        self.assertTrue(any("api-version=2024-02-01" in url for _, url in requests))
        self.assertTrue(any("api-version=2021-05-01-preview" in url for _, url in requests))

        def denied(method, url):
            if "/publicipaddresses/ip?" in url.lower():
                return Response(403, {}, {})
            return transport(method, url)

        partial = Collector(denied).collect(
            subscriptions=["00000000-0000-0000-0000-000000000001"], inventory_authorized=True
        )
        ip = next(
            r for r in partial["resources"] if r["resource_type"].endswith("/publicIPAddresses")
        )
        self.assertEqual(ip["state"], "inaccessible")
        self.assertFalse(partial["metadata"]["run_complete"])
        self.assertFalse(
            any(
                "graph.microsoft" in url
                or "management.azure.com/providers/microsoft.resourcegraph" in url.lower()
                for _, url in requests
            )
        )

    @unittest.skipUnless(os.environ.get("BICEP_COMPILER"), "Existing Bicep compiler unavailable")
    def test_real_bicep_protection_outbound_hybrid_no_restore(self):
        path = self.root / "main.bicep"
        path.write_text(
            f"""
resource policy 'Microsoft.Network/FrontDoorWebApplicationFirewallPolicies@2024-02-01' = {{
  name: 'edge'
  location: 'global'
  sku: {{ name: 'Premium_AzureFrontDoor' }}
  properties: {{
    policySettings: {{ enabledState: 'Enabled', mode: 'Prevention' }}
    customRules: {{ rules: [] }}
    managedRules: {{ managedRuleSets: [] }}
  }}
}}
resource security 'Microsoft.Cdn/profiles/securityPolicies@2024-02-01' = {{
  name: 'edge/waf'
  properties: {{
    parameters: {{
      type: 'WebApplicationFirewall'
      wafPolicy: {{ id: policy.id }}
      associations: [{{ domains: [{{ id: '{DOMAIN}' }}], patternsToMatch: ['/*'] }}]
    }}
  }}
}}
resource proxy 'Microsoft.Network/applicationGateways@2024-05-01' = {{
  name: 'proxy'
  location: 'westeurope'
  properties: {{
    gatewayIPConfigurations: [{{ name: 'proxy', properties: {{ subnet: {{ id: '{SUBNET}' }} }} }}]
    backendAddressPools: [{{ name: 'pool', properties: {{ backendAddresses: [] }} }}]
  }}
}}
resource origin 'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies@2024-05-01' = {{
  name: 'origin'
  location: 'westeurope'
  properties: {{
    policySettings: {{ state: 'Enabled', mode: 'Prevention' }}
    managedRules: {{ managedRuleSets: [] }}
    customRules: []
  }}
}}
resource ip 'Microsoft.Network/publicIPAddresses@2024-05-01' = {{
  name: 'ip'
  location: 'westeurope'
  properties: {{ ddosSettings: {{ protectionMode: 'Enabled' }} }}
}}
resource nic 'Microsoft.Network/networkInterfaces@2024-05-01' = {{
  name: 'nic'
  location: 'westeurope'
  properties: {{
    ipConfigurations: [{{ name: 'main', properties: {{
      subnet: {{ id: '{SUBNET}' }}
      publicIPAddress: {{ id: ip.id }}
    }} }}]
  }}
}}
resource subnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' = {{
  name: 'workload/proxy'
  properties: {{ addressPrefix: '10.0.0.0/24', defaultOutboundAccess: false }}
}}
resource diag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {{
  name: 'ddos'
  scope: ip
  properties: {{ logs: [{{ category: 'DDoSMitigationReports', enabled: true }}] }}
}}
resource gateway 'Microsoft.Network/virtualNetworkGateways@2024-05-01' = {{
  name: 'er'
  location: 'westeurope'
  properties: {{
    gatewayType: 'ExpressRoute'
    sku: {{ name: 'ErGw3Az', tier: 'ErGw3Az' }}
    enableBgp: true
    activeActive: false
    ipConfigurations: [{{ name: 'er', properties: {{ subnet: {{ id: '{SUBNET}' }} }} }}]
  }}
}}
resource connection 'Microsoft.Network/connections@2024-05-01' = {{
  name: 'primary'
  location: 'westeurope'
  properties: {{
    connectionType: 'ExpressRoute'
    routingWeight: 100
    virtualNetworkGateway1: {{ id: gateway.id }}
    peer: {{ id: '{NETWORK}expressRouteCircuits/circuit' }}
  }}
}}
""",
            encoding="utf-8",
        )
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            bundle = arm_source(
                path, scope=SCOPE, bicep=True, compiler=os.environ["BICEP_COMPILER"]
            )
        known = {r["resource_type"].lower(): r for r in bundle["resources"]}
        self.assertEqual(len(known), 10)
        self.assertTrue(all(r["state"] == "known" for r in known.values()))
        self.assertEqual(known["microsoft.network/connections"]["properties"]["routingWeight"], 100)
        self.assertEqual(
            known["microsoft.network/virtualnetworkgateways"]["properties"]["gatewaySku"], "ErGw3AZ"
        )
        self.assertEqual(
            known["microsoft.insights/diagnosticsettings"]["properties"]["targetResourceId"],
            IP.lower(),
        )
        self.assertIs(
            known["microsoft.network/virtualnetworks/subnets"]["properties"][
                "defaultOutboundAccess"
            ],
            False,
        )
