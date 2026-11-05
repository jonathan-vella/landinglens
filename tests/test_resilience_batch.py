import copy
import hashlib
import json
import os
import tempfile
import unittest
from collections import Counter
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from alz_assessor.arm import arm_source
from alz_assessor.azure import Collector, Response
from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import control_digest
from alz_assessor.engine import assess
from alz_assessor.network_evidence import projected_properties, review_fact
from alz_assessor.plan import plan_source
from alz_assessor.replay import export_bundle, replay_bundle, sanitize_evidence, semantic
from alz_assessor.reports import render
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import prepare_reviews, review_context
from alz_assessor.sources import terraform_source, tf_properties, tf_resource_id
from alz_assessor.terraform import InputError, tree_hash

SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/batch"
NETWORK = SCOPE + "/providers/Microsoft.Network/"
VNET = NETWORK + "virtualNetworks/vnet"
SUBNET = VNET + "/subnets/services"
POLICY = NETWORK + "firewallPolicies/policy"
TARGET = SCOPE + "/providers/Microsoft.KeyVault/vaults/shared"
PLAN = NETWORK + "ddosProtectionPlans/plan"
KEYS = ("D07.15", "D07.16", "D07.17", "D07.20", "D07.21", "D07.22", "D07.23", "D08.02", "D08.03")
SENTINEL = "PRIVATE-NOT-FOR-REPORTING"


class ResilienceBatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.catalog = load_catalog()

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def control(self, key):
        return next(c for c in self.catalog["controls"] if c["upstream_id"] == key)

    def template(self):
        return {
            "resources": [
                {
                    "type": "Microsoft.Network/azureFirewalls",
                    "name": "firewall",
                    "apiVersion": "2024-05-01",
                    "zones": ["1"],
                    "properties": {
                        "zones": ["2", "3"],
                        "sku": {"tier": "Premium", "name": "AZFW_VNet"},
                        "firewallPolicy": {"id": POLICY},
                        "ipConfigurations": [{"properties": {"subnet": {"id": SUBNET}}}],
                    },
                },
                {
                    "type": "Microsoft.Network/virtualNetworks",
                    "name": "vnet",
                    "apiVersion": "2024-05-01",
                    "properties": {
                        "enableDdosProtection": True,
                        "ddosProtectionPlan": {"id": PLAN},
                    },
                },
                {
                    "type": "Microsoft.Network/virtualNetworks/subnets",
                    "name": "vnet/services",
                    "apiVersion": "2024-05-01",
                    "properties": {
                        "addressPrefix": "10.0.0.0/26",
                        "networkSecurityGroup": {"id": NETWORK + "networkSecurityGroups/nsg"},
                        "routeTable": {"id": NETWORK + "routeTables/routes"},
                    },
                },
                {
                    "type": "Microsoft.Network/firewallPolicies/ruleCollectionGroups",
                    "name": "policy/rules",
                    "apiVersion": "2024-05-01",
                    "properties": {
                        "ruleCollections": [
                            {
                                "action": {"type": "Allow"},
                                "rules": [
                                    {
                                        "ruleType": "ApplicationRule",
                                        "terminateTLS": True,
                                        "webCategories": [SENTINEL, "Finance"],
                                        "description": SENTINEL,
                                        "httpHeadersToInsert": [{"value": SENTINEL}],
                                        "targetFqdns": [SENTINEL],
                                    },
                                    {"ruleType": "NetworkRule", "description": SENTINEL},
                                ],
                            }
                        ]
                    },
                },
                {
                    "type": "Microsoft.Network/privateEndpoints",
                    "name": "endpoint",
                    "apiVersion": "2024-05-01",
                    "properties": {
                        "subnet": {"id": SUBNET},
                        "privateLinkServiceConnections": [
                            {
                                "properties": {
                                    "privateLinkServiceId": TARGET,
                                    "groupIds": [SENTINEL],
                                    "privateLinkServiceConnectionState": {
                                        "status": "Approved",
                                        "description": SENTINEL,
                                        "actionsRequired": SENTINEL,
                                    },
                                }
                            }
                        ],
                        "customDnsConfigs": [{"fqdn": SENTINEL, "ipAddresses": [SENTINEL]}],
                    },
                },
            ]
        }

    def bundle(self, template=None):
        return arm_source(self.write("arm.json", template or self.template()), scope=SCOPE)

    def test_exact_history_membership_sources_and_unchanged_predicates(self):
        data = files("alz_assessor").joinpath("data")
        previous = data.joinpath("catalog-2026-11-05.2.json").read_bytes()
        self.assertEqual(
            hashlib.sha256(previous).hexdigest(),
            "5c5b337f12de60dafde72d98909e703c81dc5451d98a10f3624fdfec5d62f6a1",
        )
        before = {c["upstream_guid"]: c for c in json.loads(previous)["controls"]}
        matrix = json.loads(data.joinpath("batch-matrix-2026-11-05.3.json").read_text("utf-8"))
        batch = matrix["batches"][-1]
        self.assertEqual(batch["batch"], "18")
        self.assertEqual(batch["prerequisites"], ["17"])
        self.assertEqual(len(batch["recommendations"]), 9)
        changed = {r["guid"] for r in batch["recommendations"]}
        self.assertEqual({r["upstream_id"] for r in batch["recommendations"]}, set(KEYS))
        sources = {s["id"]: s for s in matrix["sources"][-1]["sources"]}
        self.assertEqual(len(sources), 18)
        for item in batch["recommendations"]:
            self.assertEqual(item["classification"], "assisted")
            for source in item["sources"]:
                self.assertEqual(len(sources[source]["sha256"]), 64)
                self.assertTrue(sources[source]["revision"])
        for control in self.catalog["controls"]:
            if control["upstream_guid"] not in changed:
                self.assertEqual(
                    control_digest(control), control_digest(before[control["upstream_guid"]])
                )
        self.assertEqual(len(self.catalog["controls"]), 255)
        self.assertEqual(
            Counter(c["automation"] for c in self.catalog["controls"]),
            {"automated": 7, "assisted": 205, "manual": 43},
        )

    def test_arm_typed_projection_and_privacy(self):
        bundle = self.bundle()
        resources = {r["resource_type"].lower(): r for r in bundle["resources"]}
        self.assertNotIn(SENTINEL, json.dumps(bundle))
        self.assertEqual(
            resources["microsoft.network/azurefirewalls"]["properties"]["configuredZones"], ["1"]
        )
        self.assertEqual(
            resources["microsoft.network/firewallpolicies/rulecollectiongroups"]["properties"][
                "applicationRules"
            ],
            [{"action": "Allow", "terminateTLS": True, "webCategoryCount": 2}],
        )
        vnet = resources["microsoft.network/virtualnetworks"]["properties"]
        self.assertIs(vnet["enableDdosProtection"], True)
        self.assertEqual(vnet["ddosProtectionPlan"]["id"], PLAN.lower())
        endpoint = resources["microsoft.network/privateendpoints"]["properties"]
        self.assertEqual(
            endpoint["privateConnections"],
            [{"resourceId": TARGET.lower(), "status": "Approved"}],
        )
        self.assertEqual(endpoint["subnet"]["id"], SUBNET.lower())

    def test_configured_zones_never_backend_redundancy(self):
        for zones in ([], ["1"], ["1", "2"], ["1", "2", "3"]):
            template = self.template()
            template["resources"][0]["zones"] = zones
            bundle = self.bundle(template)
            self.assertEqual(bundle["resources"][0]["properties"]["configuredZones"], zones)
            result = next(
                r for r in assess(bundle, self.catalog)["results"] if r["upstream_id"] == "D07.21"
            )
            self.assertEqual(result["planned"]["outcome"], "manual")
        for zones in (None, True, 1, "1", [1], ["4"], ["1", "1"], ["1"] * 4, [{}]):
            self.assertIn("unknown", review_fact({"configuredZones": zones}, "configuredZones"))
        template = self.template()
        del template["resources"][0]["zones"]
        self.assertIn(
            "unknown", self.bundle(template)["resources"][0]["properties"]["configuredZones"]
        )
        self.assertIn("backend migration", self.control("D07.21")["rationale"])

    def test_application_rule_bounds_actions_types_and_counts(self):
        kind = "azurerm_firewall_policy_rule_collection_group"

        def facts(rule, action="Deny"):
            return tf_properties(
                kind, {"application_rule_collection": [{"action": action, "rule": [rule]}]}
            )["applicationRules"]

        for tls in (True, False):
            self.assertIs(
                facts({"terminate_tls": tls, "web_categories": []})[0]["terminateTLS"], tls
            )
        for invalid in (None, "true", 1, [], {"unknown": "sensitive"}):
            fact = facts({"terminate_tls": invalid, "web_categories": [SENTINEL]})[0]
            self.assertIn("unknown", fact["terminateTLS"])
            self.assertEqual(fact["webCategoryCount"], 1)
        for invalid in (None, "", True, [1], [{}], [""], [SENTINEL] * 101, ["x" * 129]):
            self.assertIn("unknown", facts({"web_categories": invalid})[0]["webCategoryCount"])
        self.assertIn("unknown", facts({}, action="Permit")[0]["action"])
        self.assertNotIn(SENTINEL, json.dumps(facts({"web_categories": [SENTINEL]})))
        for invalid in (None, [None], [{}], [{"rule": None}], [{}] * 21):
            self.assertIn(
                "unknown",
                tf_properties(kind, {"application_rule_collection": invalid})["applicationRules"],
            )
        for count, known in ((100, True), (101, False)):
            fact = review_fact(
                {"applicationRules": [{"webCategoryCount": count}]}, "applicationRules"
            )[0]
            self.assertEqual(type(fact["webCategoryCount"]) is int, known)
        self.assertIn("unknown", review_fact({"applicationRules": [{}] * 101}, "applicationRules"))
        for rule_type in (None, {}, {"unknown": "symbolic"}, True):
            props = projected_properties(
                "Microsoft.Network/firewallPolicies/ruleCollectionGroups",
                {"ruleCollections": [{"rules": [{"ruleType": rule_type}]}]},
            )
            self.assertIn("unknown", props["applicationRules"][0])
        collections = [{"action": "Allow", "rule": [{}] * 100}] * 2
        self.assertIn(
            "unknown",
            tf_properties(kind, {"application_rule_collection": collections})["applicationRules"],
        )

    def test_private_approval_is_explicit_not_intent_ip_or_alias(self):
        for manual in (True, False, None):
            props = tf_properties(
                "azurerm_private_endpoint",
                {
                    "subnet_id": SUBNET,
                    "private_service_connection": [
                        {
                            "private_connection_resource_id": TARGET,
                            "is_manual_connection": manual,
                            "private_ip_address": "10.0.0.5",
                        }
                    ],
                },
            )
            self.assertEqual(props["privateConnections"][0]["resourceId"], TARGET.lower())
            self.assertIn("unknown", props["privateConnections"][0]["status"])
        props = tf_properties(
            "azurerm_private_endpoint",
            {
                "private_service_connection": [
                    {
                        "private_connection_resource_id": TARGET,
                        "private_connection_resource_alias": SENTINEL,
                    }
                ],
            },
        )
        self.assertIn("unknown", props["privateConnections"][0]["resourceId"])
        self.assertNotIn(SENTINEL, json.dumps(props))
        for status in ("Approved", "Pending", "Rejected", "Disconnected"):
            fact = review_fact(
                {"privateConnections": [{"resourceId": TARGET, "status": status}]},
                "privateConnections",
            )
            self.assertEqual(fact[0]["status"], status)
        for status in (None, True, "approved", {}, ["Approved"]):
            fact = review_fact(
                {"privateConnections": [{"resourceId": "alias", "status": status}]},
                "privateConnections",
            )
            self.assertIn("unknown", fact[0]["status"])
            self.assertIn("unknown", fact[0]["resourceId"])
        for entries in (None, [None], [{"properties": None}], [{}] * 21):
            props = projected_properties(
                "Microsoft.Network/privateEndpoints",
                {"manualPrivateLinkServiceConnections": entries},
            )
            self.assertIn("unknown", props["privateConnections"])
        both = {
            key: [{"properties": {"privateLinkServiceId": TARGET}}] * 11
            for key in ("privateLinkServiceConnections", "manualPrivateLinkServiceConnections")
        }
        self.assertIn(
            "unknown",
            projected_properties("Microsoft.Network/privateEndpoints", both)["privateConnections"],
        )
        self.assertEqual(
            projected_properties(
                "Microsoft.Network/privateEndpoints", {"privateLinkServiceConnections": []}
            )["privateConnections"],
            [],
        )

    def tf_values(self):
        return {
            "azurerm_firewall": {
                "name": "firewall",
                "resource_group_name": "batch",
                "sku_tier": "Premium",
                "zones": ["1"],
            },
            "azurerm_virtual_network": {
                "name": "vnet",
                "resource_group_name": "batch",
                "ddos_protection_plan": [{"id": PLAN, "enable": True}],
            },
            "azurerm_private_endpoint": {
                "name": "endpoint",
                "resource_group_name": "batch",
                "subnet_id": SUBNET,
                "private_service_connection": [
                    {"private_connection_resource_id": TARGET, "is_manual_connection": False}
                ],
            },
            "azurerm_firewall_policy_rule_collection_group": {
                "name": "rules",
                "firewall_policy_id": POLICY,
                "application_rule_collection": [
                    {
                        "action": "Allow",
                        "rule": [{"terminate_tls": True, "web_categories": ["Finance"]}],
                    }
                ],
            },
        }

    def test_raw_supplied_module_and_plan_all_new_facts(self):
        values = self.tf_values()
        module = self.root / "modules" / "network"
        self.write(
            "modules/network/main.tf.json",
            {"resource": {kind: {"test": props} for kind, props in values.items()}},
        )
        self.write(
            "source/main.tf.json",
            {
                "module": {
                    "network": {
                        "source": "example.invalid/alz/network/azurerm",
                        "version": "1.0.0",
                    }
                }
            },
        )
        manifest = self.write(
            "modules/snapshots.json",
            {
                "modules": [
                    {
                        "source": "example.invalid/alz/network/azurerm",
                        "version": "1.0.0",
                        "subdirectory": "",
                        "path": "network",
                        "sha256": tree_hash(module),
                    }
                ]
            },
        )
        plan_values = copy.deepcopy(values)
        plan_values["azurerm_firewall_policy_rule_collection_group"]["id"] = (
            POLICY + "/ruleCollectionGroups/rules"
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
                                "type": kind,
                                "address": kind + ".test",
                                "values": props,
                            }
                            for kind, props in plan_values.items()
                        ]
                    }
                },
            },
        )
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            raw = terraform_source(
                self.root / "source",
                snapshots=manifest,
                authorized_roots=[self.root],
                scope=SCOPE,
                provider_version="4.50.0",
            )
            planned = plan_source(plan, scope=SCOPE, provider_version="4.50.0")
        for bundle in (raw, planned):
            by_type = {r["resource_type"].lower(): r for r in bundle["resources"]}
            self.assertEqual(
                by_type["microsoft.network/azurefirewalls"]["properties"]["configuredZones"], ["1"]
            )
            self.assertIs(
                by_type["microsoft.network/virtualnetworks"]["properties"]["enableDdosProtection"],
                True,
            )
            self.assertIn(
                "unknown",
                by_type["microsoft.network/privateendpoints"]["properties"]["privateConnections"][
                    0
                ]["status"],
            )
            group = by_type["microsoft.network/firewallpolicies/rulecollectiongroups"]
            self.assertEqual(group["arm_id"], (POLICY + "/ruleCollectionGroups/rules").lower())
            self.assertEqual(group["properties"]["applicationRules"][0]["webCategoryCount"], 1)
        unsupported = plan_source(plan, scope=SCOPE, provider_version="4.49.0")
        self.assertTrue(all(r["state"] == "unknown" for r in unsupported["resources"]))
        for parent in (
            VNET,
            "alias",
            POLICY.replace("batch", "elsewhere"),
            {"unknown": "symbolic"},
        ):
            self.assertIsNone(
                tf_resource_id(
                    SCOPE,
                    "azurerm_firewall_policy_rule_collection_group",
                    {"name": "rules", "firewall_policy_id": parent},
                )
            )

    def test_positive_subnet_vnet_links_and_unavailable_joins(self):
        bundle = self.bundle()
        context = review_context(self.control("D07.22"), bundle)
        fw = next(r for r in context["resources"] if r["resource_type"].endswith("azureFirewalls"))
        link = fw["linked_subnets"][0]
        self.assertEqual(link["virtualNetwork"]["arm_id"], VNET.lower())
        self.assertIs(link["virtualNetwork"]["enableDdosProtection"], True)
        self.assertEqual(
            link["networkSecurityGroup.id"], (NETWORK + "networkSecurityGroups/nsg").lower()
        )
        private = review_context(self.control("D08.02"), bundle)
        endpoint = next(
            r for r in private["resources"] if r["resource_type"].endswith("privateEndpoints")
        )
        self.assertEqual(endpoint["linked_subnets"][0]["arm_id"], SUBNET.lower())
        for state in ("unknown", "inaccessible", "error"):
            changed = copy.deepcopy(bundle)
            changed["resources"][1].update(state=state, reason="fixture_" + state)
            fw = review_context(self.control("D07.22"), changed)["resources"][0]
            self.assertIn("unknown", fw["linked_subnets"][0]["virtualNetwork"])
        missing = copy.deepcopy(bundle)
        missing["resources"].pop(1)
        self.assertIn(
            "unknown",
            review_context(self.control("D07.22"), missing)["resources"][0]["linked_subnets"][0][
                "virtualNetwork"
            ],
        )
        duplicate = copy.deepcopy(bundle)
        child = copy.deepcopy(bundle["resources"][1])
        child["logical_id"] = "duplicate"
        duplicate["resources"].append(child)
        with self.assertRaisesRegex(InputError, "ambiguous ARM resource"):
            review_context(self.control("D07.22"), duplicate)
        wrong = copy.deepcopy(bundle)
        wrong["resources"][1]["resource_type"] = "Microsoft.Network/ipGroups"
        with self.assertRaisesRegex(InputError, "type does not match"):
            review_context(self.control("D07.22"), wrong)
        for value in (None, [], [{}], [{"enable": "true", "id": "alias"}], [{}] * 2):
            props = tf_properties("azurerm_virtual_network", {"ddos_protection_plan": value})
            self.assertIn("unknown", props["enableDdosProtection"])
            self.assertIn("unknown", props["ddosProtectionPlan"]["id"])

    def test_injected_management_detail_reads_denial_and_original_zones(self):
        template = self.template()
        resources = self.bundle()["resources"]
        details = {
            r["arm_id"]: {**entry, "id": r["arm_id"]}
            for entry, r in zip(template["resources"], resources, strict=True)
        }
        requests = []

        def transport(method, url):
            requests.append((method, url))
            if "/resources?" in url:
                return Response(
                    200,
                    {"value": [{"id": r["arm_id"], "type": r["resource_type"]} for r in resources]},
                    {},
                )
            identity = url.removeprefix("https://management.azure.com").split("?")[0].lower()
            if identity in details:
                self.assertIn("api-version=2024-05-01", url)
                self.assertEqual(method, "GET")
                return Response(200, details[identity], {})
            return Response(200, {"value": []}, {})

        bundle = Collector(transport).collect(
            subscriptions=["00000000-0000-0000-0000-000000000001"], inventory_authorized=True
        )
        self.assertNotIn(SENTINEL, json.dumps(bundle))
        self.assertEqual(bundle["resources"][0]["properties"]["configuredZones"], ["1"])
        endpoint = next(
            r for r in bundle["resources"] if r["resource_type"].endswith("privateEndpoints")
        )
        self.assertEqual(endpoint["properties"]["privateConnections"][0]["status"], "Approved")

        def denied(method, url):
            if "/privateendpoints/" in url.lower():
                return Response(403, {}, {})
            return transport(method, url)

        partial = Collector(denied).collect(
            subscriptions=["00000000-0000-0000-0000-000000000001"], inventory_authorized=True
        )
        endpoint = next(
            r for r in partial["resources"] if r["resource_type"].endswith("privateEndpoints")
        )
        self.assertEqual(endpoint["state"], "inaccessible")
        self.assertTrue(all(url.startswith("https://management.azure.com/") for _, url in requests))

    def test_unsupported_arm_versions_and_unresolved_expressions(self):
        template = self.template()
        for entry in template["resources"]:
            entry["apiVersion"] = "1900-01-01"
        self.assertTrue(all(r["state"] == "unknown" for r in self.bundle(template)["resources"]))
        template = self.template()
        template["resources"][0]["zones"] = "[parameters('zones')]"
        bundle = self.bundle(template)
        self.assertIn("unknown", bundle["resources"][0]["properties"]["configuredZones"])
        for key in KEYS:
            row = next(
                r for r in assess(bundle, self.catalog)["results"] if r["upstream_id"] == key
            )
            self.assertEqual(row["planned"]["outcome"], "manual")

    def test_reviews_reports_replay_and_no_fabricated_decisions(self):
        bundle = self.bundle()
        bundle.update(mode="observed", source="saved", inventory_complete=False)
        assessment = assess(bundle, self.catalog)
        records = prepare_reviews(
            assessment, self.catalog, [self.control(key)["control_id"] for key in KEYS], SCOPE
        )
        self.assertEqual(len(records["entries"]), 9)
        for record in records["entries"]:
            for field in (
                "reviewer",
                "evidence",
                "rationale",
                "valid_from",
                "valid_until",
                "outcome",
            ):
                self.assertIsNone(record[field])
            self.assertIn("Reviewer decision", str(record["preparation"]["evidence_requirements"]))
        state = ReviewSession(bundle, self.catalog, self.root / "review").state()
        self.assertEqual(state["records"], [])
        for format in ("json", "markdown", "html"):
            for minimize in (True, False):
                output = render(assessment, format, minimize=minimize)
                self.assertIn("configured-zones-not-backend-redundancy", output)
                self.assertIn("assessment-is-not-firewall-backup", output)
                self.assertNotIn(SENTINEL, output)
        sanitized = sanitize_evidence(bundle)
        self.assertNotIn(SENTINEL, json.dumps(sanitized))
        for original, retained in zip(bundle["resources"], sanitized["resources"], strict=True):
            for path in self.control("D07.22")["review_fact_paths"] + [
                "privateConnections",
                "applicationRules",
                "configuredZones",
            ]:
                before = review_fact(original["properties"], path)
                if not isinstance(before, dict) or "unknown" not in before:
                    self.assertEqual(review_fact(retained["properties"], path), before)
        export_bundle(self.root / "replay", bundle, self.catalog, at=bundle["collected_at"])
        self.assertEqual(semantic(replay_bundle(self.root / "replay")), semantic(assessment))
        stale = copy.deepcopy(bundle)
        stale["collected_at"] = "2000-01-01T00:00:00Z"
        for row in assess(stale, self.catalog)["results"]:
            if row["upstream_id"] in KEYS:
                self.assertNotIn(row["observed"]["outcome"], {"pass", "fail"})

    @unittest.skipUnless(os.environ.get("BICEP_COMPILER"), "Existing Bicep compiler unavailable")
    def test_real_existing_bicep_all_new_fact_types_without_restore(self):
        source = self.root / "main.bicep"
        source.write_text(
            f"""
resource fw 'Microsoft.Network/azureFirewalls@2024-05-01' = {{
  name: 'firewall'
  location: 'westeurope'
  zones: ['1']
  properties: {{ sku: {{ name: 'AZFW_VNet', tier: 'Premium' }} }}
}}
resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {{
  name: 'vnet'
  location: 'westeurope'
  properties: {{
    addressSpace: {{ addressPrefixes: ['10.0.0.0/16'] }}
    enableDdosProtection: true
    ddosProtectionPlan: {{ id: '{PLAN}' }}
  }}
}}
resource group 'Microsoft.Network/firewallPolicies/ruleCollectionGroups@2024-05-01' = {{
  name: 'policy/rules'
  properties: {{
    priority: 100
    ruleCollections: [{{
      name: 'applications'
      ruleCollectionType: 'FirewallPolicyFilterRuleCollection'
      priority: 100
      action: {{ type: 'Allow' }}
      rules: [{{
        name: 'https'
        ruleType: 'ApplicationRule'
        sourceAddresses: ['10.0.0.0/24']
        protocols: [{{ protocolType: 'Https', port: 443 }}]
        terminateTLS: true
        webCategories: ['Finance']
      }}]
    }}]
  }}
}}
resource endpoint 'Microsoft.Network/privateEndpoints@2024-05-01' = {{
  name: 'endpoint'
  location: 'westeurope'
  properties: {{
    subnet: {{ id: '{SUBNET}' }}
    privateLinkServiceConnections: [{{
      name: 'service'
      properties: {{ privateLinkServiceId: '{TARGET}', groupIds: ['vault'] }}
    }}]
  }}
}}
""",
            encoding="utf-8",
        )
        bundle = arm_source(source, scope=SCOPE, bicep=True, compiler=os.environ["BICEP_COMPILER"])
        by_type = {r["resource_type"].lower(): r for r in bundle["resources"]}
        self.assertEqual(
            by_type["microsoft.network/azurefirewalls"]["properties"]["configuredZones"], ["1"]
        )
        self.assertIs(
            by_type["microsoft.network/virtualnetworks"]["properties"]["enableDdosProtection"], True
        )
        self.assertEqual(
            by_type["microsoft.network/firewallpolicies/rulecollectiongroups"]["properties"][
                "applicationRules"
            ][0]["webCategoryCount"],
            1,
        )
        self.assertIn(
            "unknown",
            by_type["microsoft.network/privateendpoints"]["properties"]["privateConnections"][0][
                "status"
            ],
        )
