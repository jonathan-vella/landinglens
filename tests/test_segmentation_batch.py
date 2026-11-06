import copy
import hashlib
import importlib.util
import json
import os
import shutil
import tempfile
import unittest
from collections import Counter
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from alz_assessor.arm import arm_source, properties
from alz_assessor.azure import Collector, Response
from alz_assessor.catalog import load_catalog
from alz_assessor.comparison import comparable_fact, compare
from alz_assessor.contracts import control_digest, document, validate
from alz_assessor.engine import assess, local_subchecks
from alz_assessor.network_evidence import review_fact
from alz_assessor.plan import plan_source
from alz_assessor.replay import export_bundle, replay_bundle, sanitize_evidence, semantic
from alz_assessor.reports import render, render_xlsx
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import prepare_reviews, review_context
from alz_assessor.sources import terraform_source, tf_properties, tf_resource_id
from alz_assessor.terraform import InputError, tree_hash

SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/batch"
NETWORK = SCOPE + "/providers/Microsoft.Network/"
NSG = NETWORK + "networkSecurityGroups/nsg"
VNET = NETWORK + "virtualNetworks/vnet"
SUBNET = VNET + "/subnets/not-a-gateway-name"
GATEWAY = NETWORK + "virtualNetworkGateways/gateway"
FLOW = NETWORK + "networkWatchers/watcher/flowLogs/flow"
STORAGE = SCOPE + "/providers/Microsoft.Storage/storageAccounts/logs"
WORKSPACE = SCOPE + "/providers/Microsoft.OperationalInsights/workspaces/logs"
ASG = NETWORK + "applicationSecurityGroups/workload"
KEYS = ("D08.04", "D08.05", "D09.01", "D09.02", "D09.03", "D09.04", "D09.05", "D09.06", "D09.07")
SENTINEL = "PRIVATE-NOT-FOR-REPORTING"
AT = "2026-11-05T01:43:09Z"


class SegmentationBatchTests(unittest.TestCase):
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

    def rules(self, count):
        return [
            {
                "name": f"rule-{i}",
                "properties": {
                    "protocol": "Tcp",
                    "access": "Deny",
                    "direction": "Inbound",
                    "priority": 100 + i,
                    "sourceAddressPrefix": "VirtualNetwork",
                    "destinationAddressPrefix": "10.0.0.0/24",
                    "sourceApplicationSecurityGroups": [{"id": ASG}],
                    "destinationApplicationSecurityGroups": [],
                    "description": SENTINEL,
                    "sourcePortRange": SENTINEL,
                },
            }
            for i in range(count)
        ]

    def nsg(self, count):
        return {
            "provisioningState": "Succeeded",
            "securityRules": self.rules(count),
            "defaultSecurityRules": [
                {
                    "name": "AllowVnetInBound",
                    "properties": {
                        "priority": 65000,
                        "direction": "Inbound",
                        "access": "Allow",
                        "sourceAddressPrefix": "VirtualNetwork",
                    },
                }
            ],
        }

    def record(self, kind, identity, raw, *, observed=True):
        return {
            "logical_id": identity.lower(),
            "arm_id": identity.lower(),
            "resource_type": kind,
            "state": "known",
            "reason": "",
            "source_location": "fixture://explicit-detail",
            "properties": properties(kind, raw, observed=observed),
        }

    def bundle(self, count=901):
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
            resources=[
                self.record("Microsoft.Network/networkSecurityGroups", NSG, self.nsg(count))
            ],
        )

    def row(self, bundle):
        assessment = assess(bundle, self.catalog, at=AT)
        return next(r for r in assessment["results"] if r["upstream_id"] == "D09.07")

    def test_exact_history_membership_sources_and_one_narrow_predicate(self):
        data = files("alz_assessor").joinpath("data")
        previous = data.joinpath("catalog-2026-11-05.5.json").read_bytes()
        self.assertEqual(
            hashlib.sha256(previous).hexdigest(),
            "b2404cdc5c0c06aca70d3faf7d8e464c4bea49cbdbc80d5cc641fdd35f709153",
        )
        before = {c["upstream_guid"]: c for c in json.loads(previous)["controls"]}
        matrix = json.loads(data.joinpath("batch-matrix-2026-11-06.1.json").read_text("utf-8"))
        batch, manifest = matrix["batches"][-1], matrix["sources"][-1]
        self.assertEqual(batch["batch"], "19")
        self.assertEqual(batch["prerequisites"], ["18"])
        self.assertEqual({r["upstream_id"] for r in batch["recommendations"]}, set(KEYS))
        sources = {s["id"]: s for s in manifest["sources"]}
        self.assertEqual(len(sources), 24)
        self.assertIn("2026-01-01", sources["nsg-get-learn-fallback"]["resolved_url"])
        self.assertEqual(
            sources["nsg-rest-2024"]["revision"], "5531fa823aafa40895d51db03315fa749fcb9cf0"
        )
        changed = {r["guid"] for r in batch["recommendations"]}
        for item in batch["recommendations"]:
            for source in item["sources"]:
                self.assertEqual(len(sources[source]["sha256"]), 64)
        for control in self.catalog["controls"]:
            if control["upstream_guid"] not in changed:
                self.assertEqual(
                    control_digest(control), control_digest(before[control["upstream_guid"]])
                )
        self.assertEqual(len(self.catalog["controls"]), 255)
        self.assertEqual(
            Counter(c["automation"] for c in self.catalog["controls"]),
            {"automated": 8, "assisted": 204, "manual": 43},
        )
        self.assertEqual([key for key in KEYS if self.control(key).get("rule")], ["D09.07"])

    def test_offline_builder_replays_priority_boundary_and_preserves_receipts(self):
        repository = Path(__file__).parents[1]
        spec = importlib.util.spec_from_file_location(
            "build_batches", repository / "tools" / "build_batches.py"
        )
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        source_data = Path(str(files("alz_assessor").joinpath("data")))
        builder.DATA = self.root / "data"
        builder.REVIEWS = self.root / "reviews"
        shutil.copytree(source_data, builder.DATA)
        shutil.copytree(repository / "references" / "recommendation-batches", builder.REVIEWS)
        expected = {
            path: path.read_bytes()
            for directory in (builder.DATA, builder.REVIEWS)
            for path in directory.glob("*.json")
        }
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            builder.main()
            builder.main()
        for path, content in expected.items():
            self.assertEqual(path.read_bytes(), content, path.name)
        ledger_path = builder.REVIEWS / "ledger.json"
        ledger = json.loads(ledger_path.read_text())
        next(row for row in ledger["recommendations"] if row["batch"] == "18")["merge_commit"] = (
            "0" * 40
        )
        ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "differs from its cohort receipt"):
            builder.main()

    def test_exact_observed_custom_counts_defaults_excluded_and_subset_only(self):
        for count in (0, 900, 901, 1000, 2000):
            with self.subTest(count=count):
                bundle = self.bundle(count)
                self.assertEqual(bundle["resources"][0]["properties"]["securityRuleCount"], count)
                row = self.row(bundle)["observed"]
                self.assertEqual(row["outcome"], "pass" if count <= 900 else "fail")
                self.assertEqual(row["fact"], count)
                self.assertFalse(row["inventory_complete"])
        summary = self.bundle(901)["resources"][0]["properties"]["securityRuleSummary"]
        self.assertEqual(summary["suppliedCount"], 901)
        self.assertEqual(len(summary["rules"]), 20)
        self.assertIs(summary["truncated"], True)
        default = self.bundle(0)["resources"][0]["properties"]["defaultRuleSummary"]
        self.assertEqual(default["rules"][0]["priority"], 65000)
        self.assertIs(default["rules"][0]["sourceVirtualNetwork"], True)
        self.assertIsNone(comparable_fact({"fact": 2001}))
        self.assertIsNone(comparable_fact({"fact": 900}))

    def test_incomplete_malformed_duplicate_and_transient_populations_are_unknown(self):
        invalid = [None, {}, [None], self.rules(2001)]
        for rules in invalid:
            raw = self.nsg(1)
            raw["securityRules"] = rules
            self.assertIn(
                "unknown",
                properties("Microsoft.Network/networkSecurityGroups", raw, observed=True)[
                    "securityRuleCount"
                ],
            )
        for field, value in (
            ("priority", True),
            ("priority", 99),
            ("priority", 4097),
            ("priority", {}),
            ("direction", []),
            ("access", {}),
            ("protocol", {}),
            ("protocol", "tcp"),
            ("provisioningState", "Updating"),
        ):
            raw = self.nsg(1)
            raw["securityRules"][0]["properties"][field] = value
            self.assertIn(
                "unknown",
                properties("Microsoft.Network/networkSecurityGroups", raw, observed=True)[
                    "securityRuleCount"
                ],
            )
        for duplicate in ("name", "priority"):
            raw = self.nsg(2)
            if duplicate == "name":
                raw["securityRules"][1]["name"] = raw["securityRules"][0]["name"].upper()
            else:
                raw["securityRules"][1]["properties"]["priority"] = 100
            self.assertIn(
                "unknown",
                properties("Microsoft.Network/networkSecurityGroups", raw, observed=True)[
                    "securityRuleCount"
                ],
            )
        for state in (None, "Updating", "Failed", {"unknown": "missing"}):
            raw = self.nsg(0)
            raw["provisioningState"] = state
            self.assertIn(
                "unknown",
                properties("Microsoft.Network/networkSecurityGroups", raw, observed=True)[
                    "securityRuleCount"
                ],
            )
        for count in (True, "900", 900.0, -1, 2001, None, {}):
            bundle = self.bundle(0)
            bundle["resources"][0]["properties"]["securityRuleCount"] = count
            self.assertEqual(self.row(bundle)["observed"]["outcome"], "unknown")

    def test_planned_stale_denied_missing_and_contract_threshold_guards(self):
        for count in (0, 900, 901):
            self.assertIn(
                "unknown",
                properties("Microsoft.Network/networkSecurityGroups", self.nsg(count))[
                    "securityRuleCount"
                ],
            )
            bundle = self.bundle(count)
            bundle["mode"] = "planned"
            self.assertEqual(self.row(bundle)["planned"]["outcome"], "unknown")
        for state, outcome in (
            ("inaccessible", "unknown"),
            ("unknown", "unknown"),
            ("error", "error"),
        ):
            bundle = self.bundle(0)
            bundle["resources"][0].update(state=state, reason="resource_configuration_unavailable")
            self.assertEqual(self.row(bundle)["observed"]["outcome"], outcome)
        stale = self.bundle(0)
        stale["collected_at"] = "2000-01-01T00:00:00Z"
        self.assertEqual(self.row(stale)["observed"]["reason"], "stale_evidence")
        absent = self.bundle()
        absent["resources"] = []
        self.assertEqual(self.row(absent)["observed"]["outcome"], "unknown")
        absent["inventory_complete"] = True
        self.assertEqual(self.row(absent)["observed"]["outcome"], "not_applicable")
        for expected in (True, 899, 1000, 2000, "900"):
            changed = copy.deepcopy(self.catalog)
            next(c for c in changed["controls"] if c["upstream_id"] == "D09.07")["rule"][
                "expected"
            ] = expected
            with self.assertRaisesRegex(InputError, "observed NSG"):
                validate(changed, "catalog")

    def test_minimized_rule_summaries_and_asg_identity_validation(self):
        raw = self.nsg(1)
        props = properties("Microsoft.Network/networkSecurityGroups", raw, observed=True)
        summary = props["securityRuleSummary"]["rules"][0]
        self.assertEqual(summary["sourceAsgs"], [ASG.lower()])
        self.assertIs(summary["sourceVirtualNetwork"], True)
        self.assertIs(summary["destinationVirtualNetwork"], False)
        self.assertNotIn(SENTINEL, json.dumps(props))
        for value in (NSG, "alias", {"unknown": "missing"}):
            raw["securityRules"][0]["properties"]["sourceApplicationSecurityGroups"] = [
                {"id": value}
            ]
            summary = properties("Microsoft.Network/networkSecurityGroups", raw)[
                "securityRuleSummary"
            ]
            self.assertIn("unknown", summary["rules"][0]["sourceAsgs"][0])
        raw["securityRules"][0]["properties"]["sourceAddressPrefixes"] = []
        summary = properties("Microsoft.Network/networkSecurityGroups", raw)["securityRuleSummary"]
        self.assertIn("unknown", summary["rules"][0]["sourceVirtualNetwork"])
        retained = review_fact(
            {"securityRuleSummary": {"rules": [SENTINEL]}}, "securityRuleSummary"
        )
        self.assertIn("unknown", retained)

    def test_subnet_endpoint_counts_explicit_defaults_and_bounds(self):
        kind = "Microsoft.Network/virtualNetworks/subnets"
        for endpoints, expected in (([], 0), ([{"service": "Microsoft.Storage"}], 1)):
            props = properties(
                kind, {"serviceEndpoints": endpoints, "privateEndpointNetworkPolicies": "Enabled"}
            )
            self.assertEqual(props["serviceEndpointCount"], expected)
            self.assertEqual(props["privateEndpointNetworkPolicies"], "Enabled")
        for endpoints in (None, {}, [None], [{}] * 101, [{"service": {"unknown": "missing"}}]):
            self.assertIn(
                "unknown", properties(kind, {"serviceEndpoints": endpoints})["serviceEndpointCount"]
            )
        self.assertIn("unknown", properties(kind, {})["privateEndpointNetworkPolicies"])
        props = properties(
            kind,
            {
                "serviceEndpoints": [
                    {"service": "Microsoft.Storage", "networkIdentifier": {"id": VNET}}
                ]
            },
        )
        self.assertEqual(props["serviceEndpointNetworkIdentifiers"], [VNET.lower()])
        for value in ("Disabled", "Enabled", "NetworkSecurityGroupEnabled", "RouteTableEnabled"):
            props = tf_properties(
                "azurerm_subnet",
                {"service_endpoints": [], "private_endpoint_network_policies": value},
            )
            self.assertEqual(props["serviceEndpointCount"], 0)
            self.assertEqual(props["privateEndpointNetworkPolicies"], value)
            self.assertIn("unknown", props["serviceEndpointNetworkIdentifiers"])

    def test_egress_rule_kinds_counts_privacy_and_total_bounds(self):
        kind = "Microsoft.Network/firewallPolicies/ruleCollectionGroups"
        raw = {
            "ruleCollections": [
                {
                    "action": {"type": "Allow"},
                    "rules": [
                        {
                            "ruleType": "ApplicationRule",
                            "targetFqdns": [SENTINEL],
                            "description": SENTINEL,
                        },
                        {
                            "ruleType": "NetworkRule",
                            "destinationFqdns": [],
                            "destinationAddresses": ["10.0.0.1"],
                        },
                        {"ruleType": "NatRule", "destinationAddresses": [SENTINEL]},
                    ],
                }
            ]
        }
        facts = properties(kind, raw)["egressRules"]
        self.assertEqual(len(facts), 2)
        self.assertEqual(facts[0]["fqdnCount"], 1)
        self.assertEqual(facts[1]["ipv4AddressCount"], 1)
        self.assertNotIn(SENTINEL, json.dumps(facts))
        tf = tf_properties(
            "azurerm_firewall_policy_rule_collection_group",
            {
                "application_rule_collection": [
                    {"action": "Deny", "rule": [{"destination_fqdns": [SENTINEL]}]}
                ],
                "network_rule_collection": [
                    {
                        "action": "Allow",
                        "rule": [{"destination_addresses": ["10.0.0.1"], "destination_fqdns": []}],
                    }
                ],
            },
        )
        self.assertEqual(tf["egressRules"][0]["fqdnCount"], 1)
        self.assertEqual(tf["egressRules"][1]["ipv4AddressCount"], 1)
        for value in (False, {}, [None], [{}] * 21):
            tf = tf_properties(
                "azurerm_firewall_policy_rule_collection_group", {"network_rule_collection": value}
            )
            self.assertIn("unknown", tf["egressRules"])
        raw["ruleCollections"][0]["rules"] = [{"ruleType": "NetworkRule"}] * 101
        self.assertIn("unknown", properties(kind, raw)["egressRules"])

    def tf_values(self):
        return {
            "azurerm_network_security_group": {
                "name": "nsg",
                "resource_group_name": "batch",
                "security_rule": [],
            },
            "azurerm_network_security_rule": {
                "name": "rule",
                "resource_group_name": "batch",
                "network_security_group_name": "nsg",
                "priority": 100,
                "direction": "Inbound",
                "access": "Deny",
                "protocol": "Tcp",
                "source_address_prefix": "VirtualNetwork",
                "source_application_security_group_ids": [ASG],
            },
            "azurerm_subnet": {
                "name": "not-a-gateway-name",
                "virtual_network_name": "vnet",
                "resource_group_name": "batch",
                "service_endpoints": [],
                "address_prefixes": ["10.0.0.0/27"],
                "private_endpoint_network_policies": "RouteTableEnabled",
            },
            "azurerm_virtual_network_gateway": {
                "name": "gateway",
                "resource_group_name": "batch",
                "type": "ExpressRoute",
                "ip_configuration": [{"subnet_id": SUBNET}],
                "vpn_client_configuration": [{"root_certificate": SENTINEL}],
            },
            "azurerm_network_watcher_flow_log": {
                "name": "flow",
                "resource_group_name": "batch",
                "network_watcher_name": "watcher",
                "enabled": True,
                "target_resource_id": VNET,
                "storage_account_id": STORAGE,
                "traffic_analytics": [{"enabled": True, "workspace_resource_id": WORKSPACE}],
            },
        }

    def test_supplied_module_and_plan_all_new_types_no_fetch_or_complete_count(self):
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
                    "network": {"source": "example.invalid/alz/network/azurerm", "version": "1.0.0"}
                }
            },
        )
        snapshots = self.write(
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
                                "values": {**props, "id": tf_resource_id(SCOPE, kind, props)},
                            }
                            for kind, props in values.items()
                        ]
                    }
                },
            },
        )
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            raw = terraform_source(
                self.root / "source",
                snapshots=snapshots,
                authorized_roots=[self.root],
                scope=SCOPE,
                provider_version="4.50.0",
            )
            planned = plan_source(plan, scope=SCOPE, provider_version="4.50.0")
        for bundle in (raw, planned):
            by_type = {r["resource_type"].lower(): r for r in bundle["resources"]}
            nsg = by_type["microsoft.network/networksecuritygroups"]
            self.assertEqual(nsg["arm_id"], NSG.lower())
            self.assertIn("unknown", nsg["properties"]["securityRuleCount"])
            gateway = by_type["microsoft.network/virtualnetworkgateways"]
            self.assertEqual(gateway["arm_id"], GATEWAY.lower())
            self.assertEqual(gateway["properties"]["subnetReferences"], [SUBNET.lower()])
            self.assertEqual(gateway["properties"]["gatewayType"], "ExpressRoute")
            flow = by_type["microsoft.network/networkwatchers/flowlogs"]
            self.assertEqual(flow["arm_id"], FLOW.lower())
            self.assertIs(flow["properties"]["trafficAnalytics"]["enabled"], True)
            self.assertNotIn(SENTINEL, json.dumps(bundle))
            self.assertEqual(self.row(bundle)["planned"]["outcome"], "unknown")
        unsupported = plan_source(plan, scope=SCOPE, provider_version="4.49.0")
        self.assertTrue(all(r["state"] == "unknown" for r in unsupported["resources"]))
        for kind, parent in (
            ("azurerm_network_security_rule", "network_security_group_name"),
            ("azurerm_network_watcher_flow_log", "network_watcher_name"),
        ):
            for value in (None, {}, "bad/parent"):
                props = {**values[kind], parent: value}
                self.assertIsNone(tf_resource_id(SCOPE, kind, props))

    def test_plan_sensitive_values_remain_unknown(self):
        path = self.write(
            "sensitive.json",
            {
                "format_version": "1.2",
                "planned_values": {
                    "root_module": {
                        "resources": [
                            {
                                "mode": "managed",
                                "type": "azurerm_subnet",
                                "address": "azurerm_subnet.s",
                                "values": self.tf_values()["azurerm_subnet"],
                                "sensitive_values": {
                                    "service_endpoints": True,
                                    "address_prefixes": True,
                                },
                            }
                        ]
                    }
                },
            },
        )
        props = plan_source(path, scope=SCOPE, provider_version="4.50.0")["resources"][0][
            "properties"
        ]
        self.assertIn("unknown", props["serviceEndpointCount"])
        self.assertIn("unknown", props["addressPrefixes"])

    def test_gateway_capacity_links_and_unavailable_nsg_relationships(self):
        for prefix, expected in (
            ("10.0.0.0/26", True),
            ("10.0.0.0/27", True),
            ("10.0.0.0/28", False),
        ):
            bundle = self.bundle(0)
            bundle["resources"].extend(
                [
                    self.record(
                        "Microsoft.Network/virtualNetworkGateways",
                        GATEWAY,
                        {
                            "gatewayType": "ExpressRoute",
                            "ipConfigurations": [{"properties": {"subnet": {"id": SUBNET}}}],
                        },
                    ),
                    self.record(
                        "Microsoft.Network/virtualNetworks/subnets",
                        SUBNET,
                        {"addressPrefix": prefix, "networkSecurityGroup": {"id": NSG}},
                    ),
                ]
            )
            gateway = review_context(self.control("D09.01"), bundle)["resources"][0]
            self.assertIs(
                gateway["linked_subnets"][0]["subchecks"][
                    "supplied_ipv4_prefixes_have_minimum_27_capacity"
                ],
                expected,
            )
            subnet = review_context(self.control("D09.04"), bundle)["resources"][-1]
            self.assertEqual(subnet["linked_network_security_group"]["securityRuleCount"], 0)
            for state in ("unknown", "inaccessible", "error"):
                changed = copy.deepcopy(bundle)
                changed["resources"][0].update(
                    state=state, reason="resource_configuration_unavailable"
                )
                subnet = review_context(self.control("D09.04"), changed)["resources"][-1]
                self.assertIn("unknown", subnet["linked_network_security_group"])
            missing = copy.deepcopy(bundle)
            missing["resources"].pop(0)
            subnet = review_context(self.control("D09.04"), missing)["resources"][-1]
            self.assertIn("unknown", subnet["linked_network_security_group"])
        for value in (None, [], ["10.0.0.0/27", "2001:db8::/64"], [{"unknown": "missing"}]):
            self.assertIn(
                "unknown",
                local_subchecks({"addressPrefixes": value})[
                    "supplied_ipv4_prefixes_have_minimum_27_capacity"
                ],
            )

    def test_flow_config_is_not_ingestion_and_filters_are_withheld(self):
        raw = {
            "enabled": True,
            "targetResourceId": VNET,
            "storageId": STORAGE,
            "enabledFilteringCriteria": SENTINEL,
            "flowAnalyticsConfiguration": {
                "networkWatcherFlowAnalyticsConfiguration": {
                    "enabled": True,
                    "workspaceResourceId": WORKSPACE,
                }
            },
        }
        props = properties("Microsoft.Network/networkWatchers/flowLogs", raw)
        self.assertIs(props["filteringConfigured"], True)
        self.assertEqual(props["targetResourceId"], VNET.lower())
        self.assertNotIn(SENTINEL, json.dumps(props))
        for values in ({}, {"traffic_analytics": [{}] * 2}, {"enabled": "true"}):
            projected = tf_properties("azurerm_network_watcher_flow_log", values)
            self.assertIn("unknown", projected["enabled"])
            self.assertIn("unknown", projected["trafficAnalytics"]["enabled"])
        bundle = self.bundle()
        bundle["resources"].append(
            self.record("Microsoft.Network/networkWatchers/flowLogs", FLOW, raw)
        )
        row = next(
            r
            for r in assess(bundle, self.catalog, at=AT)["results"]
            if r["upstream_id"] == "D09.06"
        )
        self.assertEqual(row["observed"]["outcome"], "manual")

    def test_tiers_current_crosswalk_all_exports_and_original_time_replay(self):
        for count, outcome in ((900, "pass"), (901, "fail")):
            bundle = self.bundle(count)
            assessment = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
            row = next(r for r in assessment["results"] if r["upstream_id"] == "D09.07")
            self.assertEqual(row["observed"]["evidence_tier"], "verified")
            self.assertEqual(row["observed"]["outcome"], outcome)
            self.assertEqual(row["observed"]["fact"], count)
            self.assertEqual(assessment["evidence_tiers"]["counts"]["verified"], 1)
            for format in ("json", "markdown", "html", "csv", "sarif", "pr-summary"):
                output = render(assessment, format)
                self.assertNotIn(SENTINEL, output)
            self.assertTrue(render_xlsx(assessment).startswith(b"PK"))
            directory = self.root / f"tiers-{count}"
            export_bundle(directory, bundle, self.catalog, at=AT, evidence_tiers=True)
            self.assertEqual(semantic(replay_bundle(directory)), semantic(assessment))
            self.assertEqual(replay_bundle(directory)["evidence"][0]["collected_at"], AT)
            planned = copy.deepcopy(bundle)
            planned["mode"] = "planned"
            planned_report = assess(planned, self.catalog, at=AT, evidence_tiers=True)
            planned_row = next(r for r in planned_report["results"] if r["upstream_id"] == "D09.07")
            self.assertNotEqual(planned_row["planned"]["evidence_tier"], "verified")
            self.assertEqual(planned_row["planned"]["outcome"], "unknown")

    def test_nsg_link_requires_unique_known_exact_type_in_explicit_scope(self):
        bundle = self.bundle(0)
        bundle["resources"].append(
            self.record(
                "Microsoft.Network/virtualNetworks/subnets",
                SUBNET,
                {"networkSecurityGroup": {"id": NSG}},
            )
        )
        for case in ("duplicate", "wrong-type", "missing", "unknown"):
            altered = copy.deepcopy(bundle)
            if case == "duplicate":
                altered["resources"].insert(0, copy.deepcopy(altered["resources"][0]))
            elif case == "wrong-type":
                altered["resources"][0]["resource_type"] = "Microsoft.Network/virtualNetworks"
            elif case == "missing":
                altered["resources"].pop(0)
            else:
                altered["resources"][0].update(state="unknown", reason="unsupported_api_version")
            with self.subTest(case=case):
                if case in {"duplicate", "wrong-type"}:
                    with self.assertRaises(InputError):
                        review_context(self.control("D09.04"), altered)
                else:
                    subnet = review_context(self.control("D09.04"), altered)["resources"][-1]
                    self.assertIn("unknown", subnet["linked_network_security_group"])

    def test_injected_detail_reads_only_and_denied_counts_never_pass(self):
        requests = []
        nsg_detail = {
            "id": NSG,
            "type": "Microsoft.Network/networkSecurityGroups",
            "properties": self.nsg(900),
        }
        details = {
            NSG.lower(): nsg_detail,
            SUBNET.lower(): {
                "id": SUBNET,
                "type": "Microsoft.Network/virtualNetworks/subnets",
                "properties": {
                    "addressPrefix": "10.0.0.0/27",
                    "serviceEndpoints": [],
                    "networkSecurityGroup": {"id": NSG},
                },
            },
            GATEWAY.lower(): {
                "id": GATEWAY,
                "type": "Microsoft.Network/virtualNetworkGateways",
                "properties": {
                    "gatewayType": "ExpressRoute",
                    "ipConfigurations": [{"properties": {"subnet": {"id": SUBNET}}}],
                },
            },
            FLOW.lower(): {
                "id": FLOW,
                "type": "Microsoft.Network/networkWatchers/flowLogs",
                "properties": {
                    "enabled": True,
                    "targetResourceId": VNET,
                    "storageId": STORAGE,
                    "flowAnalyticsConfiguration": {
                        "networkWatcherFlowAnalyticsConfiguration": {
                            "enabled": True,
                            "workspaceResourceId": WORKSPACE,
                        }
                    },
                },
            },
            (NSG + "/securityRules/child").lower(): {
                "id": NSG + "/securityRules/child",
                "type": "Microsoft.Network/networkSecurityGroups/securityRules",
                "properties": self.rules(1)[0]["properties"],
            },
        }

        def transport(method, url):
            requests.append((method, url))
            self.assertIn(method, ("GET", "POST"))
            if method == "POST":
                self.assertIn("/policyStates/latest/queryResults?", url)
            if "/resources?" in url:
                return Response(
                    200,
                    {
                        "value": [
                            {"id": detail["id"], "type": detail["type"]}
                            for detail in details.values()
                        ]
                    },
                    {},
                )
            identity = url.removeprefix("https://management.azure.com").split("?")[0].lower()
            if identity in details:
                self.assertEqual(method, "GET")
                self.assertIn("api-version=2024-05-01", url)
                return Response(200, details[identity], {})
            return Response(200, {"value": []}, {})

        bundle = Collector(transport).collect(
            subscriptions=["00000000-0000-0000-0000-000000000001"], inventory_authorized=True
        )
        self.assertEqual(bundle["resources"][0]["properties"]["securityRuleCount"], 900)
        by_id = {r["arm_id"]: r for r in bundle["resources"]}
        self.assertEqual(len(by_id), 5)
        self.assertEqual(by_id[SUBNET.lower()]["properties"]["serviceEndpointCount"], 0)
        self.assertEqual(by_id[GATEWAY.lower()]["properties"]["subnetReferences"], [SUBNET.lower()])
        self.assertIs(by_id[FLOW.lower()]["properties"]["trafficAnalytics"]["enabled"], True)
        self.assertNotIn(SENTINEL, json.dumps(bundle))
        self.assertTrue(all(url.startswith("https://management.azure.com/") for _, url in requests))

        def denied(method, url):
            return (
                Response(403, {}, {})
                if "/networksecuritygroups/" in url.lower()
                else transport(method, url)
            )

        bundle = Collector(denied).collect(
            subscriptions=["00000000-0000-0000-0000-000000000001"], inventory_authorized=True
        )
        bundle.update(collected_at=AT, scope=SCOPE)
        self.assertEqual(bundle["resources"][0]["state"], "inaccessible")
        self.assertEqual(self.row(bundle)["observed"]["outcome"], "unknown")

    def test_replay_comparison_reports_reviews_and_no_decisions(self):
        bundle = self.bundle()
        assessment = assess(bundle, self.catalog, at=AT)
        records = prepare_reviews(assessment, self.catalog, list(KEYS), SCOPE)
        self.assertEqual(len(records["entries"]), 9)
        for entry in records["entries"]:
            for field in (
                "reviewer",
                "evidence",
                "rationale",
                "valid_from",
                "valid_until",
                "outcome",
            ):
                self.assertIsNone(entry[field])
        state = ReviewSession(bundle, self.catalog, self.root / "review").state()
        self.assertEqual(state["records"], [])
        for format in ("json", "markdown", "html"):
            output = render(assessment, format)
            self.assertNotIn(SENTINEL, output)
            self.assertIn("fixed-checklist-900-not-current-quota", output)
        self.assertEqual(
            sanitize_evidence(bundle)["resources"][0]["properties"]["securityRuleCount"], 901
        )
        export_bundle(self.root / "replay", bundle, self.catalog, at=AT)
        self.assertEqual(semantic(replay_bundle(self.root / "replay")), semantic(assessment))
        planned = copy.deepcopy(bundle)
        planned["mode"] = "planned"
        result = compare(assess(planned, self.catalog, at=AT), assessment, at=AT)
        row = next(r for r in result["results"] if r["upstream_id"] == "D09.07")
        self.assertEqual(row["comparison"], "not_comparable")
        self.assertEqual(row["observed"]["outcome"], "fail")

    @unittest.skipUnless(os.environ.get("BICEP_COMPILER"), "Existing Bicep compiler unavailable")
    def test_real_bicep_nsg_gateway_subnet_flow_without_restore(self):
        path = self.root / "main.bicep"
        path.write_text(
            f"""
resource nsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {{
  name: 'nsg'
  location: 'westeurope'
  properties: {{ securityRules: [] }}
}}
resource subnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' = {{
  name: 'vnet/not-a-gateway-name'
  properties: {{
    addressPrefix: '10.0.0.0/27'
    serviceEndpoints: []
    privateEndpointNetworkPolicies: 'Enabled'
    networkSecurityGroup: {{ id: '{NSG}' }}
  }}
}}
resource gateway 'Microsoft.Network/virtualNetworkGateways@2024-05-01' = {{
  name: 'gateway'
  location: 'westeurope'
  properties: {{
    gatewayType: 'ExpressRoute'
    ipConfigurations: [{{ name: 'gateway', properties: {{ subnet: {{ id: '{SUBNET}' }} }} }}]
  }}
}}
resource flow 'Microsoft.Network/networkWatchers/flowLogs@2024-05-01' = {{
  name: 'watcher/flow'
  location: 'westeurope'
  properties: {{
    enabled: true
    targetResourceId: '{VNET}'
    storageId: '{STORAGE}'
    flowAnalyticsConfiguration: {{ networkWatcherFlowAnalyticsConfiguration: {{
      enabled: true
      workspaceResourceId: '{WORKSPACE}'
    }} }}
  }}
}}
""",
            encoding="utf-8",
        )
        bundle = arm_source(path, scope=SCOPE, bicep=True, compiler=os.environ["BICEP_COMPILER"])
        by_type = {r["resource_type"].lower(): r for r in bundle["resources"]}
        self.assertIn(
            "unknown",
            by_type["microsoft.network/networksecuritygroups"]["properties"]["securityRuleCount"],
        )
        self.assertEqual(
            by_type["microsoft.network/virtualnetworks/subnets"]["properties"][
                "serviceEndpointCount"
            ],
            0,
        )
        self.assertEqual(
            by_type["microsoft.network/virtualnetworkgateways"]["properties"]["subnetReferences"],
            [SUBNET.lower()],
        )
        self.assertIs(
            by_type["microsoft.network/networkwatchers/flowlogs"]["properties"]["enabled"], True
        )
        self.assertEqual(self.row(bundle)["planned"]["outcome"], "unknown")
        template = self.write(
            "unsupported.json",
            {
                "resources": [
                    {
                        "type": "Microsoft.Network/networkSecurityGroups",
                        "name": "nsg",
                        "apiVersion": "1900-01-01",
                        "properties": self.nsg(0),
                    }
                ]
            },
        )
        self.assertEqual(arm_source(template, scope=SCOPE)["resources"][0]["state"], "unknown")
