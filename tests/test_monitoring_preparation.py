import copy
import hashlib
import json
import os
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from alz_assessor.arm import API_VERSIONS, arm_source, properties
from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import control_digest, document, validate
from alz_assessor.engine import assess
from alz_assessor.monitoring_evidence import alert_facts, monitor_facts
from alz_assessor.network_evidence import review_fact
from alz_assessor.plan import plan_source
from alz_assessor.replay import export_bundle, known_catalog, replay_bundle, semantic
from alz_assessor.reviews import prepare_reviews, review_context
from alz_assessor.routing_evidence import gateway_route_subchecks
from alz_assessor.sources import terraform_source, tf_properties, tf_resource_id
from alz_assessor.terraform import InputError

SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/monitoring"
NETWORK = SCOPE + "/providers/Microsoft.Network/"
TABLE = NETWORK + "routeTables/propagation"
SUBNET = NETWORK + "virtualNetworks/hub/subnets/GatewaySubnet"
GATEWAY = NETWORK + "virtualNetworkGateways/gateway"
MONITOR = NETWORK + "networkWatchers/watcher/connectionMonitors/monitor"
WORKSPACE = SCOPE + "/providers/Microsoft.OperationalInsights/workspaces/logs"
CIRCUIT = NETWORK + "expressRouteCircuits/circuit"
ACTION = SCOPE + "/providers/Microsoft.Insights/actionGroups/operators"
PRIVATE = "PRIVATE-ENDPOINT-HEADER-ROUTER-SECRET"
AT = "2026-11-06T11:00:00Z"
FIXTURE = Path(__file__).parent / "fixtures" / "monitoring" / "controls.bicep"
GUIDS = (
    "b30e38c3-f298-412b-8363-cefe179b599d",
    "5bf68dc9-325e-4873-bf88-f8214ef2e5d2",
    "e0d5973c-d4cd-421b-8881-37f5e6c4cfd3",
    "cf3fe65c-fec0-495a-8edc-9675200f2add",
    "72105cc8-aaea-4ee1-8c7a-ad25977afcaf",
    "d581a947-69a2-4783-942e-9df3664324c8",
    "b258f058-b9f6-46cd-b28d-990106f0c3f8",
    "fe2a1b53-6fbd-4c67-b58a-85d7c7a0afcb",
    "669b215a-ce43-4371-8f6f-11047f6490f1",
)


class MonitoringPreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.catalog = load_catalog(
            str(files("alz_assessor").joinpath("data", "catalog-2026-11-06.3.json"))
        )

    def record(self, kind, identity, raw):
        return {
            "logical_id": identity.lower(),
            "arm_id": identity.lower(),
            "resource_type": kind,
            "state": "known",
            "reason": "",
            "source_location": "fixture://supplied-monitoring-configuration",
            "properties": properties(kind, raw, observed=True),
        }

    def monitor(self):
        return {
            "notes": PRIVATE,
            "endpoints": [
                {"name": "from", "type": "AzureArcVM", "address": PRIVATE},
                {"name": "to", "type": "AzureVM", "resourceId": PRIVATE},
            ],
            "testConfigurations": [
                {
                    "name": "tcp",
                    "protocol": "Tcp",
                    "testFrequencySec": 60,
                    "tcpConfiguration": {"port": 443},
                    "httpConfiguration": {"path": PRIVATE, "requestHeaders": [{"value": PRIVATE}]},
                    "successThreshold": {"roundTripTimeMs": 123.5},
                }
            ],
            "testGroups": [
                {
                    "name": "hybrid",
                    "disable": False,
                    "sources": ["from"],
                    "destinations": ["to"],
                    "testConfigurations": ["tcp"],
                }
            ],
            "outputs": [
                {"type": "Workspace", "workspaceSettings": {"workspaceResourceId": WORKSPACE}}
            ],
        }

    def alert(self):
        return {
            "enabled": True,
            "scopes": [CIRCUIT],
            "criteria": {
                "odata.type": "Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria",
                "allOf": [
                    {
                        "criterionType": "StaticThresholdCriterion",
                        "metricName": "BgpAvailability",
                        "metricNamespace": "Microsoft.Network/expressRouteCircuits",
                        "timeAggregation": "Average",
                        "threshold": 0,
                        "dimensions": [{"values": [PRIVATE]}],
                    }
                ],
            },
            "actions": [{"actionGroupId": ACTION, "webHookProperties": {"secret": PRIVATE}}],
        }

    def bundle(self, disabled=False):
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
                    {"routeTable": {"id": TABLE}},
                ),
                self.record(
                    "Microsoft.Network/routeTables",
                    TABLE,
                    {"disableBgpRoutePropagation": disabled},
                ),
                self.record(
                    "Microsoft.Network/networkWatchers/connectionMonitors", MONITOR, self.monitor()
                ),
                self.record(
                    "Microsoft.Insights/metricAlerts",
                    SCOPE + "/providers/Microsoft.Insights/metricAlerts/availability",
                    self.alert(),
                ),
            ],
        )

    def by_id(self, bundle):
        result = {}
        for row in bundle["resources"]:
            result.setdefault(row["arm_id"], []).append(row)
        return result

    def test_fixed_membership_sources_and_no_catalog_activation(self):
        root = Path(__file__).resolve().parents[1]
        targets = json.loads((root / "references/recommendation-batches/targets.json").read_text())
        selected = [row for row in targets["targets"] if row["batch"] == "15"]
        self.assertEqual([row["guid"] for row in selected], list(GUIDS))
        preparation = json.loads(
            (root / "references/recommendation-batches/batch-15-preparation.json").read_text()
        )
        self.assertEqual(preparation["review_state"], "preparation-only-not-accepted")
        self.assertNotIn("catalog_version", preparation)
        self.assertEqual([row["guid"] for row in preparation["recommendations"]], list(GUIDS))
        sources = json.loads(
            (root / "references/recommendation-batches/batch-15-sources.json").read_text()
        )
        self.assertEqual(len(sources["sources"]), 30)
        indexed = {row["id"]: row for row in sources["sources"]}
        for row in preparation["recommendations"]:
            self.assertTrue(set(row["sources"]) <= set(indexed))
            self.assertLessEqual(len(row["review_fact_paths"]), 8)
            self.assertTrue(row["evidence_requirements"])
        self.assertTrue(
            indexed["expressroute-monitoring"]["resolved_url"].endswith(
                "/monitor-expressroute-reference"
            )
        )
        self.assertIn("November 2025", indexed["expressroute-bfd"]["finding"])
        self.assertIn("conflicts", indexed["connection-monitor-linked"]["finding"])
        for source in indexed.values():
            self.assertEqual(len(source["sha256"]), 64)
            self.assertEqual(len(source["revision"]), 40)
            self.assertTrue(source["retrieved_at"])
            self.assertTrue(source["reuse"])
        self.assertFalse((root / "references/recommendation-batches/batch-15.json").exists())
        original = load_catalog(
            str(files("alz_assessor").joinpath("data", "catalog-2026-11-04.2.json"))
        )
        original_controls = {row["control_id"]: row for row in original["controls"]}
        for control, expected in targets["preserved_automated"].items():
            self.assertEqual(control_digest(original_controls[control]), expected)
        self.assertEqual(len(self.catalog["controls"]), 255)

    def test_monitor_configuration_is_minimized_not_probe_health(self):
        fact = properties("Microsoft.Network/networkWatchers/connectionMonitors", self.monitor())[
            "connectionMonitorSummary"
        ]
        self.assertEqual(fact["endpointTypes"], ["AzureArcVM", "AzureVM"])
        self.assertEqual(fact["testConfigurations"], [{"protocol": "Tcp", "testFrequencySec": 60}])
        self.assertEqual(
            fact["testGroups"][0],
            {
                "disable": False,
                "sourceCount": 1,
                "destinationCount": 1,
                "testConfigurationCount": 1,
                "referencesResolved": True,
            },
        )
        self.assertEqual(fact["workspaceIds"], [WORKSPACE.lower()])
        self.assertNotIn(PRIVATE, json.dumps(fact))
        for withheld in ("address", "threshold", "headers", "notes", "health", "latency"):
            self.assertNotIn(withheld, json.dumps(fact).lower())
        self.assertEqual(monitor_facts(fact), fact)

    def test_monitor_names_and_exact_group_reference_resolution(self):
        for key in ("endpoints", "testConfigurations", "testGroups"):
            raw = self.monitor()
            raw[key].append(copy.deepcopy(raw[key][0]))
            self.assertIn(
                "unknown",
                properties("Microsoft.Network/networkWatchers/connectionMonitors", raw)[
                    "connectionMonitorSummary"
                ],
            )
        for key in ("sources", "destinations", "testConfigurations"):
            for refs in (["missing"], ["FROM"], ["from", "from"], None, True, [], [PRIVATE] * 101):
                raw = self.monitor()
                raw["testGroups"][0][key] = refs
                fact = properties("Microsoft.Network/networkWatchers/connectionMonitors", raw)[
                    "connectionMonitorSummary"
                ]
                if refs in (["missing"], ["FROM"]):
                    self.assertFalse(fact["testGroups"][0]["referencesResolved"])
                else:
                    self.assertIn("unknown", fact["testGroups"][0]["referencesResolved"])
                self.assertNotIn(PRIVATE, json.dumps(fact))

    def test_monitor_missing_wrong_type_symbolic_and_over_bound(self):
        kind = "Microsoft.Network/networkWatchers/connectionMonitors"
        for key in ("endpoints", "testConfigurations", "testGroups"):
            for value in (None, {}, [None], [], [{}] * 101, {"unknown": PRIVATE}):
                raw = self.monitor()
                raw[key] = value
                self.assertIn("unknown", properties(kind, raw)["connectionMonitorSummary"])
        for value in (None, True, 0, -1, 29, 1801, 60.0, "60", {}, float("inf")):
            raw = self.monitor()
            raw["testConfigurations"][0]["testFrequencySec"] = value
            fact = properties(kind, raw)["connectionMonitorSummary"]
            self.assertIn("unknown", fact["testConfigurations"][0]["testFrequencySec"])
        for value in (30, 60, 1800):
            raw = self.monitor()
            raw["testConfigurations"][0]["testFrequencySec"] = value
            self.assertEqual(
                properties(kind, raw)["connectionMonitorSummary"]["testConfigurations"][0][
                    "testFrequencySec"
                ],
                value,
            )
        raw = self.monitor()
        del raw["testGroups"][0]["disable"]
        raw["endpoints"][0]["type"] = PRIVATE
        raw["outputs"][0]["workspaceSettings"]["workspaceResourceId"] = CIRCUIT
        fact = properties(kind, raw)["connectionMonitorSummary"]
        self.assertIn("unknown", fact["testGroups"][0]["disable"])
        self.assertIn("unknown", fact["endpointTypes"][0])
        self.assertIn("unknown", fact["workspaceIds"][0])
        self.assertNotIn(PRIVATE, json.dumps(fact))

    def test_alert_scopes_and_criteria_never_establish_insights_or_delivery(self):
        kind = "Microsoft.Insights/metricAlerts"
        fact = properties(kind, self.alert())["expressRouteAlertSummary"]
        self.assertTrue(fact["enabled"])
        self.assertEqual(fact["circuitIds"], [CIRCUIT.lower()])
        self.assertEqual(fact["actionIds"], [ACTION.lower()])
        self.assertEqual(fact["criteria"][0]["metricName"], "BgpAvailability")
        self.assertEqual(alert_facts(fact), fact)
        self.assertNotIn(PRIVATE, json.dumps(fact))
        for field, value in (
            ("odata.type", "Microsoft.Azure.Monitor.MultipleResourceMultipleMetricCriteria"),
            ("allOf", None),
            ("allOf", []),
            ("allOf", [{}] * 101),
        ):
            raw = self.alert()
            raw["criteria"][field] = value
            self.assertIn("unknown", properties(kind, raw)["expressRouteAlertSummary"]["criteria"])
        raw = self.alert()
        raw["criteria"]["allOf"][0]["criterionType"] = "DynamicThresholdCriterion"
        raw["scopes"] = [WORKSPACE]
        raw["enabled"] = "true"
        fact = properties(kind, raw)["expressRouteAlertSummary"]
        for key in ("enabled", "criteria"):
            self.assertIn("unknown", fact[key])
        self.assertIn("unknown", fact["circuitIds"][0])
        raw = self.alert()
        raw["scopes"] = [CIRCUIT, CIRCUIT + "-other"]
        self.assertIn("unknown", properties(kind, raw)["expressRouteAlertSummary"]["criteria"])

    def test_explicit_route_propagation_and_strict_known_gateway_join(self):
        for disabled in (True, False):
            bundle = self.bundle(disabled)
            fact = gateway_route_subchecks(bundle["resources"][0], self.by_id(bundle))
            self.assertFalse(fact["truncated"])
            self.assertEqual(
                fact["gateway_subnet_routes"],
                [
                    {
                        "subnet_id": SUBNET.lower(),
                        "route_table_id": TABLE.lower(),
                        "route_propagation_enabled": not disabled,
                    }
                ],
            )
            tf = tf_properties(
                "azurerm_route_table", {"bgp_route_propagation_enabled": not disabled}
            )
            self.assertEqual(tf["disableBgpRoutePropagation"], disabled)
        for disabled in (None, "false", 0, {}, {"unknown": PRIVATE}):
            bundle = self.bundle(disabled)
            fact = gateway_route_subchecks(bundle["resources"][0], self.by_id(bundle))
            self.assertIn("unknown", fact["gateway_subnet_routes"][0]["route_propagation_enabled"])
            self.assertNotIn(PRIVATE, json.dumps(fact))
        self.assertIn(
            "unknown", tf_properties("azurerm_route_table", {})["disableBgpRoutePropagation"]
        )

    def test_gateway_join_missing_ambiguous_denied_wrong_type_unrelated_flags(self):
        for index in (0, 1, 2):
            for state in ("unknown", "inaccessible", "error"):
                bundle = self.bundle()
                bundle["resources"][index]["state"] = state
                fact = gateway_route_subchecks(bundle["resources"][0], self.by_id(bundle))
                self.assertIn("unknown", json.dumps(fact))
            bundle = self.bundle()
            bundle["resources"].append(copy.deepcopy(bundle["resources"][index]))
            self.assertIn(
                "unknown",
                json.dumps(gateway_route_subchecks(bundle["resources"][0], self.by_id(bundle))),
            )
        for index, kind in (
            (1, "Microsoft.Network/ipGroups"),
            (2, "Microsoft.Network/connections"),
        ):
            bundle = self.bundle()
            bundle["resources"][index]["resource_type"] = kind
            self.assertIn(
                "unknown",
                json.dumps(gateway_route_subchecks(bundle["resources"][0], self.by_id(bundle))),
            )
        for identity in (TABLE + "-missing", WORKSPACE, None):
            bundle = self.bundle()
            bundle["resources"][1]["properties"]["routeTable"]["id"] = identity
            fact = gateway_route_subchecks(bundle["resources"][0], self.by_id(bundle))
            self.assertIn("unknown", fact["gateway_subnet_routes"][0]["route_propagation_enabled"])
        bundle = self.bundle()
        bundle["resources"][0]["properties"]["subnetReferences"] = [
            SUBNET.replace("GatewaySubnet", "app")
        ]
        bundle["resources"][1]["arm_id"] = SUBNET.replace("GatewaySubnet", "app").lower()
        self.assertIn(
            "unknown",
            json.dumps(gateway_route_subchecks(bundle["resources"][0], self.by_id(bundle))),
        )
        bundle = self.bundle()
        bundle["resources"][0]["properties"]["subnetReferences"] = [SUBNET] * 21
        self.assertTrue(
            gateway_route_subchecks(bundle["resources"][0], self.by_id(bundle))["truncated"]
        )

    def test_typed_saved_review_context_does_not_activate_preparation(self):
        control = next(row for row in self.catalog["controls"] if row["upstream_guid"] == GUIDS[4])
        prepared = {
            **control,
            "review_resource_types": ["Microsoft.Network/virtualNetworkGateways"],
            "review_fact_paths": ["gatewayType", "subnetReferences", "disableBgpRoutePropagation"],
        }
        bundle = self.bundle()
        context = review_context(prepared, bundle)
        self.assertEqual(context["collected_at"], AT)
        self.assertFalse(context["inventory_complete"])
        self.assertTrue(
            context["resources"][0]["gateway_route_subchecks"]["gateway_subnet_routes"][0][
                "route_propagation_enabled"
            ]
        )
        for row in bundle["resources"]:
            row["properties"]["connectionMonitorSummary"] = {"endpointTypes": [PRIVATE]}
        context = review_context(
            {
                **control,
                "review_resource_types": ["Microsoft.Network/networkWatchers/connectionMonitors"],
                "review_fact_paths": ["connectionMonitorSummary"],
            },
            bundle,
        )
        self.assertNotIn(PRIVATE, json.dumps(context))
        self.assertNotIn(
            PRIVATE,
            json.dumps(
                review_fact(
                    {"connectionMonitorSummary": {"endpointTypes": [PRIVATE]}},
                    "connectionMonitorSummary",
                )
            ),
        )
        invalid_catalog = copy.deepcopy(self.catalog)
        invalid_catalog["controls"][0]["rationale"] += " preparation fixture"
        with self.assertRaisesRegex(InputError, "differs from a packaged"):
            known_catalog(invalid_catalog)

    def test_all_nine_decisions_remain_blank_and_no_verified_or_signal_tier(self):
        report = assess(self.bundle(), self.catalog, at=AT, evidence_tiers=True)
        selected = ["ALZ-" + guid for guid in GUIDS]
        prepared = prepare_reviews(report, self.catalog, selected, SCOPE)
        self.assertEqual(len(prepared["entries"]), 9)
        for entry in prepared["entries"]:
            self.assertIsNone(entry["outcome"])
            self.assertFalse(entry.get("reviewer"))
        for row in report["results"]:
            if row["control_id"] in selected:
                self.assertNotEqual(row["observed"]["outcome"], "pass")
                self.assertEqual(row["observed"]["evidence_tier"], "needs_decision")
        self.assertNotIn("microsoft.network/networkwatchers/connectionmonitors", API_VERSIONS)
        self.assertNotIn("microsoft.insights/metricalerts", API_VERSIONS)

    def test_stale_denied_and_malformed_preparation_cannot_be_verified(self):
        for condition in ("stale", "inaccessible", "error", "unknown"):
            bundle = self.bundle()
            if condition == "stale":
                bundle["collected_at"] = "2000-01-01T00:00:00Z"
            else:
                for resource in bundle["resources"]:
                    resource["state"] = condition
                    resource["reason"] = "resource_configuration_unavailable"
            report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
            selected = [
                row
                for row in report["results"]
                if row["control_id"] in {"ALZ-" + guid for guid in GUIDS}
            ]
            self.assertEqual(len(selected), 9)
            for row in selected:
                self.assertNotEqual(row["observed"]["outcome"], "pass")
                self.assertEqual(row["observed"]["evidence_tier"], "needs_decision")
        for kind, version in (
            ("Microsoft.Network/networkWatchers/connectionMonitors", "2019-06-01"),
            ("Microsoft.Insights/metricAlerts", "1900-01-01"),
        ):
            source = self.root / "unsupported.json"
            source.write_text(
                json.dumps(
                    {
                        "resources": [
                            {
                                "type": kind,
                                "apiVersion": version,
                                "name": "watcher/monitor"
                                if kind.endswith("connectionMonitors")
                                else "alert",
                                "properties": self.monitor()
                                if kind.endswith("connectionMonitors")
                                else self.alert(),
                            }
                        ]
                    }
                )
            )
            evidence = arm_source(source, scope=SCOPE)
            self.assertEqual(evidence["resources"][0]["state"], "unknown")
            self.assertNotIn(PRIVATE, json.dumps(evidence))

    def test_original_time_replay_preserves_minimized_configuration_without_guard_bypass(self):
        bundle = self.bundle()
        directory = self.root / "replay"
        export_bundle(directory, bundle, self.catalog, at=AT, evidence_tiers=True)
        replayed = replay_bundle(directory)
        original = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        self.assertEqual(semantic(original), semantic(replayed))
        content = (directory / "evidence.json").read_text()
        self.assertNotIn(PRIVATE, content)
        saved = json.loads(content)
        self.assertEqual(saved["collected_at"], AT)
        by_id = self.by_id(saved)
        self.assertTrue(
            gateway_route_subchecks(saved["resources"][0], by_id)["gateway_subnet_routes"][0][
                "route_propagation_enabled"
            ]
        )
        self.assertEqual(
            saved["resources"][3]["properties"]["connectionMonitorSummary"],
            bundle["resources"][3]["properties"]["connectionMonitorSummary"],
        )
        self.assertEqual(len(hashlib.sha256(content.encode()).hexdigest()), 64)

    def test_raw_terraform_and_sensitive_plan_configuration_without_execution(self):
        source = self.root / "tf"
        source.mkdir()
        (source / "main.tf").write_text(
            'resource "azurerm_network_connection_monitor" "hybrid" {\n'
            f'name="monitor"\nnetwork_watcher_id="{NETWORK}networkWatchers/watcher"\n'
            'endpoint { name="from" target_resource_type="AzureArcVM" }\n'
            'endpoint { name="to" target_resource_type="AzureVM" }\n'
            'test_configuration { name="tcp" protocol="Tcp" test_frequency_in_seconds=60 }\n'
            'test_group { name="hybrid" enabled=true source_endpoints=["from"] '
            'destination_endpoints=["to"] test_configuration_names=["tcp"] }\n'
            f'output_workspace_resource_ids=["{WORKSPACE}"]\n}}\n'
        )
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            raw = terraform_source(source, scope=SCOPE, provider_version="4.50.0")
        self.assertEqual(raw["resources"][0]["arm_id"], MONITOR.lower())
        self.assertFalse(
            raw["resources"][0]["properties"]["connectionMonitorSummary"]["testGroups"][0][
                "disable"
            ]
        )
        values = {
            "name": "monitor",
            "network_watcher_id": NETWORK + "networkWatchers/watcher",
            "endpoint": [{"name": "from"}, {"name": "to"}],
            "test_configuration": [{"name": "tcp", "protocol": "Tcp"}],
            "test_group": [
                {
                    "name": "hybrid",
                    "source_endpoints": ["from"],
                    "destination_endpoints": ["to"],
                    "test_configuration_names": ["tcp"],
                }
            ],
            "notes": PRIVATE,
        }
        fact = tf_properties("azurerm_network_connection_monitor", values)[
            "connectionMonitorSummary"
        ]
        self.assertIn("unknown", fact["testGroups"][0]["disable"])
        self.assertIn("unknown", fact["testConfigurations"][0]["testFrequencySec"])
        self.assertIsNone(
            tf_resource_id(
                SCOPE,
                "azurerm_network_connection_monitor",
                {
                    **values,
                    "network_watcher_id": WORKSPACE,
                },
            )
        )
        self.assertIsNone(
            tf_resource_id(
                SCOPE,
                "azurerm_network_connection_monitor",
                {
                    **values,
                    "network_watcher_id": "/subscriptions/00000000-0000-0000-0000-000000000002"
                    "/resourceGroups/other/providers/Microsoft.Network/networkWatchers/watcher",
                },
            )
        )
        plan = self.root / "plan.json"
        plan.write_text(
            json.dumps(
                {
                    "format_version": "1.2",
                    "planned_values": {
                        "root_module": {
                            "resources": [
                                {
                                    "mode": "managed",
                                    "type": "azurerm_network_connection_monitor",
                                    "address": "azurerm_network_connection_monitor.hybrid",
                                    "values": values,
                                    "sensitive_values": {"endpoint": True},
                                }
                            ]
                        }
                    },
                }
            )
        )
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            evidence = plan_source(plan, scope=SCOPE, provider_version="4.50.0")
        self.assertIn("unknown", evidence["resources"][0]["properties"]["connectionMonitorSummary"])
        self.assertNotIn(PRIVATE, json.dumps(evidence))

    def test_real_bicep_monitor_and_gateway_route_join_without_restore(self):
        compiler = os.environ.get("BICEP_COMPILER")
        if not compiler:
            self.skipTest("Set BICEP_COMPILER to an existing compiler; no acquisition")
        parameters = self.root / "parameters.json"
        parameters.write_text(
            json.dumps(
                {
                    "parameters": {
                        "workspaceId": {"value": WORKSPACE},
                        "circuitId": {"value": CIRCUIT},
                        "actionGroupId": {"value": ACTION},
                    }
                }
            )
        )
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            evidence = arm_source(
                FIXTURE, scope=SCOPE, compiler=compiler, parameters=parameters, bicep=True
            )
        validate(evidence, "evidence")
        resources = evidence["resources"]
        monitor = next(
            row for row in resources if row["resource_type"].lower().endswith("/connectionmonitors")
        )
        self.assertTrue(
            monitor["properties"]["connectionMonitorSummary"]["testGroups"][0]["referencesResolved"]
        )
        gateway = next(
            row
            for row in resources
            if row["resource_type"].lower().endswith("/virtualnetworkgateways")
        )
        self.assertTrue(
            gateway_route_subchecks(gateway, self.by_id(evidence))["gateway_subnet_routes"][0][
                "route_propagation_enabled"
            ]
        )
        alert = next(
            row for row in resources if row["resource_type"].lower().endswith("/metricalerts")
        )
        self.assertEqual(
            alert["properties"]["expressRouteAlertSummary"]["criteria"][0]["metricName"],
            "BgpAvailability",
        )


if __name__ == "__main__":
    unittest.main()
