import contextlib
import copy
import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from alz_assessor import interviews
from alz_assessor.arm import API_VERSIONS, PLANNED_API_VERSIONS, arm_source, properties
from alz_assessor.azure import Collector, Response
from alz_assessor.bicep import compile_bicep
from alz_assessor.catalog import load_catalog
from alz_assessor.cli import main
from alz_assessor.contracts import control_digest, document, validate
from alz_assessor.engine import assess
from alz_assessor.network_evidence import review_fact
from alz_assessor.plan import plan_source
from alz_assessor.replay import export_bundle, replay_bundle, sanitize_evidence, semantic
from alz_assessor.reports import render, render_xlsx
from alz_assessor.review_page import review_page
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import prepare_reviews, review_context
from alz_assessor.sources import terraform_source, tf_properties, tf_resource_id
from alz_assessor.terraform import InputError, tree_hash
from alz_assessor.topology_evidence import (
    FIREWALL,
    GATEWAY,
    GUIDS,
    HUB,
    IPCONFIG,
    PATHS,
    PEERING,
    RESOLVER,
    SUBNET,
    VNET,
    configuration_context,
    prefix_fact,
    prefix_summary,
    subnet_context,
)

ROOT = Path(__file__).resolve().parents[1]
SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
OTHER = "/subscriptions/00000000-0000-0000-0000-000000000002"
RG = SCOPE + "/resourcegroups/network"
NET = RG + "/providers/microsoft.network/virtualnetworks/not-a-designation"
REMOTE = RG + "/providers/microsoft.network/virtualnetworks/another"
SUB = NET + "/subnets/routeserversubnet"
ROUTING = RG + "/providers/microsoft.network/virtualhubs/not-a-designation"
IP = ROUTING + "/ipconfigurations/explicit"
PEER = NET + "/virtualnetworkpeerings/forward"
REVERSE = REMOTE + "/virtualnetworkpeerings/reverse"
AT = "2026-11-06T20:00:00Z"
PRIVATE = "PRIVATE-NVA-PARTNER-PAYLOAD"
CONTROLS = {"ALZ-" + guid for guid in GUIDS}


class TopologyPreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.matrix = json.loads(
            (ROOT / "references/recommendation-batches/preparation-10.json").read_text("utf-8")
        )
        self.catalog = copy.deepcopy(load_catalog())
        self.catalog["review_state"] = "authored-in-memory-fixture-not-accepted"
        rows = {row["guid"]: row for row in self.matrix["recommendations"]}
        for control in self.catalog["controls"]:
            if control["upstream_guid"] in rows:
                row = rows[control["upstream_guid"]]
                for key in ("review_resource_types", "review_fact_paths"):
                    if row[key]:
                        control[key] = row[key]
                control["evidence_requirements"] = row["evidence_requirements"]
                control["rationale"] = row["limitations"]
        validate(self.catalog, "catalog")
        network = patch("socket.socket.connect", side_effect=AssertionError("network forbidden"))
        network.start()
        self.addCleanup(network.stop)

    def record(self, kind, identity, raw, location="westeurope"):
        return {
            "logical_id": identity.lower(),
            "arm_id": identity.lower(),
            "resource_type": kind,
            "state": "known",
            "reason": "",
            "source_location": "fixture://authored-topology",
            "properties": properties(kind, raw, root={"location": location}),
        }

    def peering(self, target):
        return {
            "remoteVirtualNetwork": {"id": target},
            "allowVirtualNetworkAccess": True,
            "allowForwardedTraffic": False,
            "allowGatewayTransit": True,
            "useRemoteGateways": False,
            "privatePayload": PRIVATE,
        }

    def bundle(self):
        return document(
            "evidence",
            schema_version="1.1",
            mode="observed",
            source="saved",
            scope=SCOPE,
            collected_at=AT,
            inventory_complete=False,
            artifact_hashes={"fixture": "0" * 64},
            diagnostics=[],
            resources=[
                self.record(VNET, NET, {}),
                self.record(VNET, REMOTE, {}, "eastus"),
                self.record(SUBNET, SUB, {"addressPrefix": "10.0.0.0/26"}),
                self.record(
                    HUB,
                    ROUTING,
                    {
                        "ipConfigurations": [{"id": IP}],
                        "allowBranchToBranchTraffic": True,
                        "hubRoutingPreference": "ExpressRoute",
                        "sku": "Standard",
                        "virtualRouterIps": ["10.0.0.4"],
                        "privatePayload": PRIVATE,
                    },
                ),
                self.record(
                    IPCONFIG,
                    IP,
                    {
                        "subnet": {"id": SUB},
                        "privateIPAddress": "10.0.0.5",
                        "privatePayload": PRIVATE,
                    },
                ),
                self.record(PEERING, PEER, self.peering(REMOTE)),
                self.record(PEERING, REVERSE, self.peering(NET)),
            ],
        )

    def by_id(self, bundle):
        result = {}
        for row in bundle["resources"]:
            result.setdefault((row.get("arm_id") or "").lower(), []).append(row)
        return result

    def context(self, upstream="D01.08", bundle=None):
        control = next(c for c in self.catalog["controls"] if c["upstream_id"] == upstream)
        return review_context(control, bundle or self.bundle())

    def config(self, bundle=None, identity=ROUTING):
        bundle = bundle or self.bundle()
        row = next(r for r in bundle["resources"] if r["arm_id"] == identity)
        return configuration_context(row, bundle, self.by_id(bundle))

    def test_exact_ten_guid_matrix_and_unactivated_bank_and_catalog(self):
        targets = json.loads((ROOT / "references/recommendation-batches/targets.json").read_text())
        fixed = {t["upstream_id"]: t["guid"] for t in targets["targets"] if t["batch"] == "10"}
        self.assertEqual(
            fixed, {r["upstream_id"]: r["guid"] for r in self.matrix["recommendations"]}
        )
        self.assertEqual(set(fixed.values()), GUIDS)
        self.assertNotIn("D01.05", fixed)
        self.assertEqual(set(self.matrix["interview"]["controls"]), CONTROLS)
        self.assertNotIn(self.matrix["interview"]["id"], interviews.BANK)
        self.assertNotIn("catalog_version", self.matrix)
        self.assertEqual(self.matrix["review_state"], "preparation-only-not-accepted")
        for row in self.matrix["recommendations"]:
            self.assertLessEqual(len(row["review_fact_paths"]), 8)
            self.assertTrue(row["evidence_requirements"])
            self.assertEqual(
                row["classification"],
                "manual" if row["upstream_id"] in {"D01.01", "D01.06"} else "assisted",
            )
        for control in load_catalog()["controls"]:
            if control["upstream_guid"] in GUIDS:
                self.assertNotIn("review_fact_paths", control)
                self.assertIsNone(control["rule"])

    def test_actual_sources_hashes_redirects_limits_and_immutable_wording(self):
        captured = json.loads(
            (ROOT / "references/recommendation-batches/preparation-10-sources.json").read_text()
        )
        indexed = {s["id"]: s for s in captured["sources"]}
        self.assertEqual(len(indexed), len(captured["sources"]))
        for row in self.matrix["recommendations"]:
            self.assertTrue(set(row["sources"]) <= set(indexed))
        for source in indexed.values():
            self.assertRegex(source["sha256"], "^[0-9a-f]{64}$")
            self.assertRegex(source["revision"], "^[0-9a-f]{40}$")
            self.assertTrue(source["reuse"])
            self.assertTrue(source["retrieved_at"])
        self.assertIn("quickstart-create-", indexed["route-server-quickstart"]["resolved_url"])
        self.assertIn("/network-watcher/", indexed["network-insights"]["resolved_url"])
        self.assertIn("650", indexed["network-limits"]["finding"])
        self.assertIn("/26", indexed["route-server-quickstart"]["finding"])
        originals = {c["upstream_id"]: c for c in load_catalog()["controls"]}
        self.assertIn("/27", originals["D01.08"]["recommendation"])
        for number in ("400", "500", "1000"):
            self.assertIn(number, originals["D01.11"]["recommendation"])
        self.assertIn("P2S", self.matrix["source_qualifications"]["transit"])

    def test_exact_current_source_sizing_boundary_not_old_checklist(self):
        for length, expected in ((25, True), (26, True), (27, False), (28, False)):
            bundle = self.bundle()
            bundle["resources"][2] = self.record(
                SUBNET, SUB, {"addressPrefix": f"10.0.0.0/{length}"}
            )
            size = self.config(bundle)["configuredSubnets"][0]["currentRouteServerMinimumSize"]
            self.assertIs(size["matches"], expected)
            self.assertEqual(size["maximumPrefixLength"], 26)
            self.assertIn("quickstart-create-route-server-portal", size["source"])
        for prefixes in (["2001:db8::/64"], ["10.0.0.0/26", "10.0.1.0/26"]):
            bundle = self.bundle()
            bundle["resources"][2] = self.record(SUBNET, SUB, {"addressPrefixes": prefixes})
            value = self.config(bundle)["configuredSubnets"][0]["currentRouteServerMinimumSize"]
            self.assertIn("unknown", value["matches"])

    def test_prefix_minimization_types_and_bounds(self):
        for value in (
            None,
            [],
            ["bad"],
            ["10.0.0.1/26"],
            ["10.0.0.0/26"] * 2,
            ["10.0.0.0/26"] * 21,
            [True],
            [{"unknown": "symbolic"}],
        ):
            self.assertIn("unknown", prefix_summary(value))
        for value in (
            None,
            [],
            [{"family": True, "prefixLength": 26}],
            [{"family": 4, "prefixLength": True}],
            [{"family": 4, "prefixLength": 33}],
            [{"family": 6, "prefixLength": 129}],
            [{"family": 5, "prefixLength": 24}],
        ):
            self.assertIn("unknown", prefix_fact(value))
        for family, maximum in ((4, 32), (6, 128)):
            for length in (0, maximum):
                summary = [{"family": family, "prefixLength": length}]
                self.assertEqual(prefix_fact(summary), summary)
        conflict = properties(
            SUBNET, {"addressPrefix": "10.0.0.0/26", "addressPrefixes": ["10.0.0.0/27"]}
        )
        self.assertIn("unknown", conflict["routingSubnetPrefixSummary"])
        self.assertEqual(prefix_summary(["10.0.0.0/26"]), [{"family": 4, "prefixLength": 26}])

    def test_genuine_separate_ipconfiguration_not_invented_resource_kind(self):
        bundle = self.bundle()
        context = self.config(bundle)
        self.assertEqual(context["configuredSubnets"][0]["virtualNetworkId"], NET)
        self.assertIs(context["configuredSubnets"][0]["routeServerReservedSubnetName"], True)
        self.assertIn("not Route Server", context["warning"])
        self.assertNotIn("virtual_wan_context", json.dumps(self.context("D01.07")))
        for key in ("ipConfigurations", "kind", "virtualRouterIps"):
            self.assertNotIn(key, bundle["resources"][3]["properties"])
        for raw in (
            {},
            {"sku": "Standard"},
            {"kind": "RouteServer"},
            {"ipConfigurations": [{"properties": {"subnet": {"id": SUB}}}]},
        ):
            bundle["resources"][3] = self.record(HUB, ROUTING, raw)
            self.assertIn("unknown", self.config(bundle))
        self.assertEqual(PLANNED_API_VERSIONS[IPCONFIG], {"2024-05-01"})
        self.assertNotIn(IPCONFIG, API_VERSIONS)
        self.assertNotIn("microsoft.network/routeservers", PLANNED_API_VERSIONS)

    def test_relationship_missing_denied_duplicate_wrong_type_parent_and_scope(self):
        for index in (0, 2, 3, 4):
            for state in ("unknown", "inaccessible", "error", "absent"):
                bundle = self.bundle()
                bundle["resources"][index]["state"] = state
                bundle["resources"][index]["reason"] = "detail_denied"
                config = self.config(bundle)
                self.assertIn(
                    "unknown", config if index in (3, 4) else config["configuredSubnets"][0]
                )
            bundle = self.bundle()
            bundle["resources"].append(copy.deepcopy(bundle["resources"][index]))
            config = self.config(bundle)
            self.assertIn("unknown", config if index in (3, 4) else config["configuredSubnets"][0])
        for ref in (REMOTE, OTHER + SUB[len(SCOPE) :], PRIVATE, None):
            bundle = self.bundle()
            bundle["resources"][4]["properties"]["routingSubnetId"] = ref
            config = self.config(bundle)
            self.assertIn(
                "unknown", config if "unknown" in config else config["configuredSubnets"][0]
            )
        bundle = self.bundle()
        wrong = ROUTING + "-other/ipconfigurations/explicit"
        bundle["resources"][3]["properties"]["routingIpConfigurationIds"] = [wrong]
        bundle["resources"][4]["arm_id"] = wrong
        self.assertIn("wrong_parent", self.config(bundle)["unknown"])
        bundle = self.bundle()
        bundle["resources"][4]["resource_type"] = VNET
        self.assertIn("unknown", self.config(bundle))

    def test_attachment_bounds_duplicates_and_no_reserved_name_inference(self):
        for refs in (None, [], [SUB] * 2, [SUB] * 21, [REMOTE]):
            bundle = self.bundle()
            bundle["resources"][3]["properties"]["routingSubnetReferences"] = refs
            if refs is None:
                bundle["resources"][3]["properties"]["routingIpConfigurationIds"] = None
            self.assertIn("unknown", self.config(bundle))
        bundle = self.bundle()
        arbitrary = NET + "/subnets/arbitrary"
        bundle["resources"][2]["arm_id"] = arbitrary
        bundle["resources"][4]["properties"]["routingSubnetId"] = arbitrary
        self.assertIs(
            self.config(bundle)["configuredSubnets"][0]["routeServerReservedSubnetName"], False
        )
        bundle["resources"] = [r for r in bundle["resources"] if r["resource_type"] != HUB]
        self.assertIn("unknown", self.config(bundle, IP))
        self.assertIn("unknown", subnet_context(REMOTE, bundle, self.by_id(bundle)))

    def test_peering_configuration_positive_reciprocal_and_regional_not_hub_transit(self):
        config = self.config(identity=PEER)
        self.assertEqual(config["localVirtualNetworkId"], NET)
        self.assertEqual(config["remoteVirtualNetworkId"], REMOTE)
        self.assertIs(config["differentConfiguredRegions"], True)
        self.assertEqual(config["reciprocalConfiguration"]["arm_id"], REVERSE)
        bundle = self.bundle()
        bundle["resources"][1]["properties"]["resourceLocation"] = "westeurope"
        self.assertIs(self.config(bundle, PEER)["differentConfiguredRegions"], False)
        bundle["resources"][1]["properties"]["resourceLocation"] = None
        self.assertIn("unknown", self.config(bundle, PEER)["differentConfiguredRegions"])
        for key, value in (
            ("allowGatewayTransit", None),
            ("useRemoteGateways", 1),
            ("allowForwardedTraffic", "true"),
        ):
            facts = properties(PEERING, {key: value})["peeringTransitSummary"]
            self.assertIn("unknown", facts[key])
        self.assertNotIn("pass", json.dumps(config))

    def test_peering_self_remote_type_missing_duplicate_and_reverse_ambiguity(self):
        for target in (NET, SUB, OTHER + REMOTE[len(SCOPE) :], None):
            bundle = self.bundle()
            bundle["resources"][5]["properties"]["remoteVirtualNetwork"] = {"id": target}
            self.assertIn("unknown", self.config(bundle, PEER))
        for index in (0, 1, 5):
            bundle = self.bundle()
            bundle["resources"].append(copy.deepcopy(bundle["resources"][index]))
            self.assertIn("unknown", self.config(bundle, PEER))
        for change in ("missing", "duplicate", "denied"):
            bundle = self.bundle()
            if change == "missing":
                bundle["resources"].pop()
            elif change == "duplicate":
                bundle["resources"].append(copy.deepcopy(bundle["resources"][-1]))
            else:
                bundle["resources"][-1]["state"] = "inaccessible"
                bundle["resources"][-1]["reason"] = "detail_denied"
            self.assertIn("unknown", self.config(bundle, PEER)["reciprocalConfiguration"])

    def test_strict_scope_per_type_facts_and_population_bounds(self):
        bundle = self.bundle()
        bundle["scope"] = OTHER
        self.assertEqual(self.context(bundle=bundle)["matching_resources"], 0)
        self.assertEqual(self.context(bundle=bundle)["unbound_resources"], 3)
        bundle = self.bundle()
        bundle["resources"] += [self.record(VNET, NET + f"-{i}", {}) for i in range(101)]
        context = self.context("D01.02", bundle)
        self.assertTrue(context["truncated"])
        self.assertIn("over_100", self.config(bundle)["unknown"])
        context = self.context("D01.08")
        subnet = next(r for r in context["resources"] if r["resource_type"] == SUBNET)
        self.assertIn("unknown", subnet["facts"]["routingSubnetId"])
        self.assertEqual(
            subnet["facts"]["routingSubnetPrefixSummary"], [{"family": 4, "prefixLength": 26}]
        )
        bundle = self.bundle()
        bundle["resources"].append(copy.deepcopy(bundle["resources"][2]))
        bundle["resources"][-1]["logical_id"] += "-duplicate"
        with self.assertRaisesRegex(InputError, "Duplicate or ambiguous ARM"):
            self.context(bundle=bundle)

    def test_existing_gateway_firewall_dns_relationships_not_service_placement_verdict(self):
        bundle = self.bundle()
        gateway_subnet = NET + "/subnets/gatewaysubnet"
        bundle["resources"] += [
            self.record(SUBNET, gateway_subnet, {"addressPrefix": "10.0.1.0/27"}),
            self.record(
                GATEWAY,
                RG + "/providers/microsoft.network/virtualnetworkgateways/vpn",
                {
                    "gatewayType": "Vpn",
                    "vpnType": "RouteBased",
                    "activeActive": True,
                    "bgpSettings": {"asn": 65515},
                    "ipConfigurations": [{"properties": {"subnet": {"id": gateway_subnet}}}],
                },
            ),
            self.record(
                FIREWALL,
                RG + "/providers/microsoft.network/azurefirewalls/firewall",
                {"ipConfigurations": [{"properties": {"subnet": {"id": SUB}}}]},
            ),
            self.record(
                RESOLVER,
                RG + "/providers/microsoft.network/dnsresolvers/resolver",
                {"virtualNetwork": {"id": NET}},
            ),
        ]
        prepared = self.context("D01.04", bundle)
        for row in prepared["resources"]:
            self.assertNotIn("linked_subnets", row)
            if row["resource_type"] in (GATEWAY, FIREWALL):
                self.assertEqual(
                    row["topology_configuration"]["configuredSubnets"][0]["virtualNetworkId"], NET
                )
            if row["resource_type"] == RESOLVER:
                self.assertEqual(
                    row["topology_configuration"]["configuredVirtualNetwork"]["arm_id"], NET
                )
        self.assertNotIn(PRIVATE, json.dumps(prepared))
        self.assertNotIn("10.0.", json.dumps(prepared))

    def test_no_whole_pass_verified_or_automatic_quota_threshold(self):
        for state in ("known", "unknown", "inaccessible", "error", "absent"):
            bundle = self.bundle()
            bundle["inventory_complete"] = state == "absent"
            for row in bundle["resources"]:
                row["state"] = state
                row["reason"] = "" if state == "known" else "detail_denied"
            report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
            rows = [r for r in report["results"] if r["control_id"] in CONTROLS]
            self.assertEqual(len(rows), 10)
            self.assertTrue(all(r["observed"]["outcome"] != "pass" for r in rows))
            self.assertTrue(all(r["observed"]["evidence_tier"] != "verified" for r in rows))
            template = prepare_reviews(report, self.catalog, sorted(CONTROLS), SCOPE)
            self.assertTrue(all(r["outcome"] is None for r in template["entries"]))
        for upstream in ("D01.01", "D01.06"):
            self.assertEqual(self.context(upstream)["matching_resources"], 0)
        for control in self.catalog["controls"]:
            if control["upstream_guid"] in GUIDS:
                self.assertIsNone(control["rule"])
        bundle = self.bundle()
        bundle["scope"] = OTHER
        for when in (AT, "2027-01-01T00:00:00Z"):
            report = assess(bundle, self.catalog, at=when, evidence_tiers=True)
            self.assertTrue(
                all(
                    r["observed"]["evidence_tier"] in {"needs_decision", "manual"}
                    for r in report["results"]
                    if r["control_id"] in CONTROLS
                )
            )

    def test_raw_terraform_local_module_and_explicit_provider_only(self):
        root = self.root / "module"
        root.mkdir()
        (root / "main.tf").write_text(
            'resource "azurerm_route_server" "declared" {\nname="routing"\n'
            f'resource_group_name="network"\nsubnet_id="{SUB}"\n'
            'sku="Standard"\nbranch_to_branch_traffic_enabled=true\n'
            'hub_routing_preference="ASPath"\n}\n'
        )
        raw = terraform_source(root, scope=SCOPE, provider_version="4.50.0")
        record = raw["resources"][0]
        self.assertEqual(record["arm_id"], RG + "/providers/microsoft.network/virtualhubs/routing")
        self.assertEqual(record["properties"]["routingSubnetReferences"], [SUB])
        self.assertIs(record["properties"]["hubBranchTrafficAllowed"], True)
        self.assertEqual(record["properties"]["hubRoutingPreference"], "ASPath")
        wrapper = self.root / "wrapper"
        wrapper.mkdir()
        (wrapper / "main.tf").write_text(
            'module "supplied" {\nsource="example.invalid/routing/azurerm"\nversion="1.0.0"\n}\n'
        )
        manifest = self.root / "snapshots.json"
        manifest.write_text(
            json.dumps(
                {
                    "modules": [
                        {
                            "source": "example.invalid/routing/azurerm",
                            "version": "1.0.0",
                            "subdirectory": "",
                            "path": "module",
                            "sha256": tree_hash(root),
                        }
                    ]
                }
            )
        )
        supplied = terraform_source(
            wrapper,
            scope=SCOPE,
            provider_version="4.50.0",
            snapshots=manifest,
            authorized_roots=[self.root],
        )
        self.assertEqual(supplied["resources"][0]["properties"], record["properties"])
        unsupported = terraform_source(root, scope=SCOPE, provider_version="unreviewed")
        self.assertEqual(unsupported["resources"][0]["state"], "unknown")
        self.assertEqual(unsupported["resources"][0]["properties"], {})
        empty = tf_properties("azurerm_route_server", {})
        self.assertIn("unknown", empty["hubBranchTrafficAllowed"])
        self.assertNotIn("routingSubnetReferences", tf_properties("azurerm_virtual_hub", {}))
        self.assertIsNone(tf_resource_id(SCOPE, "azurerm_route_server", {"name": True}))

    def test_saved_plan_sensitive_attachment_unsupported_and_unknown_flags(self):
        path = self.root / "plan.json"
        base = {
            "format_version": "1.2",
            "terraform_version": "1.14.0",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "mode": "managed",
                            "type": "azurerm_route_server",
                            "address": "azurerm_route_server.routing",
                            "values": {
                                "name": "routing",
                                "resource_group_name": "network",
                                "subnet_id": SUB,
                                "branch_to_branch_traffic_enabled": True,
                                "private": PRIVATE,
                            },
                        }
                    ]
                }
            },
        }
        path.write_text(json.dumps(base))
        bundle = plan_source(path, scope=SCOPE, provider_version="4.50.0")
        self.assertEqual(bundle["mode"], "planned")
        self.assertEqual(bundle["resources"][0]["properties"]["routingSubnetReferences"], [SUB])
        row = base["planned_values"]["root_module"]["resources"][0]
        row["sensitive_values"] = {"subnet_id": True}
        path.write_text(json.dumps(base))
        bundle = plan_source(path, scope=SCOPE, provider_version="4.50.0")
        self.assertIn("unknown", bundle["resources"][0]["properties"]["routingSubnetReferences"][0])
        self.assertNotIn(PRIVATE, json.dumps(bundle))

    def test_gateway_transit_exact_asn_and_type_boundaries_without_bgp_default(self):
        for asn, expected in (
            (65514, False),
            (65515, True),
            (65516, False),
            (0, False),
            (4294967295, False),
        ):
            raw = {"vpnType": "RouteBased", "bgpSettings": {"asn": asn}}
            facts = properties(GATEWAY, raw)["gatewayTransitSummary"]
            self.assertIs(facts["asnIs65515"], expected)
            self.assertEqual(facts["vpnType"], "RouteBased")
            normalized = review_fact({"gatewayTransitSummary": facts}, "gatewayTransitSummary")
            self.assertEqual(normalized, facts)
        for asn in (None, True, 65515.0, "65515", -1, 4294967296, {"unknown": "sensitive"}):
            facts = properties(GATEWAY, {"bgpSettings": {"asn": asn}})["gatewayTransitSummary"]
            self.assertIn("unknown", facts["asnIs65515"])
        facts = tf_properties(
            "azurerm_virtual_network_gateway",
            {"vpn_type": "RouteBased", "bgp_settings": [{"asn": 65515}]},
        )
        self.assertIs(facts["gatewayTransitSummary"]["asnIs65515"], True)
        self.assertIn(
            "unknown",
            tf_properties("azurerm_virtual_network_gateway", {})["gatewayTransitSummary"][
                "asnIs65515"
            ],
        )
        for path in ("gatewayTransitSummary", "peeringTransitSummary"):
            self.assertIn(
                "unknown", review_fact({path: {"unknown": "denied", "asnIs65515": True}}, path)
            )
        invalid = tf_properties("azurerm_route_server", {"hub_routing_preference": PRIVATE})
        self.assertNotIn(PRIVATE, json.dumps(invalid))

    def test_monitoring_existing_facts_are_signals_not_executed_end_to_end_health(self):
        kind = "microsoft.network/networkwatchers/flowlogs"
        identity = RG + "/providers/microsoft.network/networkwatchers/authored/flowlogs/authored"
        bundle = self.bundle()
        bundle["resources"].append(self.record(kind, identity, {"enabled": True}))
        context = self.context("D01.10", bundle)
        self.assertEqual(context["matching_resources"], 1)
        self.assertIs(context["resources"][0]["facts"]["enabled"], True)
        report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        row = next(
            r
            for r in report["results"]
            if r["control_id"] == "ALZ-4722d929-c1b1-4cd6-81f5-4b29bade39ad"
        )
        self.assertEqual(row["observed"]["evidence_tier"], "signal")
        self.assertNotEqual(row["observed"]["outcome"], "pass")
        bundle["resources"][-1]["state"] = "inaccessible"
        bundle["resources"][-1]["reason"] = "detail_denied"
        report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        row = next(
            r
            for r in report["results"]
            if r["control_id"] == "ALZ-4722d929-c1b1-4cd6-81f5-4b29bade39ad"
        )
        self.assertEqual(row["observed"]["evidence_tier"], "needs_decision")

    def test_positive_saved_management_group_scope_and_virtual_wan_conflict(self):
        bundle = self.bundle()
        bundle["scope"] = "/providers/microsoft.management/managementgroups/selected"
        self.assertEqual(self.context(bundle=bundle)["matching_resources"], 0)
        bundle["metadata"] = {"relationships": [{"id": SCOPE, "parent": bundle["scope"]}]}
        self.assertEqual(self.context(bundle=bundle)["matching_resources"], 3)
        bundle["metadata"] = {
            "relationships": [
                {
                    "id": SCOPE,
                    "parent": "/providers/microsoft.management/managementgroups/not-selected",
                }
            ]
        }
        self.assertEqual(self.context(bundle=bundle)["matching_resources"], 0)
        bundle = self.bundle()
        bundle["resources"][3]["properties"]["virtualWanId"] = (
            RG + "/providers/microsoft.network/virtualwans/authored"
        )
        self.assertIn("virtual_wan_attachment", self.config(bundle)["unknown"])

    def test_arm_exact_version_condition_and_injected_collector_no_new_live_route(self):
        path = self.root / "template.json"
        path.write_text(
            json.dumps(
                {
                    "resources": [
                        {
                            "type": "Microsoft.Network/virtualHubs/ipConfigurations",
                            "name": "routing/ip",
                            "apiVersion": version,
                            "properties": {"subnet": {"id": SUB}},
                        }
                        for version in ("2024-05-01", "unreviewed")
                    ]
                }
            )
        )
        bundle = arm_source(path, scope=SCOPE)
        self.assertEqual([r["state"] for r in bundle["resources"]], ["known", "unknown"])
        self.assertEqual(bundle["resources"][0]["properties"]["routingSubnetId"], SUB)
        requests = []

        def transport(method, url):
            requests.append((method, url))
            if "/resources?" in url:
                return Response(200, {"value": [{"id": IP, "type": IPCONFIG}]}, {})
            return Response(200, {"value": []}, {})

        collected = Collector(transport).collect(
            subscriptions=[SCOPE.split("/")[2]], inventory_authorized=True
        )
        self.assertFalse(any("/ipconfigurations/" in url.lower() for _, url in requests))
        self.assertTrue(all(not r["properties"] for r in collected["resources"]))

    def test_reports_prepared_interview_binding_expiry_session_and_atomic_failure(self):
        question = self.matrix["interview"]
        with patch.dict(
            interviews.BANK,
            {
                question["id"]: {
                    "question": question["question"],
                    "controls": question["controls"],
                }
            },
        ):
            bundle = self.bundle()
            report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
            response = interviews.prepare_interview(report, self.catalog, question["id"], SCOPE)
            self.assertEqual(len(response["decisions"]), 10)
            self.assertTrue(all(r["outcome"] is None for r in response["decisions"]))
            with self.assertRaises(InputError):
                interviews.compile_interview(response, self.catalog, at=AT)
            response.update(
                answer="Authored fixture, not an actual owner approval.",
                reviewer="Authored fixture reviewer",
                rationale="Ten independent fixture decisions.",
                evidence="https://example.invalid/redacted",
                valid_from=AT,
                valid_until="2026-11-07T20:00:00Z",
            )
            for i, decision in enumerate(response["decisions"]):
                decision["outcome"] = "pass" if i % 2 else "fail"
            manual = interviews.compile_interview(response, self.catalog, at=AT)
            self.assertEqual(len(manual["entries"]), 10)
            for change in (
                "binding",
                "expiry",
                "blank",
                "attribution",
                "scope",
                "selection",
                "duplicate",
                "future",
            ):
                invalid = copy.deepcopy(response)
                when = AT
                if change == "binding":
                    invalid["decisions"][0]["control_sha256"] = "0" * 64
                elif change == "expiry":
                    when = "2026-11-08T20:00:00Z"
                elif change == "blank":
                    invalid["decisions"][0]["outcome"] = None
                elif change == "scope":
                    invalid["scope"] = OTHER
                elif change == "selection":
                    invalid["decisions"].pop()
                elif change == "duplicate":
                    invalid["decisions"][-1] = invalid["decisions"][0]
                elif change == "future":
                    invalid["valid_from"] = "2026-11-07T20:00:00Z"
                else:
                    invalid["reviewer"] = ""
                with self.assertRaises(InputError):
                    interviews.compile_interview(invalid, self.catalog, at=when)
            exceptions = document(
                "exceptions",
                schema_version="1.1",
                entries=[
                    {k: v for k, v in manual["entries"][0].items() if k != "outcome"}
                    | {"disposition": "accepted"}
                ],
            )
            report = assess(
                bundle,
                self.catalog,
                manual=manual,
                exceptions=exceptions,
                at=AT,
                evidence_tiers=True,
            )
            self.assertTrue(
                all(
                    r["observed"]["evidence_tier"] != "verified"
                    for r in report["results"]
                    if r["control_id"] in CONTROLS
                )
            )
            for format in ("json", "markdown", "html", "csv", "sarif", "pr-summary"):
                self.assertNotIn(PRIVATE, render(report, format))
            with zipfile.ZipFile(io.BytesIO(render_xlsx(report))) as archive:
                self.assertNotIn(
                    PRIVATE, "".join(archive.read(p).decode() for p in archive.namelist())
                )
            session = ReviewSession(
                bundle, self.catalog, self.root / "session", clock=lambda: AT, evidence_tiers=True
            )
            self.assertIn("immutable /27", review_page(session.state(), "token", "nonce"))
            invalid = copy.deepcopy(response)
            invalid["decisions"][-1]["outcome"] = None
            with self.assertRaises(InputError):
                session.save_interview({"revision": 0, "response": invalid, "replace_existing": []})
            self.assertEqual(session.revision, 0)
            self.assertFalse((session.directory / "revision-0001").exists())
            session.save_interview({"revision": 0, "response": response, "replace_existing": []})
            self.assertEqual(len(session.state()["records"]), 10)
            resumed = ReviewSession.resume(
                session.directory / "revision-0001", self.root / "resumed", clock=lambda: AT
            )
            self.assertEqual(semantic(session.report), semantic(resumed.report))

    def test_cli_saved_evidence_uses_same_prepared_workflows_without_catalog_activation(self):
        evidence = self.root / "evidence.json"
        catalog = self.root / "fixture-catalog.json"
        output = self.root / "report.json"
        evidence.write_text(json.dumps(self.bundle()))
        catalog.write_text(json.dumps(self.catalog))
        stderr = io.StringIO()
        with (
            patch(
                "sys.argv",
                [
                    "alz-assessor",
                    "assess",
                    str(evidence),
                    "--input",
                    "evidence",
                    "--catalog",
                    str(catalog),
                    "--at",
                    AT,
                    "--evidence-tiers",
                    "--output",
                    str(output),
                ],
            ),
            contextlib.redirect_stderr(stderr),
        ):
            result = main()
        self.assertEqual(result, 0, stderr.getvalue())
        report = json.loads(output.read_text())
        expected = assess(self.bundle(), self.catalog, at=AT, evidence_tiers=True)
        self.assertEqual(report, json.loads(render(expected, "json")))
        self.assertNotIn(PRIVATE, output.read_text())

    def test_privacy_original_time_replay_and_candidate_catalog_rejection(self):
        bundle = self.bundle()
        minimized = sanitize_evidence(bundle)
        for before, after in zip(bundle["resources"], minimized["resources"], strict=True):
            for path in PATHS:
                if path in before["properties"]:
                    self.assertEqual(
                        review_fact(before["properties"], path),
                        review_fact(after["properties"], path),
                    )
        self.assertEqual(
            semantic(assess(bundle, self.catalog, at=AT, evidence_tiers=True)),
            semantic(assess(minimized, self.catalog, at=AT, evidence_tiers=True)),
        )
        self.assertEqual(self.config(bundle), self.config(minimized))
        self.assertNotIn(PRIVATE, json.dumps(minimized))
        for ip in ("10.0.0.4", "10.0.0.5"):
            self.assertNotIn(ip, json.dumps(minimized))
        directory = self.root / "replay"
        with self.assertRaises(InputError):
            export_bundle(directory, bundle, self.catalog, at=AT, evidence_tiers=True)
        accepted = load_catalog()
        export_bundle(directory, bundle, accepted, at=AT, evidence_tiers=True)
        self.assertEqual(
            semantic(replay_bundle(directory)),
            semantic(assess(bundle, accepted, at=AT, evidence_tiers=True)),
        )
        for row in self.catalog["controls"]:
            if row["upstream_guid"] in GUIDS:
                changed = copy.deepcopy(row)
                changed["evidence_requirements"].append("Changed specific decision")
                self.assertNotEqual(control_digest(row), control_digest(changed))

    @unittest.skipUnless(os.environ.get("BICEP_COMPILER"), "No existing Bicep compiler supplied")
    def test_real_bicep_vnet_routing_attachment_without_restore(self):
        path = ROOT / "tests/fixtures/topology/main.bicep"
        compiled = compile_bicep(path, compiler=os.environ["BICEP_COMPILER"])
        self.assertEqual(len(compiled["template"]["resources"]), 4)
        bundle = arm_source(path, scope=RG, bicep=True, compiler=os.environ["BICEP_COMPILER"])
        self.assertTrue(all(r["state"] == "known" for r in bundle["resources"]))
        child = next(r for r in bundle["resources"] if r["resource_type"].lower() == IPCONFIG)
        parent = next(r for r in bundle["resources"] if r["resource_type"].lower() == HUB)
        self.assertIs(parent["properties"]["hubBranchTrafficAllowed"], True)
        config = configuration_context(child, bundle, self.by_id(bundle))
        self.assertIs(
            config["configuredSubnets"][0]["currentRouteServerMinimumSize"]["matches"], True
        )
