import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from alz_assessor.arm import arm_source
from alz_assessor.arm import properties as arm_properties
from alz_assessor.azure import Collector, Response
from alz_assessor.bicep import compile_bicep
from alz_assessor.contracts import validate
from alz_assessor.engine import local_subchecks
from alz_assessor.expressroute_evidence import (
    PATHS,
    bandwidth,
    circuit_properties,
    fastpath_properties,
    location_configured,
    port_properties,
    port_reference,
    review_fact,
    scale_bounds,
)
from alz_assessor.network_evidence import review_fact as network_fact
from alz_assessor.plan import plan_source
from alz_assessor.replay import sanitize_evidence
from alz_assessor.reviews import review_context
from alz_assessor.sources import terraform_source, tf_properties, tf_resource_id
from alz_assessor.terraform import InputError, tree_hash

ROOT = Path(__file__).resolve().parents[1]
SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/expressroute"
PORT = SCOPE + "/providers/Microsoft.Network/expressRoutePorts/direct"
SENTINEL = "PRIVATE-NOT-FOR-REPORTING"
GUIDS = {
    "D06.04": "7025b442-f6e9-4af6-b11f-c9574916016f",
    "D06.05": "f4e7926a-ec35-476e-a412-5dd17136bd62",
    "D06.06": "2447ec66-138a-4720-8f1c-e16ed301d6e8",
    "D06.07": "72e52e36-11cc-458b-9a4b-1511e43a58a9",
    "D06.08": "c2299c4d-7b57-4d0c-9555-62f2b3e4563a",
    "D06.09": "4d873974-8b66-42d6-b15f-512a65498f6d",
    "D06.10": "45866df8-cf85-4ca9-bbe2-65ec1478919e",
    "D06.11": "718cb437-b060-2589-8856-2e93a5c6633b",
    "D06.12": "8042d88e-79d1-47b7-9b22-a5a67e7a8ed4",
}


class ExpressRoutePreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def circuit(self):
        return {
            "sku": [{"tier": "Local", "family": "UnlimitedData", "name": SENTINEL}],
            "express_route_port_id": PORT,
            "bandwidth_in_gbps": 10,
            "rate_limiting_enabled": True,
            "authorization_key": SENTINEL,
            "service_key": SENTINEL,
            "peerings": [{"shared_key": SENTINEL}],
        }

    def test_fixed_nine_guid_matrix_sources_and_no_activation(self):
        root = ROOT / "references" / "recommendation-batches"
        matrix = json.loads((root / "batch-14-preparation.json").read_text("utf-8"))
        targets = json.loads((root / "targets.json").read_text("utf-8"))["targets"]
        manifest = json.loads((root / "batch-14-sources.json").read_text("utf-8"))
        self.assertEqual(
            {t["upstream_id"]: t["guid"] for t in targets if t["batch"] == "14"}, GUIDS
        )
        self.assertEqual({r["upstream_id"]: r["guid"] for r in matrix["recommendations"]}, GUIDS)
        self.assertNotIn("catalog_version", matrix)
        self.assertNotIn("accepted_at", matrix)
        self.assertEqual(
            matrix["review_state"], "source-reviewed-preparation-not-accepted-or-delivered"
        )
        sources = {s["id"]: s for s in manifest["sources"]}
        self.assertEqual(len(sources), 26)
        for source in sources.values():
            self.assertRegex(source["sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(source["revision"], r"^[0-9a-f]{40}$")
            self.assertTrue(source["resolved_url"].startswith("https://"))
            self.assertTrue(source["finding"])
            self.assertTrue(source["reuse"])
        self.assertIn(
            "/well-architected/service-guides/azure-expressroute",
            sources["expressroute-architecture"]["resolved_url"],
        )
        for row in matrix["recommendations"]:
            self.assertEqual(row["classification"], "assisted")
            self.assertNotIn("rule", row)
            self.assertTrue(1 <= len(row["review_fact_paths"]) <= 8)
            self.assertTrue(set(row["sources"]) <= set(sources))
            self.assertTrue(row["limitations"])
            self.assertTrue(
                any(q.startswith("Reviewer decision:") for q in row["evidence_requirements"])
            )

    def test_numeric_bounds_preserve_units_and_no_boolean_or_nan_bandwidth(self):
        for value in (1, 1.5, 5, 10, 40, 100, 200, 400, 400.0):
            self.assertEqual(bandwidth(value, direct=True), value)
        for value in (1, 50, 100, 200, 500, 1000, 2000, 5000, 10000):
            self.assertEqual(bandwidth(value, direct=False), value)
        for value in (
            None,
            True,
            False,
            "10",
            0,
            -1,
            float("inf"),
            float("-inf"),
            float("nan"),
            401,
            10**400,
            {"unknown": SENTINEL},
        ):
            self.assertIn("unknown", bandwidth(value, direct=True))
        for value in (10.0, 10001, None, True, "100", 0):
            self.assertIn("unknown", bandwidth(value, direct=False))

    def test_direct_provider_facts_are_distinct_and_conflicts_do_not_select_a_path(self):
        direct = circuit_properties(self.circuit(), terraform=True)
        self.assertEqual(direct["directCircuitBandwidthGbps"], 10)
        self.assertEqual(direct["expressRoutePort"]["id"], PORT.lower())
        self.assertIn("unknown", direct["providerCircuitBandwidthMbps"])
        self.assertIn("unknown", direct["peeringLocationConfigured"])
        provider = {
            "sku": [{"tier": "Standard", "family": "MeteredData"}],
            "bandwidth_in_mbps": 500,
            "peering_location": "Amsterdam",
            "service_provider_name": SENTINEL,
        }
        prepared = circuit_properties(provider, terraform=True)
        self.assertEqual(prepared["providerCircuitBandwidthMbps"], 500)
        self.assertTrue(prepared["peeringLocationConfigured"])
        self.assertIn("unknown", prepared["directCircuitBandwidthGbps"])
        self.assertIn("unknown", prepared["expressRoutePort"]["id"])
        conflict = circuit_properties({**self.circuit(), **provider}, terraform=True)
        for path in (
            "providerCircuitBandwidthMbps",
            "directCircuitBandwidthGbps",
            "directPortRateLimit",
            "peeringLocationConfigured",
        ):
            self.assertIn("unknown", conflict[path])
        self.assertIn("unknown", conflict["expressRoutePort"]["id"])
        raw = {"bandwidthInGbps": 10, "serviceProviderProperties": {"bandwidthInMbps": 500}}
        conflict = circuit_properties(raw, terraform=False)
        self.assertIn("unknown", conflict["directCircuitBandwidthGbps"])
        self.assertNotIn(SENTINEL, json.dumps([direct, prepared, conflict]))

    def test_arm_root_sku_tf_single_block_and_missing_defaults(self):
        raw = {
            "bandwidthInGbps": 10,
            "expressRoutePort": {"id": PORT},
            "enableDirectPortRateLimit": True,
        }
        root = {"sku": {"tier": "Local", "family": "UnlimitedData"}}
        arm = circuit_properties(raw, terraform=False, root=root)
        self.assertEqual(arm, circuit_properties(self.circuit(), terraform=True))
        self.assertIn("unknown", circuit_properties(raw, terraform=False)["circuitSku"]["tier"])
        for sku in (None, [], [{}, {}], "Local", {"tier": "Local"}):
            values = {**self.circuit(), "sku": sku}
            self.assertIn(
                "unknown", circuit_properties(values, terraform=True)["circuitSku"]["tier"]
            )
        for value in (None, "Unlimited", "unlimiteddata", {"unknown": SENTINEL}):
            values = self.circuit()
            values["sku"][0]["family"] = value
            self.assertIn(
                "unknown", circuit_properties(values, terraform=True)["circuitSku"]["family"]
            )
        missing = circuit_properties({}, terraform=True)
        self.assertIn("unknown", missing["directPortRateLimit"])
        self.assertIn("unknown", missing["directCircuitBandwidthGbps"])

    def test_port_billing_capacity_encapsulation_are_only_configuration(self):
        for capacity in (10, 100, 400):
            raw = {
                "bandwidthInGbps": capacity,
                "billingType": "MeteredData",
                "encapsulation": "QinQ",
                "peeringLocation": "Amsterdam",
                "links": [{"properties": {"macSecConfig": {"cakSecretIdentifier": SENTINEL}}}],
            }
            facts = port_properties(raw, terraform=False)
            self.assertEqual(facts["directPortBandwidthGbps"], capacity)
            self.assertEqual(facts["directPortBillingType"], "MeteredData")
            self.assertEqual(facts["directPortEncapsulation"], "QinQ")
            self.assertTrue(facts["peeringLocationConfigured"])
            self.assertNotIn(SENTINEL, json.dumps(facts))
        for capacity in (None, True, 100.0, 200, 401, "100", {"unknown": SENTINEL}):
            self.assertIn(
                "unknown",
                port_properties({"bandwidthInGbps": capacity}, terraform=False)[
                    "directPortBandwidthGbps"
                ],
            )
        for location in (None, "", " ", "[parameters('place')]", "x\n", "x" * 129):
            self.assertIn("unknown", location_configured(location))
        defaults = port_properties({}, terraform=True)
        self.assertTrue(all("unknown" in value for value in defaults.values()))

    def test_port_relationships_and_review_projection_strip_untrusted_content(self):
        for value in (
            None,
            "",
            SENTINEL,
            SCOPE,
            PORT + "/links/link1",
            PORT.replace("Ports", "Circuits"),
        ):
            self.assertIn("unknown", port_reference(value))
        props = {
            **circuit_properties(self.circuit(), terraform=True),
            **port_properties(
                {"bandwidthInGbps": 100, "billingType": "UnlimitedData", "encapsulation": "Dot1Q"},
                terraform=False,
            ),
            **fastpath_properties({}, terraform=False),
        }
        clean = {path: review_fact(props, path) for path in PATHS}
        dirty = copy.deepcopy(props)
        dirty["circuitSku"]["name"] = SENTINEL
        dirty["sharedKey"] = SENTINEL
        self.assertEqual(clean, {path: review_fact(dirty, path) for path in PATHS})
        self.assertNotIn(SENTINEL, json.dumps(clean))
        with self.assertRaisesRegex(ValueError, "Unsupported ExpressRoute"):
            review_fact(props, "sharedKey")
        self.assertIn(
            "unknown",
            review_fact({"peeringLocationConfigured": False}, "peeringLocationConfigured"),
        )

    def test_fastpath_flags_are_separate_strict_and_not_eligibility(self):
        for bypass in (True, False):
            for private in (True, False):
                raw = {
                    "expressRouteGatewayBypass": bypass,
                    "enablePrivateLinkFastPath": private,
                    "sharedKey": SENTINEL,
                }
                facts = fastpath_properties(raw, terraform=False)
                self.assertEqual(
                    facts,
                    fastpath_properties(
                        {
                            "express_route_gateway_bypass": bypass,
                            "private_link_fast_path_enabled": private,
                        },
                        terraform=True,
                    ),
                )
                self.assertEqual(facts["expressRouteGatewayBypass"], bypass)
                self.assertEqual(facts["enablePrivateLinkFastPath"], private)
                self.assertEqual(len(facts), 2)
        for value in (None, 0, 1, "true", {"unknown": SENTINEL}):
            self.assertIn(
                "unknown",
                fastpath_properties({"expressRouteGatewayBypass": value}, terraform=False)[
                    "expressRouteGatewayBypass"
                ],
            )

    def test_raw_supplied_module_plan_types_sensitivity_and_scope(self):
        values = {
            "azurerm_express_route_circuit": {
                **self.circuit(),
                "name": "local",
                "resource_group_name": "expressroute",
            },
            "azurerm_express_route_port": {
                "name": "direct",
                "resource_group_name": "expressroute",
                "bandwidth_in_gbps": 100,
                "billing_type": "MeteredData",
                "encapsulation": "QinQ",
                "peering_location": "Amsterdam",
                "link1": [{"macsec_cak_keyvault_secret_id": SENTINEL}],
            },
        }
        module = self.root / "snapshots" / "expressroute"
        self.write(
            "snapshots/expressroute/main.tf.json",
            {"resource": {kind: {"test": body} for kind, body in values.items()}},
        )
        self.write(
            "source/main.tf.json",
            {
                "module": {
                    "expressroute": {"source": "example.invalid/alz/network", "version": "1.0"}
                }
            },
        )
        manifest = self.write(
            "snapshots/snapshots.json",
            {
                "modules": [
                    {
                        "source": "example.invalid/alz/network",
                        "version": "1.0",
                        "subdirectory": "",
                        "path": "expressroute",
                        "sha256": tree_hash(module),
                    }
                ]
            },
        )
        planned = {
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
        path = self.write("plan.json", planned)
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            raw = terraform_source(
                self.root / "source",
                scope=SCOPE,
                provider_version="4.50.0",
                snapshots=manifest,
                authorized_roots=[self.root],
            )
            plan = plan_source(path, scope=SCOPE, provider_version="4.50.0")
        for bundle in (raw, plan):
            self.assertNotIn(SENTINEL, json.dumps(bundle))
            resources = {r["resource_type"].lower(): r for r in bundle["resources"]}
            circuit = resources["microsoft.network/expressroutecircuits"]
            self.assertEqual(circuit["properties"]["directCircuitBandwidthGbps"], 10)
            self.assertEqual(circuit["properties"]["expressRoutePort"]["id"], PORT.lower())
            self.assertEqual(
                circuit["arm_id"],
                (SCOPE + "/providers/Microsoft.Network/expressRouteCircuits/local").lower(),
            )
            self.assertEqual(
                resources["microsoft.network/expressrouteports"]["properties"][
                    "directPortBandwidthGbps"
                ],
                100,
            )
            sanitized = sanitize_evidence(bundle)
            validate(sanitized, "evidence")
            projected = {r["resource_type"].lower(): r for r in sanitized["resources"]}
            self.assertEqual(
                projected[circuit["resource_type"].lower()]["properties"][
                    "directCircuitBandwidthGbps"
                ],
                10,
            )
            self.assertNotIn(SENTINEL, json.dumps(sanitized))
        planned["planned_values"]["root_module"]["resources"][0]["sensitive_values"] = {
            "bandwidth_in_gbps": True,
            "sku": True,
            "express_route_port_id": True,
        }
        path = self.write("plan.json", planned)
        hidden = plan_source(path, scope=SCOPE, provider_version="4.50.0")
        props = hidden["resources"][0]["properties"]
        self.assertIn("unknown", props["directCircuitBandwidthGbps"])
        self.assertIn("unknown", props["circuitSku"]["family"])
        self.assertIn("unknown", props["expressRoutePort"]["id"])
        unsupported = plan_source(path, scope=SCOPE, provider_version="4.49.0")
        self.assertTrue(all(r["state"] == "unknown" for r in unsupported["resources"]))
        with self.assertRaisesRegex(InputError, "outside the explicit assessment scope"):
            plan_source(
                path, scope=SCOPE.replace("expressroute", "another"), provider_version="4.50.0"
            )

    def test_arm_normalization_supported_version_replay_and_old_port_facts(self):
        template = {
            "resources": [
                {
                    "type": "Microsoft.Network/expressRouteCircuits",
                    "apiVersion": "2024-05-01",
                    "name": "local",
                    "sku": {"tier": "Local", "family": "UnlimitedData", "name": SENTINEL},
                    "properties": {
                        "bandwidthInGbps": 10,
                        "expressRoutePort": {"id": PORT},
                        "enableDirectPortRateLimit": True,
                        "authorizationKey": SENTINEL,
                    },
                },
                {
                    "type": "Microsoft.Network/expressRoutePorts",
                    "apiVersion": "2024-05-01",
                    "name": "direct",
                    "identity": {
                        "type": "UserAssigned",
                        "userAssignedIdentities": {
                            SCOPE + "/providers/Microsoft.ManagedIdentity/"
                            "userAssignedIdentities/fixture": {}
                        },
                    },
                    "properties": {
                        "bandwidthInGbps": 100,
                        "billingType": "MeteredData",
                        "encapsulation": "QinQ",
                        "peeringLocation": "Amsterdam",
                        "links": [
                            {
                                "properties": {
                                    "macSecConfig": {
                                        "cipher": "GcmAes256",
                                        "sciState": "Enabled",
                                        "cakSecretIdentifier": SENTINEL,
                                    }
                                }
                            }
                        ],
                    },
                },
            ],
        }
        bundle = arm_source(self.write("arm.json", template), scope=SCOPE)
        self.assertNotIn(SENTINEL, json.dumps(bundle))
        circuit, port = bundle["resources"]
        self.assertEqual(
            circuit["properties"], tf_properties("azurerm_express_route_circuit", self.circuit())
        )
        self.assertEqual(
            port["properties"]["macsecLinks"], [{"cipher": "GcmAes256", "sciState": "Enabled"}]
        )
        self.assertIn("identitySummary", port["properties"])
        port["properties"]["billingSecrets"] = SENTINEL
        projected = sanitize_evidence(bundle)
        self.assertEqual(projected["collected_at"], bundle["collected_at"])
        self.assertNotIn(SENTINEL, json.dumps(projected))
        self.assertEqual(
            projected["resources"][1]["properties"]["directPortBillingType"], "MeteredData"
        )
        self.assertEqual(
            projected["resources"][1]["properties"]["macsecLinks"],
            port["properties"]["macsecLinks"],
        )
        self.assertEqual(
            projected["resources"][1]["properties"]["identitySummary"],
            port["properties"]["identitySummary"],
        )
        template["resources"][0]["apiVersion"] = "2024-07-01"
        unsupported = arm_source(self.write("unsupported.json", template), scope=SCOPE)
        self.assertEqual(unsupported["resources"][0]["state"], "unknown")

    def test_injected_circuit_detail_root_sku_denied_partial_and_no_extra_reads(self):
        identity = SCOPE + "/providers/Microsoft.Network/expressRouteCircuits/local"
        detail = {
            "id": identity,
            "type": "Microsoft.Network/expressRouteCircuits",
            "sku": {"tier": "Local", "family": "UnlimitedData"},
            "properties": {
                "bandwidthInGbps": 10,
                "expressRoutePort": {"id": PORT},
                "serviceKey": SENTINEL,
                "peerings": [{"properties": {"primaryPeerAddressPrefix": SENTINEL}}],
            },
        }
        requests = []

        def transport(method, url):
            requests.append((method, url))
            if method == "POST":
                self.assertIn("/policyStates/latest/queryResults?", url)
                return Response(200, {"value": []}, {})
            self.assertEqual(method, "GET")
            if "/resources?" in url:
                return Response(200, {"value": [{"id": identity, "type": detail["type"]}]}, {})
            if "/expressroutecircuits/" in url.lower():
                self.assertIn("api-version=2024-05-01", url)
                return Response(200, detail, {})
            return Response(200, {"value": []}, {})

        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            observed = Collector(transport).collect(
                subscriptions=["00000000-0000-0000-0000-000000000001"],
                inventory_authorized=True,
            )
        props = observed["resources"][0]["properties"]
        self.assertEqual(props["circuitSku"]["family"], "UnlimitedData")
        self.assertEqual(props["directCircuitBandwidthGbps"], 10)
        self.assertNotIn(SENTINEL, json.dumps(sanitize_evidence(observed)))
        self.assertFalse(any("/expressrouteports/" in url.lower() for _, url in requests))
        original_time = observed["collected_at"]

        def denied(method, url):
            if "/expressroutecircuits/" in url.lower():
                return Response(403, {}, {})
            return transport(method, url)

        observed = Collector(denied).collect(
            subscriptions=["00000000-0000-0000-0000-000000000001"],
            inventory_authorized=True,
        )
        self.assertEqual(observed["resources"][0]["state"], "inaccessible")
        self.assertFalse(observed["resources"][0]["properties"])
        detail["properties"] = {}
        partial = Collector(transport).collect(
            subscriptions=["00000000-0000-0000-0000-000000000001"],
            inventory_authorized=True,
        )
        self.assertIn(
            "unknown", partial["resources"][0]["properties"]["directCircuitBandwidthGbps"]
        )
        self.assertIn("unknown", partial["resources"][0]["properties"]["expressRoutePort"]["id"])
        self.assertTrue(original_time)

    def test_merged_gateway_fields_fastpath_minimum_and_provider_support_boundary(self):
        public = SCOPE + "/providers/Microsoft.Network/publicIPAddresses/gateway"
        raw = {
            "gatewayType": "ExpressRoute",
            "sku": {"name": "ErGwScale"},
            "enableBgp": True,
            "activeActive": False,
            "autoScaleConfiguration": {"bounds": {"min": 10, "max": 40}},
            "ipConfigurations": [{"properties": {"publicIPAddress": {"id": public}}}],
        }
        props = arm_properties("Microsoft.Network/virtualNetworkGateways", raw)
        self.assertEqual(props["gatewaySku"], "ErGwScale")
        self.assertEqual(props["gatewayType"], "ExpressRoute")
        self.assertEqual(props["enableBgp"], True)
        self.assertEqual(props["activeActive"], False)
        self.assertEqual(props["gatewayScaleBounds"], {"min": 10, "max": 40})
        self.assertEqual(props["gatewayPublicIpReferences"], [public.lower()])
        key = "configured_gateway_meets_fastpath_sku_and_minimum_scale_requirement"
        for sku, bounds, expected in (
            ("UltraPerformance", None, True),
            ("ErGw3AZ", None, True),
            ("ErGw2AZ", None, False),
            ("Standard", None, False),
            ("ErGwScale", {"min": 9, "max": 40}, False),
            ("ErGwScale", {"min": 10, "max": 40}, True),
            ("ErGwScale", {"min": 10, "max": 10}, True),
            ("ErGwScale", None, None),
        ):
            check = local_subchecks({**props, "gatewaySku": sku, "gatewayScaleBounds": bounds})[key]
            self.assertIn("unknown", check) if expected is None else self.assertEqual(
                check, expected
            )
        self.assertFalse(local_subchecks({**props, "gatewayType": "Vpn"})[key])
        for bounds in (
            {},
            None,
            {"min": True, "max": 10},
            {"min": "10", "max": 10},
            {"min": 0, "max": 40},
            {"min": 1, "max": 40},
            {"min": 10, "max": 9},
            {"min": 10, "max": 41},
        ):
            self.assertIn("unknown", scale_bounds(bounds))
        self.assertEqual(scale_bounds({"min": 1, "max": 1}), {"min": 1, "max": 1})
        tf = tf_properties(
            "azurerm_virtual_network_gateway",
            {
                "type": "ExpressRoute",
                "sku": "ErGwScale",
                "autoScaleConfiguration": raw["autoScaleConfiguration"],
                "ip_configuration": [{"public_ip_address_id": public}],
            },
        )
        self.assertIn("unknown", tf["gatewaySku"])
        self.assertIn("unknown", tf["gatewayScaleBounds"])
        self.assertEqual(tf["gatewayPublicIpReferences"], [public.lower()])
        for flags, expected in (
            ({"expressRouteGatewayBypass": True, "enablePrivateLinkFastPath": True}, True),
            ({"expressRouteGatewayBypass": False, "enablePrivateLinkFastPath": True}, False),
            ({"expressRouteGatewayBypass": False, "enablePrivateLinkFastPath": False}, True),
        ):
            check = local_subchecks(flags)["configured_private_link_fastpath_flags_are_consistent"]
            self.assertEqual(check, expected)
        self.assertIn(
            "unknown",
            local_subchecks({"expressRouteGatewayBypass": True})[
                "configured_private_link_fastpath_flags_are_consistent"
            ],
        )

    def test_reused_connection_gateway_review_links_are_unique_known_and_original_time(self):
        gateway = SCOPE + "/providers/Microsoft.Network/virtualNetworkGateways/gateway"
        public = SCOPE + "/providers/Microsoft.Network/publicIPAddresses/gateway"
        template = {
            "resources": [
                {
                    "type": "Microsoft.Network/connections",
                    "name": "connection",
                    "apiVersion": "2024-05-01",
                    "properties": {
                        "connectionType": "ExpressRoute",
                        "virtualNetworkGateway1": {"id": gateway},
                        "peer": {
                            "id": SCOPE + "/providers/Microsoft.Network/expressRouteCircuits/local"
                        },
                        "expressRouteGatewayBypass": True,
                        "enablePrivateLinkFastPath": True,
                        "routingWeight": 10,
                        "sharedKey": SENTINEL,
                    },
                },
                {
                    "type": "Microsoft.Network/virtualNetworkGateways",
                    "name": "gateway",
                    "apiVersion": "2024-05-01",
                    "properties": {
                        "gatewayType": "ExpressRoute",
                        "sku": {"name": "ErGwScale"},
                        "autoScaleConfiguration": {"bounds": {"min": 10, "max": 10}},
                        "ipConfigurations": [{"properties": {"publicIPAddress": {"id": public}}}],
                    },
                },
                {
                    "type": "Microsoft.Network/publicIPAddresses",
                    "name": "gateway",
                    "apiVersion": "2024-05-01",
                    "sku": {"name": "Standard"},
                    "zones": ["1", "2", "3"],
                    "properties": {"ipAddress": SENTINEL, "dnsSettings": {"fqdn": SENTINEL}},
                },
            ]
        }
        bundle = arm_source(self.write("hybrid.json", template), scope=SCOPE)
        row = next(
            r
            for r in json.loads(
                (
                    ROOT / "references" / "recommendation-batches" / "batch-14-preparation.json"
                ).read_text()
            )["recommendations"]
            if r["upstream_id"] == "D06.08"
        )
        control = {
            "upstream_guid": row["guid"],
            "review_fact_paths": row["review_fact_paths"],
            "review_resource_types": row["review_resource_types"],
        }
        context = review_context(control, bundle)
        connection = context["resources"][0]
        self.assertEqual(
            connection["facts"]["expressRouteCircuitId"],
            template["resources"][0]["properties"]["peer"]["id"].lower(),
        )
        linked = connection["linked_gateway"]
        self.assertEqual(linked["facts"]["gatewaySku"], "ErGwScale")
        self.assertEqual(linked["public_ips"][0]["publicIpSku"], "Standard")
        self.assertEqual(linked["public_ips"][0]["configuredZones"], ["1", "2", "3"])
        self.assertTrue(
            linked["subchecks"][
                "configured_gateway_meets_fastpath_sku_and_minimum_scale_requirement"
            ]
        )
        self.assertNotIn(SENTINEL, json.dumps(context))
        projected = sanitize_evidence(bundle)
        self.assertEqual(projected["collected_at"], bundle["collected_at"])
        replay_context = review_context(control, projected)
        self.assertEqual(replay_context["resources"][0]["linked_gateway"], linked)
        bad = copy.deepcopy(bundle)
        bad["resources"].append(copy.deepcopy(bad["resources"][1]))
        bad["resources"][-1]["logical_id"] = "duplicate.gateway"
        with self.assertRaisesRegex(InputError, "Duplicate or ambiguous ARM resource identity"):
            review_context(control, bad)
        bad = copy.deepcopy(bundle)
        bad["resources"][1]["state"] = "inaccessible"
        bad["resources"][1]["reason"] = "access_denied"
        self.assertIn("unknown", review_context(control, bad)["resources"][0]["linked_gateway"])
        bad = copy.deepcopy(bundle)
        bad["resources"][2]["state"] = "inaccessible"
        bad["resources"][2]["reason"] = "access_denied"
        self.assertIn(
            "unknown",
            review_context(control, bad)["resources"][0]["linked_gateway"]["public_ips"][0],
        )
        bad = copy.deepcopy(bundle)
        bad["resources"][1]["properties"]["gatewayPublicIpReferences"] = {"unknown": "not_supplied"}
        self.assertIn(
            "unknown", review_context(control, bad)["resources"][0]["linked_gateway"]["public_ips"]
        )
        self.assertIn(
            "unknown", network_fact({"gatewayPublicIpReferences": []}, "gatewayPublicIpReferences")
        )

    @unittest.skipUnless(os.environ.get("BICEP_COMPILER"), "existing Bicep compiler not supplied")
    def test_real_bicep_expressroute_cost_capacity_fastpath_without_restore(self):
        source = ROOT / "tests" / "fixtures" / "expressroute" / "main.bicep"
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch("socket.socket.connect", side_effect=AssertionError("network forbidden")),
        ):
            copied = Path(temporary) / "main.bicep"
            copied.write_bytes(source.read_bytes())
            compiled = compile_bicep(copied, compiler=os.environ["BICEP_COMPILER"])
        resources = {row["name"]: row for row in compiled["template"]["resources"]}
        local = circuit_properties(
            resources["local"]["properties"], terraform=False, root=resources["local"]
        )
        provider = circuit_properties(
            resources["provider"]["properties"], terraform=False, root=resources["provider"]
        )
        port = port_properties(resources["direct"]["properties"], terraform=False)
        flags = fastpath_properties(resources["fastpath"]["properties"], terraform=False)
        self.assertEqual(local["circuitSku"], {"tier": "Local", "family": "UnlimitedData"})
        self.assertEqual(local["directCircuitBandwidthGbps"], 10)
        self.assertEqual(provider["providerCircuitBandwidthMbps"], 500)
        self.assertEqual(port["directPortBandwidthGbps"], 100)
        self.assertEqual(port["directPortBillingType"], "MeteredData")
        self.assertEqual(
            flags, {"expressRouteGatewayBypass": True, "enablePrivateLinkFastPath": True}
        )
        normalized = arm_source(
            source, scope=SCOPE, bicep=True, compiler=os.environ["BICEP_COMPILER"]
        )
        by_id = {r["arm_id"]: r for r in normalized["resources"]}
        base = (SCOPE + "/providers/Microsoft.Network/").lower()
        self.assertEqual(
            by_id[base + "expressroutecircuits/local"]["properties"]["expressRoutePort"]["id"],
            PORT.lower(),
        )
        self.assertEqual(
            by_id[base + "expressroutecircuits/provider"]["properties"][
                "providerCircuitBandwidthMbps"
            ],
            500,
        )
        self.assertEqual(
            by_id[base + "expressrouteports/direct"]["properties"]["directPortBandwidthGbps"], 100
        )
        self.assertEqual(
            by_id[base + "virtualnetworkgateways/gateway"]["properties"]["gatewaySku"], "ErGwScale"
        )
        self.assertEqual(
            by_id[base + "virtualnetworkgateways/gateway"]["properties"]["gatewayScaleBounds"],
            {"min": 10, "max": 10},
        )
        self.assertTrue(
            by_id[base + "connections/fastpath"]["properties"]["expressRouteGatewayBypass"]
        )
        self.assertEqual(before, hashlib.sha256(source.read_bytes()).hexdigest())
