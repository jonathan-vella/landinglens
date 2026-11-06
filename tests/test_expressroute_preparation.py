import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from alz_assessor.bicep import compile_bicep
from alz_assessor.expressroute_evidence import (
    PATHS,
    bandwidth,
    circuit_properties,
    fastpath_properties,
    location_configured,
    port_properties,
    port_reference,
    review_fact,
)

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
        self.assertEqual(len(sources), 25)
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
        self.assertEqual(before, hashlib.sha256(source.read_bytes()).hexdigest())
