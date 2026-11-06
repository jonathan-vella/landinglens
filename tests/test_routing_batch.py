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

from alz_assessor.arm import arm_source, properties
from alz_assessor.azure import Collector, Response
from alz_assessor.catalog import load_catalog
from alz_assessor.comparison import compare
from alz_assessor.contracts import control_digest, document, validate
from alz_assessor.engine import assess, local_subchecks
from alz_assessor.network_evidence import review_fact
from alz_assessor.plan import plan_source
from alz_assessor.replay import export_bundle, replay_bundle, semantic
from alz_assessor.reports import render, render_xlsx
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import prepare_reviews
from alz_assessor.sources import terraform_source, tf_properties
from alz_assessor.terraform import InputError, tree_hash

SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/routing"
NETWORK = SCOPE + "/providers/Microsoft.Network/"
TABLE = NETWORK + "routeTables/table"
VNET = NETWORK + "virtualNetworks/local"
PEERING = VNET + "/virtualNetworkPeerings/remote"
AT = "2026-11-06T07:55:30Z"
SENTINEL = "PRIVATE-NOT-FOR-REPORTING"
KEYS = (
    "D01.12",
    "D01.13",
    "D01.14",
    "D01.15",
    "D02.01",
    "D02.02",
    "D02.03",
    "D03.01",
    "D03.02",
    "D03.03",
)


class RoutingBatchTests(unittest.TestCase):
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

    def routes(self, count):
        return {
            "provisioningState": "Succeeded",
            "routes": [
                {
                    "name": f"r{i}",
                    "properties": {
                        "addressPrefix": f"10.{i // 256}.{i % 256}.0/24",
                        "nextHopType": "VirtualAppliance",
                        "nextHopIpAddress": SENTINEL,
                        "description": SENTINEL,
                    },
                }
                for i in range(count)
            ],
        }

    def record(self, kind, identity, raw, root=None):
        return {
            "logical_id": identity.lower(),
            "arm_id": identity.lower(),
            "resource_type": kind,
            "state": "known",
            "reason": "",
            "source_location": "fixture://explicit-detail",
            "properties": properties(kind, raw, root=root, observed=True),
        }

    def bundle(self, count=401, access=True):
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
                self.record("Microsoft.Network/routeTables", TABLE, self.routes(count)),
                self.record(
                    "Microsoft.Network/virtualNetworks/virtualNetworkPeerings",
                    PEERING,
                    {
                        "allowVirtualNetworkAccess": access,
                        "remoteVirtualNetwork": {"id": NETWORK + "virtualNetworks/remote"},
                    },
                ),
            ],
        )

    def row(self, bundle, key):
        return next(
            r for r in assess(bundle, self.catalog, at=AT)["results"] if r["upstream_id"] == key
        )

    def test_exact_prior_history_matrix_membership_and_meanings(self):
        root = files("alz_assessor").joinpath("data")
        prior = root.joinpath("catalog-2026-11-06.1.json").read_bytes()
        self.assertEqual(
            hashlib.sha256(prior).hexdigest(),
            "5b7cd54ac21f525ef3dd5bbb6544dc96a821dbf7d2ab34c25bc45e2335f68603",
        )
        before = {c["upstream_guid"]: c for c in json.loads(prior)["controls"]}
        matrix = json.loads(root.joinpath("batch-matrix-2026-11-06.2.json").read_text())
        batch, sources = matrix["batches"][-1], matrix["sources"][-1]["sources"]
        self.assertEqual(batch["batch"], "11")
        self.assertEqual(batch["prerequisites"], ["19"])
        self.assertEqual({r["upstream_id"] for r in batch["recommendations"]}, set(KEYS))
        self.assertEqual(len(sources), 21)
        changed = {r["guid"] for r in batch["recommendations"]}
        for control in self.catalog["controls"]:
            if control["upstream_guid"] not in changed:
                self.assertEqual(
                    control_digest(control), control_digest(before[control["upstream_guid"]])
                )
        self.assertEqual(len(self.catalog["controls"]), 255)
        self.assertEqual(
            Counter(c["automation"] for c in self.catalog["controls"]),
            {"automated": 10, "assisted": 202, "manual": 43},
        )

    def test_observed_route_threshold_and_explicit_complete_population(self):
        for count in (0, 399, 400, 401, 1000):
            with self.subTest(count=count):
                bundle = self.bundle(count)
                row = self.row(bundle, "D01.12")["observed"]
                self.assertEqual(row["fact"], count)
                self.assertEqual(row["outcome"], "pass" if count <= 400 else "fail")
                self.assertEqual(
                    row["reason"],
                    "within_checklist_route_target"
                    if count <= 400
                    else "exceeds_checklist_route_target",
                )
                self.assertFalse(row["inventory_complete"])
        for routes in (None, {}, [None], [{}], self.routes(1001)["routes"]):
            raw = self.routes(0)
            raw["routes"] = routes
            self.assertIn(
                "unknown",
                properties("Microsoft.Network/routeTables", raw, observed=True)["routeCount"],
            )
        for state in (None, "Updating", "Failed", True):
            raw = self.routes(0)
            raw["provisioningState"] = state
            self.assertIn(
                "unknown",
                properties("Microsoft.Network/routeTables", raw, observed=True)["routeCount"],
            )
        raw = self.routes(2)
        raw["routes"][1]["name"] = "R0"
        self.assertIn(
            "unknown", properties("Microsoft.Network/routeTables", raw, observed=True)["routeCount"]
        )
        for field, value in (
            ("addressPrefix", {}),
            ("nextHopType", "unknown"),
            ("provisioningState", "Updating"),
        ):
            raw = self.routes(1)
            raw["routes"][0]["properties"][field] = value
            self.assertIn(
                "unknown",
                properties("Microsoft.Network/routeTables", raw, observed=True)["routeCount"],
            )
        for count in (True, "400", 400.0, -1, 1001, {}, None):
            bundle = self.bundle()
            bundle["resources"][0]["properties"]["routeCount"] = count
            self.assertEqual(self.row(bundle, "D01.12")["observed"]["outcome"], "unknown")

    def test_route_planned_stale_denied_missing_and_contract_guards(self):
        self.assertIn(
            "unknown", properties("Microsoft.Network/routeTables", self.routes(0))["routeCount"]
        )
        planned = self.bundle(0)
        planned["mode"] = "planned"
        self.assertEqual(self.row(planned, "D01.12")["planned"]["outcome"], "unknown")
        for state, outcome in (
            ("inaccessible", "unknown"),
            ("unknown", "unknown"),
            ("error", "error"),
        ):
            bundle = self.bundle(0)
            bundle["resources"][0].update(state=state, reason="resource_configuration_unavailable")
            self.assertEqual(self.row(bundle, "D01.12")["observed"]["outcome"], outcome)
        stale = self.bundle(0)
        stale["collected_at"] = "2000-01-01T00:00:00Z"
        self.assertEqual(self.row(stale, "D01.12")["observed"]["reason"], "stale_evidence")
        for expected in (True, 399, 401, "400"):
            catalog = copy.deepcopy(self.catalog)
            next(c for c in catalog["controls"] if c["upstream_id"] == "D01.12")["rule"][
                "expected"
            ] = expected
            with self.assertRaisesRegex(InputError, "observed route"):
                validate(catalog, "catalog")
        missing = self.bundle()
        missing["resources"] = []
        self.assertEqual(self.row(missing, "D01.12")["observed"]["outcome"], "unknown")
        missing["inventory_complete"] = True
        self.assertEqual(self.row(missing, "D01.12")["observed"]["outcome"], "not_applicable")

    def test_peering_boolean_is_explicit_per_direction_and_no_default(self):
        for access, outcome in (
            (True, "pass"),
            (False, "fail"),
            (None, "unknown"),
            ("true", "unknown"),
            (1, "unknown"),
            ({}, "unknown"),
        ):
            self.assertEqual(
                self.row(self.bundle(access=access), "D01.13")["observed"]["outcome"], outcome
            )
        self.assertIn(
            "unknown",
            tf_properties("azurerm_virtual_network_peering", {})["allowVirtualNetworkAccess"],
        )
        self.assertIn(
            "unknown",
            properties("Microsoft.Network/virtualNetworks/virtualNetworkPeerings", {})[
                "allowVirtualNetworkAccess"
            ],
        )
        planned = self.bundle(access=False)
        planned["mode"] = "planned"
        result = compare(
            assess(planned, self.catalog, at=AT),
            assess(self.bundle(access=True), self.catalog, at=AT),
            at=AT,
        )
        self.assertEqual(
            next(r for r in result["results"] if r["upstream_id"] == "D01.13")["comparison"],
            "drift",
        )
        self.assertEqual(
            next(r for r in result["results"] if r["upstream_id"] == "D01.12")["comparison"],
            "not_comparable",
        )

    def test_backend_and_frontend_context_is_minimized_not_resilience(self):
        kind = "Microsoft.Network/loadBalancers"
        raw = {
            "frontendIPConfigurations": [
                {
                    "zones": ["1", "2", "3"],
                    "properties": {
                        "privateIPAddress": SENTINEL,
                        "publicIPAddress": {"id": NETWORK + "publicIPAddresses/ip"},
                        "subnet": {"id": VNET + "/subnets/workload"},
                    },
                }
            ],
            "backendAddressPools": [
                {
                    "properties": {
                        "loadBalancerBackendAddresses": [
                            {"name": SENTINEL, "properties": {"ipAddress": SENTINEL}}
                        ]
                        * 2,
                        "backendIPConfigurations": [
                            {"id": NETWORK + "networkInterfaces/nic/ipConfigurations/one"}
                        ],
                    }
                }
            ],
        }
        props = properties(kind, raw, root={"sku": {"name": "Standard"}})
        self.assertEqual(props["loadBalancerSku"], "Standard")
        self.assertEqual(props["frontendSummary"][0]["zones"], ["1", "2", "3"])
        self.assertEqual(props["backendSummary"][0]["suppliedAddressCount"], 2)
        self.assertNotIn(SENTINEL, json.dumps(props))
        self.assertIn("unknown", tf_properties("azurerm_lb", {"sku": "Standard"})["backendSummary"])
        for field, value in (("frontendSummary", [{}] * 21), ("backendSummary", [{}] * 101)):
            self.assertIn("unknown", review_fact({field: value}, field))
        bundle = self.bundle()
        bundle["resources"].append(
            self.record(kind, NETWORK + "loadBalancers/lb", raw, root={"sku": {"name": "Standard"}})
        )
        for key in ("D01.14", "D01.15"):
            self.assertEqual(self.row(bundle, key)["observed"]["outcome"], "manual")

    def test_macsec_and_ipsec_are_config_only_without_secret_identifiers(self):
        raw = {
            "links": [
                {
                    "properties": {
                        "macSecConfig": {
                            "cipher": "GcmAesXpn256",
                            "sciState": "Enabled",
                            "cakSecretIdentifier": SENTINEL,
                            "cknSecretIdentifier": SENTINEL,
                        }
                    }
                }
            ]
            * 2
        }
        props = properties("Microsoft.Network/expressRoutePorts", raw)
        self.assertEqual(props["macsecLinks"][0]["cipher"], "GcmAesXpn256")
        self.assertNotIn(SENTINEL, json.dumps(props))
        tf = tf_properties(
            "azurerm_express_route_port",
            {
                "link1": [
                    {
                        "macsec_cipher": "GcmAes256",
                        "macsec_sci_enabled": True,
                        "macsec_ckn_keyvault_secret_id": SENTINEL,
                    }
                ],
                "link2": [{"macsec_cipher": "GcmAes128", "macsec_sci_enabled": False}],
            },
        )
        self.assertEqual(len(tf["macsecLinks"]), 2)
        self.assertNotIn(SENTINEL, json.dumps(tf))
        self.assertIn("unknown", tf_properties("azurerm_express_route_port", {})["macsecLinks"])
        connection = tf_properties(
            "azurerm_virtual_network_gateway_connection",
            {
                "type": "IPsec",
                "local_azure_ip_address_enabled": True,
                "virtual_network_gateway_id": NETWORK + "virtualNetworkGateways/vpn",
                "shared_key": SENTINEL,
                "authorization_key": SENTINEL,
            },
        )
        self.assertIs(connection["useLocalAzureIpAddress"], True)
        self.assertEqual(connection["connectionType"], "IPsec")
        self.assertNotIn(SENTINEL, json.dumps(connection))
        self.assertIn(
            "unknown", properties("Microsoft.Network/connections", {})["useLocalAzureIpAddress"]
        )

    def test_strict_rfc1918_and_bounded_local_overlap_without_global_claim(self):
        for prefix, expected in (
            ("10.0.0.0/8", True),
            ("172.16.0.0/12", True),
            ("192.168.0.0/16", True),
            ("100.64.0.0/10", False),
            ("127.0.0.0/8", False),
            ("169.254.0.0/16", False),
            ("192.0.2.0/24", False),
            ("8.0.0.0/8", False),
            ("0.0.0.0/0", False),
        ):
            result = local_subchecks({"virtualNetworkPrefixes": [prefix]})
            self.assertIs(result["supplied_vnet_ipv4_prefixes_are_rfc1918"], expected)
        result = local_subchecks({"virtualNetworkPrefixes": ["10.0.0.0/16", "10.0.0.0/24"]})
        self.assertIs(result["supplied_vnet_ipv4_prefixes_do_not_overlap"], False)
        for value in (
            None,
            [],
            ["10.0.0.1/24"],
            ["2001:db8::/64"],
            ["10.0.0.0/24"] * 101,
            [{"unknown": "required"}],
        ):
            self.assertIn(
                "unknown",
                local_subchecks({"virtualNetworkPrefixes": value})[
                    "supplied_vnet_ipv4_prefixes_are_rfc1918"
                ],
            )
        props = tf_properties("azurerm_virtual_network", {"address_space": ["10.0.0.0/24"]})
        self.assertEqual(props["virtualNetworkPrefixes"], ["10.0.0.0/24"])

    def test_tiers_all_exports_original_time_replay_and_blank_decisions(self):
        bundle = self.bundle()
        report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        for key in ("D01.12", "D01.13"):
            row = next(r for r in report["results"] if r["upstream_id"] == key)
            self.assertEqual(row["observed"]["evidence_tier"], "verified")
        self.assertEqual(report["evidence_tiers"]["counts"]["verified"], 2)
        for format in ("json", "markdown", "html", "csv", "sarif", "pr-summary"):
            self.assertNotIn(SENTINEL, render(report, format))
        self.assertTrue(render_xlsx(report).startswith(b"PK"))
        export_bundle(self.root / "replay", bundle, self.catalog, at=AT, evidence_tiers=True)
        replay = replay_bundle(self.root / "replay")
        self.assertEqual(semantic(replay), semantic(report))
        self.assertEqual(replay["evidence"][0]["collected_at"], AT)
        unresolved = assess(self.bundle(access=False), self.catalog, at=AT, evidence_tiers=True)
        prepared = prepare_reviews(unresolved, self.catalog, list(KEYS), SCOPE)
        self.assertEqual(len(prepared["entries"]), 10)
        for row in prepared["entries"]:
            for key in (
                "reviewer",
                "outcome",
                "rationale",
                "evidence",
                "valid_from",
                "valid_until",
            ):
                self.assertIsNone(row[key])
        self.assertEqual(
            ReviewSession(bundle, self.catalog, self.root / "reviews").state()["records"], []
        )

    def tf_values(self):
        return {
            "azurerm_route_table": {"name": "table", "resource_group_name": "routing", "route": []},
            "azurerm_virtual_network_peering": {
                "name": "remote",
                "resource_group_name": "routing",
                "virtual_network_name": "local",
                "allow_virtual_network_access": True,
                "remote_virtual_network_id": NETWORK + "virtualNetworks/remote",
            },
            "azurerm_lb": {
                "name": "lb",
                "resource_group_name": "routing",
                "sku": "Standard",
                "frontend_ip_configuration": [{"name": "frontend", "zones": ["1", "2", "3"]}],
            },
            "azurerm_express_route_port": {
                "name": "port",
                "resource_group_name": "routing",
                "link1": [{"macsec_cipher": "GcmAes256", "macsec_sci_enabled": True}],
                "link2": [{"macsec_cipher": "GcmAes256", "macsec_sci_enabled": True}],
            },
            "azurerm_virtual_network_gateway_connection": {
                "name": "vpn",
                "resource_group_name": "routing",
                "type": "IPsec",
                "local_azure_ip_address_enabled": True,
                "shared_key": SENTINEL,
            },
            "azurerm_virtual_network": {
                "name": "local",
                "resource_group_name": "routing",
                "address_space": ["10.0.0.0/24"],
            },
        }

    def test_supplied_module_and_plan_all_types_sensitive_and_version_guards(self):
        values = self.tf_values()
        module = self.root / "snapshots" / "routing"
        self.write(
            "snapshots/routing/main.tf.json",
            {"resource": {kind: {"test": body} for kind, body in values.items()}},
        )
        self.write(
            "source/main.tf.json",
            {
                "module": {
                    "routing": {"source": "example.invalid/alz/routing/azurerm", "version": "1.0.0"}
                }
            },
        )
        manifest = self.write(
            "snapshots/snapshots.json",
            {
                "modules": [
                    {
                        "source": "example.invalid/alz/routing/azurerm",
                        "version": "1.0.0",
                        "subdirectory": "",
                        "path": "routing",
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
                                "values": body,
                            }
                            for kind, body in values.items()
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
            bundle["collected_at"] = AT
            self.assertEqual(len(bundle["resources"]), 6)
            self.assertNotIn(SENTINEL, json.dumps(bundle))
            self.assertEqual(self.row(bundle, "D01.13")["planned"]["outcome"], "pass")
            self.assertEqual(self.row(bundle, "D01.12")["planned"]["outcome"], "unknown")
        unsupported = plan_source(plan, scope=SCOPE, provider_version="4.49.0")
        self.assertTrue(all(r["state"] == "unknown" for r in unsupported["resources"]))
        doc = json.loads(plan.read_text())
        doc["planned_values"]["root_module"]["resources"][1]["sensitive_values"] = {
            "allow_virtual_network_access": True
        }
        plan.write_text(json.dumps(doc), encoding="utf-8")
        planned = plan_source(plan, scope=SCOPE, provider_version="4.50.0")
        planned["collected_at"] = AT
        self.assertEqual(self.row(planned, "D01.13")["planned"]["outcome"], "unknown")

    def test_injected_scoped_detail_reads_and_denial_not_capacity_pass(self):
        details = [
            {"id": TABLE, "type": "Microsoft.Network/routeTables", "properties": self.routes(400)},
            {
                "id": PEERING,
                "type": "Microsoft.Network/virtualNetworks/virtualNetworkPeerings",
                "properties": {"allowVirtualNetworkAccess": False},
            },
            {
                "id": NETWORK + "loadBalancers/lb",
                "type": "Microsoft.Network/loadBalancers",
                "sku": {"name": "Standard"},
                "properties": {"frontendIPConfigurations": [], "backendAddressPools": []},
            },
            {
                "id": NETWORK + "expressRoutePorts/port",
                "type": "Microsoft.Network/expressRoutePorts",
                "properties": {"links": []},
            },
            {
                "id": NETWORK + "connections/vpn",
                "type": "Microsoft.Network/connections",
                "properties": {"connectionType": "IPsec", "sharedKey": SENTINEL},
            },
        ]
        requests = []

        def transport(method, url):
            requests.append((method, url))
            if "/resources?" in url:
                return Response(
                    200, {"value": [{"id": r["id"], "type": r["type"]} for r in details]}, {}
                )
            for detail in details:
                if url.split("?")[0].lower().endswith(detail["id"].lower()):
                    self.assertEqual(method, "GET")
                    self.assertIn("api-version=2024-05-01", url)
                    return Response(200, detail, {})
            return Response(200, {"value": []}, {})

        bundle = Collector(transport).collect(
            subscriptions=["00000000-0000-0000-0000-000000000001"], inventory_authorized=True
        )
        self.assertEqual(bundle["resources"][0]["properties"]["routeCount"], 400)
        self.assertEqual(bundle["resources"][2]["properties"]["loadBalancerSku"], "Standard")
        self.assertNotIn(SENTINEL, json.dumps(bundle))
        self.assertTrue(all(url.startswith("https://management.azure.com/") for _, url in requests))

        def denied(method, url):
            if "/routetables/" in url.lower():
                return Response(403, {}, {})
            return transport(method, url)

        bundle = Collector(denied).collect(
            subscriptions=["00000000-0000-0000-0000-000000000001"], inventory_authorized=True
        )
        bundle.update(collected_at=AT, scope=SCOPE)
        self.assertEqual(self.row(bundle, "D01.12")["observed"]["outcome"], "unknown")

    @unittest.skipUnless(os.environ.get("BICEP_COMPILER"), "Existing Bicep compiler unavailable")
    def test_real_bicep_routing_peering_lb_macsec_connection_no_restore(self):
        source = self.root / "main.bicep"
        source.write_text(
            f"""
resource table 'Microsoft.Network/routeTables@2024-05-01' = {{
  name: 'table'
  location: 'westeurope'
  properties: {{ routes: [] }}
}}
resource peering 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2024-05-01' = {{
  name: 'local/remote'
  properties: {{
    allowVirtualNetworkAccess: true
    remoteVirtualNetwork: {{ id: '{NETWORK}virtualNetworks/remote' }}
  }}
}}
resource lb 'Microsoft.Network/loadBalancers@2024-05-01' = {{
  name: 'lb'
  location: 'westeurope'
  sku: {{ name: 'Standard' }}
  properties: {{
    frontendIPConfigurations: []
    backendAddressPools: []
  }}
}}
resource port 'Microsoft.Network/expressRoutePorts@2024-05-01' = {{
  name: 'port'
  location: 'westeurope'
  properties: {{
    links: [{{
      name: 'link'
      properties: {{
        macSecConfig: {{
          cipher: 'GcmAes256'
          sciState: 'Enabled'
        }}
      }}
    }}]
  }}
}}
resource connection 'Microsoft.Network/connections@2024-05-01' = {{
  name: 'vpn'
  location: 'westeurope'
  properties: {{
    connectionType: 'IPsec'
    useLocalAzureIpAddress: true
  }}
}}
""",
            encoding="utf-8",
        )
        bundle = arm_source(source, scope=SCOPE, bicep=True, compiler=os.environ["BICEP_COMPILER"])
        bundle["collected_at"] = AT
        self.assertEqual(self.row(bundle, "D01.12")["planned"]["outcome"], "unknown")
        self.assertEqual(self.row(bundle, "D01.13")["planned"]["outcome"], "pass")
        by_type = {r["resource_type"].lower(): r for r in bundle["resources"]}
        self.assertEqual(
            by_type["microsoft.network/loadbalancers"]["properties"]["loadBalancerSku"], "Standard"
        )
        unsupported = self.write(
            "unsupported.json",
            {
                "resources": [
                    {
                        "type": "Microsoft.Network/routeTables",
                        "name": "table",
                        "apiVersion": "1900-01-01",
                        "properties": self.routes(0),
                    }
                ]
            },
        )
        self.assertEqual(arm_source(unsupported, scope=SCOPE)["resources"][0]["state"], "unknown")
