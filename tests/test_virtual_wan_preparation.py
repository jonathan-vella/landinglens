import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from alz_assessor.arm import API_VERSIONS, arm_source, properties
from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import control_digest, document, validate
from alz_assessor.engine import assess, local_subchecks
from alz_assessor.interviews import BANK, BANK_VERSION
from alz_assessor.network_evidence import review_fact
from alz_assessor.plan import plan_source
from alz_assessor.replay import export_bundle, known_catalog, replay_bundle, semantic
from alz_assessor.reports import render, render_xlsx
from alz_assessor.reviews import prepare_reviews, review_context, validate_reviews
from alz_assessor.sources import terraform_source, tf_properties, tf_resource_id
from alz_assessor.terraform import InputError
from alz_assessor.virtual_wan_evidence import (
    CONNECTION,
    FIREWALL,
    HUB,
    INTENT,
    KINDS,
    PATHS,
    TABLE,
    WAN,
    hub_context,
    label_fact,
    label_summary,
    prefix_summary,
    wan_hub_population,
)

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "references" / "recommendation-batches"
FIXTURE = Path(__file__).parent / "fixtures" / "virtual-wan" / "controls.bicep"
SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/vwan"
NETWORK = SCOPE + "/providers/Microsoft.Network/"
WAN_ID = NETWORK + "virtualWans/wan"
HUB_ID = NETWORK + "virtualHubs/hub"
FW_ID = NETWORK + "azureFirewalls/firewall"
TABLE_ID = HUB_ID + "/hubRouteTables/defaultRouteTable"
VNET_ID = NETWORK + "virtualNetworks/workload"
AT = "2026-11-06T13:00:00Z"
PRIVATE = "PRIVATE-LABEL-ROUTE-QUERY-SECRET"
GUIDS = {
    "D10.01": "412e7f98-3f63-4047-82dd-69c5b5c2622f",
    "D10.02": "54b69bad-33aa-4d5e-ac68-e1d76667313b",
    "D10.03": "7d5d1e4e-6146-458d-9558-fd77249b8211",
    "D10.04": "6667313b-4f56-464b-9e98-4a859c773e7d",
    "D10.05": "261623a7-65a9-417e-8f34-8ef254c27d42",
    "D10.06": "727c77e1-b9aa-4a37-a024-129d042422c1",
    "D10.07": "d49ac006-6670-4bc9-9948-d3e0a3a94f4d",
    "D10.08": "2586b854-237e-47f1-84a1-d45d4cd2310d",
    "D10.09": "9c75dfef-573c-461c-a698-68598595581a",
}


class VirtualWanPreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.catalog = load_catalog()

    def write(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def raw_hub(self):
        return {
            "virtualWan": {"id": WAN_ID},
            "azureFirewall": {"id": FW_ID},
            "addressPrefix": "10.12.0.0/22",
            "allowBranchToBranchTraffic": True,
            "hubRoutingPreference": "ASPath",
            "virtualRouterAutoScaleConfiguration": {"minCapacity": 2},
            "virtualRouterIps": ["10.12.0.1"],
        }

    def record(self, kind, identity, raw):
        return {
            "logical_id": identity.lower(),
            "arm_id": identity.lower(),
            "resource_type": kind,
            "state": "known",
            "reason": "",
            "source_location": "fixture://authored-vwan-configuration",
            "properties": properties(kind, raw, root={"location": "westeurope"}),
        }

    def bundle(self):
        return document(
            "evidence",
            schema_version="1.1",
            mode="observed",
            source="saved",
            collected_at=AT,
            scope=SCOPE,
            inventory_complete=False,
            artifact_hashes={"authored-fixture": "0" * 64},
            diagnostics=[],
            resources=[
                self.record(WAN, WAN_ID, {"type": "Standard", "allowBranchToBranchTraffic": True}),
                self.record(HUB, HUB_ID, self.raw_hub()),
                self.record(
                    FIREWALL,
                    FW_ID,
                    {"sku": {"name": "AZFW_Hub", "tier": "Standard"}, "virtualHub": {"id": HUB_ID}},
                ),
                self.record(
                    TABLE,
                    TABLE_ID,
                    {
                        "labels": ["Default", PRIVATE],
                        "routes": [{"destinations": [PRIVATE], "nextHop": PRIVATE}],
                    },
                ),
                self.record(
                    CONNECTION,
                    HUB_ID + "/hubVirtualNetworkConnections/connection",
                    {
                        "remoteVirtualNetwork": {"id": VNET_ID},
                        "enableInternetSecurity": True,
                        "routingConfiguration": {
                            "associatedRouteTable": {"id": TABLE_ID},
                            "propagatedRouteTables": {
                                "labels": ["Default", PRIVATE],
                                "ids": [{"id": TABLE_ID}],
                            },
                            "vnetRoutes": {"staticRoutes": [{"nextHopIpAddress": PRIVATE}]},
                        },
                    },
                ),
                self.record(
                    INTENT,
                    HUB_ID + "/routingIntent/intent",
                    {
                        "routingPolicies": [
                            {"name": PRIVATE, "destinations": ["Internet"], "nextHop": FW_ID}
                        ]
                    },
                ),
            ],
        )

    def by_id(self, bundle):
        result = {}
        for row in bundle["resources"]:
            result.setdefault((row.get("arm_id") or "").lower(), []).append(row)
        return result

    def test_nine_immutable_guids_reviewed_sources_without_activation(self):
        matrix = json.loads((REFERENCE / "batch-20-preparation.json").read_text("utf-8"))
        targets = json.loads((REFERENCE / "targets.json").read_text("utf-8"))["targets"]
        manifest = json.loads((REFERENCE / matrix["source_manifest"]).read_text("utf-8"))
        self.assertEqual(
            {t["upstream_id"]: t["guid"] for t in targets if t["batch"] == "20"}, GUIDS
        )
        self.assertEqual({r["upstream_id"]: r["guid"] for r in matrix["recommendations"]}, GUIDS)
        self.assertEqual(matrix["review_state"], "preparation-only-not-accepted")
        self.assertNotIn("catalog_version", matrix)
        self.assertNotIn("accepted_at", matrix)
        self.assertFalse((REFERENCE / "batch-20.json").exists())
        sources = {s["id"]: s for s in manifest["sources"]}
        self.assertEqual(len(sources), len(manifest["sources"]))
        self.assertEqual(len(sources), 23)
        for source in sources.values():
            self.assertRegex(source["sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(source["revision"], r"^[0-9a-f]{40}$")
            self.assertTrue(source["retrieved_at"])
            self.assertTrue(source["resolved_url"].startswith("https://"))
            self.assertTrue(source["finding"])
            self.assertTrue(source["reuse"])
        for row in matrix["recommendations"]:
            self.assertTrue(set(row["sources"]) <= sources.keys())
            self.assertTrue(
                set(row["review_fact_paths"])
                <= PATHS | {"resourceLocation", "sku.name", "firewallPolicy.id", "egressRules"}
            )
            self.assertTrue(1 <= len(row["review_fact_paths"]) <= 8)
            self.assertEqual(len(row["evidence_requirements"]), 2)
            self.assertTrue(row["implemented_subclaim"])
            self.assertTrue(row["limitations"])
        self.assertIn("/22", sources["vwan-faq"]["finding"])
        self.assertIn("hub branch default=false", sources["terraform-virtual_hub"]["finding"])
        self.assertIn("remote ER/private-intent", sources["vwan-routing-preference"]["finding"])

    def test_exact_frozen_history_original_controls_and_receipts(self):
        data = ROOT / "src" / "alz_assessor" / "data"
        for path, expected in (
            (
                data / "catalog.json",
                "5f678970f45fcd9ac635576d31cfe0f896c97199d11552d2061886aaa441004c",
            ),
            (
                data / "crosswalk.json",
                "9cc735acb396ba27bfccc2a017ec1cc1c1a1ea6eba9f3f86185814fea5c6b519",
            ),
            (
                REFERENCE / "targets.json",
                "582fe02feee03b50961e5548fa7551bbd3d8729fbcb68f51837d548e59eaa291",
            ),
            (
                REFERENCE / "ledger.json",
                "270f6f6d2fb3d1ece161d1f0fd443a6f3afd16551b0390078c9cef30ab04b784",
            ),
        ):
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected)
        original = load_catalog(str(data / "catalog-2026-11-04.2.json"))
        original_four = {
            c["upstream_guid"]: control_digest(c)
            for c in original["controls"]
            if c["automation"] == "automated"
        }
        self.assertEqual(len(original_four), 4)
        current = {c["upstream_guid"]: c for c in self.catalog["controls"]}
        for guid, expected in original_four.items():
            self.assertEqual(control_digest(current[guid]), expected)
        self.assertEqual(len(current), 255)
        self.assertEqual(BANK_VERSION, "2026-11-06.9")
        self.assertFalse(
            any(
                control in {"ALZ-" + guid for guid in GUIDS.values()}
                for question in BANK.values()
                for control in question["controls"]
            )
        )
        self.assertTrue(all(kind not in API_VERSIONS for kind in KINDS))

    def test_strict_ipv4_prefix_shape_and_exact_capacity_boundaries(self):
        for value, length in (
            ("10.12.0.0/22", 22),
            ("10.12.0.0/23", 23),
            ("10.12.0.0/24", 24),
            ("10.12.0.0/25", 25),
            ("0.0.0.0/0", 0),
            ("10.12.0.0/32", 32),
        ):
            facts = {"hubPrefixSummary": prefix_summary(value)}
            self.assertEqual(facts["hubPrefixSummary"], {"prefixLength": length})
            for boundary in (22, 23, 24):
                self.assertEqual(
                    local_subchecks(facts)[f"configured_hub_ipv4_prefix_at_least_{boundary}"],
                    length <= boundary,
                )
            self.assertNotIn(value, json.dumps(facts))
        for value in (
            None,
            True,
            23,
            "23",
            "10.12.0.1/23",
            "2001:db8::/23",
            "10.12.0.0",
            "10.12.0.0/255.255.254.0",
            "10.12.0.0/023",
            "10.12.0.0/33",
            " 10.12.0.0/23",
            {"unknown": PRIVATE},
            PRIVATE,
        ):
            fact = prefix_summary(value)
            self.assertIn("unknown", fact)
            self.assertNotIn(PRIVATE, json.dumps(fact))
            self.assertIn(
                "unknown",
                local_subchecks({"hubPrefixSummary": fact})[
                    "configured_hub_ipv4_prefix_at_least_23"
                ],
            )
        for value in (True, "23", 23.0, -1, 33, None):
            self.assertIn(
                "unknown",
                review_fact({"hubPrefixSummary": {"prefixLength": value}}, "hubPrefixSummary"),
            )

    def test_known_preference_flags_and_riu_envelope_without_defaults(self):
        for preference in ("ASPath", "ExpressRoute", "VpnGateway"):
            raw = self.raw_hub()
            raw["hubRoutingPreference"] = preference
            facts = properties(HUB, raw)
            self.assertEqual(
                local_subchecks(facts)["configured_hub_routing_preference_is_aspath"],
                preference == "ASPath",
            )
        for value in (None, "", "AS-Path", "VPN", "aspath", True, 1, {"unknown": PRIVATE}):
            raw = self.raw_hub()
            raw["hubRoutingPreference"] = value
            self.assertIn("unknown", properties(HUB, raw)["hubRoutingPreference"])
        for path in (
            "wanBranchTrafficAllowed",
            "hubBranchTrafficAllowed",
            "hubInternetSecurityEnabled",
        ):
            for value in (True, False):
                self.assertIs(review_fact({path: value}, path), value)
            for value in (None, 0, 1, "true", {"unknown": PRIVATE}):
                self.assertIn("unknown", review_fact({path: value}, path))
        for kind in ("azurerm_virtual_wan", "azurerm_virtual_hub"):
            facts = tf_properties(kind, {})
            self.assertTrue(all("unknown" in value for value in facts.values()))
        for value in (2, 3, 50):
            self.assertEqual(
                review_fact({"hubRouterMinCapacity": value}, "hubRouterMinCapacity"), value
            )
        for value in (None, True, 1, 51, 2.0, "2", {"unknown": PRIVATE}):
            self.assertIn(
                "unknown", review_fact({"hubRouterMinCapacity": value}, "hubRouterMinCapacity")
            )

    def test_exact_label_minimization_idempotence_and_empty_not_default(self):
        for labels in ([], ["Default"], ["default"], [PRIVATE], ["Default", PRIVATE]):
            summary = label_summary(labels)
            self.assertEqual(summary["suppliedCount"], len(labels))
            self.assertEqual(summary["defaultLabelExplicit"], "Default" in labels)
            self.assertEqual(label_fact(summary), summary)
            self.assertNotIn(PRIVATE, json.dumps(summary))
        self.assertNotEqual(label_summary(["Default"]), label_summary(["default"]))
        for labels in (
            None,
            {},
            [None],
            [True],
            [" "],
            ["x", "x"],
            ["x\n"],
            ["x" * 257],
            ["x" + str(i) for i in range(101)],
            {"unknown": PRIVATE},
        ):
            self.assertIn("unknown", label_summary(labels))
        summary = label_summary(["Default"])
        summary["defaultLabelExplicit"] = False
        self.assertIn("unknown", label_fact(summary))
        summary = label_summary([PRIVATE])
        summary["fingerprints"] = [PRIVATE]
        self.assertIn("unknown", label_fact(summary))

    def test_typed_child_identifiers_and_wrong_type_out_of_scope_refusal(self):
        for kind, suffix in (
            ("azurerm_virtual_hub_connection", "hubVirtualNetworkConnections"),
            ("azurerm_virtual_hub_route_table", "hubRouteTables"),
            ("azurerm_virtual_hub_routing_intent", "routingIntent"),
        ):
            self.assertEqual(
                tf_resource_id(SCOPE, kind, {"name": "child", "virtual_hub_id": HUB_ID}),
                (HUB_ID + "/" + suffix + "/child").lower(),
            )
            for parent in (None, WAN_ID, VNET_ID, TABLE_ID, HUB_ID.replace("/vwan/", "/other/")):
                self.assertIsNone(
                    tf_resource_id(SCOPE, kind, {"name": "child", "virtual_hub_id": parent})
                )
            self.assertIsNone(
                tf_resource_id(None, kind, {"name": "child", "virtual_hub_id": HUB_ID})
            )
            self.assertIsNone(
                tf_resource_id(SCOPE, kind, {"name": "bad/child", "virtual_hub_id": HUB_ID})
            )
        self.assertIn("unknown", properties(HUB, {"virtualWan": {"id": VNET_ID}})["virtualWanId"])
        self.assertIn(
            "unknown",
            properties(CONNECTION, {"remoteVirtualNetwork": {"id": WAN_ID}})[
                "hubRemoteVirtualNetworkId"
            ],
        )

    def test_local_bidirectional_firewall_intent_and_conditional_22(self):
        bundle = self.bundle()
        context = hub_context(bundle["resources"][5], self.by_id(bundle), SCOPE)
        self.assertTrue(context["explicit_internet_intent_to_joined_local_firewall"])
        self.assertTrue(context["firewall_hub_prefix_at_least_22"])
        bundle["resources"][1]["properties"]["hubPrefixSummary"] = {"prefixLength": 23}
        context = hub_context(bundle["resources"][5], self.by_id(bundle), SCOPE)
        self.assertTrue(context["explicit_internet_intent_to_joined_local_firewall"])
        self.assertFalse(context["firewall_hub_prefix_at_least_22"])
        self.assertNotIn(PRIVATE, json.dumps(context))
        for index, path, value in (
            (1, "hubFirewallId", FW_ID + "-missing"),
            (2, "virtualWanHubId", HUB_ID + "-other"),
            (2, "sku", {"name": "AZFW_VNet"}),
        ):
            bundle = self.bundle()
            bundle["resources"][index]["properties"][path] = value
            result = hub_context(bundle["resources"][5], self.by_id(bundle), SCOPE)
            self.assertIn("unknown", result["local_azure_firewall_join"])
            self.assertIn("unknown", result["explicit_internet_intent_to_joined_local_firewall"])
        bundle = self.bundle()
        second = copy.deepcopy(bundle["resources"][2])
        second["arm_id"] = (FW_ID + "-other").lower()
        second["logical_id"] = second["arm_id"]
        bundle["resources"].append(second)
        self.assertIn(
            "unknown", hub_context(second, self.by_id(bundle), SCOPE)["local_azure_firewall_join"]
        )

    def test_unknown_duplicate_denied_and_unscoped_hub_wan_firewall_joins(self):
        for index in (0, 1, 2, 5):
            for state in ("unknown", "inaccessible", "error"):
                bundle = self.bundle()
                bundle["resources"][index]["state"] = state
                result = hub_context(bundle["resources"][5], self.by_id(bundle), SCOPE)
                self.assertIn("unknown", json.dumps(result))
            bundle = self.bundle()
            bundle["resources"].append(copy.deepcopy(bundle["resources"][index]))
            self.assertIn(
                "unknown",
                json.dumps(hub_context(bundle["resources"][5], self.by_id(bundle), SCOPE)),
            )
        bundle = self.bundle()
        for scope in (None, SCOPE.replace("/vwan", "/other")):
            self.assertIn("unknown", hub_context(bundle["resources"][5], self.by_id(bundle), scope))
        bundle["resources"][1]["resource_type"] = "Microsoft.Network/virtualNetworkGateways"
        self.assertIn("unknown", hub_context(bundle["resources"][5], self.by_id(bundle), SCOPE))

    def test_policy_shapes_unknown_destinations_and_next_hops_are_not_dropped(self):
        for policies in (
            None,
            [],
            [{}],
            [{}] * 3,
            [{"name": "one", "destinations": ["Internet", "PrivateTraffic"], "nextHop": FW_ID}],
            [{"name": "one", "destinations": ["Other"], "nextHop": FW_ID}],
            [
                {"name": "one", "destinations": ["Internet"], "nextHop": FW_ID},
                {"name": "one", "destinations": ["PrivateTraffic"], "nextHop": FW_ID},
            ],
            [
                {"name": "one", "destinations": ["Internet"], "nextHop": FW_ID},
                {"name": "two", "destinations": ["Internet"], "nextHop": FW_ID},
            ],
        ):
            self.assertIn(
                "unknown", properties(INTENT, {"routingPolicies": policies})["hubRoutingPolicies"]
            )
        for next_hop in (None, HUB_ID, VNET_ID, NETWORK + "networkVirtualAppliances/nva"):
            facts = properties(
                INTENT,
                {
                    "routingPolicies": [
                        {"name": PRIVATE, "destinations": ["Internet"], "nextHop": next_hop}
                    ]
                },
            )
            self.assertIn("unknown", facts["hubRoutingPolicies"][0]["firewallId"])
            self.assertNotIn(PRIVATE, json.dumps(facts))
        bundle = self.bundle()
        bundle["resources"][5]["properties"]["hubRoutingPolicies"][0]["destination"] = (
            "PrivateTraffic"
        )
        self.assertIn(
            "unknown",
            hub_context(bundle["resources"][5], self.by_id(bundle), SCOPE)[
                "explicit_internet_intent_to_joined_local_firewall"
            ],
        )

    def test_labels_typed_tables_and_nonempty_subcheck_do_not_prove_connectivity(self):
        bundle = self.bundle()
        result = hub_context(bundle["resources"][4], self.by_id(bundle), SCOPE)
        for field in (
            "associated_local_hub_table_known",
            "explicit_propagation_labels_supplied",
            "supplied_propagation_tables_known_local",
            "supplied_propagation_tables_share_explicit_label",
        ):
            self.assertTrue(result[field])
        for labels, expected in (([], False), (["Other"], False), (["Default"], True)):
            bundle = self.bundle()
            bundle["resources"][4]["properties"]["hubConnectionRouting"]["labels"] = label_summary(
                labels
            )
            result = hub_context(bundle["resources"][4], self.by_id(bundle), SCOPE)
            self.assertEqual(result["supplied_propagation_tables_share_explicit_label"], expected)
        for refs in (
            None,
            [],
            [TABLE_ID.lower()] * 2,
            [None],
            [{"unknown": PRIVATE}],
            [NETWORK + "routeTables/ordinary"],
            [TABLE_ID.lower() + "-missing"],
            [TABLE_ID.lower()] * 101,
        ):
            bundle = self.bundle()
            bundle["resources"][4]["properties"]["hubConnectionRouting"]["propagatedTableIds"] = (
                refs
            )
            result = hub_context(bundle["resources"][4], self.by_id(bundle), SCOPE)
            self.assertIn("unknown", result["supplied_propagation_tables_known_local"])
        for state in ("unknown", "inaccessible", "error"):
            bundle = self.bundle()
            bundle["resources"][3]["state"] = state
            result = hub_context(bundle["resources"][4], self.by_id(bundle), SCOPE)
            self.assertIn("unknown", result["associated_local_hub_table_known"])
        raw = properties(CONNECTION, {})
        self.assertIn("unknown", raw["hubConnectionRouting"]["labels"])
        self.assertNotIn(PRIVATE, json.dumps(self.bundle()))

    def test_known_scoped_distinct_population_guard_and_multiple_hubs_same_region(self):
        bundle = self.bundle()
        second = copy.deepcopy(bundle["resources"][1])
        second["arm_id"] = (HUB_ID + "-second").lower()
        second["logical_id"] = second["arm_id"]
        bundle["resources"].append(second)
        result = wan_hub_population(bundle["resources"][0], self.by_id(bundle), SCOPE)
        self.assertEqual(result["suppliedDistinctKnownHubCount"], 2)
        self.assertEqual(result["suppliedDistinctConfiguredRegionCount"], 1)
        second["properties"]["resourceLocation"] = "eastus"
        self.assertEqual(
            wan_hub_population(bundle["resources"][0], self.by_id(bundle), SCOPE)[
                "suppliedDistinctConfiguredRegionCount"
            ],
            2,
        )
        for key, value in (("state", "unknown"), ("arm_id", None)):
            changed = copy.deepcopy(bundle)
            changed["resources"][-1][key] = value
            self.assertIn(
                "unknown", wan_hub_population(changed["resources"][0], self.by_id(changed), SCOPE)
            )
        for path, value in (
            ("virtualWanId", {"unknown": PRIVATE}),
            ("resourceLocation", {"unknown": PRIVATE}),
        ):
            changed = copy.deepcopy(bundle)
            changed["resources"][-1]["properties"][path] = value
            self.assertIn(
                "unknown", wan_hub_population(changed["resources"][0], self.by_id(changed), SCOPE)
            )
        bundle["resources"].append(copy.deepcopy(second))
        self.assertIn(
            "unknown", wan_hub_population(bundle["resources"][0], self.by_id(bundle), SCOPE)
        )
        bundle = self.bundle()
        unrelated = copy.deepcopy(bundle["resources"][1])
        unrelated["arm_id"] = (HUB_ID + "-other").lower()
        unrelated["logical_id"] = unrelated["arm_id"]
        unrelated["properties"]["virtualWanId"] = (WAN_ID + "-other").lower()
        bundle["resources"].append(unrelated)
        self.assertEqual(
            wan_hub_population(bundle["resources"][0], self.by_id(bundle), SCOPE)[
                "suppliedDistinctKnownHubCount"
            ],
            1,
        )
        unrelated["state"] = "unknown"
        self.assertIn(
            "unknown", wan_hub_population(bundle["resources"][0], self.by_id(bundle), SCOPE)
        )
        bundle = self.bundle()
        bundle["resources"].extend(
            self.record(HUB, HUB_ID + str(i), self.raw_hub()) for i in range(100)
        )
        self.assertIn(
            "unknown", wan_hub_population(bundle["resources"][0], self.by_id(bundle), SCOPE)
        )

    def test_authored_review_context_all_nine_without_schema_or_predicate_activation(self):
        matrix = json.loads((REFERENCE / "batch-20-preparation.json").read_text("utf-8"))
        controls = {c["upstream_guid"]: c for c in self.catalog["controls"]}
        for row in matrix["recommendations"]:
            authored = copy.deepcopy(controls[row["guid"]])
            authored["review_resource_types"] = row["review_resource_types"]
            authored["review_fact_paths"] = row["review_fact_paths"]
            context = review_context(authored, self.bundle())
            self.assertTrue(context["normalized_resources_available"])
            self.assertTrue(context["resources"])
            self.assertEqual(context["collected_at"], AT)
            self.assertNotIn(PRIVATE, json.dumps(context))
            altered = copy.deepcopy(self.catalog)
            altered["controls"] = [authored]
            with self.assertRaises(InputError):
                validate(altered, "catalog")
            with self.assertRaises(InputError):
                known_catalog(altered)

    def test_all_nine_decisions_blank_independent_and_bound_to_original_catalog(self):
        bundle = self.bundle()
        assessment = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        selected = ["ALZ-" + guid for guid in GUIDS.values()]
        reviews = prepare_reviews(assessment, self.catalog, selected, SCOPE)
        self.assertEqual(len(reviews["entries"]), 9)
        for row in reviews["entries"]:
            self.assertIsNone(row["outcome"])
            self.assertIsNone(row["reviewer"])
            self.assertIsNone(row["evidence"])
            self.assertIsNone(row["rationale"])
            self.assertTrue(row["control_sha256"])
            self.assertEqual(row["scope"], SCOPE.lower())
        with self.assertRaises(InputError):
            validate_reviews(reviews, self.catalog, SCOPE)
        for row in assessment["results"]:
            if row["control_id"] in selected:
                self.assertEqual(row["observed"]["outcome"], "manual")
                self.assertNotEqual(row["observed"]["evidence_tier"], "verified")

    def test_stale_denied_partial_and_missing_stay_unaccepted(self):
        for state in ("unknown", "inaccessible", "error"):
            bundle = self.bundle()
            for row in bundle["resources"]:
                row["state"] = state
                row["reason"] = "resource_configuration_unavailable"
            report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
            for row in report["results"]:
                if row["control_id"] in {"ALZ-" + guid for guid in GUIDS.values()}:
                    self.assertNotIn(row["observed"]["outcome"], ("pass", "fail"))
                    self.assertNotEqual(row["observed"]["evidence_tier"], "verified")
        report = assess(self.bundle(), self.catalog, at="2026-11-08T13:00:00Z", evidence_tiers=True)
        for row in report["results"]:
            if row["control_id"] in {"ALZ-" + guid for guid in GUIDS.values()}:
                self.assertEqual(row["observed"]["freshness"], "stale")
                self.assertNotEqual(row["observed"]["evidence_tier"], "verified")

    def test_original_time_packaged_replay_and_all_outputs_withheld(self):
        bundle = self.bundle()
        directory = self.root / "replay"
        export_bundle(directory, bundle, self.catalog, at=AT, evidence_tiers=True)
        replayed = replay_bundle(directory)
        original = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        self.assertEqual(semantic(original), semantic(replayed))
        saved = json.loads((directory / "evidence.json").read_text("utf-8"))
        self.assertEqual(saved["collected_at"], AT)
        result = hub_context(saved["resources"][5], self.by_id(saved), SCOPE)
        self.assertTrue(result["explicit_internet_intent_to_joined_local_firewall"])
        self.assertEqual(
            saved["resources"][1]["properties"]["hubPrefixSummary"], {"prefixLength": 22}
        )
        self.assertEqual(
            saved["resources"][3]["properties"]["hubRouteLabels"],
            bundle["resources"][3]["properties"]["hubRouteLabels"],
        )
        for fmt in ("json", "markdown", "html", "sarif", "csv"):
            self.assertNotIn(PRIVATE, render(original, fmt))
        self.assertTrue(render_xlsx(original).startswith(b"PK"))
        self.assertNotIn("10.12.", (directory / "evidence.json").read_text("utf-8"))
        self.assertNotIn(PRIVATE, (directory / "evidence.json").read_text("utf-8"))

    def test_raw_supplied_module_and_optional_sensitive_plan_without_network(self):
        source = self.root / "tf"
        module = source / "local"
        module.mkdir(parents=True)
        (source / "main.tf").write_text('module "vwan" { source = "./local" }\n', encoding="utf-8")
        (module / "main.tf").write_text(
            'resource "azurerm_virtual_hub" "hub" {\n'
            'name="hub"\nresource_group_name="vwan"\nlocation="westeurope"\n'
            f'virtual_wan_id="{WAN_ID}"\naddress_prefix="10.12.0.0/23"\n'
            'hub_routing_preference="ASPath"\nbranch_to_branch_traffic_enabled=false\n}\n',
            encoding="utf-8",
        )
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            raw = terraform_source(source, scope=SCOPE, provider_version="4.50.0")
        hub = raw["resources"][0]
        self.assertEqual(hub["arm_id"], HUB_ID.lower())
        self.assertEqual(hub["properties"]["hubPrefixSummary"], {"prefixLength": 23})
        self.assertFalse(hub["properties"]["hubBranchTrafficAllowed"])
        values = {
            "name": "connection",
            "virtual_hub_id": HUB_ID,
            "remote_virtual_network_id": VNET_ID,
            "routing": [
                {
                    "associated_route_table_id": TABLE_ID,
                    "propagated_route_table": [
                        {"labels": [PRIVATE], "route_table_ids": [TABLE_ID]}
                    ],
                }
            ],
        }
        path = self.write(
            "plan.json",
            {
                "format_version": "1.2",
                "planned_values": {
                    "root_module": {
                        "resources": [
                            {
                                "mode": "managed",
                                "type": "azurerm_virtual_hub_connection",
                                "address": "azurerm_virtual_hub_connection.connection",
                                "values": values,
                                "sensitive_values": {"routing": True},
                            }
                        ]
                    }
                },
            },
        )
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            planned = plan_source(path, scope=SCOPE, provider_version="4.50.0")
        facts = planned["resources"][0]["properties"]
        self.assertIn("unknown", facts["hubConnectionRouting"]["labels"])
        self.assertNotIn(PRIVATE, json.dumps(planned))
        unsupported = terraform_source(source, scope=SCOPE, provider_version="99.0.0")
        self.assertTrue(all(row["state"] != "known" for row in unsupported["resources"]))

    def test_unsupported_arm_api_and_malformed_sources_do_not_leak_or_pass(self):
        for kind in KINDS:
            path = self.write(
                "unsupported.json",
                {
                    "resources": [
                        {
                            "type": kind,
                            "name": "hub/child" if kind.count("/") == 2 else "resource",
                            "apiVersion": "1900-01-01",
                            "properties": {"addressPrefix": PRIVATE},
                        }
                    ]
                },
            )
            bundle = arm_source(path, scope=SCOPE)
            self.assertEqual(bundle["resources"][0]["state"], "unknown")
            self.assertNotIn(PRIVATE, json.dumps(bundle))
        with self.assertRaises(InputError):
            arm_source(self.write("bad.json", {"resources": [None]}), scope=SCOPE)

    def test_real_bicep_virtual_wan_scoped_configuration_without_restore(self):
        compiler = os.environ.get("BICEP_COMPILER")
        if not compiler:
            self.skipTest("Existing compiler not supplied; no acquisition or restoration")
        parameters = self.write(
            "parameters.json",
            {
                "parameters": {
                    key: {"value": value}
                    for key, value in {
                        "wanId": WAN_ID,
                        "hubId": HUB_ID,
                        "firewallId": FW_ID,
                        "vnetId": VNET_ID,
                        "tableId": TABLE_ID,
                    }.items()
                }
            },
        )
        bundle = arm_source(
            FIXTURE,
            scope=SCOPE,
            parameters=parameters,
            bicep=True,
            compiler=compiler,
        )
        self.assertEqual(len(bundle["resources"]), 6)
        self.assertTrue(all(row["state"] == "known" for row in bundle["resources"]))
        hub = next(row for row in bundle["resources"] if row["resource_type"].lower() == HUB)
        intent = next(row for row in bundle["resources"] if row["resource_type"].lower() == INTENT)
        self.assertTrue(
            local_subchecks(hub["properties"])["configured_hub_routing_preference_is_aspath"]
        )
        self.assertEqual(hub["properties"]["hubPrefixSummary"], {"prefixLength": 22})
        self.assertTrue(
            hub_context(intent, self.by_id(bundle), SCOPE)[
                "explicit_internet_intent_to_joined_local_firewall"
            ]
        )
        report = assess(bundle, self.catalog, at=bundle["collected_at"], evidence_tiers=True)
        self.assertTrue(
            all(
                row["planned"]["outcome"] == "manual"
                for row in report["results"]
                if row["control_id"] in {"ALZ-" + g for g in GUIDS.values()}
            )
        )


if __name__ == "__main__":
    unittest.main()
