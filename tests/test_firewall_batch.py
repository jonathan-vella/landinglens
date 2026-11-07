import copy
import hashlib
import json
import os
import runpy
import shutil
import tempfile
import unittest
from collections import Counter
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from alz_assessor.arm import arm_source
from alz_assessor.azure import Collector, Response
from alz_assessor.catalog import load_catalog
from alz_assessor.comparison import compare
from alz_assessor.contracts import control_digest
from alz_assessor.engine import assess, local_subchecks
from alz_assessor.network_evidence import projected_properties, review_fact
from alz_assessor.plan import plan_source
from alz_assessor.replay import export_bundle, replay_bundle, sanitize_evidence, semantic
from alz_assessor.reports import render
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import review_context
from alz_assessor.sources import terraform_source, tf_properties, tf_resource_id
from alz_assessor.terraform import InputError, tree_hash

SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/batch"
FIREWALL = SCOPE + "/providers/Microsoft.Network/azureFirewalls/firewall"
SUBNET = SCOPE + "/providers/Microsoft.Network/virtualNetworks/vnet/subnets/data"
GUID = "c10d51ef-f999-455d-bba0-5c90ece07447"


class FirewallBatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.catalog = load_catalog(
            str(files("alz_assessor").joinpath("data", "catalog-2026-11-05.2.json"))
        )

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def bundle(self, tier="Premium", version="2024-05-01"):
        return arm_source(
            self.write(
                "arm.json",
                {
                    "resources": [
                        {
                            "type": "Microsoft.Network/azureFirewalls",
                            "name": "firewall",
                            "apiVersion": version,
                            "properties": {"sku": {"tier": tier, "name": "AZFW_VNet"}},
                        }
                    ]
                },
            ),
            scope=SCOPE,
        )

    def row(self, bundle):
        report = assess(bundle, self.catalog)
        return next(
            r[bundle["mode"]]
            for r in report["results"]
            if r["control_id"] == self.control("D07.05")["control_id"]
        )

    def control(self, key):
        return next(c for c in self.catalog["controls"] if c["upstream_id"] == key)

    def test_exact_frozen_predecessor_and_original_meanings(self):
        data = files("alz_assessor").joinpath("data")
        prior_bytes = data.joinpath("catalog-2026-11-05.1.json").read_bytes()
        self.assertEqual(
            hashlib.sha256(prior_bytes).hexdigest(),
            "9623b50fb0faa33684b5b051d54f610c2af47021365d6bdf2968cd7c971a7664",
        )
        prior = json.loads(prior_bytes)
        old = {c["upstream_guid"]: c for c in prior["controls"]}
        batch_guids = {
            r["guid"]
            for r in json.loads(data.joinpath("batch-matrix-2026-11-05.2.json").read_text("utf-8"))[
                "batches"
            ][-1]["recommendations"]
        }
        self.assertEqual(len(batch_guids), 9)
        for control in self.catalog["controls"]:
            if control["upstream_guid"] not in batch_guids:
                self.assertEqual(
                    control_digest(control), control_digest(old[control["upstream_guid"]])
                )
        self.assertEqual(
            Counter(c["automation"] for c in self.catalog["controls"]),
            {"automated": 7, "assisted": 205, "manual": 43},
        )
        duplicate = [c for c in self.catalog["controls"] if c["upstream_id"] == "D07.12"]
        self.assertEqual(len({c["upstream_guid"] for c in duplicate}), 2)

    def test_premium_tier_positive_negative_and_uncertainty(self):
        for tier, expected in (
            ("Premium", "pass"),
            ("Standard", "fail"),
            ("Basic", "fail"),
            (None, "unknown"),
            (True, "unknown"),
            (0, "unknown"),
            ("premium", "unknown"),
            ({}, "unknown"),
            (["Premium"], "unknown"),
        ):
            self.assertEqual(self.row(self.bundle(tier))["outcome"], expected)
        self.assertEqual(self.row(self.bundle(version="2024-07-01"))["outcome"], "unknown")
        bundle = self.bundle()
        bundle["resources"][0]["properties"] = {}
        self.assertEqual(self.row(bundle)["outcome"], "unknown")
        bundle["resources"] = []
        self.assertEqual(self.row(bundle)["outcome"], "not_applicable")
        bundle["inventory_complete"] = False
        self.assertEqual(self.row(bundle)["outcome"], "unknown")
        bundle = self.bundle()
        bundle["resources"][0]["resource_type"] = "Microsoft.Network/firewallPolicies"
        bundle["resources"][0]["arm_id"] = None
        self.assertEqual(self.row(bundle)["outcome"], "not_applicable")

    def test_observed_stale_denied_error_and_independent_known_sku(self):
        bundle = self.bundle()
        bundle.update(mode="observed", source="saved", inventory_complete=False)
        self.assertEqual(self.row(bundle)["outcome"], "pass")
        for state, expected in (
            ("inaccessible", "unknown"),
            ("unknown", "unknown"),
            ("error", "error"),
        ):
            changed = copy.deepcopy(bundle)
            changed["resources"][0].update(state=state, reason="fixture_" + state)
            self.assertEqual(self.row(changed)["outcome"], expected)
        bundle["collected_at"] = "2000-01-01T00:00:00Z"
        self.assertEqual(self.row(bundle)["outcome"], "unknown")

    def test_raw_module_snapshots_and_optional_plan_without_network(self):
        module = self.root / "modules" / "firewall"
        values = {
            "name": "firewall",
            "resource_group_name": "batch",
            "sku_tier": "${var.tier}",
            "sku_name": "AZFW_VNet",
        }
        self.write(
            "modules/firewall/main.tf.json",
            {
                "variable": {"tier": {}},
                "resource": {"azurerm_firewall": {"test": values}},
            },
        )
        self.write(
            "source/main.tf.json",
            {
                "module": {
                    "test": {
                        "source": "example.invalid/alz/firewall/azurerm",
                        "version": "1.0.0",
                        "tier": "Premium",
                    }
                }
            },
        )
        manifest = self.write(
            "modules/snapshots.json",
            {
                "modules": [
                    {
                        "source": "example.invalid/alz/firewall/azurerm",
                        "version": "1.0.0",
                        "subdirectory": "",
                        "path": "firewall",
                        "sha256": tree_hash(module),
                    }
                ]
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
            self.assertEqual(self.row(raw)["outcome"], "pass")
            self.assertEqual(
                self.row(
                    terraform_source(self.root / "source", scope=SCOPE, provider_version="4.50.0")
                )["outcome"],
                "unknown",
            )
        values.update(sku_tier="Standard", id=FIREWALL)
        plan = self.write(
            "plan.json",
            {
                "format_version": "1.2",
                "planned_values": {
                    "root_module": {
                        "resources": [
                            {
                                "mode": "managed",
                                "type": "azurerm_firewall",
                                "address": "azurerm_firewall.test",
                                "values": values,
                            }
                        ]
                    }
                },
            },
        )
        self.assertEqual(
            self.row(plan_source(plan, scope=SCOPE, provider_version="4.50.0"))["outcome"], "fail"
        )
        self.assertEqual(
            self.row(plan_source(plan, scope=SCOPE, provider_version="4.49.0"))["outcome"],
            "unknown",
        )

    def test_injected_detail_reads_and_denial(self):
        requests = []

        def transport(method, url):
            requests.append((method, url))
            if "/resources?" in url:
                return Response(
                    200,
                    {"value": [{"id": FIREWALL, "type": "Microsoft.Network/azureFirewalls"}]},
                    {},
                )
            if "/azureFirewalls/firewall?" in url:
                return Response(
                    200,
                    {
                        "id": FIREWALL,
                        "properties": {
                            "sku": {"name": "AZFW_VNet", "tier": "Premium"},
                            "secret": "PRIVATE-SENTINEL",
                        },
                    },
                    {},
                )
            return Response(200, {"value": []}, {})

        bundle = Collector(transport).collect(
            subscriptions=["00000000-0000-0000-0000-000000000001"], inventory_authorized=True
        )
        self.assertEqual(self.row(bundle)["outcome"], "pass")
        self.assertNotIn("PRIVATE-SENTINEL", json.dumps(bundle))
        self.assertTrue(
            all(
                method in {"GET", "POST"} and url.startswith("https://management.azure.com/")
                for method, url in requests
            )
        )

        def denied(method, url):
            return (
                Response(403, {}, {})
                if "/azureFirewalls/firewall?" in url
                else transport(method, url)
            )

        bundle = Collector(denied).collect(
            subscriptions=["00000000-0000-0000-0000-000000000001"], inventory_authorized=True
        )
        self.assertEqual(self.row(bundle)["outcome"], "unknown")

    def test_minimum_capacity_boundaries_and_partial_relationship_context(self):
        for prefix, expected in (
            ("10.0.0.0/24", True),
            ("10.0.0.0/25", True),
            ("10.0.0.0/26", True),
            ("10.0.0.0/27", False),
            ("10.0.0.1/32", False),
        ):
            self.assertIs(
                local_subchecks({"addressPrefixes": [prefix]})[
                    "supplied_ipv4_prefixes_have_minimum_26_capacity"
                ],
                expected,
            )
        for value in (
            None,
            [],
            ["bad"],
            ["2001:db8::/64"],
            ["10.0.0.1/24"],
            [True],
            ["10.0.0.0/26"] * 101,
        ):
            self.assertIn(
                "unknown",
                local_subchecks({"addressPrefixes": value})[
                    "supplied_ipv4_prefixes_have_minimum_26_capacity"
                ],
            )
        bundle = self.bundle()
        bundle["resources"][0]["properties"]["subnetReferences"] = [SUBNET]
        child = copy.deepcopy(bundle["resources"][0])
        child.update(
            logical_id="subnet",
            arm_id=SUBNET,
            resource_type="Microsoft.Network/virtualNetworks/subnets",
            properties={"addressPrefixes": ["10.0.0.0/26"]},
        )
        bundle["resources"].append(child)
        context = review_context(self.control("D07.11"), bundle)
        self.assertIs(
            context["resources"][0]["linked_subnets"][0]["subchecks"][
                "supplied_ipv4_prefixes_have_minimum_26_capacity"
            ],
            True,
        )
        bundle["resources"].pop()
        context = review_context(self.control("D07.11"), bundle)
        self.assertIn("unknown", context["resources"][0]["linked_subnets"][0])
        report = assess(bundle, self.catalog)
        row = next(r for r in report["results"] if r["upstream_id"] == "D07.11")
        self.assertEqual(row["planned"]["outcome"], "manual")

    def test_direct_dnat_subcheck_does_not_clear_effective_policy(self):
        for source, expected in (
            ("10.0.0.1", True),
            ("10.0.0.0/24", True),
            ("10.0.0.1-10.0.0.20", True),
            ("*", False),
            ("any", False),
            ("0.0.0.0/0", False),
            ("0.0.0.0-255.255.255.255", False),
        ):
            props = tf_properties(
                "azurerm_firewall_nat_rule_collection",
                {"action": "Dnat", "rule": [{"source_addresses": [source]}]},
            )
            self.assertIs(
                local_subchecks(props)["supplied_direct_dnat_addresses_restricted"], expected
            )
        for value in (None, [], [True], ["bad"], ["10.0.0.0/24"] * 101):
            props = tf_properties(
                "azurerm_firewall_nat_rule_collection",
                {
                    "action": "Dnat",
                    "rule": [{"source_addresses": value, "source_ip_groups": [FIREWALL]}],
                },
            )
            self.assertIn(
                "unknown", local_subchecks(props)["supplied_direct_dnat_addresses_restricted"]
            )
        self.assertIn(
            "unknown",
            local_subchecks({"natRuleCollections": []})[
                "supplied_direct_dnat_addresses_restricted"
            ],
        )

    def test_reference_projection_scope_and_provider_specific_id(self):
        self.assertEqual(
            tf_resource_id(
                SCOPE,
                "azurerm_subnet",
                {"name": "data", "virtual_network_name": "vnet", "resource_group_name": "batch"},
            ),
            SUBNET.lower(),
        )
        self.assertIsNone(tf_resource_id(SCOPE, "azurerm_subnet", {"name": "data"}))
        values = {
            "name": "logs",
            "target_resource_id": FIREWALL,
            "log_analytics_destination_type": "Dedicated",
        }
        identity = tf_resource_id(SCOPE, "azurerm_monitor_diagnostic_setting", values)
        self.assertEqual(
            identity, (FIREWALL + "/providers/Microsoft.Insights/diagnosticSettings/logs").lower()
        )
        self.assertIn(
            "unknown", tf_properties("azurerm_monitor_diagnostic_setting", values)["workspaceId"]
        )
        values["id"] = FIREWALL + "|logs"
        plan = self.write(
            "diagnostic.json",
            {
                "format_version": "1.2",
                "planned_values": {
                    "root_module": {
                        "resources": [
                            {
                                "mode": "managed",
                                "type": "azurerm_monitor_diagnostic_setting",
                                "address": "diagnostic",
                                "values": values,
                            }
                        ]
                    }
                },
            },
        )
        self.assertEqual(
            plan_source(plan, scope=SCOPE, provider_version="4.50.0")["resources"][0]["arm_id"],
            identity,
        )
        self.assertIn(
            "unknown",
            projected_properties(
                "Microsoft.Network/virtualNetworks/subnets",
                {"addressPrefix": "10.0.0.0/26", "addressPrefixes": ["10.0.0.0/26"]},
            )["addressPrefixes"],
        )
        self.assertIn(
            "unknown", review_fact({"ipAddresses": ["PRIVATE-SENTINEL"]}, "ipAddresses")[0]
        )

    def test_address_unions_empty_ip_groups_and_malformed_nat_bounds(self):
        for sources, expected in (
            (["0.0.0.0/1", "128.0.0.0/1"], False),
            (["0.0.0.0-127.255.255.255", "128.0.0.0-255.255.255.255"], False),
            (["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/1"], False),
            (["10.0.0.0/24", "192.0.2.0/24"], True),
        ):
            props = tf_properties(
                "azurerm_firewall_nat_rule_collection",
                {"action": "Dnat", "rule": [{"source_addresses": sources}]},
            )
            self.assertIs(
                local_subchecks(props)["supplied_direct_dnat_addresses_restricted"], expected
            )
        for malformed in (
            None,
            [None],
            [{"properties": None}],
            [{"properties": {"rules": [None], "action": {"type": "Dnat"}}}],
            [{"properties": {"rules": [None] * 101}}],
            [None] * 21,
        ):
            self.assertIn(
                "unknown",
                local_subchecks({"natRuleCollections": malformed})[
                    "supplied_direct_dnat_addresses_restricted"
                ],
            )
        self.assertIn("unknown", tf_properties("azurerm_ip_group", {})["ipAddresses"])
        self.assertEqual(tf_properties("azurerm_ip_group", {"cidrs": []})["ipAddresses"], [])
        self.assertIn(
            "unknown", tf_properties("azurerm_ip_group", {"cidrs": ["*"]})["ipAddresses"][0]
        )
        self.assertIn(
            "unknown",
            tf_properties("azurerm_ip_group", {"cidrs": ["10.0.0.0/24"] * 101})["ipAddresses"],
        )
        for pool, expected in (([], True), ([{"id": FIREWALL}], None)):
            fact = tf_properties(
                "azurerm_subnet", {"address_prefixes": ["10.0.0.0/26"], "ip_address_pool": pool}
            )
            check = local_subchecks(fact)["supplied_ipv4_prefixes_have_minimum_26_capacity"]
            if expected is None:
                self.assertIn("unknown", check)
            else:
                self.assertIs(check, expected)

    def test_ambiguous_denied_wrong_type_links_and_explicit_truncation(self):
        bundle = self.bundle()
        bundle["resources"][0]["properties"]["subnetReferences"] = [SUBNET]
        child = copy.deepcopy(bundle["resources"][0])
        child.update(
            logical_id="subnet",
            arm_id=SUBNET,
            resource_type="Microsoft.Network/virtualNetworks/subnets",
            properties={"addressPrefixes": ["10.0.0.0/26"]},
        )
        for changes, duplicate in (
            ({"state": "inaccessible", "reason": "denied"}, False),
            ({}, True),
        ):
            changed = copy.deepcopy(bundle)
            target = copy.deepcopy(child)
            target.update(changes)
            changed["resources"].extend([target, copy.deepcopy(target)] if duplicate else [target])
            if duplicate:
                changed["resources"][-1]["logical_id"] = "duplicate"
                with self.assertRaisesRegex(InputError, "ambiguous ARM resource"):
                    review_context(self.control("D07.11"), changed)
            else:
                self.assertIn(
                    "unknown",
                    review_context(self.control("D07.11"), changed)["resources"][0][
                        "linked_subnets"
                    ][0],
                )
        wrong_type = copy.deepcopy(bundle)
        child["resource_type"] = "Microsoft.Network/ipGroups"
        wrong_type["resources"].append(child)
        with self.assertRaisesRegex(InputError, "type does not match"):
            review_context(self.control("D07.11"), wrong_type)
        bundle["resources"][0]["properties"]["subnetReferences"] = [SUBNET] * 21
        prepared = review_context(self.control("D07.11"), bundle)["resources"][0]
        self.assertEqual(len(prepared["linked_subnets"]), 20)
        self.assertTrue(prepared["links_truncated"])

    def test_offline_builder_reproduces_bytes_preserves_delivery_and_orders_versions(self):
        repository = Path(__file__).resolve().parents[1]
        data = self.root / "data"
        reviews = self.root / "reviews"
        shutil.copytree(repository / "src" / "alz_assessor" / "data", data)
        shutil.copytree(repository / "references" / "recommendation-batches", reviews)
        original = {
            str(path.relative_to(self.root)): path.read_bytes()
            for directory in (data, reviews)
            for path in directory.iterdir()
            if path.is_file()
        }
        build = runpy.run_path(str(repository / "tools" / "build_batches.py"))
        with (
            patch.dict(build["main"].__globals__, DATA=data, REVIEWS=reviews),
            patch("socket.socket.connect", side_effect=AssertionError("network forbidden")),
        ):
            build["main"]()
        for name, content in original.items():
            self.assertEqual((self.root / name).read_bytes(), content, name)
        ordered = sorted(
            [
                {"batch": "02", "catalog_version": "2026-11-05.10"},
                {"batch": "17", "catalog_version": "2026-11-05.2"},
                {"batch": "01"},
            ],
            key=build["catalog_order"],
        )
        self.assertEqual([batch["batch"] for batch in ordered], ["01", "17", "02"])
        ledger = json.loads((reviews / "ledger.json").read_text("utf-8"))
        self.assertEqual(
            Counter(row["status"] for row in ledger["recommendations"]),
            Counter(
                row["status"]
                for row in json.loads(
                    (
                        repository / "references" / "recommendation-batches" / "ledger.json"
                    ).read_text("utf-8")
                )["recommendations"]
            ),
        )
        self.assertIn("01", ledger["deliveries"])
        for status, changes, message in (
            (
                "merged",
                {"pr": "https://github.com/jonathan-vella/landinglens/pull/0"},
                "cohort receipt",
            ),
            (
                "pending",
                {"pr": "https://github.com/jonathan-vella/landinglens/pull/0"},
                "stale acceptance",
            ),
            ("pending", {"runtime_evidence": ["fixture/injected verified"]}, "stale acceptance"),
            ("implementation-in-progress", {"merge_commit": "0" * 40}, "stale acceptance"),
        ):
            changed = copy.deepcopy(ledger)
            entry = (
                next(row for row in changed["recommendations"] if row["status"] == status)
                if status == "merged"
                else next(
                    row
                    for row in changed["recommendations"]
                    if row["guid"] == "29fd366b-a180-452b-9bd7-954b7700c667"
                )
            )
            if status != "merged":
                # Author the invalid undelivered fixture even after the final receipt.
                entry.update(pr=None, merge_commit=None, runtime_evidence=[])
            entry.update(status=status, **changes)
            self.write("reviews/ledger.json", changed)
            with (
                patch.dict(build["main"].__globals__, DATA=data, REVIEWS=reviews),
                self.assertRaisesRegex(ValueError, message),
            ):
                build["main"]()

    def test_comparison_replay_reports_and_review_questions(self):
        planned = self.bundle("Basic")
        observed = self.bundle("Standard")
        observed.update(mode="observed", source="saved")
        result = compare(assess(planned, self.catalog), assess(observed, self.catalog))
        row = next(
            r for r in result["results"] if r["control_id"] == self.control("D07.05")["control_id"]
        )
        self.assertEqual(row["comparison"], "drift")
        observed["resources"][0]["properties"]["secret"] = "PRIVATE-SENTINEL"
        self.assertNotIn("PRIVATE-SENTINEL", json.dumps(sanitize_evidence(observed)))
        export_bundle(self.root / "replay", observed, self.catalog, at=observed["collected_at"])
        self.assertEqual(
            semantic(replay_bundle(self.root / "replay")),
            semantic(assess(observed, self.catalog, at=observed["collected_at"])),
        )
        report = assess(observed, self.catalog)
        for format in ("json", "markdown", "html"):
            for minimize in (True, False):
                output = render(report, format, minimize=minimize)
                self.assertIn("Reviewer decision", output)
                self.assertIn("local-direct-sources-only", output)
        state = ReviewSession(observed, self.catalog, self.root / "reviews").state()
        self.assertEqual(state["records"], [])
        self.assertTrue(
            any("Reviewer decision" in str(c["evidence_requirements"]) for c in state["controls"])
        )

    @unittest.skipUnless(os.environ.get("BICEP_COMPILER"), "Existing Bicep compiler unavailable")
    def test_existing_no_restore_bicep_firewall_sku(self):
        source = self.root / "main.bicep"
        source.write_text(
            "resource fw 'Microsoft.Network/azureFirewalls@2024-05-01' = {\n"
            " name: 'firewall'\n location: 'westeurope'\n properties: {\n"
            "  sku: { name: 'AZFW_VNet', tier: 'Premium' }\n }\n}\n",
            encoding="utf-8",
        )
        self.assertEqual(
            self.row(
                arm_source(source, scope=SCOPE, bicep=True, compiler=os.environ["BICEP_COMPILER"])
            )["outcome"],
            "pass",
        )
