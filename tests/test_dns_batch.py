import copy
import hashlib
import json
import os
import runpy
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
from alz_assessor.contracts import control_digest, document
from alz_assessor.dns_evidence import BASTION_FLAGS, KINDS, PATHS, domain_summary, target_summary
from alz_assessor.engine import assess, local_subchecks
from alz_assessor.interviews import BANK, compile_interview, prepare_interview
from alz_assessor.network_evidence import review_fact
from alz_assessor.plan import plan_source
from alz_assessor.replay import export_bundle, replay_bundle, semantic
from alz_assessor.reports import render, render_xlsx
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import prepare_reviews, review_context
from alz_assessor.sources import terraform_source, tf_properties, tf_resource_id
from alz_assessor.terraform import InputError, tree_hash

ROOT = Path(__file__).resolve().parents[1]
REFERENCES = ROOT / "references" / "recommendation-batches"
SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/dns"
NETWORK = SCOPE + "/providers/Microsoft.Network/"
VNET = NETWORK + "virtualNetworks/network"
SUBNET = VNET + "/subnets/AzureBastionSubnet"
ZONE = NETWORK + "privateDnsZones/fixture.example.invalid"
RESOLVER = NETWORK + "dnsResolvers/resolver"
RULESET = NETWORK + "dnsForwardingRulesets/ruleset"
IP = NETWORK + "publicIPAddresses/bastion"
AT = "2026-11-06T11:00:00Z"
SENTINEL = "PRIVATE-NOT-FOR-REPORTS"
DOMAIN = "private-sensitive-record.example.invalid."
DESTINATION = "10.23.45.67"
GUIDS = (
    "f348ef25-4c27-4d42-b8bb-ac7571559ab9",
    "0c47f486-656d-4699-8c30-edef5b8a93c4",
    "153e8908-ae28-4c84-a33b-6b7808b9fe5c",
    "41049d40-3a92-43c3-974d-00018ac6a9e0",
    "1e6a83de-5de3-42c1-a924-81607d5d1e4e",
    "614658d3-558f-4d77-849b-821112df27ee",
    "18c80eb0-582a-4198-bf5c-d8800b2d263b",
    "baac3ecb-a94c-4ac4-8c79-cdf27c0d78df",
    "ee1ac551-c4d5-46cf-b035-d0a3c50d87ad",
    "6eab9eb6-762b-485e-8ea8-15aa5dba0bd0",
)


class DnsBatchTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.matrix = json.loads((REFERENCES / "preparation-12.json").read_text())
        self.catalog = copy.deepcopy(load_catalog())
        for row in self.matrix["recommendations"]:
            control = self.control(row["guid"])
            control.update(
                automation=row["classification"],
                rationale=row["limitations"],
                evidence_requirements=row["evidence_requirements"],
            )
            if row["review_resource_types"]:
                control["review_resource_types"] = row["review_resource_types"]
            if row["review_fact_paths"]:
                control["review_fact_paths"] = row["review_fact_paths"]

    def control(self, guid):
        return next(c for c in self.catalog["controls"] if c["upstream_guid"] == guid)

    def test_source_reuse_terms_require_exact_https_authority_not_url_substrings(self):
        classify = runpy.run_path(str(ROOT / "tools" / "review_batch_sources.py"))[
            "microsoft_site_terms"
        ]
        self.assertTrue(classify("https://techcommunity.microsoft.com/blog/example"))
        self.assertTrue(classify("https://www.microsoft.com/en-us/legal/terms-of-use"))
        for url in (
            "http://techcommunity.microsoft.com/blog/example",
            "https://techcommunity.microsoft.com.example.invalid/blog",
            "https://example.invalid/techcommunity.microsoft.com",
            "https://example.invalid/?redirect=https://www.microsoft.com/en-us/legal/",
            "https://techcommunity.microsoft.com@example.invalid/",
            "https://www.microsoft.com.example.invalid/en-us/legal/",
            "https://www.microsoft.com/en-us/products/",
        ):
            self.assertFalse(classify(url))

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def details(self):
        region = {"location": "westeurope"}
        return [
            (
                "Microsoft.Network/virtualNetworks",
                VNET,
                {
                    "addressSpace": {"addressPrefixes": ["10.0.0.0/16"]},
                    "dhcpOptions": {"dnsServers": [DESTINATION]},
                    "encryption": {"enabled": False, "enforcement": "AllowUnencrypted"},
                },
                region,
            ),
            (
                "Microsoft.Network/virtualNetworks/subnets",
                SUBNET,
                {
                    "addressPrefix": "10.0.1.0/26",
                    "delegations": [
                        {"properties": {"serviceName": "Microsoft.Network/dnsResolvers"}}
                    ],
                },
                None,
            ),
            (
                "Microsoft.Network/privateDnsZones",
                ZONE,
                {"recordSets": [SENTINEL]},
                {
                    "location": "global",
                },
            ),
            (
                "Microsoft.Network/privateDnsZones/virtualNetworkLinks",
                ZONE + "/virtualNetworkLinks/network",
                {
                    "virtualNetwork": {"id": VNET},
                    "registrationEnabled": True,
                    "resolutionPolicy": "Default",
                    "virtualNetworkLinkState": "Completed",
                },
                {"location": "global"},
            ),
            ("Microsoft.Network/dnsResolvers", RESOLVER, {"virtualNetwork": {"id": VNET}}, region),
            (
                "Microsoft.Network/dnsResolvers/inboundEndpoints",
                RESOLVER + "/inboundEndpoints/inbound",
                {
                    "ipConfigurations": [
                        {
                            "subnet": {"id": SUBNET},
                            "privateIpAllocationMethod": "Dynamic",
                            "privateIpAddress": DESTINATION,
                        }
                    ],
                },
                region,
            ),
            (
                "Microsoft.Network/dnsResolvers/outboundEndpoints",
                RESOLVER + "/outboundEndpoints/outbound",
                {
                    "subnet": {"id": SUBNET},
                },
                region,
            ),
            (
                "Microsoft.Network/dnsForwardingRulesets",
                RULESET,
                {
                    "dnsResolverOutboundEndpoints": [
                        {"id": RESOLVER + "/outboundEndpoints/outbound"}
                    ],
                },
                region,
            ),
            (
                "Microsoft.Network/dnsForwardingRulesets/forwardingRules",
                RULESET + "/forwardingRules/rule",
                {
                    "domainName": DOMAIN,
                    "forwardingRuleState": "Enabled",
                    "targetDnsServers": [{"ipAddress": DESTINATION, "port": 53}],
                    "metadata": {"secret": SENTINEL},
                },
                None,
            ),
            (
                "Microsoft.Network/dnsForwardingRulesets/virtualNetworkLinks",
                RULESET + "/virtualNetworkLinks/network",
                {
                    "virtualNetwork": {"id": VNET},
                    "metadata": {"secret": SENTINEL},
                },
                None,
            ),
            (
                "Microsoft.Network/publicIPAddresses",
                IP,
                {
                    "publicIPAllocationMethod": "Static",
                    "publicIPAddressVersion": "IPv4",
                    "ipAddress": DESTINATION,
                    "dnsSettings": {"fqdn": SENTINEL},
                },
                {**region, "sku": {"name": "Standard", "tier": "Regional"}, "zones": []},
            ),
            (
                "Microsoft.Network/bastionHosts",
                NETWORK + "bastionHosts/bastion",
                {
                    "scaleUnits": 2,
                    "enablePrivateOnlyBastion": False,
                    "disableCopyPaste": False,
                    "enableSessionRecording": True,
                    "enableShareableLink": False,
                    "ipConfigurations": [
                        {
                            "properties": {
                                "subnet": {"id": SUBNET},
                                "publicIPAddress": {"id": IP},
                            }
                        }
                    ],
                    "dnsName": SENTINEL,
                    "networkAcls": {"ipRules": [{"addressPrefix": DESTINATION}]},
                    "recordingSasUrl": SENTINEL,
                },
                {**region, "sku": {"name": "Premium"}, "zones": ["1", "2", "3"]},
            ),
        ]

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
                {
                    "logical_id": identity.lower(),
                    "arm_id": identity.lower(),
                    "resource_type": kind,
                    "state": "known",
                    "reason": "",
                    "source_location": "fixture://dns-configuration",
                    "properties": properties(kind, body, root=root, observed=True),
                }
                for kind, identity, body, root in self.details()
            ],
        )

    def test_exact_ten_immutable_guids_sources_and_no_accepted_activation(self):
        targets = json.loads((REFERENCES / "targets.json").read_text())["targets"]
        expected_ids = [f"D03.{i:02d}" for i in range(4, 12)] + ["D05.01", "D05.02"]
        self.assertEqual([r["guid"] for r in self.matrix["recommendations"]], list(GUIDS))
        self.assertEqual([r["upstream_id"] for r in self.matrix["recommendations"]], expected_ids)
        by_guid = {target["guid"]: target for target in targets}
        for guid, identity in zip(GUIDS, expected_ids, strict=True):
            self.assertEqual(by_guid[guid]["upstream_id"], identity)
        sources = json.loads((REFERENCES / "preparation-12-sources.json").read_text())
        self.assertEqual(sources["review_state"], "preparation-only-reviewed")
        self.assertGreaterEqual(len(sources["sources"]), 42)
        source_ids = {row["id"] for row in sources["sources"]}
        for row in sources["sources"]:
            self.assertEqual(len(row["sha256"]), 64)
            self.assertTrue(row["retrieved_at"])
            self.assertTrue(row["revision"])
            self.assertTrue(row["resolved_url"].startswith("https://"))
        for row in self.matrix["recommendations"]:
            self.assertLessEqual(set(row["sources"]), source_ids)
            self.assertTrue(row["evidence_requirements"])
        baseline = load_catalog()
        self.assertEqual(len(self.catalog["controls"]), 255)
        self.assertEqual(self.control(GUIDS[4])["automation"], "manual")
        self.assertEqual(self.control(GUIDS[6])["automation"], "manual")
        for old in baseline["controls"]:
            if old["upstream_guid"] not in GUIDS:
                self.assertEqual(
                    control_digest(old), control_digest(self.control(old["upstream_guid"]))
                )
        self.assertEqual(
            BANK[self.matrix["interview"]["id"]]["controls"],
            ["ALZ-" + guid for guid in GUIDS],
        )
        self.assertNotIn("catalog_version", self.matrix)
        data = files("alz_assessor").joinpath("data")
        prior = data.joinpath("catalog-2026-11-06.7.json").read_bytes()
        self.assertEqual(
            hashlib.sha256(prior).hexdigest(),
            "3e69f21126f9cf94e06d39f7eff2797c3ba1d575d1a89a040ac7ddffdf2572fa",
        )
        before = {c["upstream_guid"]: c for c in json.loads(prior)["controls"]}
        for control in baseline["controls"]:
            if control["upstream_guid"] not in GUIDS:
                self.assertEqual(
                    control_digest(control), control_digest(before[control["upstream_guid"]])
                )
        self.assertEqual(baseline["catalog_version"], "2026-11-06.8")
        self.assertEqual(
            hashlib.sha256(data.joinpath("crosswalk-2026-11-06.7.json").read_bytes()).hexdigest(),
            "90c0d4e3caf23069f2f7bd7938ce0e6c81d7df49d25266dbfdb316675b12fed4",
        )

    def test_actual_cohort12_receipt_preserves_all_80_previous_rows_and_nine_receipts(self):
        ledger = json.loads((REFERENCES / "ledger.json").read_text())
        earlier_receipts = {
            key: value for key, value in ledger["deliveries"].items() if key != "12"
        }
        earlier_rows = [
            row
            for row in ledger["recommendations"]
            if row["status"] == "merged" and row["batch"] != "12"
        ]
        for value, expected in (
            (earlier_receipts, "1da5f99a9d027f6d687464c67d4c69926e1bcb3dce8c0704f2bb36754c4624d2"),
            (earlier_rows, "468e0d431bd3c48f7ee3242a7f0af841a6c136fff824e91c25149c069f144889"),
        ):
            self.assertEqual(
                hashlib.sha256(
                    json.dumps(
                        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
                    ).encode()
                ).hexdigest(),
                expected,
            )
        receipt = ledger["deliveries"]["12"]
        self.assertEqual(receipt["checked_head"], "98b1b39323bc0bb7ebd161139ca5f0c6578b3a4a")
        self.assertEqual(receipt["merge_commit"], "a57906768b2cafb2ba20c7ed6df59695ca18b017")
        self.assertEqual(
            receipt["local_installed_suite"], {"tests": 396, "passed": 395, "skipped": 1}
        )
        self.assertEqual(
            receipt["wheel_sha256"],
            "733592b2b07633d8b6f576097fee66bdf69f2a81c51f333d3d74e8f6b73c7b08",
        )
        self.assertEqual(len(receipt["compiler_integration_cases"]), 8)
        own = [row for row in ledger["recommendations"] if row["batch"] == "12"]
        self.assertEqual({row["guid"] for row in own}, set(GUIDS))
        self.assertTrue(
            all(
                row["status"] == "merged"
                and row["pr"] == receipt["pr"]
                and row["merge_commit"] == receipt["merge_commit"]
                for row in own
            )
        )
        self.assertEqual(sum(row["status"] == "merged" for row in ledger["recommendations"]), 90)

    def test_minimized_dns_public_ip_bastion_and_preserved_literal_facts(self):
        bundle = self.bundle()
        for secret in (SENTINEL, DOMAIN, DESTINATION):
            self.assertNotIn(secret, json.dumps(bundle))
        by_type = {r["resource_type"]: r["properties"] for r in bundle["resources"]}
        ip = by_type["Microsoft.Network/publicIPAddresses"]
        self.assertEqual(ip["publicIpSku"], "Standard")
        self.assertEqual(ip["publicIpTier"], "Regional")
        self.assertEqual(ip["configuredZones"], [])
        self.assertEqual(ip["resourceLocation"], "westeurope")
        self.assertEqual(
            by_type["Microsoft.Network/dnsForwardingRulesets/forwardingRules"][
                "forwardingTargetSummary"
            ],
            [{"addressFamily": "IPv4", "isAzureProvidedDns": False, "port": 53}],
        )
        self.assertEqual(
            by_type["Microsoft.Network/virtualNetworks"]["dnsServerSummary"],
            {
                "suppliedCount": 1,
                "usesCustomServers": True,
            },
        )
        bastion = by_type["Microsoft.Network/bastionHosts"]
        self.assertEqual(bastion["bastionSku"], "Premium")
        self.assertEqual(bastion["bastionPublicIpIds"], [IP.lower()])
        self.assertIs(bastion["enableSessionRecording"], True)
        self.assertIs(bastion["enablePrivateOnlyBastion"], False)
        report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        for row in report["results"]:
            if row["control_id"] in {"ALZ-" + g for g in GUIDS}:
                self.assertEqual(row["observed"]["outcome"], "manual")
                self.assertNotEqual(row["observed"]["evidence_tier"], "verified")

    def test_boolean_types_no_defaults_sku_private_only_and_link_conditions(self):
        for path in {*BASTION_FLAGS, "registrationEnabled", "vnetEncryptionEnabled"}:
            for value in (None, "true", 0, 1, 1.0, [], {"unknown": "sensitive"}):
                self.assertIn("unknown", review_fact({path: value}, path))
            self.assertIs(review_fact({path: False}, path), False)
        for path in (
            "bastionSku",
            "publicIpSku",
            "publicIpTier",
            "resolutionPolicy",
            "dnsLinkState",
        ):
            for value in (None, {}, True, SENTINEL):
                self.assertIn("unknown", review_fact({path: value}, path))
        for value in (True, 1, 51, 2.0, "2", None):
            self.assertIn("unknown", review_fact({"bastionScaleUnits": value}, "bastionScaleUnits"))
        for value in (2, 50):
            self.assertEqual(review_fact({"bastionScaleUnits": value}, "bastionScaleUnits"), value)
        for sku in ("Developer", "Premium"):
            props = properties("Microsoft.Network/bastionHosts", {}, root={"sku": {"name": sku}})
            self.assertEqual(props["bastionSku"], sku)
            self.assertIn("unknown", props["enablePrivateOnlyBastion"])
            self.assertIn("unknown", props["subnetReferences"])
        props = tf_properties(
            "azurerm_bastion_host", {"sku": "Premium", "copy_paste_enabled": True}
        )
        self.assertIs(props["disableCopyPaste"], False)
        self.assertIn("unknown", props["enablePrivateOnlyBastion"])
        self.assertIn("unknown", props["bastionScaleUnits"])
        self.assertIn(
            "unknown",
            tf_properties("azurerm_private_dns_zone_virtual_network_link", {})[
                "registrationEnabled"
            ],
        )
        self.assertIn(
            "unknown", tf_properties("azurerm_public_ip", {"sku": "StandardV2"})["publicIpSku"]
        )

    def test_strict_domain_target_types_and_service_bounds_without_raw_values(self):
        self.assertEqual(domain_summary("."), {"labelCount": 0, "wildcard": True})
        self.assertEqual(domain_summary("a." * 34), {"labelCount": 34, "wildcard": False})
        for value in ("a." * 35, "missing-dot", "bad..name.", "-bad.", True, {}, SENTINEL):
            self.assertIn("unknown", domain_summary(value))
        for value in (None, [], {}, [True], [{}] * 7):
            self.assertIn("unknown", target_summary(value, terraform=False))
        targets = [{"ipAddress": "168.63.129.16", "port": 53}] * 6
        self.assertTrue(target_summary(targets, terraform=False)[0]["isAzureProvidedDns"])
        for value in (None, 0, 65536, True, 53.0, "53", {"unknown": "sensitive"}):
            result = target_summary([{"ipAddress": DESTINATION, "port": value}], terraform=False)
            self.assertIn("unknown", result[0]["port"])
            self.assertNotIn(DESTINATION, json.dumps(result))
        for value in (None, "invalid", {"unknown": "sensitive"}, "fe80::1%host"):
            result = target_summary([{"ipAddress": value, "port": 53}], terraform=False)
            projected = review_fact({"forwardingTargetSummary": result}, "forwardingTargetSummary")
            self.assertIn("unknown", projected[0]["addressFamily"])
        for path in ("dnsServerSummary", "dnsResolverDelegation", "forwardingDomainSummary"):
            for value in (None, {}, True, {"unknown": "secret"}, {"suppliedCount": True}):
                self.assertIn("unknown", review_fact({path: value}, path))
        self.assertIn(
            "unknown",
            review_fact(
                {
                    "dnsServerSummary": {"suppliedCount": 0, "usesCustomServers": True},
                },
                "dnsServerSummary",
            ),
        )
        for path, maximum in (
            ("resolverOutboundEndpointIds", 2),
            ("bastionPublicIpIds", 20),
            ("resolverIpConfigurations", 20),
        ):
            self.assertIn("unknown", review_fact({path: [{}] * (maximum + 1)}, path))
        for path in PATHS:
            self.assertNotEqual(review_fact({}, path), True)

    def test_dns_subnet_range_and_bastion_capacity_are_only_bounded_subchecks(self):
        for prefix, expected in ((23, False), (24, True), (28, True), (29, False)):
            facts = {"addressPrefixes": [f"10.0.0.0/{prefix}"], "dnsResolverDelegation": {}}
            self.assertIs(
                local_subchecks(facts)["supplied_dns_resolver_ipv4_prefixes_within_24_28"], expected
            )
        for values in ([], None, ["2001:db8::/64"], [{"unknown": "secret"}]):
            self.assertIn(
                "unknown",
                local_subchecks(
                    {
                        "addressPrefixes": values,
                        "dnsResolverDelegation": {},
                    }
                )["supplied_dns_resolver_ipv4_prefixes_within_24_28"],
            )
        self.assertIs(
            local_subchecks({"addressPrefixes": ["10.0.0.0/27"]})[
                "supplied_ipv4_prefixes_have_minimum_26_capacity"
            ],
            False,
        )
        review = review_context(self.control(GUIDS[9]), self.bundle())
        host = next(r for r in review["resources"] if r["resource_type"].endswith("/bastionHosts"))
        self.assertEqual(host["linked_subnets"][0]["arm_id"], SUBNET.lower())
        self.assertIn("2021-11-02", " ".join(self.control(GUIDS[9])["evidence_requirements"]))
        # The deliberately shared fixture is configuration, not an exclusive/deployable subnet.
        self.assertNotIn("outcome", host["linked_subnets"][0])

    def test_supplied_vnet_population_overlap_never_establishes_complete_dr_roles(self):
        bundle = self.bundle()
        second = copy.deepcopy(bundle["resources"][0])
        second["logical_id"] = second["arm_id"] = VNET.lower() + "-second"
        bundle["resources"].append(second)
        key = "supplied_vnet_ipv4_prefixes_do_not_overlap"

        def checks(value):
            return review_context(self.control(GUIDS[0]), value)[
                "supplied_vnet_population_subchecks"
            ]["subchecks"]

        self.assertIs(checks(bundle)[key], False)
        second["properties"]["virtualNetworkPrefixes"] = ["10.1.0.0/16"]
        self.assertIs(checks(bundle)[key], True)
        second.update(state="inaccessible", reason="fixture denial")
        self.assertIn("unknown", checks(bundle)[key])
        over_bound = self.bundle()
        over_bound["resources"] = []
        for index in range(101):
            resource = copy.deepcopy(self.bundle()["resources"][0])
            resource["logical_id"] = resource["arm_id"] = VNET.lower() + str(index)
            over_bound["resources"].append(resource)
        self.assertIn("unknown", checks(over_bound)[key])
        self.assertIn("unknown", checks({**bundle, "resources": []})[key])

    def test_positive_typed_links_missing_denied_and_wrong_type_never_prove_topology(self):
        bundle = self.bundle()
        bundle["resources"][-1]["properties"]["bastionSku"] = "Developer"
        bundle["resources"][-1]["properties"]["bastionVirtualNetworkId"] = VNET
        host = next(
            r
            for r in review_context(self.control(GUIDS[8]), bundle)["resources"]
            if r["resource_type"].endswith("/bastionHosts")
        )
        self.assertEqual(host["linked_bastionVirtualNetworkId"][0]["arm_id"], VNET.lower())
        self.assertEqual(host["facts"]["bastionFeatureSummary"]["scaleUnits"], 2)
        review = review_context(self.control(GUIDS[3]), self.bundle())
        resolver = next(
            r for r in review["resources"] if r["resource_type"].endswith("/dnsResolvers")
        )
        self.assertEqual(resolver["linked_dnsVirtualNetworkId"][0]["arm_id"], VNET.lower())
        rule = next(
            r for r in review["resources"] if r["resource_type"].endswith("/dnsForwardingRulesets")
        )
        self.assertEqual(len(rule["linked_resolverOutboundEndpointIds"]), 1)
        for change in ("missing", "denied", "wrong-type"):
            bundle = self.bundle()
            if change == "missing":
                bundle["resources"] = [r for r in bundle["resources"] if r["arm_id"] != IP.lower()]
            elif change == "denied":
                bundle["resources"][-2].update(state="inaccessible", reason="denied", properties={})
            else:
                bundle["resources"][-1]["properties"]["bastionPublicIpIds"] = [VNET]
            host = next(
                r
                for r in review_context(self.control(GUIDS[8]), bundle)["resources"]
                if r["resource_type"].endswith("/bastionHosts")
            )
            self.assertIn("unknown", host["linked_bastionPublicIpIds"][0])
        bundle = self.bundle()
        bundle["resources"].append(copy.deepcopy(bundle["resources"][0]))
        with self.assertRaises(InputError):
            review_context(self.control(GUIDS[3]), bundle)

    def test_prepared_outputs_replay_original_time_stale_and_blank_review_session(self):
        bundle = self.bundle()
        report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        for format in ("json", "markdown", "html", "csv", "sarif", "pr-summary"):
            text = render(report, format)
            for secret in (SENTINEL, DOMAIN, DESTINATION):
                self.assertNotIn(secret, text)
        with zipfile.ZipFile(BytesIO(render_xlsx(report))) as archive:
            self.assertNotIn(
                SENTINEL, "".join(archive.read(n).decode() for n in archive.namelist())
            )
        tampered = copy.deepcopy(self.catalog)
        tampered["controls"][0]["rationale"] += " altered"
        with self.assertRaisesRegex(InputError, "Historical catalog"):
            export_bundle(self.root / "unaccepted-replay", bundle, tampered, at=AT)
        accepted = load_catalog()
        accepted_report = assess(bundle, accepted, at=AT, evidence_tiers=True)
        export_bundle(self.root / "replay", bundle, accepted, at=AT, evidence_tiers=True)
        replay = replay_bundle(self.root / "replay")
        self.assertEqual(semantic(replay), semantic(accepted_report))
        self.assertEqual(replay["evidence"][0]["collected_at"], AT)
        prepared = prepare_reviews(report, self.catalog, ["ALZ-" + g for g in GUIDS], SCOPE)
        self.assertEqual(len(prepared["entries"]), 10)
        self.assertTrue(all(e["outcome"] is None for e in prepared["entries"]))
        self.assertEqual(
            ReviewSession(bundle, accepted, self.root / "session").state()["records"], []
        )
        stale = copy.deepcopy(bundle)
        stale["collected_at"] = "2000-01-01T00:00:00Z"
        old = assess(stale, self.catalog, at=AT, evidence_tiers=True)
        for row in old["results"]:
            if row["control_id"] in {"ALZ-" + g for g in GUIDS}:
                self.assertEqual(row["observed"]["freshness"], "stale")
                self.assertNotEqual(row["observed"]["evidence_tier"], "verified")

    def test_preparation_question_blank_atomic_attributed_scope_content_and_expiry_bound(self):
        question = self.matrix["interview"]
        definition = {"question": question["question"], "controls": ["ALZ-" + g for g in GUIDS]}
        report = assess(self.bundle(), self.catalog, at=AT)
        with patch.dict(BANK, {question["id"]: definition}):
            prepared = prepare_interview(report, self.catalog, question["id"], SCOPE)
            self.assertIsNone(prepared["answer"])
            self.assertTrue(all(d["outcome"] is None for d in prepared["decisions"]))
            with self.assertRaises(InputError):
                compile_interview(prepared, self.catalog, at=AT)
            fixture = copy.deepcopy(prepared)
            fixture.update(
                answer="Synthetic acceptance fixture, not an owner decision.",
                reviewer="Fixture reviewer",
                rationale="Authored contract test only.",
                evidence="fixture://redacted",
                valid_from=AT,
                valid_until="2026-11-07T00:00:00Z",
            )
            for decision in fixture["decisions"]:
                decision["outcome"] = "fail"
            self.assertEqual(len(compile_interview(fixture, self.catalog, at=AT)["entries"]), 10)
            for key, value in (
                ("scope", "/subscriptions/00000000-0000-0000-0000-000000000002"),
                ("requirements_sha256", "0" * 64),
                ("valid_until", AT),
                ("reviewer", ""),
                ("catalog_sha256", "0" * 64),
            ):
                changed = copy.deepcopy(fixture)
                changed[key] = value
                with self.assertRaises(InputError):
                    compile_interview(changed, self.catalog, at=AT)
            changed = copy.deepcopy(fixture)
            changed["decisions"][2]["outcome"] = None
            with self.assertRaises(InputError):
                compile_interview(changed, self.catalog, at=AT)
        self.assertIn(question["id"], BANK)

    def tf_values(self):
        return {
            "azurerm_private_dns_zone": {"name": "fixture.example.invalid"},
            "azurerm_private_dns_zone_virtual_network_link": {
                "name": "network",
                "private_dns_zone_name": "fixture.example.invalid",
                "virtual_network_id": VNET,
                "registration_enabled": True,
                "resolution_policy": "Default",
            },
            "azurerm_private_dns_resolver": {"name": "resolver", "virtual_network_id": VNET},
            "azurerm_private_dns_resolver_inbound_endpoint": {
                "name": "inbound",
                "private_dns_resolver_id": RESOLVER,
                "ip_configurations": [
                    {
                        "subnet_id": SUBNET,
                        "private_ip_allocation_method": "Dynamic",
                        "private_ip_address": DESTINATION,
                    }
                ],
            },
            "azurerm_private_dns_resolver_outbound_endpoint": {
                "name": "outbound",
                "private_dns_resolver_id": RESOLVER,
                "subnet_id": SUBNET,
            },
            "azurerm_private_dns_resolver_dns_forwarding_ruleset": {
                "name": "ruleset",
                "private_dns_resolver_outbound_endpoint_ids": [
                    RESOLVER + "/outboundEndpoints/outbound"
                ],
            },
            "azurerm_private_dns_resolver_forwarding_rule": {
                "name": "rule",
                "dns_forwarding_ruleset_id": RULESET,
                "enabled": True,
                "domain_name": DOMAIN,
                "target_dns_servers": [{"ip_address": DESTINATION, "port": 53}],
            },
            "azurerm_private_dns_resolver_virtual_network_link": {
                "name": "network",
                "dns_forwarding_ruleset_id": RULESET,
                "virtual_network_id": VNET,
            },
            "azurerm_bastion_host": {
                "name": "bastion",
                "sku": "Premium",
                "scale_units": 2,
                "copy_paste_enabled": False,
                "session_recording_enabled": True,
                "ip_configuration": [
                    {"name": "main", "subnet_id": SUBNET, "public_ip_address_id": IP}
                ],
                "dns_name": SENTINEL,
            },
        }

    def test_raw_supplied_modules_and_optional_plan_types_scope_sensitive_no_execution(self):
        values = {
            kind: {**body, "resource_group_name": "dns", "location": "westeurope"}
            for kind, body in self.tf_values().items()
        }
        module = self.root / "snapshots" / "dns"
        self.write(
            "snapshots/dns/main.tf.json",
            {"resource": {kind: {"test": body} for kind, body in values.items()}},
        )
        self.write(
            "source/main.tf.json",
            {"module": {"dns": {"source": "example.invalid/dns/azurerm", "version": "1.0.0"}}},
        )
        manifest = self.write(
            "snapshots/snapshots.json",
            {
                "modules": [
                    {
                        "source": "example.invalid/dns/azurerm",
                        "version": "1.0.0",
                        "subdirectory": "",
                        "path": "dns",
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
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            raw = terraform_source(
                self.root / "source",
                scope=SCOPE,
                provider_version="4.50.0",
                snapshots=manifest,
                authorized_roots=[self.root],
            )
            planned = plan_source(
                self.write("plan.json", plan), scope=SCOPE, provider_version="4.50.0"
            )
        for bundle in (raw, planned):
            self.assertEqual({r["resource_type"].lower() for r in bundle["resources"]}, KINDS)
            self.assertTrue(all(r["arm_id"] for r in bundle["resources"]))
            for secret in (SENTINEL, DOMAIN, DESTINATION):
                self.assertNotIn(secret, json.dumps(bundle))
        resources = plan["planned_values"]["root_module"]["resources"]
        resources[6]["sensitive_values"] = {
            "target_dns_servers": [{"ip_address": True}],
            "domain_name": True,
        }
        hidden = plan_source(
            self.write("sensitive.json", plan), scope=SCOPE, provider_version="4.50.0"
        )
        self.assertIn("unknown", hidden["resources"][6]["properties"]["forwardingTargetSummary"])
        self.assertIn("unknown", hidden["resources"][6]["properties"]["forwardingDomainSummary"])
        unsupported = plan_source(
            self.write("unverified.json", plan), scope=SCOPE, provider_version="4.49.0"
        )
        self.assertTrue(all(r["state"] == "unknown" for r in unsupported["resources"]))
        self.assertIn(
            "unknown",
            tf_properties(
                "azurerm_virtual_network",
                {"encryption": [{"enabled": True, "enforcement": "AllowUnencrypted"}]},
            )["vnetEncryptionEnabled"],
        )
        for parent in (IP, RESOLVER.replace("000000000001", "000000000002")):
            self.assertIsNone(
                tf_resource_id(
                    SCOPE,
                    "azurerm_private_dns_resolver_inbound_endpoint",
                    {"name": "inbound", "private_dns_resolver_id": parent},
                )
            )

    def test_arm_root_region_zones_supported_api_and_missing_transient_link_state(self):
        resources = [
            {
                "type": kind,
                "name": identity.split("/providers/")[1].split("/", 2)[2],
                "apiVersion": next(iter(API_VERSIONS[kind.lower()])),
                "properties": body,
                **(root or {}),
            }
            for kind, identity, body, root in self.details()
        ]
        bundle = arm_source(self.write("arm.json", {"resources": resources}), scope=SCOPE)
        self.assertTrue(all(r["state"] == "known" for r in bundle["resources"]))
        self.assertEqual(bundle["resources"][-1]["properties"]["resourceLocation"], "westeurope")
        self.assertEqual(bundle["resources"][-2]["properties"]["configuredZones"], [])
        resources[4]["apiVersion"] = "2025-05-01"
        unverified = arm_source(
            self.write("unverified-arm.json", {"resources": resources}), scope=SCOPE
        )
        self.assertEqual(unverified["resources"][4]["state"], "unknown")
        self.assertEqual(unverified["resources"][4]["properties"], {})
        for state in (None, "Deleting", True, "Completed"):
            props = properties(
                "Microsoft.Network/privateDnsZones/virtualNetworkLinks",
                {
                    "virtualNetworkLinkState": state,
                    "registrationEnabled": False,
                },
            )
            self.assertIs(props["registrationEnabled"], False)
            if state != "Completed":
                self.assertIn("unknown", props["dnsLinkState"])

    def test_injected_collector_original_scope_partial_denial_no_live_reads(self):
        details = [
            {"id": identity, "type": kind, "properties": body, **(root or {})}
            for kind, identity, body, root in self.details()
        ]
        requests = []

        def transport(method, url):
            requests.append((method, url))
            if "/resources?" in url:
                return Response(
                    200, {"value": [{"id": d["id"], "type": d["type"]} for d in details]}, {}
                )
            for detail in details:
                if url.split("?")[0].lower().endswith(detail["id"].lower()):
                    return Response(200, detail, {})
            return Response(200, {"value": []}, {})

        with (
            patch("socket.socket.connect", side_effect=AssertionError("live reads forbidden")),
            patch("alz_assessor.azure.now", return_value=AT),
        ):
            bundle = Collector(transport).collect(
                subscriptions=["00000000-0000-0000-0000-000000000001"], inventory_authorized=True
            )
        self.assertEqual(bundle["collected_at"], AT)
        for secret in (SENTINEL, DOMAIN, DESTINATION):
            self.assertNotIn(secret, json.dumps(bundle))
        self.assertTrue(any("api-version=2024-06-01" in url for _, url in requests))
        self.assertTrue(any("api-version=2022-07-01" in url for _, url in requests))
        self.assertTrue(
            all(
                method == "GET" or "/policyStates/latest/queryResults" in url
                for method, url in requests
            )
        )
        self.assertTrue(all(url.startswith("https://management.azure.com/") for _, url in requests))

        def denied(method, url):
            if "/dnsresolvers/resolver?" in url.lower():
                return Response(403, {}, {})
            return transport(method, url)

        partial = Collector(denied).collect(
            subscriptions=["00000000-0000-0000-0000-000000000001"], inventory_authorized=True
        )
        resolver = next(
            r for r in partial["resources"] if r["resource_type"].endswith("/dnsResolvers")
        )
        self.assertEqual(resolver["state"], "inaccessible")
        self.assertFalse(partial["metadata"]["run_complete"])

    @unittest.skipUnless(os.environ.get("BICEP_COMPILER"), "Existing Bicep compiler unavailable")
    def test_real_bicep_dns_bastion_no_restore(self):
        bundle = arm_source(
            ROOT / "tests" / "fixtures" / "bicep" / "dns-bastion.bicep",
            scope=SCOPE,
            compiler=os.environ["BICEP_COMPILER"],
            bicep=True,
        )
        self.assertTrue(all(r["state"] == "known" for r in bundle["resources"]))
        kinds = {r["resource_type"].lower() for r in bundle["resources"]}
        self.assertLessEqual(KINDS, kinds)
        for secret in (DOMAIN, DESTINATION):
            self.assertNotIn(secret, json.dumps(bundle))
        report = assess(bundle, self.catalog, evidence_tiers=True)
        for row in report["results"]:
            if row["control_id"] in {"ALZ-" + g for g in GUIDS}:
                self.assertNotEqual(row["planned"]["evidence_tier"], "verified")


if __name__ == "__main__":
    unittest.main()
