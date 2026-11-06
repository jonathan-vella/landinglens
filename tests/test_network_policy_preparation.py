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
from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import control_digest, document, validate
from alz_assessor.engine import assess
from alz_assessor.network_evidence import review_fact
from alz_assessor.network_policy_evidence import (
    ALERT,
    DIAGNOSTIC,
    FIREWALL,
    GATEWAY,
    GUIDS,
    PARTNER,
    POLICY,
    diagnostic_facts,
    fqdn_facts,
    gateway_alert_facts,
    gateway_context,
    partner_facts,
    policy_context,
)
from alz_assessor.plan import plan_source
from alz_assessor.replay import export_bundle, known_catalog, replay_bundle, semantic
from alz_assessor.reports import render, render_xlsx
from alz_assessor.review_page import review_page
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import prepare_reviews, review_context
from alz_assessor.sources import terraform_source, tf_properties
from alz_assessor.terraform import InputError, tree_hash

ROOT = Path(__file__).resolve().parents[1]
SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/network"
OTHER = "/subscriptions/00000000-0000-0000-0000-000000000002/resourceGroups/other"
NETWORK = SCOPE + "/providers/Microsoft.Network/"
FW = NETWORK + "azureFirewalls/firewall"
CHILD = NETWORK + "firewallPolicies/child"
BASE = NETWORK + "firewallPolicies/base"
GW = NETWORK + "virtualNetworkGateways/gateway"
LOG = GW + "/providers/Microsoft.Insights/diagnosticSettings/logs"
METRIC = SCOPE + "/providers/Microsoft.Insights/metricAlerts/gateway-cpu"
WORKSPACE = SCOPE + "/providers/Microsoft.OperationalInsights/workspaces/logs"
ACTION = SCOPE + "/providers/Microsoft.Insights/actionGroups/operators"
PRIVATE = "PRIVATE-NETWORK-POLICY-RULE-PROVIDER-SECRET"
AT = "2026-11-06T15:00:00Z"
CONTROLS = {"ALZ-" + guid for guid in GUIDS}


class NetworkPolicyPreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.catalog = load_catalog()
        self.matrix = json.loads(
            (ROOT / "references/recommendation-batches/preparation-16.json").read_text("utf-8")
        )
        self.rows = {row["upstream_id"]: row for row in self.matrix["recommendations"]}
        self.network = patch(
            "socket.socket.connect", side_effect=AssertionError("network forbidden")
        )
        self.network.start()
        self.addCleanup(self.network.stop)

    def record(self, kind, identity, raw, *, root=None):
        return {
            "logical_id": identity.lower(),
            "arm_id": identity.lower(),
            "resource_type": kind,
            "state": "known",
            "reason": "",
            "source_location": "fixture://authored-network-policy",
            "properties": properties(kind, raw, root=root, observed=True),
        }

    def raw_rules(self):
        return {
            "ruleCollections": [
                {
                    "action": {"type": "Allow"},
                    "rules": [
                        {
                            "ruleType": "NetworkRule",
                            "ipProtocols": ["TCP", "UDP"],
                            "destinationFqdns": [PRIVATE],
                            "destinationAddresses": [],
                            "destinationPorts": [PRIVATE],
                            "sourceAddresses": [PRIVATE],
                            "description": PRIVATE,
                        },
                        {
                            "ruleType": "ApplicationRule",
                            "protocols": [{"protocolType": "Https", "port": 443}],
                            "targetFqdns": [PRIVATE],
                            "destinationAddresses": [],
                            "terminateTLS": False,
                            "webCategories": [],
                        },
                    ],
                }
            ]
        }

    def raw_alert(self):
        return {
            "enabled": True,
            "scopes": [GW],
            "criteria": {
                "odata.type": "Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria",
                "allOf": [
                    {
                        "criterionType": "StaticThresholdCriterion",
                        "metricName": "ExpressRouteGatewayCpuUtilization",
                        "metricNamespace": "Microsoft.Network/virtualNetworkGateways",
                        "timeAggregation": "Average",
                        "threshold": 73,
                        "dimensions": [{"name": "roleInstance", "values": [PRIVATE]}],
                    }
                ],
            },
            "actions": [{"actionGroupId": ACTION, "webHookProperties": {"token": PRIVATE}}],
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
                self.record(FIREWALL, FW, {"firewallPolicy": {"id": CHILD}}),
                self.record(
                    POLICY,
                    CHILD,
                    {"basePolicy": {"id": BASE}, "dnsSettings": {"enableProxy": True}},
                ),
                self.record(POLICY, BASE, {"dnsSettings": {"enableProxy": False}}),
                self.record(
                    POLICY + "/ruleCollectionGroups",
                    CHILD + "/ruleCollectionGroups/egress",
                    self.raw_rules(),
                ),
                self.record(
                    GATEWAY,
                    GW,
                    {
                        "gatewayType": "ExpressRoute",
                        "allowRemoteVnetTraffic": False,
                        "allowVirtualWanTraffic": True,
                    },
                ),
                self.record(
                    DIAGNOSTIC,
                    LOG,
                    {
                        "logs": [{"category": "GatewayDiagnosticLog", "enabled": True}],
                        "workspaceId": WORKSPACE,
                        "storageAccountId": PRIVATE,
                    },
                    root={"scope": GW},
                ),
                self.record(ALERT, METRIC, self.raw_alert()),
            ],
        )

    def by_id(self, bundle):
        result = {}
        for row in bundle["resources"]:
            if isinstance(row.get("arm_id"), str):
                result.setdefault(row["arm_id"].lower(), []).append(row)
        return result

    def context(self, key, bundle=None):
        row = self.rows[key]
        control = copy.deepcopy(
            next(c for c in self.catalog["controls"] if c["upstream_guid"] == row["guid"])
        )
        for field in ("review_resource_types", "review_fact_paths"):
            if field in row:
                control[field] = row[field]
        return review_context(control, bundle or self.bundle())

    def chain(self, bundle=None):
        bundle = bundle or self.bundle()
        return policy_context(bundle["resources"][0], bundle, self.by_id(bundle))

    def monitoring(self, bundle=None):
        bundle = bundle or self.bundle()
        return gateway_context(bundle["resources"][4], bundle, self.by_id(bundle))

    def test_exact_fixed_matrix_source_revision_limits_and_inactive_guards(self):
        targets = json.loads((ROOT / "references/recommendation-batches/targets.json").read_text())
        fixed = {
            row["upstream_id"]: row["guid"] for row in targets["targets"] if row["batch"] == "16"
        }
        self.assertEqual(fixed, {key: row["guid"] for key, row in self.rows.items()})
        self.assertEqual(set(fixed.values()), GUIDS)
        self.assertEqual(set(self.matrix["interview"]["controls"]), CONTROLS)
        self.assertNotIn("catalog_version", self.matrix)
        self.assertEqual(self.matrix["review_state"], "preparation-only-not-accepted")
        self.assertNotIn("network-monitoring-sovereignty-policy", interviews.BANK)
        sources = json.loads(
            (ROOT / "references/recommendation-batches/preparation-16-sources.json").read_text()
        )
        indexed = {row["id"]: row for row in sources["sources"]}
        self.assertEqual(len(indexed), len(sources["sources"]))
        for source in indexed.values():
            self.assertEqual(len(source["sha256"]), 64)
            self.assertEqual(len(source["revision"]), 40)
            self.assertTrue(source["retrieved_at"])
            self.assertTrue(source["reuse"])
        for row in self.rows.values():
            self.assertTrue(set(row["sources"]) <= set(indexed))
            self.assertLessEqual(len(row.get("review_fact_paths", [])), 8)
            self.assertEqual(
                row["classification"], "manual" if row["upstream_id"] == "D06.26" else "assisted"
            )
        self.assertIn(
            "monitor-vpn-gateway-reference", indexed["gateway-diagnostics-linked"]["resolved_url"]
        )
        self.assertIn(
            "virtual-desktop/network-connectivity", indexed["azure-local-linked"]["resolved_url"]
        )
        self.assertIn("conflicting", indexed["vnet-expressroute-linked"]["finding"])
        self.assertIn("only Zscaler", indexed["partner-current"]["finding"])
        self.assertIn("No retirement date", indexed["partner-current"]["finding"])
        original = load_catalog(str(ROOT / "src/alz_assessor/data/catalog-2026-11-04.2.json"))
        original = {row["control_id"]: row for row in original["controls"]}
        for identity, expected in targets["preserved_automated"].items():
            self.assertEqual(control_digest(original[identity]), expected)
        changed = copy.deepcopy(self.catalog)
        control = next(c for c in changed["controls"] if c["upstream_guid"] == fixed["D07.02"])
        control.update(review_resource_types=[POLICY], review_fact_paths=["basePolicy.id"])
        with self.assertRaises(InputError):
            known_catalog(changed)

    def test_policy_prefix_and_exact_local_groups_are_not_global_coverage_or_effective_dns(self):
        chain = self.chain()
        self.assertEqual(
            [row["arm_id"] for row in chain["policies"]], [CHILD.lower(), BASE.lower()]
        )
        self.assertEqual([row["dns_proxy_explicit"] for row in chain["policies"]], [True, False])
        self.assertIn("unknown", chain["termination"])
        groups = chain["policies"][0]["local_rule_groups"]
        self.assertEqual(len(groups["groups"]), 1)
        self.assertEqual(chain["policies"][1]["local_rule_groups"]["groups"], [])
        rules = groups["groups"][0]["rules"]
        self.assertEqual(rules[0]["protocols"], ["TCP", "UDP"])
        self.assertEqual(rules[1]["protocols"], ["Https"])
        self.assertEqual(rules[0]["fqdnCount"], 1)
        self.assertNotIn(PRIVATE, json.dumps(chain))
        context = self.context("D07.02")
        self.assertEqual(context["resources"][0]["configured_policy_chain"], chain)
        self.assertEqual(context["collected_at"], AT)
        self.assertFalse(context["inventory_complete"])

    def test_policy_chain_missing_duplicate_denied_type_scope_cycle_and_boundaries(self):
        for index in (0, 1, 2):
            for state in ("unknown", "error"):
                bundle = self.bundle()
                bundle["resources"][index]["state"] = state
                result = self.chain(bundle)
                self.assertIn("unknown", result if index == 0 else result["termination"])
            bundle = self.bundle()
            bundle["resources"].append(copy.deepcopy(bundle["resources"][index]))
            result = self.chain(bundle)
            self.assertIn("unknown", result if index == 0 else result["termination"])
        bundle = self.bundle()
        bundle["resources"][2]["properties"]["basePolicy"] = {"id": CHILD}
        self.assertEqual(self.chain(bundle)["unknown"], "policy_inheritance_cycle")
        bundle = self.bundle()
        bundle["resources"][1]["properties"]["basePolicy"] = {"id": FW}
        self.assertEqual(len(self.chain(bundle)["policies"]), 1)
        bundle = self.bundle()
        bundle["resources"][1]["properties"]["basePolicy"] = {"id": BASE.replace(SCOPE, OTHER)}
        bundle["resources"][2]["arm_id"] = BASE.replace(SCOPE, OTHER)
        self.assertIn("unknown", self.chain(bundle)["termination"])
        bundle = self.bundle()
        last = bundle["resources"][2]
        for i in range(19):
            identity = BASE + str(i)
            last["properties"]["basePolicy"] = {"id": identity}
            last = self.record(POLICY, identity, {"dnsSettings": {"enableProxy": True}})
            bundle["resources"].append(last)
        self.assertEqual(self.chain(bundle)["unknown"], "policy_chain_over_20")

    def test_wrong_rule_group_parent_and_unavailable_populations_stay_unknown(self):
        bundle = self.bundle()
        bundle["resources"][3]["arm_id"] = BASE.lower() + "/rulecollectiongroups/elsewhere"
        result = self.chain(bundle)
        self.assertEqual(result["policies"][0]["local_rule_groups"]["groups"], [])
        self.assertEqual(len(result["policies"][1]["local_rule_groups"]["groups"]), 1)
        bundle["resources"][3]["state"] = "error"
        self.assertEqual(
            self.chain(bundle)["policies"][0]["local_rule_groups"]["unresolved_groups"], 1
        )
        bundle = self.bundle()
        bundle["resources"].extend(copy.deepcopy(bundle["resources"][3]) for _ in range(100))
        self.assertIn("unknown", self.chain(bundle)["policies"][0]["local_rule_groups"])

    def test_gateway_diagnostics_and_gateway_metric_scopes_not_circuits_or_vpn_support(self):
        context = self.monitoring()
        self.assertEqual(len(context["diagnostics"]), 1)
        self.assertEqual(len(context["metric_alerts"]), 1)
        self.assertEqual(context["metric_alerts"][0]["configuration"]["gatewayIds"], [GW.lower()])
        self.assertIn("unknown", context["coverage"])
        self.assertIn("unknown", context["category_applicability"])
        self.assertNotIn(PRIVATE, json.dumps(context))
        context = self.context("D06.23")
        gateway = next(row for row in context["resources"] if row["arm_id"] == GW.lower())
        self.assertEqual(gateway["configured_gateway_monitoring"], self.monitoring())
        bundle = self.bundle()
        bundle["resources"][4]["properties"]["gatewayType"] = "Vpn"
        self.assertIn("unknown", self.monitoring(bundle))
        bundle = self.bundle()
        bundle["resources"][5]["properties"]["targetResourceId"] = GW + "-other"
        self.assertEqual(self.monitoring(bundle)["diagnostics"], [])
        for index in (4, 5, 6):
            bundle = self.bundle()
            bundle["resources"].append(copy.deepcopy(bundle["resources"][index]))
            result = self.monitoring(bundle)
            if index == 4:
                self.assertIn("unknown", result)
            else:
                self.assertGreater(result["unresolved_monitoring_resources"], 0)
        bundle = self.bundle()
        bundle["resources"].extend(copy.deepcopy(bundle["resources"][5]) for _ in range(99))
        self.assertIn("unknown", self.monitoring(bundle))

    def test_gateway_alerts_malformed_dynamic_duplicate_scope_and_privacy(self):
        fact = properties(ALERT, self.raw_alert())["gatewayMetricAlertSummary"]
        self.assertEqual(gateway_alert_facts(fact), fact)
        self.assertNotIn("threshold", json.dumps(fact))
        self.assertNotIn(PRIVATE, json.dumps(fact))
        for raw in (None, True, {"unknown": PRIVATE}):
            self.assertIn("unknown", gateway_alert_facts(raw))
        self.assertIn("unknown", gateway_alert_facts({})["enabled"])
        for value in ("true", 1, None):
            raw = self.raw_alert()
            raw["enabled"] = value
            self.assertIn("unknown", properties(ALERT, raw)["gatewayMetricAlertSummary"]["enabled"])
        for value in ([GW, GW], [WORKSPACE], None, [], [GW] * 101):
            raw = self.raw_alert()
            raw["scopes"] = value
            fact = gateway_alert_facts(properties(ALERT, raw)["gatewayMetricAlertSummary"])
            self.assertTrue(
                isinstance(fact["gatewayIds"], dict)
                or any(isinstance(v, dict) for v in fact["gatewayIds"])
            )
        raw = self.raw_alert()
        raw["criteria"]["allOf"][0]["criterionType"] = "DynamicThresholdCriterion"
        self.assertIn("unknown", properties(ALERT, raw)["gatewayMetricAlertSummary"]["criteria"])
        raw = self.raw_alert()
        raw["criteria"]["allOf"][0]["metricName"] = "BgpAvailability"
        fact = properties(ALERT, raw)["gatewayMetricAlertSummary"]
        self.assertIn("unknown", fact["criteria"][0]["metricName"])

    def test_diagnostics_categories_strict_flags_and_no_private_payloads(self):
        valid = {
            "logs": [{"category": "TunnelDiagnosticLog", "enabled": False}],
            "workspaceId": WORKSPACE,
            "event": PRIVATE,
        }
        fact = diagnostic_facts(valid)
        self.assertFalse(fact["logs"][0]["enabled"])
        self.assertEqual(diagnostic_facts(fact), fact)
        for logs in ([None], [{}] * 101, True, None):
            self.assertIn("unknown", diagnostic_facts({"logs": logs})["logs"])
        for row in (
            {},
            {"category": PRIVATE},
            {"category": "GatewayDiagnosticLog", "categoryGroup": "allLogs"},
        ):
            self.assertIn("unknown", diagnostic_facts({"logs": [row]}))
        for value in ("true", 1, None):
            self.assertIn(
                "unknown",
                diagnostic_facts({"logs": [{"categoryGroup": "allLogs", "enabled": value}]})[
                    "logs"
                ][0]["enabled"],
            )
        self.assertIn("unknown", diagnostic_facts({"logs": valid["logs"] * 2}))
        self.assertNotIn(PRIVATE, json.dumps(fact))

    def test_protocol_summaries_reuse_counts_with_no_ports_names_addresses_or_fqdns(self):
        fact = properties(POLICY + "/ruleCollectionGroups", self.raw_rules())["fqdnRuleSummary"]
        self.assertEqual(fqdn_facts(fact), fact)
        for key in ("ipProtocols", "protocols"):
            raw = self.raw_rules()
            row = raw["ruleCollections"][0]["rules"][0 if key == "ipProtocols" else 1]
            row[key] = [PRIVATE] if key == "ipProtocols" else [{"protocolType": PRIVATE}]
            result = properties(POLICY + "/ruleCollectionGroups", raw)["fqdnRuleSummary"]
            self.assertIn("unknown", result[0 if key == "ipProtocols" else 1]["protocols"][0])
            self.assertNotIn(PRIVATE, json.dumps(result))
        for value in (None, True, [None], [{}] * 101):
            raw = self.raw_rules()
            raw["ruleCollections"] = value
            self.assertIn(
                "unknown", properties(POLICY + "/ruleCollectionGroups", raw)["fqdnRuleSummary"]
            )

    def test_explicit_gateway_flags_and_typed_policy_references_across_adapters(self):
        for value in (True, False, None, "false", 0, {"unknown": PRIVATE}):
            arm = properties(
                GATEWAY, {"allowRemoteVnetTraffic": value, "allowVirtualWanTraffic": value}
            )
            tf = tf_properties(
                "azurerm_virtual_network_gateway",
                {"remote_vnet_traffic_enabled": value, "virtual_wan_traffic_enabled": value},
            )
            for path in ("allowRemoteVnetTraffic", "allowVirtualWanTraffic"):
                self.assertEqual(arm[path], tf[path])
                if type(value) is bool:
                    self.assertIs(arm[path], value)
                else:
                    self.assertIn("unknown", arm[path])
        for value in (BASE, BASE.upper(), FW, PRIVATE, None, True, {}):
            arm = properties(POLICY, {"basePolicy": {"id": value}})
            tf = tf_properties("azurerm_firewall_policy", {"base_policy_id": value})
            self.assertEqual(arm["basePolicy"], tf["basePolicy"])
            self.assertNotIn(PRIVATE, json.dumps(arm))
        tf = tf_properties(
            "azurerm_monitor_diagnostic_setting",
            {
                "enabled_log": [{"category": "GatewayDiagnosticLog"}],
                "log_analytics_workspace_id": WORKSPACE,
            },
        )
        self.assertTrue(tf["gatewayDiagnosticSummary"]["logs"][0]["enabled"])
        tf = tf_properties(
            "azurerm_monitor_diagnostic_setting",
            {
                "enabled_log": [{"category": "GatewayDiagnosticLog", "category_group": "allLogs"}],
            },
        )
        self.assertIn("unknown", tf["gatewayDiagnosticSummary"])
        self.assertEqual(
            properties(POLICY, {})["basePolicy"],
            {"id": {"unknown": "relationship_missing_invalid_or_wrong_type"}},
        )

    def test_original_time_replay_preserves_joins_and_rejects_unaccepted_catalog(self):
        bundle = self.bundle()
        before = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        directory = self.root / "replay"
        export_bundle(directory, bundle, self.catalog, at=AT, evidence_tiers=True)
        self.assertEqual(semantic(before), semantic(replay_bundle(directory)))
        saved = json.loads((directory / "evidence.json").read_text())
        self.assertEqual(saved["collected_at"], AT)
        self.assertEqual(self.chain(saved), self.chain(bundle))
        self.assertEqual(self.monitoring(saved), self.monitoring(bundle))
        self.assertNotIn(PRIVATE, (directory / "evidence.json").read_text())
        self.assertTrue(
            all(
                review_fact(row["properties"], "allowRemoteVnetTraffic") is False
                for row in saved["resources"]
                if row["resource_type"].lower() == GATEWAY
            )
        )

    def test_blank_separate_decisions_no_verified_or_synthetic_owner_policy(self):
        for state in ("known", "unknown", "error"):
            bundle = self.bundle()
            for row in bundle["resources"]:
                row["state"] = state
                row["reason"] = "" if state == "known" else "detail_denied"
            report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
            rows = [row for row in report["results"] if row["control_id"] in CONTROLS]
            self.assertEqual(len(rows), 9)
            self.assertTrue(all(row["observed"]["outcome"] != "pass" for row in rows))
            self.assertTrue(all(row["observed"]["evidence_tier"] != "verified" for row in rows))
            prepared = prepare_reviews(report, self.catalog, sorted(CONTROLS), SCOPE)
            self.assertEqual(len(prepared["entries"]), 9)
            self.assertTrue(all(row["outcome"] is None for row in prepared["entries"]))
        manual = self.context("D06.26")
        self.assertEqual(manual["resources"], [])
        bundle = self.bundle()
        bundle["resources"].append(self.record(FIREWALL, FW.replace(SCOPE, OTHER), {}))
        self.assertEqual(self.context("D07.01", bundle)["unbound_resources"], 1)

    def test_prepared_interview_binding_expiry_reports_session_and_independent_exceptions(self):
        question = self.matrix["interview"]
        with patch.dict(
            interviews.BANK,
            {question["id"]: {"question": question["question"], "controls": question["controls"]}},
        ):
            report = assess(self.bundle(), self.catalog, at=AT, evidence_tiers=True)
            response = interviews.prepare_interview(report, self.catalog, question["id"], SCOPE)
            self.assertEqual(len(response["decisions"]), 9)
            self.assertTrue(all(row["outcome"] is None for row in response["decisions"]))
            with self.assertRaises(InputError):
                interviews.compile_interview(response, self.catalog, at=AT)
            response.update(
                answer="Authored fixture evidence, not a real owner decision.",
                reviewer="Authored fixture reviewer",
                rationale="Nine separate decisions.",
                evidence="https://example.invalid/redacted",
                valid_from=AT,
                valid_until="2026-11-07T15:00:00Z",
            )
            for index, row in enumerate(response["decisions"]):
                row["outcome"] = "fail" if index % 2 else "pass"
            manual = interviews.compile_interview(response, self.catalog, at=AT)
            exceptions = document(
                "exceptions",
                schema_version="1.1",
                entries=[
                    {key: value for key, value in manual["entries"][0].items() if key != "outcome"}
                    | {"disposition": "accepted"}
                ],
            )
            report = assess(
                self.bundle(),
                self.catalog,
                at=AT,
                manual=manual,
                exceptions=exceptions,
                evidence_tiers=True,
            )
            rows = [r for r in report["results"] if r["control_id"] in CONTROLS]
            self.assertTrue(all(r["observed"]["evidence_tier"] != "verified" for r in rows))
            self.assertTrue(all(r["observed"]["reason"] == "manual_attestation" for r in rows))
            self.assertTrue(
                any(r["observed"].get("exception_disposition") == "accepted" for r in rows)
            )
            for format in ("json", "markdown", "html", "csv", "sarif", "pr-summary"):
                self.assertNotIn(PRIVATE, render(report, format))
            with zipfile.ZipFile(io.BytesIO(render_xlsx(report))) as archive:
                self.assertNotIn(
                    PRIVATE, "\n".join(archive.read(p).decode() for p in archive.namelist())
                )
            changed = copy.deepcopy(response)
            changed["decisions"][0]["control_sha256"] = "0" * 64
            with self.assertRaises(InputError):
                interviews.compile_interview(changed, self.catalog, at=AT)
            with self.assertRaises(InputError):
                interviews.compile_interview(response, self.catalog, at="2026-11-08T15:00:00Z")
            session = ReviewSession(
                self.bundle(),
                self.catalog,
                self.root / "session",
                clock=lambda: AT,
                evidence_tiers=True,
            )
            state = session.state()
            item = next(row for row in state["interviews"] if row["id"] == question["id"])
            self.assertEqual(len(item["template"]["decisions"]), 9)
            self.assertIn("cross borders", review_page(state, "fixture-token", "fixture-nonce"))
            state = session.save_interview(
                {"revision": 0, "response": response, "replace_existing": []}
            )
            self.assertEqual(len(state["records"]), 9)
            resumed = ReviewSession.resume(
                session.directory / "revision-0001", self.root / "resumed", clock=lambda: AT
            )
            self.assertEqual(semantic(session.report), semantic(resumed.report))

    def test_raw_supplied_local_module_and_sensitive_optional_plan_without_execution(self):
        module = self.root / "module"
        module.mkdir()
        (module / "main.tf").write_text(
            'resource "azurerm_virtual_network_gateway" "gateway" {\n'
            'name="gateway"\nresource_group_name="network"\ntype="ExpressRoute"\n'
            "remote_vnet_traffic_enabled=false\nvirtual_wan_traffic_enabled=true\n}\n"
            'resource "azurerm_firewall_policy" "child" {\n'
            f'name="child"\nresource_group_name="network"\nbase_policy_id="{BASE}"\n'
            "dns { proxy_enabled=true }\n}\n"
        )
        raw = terraform_source(module, scope=SCOPE, provider_version="4.50.0")
        self.assertTrue(
            any(
                row["properties"].get("allowRemoteVnetTraffic") is False for row in raw["resources"]
            )
        )
        wrapper = self.root / "wrapper"
        wrapper.mkdir()
        (wrapper / "main.tf").write_text(
            'module "supplied" {\nsource="example.invalid/network/policy/azurerm"\n'
            'version="1.0.0"\n}\n'
        )
        snapshots = self.root / "snapshots.json"
        snapshots.write_text(
            json.dumps(
                {
                    "modules": [
                        {
                            "source": "example.invalid/network/policy/azurerm",
                            "version": "1.0.0",
                            "subdirectory": "",
                            "path": "module",
                            "sha256": tree_hash(module),
                        }
                    ]
                }
            )
        )
        supplied = terraform_source(
            wrapper,
            scope=SCOPE,
            provider_version="4.50.0",
            snapshots=snapshots,
            authorized_roots=[module],
        )
        self.assertTrue(
            any(
                row["properties"].get("allowRemoteVnetTraffic") is False
                for row in supplied["resources"]
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
                                    "type": "azurerm_firewall_policy",
                                    "address": "azurerm_firewall_policy.child",
                                    "values": {
                                        "name": "child",
                                        "resource_group_name": "network",
                                        "base_policy_id": BASE,
                                        "dns": [{"proxy_enabled": True}],
                                        "private": PRIVATE,
                                    },
                                    "sensitive_values": {"base_policy_id": True, "dns": True},
                                }
                            ]
                        }
                    },
                }
            )
        )
        saved = plan_source(plan, scope=SCOPE, provider_version="4.50.0")
        self.assertIn("unknown", saved["resources"][0]["properties"]["basePolicy"]["id"])
        self.assertNotIn(PRIVATE, json.dumps(saved))

    def test_injected_existing_gateway_policy_reads_and_denial_no_new_routes(self):
        requests = []
        identities = [(GATEWAY, GW), (POLICY, CHILD)]

        def transport(method, url):
            requests.append((method, url))
            if "/resources?" in url:
                return Response(
                    200,
                    {"value": [{"id": identity, "type": kind} for kind, identity in identities]},
                    {},
                )
            if "/virtualNetworkGateways/gateway?" in url:
                return Response(
                    200,
                    {
                        "id": GW,
                        "properties": {
                            "gatewayType": "ExpressRoute",
                            "allowRemoteVnetTraffic": False,
                            "allowVirtualWanTraffic": True,
                            "bgpPeer": PRIVATE,
                        },
                    },
                    {},
                )
            if "/firewallPolicies/child?" in url:
                return Response(
                    200,
                    {
                        "id": CHILD,
                        "properties": {
                            "basePolicy": {"id": BASE},
                            "dnsSettings": {"enableProxy": True},
                            "private": PRIVATE,
                        },
                    },
                    {},
                )
            return Response(200, {"value": []}, {})

        bundle = Collector(transport).collect(
            subscriptions=[SCOPE.split("/")[2]], inventory_authorized=True
        )
        gateway = next(
            row for row in bundle["resources"] if row["resource_type"].lower() == GATEWAY
        )
        policy = next(row for row in bundle["resources"] if row["resource_type"].lower() == POLICY)
        self.assertIs(gateway["properties"]["allowRemoteVnetTraffic"], False)
        self.assertEqual(policy["properties"]["basePolicy"]["id"], BASE.lower())
        self.assertNotIn(PRIVATE, json.dumps(bundle))
        self.assertFalse(
            any(
                "effectiveroute" in url.lower() or "loganalytics" in url.lower()
                for _, url in requests
            )
        )

        def denied(method, url):
            if "/virtualNetworkGateways/gateway?" in url:
                return Response(403, {}, {})
            return transport(method, url)

        bundle = Collector(denied).collect(
            subscriptions=[SCOPE.split("/")[2]], inventory_authorized=True
        )
        gateway = next(
            row for row in bundle["resources"] if row["resource_type"].lower() == GATEWAY
        )
        self.assertNotEqual(gateway["state"], "known")

    def test_unsupported_versions_stale_and_malformed_evidence_never_pass(self):
        path = self.root / "unsupported.json"
        path.write_text(
            json.dumps(
                {
                    "resources": [
                        {
                            "type": GATEWAY,
                            "name": "gateway",
                            "apiVersion": "1900-01-01",
                            "properties": {
                                "gatewayType": "ExpressRoute",
                                "allowRemoteVnetTraffic": False,
                                "private": PRIVATE,
                            },
                        }
                    ]
                }
            )
        )
        bundle = arm_source(path, scope=SCOPE)
        self.assertEqual(bundle["resources"][0]["state"], "unknown")
        self.assertNotIn(PRIVATE, json.dumps(bundle))
        bundle = self.bundle()
        bundle["collected_at"] = "2026-11-01T15:00:00Z"
        report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        selected = [row for row in report["results"] if row["control_id"] in CONTROLS]
        self.assertTrue(all(row["observed"]["freshness"] == "stale" for row in selected))
        self.assertTrue(all(row["observed"]["outcome"] != "pass" for row in selected))
        bundle["resources"][0]["state"] = "unexpected"
        with self.assertRaises(InputError):
            self.context("D07.02", bundle)

    def test_partner_schema_enum_is_not_current_support_or_secured_hub_filtering(self):
        hub = NETWORK + "virtualHubs/hub"
        self.assertNotIn(PARTNER, API_VERSIONS)
        self.assertEqual(PLANNED_API_VERSIONS[PARTNER], {"2024-05-01"})
        for value in ("ZScaler", "IBoss", "CheckPoint", "Zscaler", PRIVATE, None, True):
            fact = properties(
                PARTNER,
                {
                    "securityProviderName": value,
                    "virtualHub": {"id": hub},
                    "connectionStatus": "Connected",
                    "credential": PRIVATE,
                },
            )["partnerConfiguration"]
            self.assertEqual(partner_facts(fact), fact)
            self.assertIn("unknown", fact["current_service_support"])
            self.assertEqual(fact["virtualHubId"], hub.lower())
            self.assertNotIn(PRIVATE, json.dumps(fact))
            self.assertNotIn("Connected", json.dumps(fact))
        fact = properties(
            PARTNER,
            {
                "securityProviderName": "ZScaler",
                "virtualHub": {"id": FW},
            },
        )["partnerConfiguration"]
        self.assertIn("unknown", fact["virtualHubId"])
        bundle = self.bundle()
        bundle["resources"].append(
            self.record(
                PARTNER,
                NETWORK + "securityPartnerProviders/p",
                {
                    "securityProviderName": "IBoss",
                    "virtualHub": {"id": hub},
                },
            )
        )
        directory = self.root / "partner-replay"
        export_bundle(directory, bundle, self.catalog, at=AT, evidence_tiers=True)
        saved = json.loads((directory / "evidence.json").read_text())
        self.assertEqual(
            saved["resources"][-1]["properties"]["partnerConfiguration"],
            bundle["resources"][-1]["properties"]["partnerConfiguration"],
        )

    def test_real_bicep_policy_gateway_diagnostics_without_restore(self):
        compiler = os.environ.get("BICEP_COMPILER")
        if not compiler:
            self.skipTest("Set BICEP_COMPILER to an existing compiler; no acquisition")
        parameters = self.root / "parameters.json"
        parameters.write_text(
            json.dumps(
                {
                    "parameters": {
                        "workspaceId": {"value": WORKSPACE},
                        "actionGroupId": {"value": ACTION},
                        "virtualHubId": {"value": NETWORK + "virtualHubs/hub"},
                    }
                }
            )
        )
        evidence = arm_source(
            ROOT / "tests/fixtures/network-policy/controls.bicep",
            scope=SCOPE,
            compiler=compiler,
            parameters=parameters,
            bicep=True,
        )
        validate(evidence, "evidence")
        by_id = self.by_id(evidence)
        firewall = next(r for r in evidence["resources"] if r["resource_type"].lower() == FIREWALL)
        gateway = next(r for r in evidence["resources"] if r["resource_type"].lower() == GATEWAY)
        self.assertEqual(len(policy_context(firewall, evidence, by_id)["policies"]), 2)
        self.assertIs(gateway["properties"]["allowRemoteVnetTraffic"], False)
        monitoring = gateway_context(gateway, evidence, by_id)
        self.assertEqual(len(monitoring["diagnostics"]), 1)
        self.assertEqual(len(monitoring["metric_alerts"]), 1)
        partner = next(
            row for row in evidence["resources"] if row["resource_type"].lower() == PARTNER
        )
        self.assertEqual(
            partner["properties"]["partnerConfiguration"]["schemaProviderName"], "ZScaler"
        )
        self.assertIn(
            "unknown", partner["properties"]["partnerConfiguration"]["current_service_support"]
        )
        self.assertNotIn("authored.example.invalid", json.dumps(evidence))
        report = assess(evidence, self.catalog, at=evidence["collected_at"], evidence_tiers=True)
        self.assertTrue(
            all(
                r["planned"]["evidence_tier"] != "verified"
                for r in report["results"]
                if r["control_id"] in CONTROLS
            )
        )


if __name__ == "__main__":
    unittest.main()
