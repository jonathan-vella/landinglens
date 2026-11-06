import contextlib
import copy
import io
import json
import os
import runpy
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from alz_assessor import interviews
from alz_assessor.arm import API_VERSIONS, PLANNED_API_VERSIONS, arm_source, properties
from alz_assessor.azure import Collector, Response
from alz_assessor.catalog import load_catalog
from alz_assessor.cli import main
from alz_assessor.contracts import control_digest, digest, document
from alz_assessor.engine import assess
from alz_assessor.interviews import compile_interview, prepare_interview
from alz_assessor.plan import plan_source
from alz_assessor.platform_health_evidence import (
    ACTION_GROUP,
    ACTIVITY_ALERT,
    GUIDS,
    RECEIVERS,
    SKUS,
    STORAGE,
    action_facts,
    activity_facts,
    linked_context,
    metric_facts,
    scopes,
    storage_facts,
)
from alz_assessor.replay import export_bundle, replay_bundle, sanitize_evidence, semantic
from alz_assessor.reports import render, render_xlsx
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import prepare_reviews, review_context, validate_reviews
from alz_assessor.sources import terraform_source, tf_properties
from alz_assessor.terraform import InputError

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "references" / "recommendation-batches"
SUB = "/subscriptions/00000000-0000-0000-0000-000000000001"
SCOPE = SUB + "/resourceGroups/health"
GROUP = SCOPE + "/providers/Microsoft.Insights/actionGroups/authored-actions"
ACCOUNT = SCOPE + "/providers/Microsoft.Storage/storageAccounts/authoredlogs"
METRIC = "microsoft.insights/metricalerts"
WORKSPACE = "microsoft.operationalinsights/workspaces"
LOG_ALERT = "microsoft.insights/scheduledqueryrules"
AT = "2026-11-06T21:00:00Z"
UNTIL = "2026-11-07T21:00:00Z"
PRIVATE = "PRIVATE-RECIPIENT-QUERY-LOG-KEY-WEBHOOK-PHONE-BILLING-IDENTITY"
IDS = {"ALZ-" + guid for guid in GUIDS}


class PlatformHealthPreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.matrix = json.loads((REFERENCE / "preparation-25.json").read_text("utf-8"))
        predecessor = files("alz_assessor").joinpath("data", "catalog-2026-11-06.20.json")
        self.accepted = load_catalog(str(predecessor)) if predecessor.is_file() else load_catalog()
        self.catalog = copy.deepcopy(self.accepted)
        for control in self.catalog["controls"]:
            row = next(
                (
                    r
                    for r in self.matrix["recommendations"]
                    if r["guid"] == control["upstream_guid"]
                ),
                None,
            )
            if row:
                control.update(
                    evidence_requirements=row["evidence_requirements"],
                    rationale=row["limitations"],
                )
                if "review_fact_paths" in row:
                    control.update(
                        review_fact_paths=row["review_fact_paths"],
                        review_resource_types=row["review_resource_types"],
                    )
        self.question = self.matrix["interview"]["id"]
        bank = patch.dict(
            interviews.BANK,
            {
                self.question: {
                    "question": self.matrix["interview"]["question"],
                    "controls": self.matrix["interview"]["controls"],
                }
            },
        )
        bank.start()
        self.addCleanup(bank.stop)
        network = patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden"))
        network.start()
        self.addCleanup(network.stop)

    def write(self, name, data):
        path = self.root / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def control(self, display):
        return next(c for c in self.catalog["controls"] if c["upstream_id"] == display)

    def record(self, kind, identity, raw, *, root=None):
        return {
            "logical_id": identity.lower(),
            "arm_id": identity.lower(),
            "resource_type": kind,
            "state": "known",
            "reason": "",
            "source_location": "fixture://authored-platform-health",
            "properties": properties(kind, raw, root=root, observed=True),
        }

    def action(self):
        return {
            "enabled": True,
            **{
                arm: [{"emailAddress": PRIVATE, "phoneNumber": PRIVATE, "serviceUri": PRIVATE}]
                for arm, _ in RECEIVERS.values()
            },
            "groupShortName": PRIVATE,
        }

    def activity(self, category="ServiceHealth"):
        return {
            "enabled": True,
            "scopes": [SUB],
            "condition": {
                "allOf": [
                    {"field": "category", "equals": category},
                    {"field": "properties.impactedServices", "containsAny": [PRIVATE]},
                ]
            },
            "actions": {"actionGroups": [{"actionGroupId": GROUP, "webhookProperties": PRIVATE}]},
            "description": PRIVATE,
        }

    def metric(self):
        return {
            "enabled": True,
            "scopes": [ACCOUNT],
            "evaluationFrequency": "PT5M",
            "windowSize": "PT15M",
            "criteria": {
                "odata.type": "Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria",
                "allOf": [
                    {
                        "criterionType": "StaticThresholdCriterion",
                        "metricName": PRIVATE,
                        "metricNamespace": PRIVATE,
                        "threshold": 1,
                        "dimensions": [PRIVATE],
                    }
                ],
            },
            "actions": [{"actionGroupId": GROUP, "webHookProperties": PRIVATE}],
        }

    def bundle(self):
        workspace = SCOPE + "/providers/Microsoft.OperationalInsights/workspaces/authored"
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
                self.record(ACTION_GROUP, GROUP, self.action(), root={"location": "global"}),
                self.record(
                    ACTIVITY_ALERT,
                    SCOPE + "/providers/Microsoft.Insights/activityLogAlerts/service",
                    self.activity(),
                ),
                self.record(
                    ACTIVITY_ALERT,
                    SCOPE + "/providers/Microsoft.Insights/activityLogAlerts/resource",
                    self.activity("ResourceHealth"),
                ),
                self.record(
                    STORAGE,
                    ACCOUNT,
                    {"keys": PRIVATE},
                    root={"sku": {"name": "Standard_ZRS"}, "kind": "StorageV2"},
                ),
                self.record(
                    METRIC, SCOPE + "/providers/Microsoft.Insights/metricAlerts/ops", self.metric()
                ),
                self.record(
                    WORKSPACE,
                    workspace,
                    {
                        "sku": {"name": "PerGB2018"},
                        "retentionInDays": 30,
                        "publicNetworkAccessForIngestion": "Enabled",
                        "publicNetworkAccessForQuery": "Disabled",
                        "primarySharedKey": PRIVATE,
                    },
                ),
                self.record(
                    LOG_ALERT,
                    SCOPE + "/providers/Microsoft.Insights/scheduledQueryRules/ops",
                    {
                        "enabled": True,
                        "scopes": [workspace],
                        "evaluationFrequency": "PT5M",
                        "windowSize": "PT15M",
                        "criteria": {"allOf": [{"query": PRIVATE}]},
                        "actions": {"actionGroups": [GROUP]},
                    },
                    root={"kind": "LogAlert"},
                ),
            ],
        )

    def index(self, bundle):
        result = {}
        for row in bundle["resources"]:
            result.setdefault((row.get("arm_id") or "").lower(), []).append(row)
        return result

    def report(self, **kwargs):
        return assess(self.bundle(), self.catalog, at=AT, evidence_tiers=True, **kwargs)

    def completed(self):
        response = prepare_interview(self.report(), self.catalog, self.question, SCOPE)
        response.update(
            answer="Authored fixture: nine independently considered decisions.",
            reviewer="Authored test reviewer",
            rationale="Not a real operating approval.",
            evidence="https://example.invalid/redacted",
            valid_from=AT,
            valid_until=UNTIL,
        )
        for row, outcome in zip(
            response["decisions"],
            (
                "pass",
                "fail",
                "not_applicable",
                "fail",
                "not_applicable",
                "pass",
                "fail",
                "not_applicable",
                "pass",
            ),
            strict=True,
        ):
            row["outcome"] = outcome
        return response

    def test_exact_nine_fixed_targets_unactivated_and_immutable_controls(self):
        targets = json.loads((REFERENCE / "targets.json").read_text("utf-8"))
        fixed = {r["guid"] for r in targets["targets"] if r["batch"] == "25"}
        self.assertEqual(fixed, GUIDS)
        self.assertEqual({r["guid"] for r in self.matrix["recommendations"]}, fixed)
        self.assertEqual(len(fixed), 9)
        self.assertEqual(self.matrix["review_state"], "preparation-only-reviewed")
        self.assertNotIn("catalog_version", self.matrix)
        self.assertNotIn("accepted_at", self.matrix)
        before = {c["control_id"]: c for c in self.accepted["controls"]}
        for control in self.catalog["controls"]:
            original = before[control["control_id"]]
            if control["control_id"] not in IDS:
                self.assertEqual(control_digest(control), control_digest(original))
            else:
                for key in ("recommendation", "references", "upstream_guid", "automation", "rule"):
                    self.assertEqual(control[key], original[key])
                self.assertIsNone(control["rule"])
        self.assertEqual(len(self.catalog["controls"]), 255)
        builder = runpy.run_path(str(ROOT / "tools" / "build_batches.py"), run_name="prep")
        with self.assertRaisesRegex(ValueError, "Preparation"):
            builder["apply_batch"](self.accepted, self.accepted, targets, self.matrix, [], [])
        capture = runpy.run_path(str(ROOT / "tools" / "review_batch_sources.py"), run_name="prep")
        with patch("sys.argv", ["review_batch_sources.py", "--batch", "25"]):
            with self.assertRaisesRegex(ValueError, "preparation-only"):
                capture["main"]()

    def test_actual_nine_guidance_sources_revisions_hashes_terms_and_lifecycle(self):
        capture = json.loads((REFERENCE / "preparation-25-sources.json").read_text("utf-8"))
        self.assertEqual(capture["review_state"], "preparation-only-reviewed")
        sources = {r["id"]: r for r in capture["sources"]}
        self.assertGreaterEqual(len(sources), 26)
        for row in self.matrix["recommendations"]:
            original = self.control(row["upstream_id"])
            self.assertIn(
                original["references"][0]["guidance"], [sources[s]["url"] for s in row["sources"]]
            )
            self.assertEqual(len(row["evidence_requirements"]), 3)
            self.assertEqual(row["classification"], original["automation"])
        for source in sources.values():
            self.assertRegex(source["sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(source["revision"], r"^[0-9a-f]{40}$")
            self.assertTrue(source["retrieved_at"])
            self.assertIn("only", source["reuse"])
        self.assertIn("March 31, 2026", sources["diagnostics-extension-linked"]["finding"])
        self.assertIn("forbids new deployments", sources["diagnostics-extension-linked"]["finding"])
        self.assertIn("September 1, 2026", sources["diagnostics-migration"]["finding"])
        self.assertIn("not itself specify", sources["sentinel-linked"]["finding"])
        requirements = [self.control(f"F01.{n}")["evidence_requirements"] for n in range(10, 19)]
        self.assertEqual(len({json.dumps(r) for r in requirements}), 9)

    def test_exact_qualified_skus_no_substrings_defaults_or_fake_premium_geo(self):
        self.assertEqual(len(SKUS), 8)
        for sku, redundancy in SKUS.items():
            result = storage_facts({"sku": sku, "kind": "StorageV2"})
            self.assertEqual(result["configuredRedundancy"], redundancy)
            tier, replication = sku.split("_")
            tf = tf_properties(
                "azurerm_storage_account",
                {
                    "account_tier": tier,
                    "account_replication_type": replication,
                },
            )["storageRedundancySummary"]
            self.assertEqual(tf["sku"], sku)
        for sku in (
            None,
            True,
            1,
            [],
            {},
            "standard_zrs",
            "Standard_ZRS_extra",
            "ZRS",
            "Premium_GRS",
            "Premium_RAGZRS",
            PRIVATE,
        ):
            result = storage_facts({"sku": sku})
            self.assertIn("unknown", result["sku"])
            self.assertIn("unknown", result["configuredRedundancy"])
            self.assertNotIn(PRIVATE, json.dumps(result))
        for values in ({}, {"account_replication_type": "ZRS"}, {"account_tier": "Standard"}):
            self.assertIn(
                "unknown",
                tf_properties("azurerm_storage_account", values)["storageRedundancySummary"]["sku"],
            )
        self.assertEqual(storage_facts({"sku": "Standard_LRS"})["configuredRedundancy"], "local")

    def test_all_projection_types_counts_bounds_and_payload_privacy(self):
        self.assertNotIn(PRIVATE, json.dumps(self.bundle()))
        for fn in (action_facts, activity_facts, metric_facts, storage_facts):
            for value in (None, True, 1, [], PRIVATE, {"unknown": PRIVATE}):
                result = fn(value)
                self.assertIn("unknown", result)
                self.assertNotIn(PRIVATE, json.dumps(result))
        for value in (None, True, -1, 101, "1", PRIVATE):
            result = action_facts({"receiverCounts": {"email": value}})
            self.assertIn("unknown", result["receiverCounts"]["email"])
        for size in (0, 100):
            raw = self.action()
            raw["emailReceivers"] = [{}] * size
            result = properties(ACTION_GROUP, raw)["actionGroupSummary"]
            self.assertEqual(result["receiverCounts"]["email"], size)
        for array in (None, "bad", [None], [{}] * 101, [{"unknown": PRIVATE}]):
            raw = self.action()
            raw["emailReceivers"] = array
            self.assertIn(
                "unknown",
                properties(ACTION_GROUP, raw)["actionGroupSummary"]["receiverCounts"]["email"],
            )
        for kind in (ACTION_GROUP, ACTIVITY_ALERT, METRIC):
            result = properties(kind, {})
            path = next(
                p
                for p in result
                if p
                in {"actionGroupSummary", "activityAlertSummary", "operationalMetricAlertSummary"}
            )
            self.assertIn("unknown", result[path]["enabled"])
        self.assertIn(
            "unknown", properties(ACTION_GROUP, {})["actionGroupSummary"]["globalProcessing"]
        )
        regional = properties(ACTION_GROUP, self.action(), root={"location": "westeurope"})
        self.assertIs(regional["actionGroupSummary"]["globalProcessing"], False)

    def test_service_resource_categories_are_distinct_and_unsupported_forms_unknown(self):
        for category in ("ServiceHealth", "ResourceHealth"):
            result = properties(ACTIVITY_ALERT, self.activity(category))["activityAlertSummary"]
            self.assertEqual(result["category"], category)
            self.assertEqual(result["conditionCount"], 2)
        for conditions in (
            [],
            None,
            [None],
            [{}] * 101,
            [{"field": "category", "containsAny": ["ServiceHealth"]}],
            [{"field": "category", "equals": PRIVATE}],
            [{"field": "category", "equals": "ServiceHealth"}] * 2,
            [{"anyOf": [{"field": "category", "equals": "ResourceHealth"}]}],
        ):
            raw = self.activity()
            raw["condition"] = {"allOf": conditions}
            result = properties(ACTIVITY_ALERT, raw)["activityAlertSummary"]
            self.assertIn("unknown", result["category"])
            self.assertNotIn(PRIVATE, json.dumps(result))
        for value in (True, 1, PRIVATE, [], [SUB, SUB.upper()], [PRIVATE], [SUB] * 101):
            self.assertIn("unknown", scopes(value))
        self.assertEqual(scopes([SUB]), [SUB.lower()])

    def test_generic_metric_metadata_does_not_broaden_prior_specialized_facts(self):
        result = properties(METRIC, self.metric())
        self.assertEqual(result["operationalMetricAlertSummary"]["staticConditionCount"], 1)
        self.assertIn("unknown", result["expressRouteAlertSummary"]["criteria"][0]["metricName"])
        self.assertIn("unknown", result["eventGridMetricAlertSummary"]["topicIds"])
        for change in (
            {"scopes": [ACCOUNT, ACCOUNT + "other"]},
            {
                "criteria": {
                    "odata.type": "Microsoft.Azure.Monitor.MultipleResourceMultipleMetricCriteria"
                }
            },
            {
                "criteria": {
                    "odata.type": "Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria",
                    "allOf": [{"criterionType": "DynamicThresholdCriterion"}],
                }
            },
            {"criteria": {"allOf": [{}] * 101}},
        ):
            raw = {**self.metric(), **change}
            self.assertIn(
                "unknown",
                properties(METRIC, raw)["operationalMetricAlertSummary"]["staticConditionCount"],
            )
        self.assertNotIn(PRIVATE, json.dumps(result))

    def test_strict_scoped_action_and_target_relationships(self):
        bundle = self.bundle()
        for position in (1, 2, 4, 6):
            context = linked_context(bundle["resources"][position], self.index(bundle), SCOPE)
            self.assertEqual(context["actionGroups"][0]["arm_id"], GROUP.lower())
            self.assertIn("not event emission", context["warning"])
        self.assertEqual(
            linked_context(bundle["resources"][4], self.index(bundle), SCOPE)["configuredTargets"][
                0
            ]["arm_id"],
            ACCOUNT.lower(),
        )
        for mutation in ("missing", "duplicate", "denied", "wrong_type", "outside"):
            changed = copy.deepcopy(bundle)
            if mutation == "missing":
                changed["resources"].pop(0)
            elif mutation == "duplicate":
                changed["resources"].append(copy.deepcopy(changed["resources"][0]))
            elif mutation == "denied":
                changed["resources"][0].update(state="error", reason="permission_denied")
            elif mutation == "wrong_type":
                changed["resources"][0]["resource_type"] = STORAGE
            else:
                changed["scope"] = SUB + "/resourceGroups/other"
            alert = next(r for r in changed["resources"] if r["resource_type"] == ACTIVITY_ALERT)
            result = linked_context(alert, self.index(changed), changed["scope"])
            self.assertIn("unknown", result if "unknown" in result else result["actionGroups"][0])
        for field, value in (
            ("actionIds", [GROUP] * 2),
            ("actionIds", [ACCOUNT]),
            ("actionIds", [GROUP + str(i) for i in range(6)]),
        ):
            self.assertIn("unknown", activity_facts({field: value})[field])
        changed = copy.deepcopy(bundle)
        changed["resources"][3]["state"] = "unknown"
        result = linked_context(changed["resources"][4], self.index(changed), SCOPE)
        self.assertIn("unknown", result["configuredTargets"][0])

    def test_raw_terraform_local_module_and_plan_explicit_provider_and_sensitive_fields(self):
        source = self.root / "source"
        child = source / "health"
        child.mkdir(parents=True)
        (source / "main.tf").write_text('module "health" { source = "./health" }\n', "utf-8")
        text = (
            'resource "azurerm_monitor_action_group" "a" {\n'
            'name = "authored-actions"\nresource_group_name = "health"\n'
            'enabled = true\nlocation = "global"\nshort_name = "fixture"\n'
            f'email_receiver {{ name = "fixture"\nemail_address = "{PRIVATE}" }}\n}}\n'
            'resource "azurerm_monitor_activity_log_alert" "a" {\n'
            'name = "authored-service-health"\nresource_group_name = "health"\n'
            f'enabled = true\nscopes = ["{SUB}"]\n'
            'criteria { category = "ServiceHealth" }\n'
            f'action {{ action_group_id = "{GROUP}" }}\n}}\n'
            'resource "azurerm_monitor_metric_alert" "a" {\n'
            'name = "authored-ops"\nresource_group_name = "health"\n'
            f'enabled = true\nscopes = ["{ACCOUNT}"]\nfrequency = "PT5M"\n'
            'window_size = "PT15M"\ncriteria { aggregation = "Total" }\n'
            f'action {{ action_group_id = "{GROUP}" }}\n}}\n'
        )
        (child / "main.tf").write_text(text, "utf-8")
        bundle = terraform_source(source, scope=SCOPE, provider_version="4.50.0")
        self.assertEqual(len(bundle["resources"]), 3)
        self.assertNotIn(PRIVATE, json.dumps(bundle))
        self.assertEqual(bundle["resources"][0]["arm_id"], GROUP.lower())
        self.assertEqual(
            bundle["resources"][0]["properties"]["actionGroupSummary"]["receiverCounts"]["email"], 1
        )
        values = {
            "id": GROUP,
            "name": "authored-actions",
            "resource_group_name": "health",
            "enabled": True,
            "location": "global",
            "email_receiver": [{"email_address": PRIVATE}],
        }
        plan = {
            "format_version": "1.2",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "mode": "managed",
                            "type": "azurerm_monitor_action_group",
                            "address": "azurerm_monitor_action_group.a",
                            "values": values,
                            "sensitive_values": {"enabled": True, "email_receiver": True},
                        }
                    ]
                }
            },
        }
        planned = plan_source(self.write("plan.json", plan), scope=SCOPE, provider_version="4.50.0")
        facts = planned["resources"][0]["properties"]["actionGroupSummary"]
        self.assertIn("unknown", facts["enabled"])
        self.assertIn("unknown", facts["receiverCounts"]["email"])
        self.assertNotIn(PRIVATE, json.dumps(planned))
        for provider in (None, "4.49.0"):
            unsupported = terraform_source(source, scope=SCOPE, provider_version=provider)
            self.assertTrue(all(r["state"] == "unknown" for r in unsupported["resources"]))
        for kind in (
            "azurerm_monitor_action_group",
            "azurerm_monitor_activity_log_alert",
            "azurerm_monitor_metric_alert",
        ):
            facts = tf_properties(kind, {})
            self.assertIn("unknown", next(iter(facts.values()))["enabled"])

    def test_planned_versions_no_new_observed_registry_or_live_detail_routes(self):
        for kind, version in ((ACTIVITY_ALERT, "2020-10-01"), (ACTION_GROUP, "2023-01-01")):
            self.assertEqual(PLANNED_API_VERSIONS[kind], {version})
            self.assertNotIn(kind, API_VERSIONS)
            for api in (version, "2099-01-01", None):
                template = {
                    "resources": [
                        {
                            "type": kind,
                            "apiVersion": api,
                            "name": "authored",
                            "location": "global",
                            "properties": self.action()
                            if kind == ACTION_GROUP
                            else self.activity(),
                        }
                    ]
                }
                bundle = arm_source(self.write("arm.json", template), scope=SCOPE)
                self.assertEqual(
                    bundle["resources"][0]["state"], "known" if api == version else "unknown"
                )
        requests = []

        def transport(method, url, body=None):
            requests.append(url)
            if "/resources?" in url:
                return Response(
                    200,
                    {
                        "value": [
                            {"id": GROUP, "type": ACTION_GROUP},
                            {
                                "id": SCOPE + "/providers/Microsoft.Insights/activityLogAlerts/a",
                                "type": ACTIVITY_ALERT,
                            },
                        ]
                    },
                    {},
                )
            if "policy" in url.lower():
                return Response(200, {"value": []}, {})
            self.fail("No platform-health detail route is authorized")

        bundle = Collector(transport).collect(
            subscriptions=["00000000-0000-0000-0000-000000000001"], inventory_authorized=True
        )
        self.assertTrue(all(not r["properties"] for r in bundle["resources"]))
        self.assertTrue(all("/actiongroups/" not in url.lower() for url in requests))

    def test_nine_independent_blank_reviews_and_interview_binding_expiry_atomicity(self):
        prepared = prepare_reviews(self.report(), self.catalog, sorted(IDS), SCOPE)
        self.assertEqual(len(prepared["entries"]), 9)
        for entry in prepared["entries"]:
            for key in (
                "reviewer",
                "outcome",
                "rationale",
                "evidence",
                "valid_from",
                "valid_until",
            ):
                self.assertIsNone(entry[key])
        blank = prepare_interview(self.report(), self.catalog, self.question, SCOPE)
        self.assertEqual(len(blank["decisions"]), 9)
        self.assertTrue(all(r["outcome"] is None for r in blank["decisions"]))
        with self.assertRaises(InputError):
            compile_interview(blank, self.catalog, at=AT)
        completed = self.completed()
        reviews = compile_interview(completed, self.catalog, at=AT)
        validate_reviews(reviews, self.catalog, SCOPE, at=AT)
        self.assertEqual(len(reviews["entries"]), 9)
        for key, value in (
            ("scope", SUB + "/resourceGroups/other"),
            ("catalog_sha256", "0" * 64),
            ("requirements_sha256", "0" * 64),
            ("reviewer", None),
            ("valid_from", UNTIL),
            ("valid_until", "2000-01-01T00:00:00Z"),
        ):
            altered = copy.deepcopy(completed)
            altered[key] = value
            with self.assertRaises(InputError):
                compile_interview(altered, self.catalog, at=AT)
        for alteration in ("partial", "duplicate", "binding", "selection"):
            altered = copy.deepcopy(completed)
            if alteration == "partial":
                altered["decisions"][1]["outcome"] = None
            elif alteration == "duplicate":
                altered["decisions"].append(copy.deepcopy(altered["decisions"][0]))
            elif alteration == "binding":
                altered["decisions"][0]["control_sha256"] = "0" * 64
            else:
                altered["decisions"][0]["control_id"] = "ALZ-" + "0" * 36
            with self.assertRaises(InputError):
                compile_interview(altered, self.catalog, at=AT)

    def test_tiers_scope_partial_unknown_denied_stale_never_verified(self):
        report = self.report()
        for row in report["results"]:
            if row["control_id"] in IDS:
                self.assertNotEqual(row["observed"]["outcome"], "pass")
                self.assertNotEqual(row["observed"]["evidence_tier"], "verified")
        manual = next(
            r for r in report["results"] if r["control_id"] == self.control("F01.16")["control_id"]
        )
        self.assertEqual(manual["observed"]["evidence_tier"], "manual")
        for boundary in (None, SUB + "/resourceGroups/other"):
            bundle = self.bundle()
            bundle["scope"] = boundary
            report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
            for row in report["results"]:
                if row["control_id"] in IDS and row["automation"] != "manual":
                    self.assertEqual(row["observed"]["evidence_tier"], "needs_decision")
        bundle = self.bundle()
        bundle["resources"] = [
            {**copy.deepcopy(bundle["resources"][0]), "logical_id": "duplicate-" + str(i)}
            for i in range(2)
        ]
        with self.assertRaisesRegex(InputError, "ambiguous ARM"):
            assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        stale = assess(self.bundle(), self.catalog, at="2026-11-10T21:00:00Z", evidence_tiers=True)
        for row in stale["results"]:
            if row["control_id"] in IDS:
                self.assertNotEqual(row["observed"]["evidence_tier"], "verified")
        bundle = self.bundle()
        bundle["resources"][0].update(state="error", reason="permission_denied")
        context = review_context(self.control("F01.11"), bundle)
        self.assertIn("unknown", context["resources"][0]["facts"]["actionGroupSummary"])
        self.assertFalse(context["inventory_complete"])
        self.assertEqual(context["collected_at"], AT)

    def test_all_outputs_human_confirmation_and_independent_exceptions(self):
        reviews = compile_interview(self.completed(), self.catalog, at=AT)
        report = self.report(manual=reviews)
        exceptions = document(
            "exceptions",
            schema_version="1.1",
            entries=[
                {**{k: v for k, v in entry.items() if k != "outcome"}, "disposition": "accepted"}
                for entry in reviews["entries"]
            ],
        )
        validate_reviews(exceptions, self.catalog, SCOPE, at=AT)
        excepted = self.report(exceptions=exceptions)
        for row in excepted["results"]:
            if row["control_id"] in IDS:
                self.assertEqual(row["observed"]["exception_disposition"], "accepted")
                self.assertNotEqual(row["observed"]["reason"], "manual_attestation")
        for row in report["results"]:
            if row["control_id"] in IDS:
                self.assertEqual(row["observed"]["reason"], "manual_attestation")
                self.assertNotEqual(row["observed"]["evidence_tier"], "verified")
        for format in ("json", "markdown", "html", "csv", "sarif", "pr-summary"):
            output = render(report, format)
            self.assertTrue(output)
            self.assertNotIn(PRIVATE, output)
            for control in IDS:
                if format in {"json", "csv"}:
                    self.assertIn(control, output)
        self.assertGreater(len(render_xlsx(report)), 0)

    def test_wrong_kind_facts_truncation_and_no_coverage_from_absence(self):
        bundle = self.bundle()
        action = bundle["resources"][0]
        action["properties"] = {
            "activityAlertSummary": bundle["resources"][1]["properties"]["activityAlertSummary"]
        }
        bundle["resources"] = [action]
        context = review_context(self.control("F01.10"), bundle)
        self.assertIn("unknown", context["resources"][0]["facts"]["activityAlertSummary"])
        source = self.bundle()["resources"][0]
        bundle["resources"] = [
            {**copy.deepcopy(source), "logical_id": str(i), "arm_id": GROUP.lower() + str(i)}
            for i in range(101)
        ]
        context = review_context(self.control("F01.11"), bundle)
        self.assertTrue(context["truncated"])
        self.assertEqual(context["matching_resources"], 101)
        empty = self.bundle()
        empty["resources"] = []
        empty["inventory_complete"] = True
        report = assess(empty, self.catalog, at=AT, evidence_tiers=True)
        for row in report["results"]:
            if row["control_id"] in IDS:
                self.assertNotEqual(row["observed"]["outcome"], "pass")

    def test_original_time_private_replay_idempotence_and_candidate_rejection(self):
        bundle = self.bundle()
        bundle["resources"][0]["properties"]["actionGroupSummary"]["receivers"] = PRIVATE
        sanitized = sanitize_evidence(bundle)
        self.assertNotIn(PRIVATE, json.dumps(sanitized))
        self.assertEqual(sanitized["collected_at"], AT)
        twice = sanitize_evidence(sanitized)
        for left, right in zip(sanitized["resources"], twice["resources"], strict=True):
            self.assertEqual(left["properties"], right["properties"])
        for display in range(10, 19):
            self.assertEqual(
                review_context(self.control(f"F01.{display}"), bundle),
                review_context(self.control(f"F01.{display}"), sanitized),
            )
        export_bundle(self.root / "replay", bundle, self.accepted, at=AT, evidence_tiers=True)
        self.assertEqual(
            semantic(replay_bundle(self.root / "replay")),
            semantic(assess(bundle, self.accepted, at=AT, evidence_tiers=True)),
        )
        historical = load_catalog(
            str(files("alz_assessor").joinpath("data", "catalog-2026-11-06.17.json"))
        )
        export_bundle(self.root / "prior", bundle, historical, at=AT, evidence_tiers=True)
        self.assertEqual(
            semantic(replay_bundle(self.root / "prior")),
            semantic(assess(bundle, historical, at=AT, evidence_tiers=True)),
        )
        with self.assertRaises(InputError):
            export_bundle(self.root / "candidate", bundle, self.catalog, at=AT, evidence_tiers=True)
        predecessor = files("alz_assessor").joinpath("data", "catalog-2026-11-06.20.json")
        self.assertEqual(
            digest(self.accepted),
            digest(load_catalog(str(predecessor)) if predecessor.is_file() else load_catalog()),
        )

    def test_amba_reuses_policy_joins_at_subscription_and_management_group_scope(self):
        for boundary in (SUB, "/providers/Microsoft.Management/managementGroups/authored"):
            definition = boundary + "/providers/Microsoft.Authorization/policyDefinitions/authored"
            assignment = boundary + "/providers/Microsoft.Authorization/policyAssignments/authored"
            bundle = self.bundle()
            bundle["scope"] = boundary
            bundle["resources"] = [
                self.record(
                    "microsoft.authorization/policydefinitions",
                    definition,
                    {
                        "policyType": "Custom",
                        "mode": "All",
                        "version": "1.2.3",
                        "policyRule": {
                            "if": {"field": PRIVATE},
                            "then": {"effect": "deployIfNotExists"},
                        },
                    },
                ),
                self.record(
                    "microsoft.authorization/policyassignments",
                    assignment,
                    {
                        "policyDefinitionId": definition,
                        "definitionVersion": "1.2.3",
                        "notScopes": [],
                        "enforcementMode": "Default",
                        "parameters": {},
                        "resourceSelectors": [],
                        "overrides": [],
                    },
                ),
            ]
            context = review_context(self.control("F01.17"), bundle)
            self.assertEqual(len(context["resources"]), 2)
            linked = context["resources"][1]["policy_configuration"]["definition"]
            self.assertNotIn("unknown", linked)
            self.assertIn("supplied_policy_assignments", context)
            self.assertNotIn(PRIVATE, json.dumps(context))
            report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
            result = next(
                r
                for r in report["results"]
                if r["control_id"] == self.control("F01.17")["control_id"]
            )
            self.assertEqual(result["observed"]["evidence_tier"], "signal")
            self.assertNotEqual(result["observed"]["outcome"], "pass")
            bundle["resources"].pop(0)
            context = review_context(self.control("F01.17"), bundle)
            self.assertIn("unknown", context["resources"][0]["policy_configuration"]["definition"])
            bundle["resources"][0]["properties"]["policyAssignmentSummary"]["definitionId"] = (
                "/providers/microsoft.authorization/policydefinitions/"
                "00000000-0000-0000-0000-000000000001"
            )
            context = review_context(self.control("F01.17"), bundle)
            self.assertIn(
                "not_fetched",
                context["resources"][0]["policy_configuration"]["definition"]["unknown"],
            )

    def test_independent_selection_and_changed_requirements_cannot_rebind(self):
        control = self.control("F01.18")["control_id"]
        selected = prepare_interview(
            self.report(), self.catalog, self.question, SCOPE, selected=[control]
        )
        self.assertEqual([r["control_id"] for r in selected["decisions"]], [control])
        for invalid in ([], [control, control], ["ALZ-00000000-0000-0000-0000-000000000001"]):
            with self.assertRaises(InputError):
                prepare_interview(
                    self.report(), self.catalog, self.question, SCOPE, selected=invalid
                )
        changed = copy.deepcopy(self.catalog)
        next(c for c in changed["controls"] if c["control_id"] == control)[
            "evidence_requirements"
        ].append("Changed requirement")
        with self.assertRaises(InputError):
            compile_interview(self.completed(), changed, at=AT)
        exception = prepare_reviews(
            self.report(), self.catalog, [control], SCOPE, kind="exceptions"
        )
        self.assertEqual(len(exception["entries"]), 1)
        self.assertNotIn("outcome", exception["entries"][0])
        self.assertIsNone(exception["entries"][0]["disposition"])

    def test_planned_observed_modes_and_unsupported_shapes_remain_distinct(self):
        planned = self.bundle()
        planned["mode"] = "planned"
        report = assess(planned, self.catalog, at=AT, evidence_tiers=True)
        for row in report["results"]:
            if row["control_id"] in IDS:
                self.assertIsNone(row["observed"])
                self.assertNotEqual(row["planned"]["evidence_tier"], "verified")
        for raw in (
            {"criteria": None},
            {"criteria": []},
            {"criteria": {"allOf": None}},
            {"criteria": {"allOf": [], "odata.type": PRIVATE}},
        ):
            result = properties(METRIC, raw)["operationalMetricAlertSummary"]
            self.assertIn("unknown", result["staticConditionCount"])
            self.assertNotIn(PRIVATE, json.dumps(result))
        for enabled in (False, True):
            result = properties(ACTIVITY_ALERT, {**self.activity(), "enabled": enabled})
            self.assertIs(result["activityAlertSummary"]["enabled"], enabled)
        for enabled in (None, 0, 1, "true", PRIVATE):
            result = properties(ACTIVITY_ALERT, {**self.activity(), "enabled": enabled})
            self.assertIn("unknown", result["activityAlertSummary"]["enabled"])
            self.assertNotIn(PRIVATE, json.dumps(result))

    def test_cli_candidate_catalog_and_local_session_atomic_save(self):
        bundle = self.write("saved.json", self.bundle())
        catalog = self.write("candidate.json", self.catalog)
        output = self.root / "report.json"
        with patch(
            "sys.argv",
            [
                "alz-assessor",
                "assess",
                str(bundle),
                "--input",
                "evidence",
                "--catalog",
                str(catalog),
                "--evidence-tiers",
                "--output",
                str(output),
            ],
        ):
            with (
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(main(), 0)
        report = json.loads(output.read_text("utf-8"))
        self.assertEqual(len({r["control_id"] for r in report["results"]} & IDS), 9)
        session = ReviewSession(
            self.bundle(), self.catalog, self.root / "session", clock=lambda: AT
        )
        self.assertEqual(session.state()["records"], [])
        target = compile_interview(self.completed(), self.catalog, at=AT)["entries"][0]
        save = {
            "revision": 0,
            "control_id": target["control_id"],
            "kind": "manual",
            "decision": target["outcome"],
            "replace_existing": False,
            **{
                k: target[k]
                for k in ("reviewer", "rationale", "evidence", "valid_from", "valid_until")
            },
        }
        session.save(save)
        self.assertEqual(len(session.state()["records"]), 1)
        with self.assertRaises(InputError):
            session.save(save)
        self.assertEqual(len(session.state()["records"]), 1)
        self.assertNotIn(PRIVATE, json.dumps(session.state()))

    def test_real_bicep_platform_health_configuration_without_restore(self):
        compiler = os.environ.get("BICEP_COMPILER")
        if not compiler:
            self.skipTest("No existing compiler discovered; no acquisition attempted")
        bundle = arm_source(
            ROOT / "tests" / "fixtures" / "platform-health" / "controls.bicep",
            scope=SCOPE,
            compiler=compiler,
            bicep=True,
        )
        self.assertEqual(len(bundle["resources"]), 5)
        self.assertTrue(all(r["state"] == "known" for r in bundle["resources"]))
        storage = next(r for r in bundle["resources"] if r["resource_type"].lower() == STORAGE)
        self.assertEqual(
            storage["properties"]["storageRedundancySummary"]["configuredRedundancy"], "zone"
        )
        metric = next(r for r in bundle["resources"] if r["resource_type"].lower() == METRIC)
        self.assertEqual(
            metric["properties"]["operationalMetricAlertSummary"]["staticConditionCount"], 1
        )
        alerts = [r for r in bundle["resources"] if r["resource_type"].lower() == ACTIVITY_ALERT]
        self.assertEqual(
            {r["properties"]["activityAlertSummary"]["category"] for r in alerts},
            {"ServiceHealth", "ResourceHealth"},
        )
        for row in alerts:
            linked = linked_context(row, self.index(bundle), SCOPE)
            self.assertEqual(linked["actionGroups"][0]["arm_id"], GROUP.lower())
        for row in assess(bundle, self.catalog, at=bundle["collected_at"], evidence_tiers=True)[
            "results"
        ]:
            if row["control_id"] in IDS:
                self.assertNotEqual(row["planned"]["outcome"], "pass")
                self.assertNotEqual(row["planned"]["evidence_tier"], "verified")
