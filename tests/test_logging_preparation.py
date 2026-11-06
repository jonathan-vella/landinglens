import copy
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
from alz_assessor.contracts import control_digest, digest, document
from alz_assessor.engine import assess
from alz_assessor.interviews import compile_interview, prepare_interview
from alz_assessor.logging_evidence import (
    DIAGNOSTIC,
    GUIDS,
    LOG_ALERT,
    METRIC_ALERT,
    ONBOARDING,
    TOPIC,
    WORKSPACE,
    linked_context,
    log_alert_facts,
    metric_alert_facts,
    onboarding_facts,
    references,
    topic_facts,
    workspace_facts,
)
from alz_assessor.plan import plan_source
from alz_assessor.replay import export_bundle, replay_bundle, sanitize_evidence, semantic
from alz_assessor.reports import render, render_xlsx
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import prepare_reviews, review_context, validate_reviews
from alz_assessor.sources import terraform_source, tf_properties, tf_resource_id
from alz_assessor.terraform import InputError

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "references" / "recommendation-batches"
FIXTURE = Path(__file__).parent / "fixtures" / "logging" / "controls.bicep"
SUB = "/subscriptions/00000000-0000-0000-0000-000000000001"
SCOPE = SUB + "/resourceGroups/logging"
WORKSPACE_ID = SCOPE + "/providers/Microsoft.OperationalInsights/workspaces/central-logs"
TOPIC_ID = SCOPE + "/providers/Microsoft.EventGrid/topics/authored-topic"
ONBOARDING_ID = WORKSPACE_ID + "/providers/Microsoft.SecurityInsights/onboardingStates/default"
ACTION_ID = SCOPE + "/providers/Microsoft.Insights/actionGroups/authored"
AT = "2026-11-06T15:00:00Z"
UNTIL = "2026-11-07T15:00:00Z"
PRIVATE = "PRIVATE-LOG-QUERY-TICKET-WEBHOOK-KEY-IDENTITY"
IDS = {"ALZ-" + guid for guid in GUIDS}


class LoggingPreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.matrix = json.loads((REFERENCE / "preparation-23.json").read_text("utf-8"))
        self.accepted = load_catalog(
            str(files("alz_assessor").joinpath("data", "catalog-2026-11-06.12.json"))
        )
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

    def record(self, kind, identity, raw, *, root=None):
        return {
            "logical_id": identity.lower(),
            "arm_id": identity.lower(),
            "resource_type": kind,
            "state": "known",
            "reason": "",
            "source_location": "fixture://authored-logging",
            "properties": properties(kind, raw, root=root, observed=True),
        }

    def workspace(self):
        return {
            "sku": {"name": "PerGB2018"},
            "retentionInDays": 30,
            "publicNetworkAccessForIngestion": "Enabled",
            "publicNetworkAccessForQuery": "Disabled",
            "primarySharedKey": PRIVATE,
            "customerId": PRIVATE,
            "private": PRIVATE,
        }

    def alert(self):
        return {
            "enabled": True,
            "evaluationFrequency": "PT5M",
            "windowSize": "PT5M",
            "scopes": [WORKSPACE_ID],
            "criteria": {"allOf": [{"query": PRIVATE, "dimensions": [PRIVATE]}]},
            "actions": {"actionGroups": [ACTION_ID], "customProperties": {"secret": PRIVATE}},
            "description": PRIVATE,
        }

    def metric(self):
        return {
            "enabled": True,
            "scopes": [TOPIC_ID],
            "criteria": {
                "odata.type": "Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria",
                "allOf": [
                    {
                        "criterionType": "StaticThresholdCriterion",
                        "metricNamespace": "Microsoft.EventGrid/topics",
                        "metricName": "DeadLetteredCount",
                        "timeAggregation": "Total",
                        "threshold": 10,
                        "dimensions": [{"values": [PRIVATE]}],
                    }
                ],
            },
            "actions": [{"actionGroupId": ACTION_ID, "webHookProperties": {"secret": PRIVATE}}],
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
            artifact_hashes={"fixture": "0" * 64},
            diagnostics=[],
            resources=[
                self.record(WORKSPACE, WORKSPACE_ID, self.workspace()),
                self.record(
                    ONBOARDING,
                    ONBOARDING_ID,
                    {
                        "customerManagedKey": False,
                        "tenantId": PRIVATE,
                        "onboardingStatus": PRIVATE,
                    },
                ),
                self.record(
                    DIAGNOSTIC,
                    TOPIC_ID + "/providers/Microsoft.Insights/diagnosticSettings/logs",
                    {
                        "targetResourceId": TOPIC_ID,
                        "workspaceId": WORKSPACE_ID,
                        "logs": [{"categoryGroup": "allLogs", "enabled": True}],
                        "metrics": [{"category": "AllMetrics", "enabled": True}],
                        "logAnalyticsDestinationType": "Dedicated",
                        "events": PRIVATE,
                    },
                ),
                self.record(
                    LOG_ALERT,
                    SCOPE + "/providers/Microsoft.Insights/scheduledQueryRules/logs",
                    self.alert(),
                    root={"kind": "LogAlert"},
                ),
                self.record(
                    TOPIC,
                    TOPIC_ID,
                    {
                        "inputSchema": "EventGridSchema",
                        "publicNetworkAccess": "Enabled",
                        "endpoint": PRIVATE,
                        "inputSchemaMapping": PRIVATE,
                    },
                ),
                self.record(
                    METRIC_ALERT,
                    SCOPE + "/providers/Microsoft.Insights/metricAlerts/service",
                    self.metric(),
                ),
            ],
        )

    def control(self, display):
        return next(c for c in self.catalog["controls"] if c["upstream_id"] == display)

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
            answer="Authored fixture: seven separate evidence-backed test decisions.",
            reviewer="Authored fixture reviewer",
            rationale="Not a real approval or operating claim.",
            evidence="https://example.invalid/redacted-fixture",
            valid_from=AT,
            valid_until=UNTIL,
        )
        for row, outcome in zip(
            response["decisions"],
            ("pass", "fail", "not_applicable", "fail", "pass", "fail", "pass"),
            strict=True,
        ):
            row["outcome"] = outcome
        return response

    def test_exact_fixed_targets_unactivated_matrix_and_preserved_current_catalog(self):
        targets = json.loads((REFERENCE / "targets.json").read_text("utf-8"))
        fixed = {r["guid"] for r in targets["targets"] if r["batch"] == "23"}
        self.assertEqual(fixed, GUIDS)
        self.assertEqual({r["guid"] for r in self.matrix["recommendations"]}, fixed)
        self.assertEqual(len(fixed), 7)
        self.assertEqual(self.matrix["review_state"], "preparation-only-reviewed")
        self.assertNotIn("catalog_version", self.matrix)
        self.assertNotIn("accepted_at", self.matrix)
        self.assertEqual(self.accepted["catalog_version"], "2026-11-06.12")
        before = {c["control_id"]: c for c in self.accepted["controls"]}
        for control in self.catalog["controls"]:
            if control["control_id"] not in IDS:
                self.assertEqual(
                    control_digest(control), control_digest(before[control["control_id"]])
                )
            else:
                self.assertIsNone(control["rule"])
                self.assertEqual(control["automation"], before[control["control_id"]]["automation"])
        self.assertEqual(len(self.catalog["controls"]), 255)
        builder = runpy.run_path(str(ROOT / "tools" / "build_batches.py"), run_name="prep")
        with self.assertRaisesRegex(ValueError, "Preparation"):
            builder["apply_batch"](self.accepted, self.accepted, targets, self.matrix, [], [])
        capture = runpy.run_path(str(ROOT / "tools" / "review_batch_sources.py"), run_name="prep")
        with patch("sys.argv", ["review_batch_sources.py", "--batch", "23"]):
            with self.assertRaisesRegex(ValueError, "preparation-only"):
                capture["main"]()

    def test_actual_sources_separate_planes_guidance_mismatch_and_terms(self):
        capture = json.loads((REFERENCE / "preparation-23-sources.json").read_text("utf-8"))
        self.assertEqual(capture["review_state"], "preparation-only-reviewed")
        sources = {r["id"]: r for r in capture["sources"]}
        self.assertEqual(len(sources), 22)
        self.assertTrue(
            sources["central-workspace-linked"]["resolved_url"].endswith("/workspace-design")
        )
        self.assertIn("/entra/", sources["separate-accounts-linked"]["resolved_url"])
        for row in self.matrix["recommendations"]:
            original = next(
                c for c in self.accepted["controls"] if c["upstream_guid"] == row["guid"]
            )
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
        lockbox = next(r for r in self.matrix["recommendations"] if r["upstream_id"] == "G03.10")
        self.assertNotIn("review_resource_types", lockbox)
        text = json.dumps(lockbox)
        for marker in ("Developer", "E5/G5", "four days", "twelve hours", "MG", "exclusions"):
            self.assertIn(marker, text)
        self.assertNotEqual(
            self.control("G06.01")["evidence_requirements"],
            self.control("G06.02")["evidence_requirements"],
        )

    def test_minimized_workspace_onboarding_topic_and_no_defaults(self):
        bundle = self.bundle()
        self.assertNotIn(PRIVATE, json.dumps(bundle))
        self.assertEqual(
            bundle["resources"][0]["properties"]["logWorkspaceSummary"]["retentionInDays"], 30
        )
        self.assertIs(
            bundle["resources"][1]["properties"]["sentinelOnboardingSummary"]["customerManagedKey"],
            False,
        )
        self.assertEqual(
            topic_facts({"inputSchema": "CloudEventSchemaV1_0"})["inputSchema"],
            "CloudEventSchemaV1_0",
        )
        for value in (None, {}, [], True, 1, PRIVATE, {"unknown": PRIVATE}):
            for fn in (
                workspace_facts,
                onboarding_facts,
                topic_facts,
                log_alert_facts,
                metric_alert_facts,
            ):
                result = fn(value)
                self.assertNotIn(PRIVATE, json.dumps(result))
        for value in ("true", 1, None):
            self.assertIn(
                "unknown", onboarding_facts({"customerManagedKey": value})["customerManagedKey"]
            )
        for value in (None, True, "30", 0, 29, 731):
            self.assertIn("unknown", workspace_facts({"retentionInDays": value})["retentionInDays"])
        self.assertIn("unknown", workspace_facts({})["sku"])
        self.assertIn("unknown", topic_facts({"inputSchema": PRIVATE})["inputSchema"])

    def test_references_types_duplicates_unknown_empty_and_bounds(self):
        for value in (
            None,
            {},
            [],
            [None],
            [PRIVATE],
            [TOPIC_ID],
            [WORKSPACE_ID] * 2,
            [WORKSPACE_ID] * 101,
        ):
            self.assertIn("unknown", references(value, WORKSPACE))
        self.assertEqual(references([], WORKSPACE, empty=True), [])
        self.assertEqual(references([WORKSPACE_ID], WORKSPACE), [WORKSPACE_ID.lower()])
        self.assertIn("unknown", references([WORKSPACE_ID, WORKSPACE_ID.upper()], WORKSPACE))

    def test_metric_and_log_alert_semantics_are_distinct_and_bodies_withheld(self):
        bundle = self.bundle()
        log = bundle["resources"][3]["properties"]["logAlertSummary"]
        metric = bundle["resources"][5]["properties"]["eventGridMetricAlertSummary"]
        self.assertEqual(log["kind"], "LogAlert")
        self.assertEqual(log["conditionCount"], 1)
        self.assertEqual(metric["criteria"][0]["metricName"], "DeadLetteredCount")
        self.assertNotIn("query", log)
        self.assertNotIn("threshold", json.dumps(metric))
        for raw in (
            {**self.metric(), "scopes": [WORKSPACE_ID]},
            {**self.metric(), "scopes": [TOPIC_ID, TOPIC_ID + "-other"]},
            {
                **self.metric(),
                "criteria": {
                    "odata.type": "Microsoft.Azure.Monitor.MultipleResourceMultipleMetricCriteria"
                },
            },
        ):
            result = properties(METRIC_ALERT, raw)["eventGridMetricAlertSummary"]
            self.assertTrue("unknown" in result["criteria"] or "unknown" in result["topicIds"])
        for kind in (None, "LogToMetric", "SimpleLogAlert", PRIVATE):
            result = properties(LOG_ALERT, self.alert(), root={"kind": kind})["logAlertSummary"]
            self.assertIn("unknown", result["kind"])
        for conditions in (None, [], [None], [{}] * 101):
            raw = self.alert()
            raw["criteria"] = {"allOf": conditions}
            result = properties(LOG_ALERT, raw, root={"kind": "LogAlert"})["logAlertSummary"]
            self.assertIn("unknown", result["conditionCount"])

    def test_exact_known_workspace_and_topic_joins(self):
        bundle = self.bundle()
        index = self.index(bundle)
        for position in (1, 2, 3, 5):
            linked = linked_context(bundle["resources"][position], index, SCOPE)
            self.assertEqual(len(linked["links"]), 1)
            self.assertEqual(
                linked["links"][0]["arm_id"], (TOPIC_ID if position == 5 else WORKSPACE_ID).lower()
            )
            self.assertIn("not ingestion", linked["warning"])
        for display in ("G03.08", "G03.09", "G03.11"):
            context = review_context(self.control(display), bundle)
            self.assertEqual(context["unbound_resources"], 0)
            self.assertTrue(context["resources"])
        for display in ("G03.10", "G05.01", "G06.01", "G06.02"):
            self.assertEqual(review_context(self.control(display), bundle)["resources"], [])

    def test_joins_reject_missing_duplicate_denied_wrong_type_outside_scope(self):
        for change in ("missing", "duplicate", "denied", "wrong_type", "outside"):
            bundle = self.bundle()
            if change == "missing":
                bundle["resources"].pop(0)
            elif change == "duplicate":
                bundle["resources"].append(copy.deepcopy(bundle["resources"][0]))
            elif change == "denied":
                bundle["resources"][0].update(state="error", reason="permission_denied")
            elif change == "wrong_type":
                bundle["resources"][0]["resource_type"] = TOPIC
            else:
                bundle["scope"] = SUB + "/resourceGroups/different"
            source = next(r for r in bundle["resources"] if r["resource_type"] == ONBOARDING)
            context = linked_context(source, self.index(bundle), bundle["scope"])
            self.assertIn("unknown", context if "unknown" in context else context["links"][0])
        bundle = self.bundle()
        diagnostic = bundle["resources"][2]
        diagnostic["properties"]["targetResourceId"] = WORKSPACE_ID
        self.assertIn("mismatch", linked_context(diagnostic, self.index(bundle), SCOPE)["unknown"])
        source = bundle["resources"][1]
        source["arm_id"] = source["arm_id"] + "s"
        self.assertIn(
            "requires_default", linked_context(source, self.index(bundle), SCOPE)["unknown"]
        )
        for scope in (None, "/providers/Microsoft.Management/managementGroups/tenant"):
            self.assertIn("unknown", linked_context(source, self.index(bundle), scope))

    def test_review_unbound_partial_denied_stale_and_truncated_remain_explicit(self):
        bundle = self.bundle()
        control = self.control("G03.08")
        self.assertFalse(review_context(control, bundle)["inventory_complete"])
        bundle["resources"][0]["arm_id"] = None
        context = review_context(control, bundle)
        self.assertEqual(context["unbound_resources"], 1)
        self.assertEqual(context["collected_at"], AT)
        bundle = self.bundle()
        bundle["resources"][0].update(state="error", reason="permission_denied")
        context = review_context(control, bundle)
        self.assertIn("unknown", context["resources"][0]["facts"]["logWorkspaceSummary"])
        source = self.bundle()["resources"][0]
        bundle["resources"] = [
            {
                **copy.deepcopy(source),
                "logical_id": f"workspace-{i}",
                "arm_id": WORKSPACE_ID.lower() + str(i),
            }
            for i in range(101)
        ]
        context = review_context(control, bundle)
        self.assertTrue(context["truncated"])
        self.assertEqual(context["matching_resources"], 101)
        report = assess(self.bundle(), self.catalog, at="2026-11-10T15:00:00Z", evidence_tiers=True)
        for row in report["results"]:
            if row["control_id"] in IDS:
                self.assertNotEqual(row["observed"]["outcome"], "pass")
                self.assertNotEqual(row["observed"]["evidence_tier"], "verified")

    def test_raw_terraform_and_supplied_module_use_only_explicit_reviewed_fields(self):
        source = self.root / "source"
        source.mkdir()
        (source / "main.tf").write_text(
            'module "logging" { source = "./logging" }\n', encoding="utf-8"
        )
        child = source / "logging"
        child.mkdir()
        (child / "main.tf").write_text(
            'resource "azurerm_log_analytics_workspace" "central" {\n'
            'name = "central-logs"\nresource_group_name = "logging"\n'
            'sku = "PerGB2018"\nretention_in_days = 30\n'
            "internet_ingestion_enabled = true\ninternet_query_enabled = false\n}\n"
            'resource "azurerm_sentinel_log_analytics_workspace_onboarding" "central" {\n'
            f'workspace_id = "{WORKSPACE_ID}"\n'
            "customer_managed_key_enabled = false\n}\n",
            encoding="utf-8",
        )
        bundle = terraform_source(source, scope=SCOPE, provider_version="4.50.0")
        self.assertEqual(len(bundle["resources"]), 2)
        onboarding = next(
            r for r in bundle["resources"] if r["resource_type"].lower() == ONBOARDING
        )
        self.assertEqual(onboarding["arm_id"], ONBOARDING_ID.lower())
        self.assertEqual(
            linked_context(onboarding, self.index(bundle), SCOPE)["links"][0]["arm_id"],
            WORKSPACE_ID.lower(),
        )
        facts = tf_properties("azurerm_log_analytics_workspace", {})["logWorkspaceSummary"]
        self.assertTrue(
            all(isinstance(value, dict) and "unknown" in value for value in facts.values())
        )
        self.assertIn(
            "unknown",
            tf_properties("azurerm_sentinel_log_analytics_workspace_onboarding", {})[
                "sentinelOnboardingSummary"
            ]["customerManagedKey"],
        )
        self.assertIsNone(
            tf_resource_id(
                SUB + "/resourceGroups/other",
                "azurerm_sentinel_log_analytics_workspace_onboarding",
                {"workspace_id": WORKSPACE_ID},
            )
        )

    def test_optional_plan_sensitive_workspace_and_parent_are_not_defaulted(self):
        plan = {
            "format_version": "1.2",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "mode": "managed",
                            "type": "azurerm_log_analytics_workspace",
                            "address": "azurerm_log_analytics_workspace.logs",
                            "values": {
                                "name": "central-logs",
                                "resource_group_name": "logging",
                                "sku": "PerGB2018",
                                "retention_in_days": 30,
                                "primary_shared_key": PRIVATE,
                            },
                            "sensitive_values": {"retention_in_days": True},
                        },
                        {
                            "mode": "managed",
                            "type": "azurerm_sentinel_log_analytics_workspace_onboarding",
                            "address": "azurerm_sentinel_log_analytics_workspace_onboarding.logs",
                            "values": {
                                "workspace_id": WORKSPACE_ID,
                                "customer_managed_key_enabled": False,
                            },
                            "sensitive_values": {"workspace_id": True},
                        },
                    ]
                }
            },
        }
        bundle = plan_source(self.write("plan.json", plan), scope=SCOPE, provider_version="4.50.0")
        self.assertNotIn(PRIVATE, json.dumps(bundle))
        self.assertIn(
            "unknown",
            bundle["resources"][0]["properties"]["logWorkspaceSummary"]["retentionInDays"],
        )
        self.assertIsNone(bundle["resources"][1]["arm_id"])
        unsupported = plan_source(self.root / "plan.json", scope=SCOPE, provider_version="4.49.0")
        self.assertTrue(
            all(
                row["state"] == "unknown" and not row["properties"]
                for row in unsupported["resources"]
            )
        )

    def test_planned_arm_version_kind_parent_and_scope_guards_without_new_live_registry(self):
        for kind in (WORKSPACE, ONBOARDING, LOG_ALERT, TOPIC):
            self.assertIn(kind, PLANNED_API_VERSIONS)
            self.assertNotIn(kind, API_VERSIONS)
        template = {
            "resources": [
                {
                    "type": WORKSPACE,
                    "apiVersion": "2023-09-01",
                    "name": "central-logs",
                    "properties": self.workspace(),
                },
                {
                    "type": ONBOARDING,
                    "apiVersion": "2024-03-01",
                    "name": "default",
                    "scope": WORKSPACE_ID,
                    "properties": {"customerManagedKey": False},
                },
                {
                    "type": LOG_ALERT,
                    "apiVersion": "2023-12-01",
                    "name": "logs",
                    "kind": "LogAlert",
                    "properties": self.alert(),
                },
            ],
        }
        path = self.write("arm.json", template)
        bundle = arm_source(path, scope=SCOPE)
        self.assertEqual(bundle["resources"][1]["arm_id"], ONBOARDING_ID.lower())
        self.assertEqual(
            bundle["resources"][2]["properties"]["logAlertSummary"]["kind"], "LogAlert"
        )
        for version in (None, "2099-01-01", "2024-03-01-preview"):
            template["resources"][1]["apiVersion"] = version
            bundle = arm_source(self.write("arm.json", template), scope=SCOPE)
            self.assertEqual(bundle["resources"][1]["state"], "unknown")
        template["resources"][1]["apiVersion"] = "2024-03-01"
        for scope in (None, TOPIC_ID, WORKSPACE_ID.replace("/logging/", "/outside/")):
            template["resources"][1].pop("scope", None)
            if scope is not None:
                template["resources"][1]["scope"] = scope
            bundle = arm_source(self.write("arm.json", template), scope=SCOPE)
            self.assertEqual(bundle["resources"][1]["state"], "unknown")
            self.assertIsNone(bundle["resources"][1]["arm_id"])

    def test_seven_independent_blank_reviews_and_candidate_interview_binding(self):
        report = self.report()
        prepared = prepare_reviews(report, self.catalog, sorted(IDS), SCOPE)
        self.assertEqual(len(prepared["entries"]), 7)
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
        response = prepare_interview(report, self.catalog, self.question, SCOPE)
        self.assertEqual(len(response["decisions"]), 7)
        self.assertTrue(all(r["outcome"] is None for r in response["decisions"]))
        with self.assertRaises(InputError):
            compile_interview(response, self.catalog, at=AT)
        completed = self.completed()
        reviews = compile_interview(completed, self.catalog, at=AT)
        validate_reviews(reviews, self.catalog, SCOPE, at=AT)
        self.assertEqual(len({r["control_id"] for r in reviews["entries"]}), 7)
        for key, value in (
            ("scope", SUB + "/resourceGroups/other"),
            ("catalog_sha256", "0" * 64),
            ("requirements_sha256", "0" * 64),
            ("reviewer", None),
            ("valid_until", "2000-01-01T00:00:00Z"),
        ):
            altered = copy.deepcopy(completed)
            altered[key] = value
            with self.assertRaises(InputError):
                compile_interview(altered, self.catalog, at=AT)
        altered = copy.deepcopy(completed)
        altered["decisions"][1]["outcome"] = None
        with self.assertRaises(InputError):
            compile_interview(altered, self.catalog, at=AT)
        changed = copy.deepcopy(self.catalog)
        next(c for c in changed["controls"] if c["control_id"] in IDS)[
            "evidence_requirements"
        ].append("Changed")
        with self.assertRaises(InputError):
            compile_interview(completed, changed, at=AT)

    def test_human_confirmation_outputs_tiers_and_independent_exceptions(self):
        manual = compile_interview(self.completed(), self.catalog, at=AT)
        report = self.report(manual=manual)
        for row in report["results"]:
            if row["control_id"] in IDS:
                self.assertNotEqual(row["observed"]["evidence_tier"], "verified")
        for format in ("json", "markdown", "html", "csv", "sarif", "pr-summary"):
            output = render(report, format)
            self.assertNotIn(PRIVATE, output)
            self.assertTrue(output)
        self.assertGreater(len(render_xlsx(report)), 0)
        exception = prepare_reviews(
            self.report(),
            self.catalog,
            [self.control("G06.02")["control_id"]],
            SCOPE,
            kind="exceptions",
        )
        exception["entries"][0].update(
            reviewer="Authored exception reviewer",
            rationale="Independent accepted test risk.",
            evidence="https://example.invalid/risk",
            valid_from=AT,
            valid_until=UNTIL,
            outcome="pass",
        )
        # Exception validation rejects an invented technical outcome.
        with self.assertRaises(InputError):
            validate_reviews(exception, self.catalog, SCOPE, at=AT)
        exceptions = document(
            "exceptions",
            schema_version="1.1",
            entries=[
                {
                    **{key: value for key, value in entry.items() if key != "outcome"},
                    "disposition": "accepted",
                }
                for entry in manual["entries"]
            ],
        )
        without_confirmation = self.report(exceptions=exceptions)
        for row in without_confirmation["results"]:
            if row["control_id"] in IDS:
                self.assertEqual(row["observed"]["exception_disposition"], "accepted")
                self.assertNotEqual(row["observed"]["reason"], "manual_attestation")
        both = self.report(manual=manual, exceptions=exceptions)
        for row in both["results"]:
            if row["control_id"] in IDS:
                self.assertEqual(row["observed"]["exception_disposition"], "accepted")
                self.assertEqual(row["observed"]["reason"], "manual_attestation")
                self.assertNotEqual(row["observed"]["evidence_tier"], "verified")

    def test_scoped_tiers_reject_unbound_and_wrong_kind_facts(self):
        baseline = self.report()
        self.assertEqual(sum(baseline["evidence_tiers"]["counts"].values()), 255)
        for row in baseline["results"]:
            if row["control_id"] in IDS:
                expected = (
                    "manual"
                    if row["automation"] == "manual"
                    else (
                        "needs_decision"
                        if row["control_id"] == self.control("G03.10")["control_id"]
                        else "signal"
                    )
                )
                self.assertEqual(row["observed"]["evidence_tier"], expected)
        for boundary in (
            None,
            SUB + "/resourceGroups/other",
            "/providers/Microsoft.Management/managementGroups/tenant",
        ):
            bundle = self.bundle()
            bundle["scope"] = boundary
            report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
            for row in report["results"]:
                if row["control_id"] in IDS and row["automation"] != "manual":
                    self.assertEqual(row["observed"]["evidence_tier"], "needs_decision")
        bundle = self.bundle()
        topic = bundle["resources"][4]
        topic["properties"] = {
            "logAlertSummary": bundle["resources"][3]["properties"]["logAlertSummary"]
        }
        bundle["resources"] = [topic]
        context = review_context(self.control("G03.11"), bundle)
        self.assertIn("unknown", context["resources"][0]["facts"]["logAlertSummary"])
        report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        row = next(
            r for r in report["results"] if r["control_id"] == self.control("G03.11")["control_id"]
        )
        self.assertEqual(row["observed"]["evidence_tier"], "needs_decision")

    def test_saved_injected_inventory_does_not_authorize_new_detail_routes(self):
        requests = []

        def transport(method, url, body=None):
            requests.append(url)
            if "/resources?" in url:
                return Response(
                    200,
                    {
                        "value": [
                            {"id": WORKSPACE_ID, "type": WORKSPACE},
                            {"id": ONBOARDING_ID, "type": ONBOARDING},
                            {"id": TOPIC_ID, "type": TOPIC},
                        ]
                    },
                    {},
                )
            if (
                "/providers/microsoft.authorization/policy" in url.lower()
                or "/providers/microsoft.policyinsights/policystates/latest/queryresults?"
                in url.lower()
            ):
                return Response(200, {"value": []}, {})
            self.fail("A new logging or tenant route is not authorized")

        bundle = Collector(transport).collect(
            subscriptions=["00000000-0000-0000-0000-000000000001"], inventory_authorized=True
        )
        self.assertEqual(len(bundle["resources"]), 3)
        self.assertTrue(
            all(not row["properties"] and row["api_version"] is None for row in bundle["resources"])
        )
        self.assertTrue(
            all(
                "/workspaces/" not in url.lower() and "/topics/" not in url.lower()
                for url in requests
            )
        )
        report = assess(bundle, self.catalog, at=bundle["collected_at"], evidence_tiers=True)
        for row in report["results"]:
            if row["control_id"] in IDS:
                self.assertNotEqual(row["observed"]["evidence_tier"], "verified")

    def test_explicit_plan_ids_join_without_inventing_raw_computed_ids(self):
        plan = {
            "format_version": "1.2",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "mode": "managed",
                            "type": "azurerm_log_analytics_workspace",
                            "address": "azurerm_log_analytics_workspace.logs",
                            "values": {
                                "id": WORKSPACE_ID,
                                "name": "central-logs",
                                "resource_group_name": "logging",
                                "sku": "PerGB2018",
                                "retention_in_days": 30,
                            },
                        },
                        {
                            "mode": "managed",
                            "type": "azurerm_sentinel_log_analytics_workspace_onboarding",
                            "address": "azurerm_sentinel_log_analytics_workspace_onboarding.logs",
                            "values": {
                                "id": ONBOARDING_ID,
                                "workspace_id": WORKSPACE_ID,
                                "customer_managed_key_enabled": False,
                            },
                        },
                    ]
                }
            },
        }
        bundle = plan_source(
            self.write("explicit.json", plan), scope=SCOPE, provider_version="4.50.0"
        )
        self.assertEqual(
            linked_context(bundle["resources"][1], self.index(bundle), SCOPE)["links"][0]["arm_id"],
            WORKSPACE_ID.lower(),
        )
        raw = self.root / "raw"
        raw.mkdir()
        (raw / "main.tf").write_text(
            'resource "azurerm_sentinel_log_analytics_workspace_onboarding" "central" {\n'
            "workspace_id = azurerm_log_analytics_workspace.central.id\n"
            "customer_managed_key_enabled = false\n}\n",
            encoding="utf-8",
        )
        unresolved = terraform_source(raw, scope=SCOPE, provider_version="4.50.0")
        self.assertIsNone(unresolved["resources"][0]["arm_id"])
        self.assertIn(
            "unknown", linked_context(unresolved["resources"][0], self.index(unresolved), SCOPE)
        )

    def test_original_time_replay_projection_is_private_idempotent_and_semantic(self):
        bundle = self.bundle()
        bundle["resources"][0]["properties"]["logWorkspaceSummary"]["private"] = PRIVATE
        bundle["resources"][3]["properties"]["logAlertSummary"]["query"] = PRIVATE
        sanitized = sanitize_evidence(bundle)
        self.assertNotIn(PRIVATE, json.dumps(sanitized))
        self.assertEqual(sanitized["collected_at"], AT)
        twice = sanitize_evidence(sanitized)
        for left, right in zip(sanitized["resources"], twice["resources"], strict=True):
            self.assertEqual(left["properties"], right["properties"])
        for control in self.catalog["controls"]:
            if control["control_id"] in IDS:
                self.assertEqual(
                    review_context(control, bundle), review_context(control, sanitized)
                )
        # Real packaged predecessor replay is exercised, not a synthetic accepted successor.
        export_bundle(self.root / "replay", bundle, self.accepted, at=AT, evidence_tiers=True)
        replay = replay_bundle(self.root / "replay")
        self.assertEqual(
            semantic(replay), semantic(assess(bundle, self.accepted, at=AT, evidence_tiers=True))
        )
        self.assertEqual(replay["evidence"][0]["collected_at"], AT)
        self.assertEqual(
            digest(self.accepted),
            digest(
                load_catalog(
                    str(files("alz_assessor").joinpath("data", "catalog-2026-11-06.12.json"))
                )
            ),
        )

    def test_local_session_remains_blank_and_persists_authored_decision(self):
        session = ReviewSession(
            self.bundle(), self.catalog, self.root / "session", clock=lambda: AT
        )
        self.assertEqual(session.state()["records"], [])
        self.assertNotIn(PRIVATE, json.dumps(session.state()))
        reviews = compile_interview(self.completed(), self.catalog, at=AT)
        target = next(
            row
            for row in reviews["entries"]
            if row["control_id"] == self.control("G05.01")["control_id"]
        )
        result = session.save(
            {
                "revision": 0,
                "control_id": target["control_id"],
                "kind": "manual",
                "decision": target["outcome"],
                "replace_existing": False,
                **{
                    key: target[key]
                    for key in ("reviewer", "rationale", "evidence", "valid_from", "valid_until")
                },
            }
        )
        self.assertTrue(result)
        self.assertEqual(len(session.state()["records"]), 1)

    def test_real_bicep_logging_workspace_extensions_and_alerts_without_restore(self):
        compiler = os.environ.get("BICEP_COMPILER")
        if not compiler:
            self.skipTest("No existing compiler discovered; no acquisition attempted")
        bundle = arm_source(FIXTURE, scope=SCOPE, compiler=compiler, bicep=True)
        self.assertEqual(len(bundle["resources"]), 6)
        self.assertTrue(all(row["state"] == "known" for row in bundle["resources"]))
        self.assertNotIn("print authored_fixture", json.dumps(bundle))
        onboarding = next(
            row for row in bundle["resources"] if row["resource_type"].lower() == ONBOARDING
        )
        self.assertEqual(onboarding["arm_id"], ONBOARDING_ID.lower())
        self.assertEqual(
            linked_context(onboarding, self.index(bundle), SCOPE)["links"][0]["arm_id"],
            WORKSPACE_ID.lower(),
        )
        log = next(row for row in bundle["resources"] if row["resource_type"].lower() == LOG_ALERT)
        self.assertEqual(log["properties"]["logAlertSummary"]["kind"], "LogAlert")
        for row in bundle["resources"]:
            if row["resource_type"].lower() in (DIAGNOSTIC, LOG_ALERT, METRIC_ALERT):
                self.assertEqual(len(linked_context(row, self.index(bundle), SCOPE)["links"]), 1)
        for catalog in (self.accepted, self.catalog):
            report = assess(bundle, catalog, at=bundle["collected_at"], evidence_tiers=True)
            for row in report["results"]:
                if row["control_id"] in IDS:
                    self.assertNotEqual(row["planned"]["outcome"], "pass")
                    self.assertNotEqual(row["planned"]["evidence_tier"], "verified")
