import contextlib
import copy
import hashlib
import io
import json
import os
import tempfile
import unittest
import zipfile
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from alz_assessor import interviews
from alz_assessor.arm import API_VERSIONS, PLANNED_API_VERSIONS, arm_source, properties
from alz_assessor.azure import Collector, Response
from alz_assessor.billing_evidence import BUDGET, configuration
from alz_assessor.catalog import load_catalog
from alz_assessor.cli import main
from alz_assessor.comparison import compare
from alz_assessor.contracts import control_digest, document, validate
from alz_assessor.engine import assess
from alz_assessor.plan import plan_source
from alz_assessor.policy_strategy_evidence import ASSIGNMENT, DEFINITION, INITIATIVE
from alz_assessor.policy_strategy_evidence import configuration_context as policy_context
from alz_assessor.replay import export_bundle, replay_bundle, sanitize_evidence, semantic
from alz_assessor.reports import render, render_xlsx
from alz_assessor.review_page import review_page
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import prepare_reviews, review_context
from alz_assessor.sources import terraform_source, tf_properties
from alz_assessor.sovereign_evidence import (
    LOCATION_GUIDS,
    POLICY_GUIDS,
    REQUIREMENT_GUIDS,
    REQUIREMENTS_WARNING,
)
from alz_assessor.sovereign_evidence import configuration_context as location_context
from alz_assessor.terraform import InputError, tree_hash
from alz_assessor.tiers import prepared_signal

ROOT = Path(__file__).resolve().parents[1]
SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
OTHER = "/subscriptions/00000000-0000-0000-0000-000000000002"
RG = SCOPE + "/resourcegroups/authored"
MG = "/providers/microsoft.management/managementgroups/not-a-sovereign-designation"
VM_KIND = "microsoft.compute/virtualmachines"
STORAGE = "microsoft.storage/storageaccounts"
VM = RG + "/providers/" + VM_KIND + "/authored"
STORE = RG + "/providers/" + STORAGE + "/authored"
BUDGET_ID = RG + "/providers/" + BUDGET + "/authored"
AUTH = "/providers/microsoft.authorization/"
DEF = SCOPE + AUTH + "policydefinitions/custom"
SET = SCOPE + AUTH + "policysetdefinitions/not-a-sovereign-baseline"
ASSIGN = RG + AUTH + "policyassignments/not-effective-enforcement"
BUILTIN = AUTH + "policysetdefinitions/00000000-0000-0000-0000-000000000003"
AT = "2026-11-07T04:30:00Z"
UNTIL = "2026-11-08T04:30:00Z"
PRIVATE = "PRIVATE-AMOUNT-RECIPIENT-PERSONNEL-WORKLOAD-RULE"
IDS = {
    "E02.01": "29fd366b-a180-452b-9bd7-954b7700c667",
    "E03.01": "5a917e1f-348e-4f25-9c27-d42e8bbac757",
    "E03.02": "78b22132-b41c-460b-a4d3-df8f73a67dc2",
    "E03.03": "caeea0e9-1024-41df-a52e-d99c3f22a6f4",
    "E03.04": "9b461617-db7b-4399-8ac6-d4eb7153893a",
    "E03.05": "bfaf7b7a-9e6c-4840-a2bd-2c524326bdf6",
    "E03.06": "3105633e-b168-4ce0-a016-5f10e7cdea5a",
    "E03.07": "77cf1acd-16b4-4092-8d30-6ec9579854ce",
}


class SovereignRequirementsPreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.matrix = json.loads(
            (ROOT / "references/recommendation-batches/preparation-28.json").read_text("utf-8")
        )
        self.catalog = copy.deepcopy(
            load_catalog(str(files("alz_assessor").joinpath("data", "catalog-2026-11-06.27.json")))
        )
        self.catalog["review_state"] = "authored-in-memory-preparation-not-accepted"
        rows = {row["guid"]: row for row in self.matrix["recommendations"]}
        for control in self.catalog["controls"]:
            if control["upstream_guid"] in rows:
                row = rows[control["upstream_guid"]]
                for key in ("review_resource_types", "review_fact_paths", "evidence_requirements"):
                    if key in row:
                        control[key] = copy.deepcopy(row[key])
                    else:
                        control.pop(key, None)
                control["rationale"] = row["limitations"]
        validate(self.catalog, "catalog")
        network = patch("socket.socket.connect", side_effect=AssertionError("network forbidden"))
        network.start()
        self.addCleanup(network.stop)

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def control(self, display):
        return next(c for c in self.catalog["controls"] if c["upstream_id"] == display)

    def own(self, report):
        return [r for r in report["results"] if r["upstream_id"] in IDS]

    def record(self, kind, identity, raw, root=None):
        return {
            "logical_id": identity,
            "arm_id": identity,
            "resource_type": kind,
            "state": "known",
            "reason": "",
            "source_location": "fixture://authored-requirements-not-assurance",
            "properties": properties(kind, raw, root=root),
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
            artifact_hashes={"authored-fixture": "0" * 64},
            diagnostics=[],
            resources=[
                self.record(
                    DEFINITION,
                    DEF,
                    {
                        "policyType": "Custom",
                        "mode": "All",
                        "version": "1.2.3",
                        "displayName": PRIVATE,
                        "parameters": {PRIVATE: PRIVATE},
                        "policyRule": {
                            "if": {"field": PRIVATE, "equals": PRIVATE},
                            "then": {"effect": "deny"},
                        },
                    },
                ),
                self.record(
                    INITIATIVE,
                    SET,
                    {
                        "policyType": "Custom",
                        "version": "1.2.3",
                        "displayName": "Sovereignty Baseline - Confidential Policies",
                        "policyDefinitions": [
                            {
                                "policyDefinitionId": DEF,
                                "definitionVersion": "1.2.3",
                                "policyDefinitionReferenceId": PRIVATE,
                            }
                        ],
                        "policyDefinitionGroups": [],
                    },
                ),
                self.record(
                    ASSIGNMENT,
                    ASSIGN,
                    {
                        "policyDefinitionId": SET,
                        "definitionVersion": "1.2.3",
                        "enforcementMode": "Default",
                        "notScopes": [],
                        "resourceSelectors": [],
                        "overrides": [],
                        "parameters": {PRIVATE: {"value": PRIVATE}},
                    },
                ),
                self.record(
                    VM_KIND,
                    VM,
                    {"osProfile": {PRIVATE: PRIVATE}},
                    {"location": "West Europe", "tags": {PRIVATE: PRIVATE}},
                ),
                self.record(
                    STORAGE,
                    STORE,
                    {"encryption": {PRIVATE: PRIVATE}},
                    {"sku": {"name": "Standard_GZRS"}, "kind": "StorageV2"},
                ),
                self.record(BUDGET, BUDGET_ID, self.budget_raw(), {"apiVersion": "2024-08-01"}),
            ],
        )

    def budget_raw(self):
        return {
            "category": "Cost",
            "timeGrain": "Monthly",
            "amount": PRIVATE,
            "currency": PRIVATE,
            "currentSpend": PRIVATE,
            "forecastSpend": PRIVATE,
            "filter": {PRIVATE: PRIVATE},
            "timePeriod": {PRIVATE: PRIVATE},
            "notifications": {
                mode + PRIVATE: {
                    "enabled": True,
                    "operator": "GreaterThan",
                    "thresholdType": mode,
                    "threshold": PRIVATE,
                    "contactEmails": [PRIVATE],
                    "contactGroups": [PRIVATE],
                    "contactRoles": [PRIVATE],
                }
                for mode in ("Actual", "Forecasted")
            },
        }

    def budget_fact(self, bundle=None):
        return self.context("E02.01", bundle)["resources"][0]["facts"]["budgetConfiguration"]

    def context(self, display, bundle=None):
        return review_context(self.control(display), bundle or self.bundle())

    def bank(self):
        item = self.matrix["interview"]
        return patch.dict(
            interviews.BANK,
            {item["id"]: {k: item[k] for k in ("question", "controls")}},
        )

    def response(self, selected=None):
        report = assess(self.bundle(), self.catalog, at=AT, evidence_tiers=True)
        return interviews.prepare_interview(
            report, self.catalog, self.matrix["interview"]["id"], SCOPE, selected
        )

    def filled(self, response):
        response = copy.deepcopy(response)
        response.update(
            answer="Authored fixture; not a legal, financial or organization decision.",
            reviewer="Fixture reviewer",
            rationale="Eight independently authored fixture decisions.",
            evidence="https://example.invalid/redacted",
            valid_from=AT,
            valid_until=UNTIL,
        )
        for index, row in enumerate(response["decisions"]):
            row["outcome"] = "pass" if index % 2 else "fail"
        return response

    def test_exact_eight_sources_and_no_accepted_activation(self):
        targets = ROOT / "references/recommendation-batches/targets.json"
        rows = json.loads(targets.read_text("utf-8"))["targets"]
        self.assertEqual({r["upstream_id"]: r["guid"] for r in rows if r["batch"] == "28"}, IDS)
        self.assertEqual(
            hashlib.sha256(targets.read_bytes()).hexdigest(),
            "582fe02feee03b50961e5548fa7551bbd3d8729fbcb68f51837d548e59eaa291",
        )
        self.assertEqual(REQUIREMENT_GUIDS, set(IDS.values()))
        self.assertEqual(POLICY_GUIDS, {IDS["E03.01"], IDS["E03.02"]})
        self.assertEqual(LOCATION_GUIDS, {IDS["E03.04"], IDS["E03.05"]})
        self.assertNotIn("catalog_version", self.matrix)
        self.assertEqual({r["upstream_id"]: r["guid"] for r in self.matrix["recommendations"]}, IDS)
        self.assertEqual(self.matrix["review_state"], "source-reviewed-preparation-not-accepted")
        accepted = json.loads(
            (ROOT / "references/recommendation-batches/batch-28.json").read_text("utf-8")
        )
        question = accepted["interview"]
        self.assertEqual({"id": question["id"], **interviews.BANK[question["id"]]}, question)
        self.assertNotEqual(question["question"], self.matrix["interview"]["question"])
        manifest = json.loads(
            (ROOT / "references/recommendation-batches/preparation-28-sources.json").read_text(
                "utf-8"
            )
        )
        sources = {r["id"]: r for r in manifest["sources"]}
        self.assertEqual(len(sources), len(manifest["sources"]))
        for source in sources.values():
            self.assertRegex(source["sha256"], "^[0-9a-f]{64}$")
            self.assertTrue(source["retrieved_at"])
            self.assertTrue(source["resolved_url"].startswith("https://"))
            self.assertTrue(source["finding"])
            self.assertTrue(source["reuse"])
            if source["id"] not in {"service-data-residency", "microsoft-site-reuse"}:
                self.assertRegex(source["revision"], "^[0-9a-f]{40}$")
        for row in self.matrix["recommendations"]:
            self.assertTrue(set(row["sources"]).issubset(sources))
            self.assertTrue(row["evidence_requirements"][0].startswith("Reviewer decision:"))
            self.assertNotIn("rule", row)
        self.assertIn("previous-versions", sources["sovereign-release-history"]["resolved_url"])
        self.assertIn(
            "implementation-options", sources["sovereign-objectives-link"]["resolved_url"]
        )
        self.assertIn("Actual only", sources["budget-rest-2019-10-01"]["finding"])
        self.assertIn("Actual and Forecasted", sources["budget-rest-2024-08-01"]["finding"])

    def test_candidate_does_not_change_nonown_objects_or_immutable_wording(self):
        accepted = load_catalog()
        before = {c["control_id"]: c for c in accepted["controls"]}
        self.assertEqual(len(before), 255)
        for control in self.catalog["controls"]:
            original = before[control["control_id"]]
            if control["upstream_guid"] not in REQUIREMENT_GUIDS:
                self.assertEqual(control, original)
            for key in (
                "control_id",
                "upstream_id",
                "upstream_guid",
                "recommendation",
                "automation",
            ):
                self.assertEqual(control[key], original[key])
        self.assertEqual(
            {
                r["upstream_id"]
                for r in self.matrix["recommendations"]
                if r["classification"] == "manual"
            },
            {"E03.03", "E03.06", "E03.07"},
        )

    def test_policy_context_reuses_versioned_custom_joins_not_sovereign_identity(self):
        for display in ("E03.01", "E03.02"):
            context = self.context(display)
            joined = context["resources"][2]["policy_configuration"]["definition"]
            self.assertEqual(joined["definitionId"], SET)
            self.assertEqual(joined["facts"]["version"], "1.2.3")
            self.assertEqual(joined["ancestry"], "positive_supplied_path")
            self.assertIn("saved_management_hierarchy", context)
            self.assertEqual(context["warning"], REQUIREMENTS_WARNING)
            self.assertNotIn(PRIVATE, json.dumps(context))
            self.assertNotIn("sovereignIdentity", json.dumps(context))

    def test_policy_version_missing_mismatch_wildcard_and_builtin_are_unknown(self):
        for version in (None, "1.*.*", "1.2.4", {"unknown": "not supplied"}):
            bundle = self.bundle()
            bundle["resources"][2]["properties"]["policyAssignmentSummary"]["definitionVersion"] = (
                version
            )
            definition = self.context("E03.02", bundle)["resources"][2]["policy_configuration"][
                "definition"
            ]
            self.assertIn("unknown", definition)
        bundle = self.bundle()
        bundle["resources"][2]["properties"]["policyAssignmentSummary"]["definitionId"] = BUILTIN
        joined = self.context("E03.02", bundle)["resources"][2]["policy_configuration"][
            "definition"
        ]
        self.assertEqual(joined["unknown"], "global_builtin_reference_not_fetched_or_bound")

    def test_policy_duplicate_denied_wrong_type_outside_scope_and_over_bound(self):
        for mutation in ("duplicate", "denied", "wrong_type", "outside", "over_bound"):
            bundle = self.bundle()
            row = bundle["resources"][1]
            if mutation == "duplicate":
                bundle["resources"].append({**copy.deepcopy(row), "logical_id": "duplicate"})
            elif mutation == "denied":
                row["state"], row["reason"] = "unknown", "permission denied"
            elif mutation == "wrong_type":
                row["resource_type"] = DEFINITION
            elif mutation == "outside":
                row["arm_id"] = SET.replace(SCOPE, OTHER)
            else:
                bundle["resources"] += [
                    {
                        **copy.deepcopy(row),
                        "logical_id": f"over-bound-{index}",
                        "arm_id": SET + f"-{index}",
                    }
                    for index in range(101)
                ]
            if mutation in {"duplicate", "wrong_type"}:
                with self.assertRaises(InputError):
                    self.context("E03.02", bundle)
                by_id = {}
                for resource in bundle["resources"]:
                    by_id.setdefault(resource["arm_id"], []).append(resource)
                configuration = policy_context(bundle["resources"][2], bundle, by_id)
                self.assertIn("unknown", configuration["definition"])
                continue
            resource = next(
                r for r in self.context("E03.02", bundle)["resources"] if r["arm_id"] == ASSIGN
            )
            configuration = resource["policy_configuration"]
            self.assertIn("unknown", configuration.get("definition", configuration))

    def test_location_and_redundancy_are_only_typed_source_specific_configuration(self):
        context = self.context("E03.04")
        self.assertEqual(context["resources"][0]["facts"], {"resourceLocation": "westeurope"})
        self.assertEqual(
            context["resources"][1]["facts"],
            {
                "storageRedundancySummary": {
                    "sku": "Standard_GZRS",
                    "kind": "StorageV2",
                    "configuredRedundancy": "zone_and_region",
                }
            },
        )
        self.assertTrue(all(not r["subchecks"] for r in context["resources"]))
        self.assertEqual(
            self.context("E03.05")["resources"][0]["facts"], {"resourceLocation": "westeurope"}
        )
        self.assertNotIn("secondaryLocation", json.dumps(context))
        self.assertNotIn("jurisdictionApproved", json.dumps(context))

    def test_location_duplicate_denied_wrong_identity_scope_and_over_bound_stay_unknown(self):
        for mutation in ("duplicate", "denied", "wrong_type", "outside", "over_bound"):
            bundle = self.bundle()
            row = bundle["resources"][3]
            if mutation == "duplicate":
                bundle["resources"].append({**copy.deepcopy(row), "logical_id": "duplicate"})
            elif mutation == "denied":
                row["state"], row["reason"] = "unknown", "permission denied"
            elif mutation == "wrong_type":
                row["arm_id"] = STORE
            elif mutation == "outside":
                row["arm_id"] = VM.replace(SCOPE, OTHER)
            else:
                bundle["resources"] += [
                    {
                        **copy.deepcopy(row),
                        "logical_id": f"over-bound-{index}",
                        "arm_id": VM + f"-{index}",
                    }
                    for index in range(101)
                ]
            if mutation in {"duplicate", "wrong_type"}:
                with self.assertRaises(InputError):
                    self.context("E03.05", bundle)
                by_id = {}
                for resource in bundle["resources"]:
                    by_id.setdefault(resource["arm_id"], []).append(resource)
                self.assertIn("unknown", location_context(row, by_id, bundle, ["resourceLocation"]))
                continue
            context = self.context("E03.05", bundle)
            if mutation == "outside":
                self.assertEqual(context["resources"], [])
                self.assertEqual(context["unbound_resources"], 1)
            else:
                self.assertIn("unknown", context["resources"][0]["facts"])
                self.assertEqual(context["resources"][0]["subchecks"], {})

    def test_missing_unsupported_locations_skus_and_partial_inventory_are_not_absence(self):
        for value in (None, "", PRIVATE + "/", 5, {"unknown": "sensitive"}):
            bundle = self.bundle()
            bundle["resources"][3]["properties"]["resourceLocation"] = value
            self.assertIn(
                "unknown",
                self.context("E03.05", bundle)["resources"][0]["facts"]["resourceLocation"],
            )
        bundle = self.bundle()
        bundle["resources"][4]["properties"]["storageRedundancySummary"]["sku"] = "Future_SKU"
        self.assertIn(
            "unknown",
            self.context("E03.04", bundle)["resources"][1]["facts"]["storageRedundancySummary"][
                "sku"
            ],
        )
        bundle["resources"] = []
        context = self.context("E03.04", bundle)
        self.assertFalse(context["inventory_complete"])
        self.assertEqual(context["resources"], [])
        self.assertTrue(
            all(
                r["observed"]["outcome"] == "manual"
                for r in self.own(assess(bundle, self.catalog, at=AT, evidence_tiers=True))
            )
        )

    def test_positive_saved_hierarchy_prepares_placement_not_designated_root(self):
        bundle = self.bundle()
        bundle["scope"] = MG
        bundle["metadata"] = {
            "relationships": [{"id": SCOPE, "parent": MG}],
            "completeness": {"relationships": False},
        }
        context = self.context("E03.02", bundle)
        self.assertEqual(context["resources"][2]["policy_configuration"]["configuredScope"], RG)
        self.assertFalse(context["saved_management_hierarchy"]["complete"])
        self.assertNotIn("tenantRoot", json.dumps(context))
        bundle["metadata"]["relationships"] = []
        self.assertEqual(self.context("E03.02", bundle)["resources"], [])

    def test_manual_requirements_and_integrated_budget_keep_decisions_independent(self):
        for display in ("E03.03", "E03.06", "E03.07"):
            context = self.context(display)
            self.assertEqual(context["resources"], [])
            self.assertEqual(context["warning"], REQUIREMENTS_WARNING)
        self.assertIn("Actual merged03", self.matrix["deferred_integration"])
        self.assertIn("actual merged21", self.matrix["deferred_integration"])
        self.assertEqual(self.budget_fact()["apiVersion"], "2024-08-01")
        report = assess(self.bundle(), self.catalog, at=AT, evidence_tiers=True)
        for row in self.own(report):
            self.assertEqual(row["observed"]["outcome"], "manual")
            self.assertNotEqual(row["observed"]["evidence_tier"], "verified")

    def test_adapters_raw_hcl_local_module_snapshot_and_optional_plan_reuse(self):
        values = {
            "name": "authored",
            "resource_group_name": "authored",
            "location": "West Europe",
            "admin_password": PRIVATE,
            "tags": {PRIVATE: PRIVATE},
        }
        source = self.write(
            "raw/main.tf.json",
            {
                "resource": {
                    "azurerm_linux_virtual_machine": {"authored": values},
                    "azurerm_storage_account": {
                        "authored": {
                            **values,
                            "account_tier": "Standard",
                            "account_replication_type": "GZRS",
                            "account_kind": "StorageV2",
                        }
                    },
                }
            },
        )
        self.write("parent/main.tf.json", {"module": {"vm": {"source": "./module"}}})
        self.write("parent/module/main.tf.json", json.loads(source.read_text("utf-8")))
        self.write(
            "root/main.tf.json",
            {"module": {"vm": {"source": "example.invalid/vm/azurerm", "version": "1.0.0"}}},
        )
        manifest = self.write(
            "snapshots.json",
            {
                "modules": [
                    {
                        "source": "example.invalid/vm/azurerm",
                        "version": "1.0.0",
                        "subdirectory": "",
                        "path": "raw",
                        "sha256": tree_hash(source.parent),
                    }
                ]
            },
        )
        bundles = [
            terraform_source(source.parent, scope=RG, provider_version="4.50.0"),
            terraform_source(
                self.root / "parent",
                scope=RG,
                provider_version="4.50.0",
                authorized_roots=[self.root],
            ),
            terraform_source(
                self.root / "root",
                scope=RG,
                provider_version="4.50.0",
                snapshots=manifest,
                authorized_roots=[self.root],
            ),
        ]
        plan = {
            "format_version": "1.2",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "mode": "managed",
                            "address": "azurerm_linux_virtual_machine.authored",
                            "type": "azurerm_linux_virtual_machine",
                            "values": {**values, "id": VM},
                        }
                    ]
                }
            },
        }
        bundles.append(
            plan_source(self.write("plan.json", plan), scope=RG, provider_version="4.50.0")
        )
        for bundle in bundles:
            self.assertNotIn(PRIVATE, json.dumps(bundle))
            self.assertEqual(
                self.context("E03.05", bundle)["resources"][0]["facts"]["resourceLocation"],
                "westeurope",
            )
        plan["planned_values"]["root_module"]["resources"][0]["sensitive_values"] = {
            "location": True
        }
        sensitive = plan_source(
            self.write("sensitive.json", plan), scope=RG, provider_version="4.50.0"
        )
        self.assertIn(
            "unknown",
            self.context("E03.05", sensitive)["resources"][0]["facts"]["resourceLocation"],
        )
        self.assertEqual(
            tf_properties("azurerm_storage_account", {"account_replication_type": PRIVATE})[
                "storageRedundancySummary"
            ]["sku"],
            {"unknown": "enum_missing_unresolved_or_invalid"},
        )

    def test_arm_versions_conditionals_and_injected_collector_add_no_live_routes(self):
        template = self.write(
            "template.json",
            {
                "resources": [
                    {
                        "type": VM_KIND,
                        "apiVersion": version,
                        "name": name,
                        "location": "West Europe",
                        "properties": {"osProfile": {PRIVATE: PRIVATE}},
                        **(
                            {"condition": "[parameters('condition')]"}
                            if name == "conditional"
                            else {}
                        ),
                    }
                    for name, version in (
                        ("supported", "2024-07-01"),
                        ("unsupported", "2020-01-01"),
                        ("conditional", "2024-07-01"),
                    )
                ]
            },
        )
        bundle = arm_source(template, scope=RG)
        self.assertEqual([r["state"] for r in bundle["resources"]], ["known", "unknown", "unknown"])
        self.assertNotIn(PRIVATE, json.dumps(bundle))
        self.assertEqual(PLANNED_API_VERSIONS[VM_KIND], {"2024-07-01"})
        self.assertTrue(
            all(k not in API_VERSIONS for k in (VM_KIND, DEFINITION, INITIATIVE, ASSIGNMENT))
        )
        requests = []

        def transport(method, url, body=None):
            requests.append(url.lower())
            if "/resources?" in url:
                return Response(200, {"value": [{"id": VM, "type": VM_KIND}]}, {})
            return Response(200, {"value": []}, {})

        collected = Collector(transport).collect(
            subscriptions=[SCOPE.split("/")[2]], inventory_authorized=True
        )
        self.assertFalse(
            any(
                term in url
                for url in requests
                for term in ("budget", "billing", "personnel", "confidential", "policydefinitions/")
            )
        )
        self.assertIn(
            "unknown",
            self.context("E03.05", collected)["resources"][0]["facts"]["resourceLocation"],
        )

    def test_raw_hcl_uses_existing_location_and_storage_projection_only(self):
        source = self.root / "main.tf"
        source.write_text(
            'resource "azurerm_linux_virtual_machine" "authored" {\n'
            ' name = "authored"\n resource_group_name = "authored"\n'
            ' location = "West Europe"\n tags = {}\n}\n'
            'resource "azurerm_storage_account" "authored" {\n'
            ' name = "authored"\n resource_group_name = "authored"\n'
            ' location = "West Europe"\n account_tier = "Standard"\n'
            ' account_replication_type = "ZRS"\n account_kind = "StorageV2"\n}\n',
            encoding="utf-8",
        )
        bundle = terraform_source(self.root, scope=RG, provider_version="4.50.0")
        context = self.context("E03.04", bundle)
        self.assertEqual(context["resources"][0]["facts"], {"resourceLocation": "westeurope"})
        self.assertEqual(
            context["resources"][1]["facts"]["storageRedundancySummary"]["configuredRedundancy"],
            "zone",
        )
        self.assertTrue(all(not row["subchecks"] for row in context["resources"]))
        self.assertTrue(
            all(
                row["planned"]["outcome"] == "manual"
                for row in self.own(assess(bundle, self.catalog, at=AT, evidence_tiers=True))
            )
        )

    def test_saved_policy_signals_stale_or_future_context_never_promote_requirements(self):
        bundle = self.bundle()
        bundle["metadata"] = {
            "policy_assignments": [
                {"id": ASSIGN, "definition_id": BUILTIN, "not_scopes": [], "conflict": False}
            ],
            "policy_compliance": [
                {
                    "resourceId": RG,
                    "policyAssignmentId": ASSIGN,
                    "policyDefinitionId": BUILTIN,
                    "complianceState": "Compliant",
                    "timestamp": AT,
                }
            ],
            "policy_exemptions": [],
        }
        with self.bank():
            manual = interviews.compile_interview(self.filled(self.response()), self.catalog, at=AT)
        current = assess(bundle, self.catalog, manual=manual, at=AT, evidence_tiers=True)
        for format in ("json", "markdown", "html", "csv", "sarif", "pr-summary"):
            self.assertNotIn(PRIVATE, render(current, format))
        self.assertTrue(
            all(row["observed"]["evidence_tier"] != "verified" for row in self.own(current))
        )
        self.assertNotIn("query_signals", current)
        for collected_at in ("2000-01-01T00:00:00Z", UNTIL):
            stale = copy.deepcopy(bundle)
            stale["collected_at"] = collected_at
            report = assess(stale, self.catalog, at=AT, evidence_tiers=True)
            self.assertTrue(
                all(
                    row["observed"]["evidence_tier"] not in {"signal", "verified"}
                    for row in self.own(report)
                )
            )

    def test_all_outputs_and_planned_observed_do_not_manufacture_verified(self):
        bundle = self.bundle()
        report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        for format in ("json", "markdown", "html", "csv", "sarif", "pr-summary"):
            rendered = render(report, format)
            self.assertNotIn(PRIVATE, rendered)
            if format in ("json", "markdown", "html", "csv"):
                self.assertIn("E03.07", rendered, msg=format)
        with zipfile.ZipFile(io.BytesIO(render_xlsx(report))) as archive:
            content = "".join(archive.read(p).decode() for p in archive.namelist())
            self.assertNotIn(PRIVATE, content)
            self.assertIn(IDS["E03.06"], content)
        planned = copy.deepcopy(bundle)
        planned["mode"], planned["source"] = "planned", "arm"
        combined = compare(assess(planned, self.catalog, at=AT, evidence_tiers=True), report, at=AT)
        for row in self.own(combined):
            self.assertEqual(row["planned"]["outcome"], "manual")
            self.assertEqual(row["observed"]["outcome"], "manual")
            self.assertNotEqual(row["planned"]["evidence_tier"], "verified")
            self.assertNotEqual(row["observed"]["evidence_tier"], "verified")

    def test_eight_independent_blank_outcomes_and_exceptions_with_selection(self):
        before = copy.deepcopy(interviews.BANK)
        with self.bank():
            response = self.response()
            self.assertEqual(len(response["decisions"]), 8)
            self.assertTrue(all(row["outcome"] is None for row in response["decisions"]))
            self.assertTrue(all(response[k] is None for k in ("reviewer", "answer", "evidence")))
            with self.assertRaises(InputError):
                interviews.compile_interview(response, self.catalog, at=AT)
            selected = "ALZ-" + IDS["E03.06"]
            for selection in ([selected, selected], ["ALZ-foreign"], []):
                with self.assertRaises(InputError):
                    self.response(selection)
            manual = interviews.compile_interview(
                self.filled(self.response([selected])), self.catalog, at=AT
            )
            report = assess(self.bundle(), self.catalog, manual=manual, at=AT, evidence_tiers=True)
            self.assertEqual(
                [r["control_id"] for r in self.own(report) if r["observed"]["outcome"] != "manual"],
                [selected],
            )
            self.assertTrue(
                all(r["observed"]["evidence_tier"] != "verified" for r in self.own(report))
            )
        self.assertEqual(before, interviews.BANK)
        template = prepare_reviews(
            assess(self.bundle(), self.catalog, at=AT),
            self.catalog,
            ["ALZ-" + guid for guid in IDS.values()],
            SCOPE,
            "exceptions",
        )
        self.assertTrue(all(row["disposition"] is None for row in template["entries"]))

    def test_attribution_scope_content_time_expiry_and_decision_binding(self):
        with self.bank():
            response = self.filled(self.response())
            for field, value in (
                ("scope", OTHER),
                ("reviewer", ""),
                ("evidence", ""),
                ("valid_from", UNTIL),
                ("valid_until", AT),
                ("catalog_sha256", "0" * 64),
                ("requirements_sha256", "0" * 64),
            ):
                with self.assertRaises(InputError, msg=field):
                    interviews.compile_interview({**response, field: value}, self.catalog, at=AT)
            for decisions in (
                response["decisions"][:-1],
                [response["decisions"][0]] * 8,
                [{**r, "outcome": None} for r in response["decisions"]],
                [{**r, "control_sha256": "0" * 64} for r in response["decisions"]],
            ):
                with self.assertRaises(InputError):
                    interviews.compile_interview(
                        {**response, "decisions": decisions}, self.catalog, at=AT
                    )
            manual = interviews.compile_interview(response, self.catalog, at=AT)
            for at in ("2000-01-01T00:00:00Z", UNTIL):
                report = assess(
                    self.bundle(), self.catalog, manual=manual, at=at, evidence_tiers=True
                )
                self.assertTrue(all(r["observed"]["outcome"] == "manual" for r in self.own(report)))
            changed = copy.deepcopy(self.catalog)
            control = next(c for c in changed["controls"] if c["upstream_id"] == "E03.03")
            control["rationale"] += " Changed."
            self.assertNotEqual(control_digest(control), control_digest(self.control("E03.03")))
            with self.assertRaises(InputError):
                interviews.compile_interview(response, changed, at=AT)

    def test_local_session_atomic_interview_failure_resume_and_separate_exception(self):
        with self.bank():
            session = ReviewSession(
                self.bundle(),
                self.catalog,
                self.root / "session",
                clock=lambda: AT,
                evidence_tiers=True,
            )
            state = session.state()
            question = next(
                r for r in state["interviews"] if r["id"] == self.matrix["interview"]["id"]
            )
            self.assertEqual(len(question["template"]["decisions"]), 8)
            self.assertIn(
                "vendor remote-access", review_page(state, "fixture-token", "fixture-nonce")
            )
            payload = {
                "revision": 0,
                "response": self.filled(question["template"]),
                "replace_existing": [],
            }
            before = copy.deepcopy(session.state())
            with patch.object(Path, "rename", side_effect=OSError("authored disk failure")):
                with self.assertRaisesRegex(OSError, "authored disk failure"):
                    session.save_interview(payload)
            self.assertEqual(session.state(), before)
            self.assertEqual([p.name for p in session.directory.iterdir()], ["revision-0000"])
            session.save_interview(payload)
            self.assertEqual(len(session.state()["records"]), 8)
            session.save(
                {
                    "revision": 1,
                    "control_id": "ALZ-" + IDS["E03.04"],
                    "kind": "exceptions",
                    "decision": "accepted",
                    "reviewer": "Fixture",
                    "evidence": "https://example.invalid/exception",
                    "rationale": "Authored exception; not jurisdiction approval.",
                    "valid_from": AT,
                    "valid_until": UNTIL,
                    "replace_existing": False,
                }
            )
            self.assertEqual(len(session.reviews["manual"]["entries"]), 8)
            self.assertEqual(len(session.reviews["exceptions"]["entries"]), 1)
            with self.assertRaises(InputError):
                session.save_interview(payload)
            resumed = ReviewSession.resume(
                session.directory / "revision-0002", self.root / "resumed", clock=lambda: AT
            )
            self.assertEqual(semantic(session.report), semantic(resumed.report))

    def test_sanitized_original_time_replay_preserves_facts_and_rejects_candidate(self):
        bundle = self.bundle()
        clean = sanitize_evidence(bundle)
        self.assertEqual(clean["collected_at"], AT)
        self.assertNotIn(PRIVATE, json.dumps(clean))
        for display in IDS:
            self.assertEqual(self.context(display, clean), self.context(display, bundle))
        with self.assertRaisesRegex(InputError, "differs from a packaged artifact"):
            export_bundle(self.root / "candidate", bundle, self.catalog, at=AT, evidence_tiers=True)
        for version in ("catalog.json", "catalog-2026-11-06.25.json", "catalog-2026-11-06.24.json"):
            accepted = load_catalog(str(files("alz_assessor").joinpath("data", version)))
            destination = self.root / version
            export_bundle(destination, bundle, accepted, at=AT, evidence_tiers=True)
            self.assertEqual(
                semantic(replay_bundle(destination)),
                semantic(assess(bundle, accepted, at=AT, evidence_tiers=True)),
            )

    def test_cli_saved_evidence_uses_same_candidate_without_network(self):
        evidence = self.write("saved.json", self.bundle())
        catalog = self.write("candidate.json", self.catalog)
        output = self.root / "report.json"
        with (
            contextlib.redirect_stdout(io.StringIO()),
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
        ):
            self.assertEqual(main(), 0)
        report = json.loads(output.read_text("utf-8"))
        self.assertEqual(len(self.own(report)), 8)
        self.assertNotIn(PRIVATE, json.dumps(report))
        self.assertTrue(all(r["observed"]["outcome"] == "manual" for r in self.own(report)))

    def test_budget_reuses_merged_version_qualified_helper_not_two_mode_compliance(self):
        fact = self.budget_fact()
        self.assertEqual(
            fact,
            configuration(self.budget_raw(), api_version="2024-08-01"),
        )
        self.assertEqual(
            {row["thresholdType"] for row in fact["notifications"]}, {"Actual", "Forecasted"}
        )
        self.assertTrue(all(row["enabled"] is True for row in fact["notifications"]))
        context = self.context("E02.01")
        self.assertIn("billing_configuration", context["resources"][0])
        self.assertEqual(context["resources"][0]["subchecks"], {})
        self.assertNotIn(PRIVATE, json.dumps(context))
        for version in ("2019-10-01", None, "2023-05-01", "future"):
            bundle = self.bundle()
            bundle["resources"][-1]["properties"] = properties(
                BUDGET, self.budget_raw(), root={"apiVersion": version}
            )
            notifications = self.budget_fact(bundle)["notifications"]
            if version == "2019-10-01":
                self.assertEqual(sum(r["thresholdType"] == "Actual" for r in notifications), 1)
            self.assertTrue(any(isinstance(r["thresholdType"], dict) for r in notifications))
            self.assertNotIn("Forecasted", json.dumps(notifications))

    def test_budget_api_alone_has_no_signal_and_other_tiers_use_strict_context(self):
        for display in ("E02.01", "E03.02", "E03.04", "E03.05"):
            bundle = self.bundle()
            self.assertTrue(prepared_signal(self.control(display), bundle))
            bundle["scope"] = OTHER
            self.assertFalse(prepared_signal(self.control(display), bundle))
        for values in (
            {"apiVersion": "2024-08-01"},
            {"apiVersion": "future"},
            {},
        ):
            bundle = self.bundle()
            bundle["resources"][-1]["properties"] = {"budgetConfiguration": values}
            self.assertFalse(prepared_signal(self.control("E02.01"), bundle))
        bundle = self.bundle()
        row = bundle["resources"][-1]
        row["state"], row["reason"] = "unknown", "permission denied"
        self.assertIn("unknown", self.context("E02.01", bundle)["resources"][0]["facts"])
        self.assertFalse(prepared_signal(self.control("E02.01"), bundle))

    def test_budget_notification_bounds_types_disabled_and_thresholds_are_not_evaluated(self):
        for count in (0, 1, 5, 6):
            raw = self.budget_raw()
            example = next(iter(raw["notifications"].values()))
            raw["notifications"] = {str(i): copy.deepcopy(example) for i in range(count)}
            bundle = self.bundle()
            bundle["resources"][-1]["properties"] = properties(
                BUDGET, raw, root={"apiVersion": "2024-08-01"}
            )
            notifications = self.budget_fact(bundle)["notifications"]
            if count <= 5:
                self.assertEqual(len(notifications), count)
            else:
                self.assertEqual(
                    notifications,
                    {"unknown": "budget_notifications_missing_malformed_or_over_five"},
                )
        for field, value in (
            ("enabled", "true"),
            ("operator", "Unsupported"),
            ("thresholdType", "actual"),
        ):
            raw = self.budget_raw()
            next(iter(raw["notifications"].values()))[field] = value
            fact = configuration(raw, api_version="2024-08-01")
            self.assertTrue(any(isinstance(r[field], dict) for r in fact["notifications"]))
        for threshold in (-1, 0, 0.01, 1000, 1000.01, True, None, "[parameters('private')]"):
            raw = self.budget_raw()
            for notification in raw["notifications"].values():
                notification["threshold"] = threshold
                notification["enabled"] = False
            fact = configuration(raw, api_version="2024-08-01")
            self.assertTrue(all(r["enabled"] is False for r in fact["notifications"]))
            self.assertNotIn('threshold"', json.dumps(fact))
            self.assertNotIn(PRIVATE, json.dumps(fact))

    def test_budget_parent_scope_duplicates_and_different_budgets_are_not_combined(self):
        bundle = self.bundle()
        first = bundle["resources"][-1]
        first["properties"]["budgetConfiguration"]["notifications"] = [
            {"enabled": True, "operator": "GreaterThan", "thresholdType": "Actual"}
        ]
        second = copy.deepcopy(first)
        second["arm_id"] += "-second"
        second["logical_id"] += "-second"
        second["properties"]["budgetConfiguration"]["notifications"][0]["thresholdType"] = (
            "Forecasted"
        )
        bundle["resources"].append(second)
        context = self.context("E02.01", bundle)
        self.assertEqual(len(context["resources"]), 2)
        for row in context["resources"]:
            notifications = row["facts"]["budgetConfiguration"]["notifications"]
            self.assertEqual(len(notifications), 1)
            self.assertEqual(row["subchecks"], {})
        bundle["resources"][-1]["arm_id"] = first["arm_id"]
        with self.assertRaises(InputError):
            self.context("E02.01", bundle)
        bundle = self.bundle()
        bundle["resources"][-1]["arm_id"] = MG + "/providers/" + BUDGET + "/authored"
        bundle["scope"] = MG
        self.assertIn("unknown", self.context("E02.01", bundle)["resources"][0]["facts"])
        self.assertFalse(prepared_signal(self.control("E02.01"), bundle))

    def test_budget_raw_modules_plan_and_arm_preserve_source_version_and_privacy(self):
        values = {
            "name": "authored",
            "subscription_id": SCOPE,
            "resource_group_id": RG,
            "amount": PRIVATE,
            "time_grain": "Monthly",
            "notification": [
                {
                    "enabled": True,
                    "operator": "GreaterThan",
                    "threshold_type": mode,
                    "threshold": PRIVATE,
                    "contact_emails": [PRIVATE],
                }
                for mode in ("Actual", "Forecasted")
            ],
        }
        source = self.write(
            "budget-raw/main.tf.json",
            {"resource": {"azurerm_consumption_budget_resource_group": {"authored": values}}},
        )
        self.write("budget-parent/main.tf.json", {"module": {"budget": {"source": "./module"}}})
        self.write("budget-parent/module/main.tf.json", json.loads(source.read_text("utf-8")))
        planned = self.write(
            "budget-plan.json",
            {
                "format_version": "1.2",
                "planned_values": {
                    "root_module": {
                        "resources": [
                            {
                                "mode": "managed",
                                "type": "azurerm_consumption_budget_resource_group",
                                "address": "azurerm_consumption_budget_resource_group.authored",
                                "values": {**values, "id": BUDGET_ID},
                            }
                        ]
                    }
                },
            },
        )
        bundles = [
            terraform_source(source.parent, scope=RG, provider_version="4.50.0"),
            terraform_source(
                self.root / "budget-parent",
                scope=RG,
                provider_version="4.50.0",
                authorized_roots=[self.root],
            ),
            plan_source(planned, scope=RG, provider_version="4.50.0"),
        ]
        for bundle in bundles:
            fact = self.budget_fact(bundle)
            self.assertEqual(fact["apiVersion"], "2019-10-01")
            self.assertNotIn("Forecasted", json.dumps(fact))
            self.assertNotIn(PRIVATE, json.dumps(bundle))
        template = self.write(
            "budget-arm.json",
            {
                "resources": [
                    {
                        "type": "Microsoft.Consumption/budgets",
                        "apiVersion": "2024-08-01",
                        "name": "authored",
                        "properties": self.budget_raw(),
                    }
                ]
            },
        )
        bundle = arm_source(template, scope=RG)
        self.assertEqual(
            {r["thresholdType"] for r in self.budget_fact(bundle)["notifications"]},
            {"Actual", "Forecasted"},
        )
        self.assertNotIn(PRIVATE, json.dumps(bundle))
        self.assertNotIn(BUDGET, API_VERSIONS)
        self.assertEqual(PLANNED_API_VERSIONS[BUDGET], {"2024-08-01"})

    def test_budget_session_strips_injected_financial_fields_and_preserves_original_replay(self):
        bundle = self.bundle()
        bundle["resources"][-1]["properties"].update(self.budget_raw())
        session = ReviewSession(
            bundle,
            self.catalog,
            self.root / "budget-session",
            clock=lambda: AT,
            evidence_tiers=True,
        )
        for path in (session.directory / "revision-0000").rglob("*"):
            if path.is_file():
                self.assertNotIn(PRIVATE.encode(), path.read_bytes(), msg=path.name)
        self.assertEqual(session.evidence["collected_at"], AT)
        clean = sanitize_evidence(bundle)
        self.assertEqual(self.budget_fact(clean), self.budget_fact(bundle))
        self.assertNotIn(PRIVATE, json.dumps(clean))

    @unittest.skipUnless(os.environ.get("BICEP_COMPILER"), "No existing Bicep compiler supplied")
    def test_real_bicep_existing_budget_fixture_feeds_candidate_without_restore(self):
        self.catalog = load_catalog()
        bundle = arm_source(
            ROOT / "tests/fixtures/billing/main.bicep",
            scope=RG,
            bicep=True,
            compiler=os.environ["BICEP_COMPILER"],
        )
        fact = self.budget_fact(bundle)
        self.assertEqual(fact["apiVersion"], "2024-08-01")
        self.assertEqual(
            fact["notifications"],
            [{"enabled": True, "operator": "GreaterThan", "thresholdType": "Actual"}],
        )
        self.assertEqual(self.context("E02.01", bundle)["resources"][0]["subchecks"], {})
        report = assess(bundle, self.catalog, at=bundle["collected_at"], evidence_tiers=True)
        row = next(r for r in self.own(report) if r["upstream_id"] == "E02.01")
        self.assertEqual(row["planned"]["outcome"], "manual")
        self.assertNotEqual(row["planned"]["evidence_tier"], "verified")
