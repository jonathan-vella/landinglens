import copy
import hashlib
import json
import os
import tempfile
import unittest
import zipfile
from importlib.resources import files
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from alz_assessor.arm import API_VERSIONS, PLANNED_API_VERSIONS, Expressions, arm_source, properties
from alz_assessor.azure import Collector, Response
from alz_assessor.bicep import compile_bicep
from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import digest, document, validate
from alz_assessor.engine import assess
from alz_assessor.interviews import BANK, compile_interview, prepare_interview
from alz_assessor.plan import plan_source
from alz_assessor.replay import export_bundle, replay_bundle, sanitize_evidence, semantic
from alz_assessor.reports import render, render_xlsx
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import review_context
from alz_assessor.sources import TF_TYPES, terraform_source, tf_properties, tf_resource_id
from alz_assessor.tenant_evidence import (
    ASSIGNMENT,
    DEFINITION,
    GUIDS,
    VIEW,
    authorization_count,
    authorization_fact,
    cost_scope,
    definition_reference,
    resource_context,
    resource_parent,
    view_fact,
)
from alz_assessor.terraform import InputError, tree_hash
from alz_assessor.tiers import has_fact

ROOT = Path(__file__).resolve().parents[1]
PREPARATION = ROOT / "references" / "preparation"
SUB = "/subscriptions/00000000-0000-0000-0000-000000000001"
RG = SUB + "/resourcegroups/authored"
DEF_UUID = "11111111-1111-1111-1111-111111111111"
ASSIGN_UUID = "44444444-4444-4444-4444-444444444444"
DEF_ID = SUB + "/providers/" + DEFINITION + "/" + DEF_UUID
ASSIGN_ID = RG + "/providers/" + ASSIGNMENT + "/" + ASSIGN_UUID
VIEW_ID = RG + "/providers/" + VIEW + "/authored-view"
PRINCIPAL = "33333333-3333-3333-3333-333333333333"
TENANT = "22222222-2222-2222-2222-222222222222"
READER = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
AT = "2026-11-06T16:00:00Z"
UNTIL = "2026-11-07T16:00:00Z"
PRIVATE = "PRIVATE-NOT-FOR-REPORTING"
OWN = {
    "A01.01": "70c15989-c726-42c7-b0d3-24b7375b9201",
    "A01.02": "6309957b-821a-43d1-b9d9-7fcf1802b747",
    "A01.03": "78e11934-499a-45ed-8ef7-aae5578f0ecf",
    "A02.01": "5d82e6df-6f61-42f2-82e2-3132d293be3d",
    "A02.02": "a24d0de3-d4b9-4dfb-8ddd-bbfaf123fa01",
    "A02.03": "32952499-58c8-4e6f-ada5-972e67893d55",
    "A03.01": "685cb4f2-ac9c-4b19-9167-993ed0b32415",
    "A03.02": "12cd499f-96e2-4e41-a243-231fb3245a1c",
}


class TenantPreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def matrix(self):
        return json.loads((PREPARATION / "batch-02.json").read_text("utf-8"))

    def catalog(self):
        catalog = copy.deepcopy(load_catalog())
        rows = {r["guid"]: r for r in self.matrix()["recommendations"]}
        catalog["review_state"] = "authored-preparation-fixture-not-published"
        for control in catalog["controls"]:
            if control["upstream_guid"] not in rows:
                continue
            row = rows[control["upstream_guid"]]
            for key in ("review_resource_types", "review_fact_paths", "evidence_requirements"):
                if key in row:
                    control[key] = copy.deepcopy(row[key])
            control["rationale"] = row["limitations"]
        return validate(catalog, "catalog")

    def control(self, display):
        return next(c for c in self.catalog()["controls"] if c["upstream_id"] == display)

    def own(self, report):
        return [r for r in report["results"] if r["upstream_id"] in OWN]

    def definition(self):
        return {
            "authorizations": [
                {"principalId": PRINCIPAL, "roleDefinitionId": READER, "displayName": PRIVATE}
            ],
            "eligibleAuthorizations": [],
            "managedByTenantId": TENANT,
            "registrationDefinitionName": PRIVATE,
            "description": PRIVATE,
        }

    def view(self):
        return {
            "scope": RG,
            "chart": "Table",
            "metric": "ActualCost",
            "displayName": PRIVATE,
            "query": {"filter": PRIVATE, "values": PRIVATE, "amount": PRIVATE},
            "contact": PRIVATE,
            "billingAccount": PRIVATE,
        }

    def bundle(self):
        rows = [
            (DEFINITION, DEF_ID, self.definition()),
            (ASSIGNMENT, ASSIGN_ID, {"registrationDefinitionId": DEF_ID}),
            (VIEW, VIEW_ID, self.view()),
        ]
        return document(
            "evidence",
            schema_version="1.1",
            mode="observed",
            source="saved",
            scope=SUB,
            collected_at=AT,
            inventory_complete=False,
            artifact_hashes={"authored-fixture": "0" * 64},
            diagnostics=[],
            resources=[
                {
                    "logical_id": identity,
                    "arm_id": identity,
                    "resource_type": kind,
                    "state": "known",
                    "reason": "",
                    "source_location": "fixture://authored-tenant",
                    "properties": properties(kind, values),
                }
                for kind, identity, values in rows
            ],
        )

    def context(self, bundle, index):
        by_id = {}
        for record in bundle["resources"]:
            by_id.setdefault((record.get("arm_id") or "").lower(), []).append(record)
        return resource_context(bundle["resources"][index], by_id, bundle)

    def tf_values(self):
        return {
            "azurerm_lighthouse_definition": {
                "name": PRIVATE,
                "scope": SUB,
                "lighthouse_definition_id": DEF_UUID,
                "managing_tenant_id": TENANT,
                "authorization": [{"principal_id": PRINCIPAL, "role_definition_id": READER}],
                "eligible_authorization": [],
            },
            "azurerm_lighthouse_assignment": {
                "name": ASSIGN_UUID,
                "scope": RG,
                "lighthouse_definition_id": DEF_ID,
            },
        }

    def plan(self):
        return {
            "format_version": "1.2",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "mode": "managed",
                            "address": kind + ".authored",
                            "type": kind,
                            "values": {
                                **values,
                                "id": DEF_ID if kind.endswith("definition") else ASSIGN_ID,
                            },
                        }
                        for kind, values in self.tf_values().items()
                    ]
                }
            },
        }

    def test_exact_eight_guids_reviewed_sources_and_preparation_only(self):
        targets = ROOT / "references" / "recommendation-batches" / "targets.json"
        rows = json.loads(targets.read_text("utf-8"))["targets"]
        self.assertEqual({r["upstream_id"]: r["guid"] for r in rows if r["batch"] == "02"}, OWN)
        self.assertEqual(set(OWN.values()), GUIDS)
        self.assertEqual(
            hashlib.sha256(targets.read_bytes()).hexdigest(),
            "582fe02feee03b50961e5548fa7551bbd3d8729fbcb68f51837d548e59eaa291",
        )
        matrix = self.matrix()
        self.assertEqual(matrix["review_state"], "source-reviewed-preparation-not-accepted")
        self.assertNotIn("catalog_version", matrix)
        self.assertNotIn("accepted_at", matrix)
        self.assertEqual({r["upstream_id"]: r["guid"] for r in matrix["recommendations"]}, OWN)
        sources = json.loads((PREPARATION / "batch-02-sources.json").read_text("utf-8"))
        self.assertEqual(sources["review_state"], "preparation-only-reviewed")
        self.assertEqual(len(sources["sources"]), 24)
        indexed = {s["id"]: s for s in sources["sources"]}
        for source in indexed.values():
            self.assertRegex(source["sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(source["revision"], r"^[0-9a-f]{40}$")
            self.assertTrue(source["reuse"])
            self.assertTrue(source["finding"])
            self.assertTrue(source["resolved_url"].startswith("https://"))
        for row in matrix["recommendations"]:
            self.assertTrue(set(row["sources"]) <= set(indexed))
            self.assertTrue(
                any(q.startswith("Reviewer decision:") for q in row["evidence_requirements"])
            )
            self.assertNotIn("rule", row)
            self.assertEqual(
                row["classification"],
                "manual" if row["upstream_id"] in {"A02.02", "A03.01"} else "assisted",
            )
        self.assertEqual(len(load_catalog()["controls"]), 255)
        predecessor = load_catalog(
            str(files("alz_assessor").joinpath("data", "catalog-2026-11-06.15.json"))
        )
        self.assertTrue(
            all(
                not c.get("review_fact_paths")
                for c in predecessor["controls"]
                if c["upstream_guid"] in GUIDS
            )
        )
        self.assertNotIn("interview", matrix)

    def test_authorization_pairs_minimized_not_people_roles_or_authority(self):
        summary = self.bundle()["resources"][0]["properties"]["lighthouseAuthorizationSummary"]
        self.assertEqual(summary, {"authorizationPairCount": 1, "eligiblePairCount": 0})
        self.assertEqual(authorization_fact({**summary, "private": PRIVATE}), summary)
        for raw in (
            None,
            {},
            [None],
            [],
            [{"principalId": PRINCIPAL}],
            [{"principalId": True, "roleDefinitionId": READER}],
        ):
            self.assertFalse(has_fact(authorization_count(raw, terraform=False, required=True)))
        pair = {"principalId": PRINCIPAL, "roleDefinitionId": READER}
        for raw in ([pair, pair], [pair] * 101, [{"unknown": "unresolved", **pair}]):
            self.assertFalse(has_fact(authorization_count(raw, terraform=False, required=True)))
        maximum = [
            {"principalId": f"{i:08x}-3333-3333-3333-333333333333", "roleDefinitionId": READER}
            for i in range(100)
        ]
        self.assertEqual(authorization_count(maximum, terraform=False, required=True), 100)
        self.assertEqual(authorization_count([], terraform=False, required=False), 0)
        missing = properties(DEFINITION, {"authorizations": [pair]})[
            "lighthouseAuthorizationSummary"
        ]
        self.assertIn("unknown", missing["eligiblePairCount"])
        self.assertIn(
            "unknown",
            authorization_fact({"authorizationPairCount": True})["authorizationPairCount"],
        )
        # A syntactically valid reference to an unsupported Owner role is not authority.
        pair["roleDefinitionId"] = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
        self.assertEqual(authorization_count([pair], terraform=False, required=True), 1)
        self.assertNotIn(PRINCIPAL, json.dumps(self.bundle()))
        self.assertNotIn(TENANT, json.dumps(self.bundle()))
        self.assertNotIn(PRIVATE, json.dumps(self.bundle()))

    def test_scope_and_reference_limits_do_not_invent_tenant_or_billing_resources(self):
        self.assertEqual(resource_parent(DEF_ID, DEFINITION), SUB)
        self.assertEqual(resource_parent(ASSIGN_ID, ASSIGNMENT), RG)
        self.assertEqual(definition_reference(DEF_ID.upper()), DEF_ID)
        for value in (None, True, "", RG, ASSIGN_ID, DEF_ID.replace(SUB, RG), DEF_ID + "/extra"):
            self.assertIn("unknown", definition_reference(value))
        for value in (
            None,
            True,
            "/",
            "/providers/microsoft.management/managementgroups/m",
            "/providers/microsoft.billing/billingaccounts/private",
        ):
            self.assertIn("unknown", cost_scope(value))
        self.assertEqual(cost_scope(SUB.removeprefix("/")), SUB)
        self.assertEqual(cost_scope(RG.upper()), RG)
        for kind in (DEFINITION, ASSIGNMENT, VIEW):
            self.assertNotIn(kind, API_VERSIONS)
            self.assertTrue(PLANNED_API_VERSIONS[kind])
        self.assertEqual(PLANNED_API_VERSIONS[VIEW], {"2019-11-01"})
        self.assertNotIn("azapi_resource", TF_TYPES)
        self.assertNotIn("azurerm_cost_management_view", TF_TYPES)

    def test_view_metadata_drops_queries_contacts_amounts_and_unsupported_enums(self):
        summary = self.bundle()["resources"][2]["properties"]["costViewSummary"]
        self.assertEqual(summary, {"scope": RG, "chart": "Table", "metric": "ActualCost"})
        self.assertEqual(view_fact({**summary, "query": PRIVATE}), summary)
        for key in ("chart", "metric", "scope"):
            for value in (None, True, {}, PRIVATE):
                result = view_fact({**summary, key: value})
                self.assertIn("unknown", result[key])
        self.assertIn("unknown", view_fact(None))
        self.assertFalse(has_fact(view_fact({})))
        self.assertNotIn(
            "costViewSummary", tf_properties("azurerm_cost_management_view", self.view())
        )

    def test_strict_known_join_requires_same_subscription_and_selected_scope(self):
        bundle = self.bundle()
        joined = self.context(bundle, 1)
        self.assertEqual(joined["definition_id"], DEF_ID)
        self.assertEqual(joined["lighthouseAuthorizationSummary"]["authorizationPairCount"], 1)
        for state in ("unknown", "inaccessible", "error"):
            changed = copy.deepcopy(bundle)
            changed["resources"][0]["state"] = state
            self.assertIn("unknown", self.context(changed, 1))
        for ref in (None, ASSIGN_ID, DEF_ID.replace(SUB, SUB[:-1] + "2")):
            changed = copy.deepcopy(bundle)
            changed["resources"][1]["properties"]["registrationDefinitionId"] = ref
            self.assertIn("unknown", self.context(changed, 1))
        changed = copy.deepcopy(bundle)
        changed["scope"] = RG
        self.assertIn("unknown", self.context(changed, 1))
        context = review_context(self.control("A01.03"), changed)
        self.assertIn("unknown", context["resources"][0]["tenant_configuration"])
        changed = copy.deepcopy(bundle)
        changed["resources"].append(copy.deepcopy(changed["resources"][0]))
        self.assertIn("unknown", self.context(changed, 1))
        with self.assertRaisesRegex(InputError, "Duplicate"):
            review_context(self.control("A01.03"), changed)
        changed = copy.deepcopy(bundle)
        changed["resources"][0]["resource_type"] = VIEW
        self.assertIn("unknown", self.context(changed, 1))
        with self.assertRaisesRegex(InputError, "type does not match"):
            review_context(self.control("A01.03"), changed)

    def test_view_scope_binding_unknown_denied_foreign_unbound_and_overbound(self):
        bundle = self.bundle()
        self.assertEqual(self.context(bundle, 2)["costViewSummary"]["scope"], RG)
        for value in (SUB, None, "/providers/microsoft.billing/billingaccounts/private"):
            changed = copy.deepcopy(bundle)
            changed["resources"][2]["properties"]["costViewSummary"]["scope"] = value
            self.assertIn("unknown", self.context(changed, 2))
        for state in ("unknown", "inaccessible"):
            changed = copy.deepcopy(bundle)
            changed["resources"][2]["state"] = state
            self.assertIn("unknown", self.context(changed, 2))
        for scope in (None, RG + "-other"):
            changed = copy.deepcopy(bundle)
            changed["scope"] = scope
            self.assertIn("unknown", self.context(changed, 2))
        changed = copy.deepcopy(bundle)
        changed["resources"][2]["arm_id"] = None
        self.assertIn("unknown", self.context(changed, 2))
        changed = copy.deepcopy(bundle)
        changed["resources"] = [
            {
                **copy.deepcopy(bundle["resources"][2]),
                "logical_id": f"view-{i}",
                "arm_id": VIEW_ID + f"-{i}",
            }
            for i in range(101)
        ]
        context = review_context(self.control("A02.03"), changed)
        self.assertTrue(context["truncated"])
        self.assertEqual(context["matching_resources"], 101)
        self.assertEqual(len(context["resources"]), 100)

    def test_existing_saved_management_edges_are_required_not_bare_scope_or_names(self):
        bundle = self.bundle()
        mg = "/providers/microsoft.management/managementgroups/authored"
        bundle["scope"] = mg
        self.assertIn("unknown", self.context(bundle, 1))
        bundle["metadata"] = {"relationships": [{"id": SUB, "parent": mg}]}
        self.assertEqual(self.context(bundle, 1)["definition_id"], DEF_ID)
        self.assertEqual(self.context(bundle, 2)["costViewSummary"]["scope"], RG)
        for resource in bundle["resources"]:
            resource["arm_id"] = resource["arm_id"].upper()
        self.assertEqual(self.context(bundle, 1)["definition_id"], DEF_ID)
        for edges in (
            [{"id": SUB, "parent": mg}] * 2,
            [{"id": SUB, "parent": mg + "-foreign"}],
            [{"id": RG, "parent": mg}],
        ):
            bundle["metadata"]["relationships"] = edges
            self.assertIn("unknown", self.context(bundle, 1))

    def test_arm_known_versions_unresolved_and_service_scope_restrictions(self):
        rows = [
            {
                "type": {
                    DEFINITION: "Microsoft.ManagedServices/registrationDefinitions",
                    ASSIGNMENT: "Microsoft.ManagedServices/registrationAssignments",
                    VIEW: "Microsoft.CostManagement/views",
                }[kind],
                "apiVersion": version,
                "name": name,
                "properties": values,
            }
            for kind, version, name, values in (
                (DEFINITION, "2022-10-01", DEF_UUID, self.definition()),
                (ASSIGNMENT, "2022-10-01", ASSIGN_UUID, {"registrationDefinitionId": DEF_ID}),
                (VIEW, "2019-11-01", "authored-view", {**self.view(), "scope": SUB}),
            )
        ]
        path = self.write("arm.json", {"resources": rows})
        bundle = arm_source(path, scope=SUB)
        self.assertEqual(self.context(bundle, 1)["definition_id"], DEF_ID)
        self.assertEqual(self.context(bundle, 2)["costViewSummary"]["scope"], SUB)
        self.assertNotIn(PRIVATE, json.dumps(bundle))
        self.assertNotIn(PRINCIPAL, json.dumps(bundle))
        self.assertNotIn(TENANT, json.dumps(bundle))
        rows[0]["apiVersion"] = "2099-01-01"
        bundle = arm_source(self.write("unknown.json", {"resources": rows}), scope=SUB)
        self.assertEqual(bundle["resources"][0]["state"], "unknown")
        self.assertIn("unknown", self.context(bundle, 1))
        rows[0]["apiVersion"] = "2022-10-01"
        rows[1]["condition"] = "[parameters('missing')]"
        bundle = arm_source(self.write("condition.json", {"resources": rows}), scope=SUB)
        self.assertEqual(bundle["resources"][1]["state"], "unknown")
        rows[1].pop("condition")
        wrong_scope = arm_source(self.write("rg.json", {"resources": rows}), scope=RG)
        self.assertIn("unknown", self.context(wrong_scope, 0))
        self.assertIn("unknown", self.context(wrong_scope, 1))
        mg = "/providers/microsoft.management/managementgroups/authored"
        wrong_scope = arm_source(path, scope=mg)
        self.assertTrue(all("unknown" in self.context(wrong_scope, i) for i in range(3)))

    def test_terraform_definition_identity_is_uuid_not_display_name(self):
        values = self.tf_values()
        definition, assignment = values.values()
        self.assertEqual(tf_resource_id(SUB, "azurerm_lighthouse_definition", definition), DEF_ID)
        self.assertEqual(
            tf_resource_id(SUB, "azurerm_lighthouse_assignment", assignment), ASSIGN_ID
        )
        for key, raw in (
            ("lighthouse_definition_id", None),
            ("scope", RG),
            ("scope", "/"),
            ("lighthouse_definition_id", PRIVATE),
        ):
            self.assertIsNone(
                tf_resource_id(SUB, "azurerm_lighthouse_definition", {**definition, key: raw})
            )
        self.assertIsNone(tf_resource_id(RG, "azurerm_lighthouse_definition", definition))
        self.assertIsNone(
            tf_resource_id(SUB, "azurerm_lighthouse_assignment", {**assignment, "name": None})
        )
        self.assertNotIn(
            PRIVATE, json.dumps(tf_properties("azurerm_lighthouse_definition", definition))
        )

    def test_compiled_subscription_reference_overload_is_local_literal_and_scope_bound(self):
        expression = (
            "[subscriptionResourceId('Microsoft.ManagedServices/registrationDefinitions', "
            f"'{DEF_UUID}')]"
        )
        self.assertEqual(Expressions({}, {}, SUB).value(expression), DEF_ID)
        self.assertEqual(Expressions({}, {}, RG).value(expression), DEF_ID)
        self.assertIn("unknown", Expressions({}, {}, None).value(expression))
        for value in (
            "[subscriptionResourceId('00000000-0000-0000-0000-000000000002', "
            f"'Microsoft.ManagedServices/registrationDefinitions', '{DEF_UUID}')]",
            "[subscriptionResourceId('Microsoft.ManagedServices/registrationDefinitions')]",
            "[subscriptionResourceId('Microsoft.ManagedServices/registrationDefinitions', "
            "parameters('missing'))]",
        ):
            self.assertIn("unknown", Expressions({}, {}, SUB).value(value))

    def test_raw_supplied_module_and_plan_use_same_minimized_projection(self):
        module = self.root / "module"
        module.mkdir()
        # JSON-form Terraform is also interpreted by the existing raw/supplied module adapter.
        self.write(
            "module/main.tf.json",
            {"resource": {k: {"authored": v} for k, v in self.tf_values().items()}},
        )
        self.write(
            "source/main.tf.json",
            {
                "module": {
                    "tenant": {"source": "example.invalid/tenant/azurerm", "version": "1.0.0"}
                }
            },
        )
        manifest = self.write(
            "snapshots.json",
            {
                "modules": [
                    {
                        "source": "example.invalid/tenant/azurerm",
                        "version": "1.0.0",
                        "subdirectory": "",
                        "path": "module",
                        "sha256": tree_hash(module),
                    }
                ]
            },
        )
        path = self.write("plan.json", self.plan())
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            raw = terraform_source(
                self.root / "source",
                scope=SUB,
                provider_version="4.50.0",
                snapshots=manifest,
                authorized_roots=[self.root],
            )
            planned = plan_source(path, scope=SUB, provider_version="4.50.0")
        for bundle in (raw, planned):
            self.assertEqual(len(bundle["resources"]), 2)
            self.assertTrue(all(r["arm_id"] for r in bundle["resources"]))
            self.assertNotIn(PRIVATE, json.dumps(bundle))
            self.assertNotIn(PRINCIPAL, json.dumps(bundle))
            self.assertNotIn(TENANT, json.dumps(bundle))
            self.assertEqual(self.context(bundle, 1)["definition_id"], DEF_ID)
        self.assertEqual(
            [r["properties"] for r in raw["resources"]],
            [r["properties"] for r in planned["resources"]],
        )

    def test_plan_conflicts_unverified_provider_and_sensitive_markers(self):
        for index, key, value in (
            (0, "scope", RG),
            (0, "lighthouse_definition_id", ASSIGN_UUID),
            (1, "scope", SUB),
            (1, "name", DEF_UUID),
            (1, "id", ASSIGN_ID.replace(SUB, SUB[:-1] + "2")),
        ):
            plan = self.plan()
            plan["planned_values"]["root_module"]["resources"][index]["values"][key] = value
            with self.assertRaises(InputError):
                plan_source(self.write("conflict.json", plan), scope=SUB, provider_version="4.50.0")
        path = self.write("plan.json", self.plan())
        bundle = plan_source(path, scope=SUB, provider_version="99.0.0")
        self.assertTrue(
            all(r["state"] == "unknown" and not r["properties"] for r in bundle["resources"])
        )
        plan = self.plan()
        plan["planned_values"]["root_module"]["resources"][0]["sensitive_values"] = {
            "authorization": True
        }
        bundle = plan_source(
            self.write("sensitive.json", plan), scope=SUB, provider_version="4.50.0"
        )
        self.assertFalse(
            has_fact(
                bundle["resources"][0]["properties"]["lighthouseAuthorizationSummary"][
                    "authorizationPairCount"
                ]
            )
        )
        self.assertNotIn(PRINCIPAL, json.dumps(bundle))

    def test_one_engine_tiers_reports_original_time_and_no_humanconfirmed_promotion(self):
        catalog, bundle = self.catalog(), self.bundle()
        report = assess(bundle, catalog, at=AT, evidence_tiers=True)
        own = self.own(report)
        self.assertEqual(len(own), 8)
        self.assertTrue(all(r["observed"]["outcome"] == "manual" for r in own))
        expected = {
            "A01.03": "signal",
            "A02.01": "signal",
            "A02.03": "signal",
            "A02.02": "manual",
            "A03.01": "manual",
        }
        self.assertEqual(
            {r["upstream_id"]: r["observed"]["evidence_tier"] for r in own},
            {key: expected.get(key, "needs_decision") for key in OWN},
        )
        self.assertEqual(sum(report["evidence_tiers"]["counts"].values()), 255)
        for format in ("json", "markdown", "html", "csv", "sarif", "pr-summary"):
            rendered = render(report, format)
            self.assertTrue(all(s not in rendered for s in (PRIVATE, PRINCIPAL, TENANT)))
        with zipfile.ZipFile(BytesIO(render_xlsx(report))) as archive:
            xml = "".join(archive.read(n).decode() for n in archive.namelist())
            self.assertTrue(all(s not in xml for s in (PRIVATE, PRINCIPAL, TENANT)))
        for at in ("2000-01-01T00:00:00Z", "2026-11-07T16:00:00Z"):
            changed = copy.deepcopy(bundle)
            changed["collected_at"] = at
            stale = self.own(assess(changed, catalog, at=AT, evidence_tiers=True))
            self.assertTrue(
                all(r["observed"]["evidence_tier"] not in {"verified", "signal"} for r in stale)
            )
        changed = copy.deepcopy(bundle)
        changed["resources"][0]["properties"].update(humanConfirmed=True, effectiveAccess=True)
        for scope in (RG, RG + "-other"):
            changed["scope"] = scope
            changed["resources"][1]["properties"]["humanConfirmed"] = True
            result = self.own(assess(changed, catalog, at=AT, evidence_tiers=True))
            self.assertTrue(all(r["observed"]["outcome"] != "pass" for r in result))
            self.assertTrue(
                all(
                    r["observed"]["evidence_tier"] != "signal"
                    for r in result
                    if r["upstream_id"] in {"A01.03", "A02.01"}
                )
            )
        changed = copy.deepcopy(bundle)
        changed["resources"][2]["properties"]["costViewSummary"] = {"scope": RG}
        result = self.own(assess(changed, catalog, at=AT, evidence_tiers=True))
        self.assertEqual(
            next(r for r in result if r["upstream_id"] == "A02.03")["observed"]["evidence_tier"],
            "needs_decision",
        )

    def test_blank_decisions_bind_content_scope_time_and_conditional_applicability(self):
        catalog, bundle = self.catalog(), self.bundle()
        report = assess(bundle, catalog, at=AT, evidence_tiers=True)
        question = "authored-tenant-fixture-not-registered"
        item = {
            "question": " ".join(
                q
                for row in self.matrix()["recommendations"]
                for q in row["evidence_requirements"]
                if q.startswith("Reviewer decision:")
            ),
            "controls": ["ALZ-" + guid for guid in OWN.values()],
        }
        before = copy.deepcopy(BANK)
        with patch.dict(BANK, {question: item}):
            response = prepare_interview(report, catalog, question, SUB)
            self.assertEqual(len(response["decisions"]), 8)
            self.assertTrue(all(d["outcome"] is None for d in response["decisions"]))
            self.assertTrue(
                all(
                    response[k] is None
                    for k in (
                        "answer",
                        "reviewer",
                        "rationale",
                        "evidence",
                        "valid_from",
                        "valid_until",
                    )
                )
            )
            with self.assertRaises(InputError):
                compile_interview(response, catalog, at=AT)
            filled = copy.deepcopy(response)
            filled.update(
                answer="Authored fixture, not owner approval.",
                reviewer="Fixture reviewer",
                rationale="Eight separate fixture decisions.",
                evidence="https://example.invalid/tenant",
                valid_from=AT,
                valid_until=UNTIL,
            )
            for decision in filled["decisions"]:
                decision["outcome"] = "fail"
                if decision["control_id"] == "ALZ-" + OWN["A02.02"]:
                    decision["outcome"] = "not_applicable"
            manual = compile_interview(filled, catalog, at=AT)
            result = self.own(assess(bundle, catalog, at=AT, manual=manual, evidence_tiers=True))
            self.assertEqual(
                next(r for r in result if r["upstream_id"] == "A02.02")["observed"]["outcome"],
                "not_applicable",
            )
            self.assertEqual(
                next(r for r in result if r["upstream_id"] == "A02.01")["observed"]["outcome"],
                "fail",
            )
            self.assertTrue(all(r["observed"]["evidence_tier"] != "verified" for r in result))
            for key, value in (
                ("scope", RG),
                ("requirements_sha256", "0" * 64),
                ("catalog_sha256", "0" * 64),
                ("valid_until", AT),
            ):
                with self.assertRaises(InputError):
                    compile_interview({**filled, key: value}, catalog, at=AT)
            changed = copy.deepcopy(filled)
            changed["decisions"][-1]["outcome"] = None
            with self.assertRaises(InputError):
                compile_interview(changed, catalog, at=AT)
            changed = copy.deepcopy(catalog)
            next(c for c in changed["controls"] if c["upstream_id"] == "A02.01")["rationale"] += (
                " Changed."
            )
            with self.assertRaises(InputError):
                compile_interview(filled, changed, at=AT)
        self.assertEqual(before, BANK)

    def test_local_session_save_and_independent_exception_do_not_change_configuration(self):
        bundle, catalog = self.bundle(), self.catalog()
        session = ReviewSession(
            bundle, catalog, self.root / "session", clock=lambda: AT, evidence_tiers=True
        )
        self.assertEqual(session.state()["records"], [])
        before = copy.deepcopy(session.report)
        payload = {
            "revision": 0,
            "control_id": "ALZ-" + OWN["A02.01"],
            "kind": "exceptions",
            "decision": "accepted",
            "reviewer": "Fixture",
            "evidence": "https://example.invalid/exception",
            "rationale": "Authored exception, not owner approval.",
            "valid_from": AT,
            "valid_until": UNTIL,
            "replace_existing": False,
        }
        session.save(payload)
        self.assertEqual(session.reviews["manual"]["entries"], [])
        row = next(r for r in self.own(session.report) if r["upstream_id"] == "A02.01")
        self.assertEqual(row["observed"]["outcome"], "manual")
        self.assertEqual(row["observed"]["exception_disposition"], "accepted")
        self.assertEqual(session.evidence, bundle)
        self.assertEqual(
            row["observed"]["fact"],
            next(r for r in self.own(before) if r["upstream_id"] == "A02.01")["observed"]["fact"],
        )
        session.save(
            {
                **payload,
                "revision": 1,
                "control_id": "ALZ-" + OWN["A03.01"],
                "kind": "manual",
                "decision": "fail",
            }
        )
        self.assertEqual(len(session.reviews["manual"]["entries"]), 1)
        self.assertEqual(len(session.reviews["exceptions"]["entries"]), 1)

    def test_privacy_replay_keeps_original_time_and_rejects_unaccepted_catalog(self):
        bundle, catalog = self.bundle(), self.catalog()
        with self.assertRaisesRegex(InputError, "differs from a packaged artifact"):
            export_bundle(self.root / "unaccepted", bundle, catalog, at=AT, evidence_tiers=True)
        projected = sanitize_evidence(bundle)
        self.assertEqual(projected["collected_at"], AT)
        for display in ("A01.03", "A02.01", "A02.03"):
            self.assertEqual(
                review_context(self.control(display), projected),
                review_context(self.control(display), bundle),
            )
        self.assertTrue(all(s not in json.dumps(projected) for s in (PRIVATE, PRINCIPAL, TENANT)))
        accepted = load_catalog()
        before = digest(accepted)
        export_bundle(self.root / "accepted", bundle, accepted, at=AT, evidence_tiers=True)
        replayed = replay_bundle(self.root / "accepted")
        self.assertEqual(
            semantic(replayed), semantic(assess(bundle, accepted, at=AT, evidence_tiers=True))
        )
        self.assertEqual(replayed["evidence"][0]["collected_at"], AT)
        self.assertEqual(digest(load_catalog()), before)

    def test_live_routes_and_permission_scopes_not_expanded(self):
        seen = []

        def transport(method, url, body=None):
            seen.append((method, url))
            if "/resources?" in url:
                return Response(200, {"value": [{"id": ASSIGN_ID, "type": ASSIGNMENT}]}, {})
            return Response(200, {"value": []}, {})

        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            bundle = Collector(transport).collect(
                subscriptions=[SUB.split("/")[2]], inventory_authorized=True
            )
        self.assertTrue(
            all(
                "managedservices" not in url.lower()
                and "costmanagement" not in url.lower()
                and "microsoft.billing" not in url.lower()
                for _, url in seen
            )
        )
        self.assertEqual(bundle["resources"][0]["properties"], {})

    @unittest.skipUnless(os.environ.get("BICEP_COMPILER"), "existing Bicep compiler not supplied")
    def test_real_bicep_tenant_configuration_without_restore(self):
        source = ROOT / "tests" / "fixtures" / "tenant" / "controls.bicep"
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            copied = self.root / "controls.bicep"
            copied.write_bytes(source.read_bytes())
            compiled = compile_bicep(copied, compiler=os.environ["BICEP_COMPILER"])
            bundle = arm_source(
                copied, scope=SUB, bicep=True, compiler=os.environ["BICEP_COMPILER"]
            )
        self.assertEqual(len(compiled["template"]["resources"]), 3)
        self.assertTrue(all(r["state"] == "known" for r in bundle["resources"]))
        self.assertEqual(self.context(bundle, 1)["definition_id"], DEF_ID)
        self.assertEqual(self.context(bundle, 2)["costViewSummary"]["scope"], SUB)
        self.assertTrue(all(s not in json.dumps(bundle) for s in (TENANT, PRINCIPAL)))
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), before)
        self.assertFalse(source.with_suffix(".json").exists())


if __name__ == "__main__":
    unittest.main()
