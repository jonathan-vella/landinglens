import copy
import hashlib
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
from alz_assessor.bicep import compile_bicep
from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import control_digest, document, validate
from alz_assessor.engine import assess
from alz_assessor.network_evidence import review_fact
from alz_assessor.plan import plan_source
from alz_assessor.policy_strategy_evidence import (
    ASSIGNMENT,
    DEFINITION,
    EFFECTS,
    GUIDS,
    INITIATIVE,
    KINDS,
    PATHS,
    ROLE,
    RPC,
    ancestry,
    configuration_context,
    exclusions,
    joined_definition,
    members,
    projected_properties,
    version,
)
from alz_assessor.replay import export_bundle, replay_bundle, sanitize_evidence, semantic
from alz_assessor.reports import render, render_xlsx
from alz_assessor.review_page import review_page
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import prepare_reviews, review_context
from alz_assessor.sources import terraform_source, tf_properties, tf_resource_id
from alz_assessor.terraform import InputError, tree_hash

ROOT = Path(__file__).resolve().parents[1]
SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
OTHER = "/subscriptions/00000000-0000-0000-0000-000000000002"
RG = SCOPE + "/resourcegroups/application"
AUTH = "/providers/microsoft.authorization/"
DEF = SCOPE + AUTH + "policydefinitions/custom"
SET = SCOPE + AUTH + "policysetdefinitions/grouped"
ASSIGN = RG + AUTH + "policyassignments/grouped"
ROLE_ID = RG + AUTH + "roleassignments/authored"
BUILTIN = AUTH + "policydefinitions/0a914e76-4921-4c19-b460-a2d36003525a"
MG = "/providers/microsoft.management/managementgroups/visible-not-tenant-root"
CHILD = "/providers/microsoft.management/managementgroups/not-a-designation"
PRIVATE = "PRIVATE-POLICY-RULE-PARAMETER-SELECTOR-PRINCIPAL"
AT = "2026-11-06T16:00:00Z"
CONTROLS = {"ALZ-" + guid for guid in GUIDS}
IDS = {
    "E01.01": "5c986cb2-9131-456a-8247-6e49f541acdc",
    "E01.03": "d8a2adb1-17d6-4326-af62-5ca44e5695f2",
    "E01.04": "223ace8c-b123-408c-a501-7f154e3ab369",
    "E01.05": "3829e7e3-1618-4368-9a04-77a209945bda",
    "E01.06": "43334f24-9116-4341-a2ba-527526944008",
    "E01.07": "be7d7e48-4327-46d8-adc0-55bcf619e8a1",
    "E01.08": "3f988795-25d6-4268-a6d7-0ba6c97be995",
    "E01.09": "19048384-5c98-46cb-8913-156a12476e49",
}


class PolicyStrategyPreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.matrix = json.loads(
            (ROOT / "references/recommendation-batches/preparation-27.json").read_text("utf-8")
        )
        self.catalog = copy.deepcopy(load_catalog())
        self.catalog["review_state"] = "authored-in-memory-fixture-not-accepted"
        rows = {row["guid"]: row for row in self.matrix["recommendations"]}
        for control in self.catalog["controls"]:
            if control["upstream_guid"] in rows:
                row = rows[control["upstream_guid"]]
                for key in ("review_resource_types", "review_fact_paths", "evidence_requirements"):
                    control[key] = row[key]
                control["rationale"] = row["limitations"]
        validate(self.catalog, "catalog")
        network = patch("socket.socket.connect", side_effect=AssertionError("network forbidden"))
        network.start()
        self.addCleanup(network.stop)

    def definition(self):
        return {
            "policyType": "Custom",
            "mode": "All",
            "version": "1.2.3",
            "displayName": PRIVATE,
            "description": PRIVATE,
            "metadata": {PRIVATE: PRIVATE},
            "parameters": {PRIVATE: {"defaultValue": PRIVATE}},
            "policyRule": {
                "if": {"field": PRIVATE, "equals": PRIVATE},
                "then": {"effect": "deny", "details": {PRIVATE: PRIVATE}},
            },
        }

    def initiative(self):
        return {
            "policyType": "Custom",
            "version": "1.2.3",
            "policyDefinitions": [
                {
                    "policyDefinitionId": DEF,
                    "policyDefinitionReferenceId": PRIVATE,
                    "definitionVersion": "1.2.3",
                    "parameters": {PRIVATE: PRIVATE},
                    "groupNames": [PRIVATE],
                }
            ],
            "policyDefinitionGroups": [{"name": PRIVATE, "additionalMetadataId": PRIVATE}],
            "metadata": {"category": PRIVATE},
        }

    def assignment(self):
        return {
            "policyDefinitionId": SET,
            "definitionVersion": "1.2.3",
            "enforcementMode": "Default",
            "notScopes": [RG + "/providers/microsoft.storage/storageaccounts/excluded"],
            "parameters": {PRIVATE: {"value": PRIVATE}},
            "resourceSelectors": [{"name": PRIVATE, "selectors": [{PRIVATE: PRIVATE}]}],
            "overrides": [{"kind": "policyEffect", "value": PRIVATE}],
            "identity": {"principalId": PRIVATE},
            "metadata": {PRIVATE: PRIVATE},
        }

    def record(self, kind, identity, raw):
        return {
            "logical_id": identity.lower(),
            "arm_id": identity.lower(),
            "resource_type": kind,
            "state": "known",
            "reason": "",
            "source_location": "fixture://authored-policy",
            "properties": properties(kind, raw),
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
                self.record(DEFINITION, DEF, self.definition()),
                self.record(INITIATIVE, SET, self.initiative()),
                self.record(ASSIGNMENT, ASSIGN, self.assignment()),
                self.record(
                    ROLE,
                    ROLE_ID,
                    {
                        "principalType": "Group",
                        "roleDefinitionId": SCOPE + AUTH + "roledefinitions/" + RPC,
                        "principalId": PRIVATE,
                        "condition": PRIVATE,
                    },
                ),
            ],
        )

    def by_id(self, bundle):
        result = {}
        for row in bundle["resources"]:
            result.setdefault((row.get("arm_id") or "").lower(), []).append(row)
        return result

    def context(self, upstream="E01.01", bundle=None):
        control = next(c for c in self.catalog["controls"] if c["upstream_id"] == upstream)
        return review_context(control, bundle or self.bundle())

    def joined(self, bundle=None, requested="1.2.3", target=RG, ref=DEF):
        bundle = bundle or self.bundle()
        return joined_definition(ref, requested, target, bundle, self.by_id(bundle))

    def test_exact_eight_guids_sources_and_no_accepted_activation(self):
        targets = ROOT / "references/recommendation-batches/targets.json"
        fixed = json.loads(targets.read_text("utf-8"))["targets"]
        self.assertEqual({t["upstream_id"]: t["guid"] for t in fixed if t["batch"] == "27"}, IDS)
        self.assertEqual(
            hashlib.sha256(targets.read_bytes()).hexdigest(),
            "582fe02feee03b50961e5548fa7551bbd3d8729fbcb68f51837d548e59eaa291",
        )
        self.assertEqual({r["upstream_id"]: r["guid"] for r in self.matrix["recommendations"]}, IDS)
        self.assertEqual(set(IDS.values()), GUIDS)
        self.assertNotIn("E01.02", IDS)
        self.assertNotIn("catalog_version", self.matrix)
        self.assertNotIn("accepted_at", self.matrix)
        self.assertEqual(self.matrix["review_state"], "preparation-only-not-accepted")
        self.assertNotIn(self.matrix["interview"]["id"], interviews.BANK)
        manifest = json.loads((targets.parent / "preparation-27-sources.json").read_text("utf-8"))
        sources = {s["id"]: s for s in manifest["sources"]}
        self.assertGreaterEqual(len(sources), 22)
        for source in sources.values():
            self.assertRegex(source["sha256"], "^[0-9a-f]{64}$")
            self.assertTrue(source["revision"])
            self.assertTrue(source["finding"])
            self.assertTrue(source["reuse"])
            self.assertTrue(source["resolved_url"].startswith("https://"))
        for row in self.matrix["recommendations"]:
            self.assertTrue(set(row["sources"]) <= set(sources))
            self.assertEqual(row["classification"], "assisted")
            self.assertNotIn("rule", row)
            self.assertTrue(row["evidence_requirements"][0].startswith("Reviewer decision:"))
            self.assertTrue(
                set(row["review_fact_paths"])
                <= PATHS | {"principalType", "roleDefinitionId", "managementParentId"}
            )
        accepted = load_catalog()
        self.assertEqual(len(accepted["controls"]), 255)
        for c in accepted["controls"]:
            if c["upstream_guid"] in GUIDS:
                self.assertNotIn("policyDefinitionSummary", c.get("review_fact_paths", []))
                context = review_context(c, self.bundle())
                self.assertNotIn("supplied_policy_assignments", context)
                self.assertNotIn("saved_management_hierarchy", context)
                self.assertNotIn("unbound_resources", context)

    def test_literal_effect_is_not_rule_evaluation_or_parameter_resolution(self):
        for effect in EFFECTS:
            raw = self.definition()
            raw["policyRule"]["then"]["effect"] = effect
            facts = properties(DEFINITION, raw)["policyDefinitionSummary"]
            self.assertEqual(facts["literalEffect"], effect)
            self.assertEqual(facts["mode"], "All")
            self.assertNotIn(PRIVATE, json.dumps(facts))
        for effect in (
            None,
            True,
            [],
            {"unknown": "denied"},
            "[parameters('effect')]",
            "Deny",
            PRIVATE,
        ):
            raw = self.definition()
            raw["policyRule"]["then"]["effect"] = effect
            self.assertIn(
                "unknown", properties(DEFINITION, raw)["policyDefinitionSummary"]["literalEffect"]
            )
        self.assertIn("unknown", properties(DEFINITION, {})["policyDefinitionSummary"]["mode"])
        self.assertEqual(projected_properties("unsupported", self.definition()), {})

    def test_version_gate_never_fabricates_effective_versions(self):
        for value in (
            None,
            True,
            "1.*.*",
            "1.2.*",
            "1.2.3-beta",
            "1.2",
            PRIVATE,
            {"unknown": "stale"},
        ):
            self.assertIn("unknown", version(value))
            self.assertIn("unknown", self.joined(requested=value))
        joined = self.joined()
        self.assertEqual(joined["definitionLocation"], SCOPE)
        self.assertEqual(joined["facts"]["literalEffect"], "deny")
        self.assertEqual(joined["ancestry"], "positive_supplied_path")
        self.assertEqual(self.joined(requested="1.2.4")["unknown"], "definition_version_mismatch")
        bundle = self.bundle()
        del bundle["resources"][0]["properties"]["policyDefinitionSummary"]["version"]
        self.assertIn("unknown", self.joined(bundle))

    def test_global_builtin_references_not_custom_placement_or_implicit_fetch(self):
        result = self.joined(ref=BUILTIN)
        self.assertEqual(result["definitionId"], BUILTIN)
        self.assertEqual(result["unknown"], "global_builtin_reference_not_fetched_or_bound")
        for ref in (
            BUILTIN + "/versions/1.2.3",
            AUTH + "policydefinitions/not-a-guid",
            RG + AUTH + "policydefinitions/custom",
            SCOPE + AUTH + "roledefinitions/" + RPC,
        ):
            self.assertIn("unknown", self.joined(ref=ref))
        bundle = self.bundle()
        bundle["resources"][0]["properties"]["policyDefinitionSummary"]["policyType"] = "BuiltIn"
        self.assertEqual(self.joined(bundle)["unknown"], "scoped_definition_not_explicit_custom")

    def test_strict_reference_type_scope_uniqueness_state_and_ancestry(self):
        for state in ("unknown", "inaccessible", "error", "absent"):
            bundle = self.bundle()
            bundle["resources"][0]["state"] = state
            bundle["resources"][0]["reason"] = "detail_denied"
            self.assertIn("unknown", self.joined(bundle))
        for mutate in ("duplicate", "missing", "out-of-scope", "wrong-type"):
            bundle = self.bundle()
            if mutate == "duplicate":
                bundle["resources"].append(copy.deepcopy(bundle["resources"][0]))
            elif mutate == "missing":
                del bundle["resources"][0]
            elif mutate == "out-of-scope":
                bundle["scope"] = RG
            else:
                bundle["resources"][0]["resource_type"] = ASSIGNMENT
            self.assertIn("unknown", self.joined(bundle))
        self.assertIn("unknown", self.joined(target=OTHER))
        bundle = self.bundle()
        bundle["resources"][0] = self.record(
            DEFINITION, RG + AUTH + "policydefinitions/invalid", self.definition()
        )
        self.assertEqual(
            self.joined(bundle, ref=RG + AUTH + "policydefinitions/invalid")["unknown"],
            "definition_location_not_management_group_or_subscription",
        )
        bundle["resources"] = [bundle["resources"][0]]
        report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        row = next(r for r in report["results"] if r["upstream_id"] == "E01.01")
        self.assertEqual(row["observed"]["evidence_tier"], "needs_decision")

    def test_positive_saved_hierarchy_not_names_missing_parent_or_tenant_root(self):
        bundle = self.bundle()
        bundle["scope"] = MG
        bundle["metadata"] = {
            "relationships": [{"id": CHILD, "parent": MG}, {"id": SCOPE, "parent": CHILD}]
        }
        mg_def = CHILD + AUTH + "policydefinitions/custom"
        bundle["resources"][0] = self.record(DEFINITION, mg_def, self.definition())
        self.assertIs(ancestry(CHILD, RG, bundle), True)
        self.assertEqual(self.joined(bundle, ref=mg_def)["definitionLocation"], CHILD)
        self.assertIn("not effective", self.joined(bundle, ref=mg_def)["warning"])
        for edges in (
            [],
            [{"id": SCOPE}],
            [{"id": SCOPE, "parent": CHILD}],
            [
                {"id": CHILD, "parent": MG},
                {"id": SCOPE, "parent": CHILD},
                {"id": SCOPE, "parent": MG},
            ],
            [{"id": CHILD, "parent": MG}, {"id": MG, "parent": CHILD}],
            [{"id": SCOPE, "parent": OTHER}],
        ):
            bundle["metadata"]["relationships"] = edges
            self.assertIn("unknown", self.joined(bundle, ref=mg_def))
        bundle["metadata"]["relationships"] = [
            {"id": SCOPE + str(i), "parent": MG} for i in range(101)
        ]
        self.assertIn("unknown", self.joined(bundle, ref=mg_def))

    def test_exclusion_bounds_and_literal_descendants_never_effective_exemptions(self):
        self.assertEqual(exclusions([]), [])
        self.assertEqual(exclusions([RG.upper()]), [RG])
        for entries in (
            None,
            False,
            [RG, RG.upper()],
            [PRIVATE],
            [RG] * 101,
            {"unknown": "denied"},
        ):
            self.assertIn("unknown", exclusions(entries))
        context = self.context("E01.05")
        assignment = next(r for r in context["resources"] if r["resource_type"] == ASSIGNMENT)
        config = assignment["policy_configuration"]
        self.assertEqual(config["configuredScope"], RG)
        self.assertIs(config["exclusions"][0]["withinAssignmentScope"], True)
        self.assertIn("unknown", config["savedExemptions"])
        bundle = self.bundle()
        facts = bundle["resources"][2]["properties"]["policyAssignmentSummary"]
        facts["notScopes"] = [OTHER]
        bundle["metadata"] = {
            "policy_exemptions": [
                {
                    "id": RG + AUTH + "policyexemptions/expired",
                    "assignment_id": ASSIGN,
                    "expires_on": "2026-11-05T00:00:00Z",
                    "description": PRIVATE,
                    "policyDefinitionReferenceIds": [PRIVATE],
                }
            ]
        }
        config = configuration_context(bundle["resources"][2], bundle, self.by_id(bundle))
        self.assertIn("unknown", config["exclusions"][0]["withinAssignmentScope"])
        self.assertEqual(config["savedExemptions"][0]["expires_on"], "2026-11-05T00:00:00Z")
        self.assertIn("unknown", config["exemptionCoverage"])
        self.assertNotIn(PRIVATE, json.dumps(config))

    def test_initiative_members_hash_labels_and_validate_exact_version_bindings(self):
        facts = properties(INITIATIVE, self.initiative())["policyInitiativeSummary"]
        self.assertEqual(len(facts["members"]), 1)
        self.assertEqual(facts["groupCount"], 1)
        self.assertNotIn(PRIVATE, json.dumps(facts))
        member = facts["members"][0]
        self.assertRegex(member["referenceSha256"], "^[0-9a-f]{64}$")
        for raw in (
            [],
            None,
            [None],
            [self.initiative()["policyDefinitions"][0]] * 2,
            [{"policyDefinitionId": DEF}],
            [{"policyDefinitionId": PRIVATE, "policyDefinitionReferenceId": "a"}],
            self.initiative()["policyDefinitions"] * 101,
        ):
            self.assertIn("unknown", members(raw))
        self.assertEqual(members(facts["members"], normalized=True), facts["members"])
        injected = copy.deepcopy(facts)
        injected["members"][0]["referenceSha256"] = PRIVATE
        self.assertIn(
            "unknown",
            review_fact({"policyInitiativeSummary": injected}, "policyInitiativeSummary")[
                "members"
            ],
        )
        prepared = next(r for r in self.context()["resources"] if r["resource_type"] == INITIATIVE)
        self.assertEqual(prepared["policy_configuration"]["members"][0]["definitionId"], DEF)

    def test_selector_override_and_enforcement_presence_not_inferred_defaults(self):
        expected = {"enforcementMode": "Default", "selectorCount": 1, "overrideCount": 1}
        facts = properties(ASSIGNMENT, self.assignment())["policyAssignmentSummary"]
        for key, value in expected.items():
            self.assertEqual(facts[key], value)
        empty = properties(ASSIGNMENT, {})["policyAssignmentSummary"]
        for value in empty.values():
            self.assertIn("unknown", value)
        for key in ("selectorCount", "overrideCount"):
            for value in (True, -1, 11, 1.0, PRIVATE):
                injected = copy.deepcopy(facts)
                injected[key] = value
                self.assertIn(
                    "unknown",
                    review_fact({"policyAssignmentSummary": injected}, "policyAssignmentSummary")[
                        key
                    ],
                )
        raw = self.assignment()
        raw.update(resourceSelectors=[{}] * 11, overrides=[{"unknown": "unresolved"}])
        facts = properties(ASSIGNMENT, raw)["policyAssignmentSummary"]
        self.assertIn("unknown", facts["selectorCount"])
        self.assertIn("unknown", facts["overrideCount"])

    def test_rpc_scope_reference_without_principal_or_effective_delegation(self):
        context = self.context("E01.08")
        self.assertEqual(context["matching_resources"], 1)
        row = context["resources"][0]
        self.assertEqual(row["facts"]["principalType"], "Group")
        config = row["policy_configuration"]
        self.assertIs(config["resourcePolicyContributorReference"], True)
        self.assertEqual(config["configuredScope"], RG)
        self.assertIn("unknown", config["delegation"])
        self.assertNotIn(PRIVATE, json.dumps(context))
        bundle = self.bundle()
        bundle["resources"][-1]["properties"]["roleDefinitionId"] = (
            SCOPE + AUTH + "roledefinitions/other"
        )
        self.assertIs(
            self.context("E01.08", bundle)["resources"][0]["policy_configuration"][
                "resourcePolicyContributorReference"
            ],
            False,
        )
        bundle["resources"][-1]["arm_id"] = OTHER + AUTH + "roleassignments/authored"
        self.assertEqual(self.context("E01.08", bundle)["unbound_resources"], 1)

    def test_over_bound_population_unknown_and_no_whole_pass_or_verified(self):
        bundle = self.bundle()
        bundle["resources"].extend(
            self.record(ASSIGNMENT, RG + AUTH + f"policyassignments/a{i}", self.assignment())
            for i in range(101)
        )
        context = self.context(bundle=bundle)
        self.assertTrue(context["truncated"])
        self.assertIn("unknown", context["supplied_policy_assignments"])
        self.assertEqual(
            context["resources"][0]["policy_configuration"]["unknown"],
            "policy_configuration_population_over_100",
        )
        for state in ("known", "unknown", "inaccessible", "error", "absent"):
            bundle = self.bundle()
            bundle["inventory_complete"] = state == "absent"
            for row in bundle["resources"]:
                row["state"] = state
                row["reason"] = "" if state == "known" else "detail_denied"
            report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
            rows = [r for r in report["results"] if r["control_id"] in CONTROLS]
            self.assertEqual(len(rows), 8)
            self.assertTrue(all(r["observed"]["outcome"] != "pass" for r in rows))
            self.assertTrue(all(r["observed"]["evidence_tier"] != "verified" for r in rows))
            prepared = prepare_reviews(report, self.catalog, sorted(CONTROLS), SCOPE)
            self.assertTrue(all(r["outcome"] is None for r in prepared["entries"]))
        bundle = self.bundle()
        bundle["scope"] = OTHER
        report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        self.assertTrue(
            all(
                r["observed"]["evidence_tier"] == "needs_decision"
                for r in report["results"]
                if r["control_id"] in CONTROLS
            )
        )

    def test_assignment_scope_counts_are_only_supplied_subset_not_root_limits(self):
        population = self.context("E01.09")["supplied_policy_assignments"]
        self.assertEqual(population["suppliedAssignmentCount"], 1)
        self.assertEqual(population["unresolvedAssignmentCount"], 0)
        self.assertEqual(
            population["byConfiguredScope"],
            [{"scope": RG, "assignmentCount": 1, "explicitExcludedScopeCount": 1}],
        )
        self.assertIn("unknown", population["coverage"])
        bundle = self.bundle()
        bundle["resources"].append(
            self.record(ASSIGNMENT, RG + AUTH + "policyassignments/unknown", {})
        )
        population = self.context("E01.09", bundle)["supplied_policy_assignments"]
        self.assertEqual(population["byConfiguredScope"][0]["assignmentCount"], 2)
        self.assertIn("unknown", population["byConfiguredScope"][0]["explicitExcludedScopeCount"])
        bundle["resources"][-1]["state"] = "inaccessible"
        bundle["resources"][-1]["reason"] = "detail_denied"
        self.assertEqual(
            self.context("E01.09", bundle)["supplied_policy_assignments"][
                "unresolvedAssignmentCount"
            ],
            1,
        )
        bundle["resources"] = []
        population = self.context("E01.09", bundle)["supplied_policy_assignments"]
        self.assertEqual(population["byConfiguredScope"], [])
        self.assertIn("unknown", population["coverage"])

    def test_raw_provider_module_optional_plan_and_json_privacy(self):
        root = self.root / "module"
        root.mkdir()
        (root / "main.tf").write_text(
            'resource "azurerm_policy_definition" "custom" {\nname="custom"\n'
            'policy_type="Custom"\nmode="All"\ndisplay_name="authored"\n'
            "policy_rule=" + json.dumps(json.dumps(self.definition()["policyRule"])) + "\n}\n"
            'resource "azurerm_subscription_policy_assignment" "bound" {\nname="bound"\n'
            f'subscription_id="{SCOPE}"\npolicy_definition_id="{DEF}"\n'
            "enforce=false\nnot_scopes=[]\n}\n"
        )
        raw = terraform_source(root, scope=SCOPE, provider_version="4.50.0")
        definition, assignment = raw["resources"]
        self.assertEqual(definition["arm_id"], DEF)
        self.assertEqual(
            definition["properties"]["policyDefinitionSummary"]["literalEffect"], "deny"
        )
        self.assertEqual(assignment["arm_id"], SCOPE + AUTH + "policyassignments/bound")
        self.assertEqual(
            assignment["properties"]["policyAssignmentSummary"]["enforcementMode"], "DoNotEnforce"
        )
        wrapper = self.root / "wrapper"
        wrapper.mkdir()
        (wrapper / "main.tf").write_text(
            'module "supplied" {\nsource="example.invalid/policy/azurerm"\nversion="1.0.0"\n}\n'
        )
        manifest = self.root / "snapshots.json"
        manifest.write_text(
            json.dumps(
                {
                    "modules": [
                        {
                            "source": "example.invalid/policy/azurerm",
                            "version": "1.0.0",
                            "subdirectory": "",
                            "path": "module",
                            "sha256": tree_hash(root),
                        }
                    ]
                }
            )
        )
        supplied = terraform_source(
            wrapper,
            scope=SCOPE,
            provider_version="4.50.0",
            snapshots=manifest,
            authorized_roots=[self.root],
        )
        self.assertEqual(
            [r["properties"] for r in supplied["resources"]],
            [r["properties"] for r in raw["resources"]],
        )
        path = self.root / "plan.json"
        path.write_text(
            json.dumps(
                {
                    "format_version": "1.2",
                    "terraform_version": "1.14.0",
                    "planned_values": {
                        "root_module": {
                            "resources": [
                                {
                                    "mode": "managed",
                                    "type": "azurerm_subscription_policy_assignment",
                                    "address": "azurerm_subscription_policy_assignment.bound",
                                    "values": {
                                        "name": "bound",
                                        "subscription_id": SCOPE,
                                        "policy_definition_id": DEF,
                                        "enforce": True,
                                        "not_scopes": [],
                                        "parameters": PRIVATE,
                                    },
                                    "sensitive_values": {"policy_definition_id": True},
                                }
                            ]
                        }
                    },
                }
            )
        )
        planned = plan_source(path, scope=SCOPE, provider_version="4.50.0")
        self.assertIn(
            "unknown",
            planned["resources"][0]["properties"]["policyAssignmentSummary"]["definitionId"],
        )
        self.assertNotIn(PRIVATE, json.dumps(planned))
        unverified = terraform_source(root, scope=SCOPE, provider_version="unreviewed")
        self.assertTrue(
            all(r["state"] == "unknown" and not r["properties"] for r in unverified["resources"])
        )
        for text in ('{"then":{"effect":"deny","effect":"audit"}}', "[]", PRIVATE, "x" * 100001):
            facts = tf_properties("azurerm_policy_definition", {"policy_rule": text})
            self.assertIn("unknown", facts["policyDefinitionSummary"]["literalEffect"])

    def test_provider_scopes_types_and_no_fabricated_management_group_initiative(self):
        self.assertEqual(
            tf_resource_id(SCOPE, "azurerm_policy_definition", {"name": "custom"}), DEF
        )
        for kind, values in (
            ("azurerm_policy_definition", {"name": "custom", "management_group_id": OTHER}),
            ("azurerm_policy_definition", {"name": "custom", "management_group_id": RG}),
            ("azurerm_policy_set_definition", {"name": "custom", "management_group_id": MG}),
            ("azurerm_subscription_policy_assignment", {"name": "a", "subscription_id": RG}),
            ("azurerm_resource_group_policy_assignment", {"name": "a", "resource_group_id": SCOPE}),
            (
                "azurerm_management_group_policy_assignment",
                {"name": "a", "management_group_id": SCOPE},
            ),
        ):
            self.assertIsNone(tf_resource_id(SCOPE, kind, values))
        self.assertEqual(
            tf_resource_id(
                MG,
                "azurerm_management_group_policy_assignment",
                {"name": "a", "management_group_id": MG},
            ),
            MG + AUTH + "policyassignments/a",
        )
        self.assertIsNone(tf_resource_id(MG, "azurerm_policy_definition", {"name": "custom"}))

    def test_optional_plan_cannot_revive_conflicting_or_unsupported_policy_binding(self):
        path = self.root / "plan.json"
        for kind, values in (
            (
                "azurerm_subscription_policy_assignment",
                {"name": "a", "subscription_id": RG, "id": RG + AUTH + "policyassignments/a"},
            ),
            (
                "azurerm_policy_set_definition",
                {
                    "name": "a",
                    "management_group_id": MG,
                    "id": SCOPE + AUTH + "policysetdefinitions/a",
                },
            ),
            (
                "azurerm_subscription_policy_assignment",
                {"name": "a", "subscription_id": SCOPE, "id": SCOPE + AUTH + "policyassignments/b"},
            ),
        ):
            path.write_text(
                json.dumps(
                    {
                        "format_version": "1.2",
                        "terraform_version": "1.14.0",
                        "planned_values": {
                            "root_module": {
                                "resources": [
                                    {
                                        "mode": "managed",
                                        "type": kind,
                                        "address": kind + ".authored",
                                        "values": values,
                                    }
                                ]
                            }
                        },
                    }
                )
            )
            with self.assertRaisesRegex(InputError, "Policy plan ID conflicts"):
                plan_source(path, scope=SCOPE, provider_version="4.50.0")

    def test_arm_supported_version_and_conditional_diagnostics_without_live_routes(self):
        for kind in KINDS:
            self.assertEqual(PLANNED_API_VERSIONS[kind], {"2023-04-01"})
            self.assertNotIn(kind, API_VERSIONS)
        template = self.root / "template.json"
        resources = [
            {
                "type": DEFINITION,
                "apiVersion": "2023-04-01",
                "name": "custom",
                "properties": self.definition(),
            },
            {
                "type": ASSIGNMENT,
                "apiVersion": "2023-04-01",
                "name": "unknown",
                "condition": "[parameters('condition')]",
                "properties": self.assignment(),
            },
            {
                "type": INITIATIVE,
                "apiVersion": "unsupported",
                "name": "unsupported",
                "properties": self.initiative(),
            },
        ]
        template.write_text(
            json.dumps(
                {
                    "parameters": {"condition": {"type": "bool"}},
                    "resources": resources,
                }
            )
        )
        bundle = arm_source(template, scope=SCOPE)
        self.assertEqual(bundle["resources"][0]["state"], "known")
        self.assertEqual([r["state"] for r in bundle["resources"][1:]], ["unknown", "unknown"])
        self.assertNotIn(PRIVATE, json.dumps(bundle))
        requests = []

        def transport(method, url):
            requests.append((method, url))
            if "/resources?" in url:
                return Response(200, {"value": [{"id": DEF, "type": DEFINITION}]}, {})
            return Response(200, {"value": []}, {})

        collected = Collector(transport).collect(
            subscriptions=[SCOPE.split("/")[2]], inventory_authorized=True
        )
        self.assertFalse(any("/policydefinitions/" in url.lower() for _, url in requests))
        self.assertTrue(all(not r["properties"] for r in collected["resources"]))
        self.assertTrue(all(r["api_version"] is None for r in collected["resources"]))

    def test_prepared_bank_binding_separate_decisions_reports_session_and_expiry(self):
        question = self.matrix["interview"]
        with patch.dict(
            interviews.BANK,
            {question["id"]: {"question": question["question"], "controls": question["controls"]}},
        ):
            report = assess(self.bundle(), self.catalog, at=AT, evidence_tiers=True)
            response = interviews.prepare_interview(report, self.catalog, question["id"], SCOPE)
            self.assertEqual(len(response["decisions"]), 8)
            self.assertTrue(all(r["outcome"] is None for r in response["decisions"]))
            with self.assertRaises(InputError):
                interviews.compile_interview(response, self.catalog, at=AT)
            response.update(
                answer="Authored fixture; not a real organization decision.",
                reviewer="Authored fixture reviewer",
                rationale="Eight independent fixture decisions.",
                evidence="https://example.invalid/redacted",
                valid_from=AT,
                valid_until="2026-11-07T16:00:00Z",
            )
            for i, decision in enumerate(response["decisions"]):
                decision["outcome"] = "fail" if i % 2 else "pass"
            manual = interviews.compile_interview(response, self.catalog, at=AT)
            changed = copy.deepcopy(response)
            changed["decisions"][0]["control_sha256"] = "0" * 64
            with self.assertRaises(InputError):
                interviews.compile_interview(changed, self.catalog, at=AT)
            with self.assertRaises(InputError):
                interviews.compile_interview(response, self.catalog, at="2026-11-08T16:00:00Z")
            exceptions = document(
                "exceptions",
                schema_version="1.1",
                entries=[
                    {k: v for k, v in manual["entries"][0].items() if k != "outcome"}
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
            self.assertTrue(
                any(r["observed"].get("exception_disposition") == "accepted" for r in rows)
            )
            for format in ("json", "markdown", "html", "csv", "sarif", "pr-summary"):
                self.assertNotIn(PRIVATE, render(report, format))
            with zipfile.ZipFile(io.BytesIO(render_xlsx(report))) as archive:
                self.assertNotIn(
                    PRIVATE, "".join(archive.read(p).decode() for p in archive.namelist())
                )
            session = ReviewSession(
                self.bundle(),
                self.catalog,
                self.root / "session",
                clock=lambda: AT,
                evidence_tiers=True,
            )
            state = session.state()
            self.assertIn(
                "highest appropriate", review_page(state, "fixture-token", "fixture-nonce")
            )
            self.assertEqual(
                len(
                    next(r for r in state["interviews"] if r["id"] == question["id"])["template"][
                        "decisions"
                    ]
                ),
                8,
            )
            session.save_interview({"revision": 0, "response": response, "replace_existing": []})
            self.assertEqual(len(session.state()["records"]), 8)
            resumed = ReviewSession.resume(
                session.directory / "revision-0001", self.root / "resumed", clock=lambda: AT
            )
            self.assertEqual(semantic(session.report), semantic(resumed.report))

    def test_projection_idempotence_review_content_binding_and_unaccepted_replay_guard(self):
        bundle = self.bundle()
        sanitized = sanitize_evidence(bundle)
        for before, after in zip(bundle["resources"], sanitized["resources"], strict=True):
            for path in PATHS:
                if path in before["properties"]:
                    self.assertEqual(
                        review_fact(before["properties"], path),
                        review_fact(after["properties"], path),
                    )
        self.assertEqual(
            semantic(assess(bundle, self.catalog, at=AT, evidence_tiers=True)),
            semantic(assess(sanitized, self.catalog, at=AT, evidence_tiers=True)),
        )
        self.assertNotIn(PRIVATE, json.dumps(sanitized))
        directory = self.root / "replay"
        with self.assertRaises(InputError):
            export_bundle(directory, bundle, self.catalog, at=AT, evidence_tiers=True)
        accepted = load_catalog()
        export_bundle(directory, bundle, accepted, at=AT, evidence_tiers=True)
        self.assertEqual(
            semantic(replay_bundle(directory)),
            semantic(assess(bundle, accepted, at=AT, evidence_tiers=True)),
        )
        control = next(c for c in self.catalog["controls"] if c["upstream_id"] == "E01.01")
        changed = copy.deepcopy(control)
        changed["evidence_requirements"].append("Changed review meaning")
        self.assertNotEqual(control_digest(control), control_digest(changed))

    def test_saved_policy_signals_and_query_signals_not_promoted_by_configuration(self):
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
        report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        self.assertTrue(
            all(
                r["observed"]["evidence_tier"] != "verified"
                for r in report["results"]
                if r["control_id"] in CONTROLS
            )
        )
        clean = sanitize_evidence(bundle)
        self.assertEqual(clean["metadata"]["policy_compliance"][0]["timestamp"], AT)
        self.assertNotIn(PRIVATE, json.dumps(clean))
        stale = assess(bundle, self.catalog, at="2027-01-01T00:00:00Z", evidence_tiers=True)
        self.assertTrue(
            all(
                r["observed"]["evidence_tier"] == "needs_decision"
                for r in stale["results"]
                if r["control_id"] in CONTROLS
            )
        )

    @unittest.skipUnless(os.environ.get("BICEP_COMPILER"), "No existing Bicep compiler supplied")
    def test_real_bicep_policy_strategy_without_restore(self):
        path = ROOT / "tests/fixtures/policy-strategy/main.bicep"
        compiled = compile_bicep(path, compiler=os.environ["BICEP_COMPILER"])
        self.assertEqual(len(compiled["template"]["resources"]), 3)
        bundle = arm_source(path, scope=SCOPE, bicep=True, compiler=os.environ["BICEP_COMPILER"])
        self.assertEqual(len(bundle["resources"]), 3)
        self.assertTrue(all(r["state"] == "known" for r in bundle["resources"]))
        self.assertEqual(
            bundle["resources"][0]["properties"]["policyDefinitionSummary"]["literalEffect"],
            "audit",
        )
        self.assertEqual(
            bundle["resources"][2]["properties"]["policyAssignmentSummary"]["enforcementMode"],
            "DoNotEnforce",
        )
