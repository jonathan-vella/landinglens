import contextlib
import copy
import io
import json
import os
import runpy
import tempfile
import unittest
import zipfile
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from alz_assessor import interviews
from alz_assessor.arm import API_VERSIONS, PLANNED_API_VERSIONS, arm_source, properties
from alz_assessor.catalog import load_catalog
from alz_assessor.cli import main
from alz_assessor.contracts import control_digest, digest, document, validate
from alz_assessor.engine import assess
from alz_assessor.interviews import compile_interview, prepare_interview
from alz_assessor.key_lifecycle_evidence import (
    FACTS,
    GUIDS,
    POLICY_GUID,
    STORAGE,
    VAULT,
    configuration_context,
    encryption_facts,
    resource_paths,
)
from alz_assessor.plan import plan_source
from alz_assessor.policy_strategy_evidence import ASSIGNMENT, DEFINITION, INITIATIVE, ROLE
from alz_assessor.replay import export_bundle, replay_bundle, sanitize_evidence, semantic
from alz_assessor.reports import render, render_xlsx
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import prepare_reviews, review_context, validate_reviews
from alz_assessor.sources import terraform_source, tf_properties
from alz_assessor.terraform import InputError
from alz_assessor.tiers import prepared_signal

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "references" / "recommendation-batches"
SUB = "/subscriptions/00000000-0000-0000-0000-000000000001"
SCOPE = SUB + "/resourcegroups/lifecycle"
VAULT_ID = SCOPE + "/providers/" + VAULT + "/authored"
STORAGE_ID = SCOPE + "/providers/" + STORAGE + "/authored"
DEFINITION_ID = SUB + "/providers/" + DEFINITION + "/authored"
ASSIGNMENT_ID = SUB + "/providers/" + ASSIGNMENT + "/authored"
AT = "2026-11-07T02:00:00Z"
UNTIL = "2026-11-08T02:00:00Z"
PRIVATE = "PRIVATE-KEY-CERTIFICATE-URI-ISSUER-PRINCIPAL-INCIDENT"
IDS = {"ALZ-" + guid for guid in GUIDS}
OWN = {
    "G01.01": "b86ad884-08e3-4727-94b8-75ba18f20459",
    "G01.02": "01365d38-e43f-49cc-ad86-8266abca264f",
    "G02.05": "6d70ba6c-97be-4995-8904-83845c986cb2",
    "G02.06": "913156a1-2476-4e49-b541-acdce979377b",
    "G02.09": "b12308ca-5017-4f15-9e3a-b3693829e7e3",
    "G02.10": "16183687-a047-47a2-8994-5bda43334f24",
    "G02.11": "b48ade7f-50be-4d2e-9866-d57b17942fc2",
    "G02.12": "25d62688-6d70-4ba6-a97b-e99519048384",
}


class KeyLifecyclePreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.matrix = json.loads((REFERENCE / "preparation-21.json").read_text("utf-8"))
        predecessor = files("alz_assessor").joinpath("data", "catalog-2026-11-06.24.json")
        self.accepted = load_catalog(str(predecessor)) if predecessor.is_file() else load_catalog()
        self.catalog = copy.deepcopy(self.accepted)
        rows = {r["guid"]: r for r in self.matrix["recommendations"]}
        for control in self.catalog["controls"]:
            if control["upstream_guid"] in rows:
                row = rows[control["upstream_guid"]]
                for key in ("evidence_requirements", "review_fact_paths", "review_resource_types"):
                    if key in row:
                        control[key] = copy.deepcopy(row[key])
                control["rationale"] = row["limitations"]
        validate(self.catalog, "catalog")
        question = self.matrix["interview"]
        self.question = question["id"]
        bank = patch.dict(
            interviews.BANK,
            {self.question: {k: question[k] for k in ("question", "controls")}},
        )
        bank.start()
        self.addCleanup(bank.stop)
        network = patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden"))
        network.start()
        self.addCleanup(network.stop)

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def control(self, display):
        return next(c for c in self.catalog["controls"] if c["upstream_id"] == display)

    def record(self, kind, identity, raw):
        return {
            "logical_id": identity.lower(),
            "arm_id": identity.lower(),
            "resource_type": kind,
            "state": "known",
            "reason": "",
            "source_location": "fixture://authored-key-lifecycle",
            "properties": properties(kind, raw, observed=True),
        }

    def bundle(self):
        return document(
            "evidence",
            schema_version="1.1",
            mode="observed",
            source="saved",
            collected_at=AT,
            scope=SUB,
            inventory_complete=False,
            artifact_hashes={"authored-fixture": "0" * 64},
            diagnostics=[],
            resources=[
                self.record(
                    VAULT,
                    VAULT_ID,
                    {
                        "enableRbacAuthorization": True,
                        "publicNetworkAccess": "Disabled",
                        "enablePurgeProtection": True,
                        "vaultUri": PRIVATE,
                        "accessPolicies": [{"objectId": PRIVATE}],
                        "certificates": [PRIVATE],
                        "rotationPolicy": PRIVATE,
                    },
                ),
                self.record(
                    STORAGE,
                    STORAGE_ID,
                    {
                        "encryption": {
                            "keySource": "Microsoft.Keyvault",
                            "requireInfrastructureEncryption": False,
                            "services": {
                                "queue": {"keyType": "Account"},
                                "table": {"keyType": "Service"},
                            },
                            "keyvaultproperties": {
                                "keyname": PRIVATE,
                                "keyvaulturi": PRIVATE,
                                "keyversion": PRIVATE,
                            },
                            "identity": {"userAssignedIdentity": PRIVATE},
                        }
                    },
                ),
                self.record(
                    DEFINITION,
                    DEFINITION_ID,
                    {
                        "policyType": "Custom",
                        "mode": "All",
                        "version": "1.2.3",
                        "policyRule": {
                            "if": {"field": PRIVATE},
                            "then": {"effect": "audit"},
                        },
                    },
                ),
                self.record(
                    ASSIGNMENT,
                    ASSIGNMENT_ID,
                    {
                        "policyDefinitionId": DEFINITION_ID,
                        "definitionVersion": "1.2.3",
                        "enforcementMode": "Default",
                        "notScopes": [],
                        "parameters": {},
                        "resourceSelectors": [],
                        "overrides": [],
                        "identity": {"principalId": PRIVATE},
                    },
                ),
            ],
        )

    def index(self, bundle):
        result = {}
        for resource in bundle["resources"]:
            result.setdefault((resource.get("arm_id") or "").lower(), []).append(resource)
        return result

    def context(self, resource, bundle, paths=None):
        return configuration_context(
            resource,
            self.index(bundle),
            bundle,
            paths or sorted(resource_paths(resource["resource_type"])),
        )

    def report(self, bundle=None, **kwargs):
        return assess(bundle or self.bundle(), self.catalog, at=AT, evidence_tiers=True, **kwargs)

    def completed(self):
        template = prepare_interview(self.report(), self.catalog, self.question, SUB)
        template.update(
            answer="Authored fixture, not an operating assurance.",
            reviewer="Authored fixture reviewer",
            rationale="Eight independent source-specific fixture decisions.",
            evidence="https://example.invalid/redacted",
            valid_from=AT,
            valid_until=UNTIL,
        )
        for decision, outcome in zip(
            template["decisions"],
            ("pass", "fail", "not_applicable", "fail", "pass", "fail", "not_applicable", "pass"),
            strict=True,
        ):
            decision["outcome"] = outcome
        return template

    def own(self, report):
        return [r for r in report["results"] if r["control_id"] in IDS]

    def test_exact_eight_fixed_targets_preparation_only_and_frozen_controls(self):
        targets = json.loads((REFERENCE / "targets.json").read_text("utf-8"))
        self.assertEqual(
            {r["upstream_id"]: r["guid"] for r in targets["targets"] if r["batch"] == "21"}, OWN
        )
        self.assertEqual(set(OWN.values()), GUIDS)
        self.assertEqual({r["upstream_id"]: r["guid"] for r in self.matrix["recommendations"]}, OWN)
        self.assertEqual(self.matrix["review_state"], "preparation-only-reviewed")
        self.assertNotIn("catalog_version", self.matrix)
        self.assertNotIn("accepted_at", self.matrix)
        self.assertEqual(self.accepted["catalog_version"], "2026-11-06.24")
        self.assertEqual(len(self.accepted["controls"]), 255)
        originals = {c["control_id"]: c for c in self.accepted["controls"]}
        for control in self.catalog["controls"]:
            before = originals[control["control_id"]]
            if control["control_id"] not in IDS:
                self.assertEqual(control_digest(control), control_digest(before))
            else:
                for key in ("recommendation", "references", "upstream_guid", "automation", "rule"):
                    self.assertEqual(control[key], before[key])
                self.assertIsNone(control["rule"])
                self.assertEqual(
                    before["evidence_requirements"],
                    [
                        "Scoped human review of linked recommendation, applicability "
                        "and supporting evidence"
                    ],
                )
        builder = runpy.run_path(str(ROOT / "tools" / "build_batches.py"), run_name="prep")
        with self.assertRaisesRegex(ValueError, "Preparation"):
            builder["apply_batch"](self.accepted, self.accepted, targets, self.matrix, [], [])
        capture = runpy.run_path(str(ROOT / "tools" / "review_batch_sources.py"), run_name="prep")
        with patch("sys.argv", ["review_batch_sources.py", "--batch", "21"]):
            with self.assertRaisesRegex(ValueError, "preparation-only"):
                capture["main"]()

    def test_reviewed_sources_exact_guidance_hashes_revisions_and_reuse(self):
        captured = json.loads((REFERENCE / "preparation-21-sources.json").read_text("utf-8"))
        self.assertEqual(captured["review_state"], "preparation-only-reviewed")
        sources = {r["id"]: r for r in captured["sources"]}
        self.assertGreaterEqual(len(sources), 27)
        self.assertEqual(len(sources), len(captured["sources"]))
        for source in sources.values():
            self.assertRegex(source["sha256"], "^[0-9a-f]{64}$")
            self.assertRegex(source["revision"], "^[0-9a-f]{40}$")
            self.assertTrue(source["retrieved_at"])
            self.assertIn("only", source["reuse"])
        for row in self.matrix["recommendations"]:
            original = self.control(row["upstream_id"])
            self.assertEqual(row["classification"], original["automation"])
            self.assertIn(
                original["references"][0]["guidance"], [sources[s]["url"] for s in row["sources"]]
            )
            self.assertEqual(len(row["evidence_requirements"]), 3)
        self.assertEqual(
            len({json.dumps(r["evidence_requirements"]) for r in self.matrix["recommendations"]}), 8
        )
        for source, marker in (
            ("vault-linked", "Redirects"),
            ("incident-linked", "Legacy"),
            ("certificate-renewal", "CSR/sign/merge"),
            ("key-rotation", "imported"),
            ("service-support-linked", "Managed HSM"),
            ("terraform-storage-encryption", "separate"),
            ("vault-object-types", "deprecated"),
        ):
            self.assertIn(marker.lower(), sources[source]["finding"].lower())

    def test_explicit_storage_key_source_and_queue_table_types_without_defaults(self):
        for source in ("Microsoft.Storage", "Microsoft.Keyvault"):
            facts = encryption_facts(
                {
                    "keySource": source,
                    "requireInfrastructureEncryption": False,
                    "queueKeyType": "Account",
                    "tableKeyType": "Service",
                    "keyvaulturi": PRIVATE,
                }
            )
            self.assertEqual(facts["keySource"], source)
            self.assertIs(facts["requireInfrastructureEncryption"], False)
            self.assertEqual(facts["queueKeyType"], "Account")
            self.assertEqual(facts["tableKeyType"], "Service")
            self.assertNotIn(PRIVATE, json.dumps(facts))
        for field, values in (
            ("keySource", (None, True, 0, PRIVATE, "Microsoft.KeyVault", "microsoft.storage")),
            ("requireInfrastructureEncryption", (None, "true", 1, PRIVATE)),
            ("queueKeyType", (None, True, PRIVATE, "account", "Customer")),
            ("tableKeyType", (None, 0, PRIVATE, "service", "Microsoft.Storage")),
        ):
            for value in values:
                facts = encryption_facts({field: value})
                self.assertIn("unknown", facts[field])
                self.assertNotIn(PRIVATE, json.dumps(facts))
        for invalid in (None, [], True, PRIVATE, {"unknown": PRIVATE}):
            self.assertIn("unknown", encryption_facts(invalid))
        self.assertTrue(all("unknown" in v for v in encryption_facts({}).values()))

    def test_arm_projection_minimizes_all_private_key_certificate_and_identity_fields(self):
        bundle = self.bundle()
        self.assertNotIn(PRIVATE, json.dumps(bundle))
        facts = bundle["resources"][1]["properties"]["storageEncryptionSummary"]
        self.assertEqual(
            set(facts),
            {"keySource", "requireInfrastructureEncryption", "queueKeyType", "tableKeyType"},
        )
        for row in bundle["resources"]:
            self.assertNotIn(PRIVATE, json.dumps(self.context(row, bundle)))
        self.assertIn(
            "unknown", self.context(bundle["resources"][1], bundle)["keyStoreRelationship"]
        )
        self.assertNotIn("unknown", self.context(bundle["resources"][0], bundle)["facts"])

    def test_terraform_inline_or_absent_cmk_never_infers_final_key_source(self):
        for cmk in (None, [], [{}], [None], [{PRIVATE: PRIVATE}], [{}, {}]):
            raw = {
                "infrastructure_encryption_enabled": True,
                "queue_encryption_key_type": "Account",
                "table_encryption_key_type": "Service",
            }
            if cmk is not None:
                raw["customer_managed_key"] = cmk
            facts = tf_properties("azurerm_storage_account", raw)["storageEncryptionSummary"]
            self.assertIn("unknown", facts["keySource"])
            self.assertIs(facts["requireInfrastructureEncryption"], True)
            self.assertEqual(facts["queueKeyType"], "Account")
            self.assertEqual(facts["tableKeyType"], "Service")
            self.assertNotIn(PRIVATE, json.dumps(facts))
        facts = tf_properties("azurerm_storage_account", {})["storageEncryptionSummary"]
        self.assertTrue(all("unknown" in v for v in facts.values()))

    def test_selected_scope_unique_known_type_and_top_level_guards(self):
        for mutation in ("missing", "duplicate", "denied", "outside", "no_scope", "type", "child"):
            bundle = self.bundle()
            row = bundle["resources"][1]
            if mutation == "missing":
                row["arm_id"] = None
            elif mutation == "duplicate":
                bundle["resources"].append(copy.deepcopy(row))
            elif mutation == "denied":
                row.update(state="error", reason="permission_denied")
            elif mutation == "outside":
                bundle["scope"] = SUB + "/resourcegroups/other"
            elif mutation == "no_scope":
                bundle["scope"] = None
            elif mutation == "type":
                row["resource_type"] = VAULT
            else:
                row["arm_id"] = STORAGE_ID + "/providers/" + STORAGE + "/nested"
            self.assertIn("unknown", self.context(row, bundle, ["storageEncryptionSummary"]))
        bundle = self.bundle()
        bundle["scope"] = SCOPE
        self.assertIn("facts", self.context(bundle["resources"][1], bundle))
        bundle["resources"][0]["resource_type"] = "microsoft.keyvault/managedhsms"
        self.assertFalse(prepared_signal(self.control("G02.05"), bundle))

    def test_over_bound_resources_and_wrong_kind_injected_facts_never_signal(self):
        bundle = self.bundle()
        row = bundle["resources"][1]
        bundle["resources"] = [
            {**copy.deepcopy(row), "logical_id": str(i), "arm_id": STORAGE_ID + str(i)}
            for i in range(101)
        ]
        context = review_context(self.control("G02.10"), bundle)
        self.assertTrue(context["truncated"])
        self.assertEqual(context["matching_resources"], 101)
        self.assertTrue(all("unknown" in r["facts"] for r in context["resources"]))
        self.assertFalse(prepared_signal(self.control("G02.10"), bundle))
        bundle["resources"].pop()
        self.assertTrue(prepared_signal(self.control("G02.10"), bundle))
        bundle = self.bundle()
        row = bundle["resources"][0]
        row["properties"]["storageEncryptionSummary"] = {"keySource": "Microsoft.Storage"}
        bundle["resources"] = [row]
        self.assertFalse(prepared_signal(self.control("G02.10"), bundle))
        self.assertEqual(review_context(self.control("G02.10"), bundle)["matching_resources"], 0)

    def test_policy_exact_supplied_join_uses_existing_interpreter_free_context(self):
        bundle = self.bundle()
        source = bundle["resources"][3]
        context = self.context(source, bundle)["suppliedPolicyConfiguration"]
        self.assertNotIn("unknown", context["definition"])
        self.assertEqual(context["definition"]["facts"]["literalEffect"], "audit")
        control = self.control("G02.09")
        self.assertEqual(control["upstream_guid"], POLICY_GUID)
        prepared = review_context(control, bundle)
        self.assertIn("supplied_policy_assignments", prepared)
        self.assertNotIn(PRIVATE, json.dumps(prepared))
        for mutation in ("missing", "duplicate", "denied", "version", "outside", "builtin"):
            changed = copy.deepcopy(bundle)
            definition, assignment = changed["resources"][2:4]
            if mutation == "missing":
                changed["resources"].remove(definition)
            elif mutation == "duplicate":
                changed["resources"].append(copy.deepcopy(definition))
            elif mutation == "denied":
                definition.update(state="error", reason="permission_denied")
            elif mutation == "version":
                definition["properties"]["policyDefinitionSummary"]["version"] = "1.2.4"
            elif mutation == "outside":
                changed["scope"] = SCOPE
            else:
                assignment["properties"]["policyAssignmentSummary"]["definitionId"] = (
                    "/providers/" + DEFINITION + "/authored"
                )
            result = self.context(assignment, changed)
            self.assertIn(
                "unknown",
                result
                if "unknown" in result
                else result["suppliedPolicyConfiguration"]["definition"],
            )

    def test_role_reference_not_effective_delegation_or_principal_retention(self):
        bundle = self.bundle()
        role = self.record(
            ROLE,
            SCOPE + "/providers/" + ROLE + "/00000000-0000-0000-0000-000000000002",
            {
                "roleDefinitionId": SUB + "/providers/microsoft.authorization/roledefinitions/"
                "36243c78-bf99-498c-9df9-86d9f8d28608",
                "principalType": "ServicePrincipal",
                "principalId": PRIVATE,
                "condition": PRIVATE,
            },
        )
        bundle["resources"].append(role)
        context = self.context(role, bundle)
        self.assertNotIn(PRIVATE, json.dumps(context))
        self.assertIn("unknown", context["suppliedPolicyConfiguration"]["delegation"])
        self.assertIn("effective delegation", context["warning"])
        self.assertIsNone(self.control("G02.09")["rule"])
        self.assertNotIn("pass", [r["observed"]["outcome"] for r in self.own(self.report(bundle))])

    def test_initiative_members_exact_versions_reused_and_no_fetch(self):
        bundle = self.bundle()
        identity = SUB + "/providers/" + INITIATIVE + "/authored"
        initiative = self.record(
            INITIATIVE,
            identity,
            {
                "policyType": "Custom",
                "version": "1.2.3",
                "policyDefinitions": [
                    {
                        "policyDefinitionId": DEFINITION_ID,
                        "definitionVersion": "1.2.3",
                        "policyDefinitionReferenceId": PRIVATE,
                    }
                ],
                "policyDefinitionGroups": [],
            },
        )
        bundle["resources"].append(initiative)
        context = self.context(initiative, bundle)
        self.assertNotIn("unknown", context["suppliedPolicyConfiguration"]["members"][0])
        self.assertNotIn(PRIVATE, json.dumps(context))
        bundle["resources"].remove(bundle["resources"][2])
        self.assertIn(
            "unknown", self.context(initiative, bundle)["suppliedPolicyConfiguration"]["members"][0]
        )

    def test_raw_terraform_local_module_and_plan_privacy_version_parity(self):
        root = self.root / "source"
        child = root / "lifecycle"
        child.mkdir(parents=True)
        (root / "main.tf").write_text('module "lifecycle" { source = "./lifecycle" }\n', "utf-8")
        (child / "main.tf").write_text(
            'resource "azurerm_storage_account" "authored" {\n'
            'name="authored"\nresource_group_name="lifecycle"\n'
            'infrastructure_encryption_enabled=false\nqueue_encryption_key_type="Account"\n'
            'table_encryption_key_type="Service"\n'
            f'customer_managed_key {{ key_vault_key_id="{PRIVATE}" }}\n}}\n',
            "utf-8",
        )
        raw = terraform_source(root, scope=SCOPE, provider_version="4.50.0")
        self.assertEqual(raw["mode"], "planned")
        self.assertNotIn(PRIVATE, json.dumps(raw))
        self.assertEqual(raw["resources"][0]["arm_id"], STORAGE_ID)
        values = {
            "name": "authored",
            "resource_group_name": "lifecycle",
            "infrastructure_encryption_enabled": False,
            "queue_encryption_key_type": "Account",
            "table_encryption_key_type": "Service",
            "customer_managed_key": [{"key_vault_key_id": PRIVATE}],
        }
        entry = {
            "mode": "managed",
            "type": "azurerm_storage_account",
            "address": "azurerm_storage_account.authored",
            "values": values,
        }
        plan = {
            "format_version": "1.2",
            "planned_values": {"root_module": {"resources": [entry]}},
        }
        path = self.write("plan.json", plan)
        planned = plan_source(path, scope=SCOPE, provider_version="4.50.0")
        self.assertEqual(
            raw["resources"][0]["properties"]["storageEncryptionSummary"],
            planned["resources"][0]["properties"]["storageEncryptionSummary"],
        )
        entry["sensitive_values"] = {"queue_encryption_key_type": True}
        sensitive = plan_source(
            self.write("sensitive.json", plan), scope=SCOPE, provider_version="4.50.0"
        )
        self.assertIn(
            "unknown",
            sensitive["resources"][0]["properties"]["storageEncryptionSummary"]["queueKeyType"],
        )
        values["id"] = STORAGE_ID + "conflict"
        with self.assertRaises(InputError):
            plan_source(self.write("conflict.json", plan), scope=SCOPE, provider_version="4.50.0")
        for version in (None, "4.49.0"):
            unsupported = terraform_source(root, scope=SCOPE, provider_version=version)
            self.assertEqual(unsupported["resources"][0]["state"], "unknown")
        unsupported = plan_source(path, scope=SCOPE, provider_version="4.49.0")
        self.assertEqual(unsupported["resources"][0]["state"], "unknown")

    def test_pinned_arm_storage_versions_no_registry_or_data_plane_expansion(self):
        self.assertEqual(PLANNED_API_VERSIONS[STORAGE], {"2023-05-01"})
        self.assertEqual(API_VERSIONS[STORAGE], {"2023-05-01"})
        for version in ("2023-05-01", "2099-01-01", None):
            resource = {
                "type": STORAGE,
                "name": "authored",
                "apiVersion": version,
                "properties": {
                    "encryption": {"keySource": "Microsoft.Storage", "keyvaultproperties": PRIVATE}
                },
            }
            bundle = arm_source(self.write("arm.json", {"resources": [resource]}), scope=SCOPE)
            self.assertEqual(
                bundle["resources"][0]["state"], "known" if version == "2023-05-01" else "unknown"
            )
            self.assertNotIn(PRIVATE, json.dumps(bundle))
        for kind in (VAULT + "/keys", VAULT + "/certificates", VAULT + "/secrets"):
            self.assertNotIn(kind, PLANNED_API_VERSIONS)
            self.assertNotIn(kind, API_VERSIONS)
            self.assertEqual(properties(kind, {"value": PRIVATE, "rotationPolicy": PRIVATE}), {})

    def test_eight_blank_independent_interviews_reviews_and_atomic_decisions(self):
        review = prepare_reviews(self.report(), self.catalog, sorted(IDS), SUB)
        self.assertEqual(len(review["entries"]), 8)
        for entry in review["entries"]:
            for key in (
                "reviewer",
                "outcome",
                "rationale",
                "evidence",
                "valid_from",
                "valid_until",
            ):
                self.assertIsNone(entry[key])
        template = prepare_interview(self.report(), self.catalog, self.question, SUB)
        self.assertEqual(len(template["decisions"]), 8)
        self.assertTrue(all(r["outcome"] is None for r in template["decisions"]))
        with self.assertRaises(InputError):
            compile_interview(template, self.catalog, at=AT)
        reviews = compile_interview(self.completed(), self.catalog, at=AT)
        validate_reviews(reviews, self.catalog, SUB, at=AT)
        self.assertEqual(len(reviews["entries"]), 8)
        self.assertEqual(len({r["outcome"] for r in reviews["entries"]}), 3)

    def test_interview_selection_catalog_requirements_time_expiry_attribution_guards(self):
        completed = self.completed()
        for key, value in (
            ("scope", SCOPE),
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
        for mutation in ("partial", "duplicate", "binding", "selection"):
            altered = copy.deepcopy(completed)
            if mutation == "partial":
                altered["decisions"][1]["outcome"] = None
            elif mutation == "duplicate":
                altered["decisions"].append(copy.deepcopy(altered["decisions"][0]))
            elif mutation == "binding":
                altered["decisions"][0]["control_sha256"] = "0" * 64
            else:
                altered["decisions"][0]["control_id"] = "ALZ-" + "0" * 36
            with self.assertRaises(InputError):
                compile_interview(altered, self.catalog, at=AT)
        control_id = self.control("G02.11")["control_id"]
        selected = prepare_interview(
            self.report(), self.catalog, self.question, SUB, selected=[control_id]
        )
        self.assertEqual([r["control_id"] for r in selected["decisions"]], [control_id])
        for invalid in ([], [control_id, control_id], ["ALZ-00000000-0000-0000-0000-000000000001"]):
            with self.assertRaises(InputError):
                prepare_interview(self.report(), self.catalog, self.question, SUB, selected=invalid)
        changed = copy.deepcopy(self.catalog)
        next(c for c in changed["controls"] if c["control_id"] == control_id)[
            "evidence_requirements"
        ].append("Changed requirement")
        with self.assertRaises(InputError):
            compile_interview(completed, changed, at=AT)

    def test_manual_assisted_tiers_stale_denied_unknown_never_verified(self):
        manual = {"G01.01", "G01.02", "G02.11", "G02.12"}
        for row in self.own(self.report()):
            self.assertNotEqual(row["observed"]["outcome"], "pass")
            self.assertEqual(
                row["observed"]["evidence_tier"],
                "manual" if row["upstream_id"] in manual else "signal",
            )
        for mutation in ("no_scope", "outside", "denied", "missing", "empty"):
            bundle = self.bundle()
            if mutation == "no_scope":
                bundle["scope"] = None
            elif mutation == "outside":
                bundle["scope"] = SUB + "/resourcegroups/other"
            elif mutation == "denied":
                for r in bundle["resources"]:
                    r.update(state="error", reason="permission_denied")
            elif mutation == "missing":
                for r in bundle["resources"]:
                    r["properties"] = {}
            else:
                bundle["resources"] = []
                bundle["inventory_complete"] = True
            for row in self.own(self.report(bundle)):
                self.assertEqual(
                    row["observed"]["evidence_tier"],
                    "manual" if row["upstream_id"] in manual else "needs_decision",
                )
                self.assertNotEqual(row["observed"]["outcome"], "pass")
        stale = assess(self.bundle(), self.catalog, at="2026-11-10T02:00:00Z", evidence_tiers=True)
        self.assertTrue(all(r["observed"]["evidence_tier"] != "signal" for r in self.own(stale)))

    def test_planned_observed_modes_and_partial_context_remain_distinct(self):
        bundle = self.bundle()
        bundle["mode"] = "planned"
        for row in self.own(self.report(bundle)):
            self.assertIsNone(row["observed"])
            self.assertNotEqual(row["planned"]["evidence_tier"], "verified")
        bundle = self.bundle()
        bundle["resources"] = [bundle["resources"][1]]
        bundle["resources"][0]["properties"]["storageEncryptionSummary"] = {
            "queueKeyType": "Service"
        }
        row = next(r for r in self.own(self.report(bundle)) if r["upstream_id"] == "G02.10")
        self.assertEqual(row["observed"]["evidence_tier"], "signal")
        self.assertNotEqual(row["observed"]["outcome"], "pass")
        context = review_context(self.control("G02.10"), bundle)["resources"][0]["facts"]
        self.assertIn("unknown", context["storageEncryptionSummary"]["keySource"])

    def test_all_outputs_trackers_human_confirmation_and_independent_exceptions(self):
        reviews = compile_interview(self.completed(), self.catalog, at=AT)
        report = self.report(manual=reviews)
        exceptions = document(
            "exceptions",
            schema_version="1.1",
            entries=[
                {**{k: v for k, v in e.items() if k != "outcome"}, "disposition": "accepted"}
                for e in reviews["entries"]
            ],
        )
        validate_reviews(exceptions, self.catalog, SUB, at=AT)
        excepted = self.report(exceptions=exceptions)
        for row in self.own(excepted):
            self.assertEqual(row["observed"]["exception_disposition"], "accepted")
            self.assertNotEqual(row["observed"]["reason"], "manual_attestation")
        for row in self.own(report):
            self.assertEqual(row["observed"]["reason"], "manual_attestation")
            self.assertNotEqual(row["observed"]["evidence_tier"], "verified")
        for format in ("json", "markdown", "html", "csv", "sarif", "pr-summary"):
            output = render(report, format)
            self.assertTrue(output)
            self.assertNotIn(PRIVATE, output)
            if format in {"json", "csv"}:
                for control in IDS:
                    self.assertIn(control, output)
        workbook = render_xlsx(report)
        with zipfile.ZipFile(io.BytesIO(workbook)) as archive:
            self.assertNotIn(
                PRIVATE.encode(), b"".join(archive.read(p) for p in archive.namelist())
            )

    def test_original_time_private_replay_parity_and_preparation_candidate_rejection(self):
        bundle = self.bundle()
        storage = bundle["resources"][1]["properties"]["storageEncryptionSummary"]
        storage.update(keyvaulturi=PRIVATE, keyversion=PRIVATE, identity=PRIVATE)
        sanitized = sanitize_evidence(bundle)
        self.assertNotIn(PRIVATE, json.dumps(sanitized))
        for display in OWN:
            control = self.control(display)
            self.assertEqual(review_context(control, bundle), review_context(control, sanitized))
        for name, catalog in (
            ("predecessor", self.accepted),
            (
                "historical",
                load_catalog(
                    str(files("alz_assessor").joinpath("data", "catalog-2026-11-06.23.json"))
                ),
            ),
        ):
            export_bundle(self.root / name, bundle, catalog, at=AT, evidence_tiers=True)
            self.assertEqual(
                semantic(replay_bundle(self.root / name)),
                semantic(assess(bundle, catalog, at=AT, evidence_tiers=True)),
            )
        with self.assertRaises(InputError):
            export_bundle(self.root / "candidate", bundle, self.catalog, at=AT, evidence_tiers=True)
        self.assertEqual(
            semantic(assess(bundle, self.accepted, at=AT, evidence_tiers=True)),
            semantic(assess(sanitized, self.accepted, at=AT, evidence_tiers=True)),
        )
        self.assertEqual(
            digest(self.accepted),
            digest(
                load_catalog(
                    str(files("alz_assessor").joinpath("data", "catalog-2026-11-06.24.json"))
                )
            ),
        )

    def test_cli_candidate_and_local_session_atomic_save_privacy(self):
        saved = self.write("saved.json", self.bundle())
        catalog = self.write("candidate.json", self.catalog)
        output = self.root / "report.json"
        with patch(
            "sys.argv",
            [
                "alz-assessor",
                "assess",
                str(saved),
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
        self.assertEqual(len(self.own(report)), 8)
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

    def test_real_bicep_storage_encryption_configuration_without_restore(self):
        compiler = os.environ.get("BICEP_COMPILER")
        if not compiler:
            self.skipTest("No existing compiler discovered; no acquisition attempted")
        bundle = arm_source(
            ROOT / "tests" / "fixtures" / "key-lifecycle" / "controls.bicep",
            scope=SCOPE,
            compiler=compiler,
            bicep=True,
        )
        self.assertEqual(len(bundle["resources"]), 1)
        row = bundle["resources"][0]
        self.assertEqual(row["state"], "known")
        self.assertEqual(row["arm_id"], STORAGE_ID)
        self.assertEqual(
            row["properties"]["storageEncryptionSummary"],
            {
                "keySource": "Microsoft.Storage",
                "requireInfrastructureEncryption": True,
                "queueKeyType": "Account",
                "tableKeyType": "Service",
            },
        )
        for result in self.own(
            assess(bundle, self.catalog, at=bundle["collected_at"], evidence_tiers=True)
        ):
            self.assertNotEqual(result["planned"]["evidence_tier"], "verified")
        self.assertEqual(set(FACTS), {VAULT, STORAGE, DEFINITION, INITIATIVE, ASSIGNMENT, ROLE})


if __name__ == "__main__":
    unittest.main()
