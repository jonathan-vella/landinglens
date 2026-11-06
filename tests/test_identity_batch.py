import copy
import hashlib
import json
import os
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from alz_assessor.arm import arm_source, properties
from alz_assessor.azure import Collector, Response
from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import control_digest, document
from alz_assessor.engine import assess
from alz_assessor.interviews import compile_interview, prepare_interview, question_bank
from alz_assessor.network_evidence import review_fact
from alz_assessor.plan import plan_source
from alz_assessor.replay import export_bundle, replay_bundle, semantic
from alz_assessor.reports import render, render_xlsx
from alz_assessor.review_session import ReviewSession
from alz_assessor.sources import terraform_source, tf_properties, tf_resource_id
from alz_assessor.terraform import InputError, tree_hash

SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/access"
STORAGE = SCOPE + "/providers/Microsoft.Storage/storageAccounts/store"
ROLE = SCOPE + "/providers/Microsoft.Authorization/roleAssignments/role"
DEFINITION = SCOPE + "/providers/Microsoft.Authorization/roleDefinitions/reader"
IDENTITY = SCOPE + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/workload"
SENTINEL = "PRIVATE-NOT-FOR-REPORTING"
AT = "2026-11-06T08:25:33Z"
GUIDS = (
    "348ef254-c27d-442e-abba-c7571559ab91",
    "4348bf81-7573-4512-8f46-9061cc198fea",
    "12e7f983-f630-4472-8dd6-9c5b5c2622f5",
    "4b69bad3-3aad-45e8-a68e-1d76667313b4",
    "53e8908a-e28c-484c-93b6-b7808b9fe5c4",
    "1049d403-a923-4c34-94d0-0018ac6a9e01",
    "e6a83de5-de32-4c19-a248-1607d5d1e4e6",
    "14658d35-58fd-4772-99b8-21112df27ee4",
)


class IdentityBatchTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.catalog = load_catalog()

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def identity(self):
        return {
            "type": "UserAssigned",
            "userAssignedIdentities": {IDENTITY: {"principalId": SENTINEL, "clientId": SENTINEL}},
            "principalId": SENTINEL,
            "tenantId": SENTINEL,
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
                {
                    "logical_id": STORAGE.lower(),
                    "arm_id": STORAGE.lower(),
                    "resource_type": "Microsoft.Storage/storageAccounts",
                    "state": "known",
                    "reason": "",
                    "source_location": "fixture://storage",
                    "properties": properties(
                        "Microsoft.Storage/storageAccounts", {}, root={"identity": self.identity()}
                    ),
                },
                {
                    "logical_id": ROLE.lower(),
                    "arm_id": ROLE.lower(),
                    "resource_type": "Microsoft.Authorization/roleAssignments",
                    "state": "known",
                    "reason": "",
                    "source_location": "fixture://assignment",
                    "properties": properties(
                        "Microsoft.Authorization/roleAssignments",
                        {
                            "principalType": "Group",
                            "roleDefinitionId": DEFINITION,
                            "principalId": SENTINEL,
                            "condition": SENTINEL,
                            "description": SENTINEL,
                        },
                    ),
                },
            ],
        )

    def test_exact_history_all_eight_guids_sources_and_unchanged_predicates(self):
        root = files("alz_assessor").joinpath("data")
        prior = root.joinpath("catalog-2026-11-06.2.json").read_bytes()
        self.assertEqual(
            hashlib.sha256(prior).hexdigest(),
            "674e9cfaae085ab079d92f8fdfceacd3c0af2b55a061185fb8750d1261168f4b",
        )
        old = {c["upstream_guid"]: c for c in json.loads(prior)["controls"]}
        matrix = json.loads(root.joinpath("batch-matrix-2026-11-06.3.json").read_text())
        batch, sources = matrix["batches"][-1], matrix["sources"][-1]["sources"]
        self.assertEqual(batch["batch"], "04")
        self.assertEqual({r["guid"] for r in batch["recommendations"]}, set(GUIDS))
        self.assertEqual(len(sources), 14)
        legacy = [r for r in sources if "/active-directory/" in r["url"]]
        self.assertEqual(len(legacy), 4)
        self.assertTrue(all("/entra/" in r["resolved_url"] for r in legacy))
        for control in self.catalog["controls"]:
            if control["upstream_guid"] not in GUIDS:
                self.assertEqual(
                    control_digest(control), control_digest(old[control["upstream_guid"]])
                )
            elif control["upstream_id"] == "B03.02":
                self.assertIsNone(control["rule"])
        self.assertEqual(sum(c["automation"] == "automated" for c in self.catalog["controls"]), 10)
        self.assertEqual(len(self.catalog["controls"]), 255)

    def test_minimal_identity_types_counts_privacy_and_no_adoption_claim(self):
        bundle = self.bundle()
        summary = bundle["resources"][0]["properties"]["identitySummary"]
        self.assertEqual(summary, {"type": "UserAssigned", "userAssignedCount": 1})
        self.assertNotIn(SENTINEL, json.dumps(bundle))
        self.assertNotIn(IDENTITY.lower(), json.dumps(bundle).lower())
        for value in (
            None,
            {},
            {"type": "UserAssigned", "userAssignedIdentities": []},
            {"type": True},
            {"type": "unknown"},
        ):
            props = properties("Microsoft.Storage/storageAccounts", {}, root={"identity": value})
            fact = review_fact(props, "identitySummary")
            self.assertTrue("unknown" in fact or isinstance(fact.get("userAssignedCount"), dict))
        for ids in ([IDENTITY, IDENTITY.upper()], [STORAGE], [None], ["alias"], [IDENTITY] * 101):
            props = tf_properties(
                "azurerm_storage_account",
                {"identity": [{"type": "UserAssigned", "identity_ids": ids}]},
            )
            self.assertIn("unknown", props["identitySummary"]["userAssignedCount"])
        for kind, count in (("None", 1), ("SystemAssigned", 1), ("UserAssigned", 0)):
            fact = review_fact(
                {"identitySummary": {"type": kind, "userAssignedCount": count}}, "identitySummary"
            )
            self.assertIn("unknown", fact)
        for count in (True, "1", 1.0, -1, 101):
            self.assertIn(
                "unknown",
                review_fact(
                    {"identitySummary": {"type": "UserAssigned", "userAssignedCount": count}},
                    "identitySummary",
                )["userAssignedCount"],
            )
        self.assertIn(
            "unknown",
            tf_properties(
                "azurerm_express_route_port",
                {"identity": [{"type": "SystemAssigned", "identity_ids": []}]},
            )["identitySummary"],
        )

    def test_assignment_type_definition_and_scope_are_not_effective_access(self):
        props = self.bundle()["resources"][1]["properties"]
        self.assertEqual(props, {"principalType": "Group", "roleDefinitionId": DEFINITION.lower()})
        for value in (None, True, {}, "MSA", "Member"):
            self.assertIn(
                "unknown",
                properties("Microsoft.Authorization/roleAssignments", {"principalType": value})[
                    "principalType"
                ],
            )
        for value in (None, IDENTITY, "Reader", {}, True):
            self.assertIn(
                "unknown",
                properties("Microsoft.Authorization/roleAssignments", {"roleDefinitionId": value})[
                    "roleDefinitionId"
                ],
            )
        for scope in (SCOPE, SCOPE + "/providers/Microsoft.Storage/storageAccounts/store"):
            result = tf_resource_id(
                SCOPE, "azurerm_role_assignment", {"scope": scope, "name": "role"}
            )
            self.assertTrue(
                result.endswith("/providers/microsoft.authorization/roleassignments/role")
            )
        for scope in ("/subscriptions/00000000-0000-0000-0000-000000000002", None, "alias"):
            self.assertIsNone(
                tf_resource_id(SCOPE, "azurerm_role_assignment", {"scope": scope, "name": "role"})
            )

    def test_source_specific_grouped_interview_keeps_duplicate_ids_and_blank_decisions(self):
        report = assess(self.bundle(), self.catalog, at=AT, evidence_tiers=True)
        prepared = prepare_interview(report, self.catalog, "access-operating-model", SCOPE)
        self.assertEqual(len(prepared["decisions"]), 8)
        self.assertEqual(
            {d["control_id"] for d in prepared["decisions"]}, {"ALZ-" + guid for guid in GUIDS}
        )
        for field in ("answer", "reviewer", "rationale", "evidence", "valid_from", "valid_until"):
            self.assertIsNone(prepared[field])
        self.assertTrue(all(d["outcome"] is None for d in prepared["decisions"]))
        with self.assertRaises(InputError):
            compile_interview(prepared, self.catalog, at=AT)
        with self.assertRaises(InputError):
            prepare_interview(report, self.catalog, "access-operating-model", SCOPE, ["B03.02"])
        question = next(
            q
            for q in question_bank(self.catalog)["questions"]
            if q["id"] == "access-operating-model"
        )
        self.assertIn("report-only", json.dumps(question))
        self.assertEqual(
            ReviewSession(self.bundle(), self.catalog, self.root / "session").state()["records"], []
        )

    def completed_interview(self):
        report = assess(self.bundle(), self.catalog, at=AT, evidence_tiers=True)
        prepared = prepare_interview(report, self.catalog, "access-operating-model", SCOPE)
        prepared.update(
            answer="Authored fixture: explicit separate decisions below.",
            reviewer="Fixture reviewer",
            rationale="Source-bound authored workflow only.",
            evidence="https://example.invalid/redacted-fixture",
            valid_from=AT,
            valid_until="2026-11-07T08:25:33Z",
        )
        for index, decision in enumerate(prepared["decisions"]):
            decision["outcome"] = "pass" if index % 2 else "fail"
        return prepared

    def test_bound_decisions_expiry_content_scope_and_no_verified_enforcement(self):
        completed = self.completed_interview()
        reviews = compile_interview(completed, self.catalog, at=AT)
        report = assess(self.bundle(), self.catalog, at=AT, evidence_tiers=True, manual=reviews)
        for guid in GUIDS:
            row = next(r for r in report["results"] if r["control_id"] == "ALZ-" + guid)
            self.assertIn(row["observed"]["outcome"], {"pass", "fail"})
            self.assertNotEqual(row["observed"]["evidence_tier"], "verified")
        for field, value in (
            ("catalog_sha256", "0" * 64),
            ("bank_version", "old"),
            ("scope", "alias"),
            ("answer", ""),
            ("reviewer", None),
            ("valid_until", "2000-01-01T00:00:00Z"),
        ):
            altered = copy.deepcopy(completed)
            altered[field] = value
            with self.assertRaises(InputError):
                compile_interview(altered, self.catalog, at=AT)
        altered = copy.deepcopy(completed)
        altered["decisions"][1]["outcome"] = None
        with self.assertRaises(InputError):
            compile_interview(altered, self.catalog, at=AT)
        altered = copy.deepcopy(completed)
        altered["decisions"][1]["control_id"] = altered["decisions"][0]["control_id"]
        with self.assertRaises(InputError):
            compile_interview(altered, self.catalog, at=AT)

    def test_tiers_all_exports_original_time_replay_no_personal_records(self):
        bundle = self.bundle()
        report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        self.assertEqual(report["evidence_tiers"]["counts"]["verified"], 0)
        for format in ("json", "markdown", "html", "csv", "sarif", "pr-summary"):
            self.assertNotIn(SENTINEL, render(report, format))
        self.assertTrue(render_xlsx(report).startswith(b"PK"))
        export_bundle(self.root / "replay", bundle, self.catalog, at=AT, evidence_tiers=True)
        replay = replay_bundle(self.root / "replay")
        self.assertEqual(semantic(replay), semantic(report))
        self.assertEqual(replay["evidence"][0]["collected_at"], AT)
        stale = copy.deepcopy(bundle)
        stale["collected_at"] = "2000-01-01T00:00:00Z"
        old = assess(stale, self.catalog, at=AT, evidence_tiers=True)
        self.assertEqual(old["evidence_tiers"]["counts"]["signal"], 0)

    def test_supplied_module_plan_sensitive_and_unsupported_configuration(self):
        values = {
            "azurerm_storage_account": {
                "name": "store",
                "resource_group_name": "access",
                "identity": [{"type": "UserAssigned", "identity_ids": [IDENTITY]}],
            },
            "azurerm_role_assignment": {
                "name": "role",
                "scope": SCOPE,
                "principal_type": "Group",
                "role_definition_id": DEFINITION,
                "principal_id": SENTINEL,
                "condition": SENTINEL,
            },
        }
        module = self.root / "snapshots" / "access"
        self.write(
            "snapshots/access/main.tf.json",
            {"resource": {kind: {"test": body} for kind, body in values.items()}},
        )
        self.write(
            "source/main.tf.json",
            {
                "module": {
                    "access": {"source": "example.invalid/alz/access/azurerm", "version": "1.0.0"}
                }
            },
        )
        manifest = self.write(
            "snapshots/snapshots.json",
            {
                "modules": [
                    {
                        "source": "example.invalid/alz/access/azurerm",
                        "version": "1.0.0",
                        "subdirectory": "",
                        "path": "access",
                        "sha256": tree_hash(module),
                    }
                ]
            },
        )
        path = self.write(
            "plan.json",
            {
                "format_version": "1.2",
                "planned_values": {
                    "root_module": {
                        "resources": [
                            {
                                "mode": "managed",
                                "type": kind,
                                "address": kind + ".test",
                                "values": {
                                    **body,
                                    "id": tf_resource_id(SCOPE, kind, body),
                                },
                            }
                            for kind, body in values.items()
                        ]
                    }
                },
            },
        )
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            raw = terraform_source(
                self.root / "source",
                scope=SCOPE,
                provider_version="4.50.0",
                snapshots=manifest,
                authorized_roots=[self.root],
            )
            planned = plan_source(path, scope=SCOPE, provider_version="4.50.0")
        for bundle in (raw, planned):
            self.assertNotIn(SENTINEL, json.dumps(bundle))
            by_type = {r["resource_type"].lower(): r for r in bundle["resources"]}
            self.assertEqual(
                by_type["microsoft.storage/storageaccounts"]["properties"]["identitySummary"][
                    "userAssignedCount"
                ],
                1,
            )
            self.assertEqual(
                by_type["microsoft.authorization/roleassignments"]["properties"]["principalType"],
                "Group",
            )
            self.assertEqual(
                by_type["microsoft.authorization/roleassignments"]["arm_id"], ROLE.lower()
            )
        doc = json.loads(path.read_text())
        doc["planned_values"]["root_module"]["resources"][0]["sensitive_values"] = {
            "identity": True
        }
        path.write_text(json.dumps(doc))
        hidden = plan_source(path, scope=SCOPE, provider_version="4.50.0")
        self.assertIn("unknown", hidden["resources"][0]["properties"]["identitySummary"])
        unsupported = plan_source(path, scope=SCOPE, provider_version="4.49.0")
        self.assertTrue(all(r["state"] == "unknown" for r in unsupported["resources"]))

    def test_injected_scoped_details_denied_and_no_directory_or_graph_call(self):
        details = [
            {
                "id": STORAGE,
                "type": "Microsoft.Storage/storageAccounts",
                "identity": self.identity(),
                "properties": {},
            },
            {
                "id": ROLE,
                "type": "Microsoft.Authorization/roleAssignments",
                "properties": {
                    "principalType": "Group",
                    "roleDefinitionId": DEFINITION,
                    "principalId": SENTINEL,
                    "condition": SENTINEL,
                },
            },
        ]
        requests = []

        def transport(method, url):
            requests.append((method, url))
            self.assertTrue(url.startswith("https://management.azure.com/"))
            if "/blobservices/default?" in url.lower():
                return Response(403, {}, {})
            if "/resources?" in url:
                return Response(
                    200, {"value": [{"id": r["id"], "type": r["type"]} for r in details]}, {}
                )
            for entry in details:
                if url.split("?")[0].lower().endswith(entry["id"].lower()):
                    self.assertEqual(method, "GET")
                    return Response(200, entry, {})
            return Response(200, {"value": []}, {})

        bundle = Collector(transport).collect(
            subscriptions=["00000000-0000-0000-0000-000000000001"], inventory_authorized=True
        )
        self.assertNotIn(SENTINEL, json.dumps(bundle))
        role = next(
            r for r in bundle["resources"] if r["resource_type"].lower().endswith("roleassignments")
        )
        self.assertEqual(role["properties"]["principalType"], "Group")
        self.assertTrue(any("api-version=2022-04-01" in url for _, url in requests))

        def denied(method, url):
            if "/roleassignments/" in url.lower():
                return Response(403, {}, {})
            return transport(method, url)

        bundle = Collector(denied).collect(
            subscriptions=["00000000-0000-0000-0000-000000000001"], inventory_authorized=True
        )
        role = next(
            r for r in bundle["resources"] if r["resource_type"].lower().endswith("roleassignments")
        )
        self.assertEqual(role["state"], "inaccessible")

    @unittest.skipUnless(os.environ.get("BICEP_COMPILER"), "Existing Bicep compiler unavailable")
    def test_real_bicep_storage_identity_role_context_without_restore(self):
        path = self.root / "main.bicep"
        path.write_text(
            f"""
resource store 'Microsoft.Storage/storageAccounts@2023-05-01' = {{
  name: 'store'
  location: 'westeurope'
  sku: {{ name: 'Standard_LRS' }}
  kind: 'StorageV2'
  identity: {{
    type: 'UserAssigned'
    userAssignedIdentities: {{ '{IDENTITY}': {{}} }}
  }}
}}
resource role 'Microsoft.Authorization/roleAssignments@2022-04-01' = {{
  name: '00000000-0000-0000-0000-000000000777'
  properties: {{
    principalType: 'Group'
    principalId: '00000000-0000-0000-0000-000000000888'
    roleDefinitionId: '{DEFINITION}'
  }}
}}
""",
            encoding="utf-8",
        )
        bundle = arm_source(path, scope=SCOPE, bicep=True, compiler=os.environ["BICEP_COMPILER"])
        props = {r["resource_type"].lower(): r["properties"] for r in bundle["resources"]}
        self.assertEqual(
            props["microsoft.storage/storageaccounts"]["identitySummary"]["userAssignedCount"], 1
        )
        self.assertEqual(props["microsoft.authorization/roleassignments"]["principalType"], "Group")
        self.assertNotIn("00000000-0000-0000-0000-000000000888", json.dumps(bundle))
