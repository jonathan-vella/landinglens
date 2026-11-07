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
from alz_assessor.recovery_evidence import (
    ASR_ITEM,
    ASSIGNMENT_TYPES,
    BACKUP_ITEM,
    BACKUP_VAULT,
    CATEGORIES,
    DATASTORES,
    DIAGNOSTIC,
    EXTENSION,
    FACTS,
    FAILOVER,
    GATEWAY,
    GUEST,
    GUIDS,
    ONBOARDING,
    PROFILE,
    REDUNDANCIES,
    SQL,
    STORAGE,
    STORAGE_CONFIG,
    VAULT,
    VM,
    WORKSPACE,
    backup_vault_facts,
    linked_context,
    review_fact,
    unique_known,
)
from alz_assessor.replay import export_bundle, replay_bundle, sanitize_evidence, semantic
from alz_assessor.reports import render, render_xlsx
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import prepare_reviews, review_context, validate_reviews
from alz_assessor.sources import TF_TYPES, terraform_source, tf_properties, tf_resource_id
from alz_assessor.terraform import InputError
from alz_assessor.tiers import prepared_signal

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "references" / "recommendation-batches"
SUB = "/subscriptions/00000000-0000-0000-0000-000000000001"
SCOPE = SUB + "/resourceGroups/recovery"
VAULT_ID = SCOPE + "/providers/Microsoft.RecoveryServices/vaults/authored"
VM_ID = SCOPE + "/providers/Microsoft.Compute/virtualMachines/authored"
SQL_ID = SCOPE + "/providers/Microsoft.Sql/servers/primary"
PROFILE_ID = SCOPE + "/providers/Microsoft.Cdn/profiles/authored"
WORKSPACE_ID = SCOPE + "/providers/Microsoft.OperationalInsights/workspaces/authored"
BACKUP_ID = VAULT_ID + "/backupFabrics/Azure/protectionContainers/authored/protectedItems/authored"
ASR_ID = (
    VAULT_ID + "/replicationFabrics/authored/replicationProtectionContainers/authored/"
    "replicationProtectedItems/authored"
)
AT = "2026-11-06T23:00:00Z"
UNTIL = "2026-11-07T23:00:00Z"
PRIVATE = "PRIVATE-BACKUP-GUEST-WAF-QUERY-KEY-PAYLOAD"
IDS = {"ALZ-" + guid for guid in GUIDS}


class RecoveryPreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.matrix = json.loads((REFERENCE / "preparation-26.json").read_text("utf-8"))
        predecessor = files("alz_assessor").joinpath("data", "catalog-2026-11-06.21.json")
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

    def record(self, kind, identity, raw=None, *, root=None):
        return {
            "logical_id": identity.lower(),
            "arm_id": identity.lower(),
            "resource_type": kind,
            "state": "known",
            "reason": "",
            "source_location": "fixture://authored-recovery",
            "properties": properties(kind, raw or {}, root=root, observed=True),
        }

    def bundle(self):
        backup_policy = VAULT_ID + "/backupPolicies/authored"
        asr_policy = VAULT_ID + "/replicationPolicies/authored"
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
                self.record(VAULT, VAULT_ID),
                self.record(VM, VM_ID),
                self.record(
                    STORAGE_CONFIG,
                    VAULT_ID + "/backupstorageconfig/vaultstorageconfig",
                    {"storageModelType": "ZoneRedundant", "crossRegionRestoreFlag": False},
                ),
                self.record(
                    BACKUP_VAULT,
                    SCOPE + "/providers/Microsoft.DataProtection/backupVaults/authored",
                    {
                        "storageSettings": [
                            {"datastoreType": "VaultStore", "type": "GeoRedundant"}
                        ],
                        "featureSettings": {"crossRegionRestoreSettings": {"state": "Enabled"}},
                        "securitySettings": {"encryptionSettings": {"keyUri": PRIVATE}},
                    },
                ),
                self.record(VAULT + "/backuppolicies", backup_policy),
                self.record(VAULT + "/replicationpolicies", asr_policy),
                self.record(
                    BACKUP_ITEM,
                    BACKUP_ID,
                    {
                        "protectedItemType": "Microsoft.Compute/virtualMachines",
                        "sourceResourceId": VM_ID,
                        "policyId": backup_policy,
                        "lastBackupStatus": PRIVATE,
                        "lastBackupTime": PRIVATE,
                    },
                ),
                self.record(
                    ASR_ITEM,
                    ASR_ID,
                    {
                        "policyId": asr_policy,
                        "providerSpecificDetails": {
                            "instanceType": "A2A",
                            "fabricObjectId": VM_ID,
                            "recoveryResourceGroupId": SCOPE,
                            "vmDisks": [PRIVATE],
                        },
                        "replicationHealth": PRIVATE,
                    },
                ),
                self.record("microsoft.resources/resourcegroups", SCOPE),
                self.record(
                    EXTENSION,
                    VM_ID + "/extensions/AzurePolicyforLinux",
                    {
                        "publisher": "Microsoft.GuestConfiguration",
                        "type": "ConfigurationForLinux",
                        "autoUpgradeMinorVersion": True,
                        "enableAutomaticUpgrade": False,
                        "settings": PRIVATE,
                        "protectedSettings": PRIVATE,
                        "instanceView": PRIVATE,
                    },
                ),
                self.record(
                    GUEST,
                    VM_ID + "/providers/Microsoft.GuestConfiguration/"
                    "guestConfigurationAssignments/authored",
                    {
                        "guestConfiguration": {
                            "assignmentType": "ApplyAndMonitor",
                            "contentUri": PRIVATE,
                            "configurationParameter": [PRIVATE],
                        },
                        "latestAssignmentReport": PRIVATE,
                    },
                ),
                self.record(SQL, SQL_ID),
                self.record(SQL, SQL_ID.replace("/primary", "/secondary")),
                self.record(SQL + "/databases", SQL_ID + "/databases/authored"),
                self.record(
                    FAILOVER,
                    SQL_ID + "/failoverGroups/authored",
                    {
                        "databases": [SQL_ID + "/databases/authored"],
                        "partnerServers": [{"id": SQL_ID.replace("/primary", "/secondary")}],
                        "readWriteEndpoint": {"failoverPolicy": "Manual"},
                        "connectionString": PRIVATE,
                    },
                ),
                self.record(PROFILE, PROFILE_ID, root={"sku": {"name": "Premium_AzureFrontDoor"}}),
                self.record(
                    DIAGNOSTIC,
                    PROFILE_ID + "/providers/Microsoft.Insights/diagnosticSettings/authored",
                    {
                        "workspaceId": WORKSPACE_ID,
                        "logs": [{"category": CATEGORIES[1], "enabled": True}],
                        "eventHubName": PRIVATE,
                        "privateLogPayload": PRIVATE,
                    },
                    root={"scope": PROFILE_ID},
                ),
                self.record(
                    WORKSPACE,
                    WORKSPACE_ID,
                    {"sku": {"name": "PerGB2018"}, "retentionInDays": 30},
                ),
                self.record(
                    ONBOARDING,
                    WORKSPACE_ID + "/providers/Microsoft.SecurityInsights/onboardingStates/default",
                    {"customerManagedKey": False},
                ),
            ],
        )

    def index(self, bundle):
        result = {}
        for row in bundle["resources"]:
            result.setdefault((row.get("arm_id") or "").lower(), []).append(row)
        return result

    def resource(self, bundle, kind):
        return next(r for r in bundle["resources"] if r["resource_type"].lower() == kind)

    def context(self, kind, bundle=None):
        bundle = bundle or self.bundle()
        return linked_context(self.resource(bundle, kind), bundle, self.index(bundle))

    def report(self, **kwargs):
        return assess(self.bundle(), self.catalog, at=AT, evidence_tiers=True, **kwargs)

    def completed(self):
        response = prepare_interview(self.report(), self.catalog, self.question, SCOPE)
        response.update(
            answer="Authored fixture: eight separate decisions, not a real assurance.",
            reviewer="Authored test reviewer",
            rationale="Independent test decisions only.",
            evidence="https://example.invalid/redacted",
            valid_from=AT,
            valid_until=UNTIL,
        )
        for row, outcome in zip(
            response["decisions"],
            ("pass", "fail", "not_applicable", "fail", "pass", "fail", "not_applicable", "pass"),
            strict=True,
        ):
            row["outcome"] = outcome
        return response

    def test_exact_eight_fixed_targets_preparation_only_and_frozen_predecessor(self):
        targets = json.loads((REFERENCE / "targets.json").read_text("utf-8"))
        self.assertEqual({r["guid"] for r in targets["targets"] if r["batch"] == "26"}, GUIDS)
        self.assertEqual({r["guid"] for r in self.matrix["recommendations"]}, GUIDS)
        self.assertEqual(len(GUIDS), 8)
        self.assertEqual(len(self.accepted["controls"]), 255)
        self.assertNotIn("catalog_version", self.matrix)
        self.assertNotIn("accepted_at", self.matrix)
        self.assertEqual(self.matrix["review_state"], "preparation-only-reviewed")
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
        with patch("sys.argv", ["review_batch_sources.py", "--batch", "26"]):
            with self.assertRaisesRegex(ValueError, "preparation-only"):
                capture["main"]()

    def test_actual_eight_guidance_captures_hashes_terms_and_current_source_discrepancies(self):
        capture = json.loads((REFERENCE / "preparation-26-sources.json").read_text("utf-8"))
        self.assertEqual(capture["review_state"], "preparation-only-reviewed")
        sources = {r["id"]: r for r in capture["sources"]}
        self.assertGreaterEqual(len(sources), 36)
        for source in sources.values():
            self.assertRegex(source["sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(source["revision"], r"^[0-9a-f]{40}$")
            self.assertTrue(source["retrieved_at"])
            self.assertIn("only", source["reuse"])
        for row in self.matrix["recommendations"]:
            original = self.control(row["upstream_id"])
            self.assertIn(
                original["references"][0]["guidance"], [sources[s]["url"] for s in row["sources"]]
            )
            self.assertEqual(len(row["evidence_requirements"]), 3)
            self.assertEqual(row["classification"], "assisted")
        self.assertEqual(
            len({json.dumps(r["evidence_requirements"]) for r in self.matrix["recommendations"]}), 8
        )
        for source, marker in (
            ("guest-linked", "November 2026"),
            ("guest-linked", "redirects"),
            ("recovery-vault-settings", "snapshot"),
            ("backup-vault-settings", "universal"),
            ("backup-center-linked", "legacy"),
            ("waf-sentinel", "unlike"),
            ("backup-vault-arm", "SnapshotStore"),
        ):
            self.assertIn(marker, sources[source]["finding"])

    def test_service_qualified_redundancy_explicit_enums_and_no_defaults(self):
        for redundancy in REDUNDANCIES:
            tf = tf_properties("azurerm_recovery_services_vault", {"storage_mode_type": redundancy})
            arm = properties(STORAGE_CONFIG, {"storageModelType": redundancy})
            self.assertEqual(tf["recoveryStorageSummary"]["storageModelType"], redundancy)
            self.assertEqual(tf, arm)
            for datastore in DATASTORES:
                facts = backup_vault_facts(
                    {"storageSettings": [{"datastoreType": datastore, "type": redundancy}]}
                )
                self.assertEqual(facts["storageSettings"][0]["type"], redundancy)
        for kind in ("azurerm_recovery_services_vault", "azurerm_data_protection_backup_vault"):
            facts = tf_properties(kind, {})
            self.assertNotIn("GeoRedundant", json.dumps(facts))
        arm_vault = properties(VAULT, {"storageModelType": "GeoRedundant"})
        self.assertIn("unknown", arm_vault["recoveryStorageSummary"])
        storage = tf_properties(
            "azurerm_storage_account",
            {"account_tier": "Standard", "account_replication_type": "GRS"},
        )
        self.assertNotIn("recoveryStorageSummary", storage)
        for value in (None, True, 1, PRIVATE, "GRS", "GeoRedundantExtra", []):
            facts = review_fact(
                {"recoveryStorageSummary": {"storageModelType": value}}, "recoveryStorageSummary"
            )
            self.assertIn("unknown", facts["storageModelType"])
            self.assertNotIn(PRIVATE, json.dumps(facts))

    def test_datastore_bounds_duplicates_wrong_shapes_and_stale_snapshotstore(self):
        for settings in (
            None,
            [],
            [None],
            [{}] * 4,
            [{"datastoreType": "VaultStore", "type": "GeoRedundant"}] * 2,
            [{"datastoreType": "SnapshotStore", "type": "GeoRedundant"}],
            [{"datastoreType": PRIVATE, "type": PRIVATE}],
            [{"datastoreType": {"unknown": PRIVATE}}],
        ):
            facts = backup_vault_facts({"storageSettings": settings})
            self.assertIn("unknown", facts["storageSettings"])
            self.assertNotIn(PRIVATE, json.dumps(facts))
        self.assertEqual(
            len(
                backup_vault_facts(
                    {
                        "storageSettings": [
                            {"datastoreType": d, "type": "ZoneRedundant"} for d in DATASTORES
                        ]
                    }
                )["storageSettings"]
            ),
            3,
        )
        tf = tf_properties(
            "azurerm_data_protection_backup_vault",
            {"datastore_type": "SnapshotStore", "redundancy": "GeoRedundant"},
        )
        self.assertIn("unknown", tf["backupVaultSummary"]["storageSettings"])

    def test_all_new_fact_shapes_and_payload_privacy(self):
        self.assertNotIn(PRIVATE, json.dumps(self.bundle()))
        for fn in FACTS.values():
            for value in (None, True, 1, [], PRIVATE, {"unknown": PRIVATE}):
                result = fn(value)
                self.assertIn("unknown", result)
                self.assertNotIn(PRIVATE, json.dumps(result))
        projected = sanitize_evidence(self.bundle())
        self.assertNotIn(PRIVATE, json.dumps(projected))
        self.assertEqual(projected["collected_at"], AT)
        twice = sanitize_evidence(projected)
        for left, right in zip(projected["resources"], twice["resources"], strict=True):
            self.assertEqual(left["properties"], right["properties"])

    def test_exact_backup_and_a2a_discriminators_no_health_or_success(self):
        for discriminator in (
            None,
            "AzureIaaSVMProtectedItem",
            "Microsoft.ClassicCompute/virtualMachines",
            PRIVATE,
        ):
            result = properties(
                BACKUP_ITEM,
                {
                    "protectedItemType": discriminator,
                    "sourceResourceId": VM_ID,
                    "policyId": VAULT_ID + "/backupPolicies/authored",
                },
            )
            self.assertIn("unknown", result["vmBackupSummary"])
        for discriminator in (None, "A2ACrossClusterMigration", "InMage", PRIVATE):
            result = properties(
                ASR_ITEM,
                {
                    "providerSpecificDetails": {
                        "instanceType": discriminator,
                        "fabricObjectId": VM_ID,
                    },
                    "policyId": VAULT_ID + "/replicationPolicies/authored",
                },
            )
            self.assertIn("unknown", result["a2aReplicationSummary"])
        for kind in (BACKUP_ITEM, ASR_ITEM):
            context = self.context(kind)
            self.assertEqual(context["sourceVm"]["arm_id"], VM_ID.lower())
            self.assertEqual(context["vault"]["arm_id"], VAULT_ID.lower())
            self.assertNotIn("unknown", context["policy"])
            self.assertIn("not complete protection", context["warning"])
        self.assertNotIn("lastBackupStatus", json.dumps(self.bundle()))
        self.assertNotIn("replicationHealth", json.dumps(self.bundle()))
        self.assertEqual(self.context(ASR_ITEM)["recoveryResourceGroup"]["arm_id"], SCOPE.lower())

    def test_relationships_missing_ambiguous_denied_wrong_type_outside_scope(self):
        for mutation in ("missing", "duplicate", "denied", "wrong_type", "outside"):
            bundle = self.bundle()
            vm = self.resource(bundle, VM)
            if mutation == "missing":
                bundle["resources"].remove(vm)
            elif mutation == "duplicate":
                bundle["resources"].append(copy.deepcopy(vm))
            elif mutation == "denied":
                vm.update(state="error", reason="permission_denied")
            elif mutation == "wrong_type":
                vm["resource_type"] = STORAGE
            else:
                bundle["scope"] = SUB + "/resourceGroups/other"
            context = self.context(ASR_ITEM, bundle)
            self.assertIn("unknown", context if "unknown" in context else context["sourceVm"])
        bundle = self.bundle()
        item = self.resource(bundle, BACKUP_ITEM)
        item["properties"]["vmBackupSummary"]["policyId"] = (
            VAULT_ID.replace("/authored", "/other") + "/backupPolicies/authored"
        ).lower()
        self.assertIn("unknown", self.context(BACKUP_ITEM, bundle)["policy"])
        bundle = self.bundle()
        cfg = self.resource(bundle, STORAGE_CONFIG)
        cfg["arm_id"] = cfg["arm_id"].replace("vaultstorageconfig", "arbitrary")
        self.assertIn("unknown", self.context(STORAGE_CONFIG, bundle))

    def test_guest_modes_exact_extension_pairs_instance_name_and_parent(self):
        for mode in ASSIGNMENT_TYPES:
            result = properties(GUEST, {"guestConfiguration": {"assignmentType": mode}})
            self.assertEqual(result["guestAssignmentSummary"]["assignmentType"], mode)
        for mode in (None, "Null", "audit", PRIVATE, True):
            result = properties(GUEST, {"guestConfiguration": {"assignmentType": mode}})
            self.assertIn("unknown", result["guestAssignmentSummary"]["assignmentType"])
        for publisher, kind in (
            ("Microsoft.GuestConfiguration", "ConfigurationForLinux"),
            ("Microsoft.GuestConfiguration", "ConfigurationforWindows"),
        ):
            self.assertNotIn(
                "unknown",
                properties(EXTENSION, {"publisher": publisher, "type": kind})[
                    "machineConfigurationExtension"
                ],
            )
        for publisher, kind in (
            (PRIVATE, "ConfigurationForLinux"),
            ("Microsoft.GuestConfiguration", "ConfigurationforLinux"),
            ("Microsoft.Azure.Extensions", "CustomScript"),
        ):
            self.assertIn(
                "unknown",
                properties(EXTENSION, {"publisher": publisher, "type": kind})[
                    "machineConfigurationExtension"
                ],
            )
        self.assertEqual(self.context(GUEST)["machine"]["arm_id"], VM_ID.lower())
        self.assertIs(self.context(EXTENSION)["baselineInstanceNameMatches"], True)
        bundle = self.bundle()
        ext = self.resource(bundle, EXTENSION)
        ext["arm_id"] = ext["arm_id"].replace("azurepolicyforlinux", "arbitrary")
        self.assertIs(self.context(EXTENSION, bundle)["baselineInstanceNameMatches"], False)
        guest = self.resource(bundle, GUEST)
        guest["arm_id"] = guest["arm_id"].replace(
            "microsoft.compute/virtualmachines", "microsoft.hybridcompute/machines"
        )
        self.assertIn("unknown", self.context(GUEST, bundle))

    def test_sql_typed_membership_primary_partner_and_no_runtime_sla(self):
        context = self.context(FAILOVER)
        self.assertEqual(context["primaryServer"]["arm_id"], SQL_ID.lower())
        self.assertNotIn("unknown", context["databaseIds"][0])
        self.assertNotIn("unknown", context["partnerServerIds"][0])
        bundle = self.bundle()
        facts = self.resource(bundle, FAILOVER)["properties"]["sqlFailoverSummary"]
        facts["databaseIds"] = [
            (SQL_ID + "/databases/authored").replace("/primary/", "/secondary/").lower()
        ]
        facts["partnerServerIds"] = [SQL_ID.lower()]
        context = self.context(FAILOVER, bundle)
        self.assertIn("unknown", context["databaseIds"][0])
        self.assertIn("unknown", context["partnerServerIds"][0])
        for values in (
            {"databaseIds": [VM_ID]},
            {"databaseIds": [SQL_ID + "/databases/a"] * 2},
            {"databaseIds": [SQL_ID + "/databases/a"] * 101},
            {"partnerServerIds": [PRIVATE]},
            {"readWriteFailoverPolicy": "CustomerManaged"},
        ):
            facts = review_fact({"sqlFailoverSummary": values}, "sqlFailoverSummary")
            self.assertIn("unknown", facts[next(iter(values))])
            self.assertNotIn(PRIVATE, json.dumps(facts))

    def test_waf_exact_service_category_enabled_destination_and_onboarding_links(self):
        context = self.context(DIAGNOSTIC)
        self.assertEqual(context["configuredWafLog"], {"category": CATEGORIES[1], "enabled": True})
        self.assertEqual(context["workspace"]["arm_id"], WORKSPACE_ID.lower())
        self.assertNotIn("unknown", context["sentinelOnboarding"])
        self.assertIn("WAF ingestion/review/detection", context["warning"])
        bundle = self.bundle()
        diagnostic = self.resource(bundle, DIAGNOSTIC)
        diagnostic["properties"]["targetResourceId"] = VM_ID.lower()
        self.assertIn("unknown", self.context(DIAGNOSTIC, bundle))
        for sku in (None, "Standard_Microsoft", "Premium_AzureFrontDoorExtra", PRIVATE):
            bundle = self.bundle()
            self.resource(bundle, PROFILE)["properties"] = {"frontDoorProfileSummary": {"sku": sku}}
            self.assertIn("unknown", self.context(DIAGNOSTIC, bundle))
        for name in ("default2", "arbitrary"):
            bundle = self.bundle()
            self.resource(bundle, ONBOARDING)["arm_id"] = (
                self.resource(bundle, ONBOARDING)["arm_id"].rsplit("/", 1)[0] + "/" + name
            )
            self.assertIn("unknown", self.context(DIAGNOSTIC, bundle)["sentinelOnboarding"])

    def test_waf_case_sensitive_categories_groups_duplicates_and_unknown_not_disabled(self):
        for logs in (
            None,
            [],
            [None],
            [{}] * 101,
            [{"categoryGroup": "allLogs", "enabled": True}],
            [{"category": "FrontDoorFirewallLog", "enabled": True}],
            [{"category": CATEGORIES[2], "enabled": True}],
            [{"category": CATEGORIES[1], "categoryGroup": "allLogs", "enabled": True}],
            [{"category": CATEGORIES[1], "enabled": True}] * 2,
            [{"category": PRIVATE, "enabled": True}],
        ):
            facts = properties(DIAGNOSTIC, {"logs": logs})["wafDiagnosticSummary"]
            self.assertIn("unknown", facts["categories"][CATEGORIES[1]])
            self.assertNotIn(PRIVATE, json.dumps(facts))
        for enabled in (False, True):
            facts = properties(
                DIAGNOSTIC, {"logs": [{"category": CATEGORIES[1], "enabled": enabled}]}
            )
            self.assertIs(facts["wafDiagnosticSummary"]["categories"][CATEGORIES[1]], enabled)
        for enabled in (None, 0, "true", PRIVATE):
            facts = properties(
                DIAGNOSTIC, {"logs": [{"category": CATEGORIES[1], "enabled": enabled}]}
            )
            self.assertIn("unknown", facts["wafDiagnosticSummary"]["categories"][CATEGORIES[1]])
        bundle = self.bundle()
        diagnostic = self.resource(bundle, DIAGNOSTIC)
        gateway_id = SCOPE + "/providers/Microsoft.Network/applicationGateways/authored"
        self.resource(bundle, PROFILE).update(
            resource_type=GATEWAY, arm_id=gateway_id.lower(), properties={}
        )
        diagnostic.update(
            arm_id=(
                gateway_id + "/providers/Microsoft.Insights/diagnosticSettings/authored"
            ).lower(),
            properties=properties(
                DIAGNOSTIC,
                {
                    "workspaceId": WORKSPACE_ID,
                    "logs": [{"category": CATEGORIES[0], "enabled": True}],
                },
                root={"scope": gateway_id},
            ),
        )
        self.assertEqual(
            self.context(DIAGNOSTIC, bundle)["configuredWafLog"],
            {"category": CATEGORIES[0], "enabled": True},
        )

    def test_raw_terraform_local_module_and_literal_child_identities(self):
        source = self.root / "source"
        child = source / "recovery"
        child.mkdir(parents=True)
        (source / "main.tf").write_text('module "recovery" { source = "./recovery" }\n', "utf-8")
        text = (
            'resource "azurerm_recovery_services_vault" "a" {\n'
            'name = "authored"\nresource_group_name = "recovery"\n'
            'storage_mode_type = "ZoneRedundant"\ncross_region_restore_enabled = false\n}\n'
            'resource "azurerm_virtual_machine_extension" "a" {\n'
            f'name = "AzurePolicyforLinux"\nvirtual_machine_id = "{VM_ID}"\n'
            'publisher = "Microsoft.GuestConfiguration"\ntype = "ConfigurationForLinux"\n'
            f'protected_settings = "{PRIVATE}"\n}}\n'
            'resource "azurerm_policy_virtual_machine_configuration_assignment" "a" {\n'
            f'name = "authored"\nvirtual_machine_id = "{VM_ID}"\n'
            f'configuration {{ assignment_type = "Audit"\ncontent_uri = "{PRIVATE}" }}\n}}\n'
            'resource "azurerm_mssql_failover_group" "a" {\n'
            f'name = "authored"\nserver_id = "{SQL_ID}"\n'
            'read_write_endpoint_failover_policy { mode = "Manual" }\n}\n'
            'resource "azurerm_backup_protected_vm" "a" {\n'
            f'source_vm_id = "{VM_ID}"\n}}\n'
        )
        (child / "main.tf").write_text(text, "utf-8")
        bundle = terraform_source(source, scope=SCOPE, provider_version="4.50.0")
        self.assertEqual(len(bundle["resources"]), 5)
        self.assertNotIn(PRIVATE, json.dumps(bundle))
        self.assertEqual(
            self.resource(bundle, EXTENSION)["arm_id"],
            (VM_ID + "/extensions/AzurePolicyforLinux").lower(),
        )
        self.assertEqual(
            self.resource(bundle, GUEST)["properties"]["guestAssignmentSummary"]["assignmentType"],
            "Audit",
        )
        self.assertIsNone(self.resource(bundle, BACKUP_ITEM)["arm_id"])
        for provider in (None, "4.49.0"):
            unsupported = terraform_source(source, scope=SCOPE, provider_version=provider)
            self.assertTrue(all(r["state"] == "unknown" for r in unsupported["resources"]))
        for kind in (
            "azurerm_virtual_machine_extension",
            "azurerm_policy_virtual_machine_configuration_assignment",
        ):
            self.assertIsNone(
                tf_resource_id(SCOPE, kind, {"name": "a", "virtual_machine_id": SQL_ID})
            )
            self.assertIsNone(
                tf_resource_id(
                    SCOPE,
                    kind,
                    {"name": "a", "virtual_machine_id": VM_ID.replace("/recovery/", "/outside/")},
                )
            )

    def test_supplied_plan_versions_sensitive_markers_and_conflicting_binding(self):
        values = {
            "id": VAULT_ID,
            "name": "authored",
            "resource_group_name": "recovery",
            "storage_mode_type": "GeoRedundant",
            "cross_region_restore_enabled": True,
        }
        plan = {
            "format_version": "1.2",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "mode": "managed",
                            "type": "azurerm_recovery_services_vault",
                            "address": "azurerm_recovery_services_vault.a",
                            "values": values,
                            "sensitive_values": {"storage_mode_type": True},
                        }
                    ]
                }
            },
        }
        bundle = plan_source(self.write("plan.json", plan), scope=SCOPE, provider_version="4.50.0")
        facts = bundle["resources"][0]["properties"]["recoveryStorageSummary"]
        self.assertIn("unknown", facts["storageModelType"])
        self.assertIs(facts["crossRegionRestoreFlag"], True)
        values["id"] = VAULT_ID + "other"
        with self.assertRaises(InputError):
            plan_source(self.write("bad-plan.json", plan), scope=SCOPE, provider_version="4.50.0")
        values["id"] = VAULT_ID
        bundle = plan_source(self.write("plan.json", plan), scope=SCOPE, provider_version="4.49.0")
        self.assertEqual(bundle["resources"][0]["state"], "unknown")

    def test_all_adapter_families_raw_json_plan_and_projection_parity(self):
        cases = {
            "azurerm_recovery_services_vault": {
                "name": "authored",
                "resource_group_name": "recovery",
                "storage_mode_type": "ZoneRedundant",
                "cross_region_restore_enabled": False,
            },
            "azurerm_data_protection_backup_vault": {
                "name": "authored",
                "resource_group_name": "recovery",
                "datastore_type": "VaultStore",
                "redundancy": "GeoRedundant",
                "cross_region_restore_enabled": True,
            },
            "azurerm_backup_protected_vm": {
                "source_vm_id": VM_ID,
                "backup_policy_id": VAULT_ID + "/backupPolicies/authored",
            },
            "azurerm_site_recovery_replicated_vm": {
                "name": "authored",
                "resource_group_name": "recovery",
                "recovery_vault_name": "authored",
                "source_recovery_fabric_name": "authored",
                "source_recovery_protection_container_name": "authored",
                "source_vm_id": VM_ID,
                "recovery_replication_policy_id": VAULT_ID + "/replicationPolicies/authored",
                "target_resource_group_id": SCOPE,
            },
            "azurerm_policy_virtual_machine_configuration_assignment": {
                "name": "authored",
                "virtual_machine_id": VM_ID,
                "configuration": [
                    {"assignment_type": "ApplyAndAutoCorrect", "content_uri": PRIVATE}
                ],
            },
            "azurerm_virtual_machine_extension": {
                "name": "AzurePolicyforLinux",
                "virtual_machine_id": VM_ID,
                "publisher": "Microsoft.GuestConfiguration",
                "type": "ConfigurationForLinux",
                "auto_upgrade_minor_version": False,
                "automatic_upgrade_enabled": True,
                "settings": PRIVATE,
                "protected_settings": PRIVATE,
            },
            "azurerm_mssql_failover_group": {
                "name": "authored",
                "server_id": SQL_ID,
                "databases": [SQL_ID + "/databases/authored"],
                "partner_server": [{"id": SQL_ID.replace("/primary", "/secondary")}],
                "read_write_endpoint_failover_policy": [{"mode": "Manual"}],
            },
            "azurerm_cdn_frontdoor_profile": {
                "name": "authored",
                "resource_group_name": "recovery",
                "sku_name": "Premium_AzureFrontDoor",
            },
            "azurerm_monitor_diagnostic_setting": {
                "name": "authored",
                "target_resource_id": PROFILE_ID,
                "log_analytics_workspace_id": WORKSPACE_ID,
                "enabled_log": [{"category": CATEGORIES[1]}],
                "private_payload": PRIVATE,
            },
        }
        source = self.root / "all-adapters"
        source.mkdir()
        (source / "main.tf.json").write_text(
            json.dumps(
                {"resource": {kind: {"authored": values} for kind, values in cases.items()}}
            ),
            encoding="utf-8",
        )
        raw = terraform_source(source, scope=SCOPE, provider_version="4.50.0")
        planned = []
        for kind, values in cases.items():
            identity = (
                BACKUP_ID
                if kind == "azurerm_backup_protected_vm"
                else tf_resource_id(SCOPE, kind, values)
            )
            planned.append(
                {
                    "mode": "managed",
                    "type": kind,
                    "address": kind + ".authored",
                    "values": {**values, "id": identity},
                }
            )
        plan = plan_source(
            self.write(
                "all-plan.json",
                {
                    "format_version": "1.2",
                    "planned_values": {"root_module": {"resources": planned}},
                },
            ),
            scope=SCOPE,
            provider_version="4.50.0",
        )
        self.assertEqual(len(raw["resources"]), len(cases))
        self.assertNotIn(PRIVATE, json.dumps([raw, plan]))
        for kind, values in cases.items():
            expected = tf_properties(kind, values)
            for bundle in (raw, plan):
                row = self.resource(bundle, TF_TYPES[kind].lower())
                self.assertEqual(row["properties"], expected)
        self.assertEqual(self.resource(raw, ASR_ITEM)["arm_id"], ASR_ID.lower())
        self.assertIsNone(self.resource(raw, BACKUP_ITEM)["arm_id"])
        self.assertEqual(self.resource(plan, BACKUP_ITEM)["arm_id"], BACKUP_ID.lower())

    def test_waf_storage_and_workspace_joins_do_not_infer_sentinel_or_ingestion(self):
        for mutation in ("missing", "duplicate", "denied", "wrong_type", "outside"):
            bundle = self.bundle()
            workspace = self.resource(bundle, WORKSPACE)
            if mutation == "missing":
                bundle["resources"].remove(workspace)
            elif mutation == "duplicate":
                bundle["resources"].append(copy.deepcopy(workspace))
            elif mutation == "denied":
                workspace.update(state="error", reason="permission_denied")
            elif mutation == "wrong_type":
                workspace["resource_type"] = STORAGE
            else:
                workspace["arm_id"] = workspace["arm_id"].replace("/recovery/", "/outside/")
            context = self.context(DIAGNOSTIC, bundle)
            self.assertIn("unknown", context["workspace"])
            self.assertIn("unknown", context["sentinelOnboarding"])
        bundle = self.bundle()
        identity = SCOPE + "/providers/Microsoft.Storage/storageAccounts/authoredlogs"
        bundle["resources"].append(
            self.record(
                STORAGE, identity, root={"kind": "StorageV2", "sku": {"name": "Standard_LRS"}}
            )
        )
        self.resource(bundle, DIAGNOSTIC)["properties"]["wafDiagnosticSummary"][
            "storageAccountId"
        ] = identity.lower()
        self.assertEqual(self.context(DIAGNOSTIC, bundle)["storage"]["arm_id"], identity.lower())
        self.resource(bundle, DIAGNOSTIC)["properties"]["wafDiagnosticSummary"][
            "storageAccountId"
        ] = VM_ID.lower()
        self.assertIn("unknown", self.context(DIAGNOSTIC, bundle)["storage"])

    def test_unsupported_source_qualification_cannot_supply_control_signals(self):
        for kind, display in (
            (DIAGNOSTIC, "F06.01"),
            (GUEST, "F03.01"),
            (STORAGE_CONFIG, "F02.02"),
        ):
            bundle = self.bundle()
            source = self.resource(bundle, kind)
            if kind == DIAGNOSTIC:
                source["properties"]["targetResourceId"] = VM_ID.lower()
            elif kind == GUEST:
                source["arm_id"] = source["arm_id"].replace(
                    "microsoft.compute/virtualmachines", "microsoft.hybridcompute/machines"
                )
            else:
                source["arm_id"] = source["arm_id"].replace("vaultstorageconfig", "arbitrary")
            bundle["resources"] = [source]
            self.assertFalse(prepared_signal(self.control(display), bundle))
            context = review_context(self.control(display), bundle)
            self.assertTrue(
                all(
                    "unknown" in fact
                    for resource in context["resources"]
                    for fact in resource["facts"].values()
                )
            )

    def test_pinned_arm_versions_guest_extension_scope_and_no_live_routes(self):
        for kind in (
            VAULT,
            STORAGE_CONFIG,
            BACKUP_VAULT,
            BACKUP_ITEM,
            ASR_ITEM,
            GUEST,
            EXTENSION,
            FAILOVER,
            PROFILE,
        ):
            self.assertNotIn(kind, API_VERSIONS)
            version = next(iter(PLANNED_API_VERSIONS[kind]))
            names = {
                VAULT: "authored",
                STORAGE_CONFIG: "authored/vaultstorageconfig",
                BACKUP_ITEM: "authored/Azure/authored/authored",
                ASR_ITEM: "authored/authored/authored/authored",
                EXTENSION: "authored/AzurePolicyforLinux",
                FAILOVER: "primary/authored",
            }
            for api in (version, "2099-01-01", None):
                entry = {
                    "type": kind,
                    "apiVersion": api,
                    "name": names.get(kind, "authored"),
                    "properties": {},
                }
                if kind == GUEST:
                    entry["scope"] = VM_ID
                bundle = arm_source(self.write("arm.json", {"resources": [entry]}), scope=SCOPE)
                self.assertEqual(
                    bundle["resources"][0]["state"], "known" if api == version else "unknown"
                )
        for target in (VM_ID.replace("/recovery/", "/outside/"), SQL_ID, None):
            entry = {"type": GUEST, "apiVersion": "2024-04-05", "name": "a", "scope": target}
            result = arm_source(self.write("guest.json", {"resources": [entry]}), scope=SCOPE)
            self.assertEqual(result["resources"][0]["state"], "unknown")
        requests = []

        def transport(method, url, body=None):
            requests.append(url)
            if "/resources?" in url:
                return Response(200, {"value": [{"id": VAULT_ID, "type": VAULT}]}, {})
            if "policy" in url.lower():
                return Response(200, {"value": []}, {})
            self.fail("No recovery detail route is authorized")

        bundle = Collector(transport).collect(
            subscriptions=["00000000-0000-0000-0000-000000000001"], inventory_authorized=True
        )
        self.assertTrue(all(not r["properties"] for r in bundle["resources"]))
        self.assertTrue(all("/vaults/" not in url.lower() for url in requests))

    def test_eight_independent_blank_interview_and_review_decisions(self):
        prepared = prepare_reviews(self.report(), self.catalog, sorted(IDS), SCOPE)
        self.assertEqual(len(prepared["entries"]), 8)
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
        self.assertEqual(len(blank["decisions"]), 8)
        self.assertTrue(all(r["outcome"] is None for r in blank["decisions"]))
        with self.assertRaises(InputError):
            compile_interview(blank, self.catalog, at=AT)
        reviews = compile_interview(self.completed(), self.catalog, at=AT)
        validate_reviews(reviews, self.catalog, SCOPE, at=AT)
        self.assertEqual(len(reviews["entries"]), 8)

    def test_interview_selection_binding_time_expiry_attribution_and_atomicity(self):
        completed = self.completed()
        for key, value in (
            ("scope", SUB + "/resourceGroups/other"),
            ("catalog_sha256", "0" * 64),
            ("requirements_sha256", "0" * 64),
            ("reviewer", None),
            ("valid_from", UNTIL),
            ("valid_until", "2000-01-01T00:00:00Z"),
        ):
            changed = copy.deepcopy(completed)
            changed[key] = value
            with self.assertRaises(InputError):
                compile_interview(changed, self.catalog, at=AT)
        for alteration in ("partial", "duplicate", "binding", "selection"):
            changed = copy.deepcopy(completed)
            if alteration == "partial":
                changed["decisions"][1]["outcome"] = None
            elif alteration == "duplicate":
                changed["decisions"].append(copy.deepcopy(changed["decisions"][0]))
            elif alteration == "binding":
                changed["decisions"][0]["control_sha256"] = "0" * 64
            else:
                changed["decisions"][0]["control_id"] = "ALZ-" + "0" * 36
            with self.assertRaises(InputError):
                compile_interview(changed, self.catalog, at=AT)
        control = self.control("F06.02")["control_id"]
        selected = prepare_interview(
            self.report(), self.catalog, self.question, SCOPE, selected=[control]
        )
        self.assertEqual([r["control_id"] for r in selected["decisions"]], [control])
        for invalid in ([], [control, control], ["ALZ-00000000-0000-0000-0000-000000000001"]):
            with self.assertRaises(InputError):
                prepare_interview(
                    self.report(), self.catalog, self.question, SCOPE, selected=invalid
                )
        changed_catalog = copy.deepcopy(self.catalog)
        next(c for c in changed_catalog["controls"] if c["control_id"] == control)[
            "evidence_requirements"
        ].append("Changed requirement")
        with self.assertRaises(InputError):
            compile_interview(completed, changed_catalog, at=AT)

    def test_tiers_no_scope_wrong_kind_stale_denied_partial_never_verified(self):
        report = self.report()
        for row in report["results"]:
            if row["control_id"] in IDS:
                self.assertNotEqual(row["observed"]["outcome"], "pass")
                self.assertEqual(row["observed"]["evidence_tier"], "signal")
        for boundary in (None, SUB + "/resourceGroups/other"):
            bundle = self.bundle()
            bundle["scope"] = boundary
            report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
            for row in report["results"]:
                if row["control_id"] in IDS:
                    self.assertEqual(row["observed"]["evidence_tier"], "needs_decision")
        stale = assess(self.bundle(), self.catalog, at="2026-11-10T23:00:00Z", evidence_tiers=True)
        for row in stale["results"]:
            if row["control_id"] in IDS:
                self.assertEqual(row["observed"]["evidence_tier"], "needs_decision")
        bundle = self.bundle()
        for r in bundle["resources"]:
            r.update(state="error", reason="permission_denied")
        report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        for row in report["results"]:
            if row["control_id"] in IDS:
                self.assertNotEqual(row["observed"]["evidence_tier"], "verified")
        bundle = self.bundle()
        backup = self.resource(bundle, BACKUP_ITEM)
        backup["resource_type"] = STORAGE
        bundle["resources"] = [backup]
        self.assertFalse(prepared_signal(self.control("F02.01"), bundle))

    def test_population_bounds_and_absence_never_becomes_coverage(self):
        bundle = self.bundle()
        source = self.resource(bundle, BACKUP_VAULT)
        bundle["resources"] = [
            {**copy.deepcopy(source), "logical_id": str(i), "arm_id": source["arm_id"] + str(i)}
            for i in range(101)
        ]
        context = review_context(self.control("F02.02"), bundle)
        self.assertEqual(context["matching_resources"], 101)
        self.assertTrue(context["truncated"])
        self.assertTrue(
            all("unknown" in r["facts"]["backupVaultSummary"] for r in context["resources"])
        )
        self.assertFalse(prepared_signal(self.control("F02.02"), bundle))
        bundle["resources"].pop()
        self.assertTrue(prepared_signal(self.control("F02.02"), bundle))
        bundle["resources"] = []
        bundle["inventory_complete"] = True
        report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        for row in report["results"]:
            if row["control_id"] in IDS:
                self.assertNotEqual(row["observed"]["outcome"], "pass")

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
            if format in {"json", "csv"}:
                for control in IDS:
                    self.assertIn(control, output)
        self.assertGreater(len(render_xlsx(report)), 0)

    def test_private_original_time_replay_candidate_rejection_and_preserved_catalogs(self):
        bundle = self.bundle()
        self.resource(bundle, GUEST)["properties"]["guestAssignmentSummary"]["contentUri"] = PRIVATE
        sanitized = sanitize_evidence(bundle)
        self.assertNotIn(PRIVATE, json.dumps(sanitized))
        for row in self.matrix["recommendations"]:
            control = self.control(row["upstream_id"])
            self.assertEqual(review_context(control, bundle), review_context(control, sanitized))
        for name, catalog in (
            ("predecessor", self.accepted),
            (
                "historical",
                load_catalog(
                    str(files("alz_assessor").joinpath("data", "catalog-2026-11-06.20.json"))
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
        predecessor = files("alz_assessor").joinpath("data", "catalog-2026-11-06.21.json")
        self.assertEqual(
            digest(self.accepted),
            digest(load_catalog(str(predecessor)) if predecessor.is_file() else load_catalog()),
        )

    def test_cli_candidate_and_local_session_atomic_save(self):
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
        self.assertEqual(len({r["control_id"] for r in report["results"]} & IDS), 8)
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

    def test_policy_configuration_reused_without_builtin_fetch_or_second_interpreter(self):
        from alz_assessor.policy_strategy_evidence import ASSIGNMENT, DEFINITION

        for boundary in (SUB, "/providers/Microsoft.Management/managementGroups/authored"):
            definition = boundary + "/providers/Microsoft.Authorization/policyDefinitions/authored"
            assignment = boundary + "/providers/Microsoft.Authorization/policyAssignments/authored"
            bundle = self.bundle()
            bundle["scope"] = boundary
            bundle["resources"] = [
                self.record(
                    DEFINITION,
                    definition,
                    {
                        "policyType": "Custom",
                        "mode": "All",
                        "version": "1.2.3",
                        "policyRule": {
                            "if": {"field": PRIVATE},
                            "then": {"effect": "auditIfNotExists"},
                        },
                    },
                ),
                self.record(
                    ASSIGNMENT,
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
            context = review_context(self.control("F03.02"), bundle)
            self.assertEqual(len(context["resources"]), 2)
            self.assertNotIn(
                "unknown", context["resources"][1]["policy_configuration"]["definition"]
            )
            self.assertIn("supplied_policy_assignments", context)
            self.assertNotIn(PRIVATE, json.dumps(context))
            self.assertTrue(prepared_signal(self.control("F03.02"), bundle))
            bundle["resources"].pop(0)
            context = review_context(self.control("F03.02"), bundle)
            self.assertIn("unknown", context["resources"][0]["policy_configuration"]["definition"])

    def test_planned_observed_modes_and_unbound_shapes_remain_distinct(self):
        bundle = self.bundle()
        bundle["mode"] = "planned"
        report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        for row in report["results"]:
            if row["control_id"] in IDS:
                self.assertIsNone(row["observed"])
                self.assertNotEqual(row["planned"]["evidence_tier"], "verified")
        bundle = self.bundle()
        source = self.resource(bundle, BACKUP_VAULT)
        source["arm_id"] = SUB + "/providers/microsoft.dataprotection/backupvaults/authored"
        self.assertFalse(unique_known(source, bundle, self.index(bundle)))

    def test_real_bicep_recovery_guest_sql_waf_configuration_without_restore(self):
        compiler = os.environ.get("BICEP_COMPILER")
        if not compiler:
            self.skipTest("No existing compiler discovered; no acquisition attempted")
        bundle = arm_source(
            ROOT / "tests" / "fixtures" / "recovery" / "controls.bicep",
            scope=SCOPE,
            compiler=compiler,
            bicep=True,
        )
        self.assertTrue(all(r["state"] == "known" for r in bundle["resources"]))
        self.assertEqual(
            self.resource(bundle, BACKUP_VAULT)["properties"]["backupVaultSummary"][
                "storageSettings"
            ],
            [{"datastoreType": "VaultStore", "type": "ZoneRedundant"}],
        )
        guest = self.resource(bundle, GUEST)
        self.assertEqual(guest["properties"]["guestAssignmentSummary"]["assignmentType"], "Audit")
        self.assertEqual(
            guest["arm_id"],
            (
                VM_ID
                + "/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments/authored"
            ).lower(),
        )
        self.assertEqual(
            self.resource(bundle, FAILOVER)["properties"]["sqlFailoverSummary"][
                "readWriteFailoverPolicy"
            ],
            "Manual",
        )
        diagnostic = self.resource(bundle, DIAGNOSTIC)
        self.assertEqual(
            diagnostic["properties"]["wafDiagnosticSummary"]["categories"][CATEGORIES[1]], True
        )
        self.assertEqual(
            self.context(DIAGNOSTIC, bundle)["configuredWafLog"],
            {"category": CATEGORIES[1], "enabled": True},
        )
        for row in assess(bundle, self.catalog, at=bundle["collected_at"], evidence_tiers=True)[
            "results"
        ]:
            if row["control_id"] in IDS:
                self.assertNotEqual(row["planned"]["evidence_tier"], "verified")
