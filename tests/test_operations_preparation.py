import contextlib
import copy
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
from alz_assessor.bicep import compile_bicep
from alz_assessor.catalog import load_catalog
from alz_assessor.cli import main
from alz_assessor.contracts import control_digest, document, validate
from alz_assessor.engine import assess
from alz_assessor.network_evidence import review_fact
from alz_assessor.operations_evidence import (
    ARC,
    ASSIGNMENT,
    DEFINITION,
    EXPORT,
    FLOW,
    GUEST,
    GUIDS,
    IMMUTABLE,
    LOCK,
    PATHS,
    ROLE,
    STORAGE,
    TABLE,
    TF_KINDS,
    TF_TOTAL,
    VM,
    WORKSPACE,
    configuration_context,
    lock_scope,
    table_selection,
)
from alz_assessor.plan import plan_source
from alz_assessor.replay import export_bundle, replay_bundle, sanitize_evidence, semantic
from alz_assessor.reports import render, render_xlsx
from alz_assessor.review_page import review_page
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import prepare_reviews, review_context
from alz_assessor.sources import terraform_source, tf_properties, tf_resource_id
from alz_assessor.terraform import InputError, tree_hash
from alz_assessor.tiers import prepared_signal

ROOT = Path(__file__).resolve().parents[1]
SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
OTHER = "/subscriptions/00000000-0000-0000-0000-000000000002"
RG = SCOPE + "/resourcegroups/operations"
WS = RG + "/providers/" + WORKSPACE + "/authored"
STORE = RG + "/providers/" + STORAGE + "/authored"
MACHINE = RG + "/providers/" + VM + "/authored"
HYBRID = RG + "/providers/" + ARC + "/authored"
AT = "2026-11-06T23:30:00Z"
PRIVATE = "PRIVATE-LOG-GUEST-PATCH-TRAFFIC-CONTENT"
CONTROLS = {"ALZ-" + guid for guid in GUIDS}


def previous_catalog():
    return load_catalog(str(files("alz_assessor").joinpath("data", "catalog-2026-11-06.22.json")))


class OperationsPreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.matrix = json.loads(
            (ROOT / "references/recommendation-batches/preparation-24.json").read_text("utf-8")
        )
        self.catalog = copy.deepcopy(previous_catalog())
        self.catalog["review_state"] = "authored-in-memory-fixture-not-accepted"
        rows = {r["guid"]: r for r in self.matrix["recommendations"]}
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

    def record(self, kind, identity, raw, location="westeurope"):
        return {
            "logical_id": identity.lower(),
            "arm_id": identity.lower(),
            "resource_type": kind,
            "state": "known",
            "reason": "",
            "source_location": "fixture://authored-operations",
            "properties": properties(kind, raw, root={"location": location}),
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
                self.record(
                    WORKSPACE,
                    WS,
                    {
                        "sku": {"name": "PerGB2018"},
                        "retentionInDays": 30,
                        "publicNetworkAccessForIngestion": "Disabled",
                        "publicNetworkAccessForQuery": "Disabled",
                        "private": PRIVATE,
                    },
                ),
                self.record(STORAGE, STORE, {"minimumTlsVersion": "TLS1_2"}),
                self.record(
                    TABLE,
                    WS + "/tables/heartbeat",
                    {
                        "plan": "Analytics",
                        "retentionInDays": 730,
                        "totalRetentionInDays": 4383,
                        "searchResults": {"query": PRIVATE},
                        "schema": {"columns": PRIVATE},
                    },
                ),
                self.record(
                    EXPORT,
                    WS + "/dataexports/authored",
                    {
                        "enable": True,
                        "tableNames": ["Heartbeat"],
                        "destination": {"resourceId": STORE},
                        "logs": PRIVATE,
                    },
                ),
                self.record(
                    IMMUTABLE,
                    STORE + "/blobservices/default/containers/authored/"
                    "immutabilitypolicies/default",
                    {
                        "immutabilityPeriodSinceCreationInDays": 146000,
                        "state": "Locked",
                        "allowProtectedAppendWrites": False,
                        "allowProtectedAppendWritesAll": False,
                        "legalHold": PRIVATE,
                    },
                ),
                self.record(
                    VM,
                    MACHINE,
                    {
                        "osProfile": {
                            "linuxConfiguration": {
                                "provisionVMAgent": True,
                                "patchSettings": {
                                    "assessmentMode": "AutomaticByPlatform",
                                    "patchMode": "AutomaticByPlatform",
                                },
                                "adminPassword": PRIVATE,
                            }
                        }
                    },
                ),
                self.record(
                    ARC,
                    HYBRID,
                    {
                        "osType": "linux",
                        "osProfile": {
                            "linuxConfiguration": {
                                "patchSettings": {
                                    "assessmentMode": "AutomaticByPlatform",
                                    "patchMode": "AutomaticByPlatform",
                                }
                            }
                        },
                        "extensions": [{"status": {"message": PRIVATE}}],
                        "locationData": {"city": PRIVATE},
                        "clientPublicKey": PRIVATE,
                    },
                ),
                self.record(
                    GUEST,
                    MACHINE + "/providers/" + GUEST + "/authored",
                    {
                        "guestConfiguration": {
                            "assignmentType": "Audit",
                            "kind": "DSC",
                            "contentUri": PRIVATE,
                            "configurationProtectedParameter": PRIVATE,
                        },
                        "latestAssignmentReport": {"resources": PRIVATE},
                    },
                ),
                self.record(
                    LOCK,
                    WS + "/providers/" + LOCK + "/authored",
                    {"level": "CanNotDelete", "notes": PRIVATE, "owners": [PRIVATE]},
                ),
                self.record(
                    FLOW,
                    RG + "/providers/microsoft.network/networkwatchers/authored/flowlogs/authored",
                    {
                        "enabled": True,
                        "storageId": STORE,
                        "targetResourceId": RG
                        + "/providers/microsoft.network/virtualnetworks/authored",
                        "flowAnalyticsConfiguration": {
                            "networkWatcherFlowAnalyticsConfiguration": {
                                "enabled": True,
                                "workspaceResourceId": WS,
                            }
                        },
                        "traffic": PRIVATE,
                    },
                ),
                self.record(
                    DEFINITION,
                    SCOPE + "/providers/" + DEFINITION + "/authored",
                    {
                        "policyType": "Custom",
                        "mode": "All",
                        "version": "1.0.0",
                        "policyRule": {"if": {"secret": PRIVATE}, "then": {"effect": "deny"}},
                    },
                ),
                self.record(
                    ASSIGNMENT,
                    SCOPE + "/providers/" + ASSIGNMENT + "/authored",
                    {
                        "policyDefinitionId": SCOPE + "/providers/" + DEFINITION + "/authored",
                        "definitionVersion": "1.0.0",
                        "enforcementMode": "Default",
                        "notScopes": [],
                        "resourceSelectors": [],
                        "overrides": [],
                        "parameters": {"secret": PRIVATE},
                    },
                ),
                self.record(
                    ROLE,
                    RG + "/providers/" + ROLE + "/authored",
                    {
                        "principalId": PRIVATE,
                        "principalType": "Group",
                        "roleDefinitionId": SCOPE + "/providers/microsoft.authorization/"
                        "roledefinitions/00000000-0000-0000-0000-000000000005",
                    },
                ),
            ],
        )

    def control(self, upstream):
        return next(c for c in self.catalog["controls"] if c["upstream_id"] == upstream)

    def context(self, upstream, bundle=None):
        return review_context(self.control(upstream), bundle or self.bundle())

    def config(self, index, bundle=None):
        bundle = bundle or self.bundle()
        by_id = {}
        for row in bundle["resources"]:
            by_id.setdefault((row.get("arm_id") or "").lower(), []).append(row)
        return configuration_context(bundle["resources"][index], bundle, by_id)

    def tier(self, upstream, bundle=None, at=AT):
        report = assess(bundle or self.bundle(), self.catalog, at=at, evidence_tiers=True)
        return next(
            r for r in report["results"] if r["control_id"] == self.control(upstream)["control_id"]
        )["observed"]

    def test_exact_fixed_nine_and_preserved_preparation_catalog(self):
        targets = json.loads((ROOT / "references/recommendation-batches/targets.json").read_text())
        fixed = {t["upstream_id"]: t["guid"] for t in targets["targets"] if t["batch"] == "24"}
        self.assertEqual(
            fixed, {r["upstream_id"]: r["guid"] for r in self.matrix["recommendations"]}
        )
        self.assertEqual(set(fixed.values()), GUIDS)
        self.assertEqual(set(self.matrix["interview"]["controls"]), CONTROLS)
        self.assertNotIn("catalog_version", self.matrix)
        for control in previous_catalog()["controls"]:
            if control["upstream_guid"] in GUIDS:
                self.assertNotIn("review_fact_paths", control)
                self.assertIsNone(control["rule"])
                self.assertEqual(control["automation"], "assisted")
        sources = json.loads(
            (ROOT / "references/recommendation-batches/preparation-24-sources.json").read_text()
        )
        indexed = {s["id"]: s for s in sources["sources"]}
        self.assertEqual(len(indexed), len(sources["sources"]))
        for row in self.matrix["recommendations"]:
            self.assertTrue(set(row["sources"]) <= set(indexed))
        for source in indexed.values():
            self.assertRegex(source["revision"], "^[0-9a-f]{40}$")
            self.assertRegex(source["sha256"], "^[0-9a-f]{64}$")
            self.assertTrue(source["reuse"])
            self.assertTrue(source["retrieved_at"])
        self.assertIn("data-retention-configure", indexed["retention-linked"]["resolved_url"])
        self.assertIn("workspace-design", indexed["regional-workspace-linked"]["resolved_url"])
        self.assertIn(
            "01-overview-concepts", indexed["machine-configuration-linked"]["resolved_url"]
        )
        self.assertIn("network-watcher-overview", indexed["watcher-linked"]["resolved_url"])
        self.assertIn("twelve years", self.control("F01.03")["recommendation"])
        self.assertIn("eight-day", self.matrix["source_qualifications"]["retention"])
        self.assertIn("private preview", self.matrix["source_qualifications"]["deny"])

    def test_all_nine_workflows_are_signals_never_whole_passes(self):
        bundle = self.bundle()
        for index in range(1, 10):
            upstream = f"F01.{index:02}"
            context = self.context(upstream, bundle)
            self.assertGreater(context["matching_resources"], 0)
            self.assertFalse(context["truncated"])
            self.assertNotIn(PRIVATE, json.dumps(context))
            self.assertTrue(all("operations_configuration" in r for r in context["resources"]))
            body = self.tier(upstream, bundle)
            self.assertEqual(body["evidence_tier"], "signal", upstream)
            self.assertNotEqual(body["outcome"], "pass")
        prepared = prepare_reviews(
            assess(bundle, self.catalog, at=AT), self.catalog, sorted(CONTROLS), SCOPE
        )
        for entry in prepared["entries"]:
            if entry["control_id"] in CONTROLS:
                self.assertIsNone(entry["outcome"])
        self.assertEqual(self.config(3)["storageDestination"]["arm_id"], STORE)
        self.assertIn("unknown", self.config(3)["containerPolicyBinding"])
        self.assertEqual(self.config(7)["machine"]["arm_id"], MACHINE)
        self.assertEqual(self.config(8)["configuredScope"], WS)
        self.assertIn("unknown", self.config(8)["effectiveProtection"])
        self.assertEqual(self.config(11)["policy"]["definition"]["facts"]["literalEffect"], "deny")

    def test_exact_retention_units_analytics_total_and_discrete_provider_boundaries(self):
        for days, supported in ((3, False), (4, True), (730, True), (731, False)):
            fact = properties(
                TABLE, {"plan": "Analytics", "retentionInDays": days, "totalRetentionInDays": 4383}
            )["operationsTableRetention"]
            self.assertEqual(type(fact["analyticsDays"]) is int, supported)
        for days, supported in ((3, False), (4, True), (4382, True), (4383, True), (4384, False)):
            fact = properties(
                TABLE, {"plan": "Analytics", "retentionInDays": 4, "totalRetentionInDays": days}
            )["operationsTableRetention"]
            self.assertEqual(type(fact["totalDays"]) is int, supported)
        for days in TF_TOTAL | {4, 730, 731, 1094, 1096, 4384}:
            fact = tf_properties(
                "azurerm_log_analytics_workspace_table",
                {
                    "plan": "Analytics",
                    "retention_in_days": 4,
                    "total_retention_in_days": days,
                },
            )["operationsTableRetention"]
            self.assertEqual(type(fact["totalDays"]) is int, days in TF_TOTAL | {4, 730})
        for value in (None, True, 30.0, "30", 0, -2, {"unknown": "sensitive"}):
            fact = properties(
                TABLE,
                {"plan": "Analytics", "retentionInDays": value, "totalRetentionInDays": value},
            )["operationsTableRetention"]
            self.assertIn("unknown", fact["analyticsDays"])
            self.assertIn("unknown", fact["totalDays"])
        sentinel = properties(
            TABLE, {"plan": "Analytics", "retentionInDays": -1, "totalRetentionInDays": -1}
        )["operationsTableRetention"]
        self.assertEqual(sentinel["analyticsDays"], {"inherits": "parent"})
        self.assertEqual(
            sentinel,
            review_fact({"operationsTableRetention": sentinel}, "operationsTableRetention"),
        )
        invalid = properties(
            TABLE, {"plan": "Analytics", "retentionInDays": 31, "totalRetentionInDays": 30}
        )["operationsTableRetention"]
        self.assertIn("unknown", invalid)
        for kind, raw in (
            (TABLE, {"plan": "Basic", "retentionInDays": 8, "totalRetentionInDays": 30}),
            (
                "azurerm_log_analytics_workspace_table",
                {"plan": "Basic", "retention_in_days": 8, "total_retention_in_days": 30},
            ),
        ):
            fact = (properties if kind == TABLE else tf_properties)(kind, raw)
            self.assertIn("unknown", fact["operationsTableRetention"]["analyticsDays"])
        for days, supported in ((0, False), (1, True), (146000, True), (146001, False)):
            fact = properties(IMMUTABLE, {"immutabilityPeriodSinceCreationInDays": days})
            self.assertEqual(type(fact["operationsImmutability"]["days"]) is int, supported)

    def test_export_selection_minimization_bounds_duplicates_and_missing_defaults(self):
        for value in (None, [], ["a"] * 2, ["a"] * 101, [True], [PRIVATE + "!"], ["bad/name"]):
            self.assertIn("unknown", table_selection(value))
        self.assertEqual(len(table_selection([f"Table{i}" for i in range(100)])), 100)
        self.assertNotIn("Heartbeat", json.dumps(self.bundle()["resources"][3]["properties"]))
        for path in PATHS:
            self.assertIn(
                "unknown", review_fact({path: {"unknown": "denied", "level": "ReadOnly"}}, path)
            )
        for kind, path in (
            (EXPORT, "operationsExport"),
            (LOCK, "operationsLock"),
            (GUEST, "operationsGuestAssignment"),
            (ARC, "operationsArcPatch"),
        ):
            fact = properties(kind, {})[path]
            self.assertNotIn("true", json.dumps(fact).lower())
        self.assertIn("unknown", properties(IMMUTABLE, {})["operationsImmutability"]["state"])
        self.assertIn(
            "unknown",
            tf_properties(
                "azurerm_storage_container_immutability_policy", {"immutability_period_in_days": 1}
            )["operationsImmutability"]["state"],
        )

    def test_arc_os_type_profile_ambiguity_and_terraform_unsupported_no_fake_fields(self):
        for os_name in ("linux", "windows"):
            raw = {
                "osType": os_name,
                "osProfile": {
                    os_name + "Configuration": {
                        "patchSettings": {
                            "assessmentMode": "AutomaticByPlatform",
                            "patchMode": "Manual",
                        }
                    }
                },
            }
            fact = properties(ARC, raw)["operationsArcPatch"]
            self.assertEqual(fact["os"], os_name)
            self.assertEqual(fact["assessmentMode"], "AutomaticByPlatform")
            raw["osProfile"][
                "windowsConfiguration" if os_name == "linux" else "linuxConfiguration"
            ] = {}
            self.assertIn("unknown", properties(ARC, raw)["operationsArcPatch"])
        for os_name in (None, True, [], "Linux", "unsupported"):
            self.assertIn("unknown", properties(ARC, {"osType": os_name})["operationsArcPatch"])
        fact = tf_properties(
            "azurerm_arc_machine",
            {
                "osType": "linux",
                "patch_mode": "AutomaticByPlatform",
                "patch_assessment_mode": "AutomaticByPlatform",
            },
        )
        self.assertIn("unknown", fact["operationsArcPatch"])
        for mode in ("Audit", "ApplyAndMonitor", "ApplyAndAutoCorrect", "DeployAndAutoCorrect"):
            self.assertEqual(
                properties(GUEST, {"guestConfiguration": {"assignmentType": mode}})[
                    "operationsGuestAssignment"
                ]["assignmentType"],
                mode,
            )

    def test_missing_duplicate_wrong_kind_out_of_scope_denied_and_overbound_no_signal(self):
        for change in (
            "missing",
            "duplicate",
            "wrong-kind",
            "out-of-scope",
            "denied",
            "unknown",
            "overbound",
            "subscription-shape",
        ):
            bundle = self.bundle()
            row = bundle["resources"][8]
            bundle["resources"] = [bundle["resources"][0], row]
            if change == "missing":
                row["arm_id"] = None
            elif change == "duplicate":
                bundle["resources"].append(dict(copy.deepcopy(row), logical_id="duplicate"))
            elif change == "wrong-kind":
                row["arm_id"] = WS + "/providers/" + GUEST + "/authored"
            elif change == "out-of-scope":
                row["arm_id"] = row["arm_id"].replace(SCOPE, OTHER)
            elif change in ("denied", "unknown"):
                row["state"] = "inaccessible" if change == "denied" else "unknown"
                row["reason"] = "detail_denied"
            elif change == "subscription-shape":
                row["arm_id"] = SCOPE + "/providers/" + LOCK + "/invalid/child"
            else:
                bundle["resources"] = [bundle["resources"][0]] + [
                    dict(
                        copy.deepcopy(row),
                        logical_id=f"lock{i}",
                        arm_id=WS + "/providers/" + LOCK + f"/lock{i}",
                    )
                    for i in range(101)
                ]
            if change in {"duplicate", "wrong-kind", "subscription-shape"}:
                with self.assertRaises(InputError):
                    self.tier("F01.08", bundle)
                self.assertFalse(prepared_signal(self.control("F01.08"), bundle))
                continue
            self.assertEqual(self.tier("F01.08", bundle)["evidence_tier"], "needs_decision", change)
            context = self.context("F01.08", bundle)
            self.assertTrue(
                all("unknown" in r["facts"]["operationsLock"] for r in context["resources"])
            )
        stale = self.tier("F01.08", at="2026-11-09T23:30:00Z")
        self.assertEqual(stale["evidence_tier"], "needs_decision")

    def test_typed_relationships_require_known_unique_machine_workspace_storage(self):
        for index, key in ((3, "workspace"), (3, "storageDestination"), (7, "machine")):
            for change in ("missing", "duplicate", "denied", "wrong-kind"):
                bundle = self.bundle()
                target = {("workspace", 3): 0, ("storageDestination", 3): 1, ("machine", 7): 5}[
                    (key, index)
                ]
                row = bundle["resources"][target]
                if change == "missing":
                    row["arm_id"] = None
                elif change == "duplicate":
                    bundle["resources"].append(copy.deepcopy(row))
                elif change == "denied":
                    row["state"], row["reason"] = "inaccessible", "detail_denied"
                else:
                    row["resource_type"] = STORAGE if target != 1 else VM
                context = self.config(index, bundle)
                self.assertIn("unknown", context if key not in context else context[key])
        bundle = self.bundle()
        bundle["scope"] = "/providers/microsoft.management/managementgroups/selected"
        self.assertEqual(self.context("F01.03", bundle)["matching_resources"], 0)
        bundle["metadata"] = {"relationships": [{"id": SCOPE, "parent": bundle["scope"]}]}
        self.assertEqual(self.config(3, bundle)["workspace"]["arm_id"], WS)

    def test_lock_scope_control_plane_context_no_criticality_or_management_group_default(self):
        for target in (SCOPE, RG, WS):
            self.assertEqual(lock_scope(target), target)
            identity = tf_resource_id(
                SCOPE, "azurerm_management_lock", {"name": "authored", "scope": target}
            )
            self.assertEqual(identity, target + "/providers/" + LOCK + "/authored")
        for target in (
            None,
            True,
            "bad",
            SCOPE + "suffix",
            "/providers/microsoft.management/managementgroups/root",
            OTHER + "/bad",
            WS + "/child",
        ):
            self.assertIsNone(lock_scope(target))
        for level in ("CanNotDelete", "ReadOnly"):
            self.assertEqual(properties(LOCK, {"level": level})["operationsLock"]["level"], level)
        for level in (None, "NotSpecified", "Delete", True, PRIVATE):
            self.assertIn("unknown", properties(LOCK, {"level": level})["operationsLock"]["level"])

    def test_arm_pinned_versions_extensions_no_new_collector_endpoints(self):
        path = self.root / "arm.json"
        entries = [
            {"type": kind, "name": name, "apiVersion": version, "properties": raw, **extra}
            for kind, name, version, raw, extra in [
                (WORKSPACE, "authored", "2023-09-01", {}, {}),
                (
                    TABLE,
                    "authored/Heartbeat",
                    "2023-09-01",
                    {"plan": "Analytics", "retentionInDays": 30, "totalRetentionInDays": 4383},
                    {},
                ),
                (LOCK, "authored", "2020-05-01", {"level": "CanNotDelete"}, {"scope": WS}),
                (
                    GUEST,
                    "authored",
                    "2024-04-05",
                    {"guestConfiguration": {"assignmentType": "Audit"}},
                    {"scope": MACHINE},
                ),
                (ARC, "authored", "2024-07-10", {}, {}),
            ]
        ]
        path.write_text(json.dumps({"resources": entries}))
        bundle = arm_source(path, scope=RG)
        self.assertTrue(all(r["state"] == "known" for r in bundle["resources"]))
        self.assertEqual(bundle["resources"][2]["arm_id"], WS + "/providers/" + LOCK + "/authored")
        self.assertEqual(
            bundle["resources"][3]["arm_id"], MACHINE + "/providers/" + GUEST + "/authored"
        )
        for entry in entries:
            entry["apiVersion"] = "unreviewed"
        path.write_text(json.dumps({"resources": entries}))
        bundle = arm_source(path, scope=RG)
        self.assertTrue(
            all(r["state"] == "unknown" and not r["properties"] for r in bundle["resources"])
        )
        for target in (OTHER, "/providers/microsoft.management/managementgroups/root"):
            path.write_text(
                json.dumps(
                    {
                        "resources": [
                            {
                                "type": LOCK,
                                "name": "authored",
                                "apiVersion": "2020-05-01",
                                "scope": target,
                                "properties": {"level": "CanNotDelete"},
                            }
                        ]
                    }
                )
            )
            self.assertEqual(arm_source(path, scope=RG)["resources"][0]["state"], "unknown")
        self.assertTrue(
            all(kind not in API_VERSIONS for kind in (ARC, LOCK, GUEST, TABLE, EXPORT, IMMUTABLE))
        )
        requests = []

        def transport(method, url):
            requests.append((method, url))
            return Response(
                200,
                {"value": [{"id": HYBRID, "type": ARC}]} if "/resources?" in url else {"value": []},
                {},
            )

        collected = Collector(transport).collect(
            subscriptions=[SCOPE.split("/")[2]], inventory_authorized=True
        )
        self.assertFalse(any("/machines/" in url.lower() for _, url in requests))
        self.assertTrue(all(not r["properties"] for r in collected["resources"]))
        for kind in (ARC, LOCK, GUEST, TABLE, EXPORT, IMMUTABLE):
            self.assertIn(kind, PLANNED_API_VERSIONS)

    def test_raw_terraform_local_module_and_plan_id_sensitive_values(self):
        module = self.root / "module"
        module.mkdir()
        raw = (
            'resource "azurerm_log_analytics_workspace_table" "table" {\n'
            f'name="Heartbeat"\nworkspace_id="{WS}"\nplan="Analytics"\n'
            "retention_in_days=30\ntotal_retention_in_days=4383\n}\n"
            'resource "azurerm_log_analytics_data_export_rule" "export" {\n'
            f'name="authored"\nworkspace_resource_id="{WS}"\ndestination_resource_id="{STORE}"\n'
            'table_names=["Heartbeat"]\nenabled=true\n}\n'
        )
        (module / "main.tf").write_text(raw)
        bundle = terraform_source(module, scope=SCOPE, provider_version="4.50.0")
        self.assertEqual(bundle["resources"][0]["arm_id"], WS + "/tables/heartbeat")
        self.assertEqual(
            bundle["resources"][1]["properties"]["operationsExport"]["destinationId"], STORE
        )
        wrapper = self.root / "wrapper"
        wrapper.mkdir()
        (wrapper / "main.tf").write_text(
            'module "supplied" {\nsource="example.invalid/ops/azurerm"\nversion="1.0.0"\n}\n'
        )
        manifest = self.root / "snapshots.json"
        manifest.write_text(
            json.dumps(
                {
                    "modules": [
                        {
                            "source": "example.invalid/ops/azurerm",
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
            snapshots=manifest,
            authorized_roots=[self.root],
        )
        self.assertEqual(
            [r["properties"] for r in supplied["resources"]],
            [r["properties"] for r in bundle["resources"]],
        )
        unsupported = terraform_source(module, scope=SCOPE, provider_version="unreviewed")
        self.assertTrue(all(r["state"] == "unknown" for r in unsupported["resources"]))
        path = self.root / "plan.json"
        planned = {
            "format_version": "1.2",
            "terraform_version": "1.14.0",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "mode": "managed",
                            "type": "azurerm_log_analytics_data_export_rule",
                            "address": "azurerm_log_analytics_data_export_rule.authored",
                            "values": {
                                "name": "authored",
                                "workspace_resource_id": WS,
                                "destination_resource_id": STORE,
                                "enabled": True,
                                "table_names": ["Heartbeat"],
                                "private": PRIVATE,
                            },
                        }
                    ]
                }
            },
        }
        path.write_text(json.dumps(planned))
        bundle = plan_source(path, scope=SCOPE, provider_version="4.50.0")
        self.assertEqual(bundle["mode"], "planned")
        row = planned["planned_values"]["root_module"]["resources"][0]
        row["sensitive_values"] = {"table_names": True}
        path.write_text(json.dumps(planned))
        sensitive = plan_source(path, scope=SCOPE, provider_version="4.50.0")
        self.assertIn(
            "unknown",
            sensitive["resources"][0]["properties"]["operationsExport"]["tableFingerprints"],
        )
        self.assertNotIn(PRIVATE, json.dumps(sensitive))
        row["values"]["id"] = OTHER + "/providers/" + EXPORT + "/conflict"
        path.write_text(json.dumps(planned))
        with self.assertRaises(InputError):
            plan_source(path, scope=SCOPE, provider_version="4.50.0")
        for kind in TF_KINDS:
            self.assertIsNone(tf_resource_id(SCOPE, kind, {}))

    def test_guest_lock_immutability_raw_and_plan_surface_parity_and_explicit_units(self):
        examples = [
            (
                "azurerm_policy_virtual_machine_configuration_assignment",
                {
                    "name": "authored",
                    "virtual_machine_id": MACHINE,
                    "configuration": [{"assignment_type": "Audit", "content_uri": PRIVATE}],
                },
                MACHINE + "/providers/" + GUEST + "/authored",
                "operationsGuestAssignment",
            ),
            (
                "azurerm_management_lock",
                {"name": "authored", "scope": WS, "lock_level": "ReadOnly", "notes": PRIVATE},
                WS + "/providers/" + LOCK + "/authored",
                "operationsLock",
            ),
            (
                "azurerm_storage_container_immutability_policy",
                {
                    "storage_container_resource_manager_id": STORE
                    + "/blobservices/default/containers/authored",
                    "immutability_period_in_days": 146000,
                    "locked": True,
                    "protected_append_writes_enabled": False,
                    "protected_append_writes_all_enabled": False,
                },
                STORE + "/blobservices/default/containers/authored/immutabilitypolicies/default",
                "operationsImmutability",
            ),
            (
                "azurerm_arc_machine",
                {
                    "name": "authored",
                    "resource_group_name": "operations",
                    "kind": "SCVMM",
                    "id": HYBRID,
                },
                HYBRID,
                "operationsArcPatch",
            ),
        ]
        root = self.root / "all"
        root.mkdir()
        (root / "main.tf").write_text(
            'resource "azurerm_policy_virtual_machine_configuration_assignment" "authored" {\n'
            f'name="authored"\nvirtual_machine_id="{MACHINE}"\n'
            'configuration {\nassignment_type="Audit"\n}\n}\n'
            'resource "azurerm_management_lock" "authored" {\n'
            f'name="authored"\nscope="{WS}"\nlock_level="ReadOnly"\n}}\n'
            'resource "azurerm_storage_container_immutability_policy" "authored" {\n'
            f'storage_container_resource_manager_id="{STORE}/blobservices/default/containers/authored"\n'
            "immutability_period_in_days=146000\nlocked=true\n"
            "protected_append_writes_enabled=false\nprotected_append_writes_all_enabled=false\n}\n"
            'resource "azurerm_arc_machine" "authored" {\nname="authored"\n'
            'resource_group_name="operations"\nkind="SCVMM"\n}\n'
        )
        raw = terraform_source(root, scope=SCOPE, provider_version="4.50.0")
        self.assertEqual(len(raw["resources"]), 4)
        path = self.root / "all-plan.json"
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
                                for kind, values, _, _ in examples
                            ]
                        }
                    },
                }
            )
        )
        planned = plan_source(path, scope=SCOPE, provider_version="4.50.0")
        for kind, values, identity, field in examples:
            row = next(r for r in planned["resources"] if r["arm_id"] == identity)
            self.assertEqual(row["properties"][field], tf_properties(kind, values)[field])
            self.assertEqual(
                row["properties"][field],
                next(r for r in raw["resources"] if r["arm_id"] == identity)["properties"][field],
            )
            self.assertNotIn(PRIVATE, json.dumps(row))
            if kind in TF_KINDS:
                key = TF_KINDS[kind][0]
                self.assertIsNone(
                    tf_resource_id(
                        SCOPE, kind, dict(values, **{key: values[key].replace(SCOPE, OTHER)})
                    )
                )

    def test_wrong_resource_fact_injection_and_invalid_literals_cannot_supply_signal(self):
        bundle = self.bundle()
        bundle["resources"] = [bundle["resources"][0]]
        bundle["resources"][0]["properties"]["operationsLock"] = {"level": "ReadOnly"}
        self.assertEqual(self.context("F01.08", bundle)["matching_resources"], 0)
        self.assertEqual(self.tier("F01.08", bundle)["evidence_tier"], "needs_decision")
        for kind, path, field in (
            (GUEST, "operationsGuestAssignment", "assignmentType"),
            (ARC, "operationsArcPatch", "assessmentMode"),
            (IMMUTABLE, "operationsImmutability", "state"),
        ):
            for value in (None, True, 1, [], PRIVATE, {"unknown": "denied"}):
                supplied = {field: value}
                if kind == ARC:
                    supplied["os"] = "linux"
                fact = review_fact({path: supplied}, path)
                self.assertIn("unknown", fact[field])
                self.assertNotIn(PRIVATE, json.dumps(fact))

    def test_review_binding_atomicity_time_expiry_outputs_and_session_resume(self):
        question = self.matrix["interview"]
        with patch.dict(
            interviews.BANK,
            {
                question["id"]: {
                    "question": question["question"],
                    "controls": question["controls"],
                }
            },
        ):
            bundle = self.bundle()
            report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
            response = interviews.prepare_interview(report, self.catalog, question["id"], SCOPE)
            self.assertEqual(len(response["decisions"]), 9)
            self.assertTrue(all(r["outcome"] is None for r in response["decisions"]))
            with self.assertRaises(InputError):
                interviews.compile_interview(response, self.catalog, at=AT)
            response.update(
                answer="Authored fixture, not owner assurance.",
                reviewer="Fixture",
                rationale="Nine independent authored decisions.",
                evidence="https://example.invalid/redacted",
                valid_from=AT,
                valid_until="2026-11-07T23:30:00Z",
            )
            for i, decision in enumerate(response["decisions"]):
                decision["outcome"] = "pass" if i % 2 else "fail"
            manual = interviews.compile_interview(response, self.catalog, at=AT)
            for change in (
                "binding",
                "expiry",
                "blank",
                "attribution",
                "scope",
                "selection",
                "duplicate",
                "future",
            ):
                invalid, when = copy.deepcopy(response), AT
                if change == "binding":
                    invalid["decisions"][0]["control_sha256"] = "0" * 64
                elif change == "expiry":
                    when = "2026-11-08T23:30:00Z"
                elif change == "blank":
                    invalid["decisions"][0]["outcome"] = None
                elif change == "scope":
                    invalid["scope"] = OTHER
                elif change == "selection":
                    invalid["decisions"].pop()
                elif change == "duplicate":
                    invalid["decisions"][-1] = invalid["decisions"][0]
                elif change == "future":
                    invalid["valid_from"] = "2026-11-07T23:30:00Z"
                else:
                    invalid["reviewer"] = ""
                with self.assertRaises(InputError):
                    interviews.compile_interview(invalid, self.catalog, at=when)
            exceptions = document(
                "exceptions",
                schema_version="1.1",
                entries=[
                    {k: v for k, v in manual["entries"][0].items() if k != "outcome"}
                    | {"disposition": "accepted"}
                ],
            )
            report = assess(
                bundle,
                self.catalog,
                manual=manual,
                exceptions=exceptions,
                at=AT,
                evidence_tiers=True,
            )
            self.assertTrue(
                all(
                    r["observed"]["evidence_tier"] != "verified"
                    for r in report["results"]
                    if r["control_id"] in CONTROLS
                )
            )
            for format in ("json", "markdown", "html", "csv", "sarif", "pr-summary"):
                self.assertNotIn(PRIVATE, render(report, format))
            with zipfile.ZipFile(io.BytesIO(render_xlsx(report))) as archive:
                self.assertNotIn(
                    PRIVATE, "".join(archive.read(p).decode() for p in archive.namelist())
                )
            session = ReviewSession(
                bundle, self.catalog, self.root / "session", clock=lambda: AT, evidence_tiers=True
            )
            self.assertIn("F01.09", review_page(session.state(), "token", "nonce"))
            invalid = copy.deepcopy(response)
            invalid["decisions"][-1]["outcome"] = None
            with self.assertRaises(InputError):
                session.save_interview({"revision": 0, "response": invalid, "replace_existing": []})
            self.assertEqual(session.revision, 0)
            self.assertFalse((session.directory / "revision-0001").exists())
            session.save_interview({"revision": 0, "response": response, "replace_existing": []})
            self.assertEqual(len(session.state()["records"]), 9)
            resumed = ReviewSession.resume(
                session.directory / "revision-0001", self.root / "resumed", clock=lambda: AT
            )
            self.assertEqual(semantic(session.report), semantic(resumed.report))

    def test_privacy_original_time_replay_preserves_facts_and_rejects_candidate_catalog(self):
        bundle = self.bundle()
        minimized = sanitize_evidence(bundle)
        self.assertNotIn(PRIVATE, json.dumps(minimized))
        for before, after in zip(bundle["resources"], minimized["resources"], strict=True):
            for path in PATHS:
                if path in before["properties"]:
                    self.assertEqual(
                        review_fact(before["properties"], path),
                        review_fact(after["properties"], path),
                    )
        self.assertEqual(
            semantic(assess(bundle, self.catalog, at=AT, evidence_tiers=True)),
            semantic(assess(minimized, self.catalog, at=AT, evidence_tiers=True)),
        )
        for index in range(len(bundle["resources"])):
            self.assertEqual(self.config(index, bundle), self.config(index, minimized))
        directory = self.root / "replay"
        with self.assertRaises(InputError):
            export_bundle(directory, bundle, self.catalog, at=AT, evidence_tiers=True)
        accepted = load_catalog()
        export_bundle(directory, bundle, accepted, at=AT, evidence_tiers=True)
        self.assertEqual(
            semantic(replay_bundle(directory)),
            semantic(assess(bundle, accepted, at=AT, evidence_tiers=True)),
        )
        for upstream in ("F01.01", "F01.03", "F01.04", "F01.08", "F01.09"):
            changed = copy.deepcopy(self.control(upstream))
            changed["evidence_requirements"].append("Changed specific decision")
            self.assertNotEqual(control_digest(changed), control_digest(self.control(upstream)))

    def test_cli_saved_evidence_uses_same_workflows_without_accepted_activation(self):
        evidence, catalog, output = (
            self.root / name for name in ("evidence.json", "catalog.json", "report.json")
        )
        evidence.write_text(json.dumps(self.bundle()))
        catalog.write_text(json.dumps(self.catalog))
        with (
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
            contextlib.redirect_stderr(io.StringIO()),
        ):
            code = main()
        self.assertIn(code, (0, 2))
        report = json.loads(output.read_text())
        self.assertEqual(sum(r["control_id"] in CONTROLS for r in report["results"]), 9)
        self.assertNotIn(PRIVATE, output.read_text())

    @unittest.skipUnless(os.environ.get("BICEP_COMPILER"), "No existing Bicep compiler supplied")
    def test_real_bicep_operations_configuration_without_restore(self):
        path = ROOT / "tests/fixtures/operations/main.bicep"
        compiled = compile_bicep(path, compiler=os.environ["BICEP_COMPILER"])
        self.assertEqual(len(compiled["template"]["resources"]), 5)
        bundle = arm_source(path, scope=RG, bicep=True, compiler=os.environ["BICEP_COMPILER"])
        self.assertTrue(all(r["state"] == "known" for r in bundle["resources"]))
        by_kind = {r["resource_type"].lower(): r for r in bundle["resources"]}
        self.assertEqual(
            by_kind[TABLE]["properties"]["operationsTableRetention"]["totalDays"], 4383
        )
        self.assertEqual(by_kind[LOCK]["arm_id"], WS + "/providers/" + LOCK + "/authored")
        self.assertTrue(by_kind[EXPORT]["properties"]["operationsExport"]["enabled"])
        self.assertEqual(
            self.context("F01.08", bundle)["resources"][0]["facts"]["operationsLock"]["level"],
            "CanNotDelete",
        )
