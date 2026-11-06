import copy
import hashlib
import json
import os
import tempfile
import unittest
import zipfile
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from alz_assessor.arm import API_VERSIONS, PLANNED_API_VERSIONS, arm_source
from alz_assessor.arm import properties as arm_properties
from alz_assessor.azure import Collector, Response
from alz_assessor.bicep import compile_bicep
from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import control_digest, digest, document, validate
from alz_assessor.engine import assess
from alz_assessor.governance_evidence import (
    DASHBOARD_KIND,
    MARKDOWN_PART,
    METRICS_PART,
    MG_KIND,
    PATHS,
    VM_KIND,
    dashboard_summary,
    hierarchy_context,
    projected_properties,
    review_fact,
    summary_fact,
    tag_count,
)
from alz_assessor.interviews import BANK, compile_interview, prepare_interview
from alz_assessor.plan import plan_source
from alz_assessor.replay import export_bundle, replay_bundle, sanitize_evidence, semantic
from alz_assessor.reports import render, render_xlsx
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import review_context
from alz_assessor.sources import terraform_source, tf_properties
from alz_assessor.terraform import InputError
from alz_assessor.tiers import has_fact

ROOT = Path(__file__).resolve().parents[1]
PREPARATION = ROOT / "references" / "preparation"
SUB = "/subscriptions/00000000-0000-0000-0000-000000000001"
SCOPE = SUB + "/resourcegroups/governance"
CAPACITY = SCOPE + "/providers/microsoft.compute/capacityreservationgroups/authored"
MG = "/providers/microsoft.management/managementgroups/platform"
CHILD = "/providers/microsoft.management/managementgroups/not-a-role"
AT = "2026-11-06T12:00:00Z"
SENTINEL = "PRIVATE-NOT-FOR-REPORTING"
GUIDS = {
    "C02.08": "49b82111-2df2-47ee-912e-7f983f630472",
    "C02.09": "2dd69c5b-5c26-422f-94b6-9bad33aad5e8",
    "C02.10": "c68e1d76-6673-413b-9f56-64b5e984a859",
    "C02.11": "c773e7d2-6162-43a7-95a9-17e1f348ef25",
    "C02.12": "ae28c84c-33b6-4b78-88b9-fe5c41049d40",
    "C02.13": "3a923c34-74d0-4001-aac6-a9e01e6a83de",
    "C02.14": "5de32c19-9248-4160-9d5d-1e4e614658d3",
}


class GovernancePreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def write(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def matrix(self):
        return json.loads((PREPARATION / "batch-08.json").read_text("utf-8"))

    def catalog(self):
        catalog = copy.deepcopy(load_catalog())
        rows = {r["guid"]: r for r in self.matrix()["recommendations"]}
        catalog["review_state"] = "authored-in-memory-fixture-not-published"
        for control in catalog["controls"]:
            if control["upstream_guid"] not in rows:
                continue
            row = rows[control["upstream_guid"]]
            for field in ("review_resource_types", "review_fact_paths", "evidence_requirements"):
                if field in row:
                    control[field] = copy.deepcopy(row[field])
            control["rationale"] = row["limitations"]
        return validate(catalog, "catalog")

    def dashboard(self, *, terraform=False):
        parts = [
            {"metadata": {"type": kind, "inputs": [SENTINEL], "settings": {SENTINEL: SENTINEL}}}
            for kind in (METRICS_PART, MARKDOWN_PART, SENTINEL)
        ]
        if terraform:
            return {"lenses": {"0": {"parts": {str(i): p for i, p in enumerate(parts)}}}}
        return {"lenses": [{"parts": parts}]}

    def bundle(self):
        rows = [
            (
                "Microsoft.Compute/virtualMachines",
                SCOPE + "/providers/microsoft.compute/virtualmachines/not-a-domain-controller",
                {"capacityReservation": {"capacityReservationGroup": {"id": CAPACITY}}},
                {"tags": {SENTINEL: SENTINEL}},
            ),
            (
                "Microsoft.Portal/dashboards",
                SCOPE + "/providers/microsoft.portal/dashboards/capacity",
                self.dashboard(),
                {"tags": {}},
            ),
            (
                "Microsoft.Management/managementGroups",
                CHILD,
                {"details": {"parent": {"id": MG}}, "displayName": SENTINEL},
                {},
            ),
            (
                "Microsoft.Authorization/roleAssignments",
                SCOPE + "/providers/microsoft.authorization/roleassignments/authored",
                {
                    "principalType": "Group",
                    "roleDefinitionId": SUB
                    + "/providers/microsoft.authorization/roledefinitions/authored",
                    "principalId": SENTINEL,
                },
                {},
            ),
        ]
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
                {
                    "logical_id": identity,
                    "arm_id": identity,
                    "resource_type": kind,
                    "state": "known",
                    "reason": "",
                    "source_location": "fixture://authored-governance",
                    "properties": arm_properties(kind, values, root=top),
                }
                for kind, identity, values, top in rows
            ],
        )

    def own(self, report):
        return [r for r in report["results"] if r["upstream_id"] in GUIDS]

    def test_exact_seven_guid_preparation_sources_and_pinned_baseline(self):
        fixed = ROOT / "references" / "recommendation-batches" / "targets.json"
        targets = json.loads(fixed.read_text("utf-8"))["targets"]
        self.assertEqual(
            {t["upstream_id"]: t["guid"] for t in targets if t["batch"] == "08"}, GUIDS
        )
        self.assertEqual(
            hashlib.sha256(fixed.read_bytes()).hexdigest(),
            "582fe02feee03b50961e5548fa7551bbd3d8729fbcb68f51837d548e59eaa291",
        )
        matrix = self.matrix()
        self.assertEqual({r["upstream_id"]: r["guid"] for r in matrix["recommendations"]}, GUIDS)
        self.assertEqual(matrix["review_state"], "source-reviewed-preparation-not-accepted")
        self.assertNotIn("catalog_version", matrix)
        self.assertNotIn("accepted_at", matrix)
        accepted = json.loads((fixed.parent / "batch-08.json").read_text("utf-8"))
        self.assertEqual(accepted["catalog_version"], "2026-11-06.10")
        self.assertEqual(accepted["review_state"], "owner-delegated-source-backed-matrix")
        self.assertEqual({r["upstream_id"]: r["guid"] for r in accepted["recommendations"]}, GUIDS)
        manifest = json.loads((PREPARATION / "batch-08-sources.json").read_text("utf-8"))
        sources = {s["id"]: s for s in manifest["sources"]}
        self.assertEqual(len(sources), 24)
        for source in sources.values():
            self.assertRegex(source["sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(source["revision"], r"^[0-9a-f]{40}$")
            self.assertTrue(source["finding"])
            self.assertTrue(source["reuse"])
            self.assertTrue(source["resolved_url"].startswith("https://"))
        self.assertTrue(
            sources["cost-operating-plan"]["resolved_url"].endswith("/manage/administer")
        )
        for row in matrix["recommendations"]:
            self.assertTrue(set(row["sources"]) <= set(sources))
            self.assertNotIn("rule", row)
            self.assertTrue(row["limitations"])
            self.assertTrue(
                any(q.startswith("Reviewer decision:") for q in row["evidence_requirements"])
            )
            self.assertEqual(
                row["classification"],
                "manual" if row["upstream_id"] in {"C02.08", "C02.09", "C02.12"} else "assisted",
            )
        data = ROOT / "src" / "alz_assessor" / "data"
        frozen = data / "catalog-2026-11-06.7.json"
        original = frozen if frozen.exists() else data / "catalog.json"
        self.assertEqual(
            hashlib.sha256(original.read_bytes()).hexdigest(),
            "3e69f21126f9cf94e06d39f7eff2797c3ba1d575d1a89a040ac7ddffdf2572fa",
        )
        self.assertEqual(len(load_catalog()["controls"]), 255)

    def test_tags_are_counts_not_keys_values_defaults_or_cost_taxonomy(self):
        for raw, expected in (({}, 0), ({"arbitrary": SENTINEL}, 1), ({"k": ""}, 1)):
            self.assertEqual(tag_count(raw), expected)
        for raw in (
            None,
            [],
            False,
            {"unknown": "unresolved"},
            {"Owner": "a", "owner": "b"},
            {"": "x"},
            {"key": 1},
            {"key": None},
            {"a/b": "x"},
            {"k": "x" * 257},
            {"k" * 513: "v"},
            {str(i): "v" for i in range(51)},
        ):
            with self.subTest(raw=raw):
                self.assertIn("unknown", tag_count(raw))
        self.assertEqual(tag_count({"x" * 128: "v"}, storage=True), 1)
        self.assertIn("unknown", tag_count({"x" * 129: "v"}, storage=True))
        self.assertEqual(tag_count({str(i): "v" for i in range(50)}), 50)
        self.assertNotIn("tagCount", projected_properties(MG_KIND, {}, root={"tags": {"x": "v"}}))
        self.assertNotIn("tagCount", projected_properties(VM_KIND, {}))
        for raw in (True, -1, 51, 1.0, SENTINEL):
            self.assertFalse(has_fact(review_fact({"tagCount": raw}, "tagCount")))

    def test_dashboard_shapes_privacy_counts_and_no_metric_coverage_claims(self):
        expected = {
            "lensCount": 1,
            "tileCount": 3,
            "metricsChartCount": 1,
            "markdownCount": 1,
            "otherTileCount": 1,
        }
        self.assertEqual(dashboard_summary(self.dashboard()), expected)
        self.assertEqual(
            dashboard_summary(json.dumps(self.dashboard(terraform=True)), terraform=True), expected
        )
        self.assertEqual(summary_fact({**expected, "raw": SENTINEL}), expected)
        self.assertNotIn(SENTINEL, json.dumps(expected))
        self.assertEqual(
            dashboard_summary({"lenses": []}),
            dict.fromkeys(expected, 0),
        )
        for raw in (
            None,
            {},
            {"lenses": {}},
            {"lenses": [{"parts": None}]},
            {"lenses": [{"parts": [None]}]},
            {"lenses": [{"parts": [{"metadata": {"type": True}}]}]},
            {"lenses": [{"parts": []}] * 21},
            {"lenses": [{"parts": [{}] * 101}]},
            {"lenses": [{"parts": [{"metadata": {"type": "x"}}] * 60}] * 2},
        ):
            self.assertFalse(has_fact(dashboard_summary(raw)))
        for raw in ('{"lenses":[],"lenses":[]}', "not JSON", '{"lenses":NaN}', " " * 100001):
            self.assertFalse(has_fact(dashboard_summary(raw, terraform=True)))
        for key in expected:
            changed = {**expected, key: True}
            self.assertFalse(has_fact(summary_fact(changed)))
        self.assertFalse(has_fact(summary_fact({**expected, "tileCount": 99})))
        self.assertFalse(has_fact(summary_fact({**expected, "unknown": "unresolved"})))
        maximum = {
            "lenses": [{"parts": [{"metadata": {"type": METRICS_PART}}] * 5} for _ in range(20)]
        }
        self.assertEqual(dashboard_summary(maximum)["lensCount"], 20)
        self.assertEqual(dashboard_summary(maximum)["tileCount"], 100)
        maximum["lenses"][0]["parts"].append({"metadata": {"type": METRICS_PART}})
        self.assertFalse(has_fact(dashboard_summary(maximum)))
        self.assertFalse(
            has_fact(
                dashboard_summary(
                    {
                        "lenses": [
                            {
                                "parts": [
                                    {"unknown": "unresolved", "metadata": {"type": METRICS_PART}}
                                ]
                            }
                        ]
                    }
                )
            )
        )

    def test_capacity_is_only_an_explicit_typed_reference(self):
        for value in (
            None,
            True,
            "",
            SCOPE,
            SCOPE + "/providers/microsoft.storage/storageaccounts/x",
        ):
            normalized = tf_properties(
                "azurerm_linux_virtual_machine", {"capacity_reservation_group_id": value}
            )
            self.assertFalse(has_fact(normalized["capacityReservationGroupId"]))
        for kind in ("azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine"):
            normalized = tf_properties(
                kind, {"capacity_reservation_group_id": CAPACITY, "tags": {}}
            )
            self.assertEqual(normalized["capacityReservationGroupId"], CAPACITY)
            self.assertEqual(normalized["tagCount"], 0)
            self.assertNotIn("reservedInstance", normalized)
        self.assertNotIn(
            "capacityReservationGroupId", tf_properties("azurerm_linux_virtual_machine", {})
        )
        self.assertFalse(
            has_fact(
                review_fact({"capacityReservationGroupId": SENTINEL}, "capacityReservationGroupId")
            )
        )

    def test_arm_and_terraform_plan_and_literal_source_normalization(self):
        source = self.write(
            "arm.json",
            {
                "resources": [
                    {
                        "type": "Microsoft.Portal/dashboards",
                        "name": "capacity",
                        "apiVersion": "2020-09-01-preview",
                        "tags": {SENTINEL: SENTINEL},
                        "properties": self.dashboard(),
                    },
                    {
                        "type": "Microsoft.Compute/virtualMachines",
                        "name": "vm",
                        "apiVersion": "2024-07-01",
                        "properties": {
                            "capacityReservation": {"capacityReservationGroup": {"id": CAPACITY}},
                            "osProfile": {"adminPassword": SENTINEL},
                        },
                        "tags": {},
                    },
                ]
            },
        )
        normalized = arm_source(source, scope=SCOPE)
        self.assertEqual(normalized["resources"][0]["properties"]["tagCount"], 1)
        self.assertEqual(
            normalized["resources"][1]["properties"]["capacityReservationGroupId"], CAPACITY
        )
        self.assertNotIn(SENTINEL, json.dumps(normalized))
        resources = [
            {
                "address": "azurerm_portal_dashboard.authored",
                "mode": "managed",
                "type": "azurerm_portal_dashboard",
                "values": {
                    "name": "capacity",
                    "resource_group_name": "governance",
                    "dashboard_properties": json.dumps(self.dashboard(terraform=True)),
                    "tags": {SENTINEL: SENTINEL},
                },
            },
            {
                "address": "azurerm_linux_virtual_machine.authored",
                "mode": "managed",
                "type": "azurerm_linux_virtual_machine",
                "values": {
                    "name": "vm",
                    "resource_group_name": "governance",
                    "capacity_reservation_group_id": CAPACITY,
                    "admin_password": SENTINEL,
                },
            },
        ]
        plan = self.write(
            "plan.json",
            {"format_version": "1.2", "planned_values": {"root_module": {"resources": resources}}},
        )
        projected = plan_source(plan, scope=SCOPE, provider_version="4.50.0")
        self.assertEqual(
            projected["resources"][0]["properties"]["dashboardSummary"]["tileCount"], 3
        )
        self.assertEqual(
            projected["resources"][1]["properties"]["capacityReservationGroupId"], CAPACITY
        )
        self.assertNotIn(SENTINEL, json.dumps(projected))
        resources[0]["sensitive_values"] = {"dashboard_properties": True, "tags": True}
        plan.write_text(
            json.dumps(
                {
                    "format_version": "1.2",
                    "planned_values": {"root_module": {"resources": resources}},
                }
            )
        )
        hidden = plan_source(plan, scope=SCOPE, provider_version="4.50.0")
        self.assertFalse(has_fact(hidden["resources"][0]["properties"]["dashboardSummary"]))
        self.assertFalse(has_fact(hidden["resources"][0]["properties"]["tagCount"]))
        hcl = self.root / "source"
        hcl.mkdir()
        (hcl / "main.tf").write_text(
            'resource "azurerm_portal_dashboard" "authored" {\n'
            ' name = "capacity"\n resource_group_name = "governance"\n'
            ' tags = { arbitrary = "PRIVATE-NOT-FOR-REPORTING" }\n'
            ' dashboard_properties = "{\\"lenses\\":{\\"0\\":{\\"parts\\":{}}}}"\n}\n',
            encoding="utf-8",
        )
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            raw = terraform_source(hcl, scope=SCOPE, provider_version="4.50.0")
        props = raw["resources"][0]["properties"]
        self.assertEqual(props["tagCount"], 1)
        self.assertEqual(props["dashboardSummary"]["tileCount"], 0)
        self.assertNotIn(SENTINEL, json.dumps(raw))

    def test_unsupported_versions_and_unresolved_data_do_not_become_facts(self):
        template = self.write(
            "unsupported.json",
            {
                "resources": [
                    {
                        "type": "Microsoft.Portal/dashboards",
                        "apiVersion": "2099-01-01",
                        "name": "x",
                        "properties": self.dashboard(),
                        "tags": {},
                    }
                ]
            },
        )
        bundle = arm_source(template, scope=SCOPE)
        self.assertEqual(bundle["resources"][0]["state"], "unknown")
        self.assertEqual(bundle["resources"][0]["properties"], {})
        self.assertEqual(PLANNED_API_VERSIONS[DASHBOARD_KIND], {"2020-09-01-preview"})
        self.assertNotIn(DASHBOARD_KIND, API_VERSIONS)
        self.assertNotIn(MG_KIND, API_VERSIONS)
        self.assertNotIn(VM_KIND, API_VERSIONS)

    def test_saved_hierarchy_scope_types_cycles_duplicates_and_privacy(self):
        explicit = tf_properties(
            "azurerm_management_group", {"parent_management_group_id": MG, "display_name": SENTINEL}
        )
        self.assertEqual(explicit["managementParentId"], MG)
        self.assertNotIn(SENTINEL, json.dumps(explicit))
        missing = tf_properties("azurerm_management_group", {"name": "identity"})
        self.assertFalse(has_fact(missing["managementParentId"]))
        self.assertEqual(
            arm_properties(
                "Microsoft.Management/managementGroups", {"details": {"parent": {"id": MG}}}
            )["managementParentId"],
            MG,
        )
        bundle = self.bundle()
        bundle["scope"] = MG
        bundle["metadata"] = {
            "relationships": [
                {"id": CHILD, "parent": MG, "displayName": SENTINEL},
                {"id": SUB, "parent": CHILD, "directoryRecords": SENTINEL},
                {"id": SUB, "relationship": "explicit_or_verified_descendant"},
            ],
            "completeness": {"relationships": False},
        }
        expected = hierarchy_context(bundle)
        self.assertEqual(expected["matching_relationships"], 2)
        self.assertFalse(expected["complete"])
        self.assertNotIn(SENTINEL, json.dumps(expected))
        control = next(c for c in self.catalog()["controls"] if c["upstream_id"] == "C02.13")
        context = review_context(control, bundle)
        self.assertEqual(context["saved_management_hierarchy"], expected)
        sanitized = sanitize_evidence(bundle)
        self.assertEqual(review_context(control, sanitized), context)
        self.assertEqual(sanitized["collected_at"], AT)
        for relationships in (
            [{"id": SUB, "parent": SCOPE}],
            [{"id": CHILD, "parent": MG}] * 2,
            [{"id": CHILD, "parent": SUB}],
            [{"id": CHILD, "parent": "/providers/microsoft.management/managementgroups/outside"}],
            [{"id": CHILD, "parent": CHILD}],
            [{"id": CHILD, "parent": MG}] * 101,
            [{"id": SCOPE, "parent": MG}],
            [{"id": SUB}],
            [
                {"id": CHILD, "parent": "/providers/microsoft.management/managementgroups/cycle"},
                {"id": "/providers/microsoft.management/managementgroups/cycle", "parent": CHILD},
            ],
        ):
            changed = copy.deepcopy(bundle)
            changed["metadata"]["relationships"] = relationships
            self.assertIn("unknown", hierarchy_context(changed))
            with self.assertRaisesRegex(InputError, "saved hierarchy"):
                sanitize_evidence(changed)
        changed = copy.deepcopy(bundle)
        changed["scope"] = SCOPE
        self.assertIn("unknown", hierarchy_context(changed))
        self.assertIn("unknown", hierarchy_context(self.bundle()))

    def test_review_types_denied_partial_malformed_and_original_time(self):
        bundle, catalog = self.bundle(), self.catalog()
        dashboard = next(c for c in catalog["controls"] if c["upstream_id"] == "C02.11")
        context = review_context(dashboard, bundle)
        self.assertEqual(context["matching_resources"], 1)
        self.assertFalse(context["inventory_complete"])
        self.assertEqual(context["collected_at"], AT)
        self.assertEqual(context["resources"][0]["facts"]["dashboardSummary"]["tileCount"], 3)
        self.assertNotIn(SENTINEL, json.dumps(context))
        changed = copy.deepcopy(bundle)
        changed["resources"][1].update(state="inaccessible", reason="access_denied")
        self.assertFalse(has_fact(review_context(dashboard, changed)["resources"][0]["facts"]))
        changed = copy.deepcopy(bundle)
        changed["resources"][1]["properties"]["dashboardSummary"] = {"tileCount": True}
        self.assertFalse(has_fact(review_context(dashboard, changed)["resources"][0]["facts"]))
        changed = copy.deepcopy(bundle)
        changed["resources"].append(
            {**copy.deepcopy(bundle["resources"][1]), "logical_id": "duplicate"}
        )
        with self.assertRaisesRegex(InputError, "Duplicate or ambiguous ARM"):
            review_context(dashboard, changed)
        changed = copy.deepcopy(bundle)
        changed["resources"][1]["resource_type"] = "Microsoft.Compute/virtualMachines"
        with self.assertRaisesRegex(InputError, "type does not match"):
            review_context(dashboard, changed)

    def test_all_surface_in_memory_preparation_not_activated_or_verified(self):
        catalog, bundle = self.catalog(), self.bundle()
        before = digest(load_catalog())
        report = assess(bundle, catalog, at=AT, evidence_tiers=True)
        own = self.own(report)
        self.assertEqual(len(own), 7)
        self.assertTrue(all(r["observed"]["outcome"] == "manual" for r in own))
        tiers = {r["upstream_id"]: r["observed"]["evidence_tier"] for r in own}
        self.assertEqual(
            tiers,
            {
                identity: "manual"
                if identity in {"C02.08", "C02.09", "C02.12"}
                else "needs_decision"
                if identity == "C02.13"
                else "signal"
                for identity in GUIDS
            },
        )
        self.assertEqual(sum(report["evidence_tiers"]["counts"].values()), 255)
        for format in ("json", "markdown", "html", "csv", "sarif", "pr-summary"):
            self.assertNotIn(SENTINEL, render(report, format))
        with zipfile.ZipFile(BytesIO(render_xlsx(report))) as archive:
            self.assertNotIn(
                SENTINEL, "".join(archive.read(n).decode() for n in archive.namelist())
            )
        session = ReviewSession(
            bundle, catalog, self.root / "session", clock=lambda: AT, evidence_tiers=True
        )
        self.assertEqual(session.state()["records"], [])
        self.assertEqual(digest(load_catalog()), before)
        for at in ("2000-01-01T00:00:00Z", "2026-11-07T12:00:00Z"):
            changed = copy.deepcopy(bundle)
            changed["collected_at"] = at
            stale = self.own(assess(changed, catalog, at=AT, evidence_tiers=True))
            self.assertTrue(all(r["observed"]["evidence_tier"] != "signal" for r in stale))
            self.assertTrue(all(r["observed"]["outcome"] != "pass" for r in stale))

    def test_blank_interview_separate_content_scope_expiry_and_exception_bindings(self):
        catalog, bundle = self.catalog(), self.bundle()
        report = assess(bundle, catalog, at=AT, evidence_tiers=True)
        question = "authored-governance-fixture-not-registered"
        item = {
            "question": " ".join(
                q
                for row in self.matrix()["recommendations"]
                for q in row["evidence_requirements"]
                if q.startswith("Reviewer decision:")
            ),
            "controls": ["ALZ-" + guid for guid in GUIDS.values()],
        }
        before = copy.deepcopy(BANK)
        with patch.dict(BANK, {question: item}):
            response = prepare_interview(report, catalog, question, SCOPE)
            self.assertEqual(len(response["decisions"]), 7)
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
                answer="Authored fixture, not an actual owner approval.",
                reviewer="Fixture reviewer",
                rationale="Seven separately authored decisions.",
                evidence="https://example.invalid/governance",
                valid_from=AT,
                valid_until="2026-11-07T12:00:00Z",
            )
            for entry in filled["decisions"]:
                entry["outcome"] = "fail"
            manual = compile_interview(filled, catalog, at=AT)
            self.assertEqual(len(manual["entries"]), 7)
            reviewed = assess(bundle, catalog, at=AT, manual=manual, evidence_tiers=True)
            self.assertTrue(all(r["observed"]["outcome"] == "fail" for r in self.own(reviewed)))
            for key, value in (
                ("scope", SUB),
                ("requirements_sha256", "0" * 64),
                ("catalog_sha256", "0" * 64),
                ("valid_until", "2000-01-01T00:00:00Z"),
            ):
                changed = copy.deepcopy(filled)
                changed[key] = value
                with self.assertRaises(InputError):
                    compile_interview(changed, catalog, at=AT)
            changed = copy.deepcopy(filled)
            changed["decisions"][-1]["outcome"] = None
            with self.assertRaises(InputError):
                compile_interview(changed, catalog, at=AT)
            changed = copy.deepcopy(catalog)
            next(c for c in changed["controls"] if c["upstream_id"] == "C02.10")["rationale"] += (
                " Changed."
            )
            with self.assertRaises(InputError):
                compile_interview(filled, changed, at=AT)
            exceptions = document(
                "exceptions",
                schema_version="1.1",
                entries=[
                    {
                        "control_id": manual["entries"][0]["control_id"],
                        "control_sha256": manual["entries"][0]["control_sha256"],
                        "scope": SCOPE,
                        "rationale": "Authored exception, not owner approval.",
                        "reviewer": "Fixture",
                        "evidence": "https://example.invalid/exception",
                        "valid_from": AT,
                        "valid_until": "2026-11-07T12:00:00Z",
                        "disposition": "accepted",
                    }
                ],
            )
            excepted = assess(bundle, catalog, at=AT, exceptions=exceptions, evidence_tiers=True)
            first = next(r for r in self.own(excepted) if r["upstream_id"] == "C02.08")
            self.assertEqual(first["observed"]["outcome"], "manual")
            exception_id = manual["entries"][0]["control_id"]
            excepted_row = next(r for r in self.own(excepted) if r["control_id"] == exception_id)
            self.assertEqual(excepted_row["observed"]["exception_disposition"], "accepted")
        self.assertEqual(BANK, before)

    def test_preparation_replay_refusal_and_exact_packaged_replay(self):
        bundle, catalog = self.bundle(), self.catalog()
        with self.assertRaisesRegex(InputError, "differs from a packaged artifact"):
            export_bundle(self.root / "unaccepted", bundle, catalog, at=AT, evidence_tiers=True)
        projected = sanitize_evidence(bundle)
        self.assertEqual(projected["collected_at"], AT)
        self.assertNotIn(SENTINEL, json.dumps(projected))
        for original, sanitized in zip(bundle["resources"], projected["resources"], strict=True):
            for path in PATHS & original["properties"].keys():
                self.assertEqual(
                    review_fact(original["properties"], path),
                    review_fact(sanitized["properties"], path),
                )
        packaged = load_catalog()
        export_bundle(self.root / "accepted", bundle, packaged, at=AT, evidence_tiers=True)
        replayed = replay_bundle(self.root / "accepted")
        self.assertEqual(
            semantic(replayed), semantic(assess(bundle, packaged, at=AT, evidence_tiers=True))
        )
        self.assertEqual(replayed["evidence"][0]["collected_at"], AT)
        tampered = copy.deepcopy(packaged)
        tampered["controls"][0]["rationale"] += " Tampered."
        with self.assertRaisesRegex(InputError, "differs from a packaged artifact"):
            export_bundle(self.root / "tampered", bundle, tampered, at=AT)

    def test_live_collector_permissions_and_new_resource_reads_not_expanded(self):
        seen = []

        def transport(method, url, body=None):
            seen.append((method, url))
            if "/resources?" in url:
                return Response(
                    200,
                    {
                        "value": [
                            {
                                "id": SCOPE + "/providers/microsoft.portal/dashboards/authored",
                                "type": "Microsoft.Portal/dashboards",
                            }
                        ]
                    },
                    {},
                )
            return Response(200, {"value": []}, {})

        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            bundle = Collector(transport).collect(
                subscriptions=[SUB.split("/")[2]], inventory_authorized=True
            )
        self.assertTrue(all("microsoft.portal/dashboards" not in url.lower() for _, url in seen))
        self.assertTrue(
            all(
                "billing" not in url.lower()
                and "usage" not in url.lower()
                and "quota" not in url.lower()
                for _, url in seen
            )
        )
        self.assertFalse(has_fact(bundle["resources"][0]["properties"].get("dashboardSummary")))

    def accepted_catalog(self):
        data = ROOT / "src" / "alz_assessor" / "data"
        frozen = data / "catalog-2026-11-06.10.json"
        return load_catalog(str(frozen)) if frozen.exists() else load_catalog()

    def scoped_bundle(self):
        bundle = self.bundle()
        bundle["scope"] = MG
        bundle["metadata"] = {
            "relationships": [{"id": CHILD, "parent": MG}, {"id": SUB, "parent": CHILD}],
            "completeness": {"relationships": False},
        }
        return bundle

    def test_accepted_exact_successor_preserves_all_predecessor_control_objects_and_sources(self):
        data = ROOT / "src" / "alz_assessor" / "data"
        for name, expected in (
            (
                "catalog-2026-11-06.9.json",
                "5f678970f45fcd9ac635576d31cfe0f896c97199d11552d2061886aaa441004c",
            ),
            (
                "crosswalk-2026-11-06.9.json",
                "9cc735acb396ba27bfccc2a017ec1cc1c1a1ea6eba9f3f86185814fea5c6b519",
            ),
        ):
            self.assertEqual(hashlib.sha256((data / name).read_bytes()).hexdigest(), expected)
        before = load_catalog(str(data / "catalog-2026-11-06.9.json"))
        catalog = self.accepted_catalog()
        self.assertEqual(catalog["catalog_version"], "2026-11-06.10")
        self.assertEqual(len(catalog["controls"]), 255)
        previous = {c["upstream_guid"]: c for c in before["controls"]}
        for control in catalog["controls"]:
            if control["upstream_guid"] not in GUIDS.values():
                self.assertEqual(control, previous[control["upstream_guid"]])
        original = load_catalog(str(data / "catalog-2026-11-04.2.json"))
        for control in original["controls"]:
            if control["automation"] == "automated":
                retained = next(
                    c for c in catalog["controls"] if c["control_id"] == control["control_id"]
                )
                self.assertEqual(retained, previous[control["upstream_guid"]])
                self.assertEqual(control_digest(retained), control_digest(control))
        old_crosswalk = json.loads((data / "crosswalk-2026-11-06.9.json").read_text("utf-8"))
        current = json.loads((data / "crosswalk.json").read_text("utf-8"))
        self.assertEqual(current["entries"], old_crosswalk["entries"])
        self.assertEqual(current["sources"], old_crosswalk["sources"])
        accepted_sources = ROOT / "references" / "recommendation-batches" / "batch-08-sources.json"
        self.assertEqual(
            accepted_sources.read_bytes(), (PREPARATION / "batch-08-sources.json").read_bytes()
        )
        self.assertEqual(
            hashlib.sha256(accepted_sources.read_bytes()).hexdigest(),
            "0bec744bf862cb3689b9962a1672dd05ff82f68dd3d3cdf28ea2de8124cb89fb",
        )

    def test_accepted_all_surfaces_bank_replay_session_and_seven_independent_decisions(self):
        catalog, bundle = self.accepted_catalog(), self.scoped_bundle()
        report = assess(bundle, catalog, at=AT, evidence_tiers=True)
        own = self.own(report)
        self.assertEqual(len(own), 7)
        self.assertTrue(all(r["observed"]["outcome"] == "manual" for r in own))
        self.assertEqual(
            {r["upstream_id"]: r["observed"]["evidence_tier"] for r in own},
            {
                identity: "manual" if identity in {"C02.08", "C02.09", "C02.12"} else "signal"
                for identity in GUIDS
            },
        )
        for format in ("json", "markdown", "html", "csv", "sarif", "pr-summary"):
            self.assertNotIn(SENTINEL, render(report, format))
        with zipfile.ZipFile(BytesIO(render_xlsx(report))) as archive:
            self.assertNotIn(
                SENTINEL, "".join(archive.read(n).decode() for n in archive.namelist())
            )
        export_bundle(self.root / "accepted-cohort08", bundle, catalog, at=AT, evidence_tiers=True)
        replayed = replay_bundle(self.root / "accepted-cohort08")
        self.assertEqual(semantic(replayed), semantic(report))
        identity = next(c for c in catalog["controls"] if c["upstream_id"] == "C02.13")
        self.assertEqual(
            review_context(identity, bundle), review_context(identity, sanitize_evidence(bundle))
        )
        session = ReviewSession(
            bundle, catalog, self.root / "accepted-session", clock=lambda: AT, evidence_tiers=True
        )
        self.assertEqual(session.state()["records"], [])
        response = prepare_interview(report, catalog, "resource-cost-governance", MG)
        self.assertEqual(len(response["decisions"]), 7)
        self.assertTrue(all(d["outcome"] is None for d in response["decisions"]))
        self.assertIsNone(response["answer"])
        with self.assertRaises(InputError):
            compile_interview(response, catalog, at=AT)
        response.update(
            answer="Authored offline acceptance fixture, not an owner approval.",
            reviewer="Fixture reviewer",
            rationale="Seven distinct fixture decisions.",
            evidence="https://example.invalid/cohort08",
            valid_from=AT,
            valid_until="2026-11-07T12:00:00Z",
        )
        for row in response["decisions"]:
            row["outcome"] = "fail"
        manual = compile_interview(response, catalog, at=AT)
        reviewed = assess(bundle, catalog, at=AT, manual=manual, evidence_tiers=True)
        self.assertTrue(all(r["observed"]["outcome"] == "fail" for r in self.own(reviewed)))
        self.assertTrue(
            all(r["observed"]["evidence_tier"] != "verified" for r in self.own(reviewed))
        )
        for binding in ("catalog_sha256", "requirements_sha256"):
            changed = copy.deepcopy(response)
            changed[binding] = "0" * 64
            with self.assertRaises(InputError):
                compile_interview(changed, catalog, at=AT)
        control_ids = {c["control_id"]: c for c in catalog["controls"]}
        self.assertTrue(
            all(
                e["control_sha256"] == control_digest(control_ids[e["control_id"]])
                for e in manual["entries"]
            )
        )

    def test_accepted_unbound_foreign_missing_and_stale_resources_supply_no_signal(self):
        catalog, bundle = self.accepted_catalog(), self.bundle()
        for mode in ("unbound", "foreign", "missing", "stale", "denied"):
            changed = copy.deepcopy(bundle)
            if mode == "missing":
                changed["resources"] = []
            elif mode == "stale":
                changed["collected_at"] = "2000-01-01T00:00:00Z"
            else:
                for resource in changed["resources"]:
                    if mode == "unbound":
                        resource["arm_id"] = None
                    elif mode == "foreign":
                        resource["arm_id"] = resource["arm_id"].replace(
                            SUB, "/subscriptions/00000000-0000-0000-0000-000000000099"
                        )
                    elif mode == "denied":
                        resource.update(state="inaccessible", reason="access_denied")
            report = self.own(assess(changed, catalog, at=AT, evidence_tiers=True))
            self.assertTrue(all(r["observed"]["outcome"] != "pass" for r in report))
            self.assertTrue(all(r["observed"]["evidence_tier"] != "signal" for r in report))
        bad = self.scoped_bundle()
        bad["metadata"] = {"scopes": [SUB]}
        report = self.own(assess(bad, catalog, at=AT, evidence_tiers=True))
        self.assertTrue(all(r["observed"]["evidence_tier"] != "signal" for r in report))

    def test_all_99_prior_own_guid_receipts_remain_exact(self):
        ledger = json.loads(
            (ROOT / "references" / "recommendation-batches" / "ledger.json").read_text("utf-8")
        )
        earlier = {"01", "04", "11", "12", "13", "14", "15", "17", "18", "19", "22"}
        rows = [row for row in ledger["recommendations"] if row["batch"] in earlier]
        receipts = {key: value for key, value in ledger["deliveries"].items() if key in earlier}
        self.assertEqual(len(rows), 99)
        self.assertTrue(all(row["status"] == "merged" for row in rows))
        self.assertEqual(
            digest(rows), "0ac124b55e2e59e0e38d54b2902ee370175d5694d57c05afaf49b9e455a8b4de"
        )
        self.assertEqual(
            digest(receipts), "f29ea9fe2a724da9e94dfa274a5cf319f39c06f999e735c87c953a57e43193bb"
        )

    @unittest.skipUnless(os.environ.get("BICEP_COMPILER"), "existing Bicep compiler not supplied")
    def test_real_bicep_governance_without_restore(self):
        source = ROOT / "tests" / "fixtures" / "governance" / "main.bicep"
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch("socket.socket.connect", side_effect=AssertionError("network forbidden")),
        ):
            copied = Path(temporary) / "main.bicep"
            copied.write_bytes(source.read_bytes())
            compiled = compile_bicep(copied, compiler=os.environ["BICEP_COMPILER"])
            bundle = arm_source(
                copied, scope=SCOPE, bicep=True, compiler=os.environ["BICEP_COMPILER"]
            )
        self.assertEqual(len(compiled["template"]["resources"]), 2)
        dashboard = next(
            r for r in bundle["resources"] if r["resource_type"].lower() == DASHBOARD_KIND
        )
        vm = next(r for r in bundle["resources"] if r["resource_type"].lower() == VM_KIND)
        self.assertEqual(dashboard["properties"]["dashboardSummary"]["markdownCount"], 1)
        self.assertEqual(dashboard["properties"]["dashboardSummary"]["metricsChartCount"], 0)
        self.assertEqual(vm["properties"]["capacityReservationGroupId"], CAPACITY)
        self.assertEqual(vm["properties"]["tagCount"], 0)
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), before)
        self.assertFalse(source.with_suffix(".json").exists())


if __name__ == "__main__":
    unittest.main()
