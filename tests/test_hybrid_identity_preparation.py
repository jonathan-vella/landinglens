import contextlib
import copy
import hashlib
import io
import json
import os
import runpy
import subprocess
import sys
import tempfile
import unittest
import zipfile
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from alz_assessor.arm import API_VERSIONS, PLANNED_API_VERSIONS, arm_source, properties
from alz_assessor.azure import Collector, Response
from alz_assessor.bicep import compile_bicep
from alz_assessor.catalog import load_catalog
from alz_assessor.cli import main
from alz_assessor.comparison import compare
from alz_assessor.contracts import digest, document, validate
from alz_assessor.engine import assess
from alz_assessor.identity_evidence import (
    HYBRID_GUIDS,
    PEERING_KIND,
    VAULT_KIND,
    VNET_KIND,
    hybrid_context,
)
from alz_assessor.interviews import BANK, compile_interview, prepare_interview
from alz_assessor.plan import plan_source
from alz_assessor.replay import export_bundle, replay_bundle, sanitize_evidence, semantic
from alz_assessor.reports import render, render_xlsx
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import review_context
from alz_assessor.sources import terraform_source, tf_properties
from alz_assessor.terraform import InputError, tree_hash

ROOT = Path(__file__).resolve().parents[1]
PREPARATION = ROOT / "references" / "preparation"
SUB = "/subscriptions/00000000-0000-0000-0000-000000000001"
RG = SUB + "/resourcegroups/authored"
NETWORK = RG + "/providers/" + VNET_KIND + "/"
LOCAL, REMOTE = NETWORK + "local", NETWORK + "remote"
PEERING = LOCAL + "/virtualnetworkpeerings/authored"
VAULT = RG + "/providers/" + VAULT_KIND + "/authored"
AT = "2026-11-06T19:00:00Z"
UNTIL = "2026-11-07T19:00:00Z"
PRIVATE = "PRIVATE-NOT-FOR-REPORTING"
OWN = {
    "B03.16": "cd163e39-84a5-4b39-97b7-6973abd70d94",
    "B03.17": "35037e68-9349-4c15-b371-228514f4cdff",
    "B03.18": "d5d1e4e6-1465-48d3-958f-d77249b82111",
    "B04.01": "9cf5418b-1520-4b7b-add7-88eb28f833e8",
    "B04.02": "d4d1ad54-1abc-4919-b267-3f342d3b49e4",
    "B04.03": "d505ebcb-79b1-4274-9c0d-a27c8bea489c",
    "B04.04": "0ce74f19-9abb-47e4-ae95-6b057a1d2be9",
    "B05.01": "1770a2ac-c194-4e5c-ade4-82939d38a510",
}


class HybridIdentityPreparationTests(unittest.TestCase):
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
        return json.loads((PREPARATION / "batch-06.json").read_text("utf-8"))

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

    def bundle(self):
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
                    "source_location": "fixture://authored-hybrid-identity",
                    "properties": properties(kind, values),
                }
                for kind, identity, values in (
                    (VNET_KIND, LOCAL, {}),
                    (VNET_KIND, REMOTE, {}),
                    (
                        PEERING_KIND,
                        PEERING,
                        {
                            "allowVirtualNetworkAccess": True,
                            "remoteVirtualNetwork": {"id": REMOTE},
                            "identityOwner": PRIVATE,
                        },
                    ),
                    (
                        VAULT_KIND,
                        VAULT,
                        {
                            "enableRbacAuthorization": True,
                            "tenantId": PRIVATE,
                            "accessPolicies": [{"objectId": PRIVATE}],
                            "secret": PRIVATE,
                        },
                    ),
                )
            ],
        )

    def context(self, bundle, index):
        by_id = {}
        for row in bundle["resources"]:
            by_id.setdefault((row.get("arm_id") or "").lower(), []).append(row)
        return hybrid_context(bundle["resources"][index], by_id, bundle)

    def interview(self, report, catalog):
        key = "authored-hybrid-identity-not-registered"
        item = {
            "question": " ".join(
                q
                for row in self.matrix()["recommendations"]
                for q in row["evidence_requirements"]
                if q.startswith("Reviewer decision:")
            ),
            "controls": ["ALZ-" + guid for guid in OWN.values()],
        }
        return patch.dict(BANK, {key: item}), key

    def test_exact_fixed_membership_sources_and_no_activation(self):
        targets = ROOT / "references" / "recommendation-batches" / "targets.json"
        rows = json.loads(targets.read_text("utf-8"))["targets"]
        self.assertEqual({r["upstream_id"]: r["guid"] for r in rows if r["batch"] == "06"}, OWN)
        self.assertEqual(HYBRID_GUIDS, set(OWN.values()))
        self.assertEqual(
            hashlib.sha256(targets.read_bytes()).hexdigest(),
            "582fe02feee03b50961e5548fa7551bbd3d8729fbcb68f51837d548e59eaa291",
        )
        matrix = self.matrix()
        self.assertEqual(matrix["review_state"], "source-reviewed-preparation-not-accepted")
        self.assertNotIn("catalog_version", matrix)
        self.assertNotIn("accepted_at", matrix)
        self.assertNotIn("interview", matrix)
        self.assertEqual({r["upstream_id"]: r["guid"] for r in matrix["recommendations"]}, OWN)
        sources = json.loads((PREPARATION / "batch-06-sources.json").read_text("utf-8"))
        self.assertEqual(sources["review_state"], "preparation-only-reviewed")
        self.assertEqual(len(sources["sources"]), 20)
        indexed = {s["id"]: s for s in sources["sources"]}
        for source in indexed.values():
            self.assertRegex(source["sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(source["revision"], r"^[0-9a-f]{40}$")
            self.assertTrue(source["reuse"] and source["finding"])
            self.assertTrue(source["resolved_url"].startswith("https://"))
        for row in matrix["recommendations"]:
            self.assertTrue(set(row["sources"]) <= set(indexed))
            self.assertNotIn("rule", row)
            self.assertEqual(
                row["classification"], "manual" if row["upstream_id"] == "B05.01" else "assisted"
            )
        frozen = files("alz_assessor").joinpath("data", "catalog-2026-11-06.16.json")
        predecessor = load_catalog(str(frozen)) if frozen.is_file() else load_catalog()
        self.assertEqual(predecessor["catalog_version"], "2026-11-06.16")
        self.assertTrue(
            all(
                not c.get("review_fact_paths")
                for c in predecessor["controls"]
                if c["upstream_guid"] in HYBRID_GUIDS
            )
        )
        self.assertTrue(
            all(
                not c.get("review_fact_paths")
                for c in predecessor["controls"]
                if c["upstream_guid"] in HYBRID_GUIDS
            )
        )

    def test_source_specific_questions_preserve_current_qualifications(self):
        indexed = {
            r["upstream_id"]: " ".join(r["evidence_requirements"])
            for r in self.matrix()["recommendations"]
        }
        for display, markers in {
            "B03.16": ("Cloud Sync", "catch-up", "only one active", "pending-export"),
            "B03.17": ("synced-account exception", "active/eligible", "on-premises compromise"),
            "B03.18": ("404", "three preferred", "platform service ownership", "SSO"),
            "B04.01": ("both-direction", "authentication", "Entra-native", "isolation"),
            "B04.02": ("2026-02-01", "SQL principals", "storage", "outage"),
            "B04.03": ("start-time snapshots", "applied", "nested-group", "Workload ID"),
            "B04.04": ("2026-11-16", "one account owner", "MCA/CSP", "DG/SG"),
            "B05.01": ("unknown countries", "exported/downloaded", "eligibility", "exceptions"),
        }.items():
            for marker in markers:
                self.assertIn(marker.lower(), indexed[display].lower())

    def test_preparation_activation_and_unguarded_recapture_are_refused(self):
        apply_batch = runpy.run_path(str(ROOT / "tools" / "build_batches.py"))["apply_batch"]
        for state in ("source-reviewed-preparation-not-accepted", "preparation-only-reviewed"):
            with self.assertRaisesRegex(ValueError, "Preparation matrices cannot activate"):
                apply_batch({}, {}, {}, {**self.matrix(), "review_state": state}, [], [])
        before = (PREPARATION / "batch-06-sources.json").read_bytes()
        for arguments, expected in (
            ([], "require --preparation-only"),
            (["--preparation-only"], "Frozen source review exists"),
        ):
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools" / "review_batch_sources.py"),
                    "--batch",
                    "06",
                    *arguments,
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(expected, result.stderr)
        self.assertEqual((PREPARATION / "batch-06-sources.json").read_bytes(), before)

    def test_only_real_existing_resource_apis_no_directory_transport(self):
        self.assertEqual(PLANNED_API_VERSIONS[PEERING_KIND], {"2024-05-01"})
        self.assertEqual(PLANNED_API_VERSIONS[VAULT_KIND], {"2024-11-01"})
        self.assertEqual(API_VERSIONS[PEERING_KIND], {"2024-05-01"})
        for kind in API_VERSIONS:
            self.assertFalse(
                any(token in kind for token in ("pim", "billing", "appproxy", "graph"))
            )

    def test_peering_requires_both_unique_known_typed_in_boundary_vnets(self):
        bundle = self.bundle()
        result = self.context(bundle, 2)
        self.assertEqual(result["source_vnet_id"], LOCAL)
        self.assertEqual(
            result["facts"],
            {"allowVirtualNetworkAccess": True, "remoteVirtualNetwork.id": REMOTE},
        )
        for index in (0, 1, 2):
            for key, value in (("state", "unknown"), ("resource_type", VAULT_KIND)):
                changed = copy.deepcopy(bundle)
                changed["resources"][index][key] = value
                self.assertIn("unknown", self.context(changed, 2))
            changed = copy.deepcopy(bundle)
            changed["resources"].append(copy.deepcopy(changed["resources"][index]))
            self.assertIn("unknown", self.context(changed, 2))
        for identity in (LOCAL, PRIVATE, True, None, REMOTE.replace(SUB, SUB[:-1] + "2")):
            changed = copy.deepcopy(bundle)
            changed["resources"][2]["properties"]["remoteVirtualNetwork"]["id"] = identity
            self.assertIn("unknown", self.context(changed, 2))
        changed = copy.deepcopy(bundle)
        changed["scope"] = RG + "-other"
        self.assertIn("unknown", self.context(changed, 2))

    def test_missing_and_over_bound_population_not_absence(self):
        bundle = self.bundle()
        bundle["resources"][2]["properties"] = {}
        self.assertIn("unknown", self.context(bundle, 2))
        bundle = self.bundle()
        for index in range(100):
            row = copy.deepcopy(bundle["resources"][2])
            row["arm_id"] = row["logical_id"] = PEERING + str(index)
            bundle["resources"].append(row)
        self.assertIn("over_100", self.context(bundle, 2)["unknown"])
        row = next(
            r
            for r in self.own(assess(bundle, self.catalog(), at=AT, evidence_tiers=True))
            if r["upstream_id"] == "B04.01"
        )
        self.assertEqual(row["observed"]["evidence_tier"], "needs_decision")
        context = review_context(self.control("B04.01"), bundle)
        self.assertTrue(context["truncated"])
        self.assertEqual(context["matching_resources"], 101)

    def test_vault_boolean_types_no_default_and_no_cross_kind_fact(self):
        for identity in (
            VAULT.replace("/resourcegroups/authored", ""),
            VAULT + "/secrets/unsupported",
        ):
            bundle = self.bundle()
            bundle["resources"][3]["arm_id"] = identity
            self.assertIn("unknown", self.context(bundle, 3))
        for value in (True, False, None, "true", 1, [], {"unknown": "denied"}):
            bundle = self.bundle()
            bundle["resources"][3]["properties"]["enableRbacAuthorization"] = value
            fact = self.context(bundle, 3)["facts"]["enableRbacAuthorization"]
            if type(value) is bool:
                self.assertIs(fact, value)
            else:
                self.assertIn("unknown", fact)
        bundle = self.bundle()
        bundle["resources"][3]["properties"] = {}
        self.assertIn("unknown", self.context(bundle, 3)["facts"]["enableRbacAuthorization"])
        bundle["resources"][3]["properties"] = {
            "allowVirtualNetworkAccess": True,
            "humanConfirmed": True,
            "effectiveDataAccess": True,
        }
        row = next(
            r
            for r in self.own(assess(bundle, self.catalog(), at=AT, evidence_tiers=True))
            if r["upstream_id"] == "B04.02"
        )
        self.assertEqual(row["observed"]["evidence_tier"], "needs_decision")

    def test_saved_mg_edges_are_required_not_bare_management_scope(self):
        bundle = self.bundle()
        mg = "/providers/microsoft.management/managementgroups/authored"
        bundle["scope"] = mg
        self.assertIn("unknown", self.context(bundle, 2))
        bundle["metadata"] = {"relationships": [{"id": SUB, "parent": mg}]}
        self.assertEqual(self.context(bundle, 2)["facts"]["remoteVirtualNetwork.id"], REMOTE)
        bundle["metadata"]["relationships"].append({"id": SUB, "parent": mg})
        self.assertIn("unknown", self.context(bundle, 2))

    def test_review_selection_context_is_partial_and_does_not_designate_roles(self):
        bundle = self.bundle()
        for display, size in (("B04.01", 1), ("B04.02", 1), ("B03.16", 0), ("B04.03", 0)):
            context = review_context(self.control(display), bundle)
            self.assertEqual(len(context["resources"]), size)
            self.assertFalse(context["inventory_complete"])
            self.assertEqual(context["collected_at"], AT)
        context = review_context(self.control("B04.01"), bundle)["resources"][0]
        self.assertEqual(context["facts"], self.context(bundle, 2)["facts"])
        self.assertEqual(context["subchecks"], {})
        self.assertIn("neither VNet is designated", context["hybrid_configuration"]["warning"])
        bundle["scope"] = RG + "-other"
        self.assertEqual(review_context(self.control("B04.01"), bundle)["unbound_resources"], 1)

    def test_existing_arm_terraform_and_plan_projection_no_private_material(self):
        kinds = (
            (
                "azurerm_virtual_network_peering",
                PEERING_KIND,
                PEERING,
                {
                    "name": "authored",
                    "resource_group_name": "authored",
                    "virtual_network_name": "local",
                    "remote_virtual_network_id": REMOTE,
                    "allow_virtual_network_access": False,
                },
            ),
            (
                "azurerm_key_vault",
                VAULT_KIND,
                VAULT,
                {
                    "name": "authored",
                    "resource_group_name": "authored",
                    "rbac_authorization_enabled": False,
                    "tenant_id": PRIVATE,
                    "access_policy": [{"object_id": PRIVATE}],
                },
            ),
        )
        plan = {
            "format_version": "1.2",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "mode": "managed",
                            "address": kind + ".authored",
                            "type": kind,
                            "values": {**values, "id": identity},
                        }
                        for kind, _, identity, values in kinds
                    ]
                }
            },
        }
        module = self.root / "module"
        self.write(
            "module/main.tf.json",
            {"resource": {kind: {"authored": values} for kind, _, _, values in kinds}},
        )
        self.write(
            "source/main.tf.json",
            {
                "module": {
                    "hybrid": {"source": "example.invalid/hybrid/azurerm", "version": "1.0.0"}
                }
            },
        )
        manifest = self.write(
            "snapshots.json",
            {
                "modules": [
                    {
                        "source": "example.invalid/hybrid/azurerm",
                        "version": "1.0.0",
                        "subdirectory": "",
                        "path": "module",
                        "sha256": tree_hash(module),
                    }
                ]
            },
        )
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            raw = terraform_source(
                self.root / "source",
                scope=SUB,
                provider_version="4.50.0",
                snapshots=manifest,
                authorized_roots=[self.root],
            )
            planned = plan_source(
                self.write("plan.json", plan), scope=SUB, provider_version="4.50.0"
            )
        for bundle in (raw, planned):
            self.assertEqual(len(bundle["resources"]), 2)
            self.assertNotIn(PRIVATE, json.dumps(bundle))
            for row, (kind, _, identity, values) in zip(bundle["resources"], kinds, strict=True):
                self.assertEqual(row["arm_id"], identity)
                self.assertEqual(row["properties"], tf_properties(kind, values))
        self.assertEqual(raw["resources"][1]["properties"]["enableRbacAuthorization"], False)
        plan["planned_values"]["root_module"]["resources"][1]["sensitive_values"] = {
            "rbac_authorization_enabled": True
        }
        sensitive = plan_source(
            self.write("sensitive.json", plan), scope=SUB, provider_version="4.50.0"
        )
        self.assertIn("unknown", sensitive["resources"][1]["properties"]["enableRbacAuthorization"])
        plan["planned_values"]["root_module"]["resources"][0]["values"]["id"] = PEERING.replace(
            SUB, SUB[:-1] + "2"
        )
        with self.assertRaises(InputError):
            plan_source(self.write("conflict.json", plan), scope=SUB, provider_version="4.50.0")

    def test_one_engine_tiers_all_outputs_time_and_planned_observed_separation(self):
        bundle, catalog = self.bundle(), self.catalog()
        report = assess(bundle, catalog, at=AT, evidence_tiers=True)
        own = self.own(report)
        self.assertEqual(len(own), 8)
        self.assertTrue(all(r["observed"]["outcome"] == "manual" for r in own))
        self.assertEqual(
            {r["upstream_id"]: r["observed"]["evidence_tier"] for r in own},
            {
                key: "manual"
                if key == "B05.01"
                else "signal"
                if key in {"B04.01", "B04.02"}
                else "needs_decision"
                for key in OWN
            },
        )
        for format in ("json", "markdown", "html", "csv", "sarif", "pr-summary"):
            self.assertNotIn(PRIVATE, render(report, format))
        with zipfile.ZipFile(io.BytesIO(render_xlsx(report))) as archive:
            self.assertNotIn(PRIVATE, "".join(archive.read(n).decode() for n in archive.namelist()))
        for when in ("2000-01-01T00:00:00Z", UNTIL):
            changed = copy.deepcopy(bundle)
            changed["collected_at"] = when
            self.assertTrue(
                all(
                    r["observed"]["evidence_tier"] not in {"signal", "verified"}
                    for r in self.own(assess(changed, catalog, at=AT, evidence_tiers=True))
                )
            )
        planned = copy.deepcopy(bundle)
        planned["mode"], planned["source"] = "planned", "arm"
        planned["resources"][3]["properties"]["enableRbacAuthorization"] = False
        combined = compare(assess(planned, catalog, at=AT, evidence_tiers=True), report, at=AT)
        self.assertTrue(all(r["planned"] and r["observed"] for r in self.own(combined)))
        self.assertTrue(all(r["planned"]["outcome"] == "manual" for r in self.own(combined)))

    def test_eight_independent_blank_interview_decisions_binding_and_attribution(self):
        catalog, bundle = self.catalog(), self.bundle()
        report = assess(bundle, catalog, at=AT, evidence_tiers=True)
        manager, key = self.interview(report, catalog)
        before = copy.deepcopy(BANK)
        with manager:
            template = prepare_interview(report, catalog, key, SUB)
            self.assertEqual(len(template["decisions"]), 8)
            self.assertTrue(all(d["outcome"] is None for d in template["decisions"]))
            self.assertTrue(
                all(
                    template[k] is None
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
                compile_interview(template, catalog, at=AT)
            filled = copy.deepcopy(template)
            filled.update(
                answer="Authored fixture, not owner approval.",
                reviewer="Fixture reviewer",
                rationale="Eight independent fixture decisions.",
                evidence="https://example.invalid/review",
                valid_from=AT,
                valid_until=UNTIL,
            )
            for decision in filled["decisions"]:
                decision["outcome"] = "fail"
                if decision["control_id"] == "ALZ-" + OWN["B03.18"]:
                    decision["outcome"] = "not_applicable"
            reviews = compile_interview(filled, catalog, at=AT)
            self.assertEqual(len(reviews["entries"]), 8)
            report = assess(bundle, catalog, at=AT, manual=reviews, evidence_tiers=True)
            own = self.own(report)
            self.assertEqual(
                next(r for r in own if r["upstream_id"] == "B03.18")["observed"]["outcome"],
                "not_applicable",
            )
            self.assertTrue(all(r["observed"]["evidence_tier"] != "verified" for r in own))
            for field, value in (
                ("scope", RG),
                ("reviewer", ""),
                ("evidence", ""),
                ("valid_until", AT),
                ("catalog_sha256", "0" * 64),
                ("requirements_sha256", "0" * 64),
            ):
                with self.assertRaises(InputError):
                    compile_interview({**filled, field: value}, catalog, at=AT)
            changed = copy.deepcopy(filled)
            changed["decisions"][-1]["outcome"] = None
            with self.assertRaises(InputError):
                compile_interview(changed, catalog, at=AT)
            changed = copy.deepcopy(catalog)
            next(c for c in changed["controls"] if c["upstream_id"] == "B03.16")["rationale"] += (
                " Changed."
            )
            with self.assertRaises(InputError):
                compile_interview(filled, changed, at=AT)
        self.assertEqual(BANK, before)

    def test_session_exception_is_independent_and_replacement_atomic(self):
        session = ReviewSession(
            self.bundle(),
            self.catalog(),
            self.root / "session",
            clock=lambda: AT,
            evidence_tiers=True,
        )
        payload = {
            "revision": 0,
            "control_id": "ALZ-" + OWN["B03.17"],
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
        row = next(r for r in self.own(session.report) if r["upstream_id"] == "B03.17")
        self.assertEqual(row["observed"]["outcome"], "manual")
        self.assertEqual(row["observed"]["exception_disposition"], "accepted")
        before = copy.deepcopy(session.report)
        disk = {p.name: p.read_bytes() for p in (self.root / "session").iterdir() if p.is_file()}
        with self.assertRaises(InputError):
            session.save({**payload, "revision": 1, "rationale": "Unconfirmed replacement."})
        self.assertEqual(session.report, before)
        self.assertEqual(
            disk, {p.name: p.read_bytes() for p in (self.root / "session").iterdir() if p.is_file()}
        )
        session.save(
            {
                **payload,
                "revision": 1,
                "control_id": "ALZ-" + OWN["B05.01"],
                "kind": "manual",
                "decision": "fail",
            }
        )
        self.assertEqual(len(session.reviews["manual"]["entries"]), 1)
        self.assertEqual(len(session.reviews["exceptions"]["entries"]), 1)
        self.assertEqual(session.evidence, self.bundle())

    def test_session_disk_failure_preserves_eight_blank_decisions_and_prior_revision(self):
        session = ReviewSession(
            self.bundle(),
            self.catalog(),
            self.root / "atomic",
            clock=lambda: AT,
            evidence_tiers=True,
        )
        before = session.state()
        with patch.object(Path, "rename", side_effect=OSError("authored disk failure")):
            with self.assertRaisesRegex(OSError, "authored disk failure"):
                session.save(
                    {
                        "revision": 0,
                        "control_id": "ALZ-" + OWN["B04.02"],
                        "kind": "manual",
                        "decision": "fail",
                        "reviewer": "Fixture",
                        "evidence": "https://example.invalid/review",
                        "rationale": "Authored fixture.",
                        "valid_from": AT,
                        "valid_until": UNTIL,
                        "replace_existing": False,
                    }
                )
        self.assertEqual(session.state(), before)
        self.assertEqual([p.name for p in session.directory.iterdir()], ["revision-0000"])
        self.assertEqual(session.reviews["manual"]["entries"], [])

    def test_interview_selection_and_expired_decisions_are_not_inferred(self):
        catalog, bundle = self.catalog(), self.bundle()
        report = assess(bundle, catalog, at=AT, evidence_tiers=True)
        manager, key = self.interview(report, catalog)
        with manager:
            selected = prepare_interview(report, catalog, key, SUB, ["ALZ-" + OWN["B03.17"]])
            self.assertEqual(
                [d["control_id"] for d in selected["decisions"]], ["ALZ-" + OWN["B03.17"]]
            )
            self.assertIsNone(selected["decisions"][0]["outcome"])
            with self.assertRaises(InputError):
                prepare_interview(report, catalog, key, SUB, ["ALZ-not-in-this-cohort"])
            selected.update(
                answer="Authored fixture.",
                reviewer="Fixture",
                rationale="Independent decision.",
                evidence="https://example.invalid/review",
                valid_from=AT,
                valid_until=UNTIL,
            )
            selected["decisions"][0]["outcome"] = "pass"
            manual = compile_interview(selected, catalog, at=AT)
            current = self.own(assess(bundle, catalog, at=AT, manual=manual, evidence_tiers=True))
            self.assertEqual(
                next(r for r in current if r["upstream_id"] == "B03.17")["observed"]["outcome"],
                "pass",
            )
            self.assertTrue(
                all(
                    r["observed"]["outcome"] == "manual"
                    for r in current
                    if r["upstream_id"] != "B03.17"
                )
            )
            expired = self.own(
                assess(bundle, catalog, at=UNTIL, manual=manual, evidence_tiers=True)
            )
            self.assertTrue(all(r["observed"]["outcome"] == "manual" for r in expired))
            self.assertTrue(all(r["observed"]["evidence_tier"] != "verified" for r in current))

    def test_sanitized_original_time_replay_and_unaccepted_candidate_rejection(self):
        bundle, catalog = self.bundle(), self.catalog()
        with self.assertRaisesRegex(InputError, "differs from a packaged artifact"):
            export_bundle(self.root / "candidate", bundle, catalog, at=AT, evidence_tiers=True)
        sanitized = sanitize_evidence(bundle)
        self.assertEqual(sanitized["collected_at"], AT)
        self.assertNotIn(PRIVATE, json.dumps(sanitized))
        for display in ("B04.01", "B04.02"):
            self.assertEqual(
                review_context(self.control(display), sanitized),
                review_context(self.control(display), bundle),
            )
        accepted = load_catalog()
        before = digest(accepted)
        export_bundle(self.root / "accepted", bundle, accepted, at=AT, evidence_tiers=True)
        replayed = replay_bundle(self.root / "accepted")
        self.assertEqual(
            semantic(replayed), semantic(assess(bundle, accepted, at=AT, evidence_tiers=True))
        )
        self.assertEqual(digest(load_catalog()), before)

    def test_cli_preparation_uses_existing_engine_without_transport_or_query(self):
        evidence = self.write("saved.json", self.bundle())
        catalog = self.write("catalog.json", self.catalog())
        output = self.root / "assessment.json"
        with (
            contextlib.redirect_stdout(io.StringIO()),
            patch("socket.socket.connect", side_effect=AssertionError("network forbidden")),
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
        self.assertNotIn("query_signals", report)
        self.assertNotIn(PRIVATE, json.dumps(report))

    def test_injected_collector_does_not_add_directory_or_billing_routes(self):
        seen = []

        def transport(method, url, body=None):
            seen.append(url.lower())
            if "/resources?" in url:
                return Response(200, {"value": [{"id": PEERING, "type": PEERING_KIND}]}, {})
            if PEERING in url.lower():
                return Response(200, {"id": PEERING, "properties": {}}, {})
            return Response(200, {"value": []}, {})

        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            bundle = Collector(transport).collect(
                subscriptions=[SUB.split("/")[2]], inventory_authorized=True
            )
        self.assertIn("unknown", bundle["resources"][0]["properties"]["allowVirtualNetworkAccess"])
        self.assertTrue(
            all(
                not any(
                    s in url
                    for s in (
                        "graph",
                        "billing",
                        "pim",
                        "connectors",
                        "applicationproxy",
                    )
                )
                for url in seen
            )
        )

    @unittest.skipUnless(os.environ.get("BICEP_COMPILER"), "existing Bicep compiler not supplied")
    def test_real_bicep_peering_and_vault_configuration_without_restore(self):
        source = ROOT / "tests" / "fixtures" / "hybrid-identity" / "controls.bicep"
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        copied = self.root / "controls.bicep"
        copied.write_bytes(source.read_bytes())
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            compiled = compile_bicep(copied, compiler=os.environ["BICEP_COMPILER"])
            bundle = arm_source(copied, scope=RG, bicep=True, compiler=os.environ["BICEP_COMPILER"])
        self.assertEqual(len(compiled["template"]["resources"]), 4)
        peering = next(
            i
            for i, r in enumerate(bundle["resources"])
            if r["resource_type"].lower() == PEERING_KIND
        )
        vault = next(
            i for i, r in enumerate(bundle["resources"]) if r["resource_type"].lower() == VAULT_KIND
        )
        self.assertEqual(self.context(bundle, peering)["facts"]["remoteVirtualNetwork.id"], REMOTE)
        self.assertIs(self.context(bundle, vault)["facts"]["enableRbacAuthorization"], True)
        own = self.own(
            assess(bundle, self.catalog(), at=bundle["collected_at"], evidence_tiers=True)
        )
        self.assertTrue(all(r["planned"]["outcome"] == "manual" for r in own))
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), before)
        self.assertFalse(source.with_suffix(".json").exists())


if __name__ == "__main__":
    unittest.main()
