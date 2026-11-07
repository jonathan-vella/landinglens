import contextlib
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

from alz_assessor.arm import API_VERSIONS, PLANNED_API_VERSIONS, arm_source, properties
from alz_assessor.catalog import load_catalog
from alz_assessor.cli import main
from alz_assessor.comparison import compare
from alz_assessor.contracts import control_digest, document, validate
from alz_assessor.engine import assess
from alz_assessor.interviews import BANK, BANK_VERSION, compile_interview, prepare_interview
from alz_assessor.organization_evidence import (
    GUIDS,
    MG_KIND,
    SETTINGS,
    SUB_KIND,
    configuration_context,
    explicit_identity,
)
from alz_assessor.plan import plan_source
from alz_assessor.replay import export_bundle, replay_bundle, sanitize_evidence, semantic
from alz_assessor.reports import render, render_xlsx
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import review_context
from alz_assessor.sources import terraform_source, tf_properties
from alz_assessor.terraform import InputError

ROOT = Path(__file__).resolve().parents[1]
PREPARATION = ROOT / "references" / "preparation"
MG = "/providers/microsoft.management/managementgroups/authored"
CHILD = "/providers/microsoft.management/managementgroups/sandbox-platform-root-is-only-a-key"
SUB = "/subscriptions/00000000-0000-0000-0000-000000000001"
AT = "2026-11-07T01:00:00Z"
UNTIL = "2026-11-08T01:00:00Z"
PRIVATE = "PRIVATE-NOT-FOR-REPORTING"
OWN = {
    "C01.01": "cacf55bc-e4e4-46be-96bc-57a5f23a269a",
    "C02.01": "2df27ee4-12e7-4f98-9f63-04722dd69c5b",
    "C02.02": "667313b4-f566-44b5-b984-a859c773e7d2",
    "C02.03": "61623a76-5a91-47e1-b348-ef254c27d42e",
    "C02.04": "8bbac757-1559-4ab9-853e-8908ae28c84c",
    "C02.05": "33b6b780-8b9f-4e5c-9104-9d403a923c34",
    "C02.06": "74d00018-ac6a-49e0-8e6a-83de5de32c19",
    "C02.07": "92481607-d5d1-4e4e-9146-58d3558fd772",
}


class OrganizationPreparationTests(unittest.TestCase):
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
        return json.loads((PREPARATION / "batch-07.json").read_text("utf-8"))

    def catalog(self):
        catalog = copy.deepcopy(load_catalog())
        rows = {r["guid"]: r for r in self.matrix()["recommendations"]}
        catalog["review_state"] = "authored-preparation-fixture-not-published"
        for control in catalog["controls"]:
            if control["upstream_guid"] in rows:
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
            scope=MG,
            collected_at=AT,
            inventory_complete=False,
            artifact_hashes={"authored-fixture": "0" * 64},
            diagnostics=[],
            metadata={
                "relationships": [{"id": CHILD, "parent": MG}, {"id": SUB, "parent": CHILD}],
                "completeness": {"relationships": False},
            },
            resources=[
                {
                    "logical_id": identity,
                    "arm_id": identity,
                    "resource_type": kind,
                    "state": "known",
                    **({"api_version": "2020-05-01"} if kind == SETTINGS else {}),
                    "reason": "",
                    "source_location": "fixture://authored-organization",
                    "properties": values,
                }
                for identity, kind, values in (
                    (MG, MG_KIND, {}),
                    (CHILD, MG_KIND, {"managementParentId": MG}),
                    (SUB, SUB_KIND, {}),
                    (
                        MG + "/settings/default",
                        SETTINGS,
                        {
                            "defaultManagementGroup": CHILD,
                            "requireAuthorizationForGroupCreation": True,
                        },
                    ),
                )
            ],
        )

    def interview(self):
        item = self.matrix()["interview"]
        return patch.dict(BANK, {item["id"]: {k: item[k] for k in ("question", "controls")}})

    def filled(self, template):
        value = copy.deepcopy(template)
        value.update(
            answer="Authored fixture, not owner approval.",
            reviewer="Fixture",
            rationale="Eight independent source-specific fixture decisions.",
            evidence="https://example.invalid/review",
            valid_from=AT,
            valid_until=UNTIL,
        )
        for decision in value["decisions"]:
            decision["outcome"] = "fail"
        return value

    def test_exact_fixed_eight_sources_without_accepted_activation(self):
        targets_path = ROOT / "references" / "recommendation-batches" / "targets.json"
        targets = json.loads(targets_path.read_text("utf-8"))["targets"]
        self.assertEqual({r["upstream_id"]: r["guid"] for r in targets if r["batch"] == "07"}, OWN)
        self.assertEqual(
            hashlib.sha256(targets_path.read_bytes()).hexdigest(),
            "582fe02feee03b50961e5548fa7551bbd3d8729fbcb68f51837d548e59eaa291",
        )
        matrix = self.matrix()
        self.assertEqual(GUIDS, set(OWN.values()))
        self.assertEqual(matrix["review_state"], "source-reviewed-preparation-not-accepted")
        self.assertNotIn("catalog_version", matrix)
        question = matrix["interview"]
        self.assertEqual(question, {"id": question["id"], **BANK[question["id"]]})
        self.assertEqual(BANK_VERSION, load_catalog()["catalog_version"])
        self.assertEqual({r["upstream_id"]: r["guid"] for r in matrix["recommendations"]}, OWN)
        sources = json.loads((PREPARATION / "batch-07-sources.json").read_text("utf-8"))["sources"]
        by_id = {s["id"]: s for s in sources}
        self.assertGreaterEqual(len(by_id), 10)
        for source in sources:
            self.assertRegex(source["sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(source["revision"], r"^[0-9a-f]{40}$")
            self.assertTrue(source["finding"])
            self.assertTrue(source["reuse"])
        for row in matrix["recommendations"]:
            self.assertTrue(set(row["sources"]) <= set(by_id))
            self.assertEqual(row["classification"], "assisted")
            self.assertNotIn("rule", row)
            self.assertEqual(
                sum(r.startswith("Reviewer decision:") for r in row["evidence_requirements"]), 2
            )

    def test_accepted_bytes_all_nonown_and_original_four_objects_preserved(self):
        accepted = load_catalog()
        data = ROOT / "src" / "alz_assessor" / "data"
        for name, expected in (
            (
                "catalog-2026-11-06.21.json",
                "b7395794a08feed20fe29b61849409541639f525b2970aaad248964f13b7860c",
            ),
            (
                "crosswalk-2026-11-06.21.json",
                "5476deaef6c8d9463bf23a4c7f62f18e2dc4341108d3ea880c0aea3aabaa22a0",
            ),
        ):
            self.assertEqual(hashlib.sha256((data / name).read_bytes()).hexdigest(), expected)
        self.assertEqual(len(accepted["controls"]), 255)
        candidate = {c["control_id"]: c for c in self.catalog()["controls"]}
        for control in accepted["controls"]:
            if control["upstream_guid"] not in GUIDS:
                self.assertEqual(control, candidate[control["control_id"]])
        original = load_catalog(str(data / "catalog-2026-11-04.2.json"))
        for control in original["controls"]:
            if control["automation"] == "automated":
                self.assertEqual(
                    control_digest(control), control_digest(candidate[control["control_id"]])
                )

    def test_partial_depth_excludes_anchor_and_subscription_not_a_threshold(self):
        bundle = self.bundle()
        context = configuration_context(bundle)
        self.assertNotIn("unknown", context)
        self.assertEqual(context["maximum_supplied_management_group_edges_below_selected"], 1)
        self.assertEqual(
            [edge["management_group_edges_below_selected"] for edge in context["relationships"]],
            [1, 1],
        )
        self.assertFalse(context["complete_estate"])
        self.assertIn("unknown", context["tenant_root_designation"])
        for depth in (3, 4, 5, 6, 7):
            bundle = self.bundle()
            bundle["resources"] = bundle["resources"][:2]
            bundle["metadata"] = {}
            parent = CHILD
            for index in range(depth - 1):
                child = MG + f"-depth-{index}"
                bundle["resources"].append(
                    {
                        **bundle["resources"][1],
                        "arm_id": child,
                        "logical_id": child,
                        "properties": {"managementParentId": parent},
                    }
                )
                parent = child
            self.assertEqual(
                configuration_context(bundle)[
                    "maximum_supplied_management_group_edges_below_selected"
                ],
                depth,
            )
            self.assertTrue(
                all(
                    r["observed"]["outcome"] == "manual"
                    for r in self.own(assess(bundle, self.catalog(), at=AT, evidence_tiers=True))
                )
            )

    def test_default_and_creation_settings_independent_not_effective_assurance(self):
        for default in (MG, CHILD):
            for creation in (True, False):
                bundle = self.bundle()
                bundle["resources"][-1]["properties"].update(
                    defaultManagementGroup=default, requireAuthorizationForGroupCreation=creation
                )
                context = configuration_context(bundle)
                self.assertEqual(
                    context["settings"][0]["facts"],
                    {
                        "defaultManagementGroup": default,
                        "requireAuthorizationForGroupCreation": creation,
                    },
                )
                self.assertIn("unknown", context["root_subscription_absence"])
                self.assertIn("unknown", context["effective_authorization"])
                self.assertFalse(context["complete_estate"])
        bundle["metadata"]["completeness"]["relationships"] = True
        bundle["inventory_complete"] = True
        self.assertFalse(configuration_context(bundle)["complete_estate"])

    def test_invalid_missing_settings_are_unknown_not_defaults(self):
        for value in (None, 0, 1, "true", [], {}, {"unknown": "denied"}):
            bundle = self.bundle()
            bundle["resources"][-1]["properties"]["requireAuthorizationForGroupCreation"] = value
            facts = configuration_context(bundle)["settings"][0]["facts"]
            self.assertIn("unknown", facts["requireAuthorizationForGroupCreation"])
            row = next(
                r
                for r in self.own(assess(bundle, self.catalog(), at=AT, evidence_tiers=True))
                if r["upstream_id"] == "C02.06"
            )
            self.assertEqual(row["observed"]["evidence_tier"], "needs_decision")
        for value in (None, True, [], {}, CHILD + "/settings/default", MG + "-foreign"):
            bundle = self.bundle()
            bundle["resources"][-1]["properties"]["defaultManagementGroup"] = value
            self.assertIn(
                "unknown",
                configuration_context(bundle)["settings"][0]["facts"]["defaultManagementGroup"],
            )

    def test_graph_duplicates_cycles_missing_foreign_and_conflicts_unknown(self):
        bad_edges = (
            [{"id": CHILD, "parent": MG}, {"id": CHILD, "parent": MG}],
            [{"id": CHILD, "parent": CHILD}],
            [{"id": CHILD, "parent": SUB}],
            [{"id": CHILD, "parent": MG + "-foreign"}],
            [{"id": CHILD, "parent": MG + "-cycle"}, {"id": MG + "-cycle", "parent": CHILD}],
            [{"id": CHILD}],
            [{"id": CHILD, "parent": MG}] * 101,
        )
        for edges in bad_edges:
            bundle = self.bundle()
            bundle["metadata"]["relationships"] = edges
            self.assertIn("unknown", configuration_context(bundle))
        for parent in (CHILD, SUB, MG + "-foreign", None, True, {"unknown": "partial"}):
            bundle = self.bundle()
            bundle["resources"][1]["properties"]["managementParentId"] = parent
            self.assertIn("unknown", configuration_context(bundle))
        bundle = self.bundle()
        bundle["resources"][0]["properties"]["managementParentId"] = CHILD
        self.assertIn("unknown", configuration_context(bundle))
        bundle = self.bundle()
        bundle["resources"].pop(2)
        self.assertIn("unknown", configuration_context(bundle))

    def test_unique_known_types_selected_scope_and_exact_default_child_required(self):
        for version in (None, True, "", "2023-04-01", "2099-01-01"):
            bundle = self.bundle()
            bundle["resources"][-1]["api_version"] = version
            self.assertIn("unknown", configuration_context(bundle))
        for state in ("unknown", "inaccessible", "error", "denied", "unsupported"):
            bundle = self.bundle()
            bundle["resources"][1]["state"] = state
            self.assertIn("unknown", configuration_context(bundle))
        for identity in (
            SUB + "/resourcegroups/foreign",
            CHILD + "/settings/default",
            "/providers/microsoft.management/managementgroups/foreign/settings/default",
            MG + "/settings/not-default",
            MG + "/settings/default/extra/value",
        ):
            bundle = self.bundle()
            bundle["resources"][-1]["arm_id"] = identity
            self.assertIn("unknown", configuration_context(bundle))
        for selected in (SUB, SUB + "/resourcegroups/authored", MG + "-foreign"):
            bundle = self.bundle()
            bundle["scope"] = selected
            self.assertIn("unknown", configuration_context(bundle))
        bundle = self.bundle()
        bundle["resources"].append(copy.deepcopy(bundle["resources"][0]))
        self.assertIn("unknown", configuration_context(bundle))
        bundle = self.bundle()
        bundle["resources"][1]["resource_type"] = SUB_KIND
        self.assertIn("unknown", configuration_context(bundle))

    def test_population_bound_100_is_parser_limit_not_compliance(self):
        for count in (100, 101):
            bundle = self.bundle()
            bundle["resources"] = bundle["resources"][:2]
            bundle["metadata"] = {}
            bundle["resources"] += [
                {
                    **copy.deepcopy(bundle["resources"][1]),
                    "arm_id": MG + f"-{i}",
                    "logical_id": MG + f"-{i}",
                }
                for i in range(count - 2)
            ]
            self.assertEqual("unknown" in configuration_context(bundle), count == 101)
        bundle["resources"] = []
        self.assertIn("unknown", configuration_context(bundle))

    def test_labels_tags_humanconfirmation_never_invent_business_purpose(self):
        bundle = self.bundle()
        for row in bundle["resources"]:
            row["properties"].update(
                displayName=PRIVATE,
                tags={PRIVATE: PRIVATE},
                tenantId=PRIVATE,
                principalId=PRIVATE,
                namingStandardApproved=True,
                sandbox=True,
                platform=True,
                connectivity=True,
                humanConfirmed=True,
            )
        self.assertNotIn(PRIVATE, json.dumps(configuration_context(bundle)))
        for display in OWN:
            context = review_context(self.control(display), bundle)
            self.assertNotIn(PRIVATE, json.dumps(context))
        report = assess(bundle, self.catalog(), at=AT, evidence_tiers=True)
        self.assertTrue(all(r["observed"]["outcome"] == "manual" for r in self.own(report)))
        self.assertTrue(all(r["observed"]["evidence_tier"] != "verified" for r in self.own(report)))

    def test_outputs_tiers_stale_future_and_planned_observed_separation(self):
        bundle, catalog = self.bundle(), self.catalog()
        report = assess(bundle, catalog, at=AT, evidence_tiers=True)
        self.assertEqual(len(self.own(report)), 8)
        self.assertEqual(
            {r["upstream_id"]: r["observed"]["evidence_tier"] for r in self.own(report)},
            {key: "needs_decision" if key == "C01.01" else "signal" for key in OWN},
        )
        for format in ("json", "markdown", "html", "csv", "sarif", "pr-summary"):
            self.assertNotIn(PRIVATE, render(report, format))
        with zipfile.ZipFile(io.BytesIO(render_xlsx(report))) as archive:
            self.assertNotIn(PRIVATE, "".join(archive.read(n).decode() for n in archive.namelist()))
        for time in ("2000-01-01T00:00:00Z", UNTIL):
            changed = copy.deepcopy(bundle)
            changed["collected_at"] = time
            self.assertTrue(
                all(
                    r["observed"]["evidence_tier"] not in {"signal", "verified"}
                    for r in self.own(assess(changed, catalog, at=AT, evidence_tiers=True))
                )
            )
        planned = copy.deepcopy(bundle)
        planned["mode"], planned["source"] = "planned", "arm"
        combined = compare(assess(planned, catalog, at=AT, evidence_tiers=True), report, at=AT)
        self.assertTrue(all(r["planned"] and r["observed"] for r in self.own(combined)))
        self.assertTrue(all(r["planned"]["outcome"] == "manual" for r in self.own(combined)))

    def test_eight_independent_blank_decisions_bindings_attribution_time(self):
        catalog, bundle = self.catalog(), self.bundle()
        report = assess(bundle, catalog, at=AT, evidence_tiers=True)
        before = copy.deepcopy(BANK)
        with self.interview():
            template = prepare_interview(report, catalog, self.matrix()["interview"]["id"], MG)
            self.assertEqual(len(template["decisions"]), 8)
            self.assertTrue(all(d["outcome"] is None for d in template["decisions"]))
            for field in (
                "answer",
                "reviewer",
                "rationale",
                "evidence",
                "valid_from",
                "valid_until",
            ):
                self.assertIsNone(template[field])
            with self.assertRaises(InputError):
                compile_interview(template, catalog, at=AT)
            filled = self.filled(template)
            manual = compile_interview(filled, catalog, at=AT)
            self.assertEqual(len(manual["entries"]), 8)
            current = self.own(assess(bundle, catalog, at=AT, manual=manual, evidence_tiers=True))
            self.assertTrue(all(r["observed"]["outcome"] == "fail" for r in current))
            self.assertTrue(all(r["observed"]["evidence_tier"] != "verified" for r in current))
            for field, value in (
                ("scope", SUB),
                ("reviewer", ""),
                ("evidence", ""),
                ("valid_until", AT),
                ("valid_from", UNTIL),
                ("catalog_sha256", "0" * 64),
                ("requirements_sha256", "0" * 64),
            ):
                with self.assertRaises(InputError):
                    compile_interview({**filled, field: value}, catalog, at=AT)
            for decisions in (
                filled["decisions"][:-1],
                [filled["decisions"][0]] * 8,
                [{**d, "outcome": None} for d in filled["decisions"]],
            ):
                with self.assertRaises(InputError):
                    compile_interview({**filled, "decisions": decisions}, catalog, at=AT)
            changed = copy.deepcopy(catalog)
            next(c for c in changed["controls"] if c["upstream_id"] == "C02.06")["rationale"] += (
                " Changed."
            )
            with self.assertRaises(InputError):
                compile_interview(filled, changed, at=AT)
        self.assertEqual(BANK, before)

    def test_explicit_selection_does_not_apply_to_other_or_expired_controls(self):
        bundle, catalog = self.bundle(), self.catalog()
        report = assess(bundle, catalog, at=AT, evidence_tiers=True)
        identity = "ALZ-" + OWN["C01.01"]
        with self.interview():
            key = self.matrix()["interview"]["id"]
            template = prepare_interview(report, catalog, key, MG, [identity])
            for selection in ([identity, identity], ["ALZ-foreign"], []):
                with self.assertRaises(InputError):
                    prepare_interview(report, catalog, key, MG, selection)
            filled = self.filled(template)
            filled["decisions"][0]["outcome"] = "pass"
            manual = compile_interview(filled, catalog, at=AT)
            current = self.own(assess(bundle, catalog, at=AT, manual=manual, evidence_tiers=True))
            self.assertEqual(
                [r["control_id"] for r in current if r["observed"]["outcome"] == "pass"], [identity]
            )
            self.assertTrue(all(r["observed"]["evidence_tier"] != "verified" for r in current))
            expired = self.own(
                assess(bundle, catalog, at=UNTIL, manual=manual, evidence_tiers=True)
            )
            self.assertTrue(all(r["observed"]["outcome"] == "manual" for r in expired))

    def test_session_decisions_exceptions_and_failed_write_atomicity(self):
        session = ReviewSession(
            self.bundle(),
            self.catalog(),
            self.root / "session",
            clock=lambda: AT,
            evidence_tiers=True,
        )
        payload = dict(
            revision=0,
            control_id="ALZ-" + OWN["C01.01"],
            kind="exceptions",
            decision="accepted",
            reviewer="Fixture",
            evidence="https://example.invalid/exception",
            rationale="Authored exception, not owner approval.",
            valid_from=AT,
            valid_until=UNTIL,
            replace_existing=False,
        )
        session.save(payload)
        self.assertEqual(session.reviews["manual"]["entries"], [])
        row = next(r for r in self.own(session.report) if r["upstream_id"] == "C01.01")
        self.assertEqual(row["observed"]["outcome"], "manual")
        self.assertEqual(row["observed"]["exception_disposition"], "accepted")
        before = copy.deepcopy(session.state())
        with patch.object(Path, "rename", side_effect=OSError("authored disk failure")):
            with self.assertRaisesRegex(OSError, "authored disk failure"):
                session.save({**payload, "revision": 1, "control_id": "ALZ-" + OWN["C02.01"]})
        self.assertEqual(session.state(), before)
        with self.interview():
            response = self.filled(
                prepare_interview(
                    session.report, self.catalog(), self.matrix()["interview"]["id"], MG
                )
            )
            session.save_interview({"revision": 1, "response": response, "replace_existing": []})
        self.assertEqual(len(session.reviews["manual"]["entries"]), 8)

    def test_original_time_private_replay_and_candidate_rejection(self):
        bundle = self.bundle()
        for row in bundle["resources"]:
            row["properties"].update(
                displayName=PRIVATE, principalId=PRIVATE, tags={PRIVATE: PRIVATE}
            )
        sanitized = sanitize_evidence(bundle)
        self.assertEqual(sanitized["collected_at"], AT)
        self.assertNotIn(PRIVATE, json.dumps(sanitized))
        self.assertEqual(configuration_context(sanitized), configuration_context(bundle))
        invalid_version = copy.deepcopy(bundle)
        invalid_version["resources"][-1]["api_version"] = PRIVATE
        self.assertNotIn(PRIVATE, json.dumps(sanitize_evidence(invalid_version)))
        for display in OWN:
            self.assertEqual(
                review_context(self.control(display), sanitized),
                review_context(self.control(display), bundle),
            )
        with self.assertRaisesRegex(InputError, "differs from a packaged artifact"):
            export_bundle(
                self.root / "candidate", bundle, self.catalog(), at=AT, evidence_tiers=True
            )
        accepted = load_catalog()
        export_bundle(self.root / "accepted", bundle, accepted, at=AT, evidence_tiers=True)
        replayed = replay_bundle(self.root / "accepted")
        self.assertEqual(
            semantic(replayed), semantic(assess(bundle, accepted, at=AT, evidence_tiers=True))
        )
        self.assertEqual(replayed["evidence"][0]["collected_at"], AT)

    def test_explicit_keys_are_not_display_names_or_tenant_root_designations(self):
        self.assertEqual(explicit_identity(MG_KIND, "authored", MG), MG)
        self.assertEqual(
            explicit_identity(SETTINGS, "authored/default", MG), MG + "/settings/default"
        )
        for value in (None, True, {}, "a/b", "", "a%20", "../a"):
            self.assertIsNone(explicit_identity(MG_KIND, value, MG))
        self.assertIsNone(explicit_identity(MG_KIND, "authored", SUB))
        self.assertIsNone(explicit_identity(SETTINGS, "authored/nondefault", MG))
        result = tf_properties(
            "azurerm_management_group",
            {
                "display_name": PRIVATE,
                "name": PRIVATE,
                "parent_management_group_id": MG,
                "subscription_ids": [],
                "tags": {PRIVATE: PRIVATE},
            },
        )
        self.assertEqual(result, {"managementParentId": MG})
        self.assertNotIn(PRIVATE, json.dumps(result))

    def test_literal_hcl_explicit_keys_and_parent_without_defaults(self):
        source = self.root / "main.tf"
        source.write_text(
            'resource "azurerm_management_group" "anchor" {\n name = "authored"\n}\n'
            'resource "azurerm_management_group" "child" {\n'
            f' name = "{CHILD.rsplit("/", 1)[-1]}"\n'
            f' parent_management_group_id = "{MG}"\n'
            f' display_name = "{PRIVATE}"\n}}\n',
            encoding="utf-8",
        )
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            bundle = terraform_source(self.root, scope=MG, provider_version="4.50.0")
        self.assertNotIn(PRIVATE, json.dumps(bundle))
        self.assertEqual(
            configuration_context(bundle)["maximum_supplied_management_group_edges_below_selected"],
            1,
        )
        bundle["resources"][1]["properties"] = {}
        self.assertIn("unknown", configuration_context(bundle))

    def test_unresolved_keys_expressions_and_wrong_version_never_supply_configuration(self):
        source = self.write(
            "raw/main.tf.json",
            {
                "resource": {
                    "azurerm_management_group": {
                        "unknown": {
                            "display_name": PRIVATE,
                            "parent_management_group_id": MG,
                        }
                    }
                },
            },
        )
        bundle = terraform_source(source.parent, scope=MG, provider_version="4.50.0")
        self.assertIsNone(bundle["resources"][0]["arm_id"])
        self.assertIn("unknown", configuration_context(bundle))
        template = self.arm_template()
        template["resources"][-1]["name"] = "[format('{0}/{1}', 'authored', 'default')]"
        bundle = arm_source(self.write("pure-formatted-expression.json", template), scope=MG)
        self.assertIsNotNone(bundle["resources"][-1]["arm_id"])
        self.assertNotIn(PRIVATE, json.dumps(bundle))
        template["resources"][-1]["name"] = (
            "[format('{0}/{1}', reference('external').name, 'default')]"
        )
        bundle = arm_source(self.write("unsupported-expression.json", template), scope=MG)
        self.assertIsNone(bundle["resources"][-1]["arm_id"])
        self.assertIn("unknown", configuration_context(bundle))
        self.assertNotIn(PRIVATE, json.dumps(bundle))

    def test_raw_terraform_local_module_and_plan_have_same_explicit_parent_fact(self):
        values = {
            "name": CHILD.rsplit("/", 1)[-1],
            "parent_management_group_id": MG,
            "display_name": PRIVATE,
        }
        source = {
            "resource": {
                "azurerm_management_group": {"child": values, "anchor": {"name": "authored"}}
            }
        }
        self.write("raw/main.tf.json", source)
        self.write("parent/main.tf.json", {"module": {"groups": {"source": "./module"}}})
        self.write("parent/module/main.tf.json", source)
        planned = {
            "format_version": "1.2",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "mode": "managed",
                            "address": "azurerm_management_group." + key,
                            "type": "azurerm_management_group",
                            "values": {**value, "id": CHILD if key == "child" else MG},
                        }
                        for key, value in source["resource"]["azurerm_management_group"].items()
                    ]
                }
            },
        }
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            bundles = [
                terraform_source(self.root / "raw", scope=MG, provider_version="4.50.0"),
                terraform_source(
                    self.root / "parent",
                    scope=MG,
                    provider_version="4.50.0",
                    authorized_roots=[self.root],
                ),
                plan_source(self.write("plan.json", planned), scope=MG, provider_version="4.50.0"),
            ]
        for bundle in bundles:
            self.assertNotIn(PRIVATE, json.dumps(bundle))
            self.assertEqual(
                configuration_context(bundle)[
                    "maximum_supplied_management_group_edges_below_selected"
                ],
                1,
            )
            self.assertEqual(bundle["mode"], "planned")
        item = planned["planned_values"]["root_module"]["resources"][0]
        item["sensitive_values"] = {"parent_management_group_id": True}
        bundle = plan_source(
            self.write("sensitive.json", planned), scope=MG, provider_version="4.50.0"
        )
        self.assertIn("unknown", configuration_context(bundle))
        item["sensitive_values"] = {}
        item["values"]["id"] = MG + "-wrong"
        with self.assertRaises(InputError):
            plan_source(self.write("conflict.json", planned), scope=MG, provider_version="4.50.0")
        unsupported = terraform_source(self.root / "raw", scope=MG, provider_version="0.0.0")
        self.assertIn("unknown", configuration_context(unsupported))

    def arm_template(self, version="2020-05-01"):
        return {
            "contentVersion": "1.0.0.0",
            "resources": [
                {"type": MG_KIND, "apiVersion": version, "name": "authored", "properties": {}},
                {
                    "type": MG_KIND,
                    "apiVersion": version,
                    "name": CHILD.rsplit("/", 1)[-1],
                    "properties": {"details": {"parent": {"id": MG}}, "displayName": PRIVATE},
                },
                {
                    "type": SETTINGS,
                    "apiVersion": version,
                    "name": "authored/default",
                    "properties": {
                        "defaultManagementGroup": CHILD,
                        "requireAuthorizationForGroupCreation": True,
                        "tenantId": PRIVATE,
                    },
                },
            ],
        }

    def test_arm_pinned_type_version_scope_and_private_property_projection(self):
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            bundle = arm_source(self.write("arm.json", self.arm_template()), scope=MG)
        self.assertNotIn(PRIVATE, json.dumps(bundle))
        self.assertEqual(
            configuration_context(bundle)["settings"][0]["facts"],
            {
                "defaultManagementGroup": CHILD,
                "requireAuthorizationForGroupCreation": True,
            },
        )
        for version in ("2099-01-01", "2023-04-01", None):
            bundle = arm_source(
                self.write("unsupported.json", self.arm_template(version)), scope=MG
            )
            self.assertIn("unknown", configuration_context(bundle))
        for scope in (SUB, None):
            bundle = arm_source(self.write("unbound.json", self.arm_template()), scope=scope)
            self.assertIn("unknown", configuration_context(bundle))
        self.assertNotIn(SETTINGS, API_VERSIONS)
        self.assertEqual(PLANNED_API_VERSIONS[SETTINGS], {"2020-05-01"})
        self.assertEqual(
            properties(SETTINGS, {"requireAuthorizationForGroupCreation": False})[
                "requireAuthorizationForGroupCreation"
            ],
            False,
        )

    def test_cli_saved_only_no_query_execution_or_new_collector_api(self):
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
        allowlist = json.loads(
            (ROOT / "src" / "alz_assessor" / "data" / "query-allowlist.json").read_text("utf-8")
        )
        display = {c["upstream_guid"]: c["upstream_id"] for c in load_catalog()["controls"]}
        self.assertEqual(
            {display[q["guid"]] for q in allowlist["queries"] if q["allowed"] is True},
            {"D07.06", "D07.07"},
        )

    def test_real_bicep_management_keys_parents_settings_without_restore(self):
        compiler = os.environ.get("BICEP_COMPILER")
        if not compiler:
            self.skipTest("No existing compiler discovered; no acquisition attempted")
        bundle = arm_source(
            ROOT / "tests" / "fixtures" / "organization" / "main.bicep",
            scope=MG,
            compiler=compiler,
            bicep=True,
        )
        context = configuration_context(bundle)
        self.assertNotIn("unknown", context)
        self.assertEqual(context["maximum_supplied_management_group_edges_below_selected"], 1)
        self.assertTrue(context["settings"][0]["facts"]["requireAuthorizationForGroupCreation"])
        self.assertFalse(context["complete_estate"])
        self.assertIn("unknown", context["tenant_root_designation"])
