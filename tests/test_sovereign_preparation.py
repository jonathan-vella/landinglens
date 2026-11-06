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
from alz_assessor.azure import Collector, Response
from alz_assessor.bicep import compile_bicep
from alz_assessor.catalog import load_catalog
from alz_assessor.cli import main
from alz_assessor.comparison import compare
from alz_assessor.contracts import control_digest, document, validate
from alz_assessor.engine import assess
from alz_assessor.governance_evidence import MG_KIND, TAG_KINDS, VM_KIND, tag_count
from alz_assessor.interviews import BANK, BANK_VERSION, compile_interview, prepare_interview
from alz_assessor.plan import plan_source
from alz_assessor.replay import export_bundle, replay_bundle, sanitize_evidence, semantic
from alz_assessor.reports import render, render_xlsx
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import review_context
from alz_assessor.sources import terraform_source, tf_properties
from alz_assessor.sovereign_evidence import GUIDS, configuration_context, resource_paths
from alz_assessor.terraform import InputError, tree_hash

ROOT = Path(__file__).resolve().parents[1]
PREPARATION = ROOT / "references" / "preparation"
SUB = "/subscriptions/00000000-0000-0000-0000-000000000001"
RG = SUB + "/resourcegroups/authored"
MG = "/providers/microsoft.management/managementgroups/authored"
CHILD = "/providers/microsoft.management/managementgroups/confidential-corp-is-only-a-name"
VM = RG + "/providers/" + VM_KIND + "/authored"
AT = "2026-11-06T22:00:00Z"
UNTIL = "2026-11-07T22:00:00Z"
PRIVATE = "PRIVATE-NOT-FOR-REPORTING"
OWN = {
    "C02.15": "6cc0ea22-42bb-441e-a345-804ab0a09666",
    "C03.01": "250d81ce-8bbe-4f85-9051-6a18a8221e50",
    "C03.02": "19ca3f89-397d-44b1-b5b6-5e18661372ac",
    "C03.03": "4c27d42e-8bba-4c75-9155-9ab9153e8908",
    "C04.01": "914b8cb7-c2f6-40fa-ae18-81c049e0cb5a",
    "C04.02": "51a1e9e9-a49a-40b2-87b9-ff753bc6de86",
    "C04.03": "a89153d8-18b2-4caf-bc19-850fc8fba00f",
}


class SovereignPreparationTests(unittest.TestCase):
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
        return json.loads((PREPARATION / "batch-09.json").read_text("utf-8"))

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
                    "reason": "",
                    "source_location": "fixture://authored-sovereign",
                    "properties": values,
                }
                for identity, kind, values in (
                    (MG, MG_KIND, {}),
                    (CHILD, MG_KIND, {"managementParentId": MG}),
                    (
                        VM,
                        VM_KIND,
                        properties(
                            VM_KIND,
                            {},
                            root={"location": "West Europe", "tags": {PRIVATE: PRIVATE}},
                        ),
                    ),
                )
            ],
        )

    def context(self, bundle, index, paths=None):
        by_id = {}
        for row in bundle["resources"]:
            by_id.setdefault((row.get("arm_id") or "").lower(), []).append(row)
        row = bundle["resources"][index]
        return configuration_context(
            row, by_id, bundle, paths or sorted(resource_paths(row["resource_type"]))
        )

    def interview(self):
        item = self.matrix()["interview"]
        return patch.dict(BANK, {item["id"]: {k: item[k] for k in ("question", "controls")}})

    def filled(self, template):
        value = copy.deepcopy(template)
        value.update(
            answer="Authored fixture, not owner approval.",
            reviewer="Fixture",
            rationale="Seven independent source-specific fixture decisions.",
            evidence="https://example.invalid/review",
            valid_from=AT,
            valid_until=UNTIL,
        )
        for decision in value["decisions"]:
            decision["outcome"] = "fail"
        return value

    def test_exact_fixed_seven_sources_and_unregistered_preparation(self):
        targets_path = ROOT / "references" / "recommendation-batches" / "targets.json"
        targets = json.loads(targets_path.read_text("utf-8"))["targets"]
        self.assertEqual({r["upstream_id"]: r["guid"] for r in targets if r["batch"] == "09"}, OWN)
        self.assertEqual(
            hashlib.sha256(targets_path.read_bytes()).hexdigest(),
            "582fe02feee03b50961e5548fa7551bbd3d8729fbcb68f51837d548e59eaa291",
        )
        self.assertEqual(GUIDS, set(OWN.values()))
        matrix = self.matrix()
        self.assertEqual(matrix["review_state"], "source-reviewed-preparation-not-accepted")
        self.assertNotIn("catalog_version", matrix)
        self.assertEqual({r["upstream_id"]: r["guid"] for r in matrix["recommendations"]}, OWN)
        self.assertNotIn(matrix["interview"]["id"], BANK)
        self.assertEqual(BANK_VERSION, load_catalog()["catalog_version"])
        manifest = json.loads((PREPARATION / "batch-09-sources.json").read_text("utf-8"))
        sources = {s["id"]: s for s in manifest["sources"]}
        self.assertEqual(len(sources), 17)
        for source in sources.values():
            self.assertRegex(source["sha256"], r"^[0-9a-f]{64}$")
            if source["id"] != "regional-services":
                self.assertRegex(source["revision"], r"^[0-9a-f]{40}$")
            self.assertTrue(source["finding"])
            self.assertTrue(source["reuse"])
            self.assertTrue(source["resolved_url"].startswith("https://"))
        for row in matrix["recommendations"]:
            self.assertTrue(set(row["sources"]) <= set(sources))
            self.assertNotIn("rule", row)
            self.assertTrue(row["limitations"])
            self.assertEqual(
                row["classification"],
                "manual" if row["upstream_id"] in {"C03.01", "C04.02"} else "assisted",
            )
            self.assertGreaterEqual(
                sum(r.startswith("Reviewer decision:") for r in row["evidence_requirements"]), 2
            )
        self.assertEqual(len(load_catalog()["controls"]), 255)

    def test_predecessor_bytes_and_full_original_objects_are_untouched(self):
        data = ROOT / "src" / "alz_assessor" / "data"
        for prefix, expected in (
            ("catalog", "8da27e4849f887b68129a19ce5f814b2b3d66186f364524755011983647baf33"),
            ("crosswalk", "a077b38749f189a479eb07bc1a9794977f44203005f637f98d018b12062d470d"),
        ):
            frozen = data / (prefix + "-2026-11-06.19.json")
            path = frozen if frozen.exists() else data / (prefix + ".json")
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected)
        accepted = load_catalog()
        original = load_catalog(str(data / "catalog-2026-11-04.2.json"))
        for control in original["controls"]:
            if control["automation"] == "automated":
                retained = next(
                    c for c in accepted["controls"] if c["control_id"] == control["control_id"]
                )
                self.assertEqual(control_digest(retained), control_digest(control))
                self.assertEqual(
                    retained,
                    next(
                        c
                        for c in self.catalog()["controls"]
                        if c["control_id"] == control["control_id"]
                    ),
                )
        self.assertTrue(
            all(
                not c.get("review_fact_paths")
                for c in accepted["controls"]
                if c["upstream_guid"] in GUIDS
            )
        )

    def test_parent_join_requires_known_unique_typed_scoped_positive_edges(self):
        bundle = self.bundle()
        self.assertEqual(self.context(bundle, 1)["facts"], {"managementParentId": MG})
        for index in (0, 1):
            for field, value in (("state", "unknown"), ("resource_type", VM_KIND)):
                changed = copy.deepcopy(bundle)
                changed["resources"][index][field] = value
                context = self.context(changed, 1)
                self.assertTrue(
                    "unknown" in context or "unknown" in context["facts"]["managementParentId"]
                )
            changed = copy.deepcopy(bundle)
            changed["resources"].append(copy.deepcopy(changed["resources"][index]))
            context = self.context(changed, 1)
            self.assertTrue(
                "unknown" in context or "unknown" in context["facts"]["managementParentId"]
            )
        for parent in (
            CHILD,
            VM,
            None,
            False,
            {},
            "/providers/microsoft.management/managementgroups/foreign",
        ):
            changed = copy.deepcopy(bundle)
            changed["resources"][1]["properties"]["managementParentId"] = parent
            self.assertIn("unknown", self.context(changed, 1)["facts"]["managementParentId"])
        bundle["metadata"] = {}
        self.assertIn("unknown", self.context(bundle, 1))

    def test_missing_conflicting_cyclic_or_foreign_hierarchy_stays_unknown(self):
        for edges in (
            [{"id": CHILD, "parent": MG}, {"id": CHILD, "parent": MG}],
            [{"id": CHILD, "parent": CHILD}],
            [{"id": CHILD, "parent": SUB}],
            [{"id": CHILD, "parent": MG + "-foreign"}],
            [{"id": CHILD, "parent": MG + "-cycle"}, {"id": MG + "-cycle", "parent": CHILD}],
            [{"id": CHILD, "parent": MG}] * 101,
        ):
            bundle = self.bundle()
            bundle["metadata"]["relationships"] = edges
            self.assertIn("unknown", self.context(bundle, 1))
        bundle = self.bundle()
        other = MG + "-other"
        bundle["resources"].append({**bundle["resources"][0], "arm_id": other, "logical_id": other})
        bundle["metadata"]["relationships"].append({"id": other, "parent": MG})
        bundle["resources"][1]["properties"]["managementParentId"] = other
        self.assertIn("unknown", self.context(bundle, 1)["facts"]["managementParentId"])

    def test_names_and_human_confirmation_never_designate_a_role_or_pass(self):
        bundle = self.bundle()
        for row in bundle["resources"]:
            row["properties"].update(
                displayName="Public Confidential Corp Confidential Online landing zones",
                humanConfirmed=True,
                dataClassification=PRIVATE,
                sovereigntyVerified=True,
            )
        for index in (0, 1):
            self.assertNotIn(PRIVATE, json.dumps(self.context(bundle, index)))
        report = assess(bundle, self.catalog(), at=AT, evidence_tiers=True)
        self.assertTrue(all(r["observed"]["outcome"] == "manual" for r in self.own(report)))
        self.assertTrue(all(r["observed"]["evidence_tier"] != "verified" for r in self.own(report)))

    def test_location_labels_are_not_a_multiregion_or_availability_predicate(self):
        bundle = self.bundle()
        for label in ("westeurope", "West Europe", "NotARealRegion", "zz"):
            bundle["resources"][2]["properties"]["resourceLocation"] = label
            self.assertIsInstance(self.context(bundle, 2)["facts"]["resourceLocation"], str)
        for value in (None, True, 1, [], {}, {"unknown": "denied"}, PRIVATE, "x" * 41):
            bundle["resources"][2]["properties"]["resourceLocation"] = value
            self.assertIn("unknown", self.context(bundle, 2)["facts"]["resourceLocation"])
        bundle = self.bundle()
        second = copy.deepcopy(bundle["resources"][2])
        second.update(arm_id=VM + "-second", logical_id=VM + "-second")
        second["properties"]["resourceLocation"] = "northeurope"
        bundle["resources"].append(second)
        report = assess(bundle, self.catalog(), at=AT, evidence_tiers=True)
        for row in self.own(report):
            self.assertEqual(row["observed"]["outcome"], "manual")
        context = review_context(self.control("C03.02"), bundle)
        self.assertEqual(context["matching_resources"], 2)
        self.assertTrue(all(not r["subchecks"] for r in context["resources"]))
        self.assertIn(
            "physical/legal independence",
            context["resources"][0]["sovereign_configuration"]["warning"],
        )

    def test_type_scope_population_and_missing_input_not_absence(self):
        for identity in (
            VM.replace("/resourcegroups/authored", ""),
            VM + "/extensions/unsupported",
        ):
            bundle = self.bundle()
            bundle["resources"][2]["arm_id"] = identity
            self.assertIn("unknown", self.context(bundle, 2))
        for scope in (RG + "-foreign", SUB[:-1] + "2"):
            bundle = self.bundle()
            bundle["scope"] = scope
            self.assertIn("unknown", self.context(bundle, 2))
        for count in (100, 101):
            bundle = self.bundle()
            base = bundle["resources"][2]
            bundle["resources"] += [
                {**copy.deepcopy(base), "arm_id": VM + str(i), "logical_id": VM + str(i)}
                for i in range(count - 1)
            ]
            context = self.context(bundle, 2)
            self.assertEqual("unknown" in context, count == 101)
        bundle["resources"] = []
        report = assess(bundle, self.catalog(), at=AT, evidence_tiers=True)
        self.assertTrue(
            all(
                r["observed"]["evidence_tier"] in {"manual", "needs_decision"}
                for r in self.own(report)
            )
        )

    def test_denied_ambiguous_partial_and_over_bound_context_is_not_a_signal(self):
        for state in ("unknown", "denied", "unsupported"):
            bundle = self.bundle()
            bundle["resources"][2]["state"] = state
            self.assertIn("unknown", self.context(bundle, 2))
        for path, invalid in (
            ("tagCount", True),
            ("tagCount", -1),
            ("tagCount", 51),
            ("tagCount", {"unknown": "denied"}),
            ("resourceLocation", {"unknown": "partial"}),
        ):
            bundle = self.bundle()
            bundle["resources"][2]["properties"] = {path: invalid}
            self.assertIn("unknown", self.context(bundle, 2, [path])["facts"][path])
        bundle = self.bundle()
        bundle["resources"].append(copy.deepcopy(bundle["resources"][2]))
        bundle["resources"][-1]["logical_id"] += "-duplicate"
        self.assertIn("unknown", self.context(bundle, 2))
        with self.assertRaisesRegex(InputError, "Duplicate or ambiguous ARM"):
            review_context(self.control("C03.02"), bundle)
        bundle = self.bundle()
        base = bundle["resources"][2]
        bundle["resources"] += [
            {**copy.deepcopy(base), "arm_id": VM + str(i), "logical_id": VM + str(i)}
            for i in range(100)
        ]
        context = review_context(self.control("C03.02"), bundle)
        self.assertTrue(context["truncated"])
        self.assertEqual(context["matching_resources"], 101)
        self.assertTrue(all("unknown" in r["facts"] for r in context["resources"]))
        row = next(
            r
            for r in self.own(assess(bundle, self.catalog(), at=AT, evidence_tiers=True))
            if r["upstream_id"] == "C03.02"
        )
        self.assertEqual(row["observed"]["evidence_tier"], "needs_decision")

    def test_tag_bounds_explicit_zero_and_no_values(self):
        self.assertEqual(tag_count({}), 0)
        self.assertEqual(tag_count({str(i): "v" * 256 for i in range(50)}), 50)
        self.assertEqual(tag_count({"k" * 512: ""}), 1)
        self.assertEqual(tag_count({"k" * 128: ""}, storage=True), 1)
        for raw in (
            None,
            [],
            False,
            {"unknown": "unresolved"},
            {"Owner": "a", "owner": "b"},
            {"": "x"},
            {"key": 1},
            {"a/b": "x"},
            {"k": "x" * 257},
            {"k" * 513: "v"},
            {str(i): "v" for i in range(51)},
        ):
            self.assertIn("unknown", tag_count(raw))
        self.assertIn("unknown", tag_count({"k" * 129: "v"}, storage=True))
        for kind in TAG_KINDS:
            identity = (
                SUB
                if kind.endswith("/subscriptions")
                else RG
                if kind.endswith("/resourcegroups")
                else RG + "/providers/" + kind + "/authored"
            )
            bundle = self.bundle()
            bundle["scope"], bundle["metadata"] = SUB, {}
            bundle["resources"] = [
                {
                    **bundle["resources"][2],
                    "arm_id": identity,
                    "logical_id": identity,
                    "resource_type": kind,
                    "properties": {"tagCount": 0},
                }
            ]
            self.assertEqual(self.context(bundle, 0, ["tagCount"])["facts"], {"tagCount": 0})
        self.assertNotIn("tagCount", resource_paths(MG_KIND))

    def test_all_outputs_tiers_time_and_planned_observed_remain_separate(self):
        bundle, catalog = self.bundle(), self.catalog()
        report = assess(bundle, catalog, at=AT, evidence_tiers=True)
        own = self.own(report)
        self.assertEqual(len(own), 7)
        self.assertEqual(
            {r["upstream_id"]: r["observed"]["evidence_tier"] for r in own},
            {key: "manual" if key in {"C03.01", "C04.02"} else "signal" for key in OWN},
        )
        for format in ("json", "markdown", "html", "csv", "sarif", "pr-summary"):
            self.assertNotIn(PRIVATE, render(report, format))
        with zipfile.ZipFile(io.BytesIO(render_xlsx(report))) as archive:
            self.assertNotIn(PRIVATE, "".join(archive.read(n).decode() for n in archive.namelist()))
        for at in ("2000-01-01T00:00:00Z", UNTIL):
            changed = copy.deepcopy(bundle)
            changed["collected_at"] = at
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

    def test_review_context_uses_same_strict_facts_and_only_requested_paths(self):
        bundle = self.bundle()
        for display in ("C02.15", "C04.01"):
            context = review_context(self.control(display), bundle)
            self.assertEqual(
                context["resources"][1]["facts"],
                self.context(bundle, 1, ["managementParentId"])["facts"],
            )
            self.assertFalse(context["saved_management_hierarchy"]["complete"])
        context = review_context(self.control("C03.02"), bundle)
        self.assertEqual(context["resources"][0]["facts"], {"resourceLocation": "westeurope"})
        context = review_context(self.control("C04.03"), bundle)
        self.assertEqual(context["resources"][0]["facts"], {"tagCount": 1})
        for display in ("C03.01", "C04.02"):
            self.assertEqual(review_context(self.control(display), bundle)["resources"], [])
        bundle["scope"] = RG + "-foreign"
        self.assertEqual(review_context(self.control("C03.02"), bundle)["unbound_resources"], 1)

    def test_seven_blank_independent_decisions_and_binding_attribution_expiry(self):
        catalog, bundle = self.catalog(), self.bundle()
        report = assess(bundle, catalog, at=AT, evidence_tiers=True)
        item = self.matrix()["interview"]
        with self.interview():
            template = prepare_interview(report, catalog, item["id"], MG)
            self.assertEqual(len(template["decisions"]), 7)
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
            filled = self.filled(template)
            manual = compile_interview(filled, catalog, at=AT)
            self.assertEqual(len(manual["entries"]), 7)
            reviewed = self.own(assess(bundle, catalog, at=AT, manual=manual, evidence_tiers=True))
            self.assertTrue(all(r["observed"]["outcome"] == "fail" for r in reviewed))
            self.assertTrue(all(r["observed"]["evidence_tier"] != "verified" for r in reviewed))
            for field, value in (
                ("scope", SUB),
                ("reviewer", ""),
                ("evidence", ""),
                ("valid_until", AT),
                ("catalog_sha256", "0" * 64),
                ("requirements_sha256", "0" * 64),
            ):
                with self.assertRaises(InputError):
                    compile_interview({**filled, field: value}, catalog, at=AT)
            for decisions in (
                filled["decisions"][:-1],
                [filled["decisions"][0]] * 7,
                [{**d, "outcome": None} for d in filled["decisions"]],
            ):
                with self.assertRaises(InputError):
                    compile_interview({**filled, "decisions": decisions}, catalog, at=AT)
            changed = copy.deepcopy(catalog)
            next(c for c in changed["controls"] if c["upstream_id"] == "C04.01")["rationale"] += (
                " Changed."
            )
            with self.assertRaises(InputError):
                compile_interview(filled, changed, at=AT)
        self.assertNotIn(item["id"], BANK)

    def test_selection_binding_does_not_apply_to_unselected_or_expired_controls(self):
        bundle, catalog = self.bundle(), self.catalog()
        report = assess(bundle, catalog, at=AT, evidence_tiers=True)
        identity = "ALZ-" + OWN["C03.01"]
        with self.interview():
            key = self.matrix()["interview"]["id"]
            template = prepare_interview(report, catalog, key, MG, [identity])
            for selection in ([identity, identity], ["ALZ-not-this-cohort"], []):
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

    def test_session_exception_and_disk_failure_are_independent_and_atomic(self):
        session = ReviewSession(
            self.bundle(),
            self.catalog(),
            self.root / "session",
            clock=lambda: AT,
            evidence_tiers=True,
        )
        payload = dict(
            revision=0,
            control_id="ALZ-" + OWN["C04.02"],
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
        row = next(r for r in self.own(session.report) if r["upstream_id"] == "C04.02")
        self.assertEqual(row["observed"]["outcome"], "manual")
        self.assertEqual(row["observed"]["exception_disposition"], "accepted")
        before = copy.deepcopy(session.state())
        with self.assertRaises(InputError):
            session.save({**payload, "revision": 1, "rationale": "Unconfirmed replacement."})
        with patch.object(Path, "rename", side_effect=OSError("authored disk failure")):
            with self.assertRaisesRegex(OSError, "authored disk failure"):
                session.save({**payload, "revision": 1, "control_id": "ALZ-" + OWN["C03.01"]})
        self.assertEqual(session.state(), before)
        self.assertEqual(
            sorted(p.name for p in session.directory.iterdir()), ["revision-0000", "revision-0001"]
        )
        self.assertEqual(session.reviews["manual"]["entries"], [])

    def test_original_time_sanitization_replay_and_candidate_rejection(self):
        bundle, catalog = self.bundle(), self.catalog()
        sanitized = sanitize_evidence(bundle)
        self.assertEqual(sanitized["collected_at"], AT)
        self.assertNotIn(PRIVATE, json.dumps(sanitized))
        for display in ("C02.15", "C03.02", "C03.03", "C04.01", "C04.03"):
            self.assertEqual(
                review_context(self.control(display), sanitized),
                review_context(self.control(display), bundle),
            )
        with self.assertRaisesRegex(InputError, "differs from a packaged artifact"):
            export_bundle(self.root / "candidate", bundle, catalog, at=AT, evidence_tiers=True)
        accepted = load_catalog()
        export_bundle(self.root / "accepted", bundle, accepted, at=AT, evidence_tiers=True)
        replayed = replay_bundle(self.root / "accepted")
        self.assertEqual(
            semantic(replayed), semantic(assess(bundle, accepted, at=AT, evidence_tiers=True))
        )
        self.assertEqual(replayed["evidence"][0]["collected_at"], AT)

    def test_existing_adapters_local_module_plan_arm_and_sensitive_values(self):
        values = {
            "name": "authored",
            "resource_group_name": "authored",
            "location": "West Europe",
            "tags": {PRIVATE: PRIVATE},
            "admin_username": PRIVATE,
            "admin_password": PRIVATE,
        }
        source = self.write(
            "raw/main.tf.json",
            {"resource": {"azurerm_linux_virtual_machine": {"authored": values}}},
        )
        self.write("parent/main.tf.json", {"module": {"vm": {"source": "./module"}}})
        self.write("parent/module/main.tf.json", json.loads(source.read_text("utf-8")))
        module = source.parent
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
                        "sha256": tree_hash(module),
                    }
                ]
            },
        )
        planned = {
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
        arm = {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "resources": [
                {
                    "type": "Microsoft.Compute/virtualMachines",
                    "apiVersion": "2024-07-01",
                    "name": "authored",
                    "location": "West Europe",
                    "tags": {PRIVATE: PRIVATE},
                    "properties": {"osProfile": {PRIVATE: PRIVATE}},
                }
            ],
        }
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
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
                plan_source(self.write("plan.json", planned), scope=RG, provider_version="4.50.0"),
                arm_source(self.write("arm.json", arm), scope=RG),
            ]
        for bundle in bundles:
            self.assertNotIn(PRIVATE, json.dumps(bundle))
            self.assertEqual(bundle["resources"][0]["properties"]["resourceLocation"], "westeurope")
            self.assertEqual(self.context(bundle, 0, ["tagCount"])["facts"], {"tagCount": 1})
            self.assertEqual(
                self.context(bundle, 0, ["resourceLocation"])["facts"],
                {"resourceLocation": "westeurope"},
            )
        resource = planned["planned_values"]["root_module"]["resources"][0]
        resource["sensitive_values"] = {"location": True, "tags": True}
        sensitive = plan_source(
            self.write("sensitive.json", planned), scope=RG, provider_version="4.50.0"
        )
        self.assertIn("unknown", self.context(sensitive, 0)["facts"]["resourceLocation"])
        self.assertIn("unknown", self.context(sensitive, 0)["facts"]["tagCount"])
        for kind in ("azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine"):
            self.assertEqual(tf_properties(kind, values)["tagCount"], 1)
        mg = tf_properties(
            "azurerm_management_group",
            {"name": PRIVATE, "display_name": PRIVATE, "parent_management_group_id": MG},
        )
        self.assertEqual(mg, {"managementParentId": MG})

    def test_cli_and_injected_collector_add_no_live_or_availability_transport(self):
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
        self.assertEqual(len(self.own(report)), 7)
        self.assertNotIn("query_signals", report)
        self.assertNotIn(PRIVATE, json.dumps(report))
        seen = []

        def transport(method, url, body=None):
            seen.append(url.lower())
            if "/resources?" in url:
                return Response(200, {"value": [{"id": VM, "type": VM_KIND}]}, {})
            return Response(200, {"value": []}, {})

        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            bundle = Collector(transport).collect(
                subscriptions=[SUB.split("/")[2]], inventory_authorized=True
            )
        self.assertTrue(
            all(
                not any(
                    s in url
                    for s in (
                        "quota",
                        "availability",
                        "billing",
                        "graph",
                        "microsoft.compute/virtualmachines/",
                    )
                )
                for url in seen
            )
        )
        self.assertNotIn(VM_KIND, API_VERSIONS)
        self.assertNotIn(MG_KIND, API_VERSIONS)
        self.assertEqual(PLANNED_API_VERSIONS[VM_KIND], {"2024-07-01"})
        for path in ("resourceLocation", "tagCount"):
            self.assertIn("unknown", self.context(bundle, 0, [path])["facts"][path])

    def test_raw_hcl_parent_projection_and_unsupported_schema_stay_explicit(self):
        source = self.root / "main.tf"
        source.write_text(
            'resource "azurerm_management_group" "child" {\n'
            ' name = "not-a-confidential-role"\n'
            f' parent_management_group_id = "{MG}"\n'
            f' display_name = "{PRIVATE}"\n'
            '}\nresource "azurerm_linux_virtual_machine" "vm" {\n'
            ' name = "authored"\n resource_group_name = "authored"\n'
            ' location = "West Europe"\n tags = {}\n}\n',
            encoding="utf-8",
        )
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            bundle = terraform_source(self.root, scope=RG, provider_version="4.50.0")
        self.assertEqual(bundle["resources"][0]["properties"], {"managementParentId": MG})
        self.assertEqual(self.context(bundle, 1, ["tagCount"])["facts"], {"tagCount": 0})
        self.assertNotIn(PRIVATE, json.dumps(bundle))
        template = self.write(
            "unsupported.json",
            {
                "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                "contentVersion": "1.0.0.0",
                "resources": [
                    {
                        "type": "Microsoft.Compute/virtualMachines",
                        "apiVersion": "2099-01-01",
                        "name": "authored",
                        "location": "West Europe",
                        "tags": {},
                        "properties": {},
                    }
                ],
            },
        )
        unsupported = arm_source(template, scope=RG)
        self.assertIn("unknown", self.context(unsupported, 0))

    @unittest.skipUnless(os.environ.get("BICEP_COMPILER"), "existing Bicep compiler not supplied")
    def test_real_bicep_location_and_tag_configuration_without_restore(self):
        source = ROOT / "tests" / "fixtures" / "sovereign" / "configuration.bicep"
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        copied = self.root / "configuration.bicep"
        copied.write_bytes(source.read_bytes())
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            compiled = compile_bicep(copied, compiler=os.environ["BICEP_COMPILER"])
            bundle = arm_source(copied, scope=RG, bicep=True, compiler=os.environ["BICEP_COMPILER"])
        self.assertEqual(len(compiled["template"]["resources"]), 2)
        self.assertEqual(
            [
                self.context(bundle, i, ["resourceLocation"])["facts"]["resourceLocation"]
                for i in (0, 1)
            ],
            ["westeurope", "northeurope"],
        )
        self.assertEqual(
            [self.context(bundle, i, ["tagCount"])["facts"]["tagCount"] for i in (0, 1)], [1, 0]
        )
        self.assertNotIn(PRIVATE, json.dumps(bundle))
        report = assess(bundle, self.catalog(), at=bundle["collected_at"], evidence_tiers=True)
        self.assertTrue(all(r["planned"]["outcome"] == "manual" for r in self.own(report)))
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), before)
        self.assertFalse(source.with_suffix(".json").exists())


if __name__ == "__main__":
    unittest.main()
