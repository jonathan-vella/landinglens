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

from alz_assessor import interviews
from alz_assessor.arm import API_VERSIONS, PLANNED_API_VERSIONS, arm_source, properties
from alz_assessor.azure import Collector, Response
from alz_assessor.bicep import compile_bicep
from alz_assessor.billing_evidence import (
    BUDGET,
    GRAINS,
    GUIDS,
    OPERATORS,
    TF_KINDS,
    budget_parent,
    configuration,
    notifications,
    resource_context,
    review_fact,
)
from alz_assessor.catalog import load_catalog
from alz_assessor.cli import main
from alz_assessor.comparison import compare
from alz_assessor.contracts import control_digest, document, validate
from alz_assessor.engine import assess
from alz_assessor.plan import plan_source
from alz_assessor.replay import export_bundle, replay_bundle, sanitize_evidence, semantic
from alz_assessor.reports import render, render_xlsx
from alz_assessor.review_page import review_page
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import review_context
from alz_assessor.sources import terraform_source, tf_properties, tf_resource_id
from alz_assessor.terraform import InputError, tree_hash
from alz_assessor.tiers import has_fact

ROOT = Path(__file__).resolve().parents[1]
PREPARATION = ROOT / "references" / "preparation"
SUB = "/subscriptions/00000000-0000-0000-0000-000000000001"
RG = SUB + "/resourcegroups/authored"
OTHER = "/subscriptions/00000000-0000-0000-0000-000000000002"
ID = RG + "/providers/" + BUDGET + "/authored"
AT = "2026-11-07T02:00:00Z"
UNTIL = "2026-11-08T02:00:00Z"
PRIVATE = "PRIVATE-NOT-FOR-REPORTING"
OWN = {
    "A03.03": "54f0d8b1-22a3-4c0d-8ce2-58b9e086c93a",
    "A03.04": "ca0fe401-12ad-46fc-8a7e-86293866a9f6",
    "A03.05": "5cf9f485-2784-49b3-9824-75d9b8bdb57b",
    "A04.01": "6ad5c3dd-e5ea-4ff1-81a4-7886ff87845c",
    "A04.02": "90e87802-602f-4dfb-acea-67c60689f1d7",
    "A04.03": "e81a73f0-84c4-4641-b406-14db3b4d1f50",
    "A04.04": "ae757485-92a4-482a-8bc9-eefe6f5b5ec3",
}
CONTROLS = {"ALZ-" + guid for guid in OWN.values()}


class BillingPreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.matrix = json.loads((PREPARATION / "batch-03.json").read_text("utf-8"))
        self.catalog = copy.deepcopy(load_catalog())
        self.catalog["review_state"] = "authored-preparation-fixture-not-published"
        rows = {r["guid"]: r for r in self.matrix["recommendations"]}
        for control in self.catalog["controls"]:
            if control["upstream_guid"] not in rows:
                continue
            row = rows[control["upstream_guid"]]
            for key in ("review_resource_types", "review_fact_paths", "evidence_requirements"):
                if key in row:
                    control[key] = copy.deepcopy(row[key])
            control["rationale"] = row["limitations"]
        validate(self.catalog, "catalog")

    def control(self, upstream="A03.03"):
        return next(c for c in self.catalog["controls"] if c["upstream_guid"] == OWN[upstream])

    def raw(self):
        return {
            "category": "Cost",
            "timeGrain": "Monthly",
            "amount": PRIVATE,
            "currency": PRIVATE,
            "currentSpend": PRIVATE,
            "filter": {PRIVATE: PRIVATE},
            "timePeriod": {PRIVATE: PRIVATE},
            "notifications": {
                PRIVATE: {
                    "enabled": True,
                    "operator": "GreaterThan",
                    "thresholdType": "Actual",
                    "threshold": PRIVATE,
                    "contactEmails": [PRIVATE],
                    "contactRoles": [PRIVATE],
                    "contactGroups": [PRIVATE],
                    "webhook": PRIVATE,
                }
            },
        }

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
                    "logical_id": ID,
                    "arm_id": ID,
                    "resource_type": BUDGET,
                    "state": "known",
                    "reason": "",
                    "source_location": "fixture://authored-budget",
                    "properties": properties(BUDGET, self.raw()),
                }
            ],
        )

    def context(self, bundle=None):
        bundle = bundle or self.bundle()
        by_id = {}
        for row in bundle["resources"]:
            by_id.setdefault((row.get("arm_id") or "").lower(), []).append(row)
        return resource_context(bundle["resources"][0], by_id, bundle)

    def tier(self, bundle, upstream="A03.03", *, at=AT):
        report = assess(bundle, self.catalog, at=at, evidence_tiers=True)
        return next(r[bundle["mode"]] for r in report["results"] if r["upstream_id"] == upstream)

    def plan(self, kind, values):
        path = self.root / "plan.json"
        path.write_text(
            json.dumps(
                {
                    "format_version": "1.2",
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
        return path

    def test_exact_seven_guids_sources_and_unchanged_accepted_boundary(self):
        targets = ROOT / "references" / "recommendation-batches" / "targets.json"
        rows = json.loads(targets.read_text("utf-8"))["targets"]
        self.assertEqual({r["upstream_id"]: r["guid"] for r in rows if r["batch"] == "03"}, OWN)
        self.assertEqual(set(OWN.values()), GUIDS)
        self.assertEqual(
            hashlib.sha256(targets.read_bytes()).hexdigest(),
            "582fe02feee03b50961e5548fa7551bbd3d8729fbcb68f51837d548e59eaa291",
        )
        self.assertEqual(self.matrix["review_state"], "source-reviewed-preparation-not-accepted")
        self.assertNotIn("catalog_version", self.matrix)
        self.assertNotIn("accepted_at", self.matrix)
        self.assertEqual({r["upstream_id"]: r["guid"] for r in self.matrix["recommendations"]}, OWN)
        manifest = json.loads((PREPARATION / "batch-03-sources.json").read_text("utf-8"))
        self.assertEqual(manifest["review_state"], "preparation-only-reviewed")
        indexed = {r["id"]: r for r in manifest["sources"]}
        self.assertEqual(len(indexed), 20)
        for source in indexed.values():
            self.assertRegex(source["sha256"], r"^[0-9a-f]{64}$")
            self.assertTrue(source["finding"])
            self.assertTrue(source["reuse"])
            self.assertTrue(source["resolved_url"].startswith("https://"))
            if source["id"].endswith("-offer"):
                self.assertEqual(source["revision"], "retrieved-page")
            else:
                self.assertRegex(source["revision"], r"^[0-9a-f]{40}$")
        for row in self.matrix["recommendations"]:
            self.assertTrue(set(row["sources"]) <= set(indexed))
            self.assertEqual(
                row["classification"], "manual" if row["upstream_id"] == "A04.04" else "assisted"
            )
            self.assertNotIn("rule", row)
            self.assertTrue(
                all(
                    r.startswith(("Preparation:", "Reviewer decision:"))
                    for r in row["evidence_requirements"]
                )
            )
        self.assertNotIn(self.matrix["interview"]["id"], interviews.BANK)
        self.assertEqual(len(load_catalog()["controls"]), 255)

    def test_explicit_metadata_only_no_defaults_financial_or_recipient_payload(self):
        fact = configuration(self.raw())
        self.assertEqual(fact["category"], "Cost")
        self.assertEqual(fact["timeGrain"], "Monthly")
        self.assertEqual(
            fact["notifications"],
            [
                {
                    "enabled": True,
                    "operator": "GreaterThan",
                    "thresholdType": "Actual",
                }
            ],
        )
        self.assertNotIn(PRIVATE, json.dumps(fact))
        for grain in GRAINS:
            self.assertEqual(configuration({"timeGrain": grain})["timeGrain"], grain)
        for operator in OPERATORS:
            for kind in ("Actual", "Forecasted"):
                row = {"enabled": False, "operator": operator, "thresholdType": kind}
                self.assertEqual(notifications({"name": row}), [row])
        fact = configuration({})
        self.assertTrue(all("unknown" in value for value in fact.values()))
        tf = tf_properties(
            "azurerm_consumption_budget_subscription",
            {
                "amount": PRIVATE,
                "notification": [{}],
            },
        )["budgetConfiguration"]
        self.assertIn("unknown", tf["category"])
        self.assertIn("unknown", tf["timeGrain"])
        self.assertTrue(all("unknown" in v for v in tf["notifications"][0].values()))

    def test_notification_shapes_types_five_bound_and_no_threshold_predicate(self):
        row = next(iter(self.raw()["notifications"].values()))
        self.assertEqual(len(notifications({str(i): row for i in range(5)})), 5)
        for raw in (
            None,
            [],
            False,
            {"unknown": "denied"},
            {str(i): row for i in range(6)},
            {"a": None},
            {"a": []},
            {"a": {"unknown": "partial"}},
        ):
            self.assertIn("unknown", notifications(raw))
        for raw in (None, {}, False, [row] * 6, [None], [{"unknown": "partial"}]):
            self.assertIn("unknown", notifications(raw, terraform=True))
        self.assertEqual(notifications({}), [])
        self.assertEqual(notifications([], normalized=True), [])
        for value in (None, True, 1, [], PRIVATE, {"unknown": "denied"}):
            for field in ("operator", "thresholdType", "timeGrain", "category"):
                changed = self.raw()
                if field in {"operator", "thresholdType"}:
                    changed["notifications"][PRIVATE][field] = value
                    result = configuration(changed)["notifications"][0][field]
                else:
                    changed[field] = value
                    result = configuration(changed)[field]
                self.assertIn("unknown", result)
            if value is not True:
                changed = copy.deepcopy(row)
                changed["enabled"] = value
                self.assertIn("unknown", notifications({"a": changed})[0]["enabled"])
        changed = self.raw()
        changed["notifications"][PRIVATE]["threshold"] = -1000000
        self.assertEqual(configuration(changed), configuration(self.raw()))
        self.assertNotIn("threshold", configuration(changed)["notifications"][0])

    def test_notification_keys_and_order_are_discarded_not_a_private_side_channel(self):
        one = {"enabled": True, "operator": "EqualTo", "thresholdType": "Actual"}
        two = {"enabled": False, "operator": "GreaterThan", "thresholdType": "Forecasted"}
        self.assertEqual(
            notifications({"financial-key": one, PRIVATE: two}),
            notifications({"other-key": two, "third-key": one}),
        )
        self.assertEqual(
            configuration(self.raw()),
            review_fact({"budgetConfiguration": configuration(self.raw())}, "budgetConfiguration"),
        )

    def test_unique_known_typed_selected_scope_relationship_required(self):
        self.assertIn("facts", self.context())
        for change in ("duplicate", "denied", "unbound", "wrong-type", "billing", "mg", "child"):
            bundle = self.bundle()
            row = bundle["resources"][0]
            if change == "duplicate":
                bundle["resources"].append(copy.deepcopy(row))
            elif change == "denied":
                row["state"], row["reason"] = "unknown", "authorization_denied"
            elif change == "unbound":
                bundle["scope"] = OTHER
            elif change == "wrong-type":
                row["resource_type"] = "Microsoft.CostManagement/views"
            else:
                row["arm_id"] = {
                    "billing": "/providers/microsoft.billing/billingaccounts/private/providers/"
                    + BUDGET
                    + "/authored",
                    "mg": "/providers/microsoft.management/managementgroups/root/providers/"
                    + BUDGET
                    + "/authored",
                    "child": ID + "/unsupported/child",
                }[change]
            self.assertIn("unknown", self.context(bundle), change)
        for parent in (SUB, RG):
            self.assertEqual(budget_parent(parent + "/providers/" + BUDGET + "/authored"), parent)
        for raw in (None, False, PRIVATE, SUB, ID + "/child"):
            self.assertIsNone(budget_parent(raw))

    def test_no_whole_pass_or_verified_or_other_six_machine_signals(self):
        bundle = self.bundle()
        for upstream in OWN:
            body = self.tier(bundle, upstream)
            self.assertNotEqual(body["outcome"], "pass")
            self.assertEqual(
                body["evidence_tier"],
                "signal"
                if upstream == "A03.03"
                else "manual"
                if upstream == "A04.04"
                else "needs_decision",
            )
        for change in ("duplicate", "unknown", "absent", "empty-facts"):
            changed = copy.deepcopy(bundle)
            if change == "duplicate":
                changed["resources"].append(copy.deepcopy(changed["resources"][0]))
                changed["resources"][-1]["logical_id"] = "distinct-logical-same-arm-id"
                with self.assertRaises(InputError):
                    self.tier(changed)
                continue
            elif change == "unknown":
                changed["resources"][0]["state"] = "unknown"
                changed["resources"][0]["reason"] = "authorization_denied"
            elif change == "absent":
                changed["resources"] = []
            else:
                changed["resources"][0]["properties"] = {}
            self.assertEqual(self.tier(changed)["evidence_tier"], "needs_decision")
        self.assertEqual(
            self.tier(bundle, at="2026-11-09T02:00:00Z")["evidence_tier"], "needs_decision"
        )
        planned = copy.deepcopy(bundle)
        planned["mode"], planned["source"] = "planned", "arm"
        report = compare(
            assess(planned, self.catalog, at=AT, evidence_tiers=True),
            assess(bundle, self.catalog, at=AT, evidence_tiers=True),
            at=AT,
        )
        own = next(r for r in report["results"] if r["upstream_id"] == "A03.03")
        self.assertEqual(own["planned"]["evidence_tier"], "signal")
        self.assertEqual(own["observed"]["evidence_tier"], "signal")

    def test_invalid_scope_context_never_exposes_unbound_facts_or_subchecks(self):
        bundle = self.bundle()
        bundle["resources"].append(copy.deepcopy(bundle["resources"][0]))
        bundle["resources"][-1]["logical_id"] = "distinct-logical-same-arm-id"
        with self.assertRaises(InputError):
            review_context(self.control(), bundle)
        bundle["resources"].pop()
        bundle["resources"][0]["state"] = "unknown"
        bundle["resources"][0]["reason"] = "authorization_denied"
        context = review_context(self.control(), bundle)
        self.assertTrue(all("unknown" in row["facts"] for row in context["resources"]))
        self.assertTrue(all(row["subchecks"] == {} for row in context["resources"]))
        bundle["scope"] = OTHER
        self.assertEqual(review_context(self.control(), bundle)["matching_resources"], 0)

    def test_raw_terraform_and_explicit_local_module_parity(self):
        module = self.root / "module"
        module.mkdir()
        (module / "main.tf").write_text(
            'resource "azurerm_consumption_budget_resource_group" "authored" {\n'
            f'name="authored"\nresource_group_id="{RG}"\namount=10\ntime_grain="Monthly"\n'
            'time_period {\nstart_date="2026-11-01T00:00:00Z"\n}\nnotification {\n'
            'enabled=true\noperator="GreaterThan"\nthreshold_type="Actual"\nthreshold=50\n'
            f'contact_emails=["{PRIVATE}"]\n}}\n}}\n'
        )
        raw = terraform_source(module, scope=SUB, provider_version="4.50.0")
        self.assertEqual(raw["resources"][0]["arm_id"], ID)
        self.assertNotIn(PRIVATE, json.dumps(raw))
        wrapper = self.root / "wrapper"
        wrapper.mkdir()
        (wrapper / "main.tf").write_text(
            'module "supplied" {\nsource="example.invalid/budget/azurerm"\nversion="1.0.0"\n}\n'
        )
        manifest = self.root / "snapshots.json"
        manifest.write_text(
            json.dumps(
                {
                    "modules": [
                        {
                            "source": "example.invalid/budget/azurerm",
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
            scope=SUB,
            provider_version="4.50.0",
            snapshots=manifest,
            authorized_roots=[self.root],
        )
        self.assertEqual(supplied["resources"][0]["properties"], raw["resources"][0]["properties"])
        unknown = terraform_source(module, scope=SUB, provider_version="unreviewed")
        self.assertEqual(unknown["resources"][0]["state"], "unknown")
        self.assertEqual(unknown["resources"][0]["properties"], {})

    def test_plan_and_raw_typed_ids_versions_sensitive_and_conflicting_scope(self):
        for kind, key in TF_KINDS.items():
            target = SUB if key == "subscription_id" else RG
            values = {
                "name": "authored",
                key: target,
                "time_grain": "Monthly",
                "notification": [
                    {
                        "enabled": True,
                        "operator": "GreaterThan",
                        "threshold_type": "Actual",
                        "contact_emails": [PRIVATE],
                    }
                ],
            }
            expected = target + "/providers/" + BUDGET + "/authored"
            self.assertEqual(tf_resource_id(SUB, kind, values), expected)
            path = self.plan(kind, values)
            planned = plan_source(path, scope=SUB, provider_version="4.50.0")
            self.assertEqual(planned["resources"][0]["arm_id"], expected)
            self.assertEqual(planned["resources"][0]["properties"], tf_properties(kind, values))
            self.assertNotIn(PRIVATE, json.dumps(planned))
            self.assertEqual(
                plan_source(path, scope=SUB, provider_version="unreviewed")["resources"][0][
                    "state"
                ],
                "unknown",
            )
            data = json.loads(path.read_text())
            entry = data["planned_values"]["root_module"]["resources"][0]
            entry["sensitive_values"] = {"notification": True, "time_grain": True}
            path.write_text(json.dumps(data))
            sensitive = plan_source(path, scope=SUB, provider_version="4.50.0")
            self.assertFalse(
                has_fact(sensitive["resources"][0]["properties"]["budgetConfiguration"])
            )
            values["id"] = OTHER + "/providers/" + BUDGET + "/authored"
            with self.assertRaises(InputError):
                plan_source(self.plan(kind, values), scope=SUB, provider_version="4.50.0")
            for bad in (
                None,
                True,
                PRIVATE,
                OTHER,
                "/providers/microsoft.management/managementgroups/root",
            ):
                self.assertIsNone(tf_resource_id(SUB, kind, {**values, key: bad}))
            self.assertIsNone(tf_resource_id(OTHER, kind, values))

    def test_arm_exact_version_and_no_new_collector_route(self):
        path = self.root / "arm.json"
        template = {
            "resources": [
                {
                    "type": "Microsoft.Consumption/budgets",
                    "apiVersion": "2024-08-01",
                    "name": "authored",
                    "properties": self.raw(),
                }
            ]
        }
        path.write_text(json.dumps(template))
        bundle = arm_source(path, scope=RG)
        self.assertEqual(bundle["resources"][0]["state"], "known")
        self.assertEqual(bundle["resources"][0]["arm_id"], ID)
        self.assertNotIn(PRIVATE, json.dumps(bundle))
        template["resources"][0]["apiVersion"] = "2026-06-01"
        path.write_text(json.dumps(template))
        row = arm_source(path, scope=RG)["resources"][0]
        self.assertEqual(row["state"], "unknown")
        self.assertEqual(row["properties"], {})
        self.assertNotIn(BUDGET, API_VERSIONS)
        self.assertEqual(PLANNED_API_VERSIONS[BUDGET], {"2024-08-01"})
        requests = []

        def transport(method, url):
            requests.append((method, url))
            return Response(
                200,
                {"value": [{"id": ID, "type": BUDGET}]} if "/resources?" in url else {"value": []},
                {},
            )

        collected = Collector(transport).collect(
            subscriptions=[SUB.split("/")[2]],
            inventory_authorized=True,
        )
        self.assertFalse(any("consumption" in url.lower() for _, url in requests))
        self.assertTrue(all(not r["properties"] for r in collected["resources"]))

    def test_interview_selection_binding_time_attribution_and_independent_exceptions(self):
        question = self.matrix["interview"]
        with patch.dict(interviews.BANK, {question["id"]: question}):
            bundle = self.bundle()
            report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
            response = interviews.prepare_interview(report, self.catalog, question["id"], SUB)
            self.assertEqual(len(response["decisions"]), 7)
            self.assertTrue(all(row["outcome"] is None for row in response["decisions"]))
            with self.assertRaises(InputError):
                interviews.compile_interview(response, self.catalog, at=AT)
            response.update(
                answer="Authored fixture only, not owner or financial assurance.",
                reviewer="Fixture",
                rationale="Independent synthetic decisions.",
                evidence="https://example.invalid/redacted",
                valid_from=AT,
                valid_until=UNTIL,
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
                    when = "2026-11-09T02:00:00Z"
                elif change == "blank":
                    invalid["decisions"][0]["outcome"] = None
                elif change == "attribution":
                    invalid["reviewer"] = ""
                elif change == "scope":
                    invalid["scope"] = OTHER
                elif change == "selection":
                    invalid["decisions"].pop()
                elif change == "duplicate":
                    invalid["decisions"][-1] = invalid["decisions"][0]
                else:
                    invalid["valid_from"] = UNTIL
                with self.assertRaises(InputError):
                    interviews.compile_interview(invalid, self.catalog, at=when)
            selected = interviews.prepare_interview(
                report,
                self.catalog,
                question["id"],
                SUB,
                selected=[question["controls"][0]],
            )
            self.assertEqual(len(selected["decisions"]), 1)
            exceptions = document(
                "exceptions",
                schema_version="1.1",
                entries=[
                    {k: v for k, v in manual["entries"][0].items() if k != "outcome"}
                    | {"disposition": "accepted"},
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
            own = [r for r in report["results"] if r["control_id"] in CONTROLS]
            self.assertEqual(len(own), 7)
            self.assertTrue(all(r["observed"]["evidence_tier"] != "verified" for r in own))
            self.assertEqual(
                sum(r["observed"]["exception_disposition"] == "accepted" for r in own), 1
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
            self.assertIn("A04.04", review_page(session.state(), "token", "nonce"))
            invalid = copy.deepcopy(response)
            invalid["decisions"][-1]["outcome"] = None
            with self.assertRaises(InputError):
                session.save_interview({"revision": 0, "response": invalid, "replace_existing": []})
            self.assertEqual(session.revision, 0)
            self.assertFalse((session.directory / "revision-0001").exists())
            session.save_interview({"revision": 0, "response": response, "replace_existing": []})
            self.assertEqual(len(session.state()["records"]), 7)
            resumed = ReviewSession.resume(
                session.directory / "revision-0001", self.root / "resumed", clock=lambda: AT
            )
            self.assertEqual(semantic(session.report), semantic(resumed.report))

    def test_all_seven_decisions_bind_distinct_source_requirements(self):
        for upstream in OWN:
            control = self.control(upstream)
            changed = copy.deepcopy(control)
            changed["evidence_requirements"].append("Changed specific decision")
            self.assertNotEqual(control_digest(changed), control_digest(control))
        all_requirements = [
            tuple(self.control(upstream)["evidence_requirements"]) for upstream in OWN
        ]
        self.assertEqual(len(set(all_requirements)), 7)

    def test_privacy_original_time_replay_and_candidate_rejection(self):
        bundle = self.bundle()
        minimized = sanitize_evidence(bundle)
        self.assertNotIn(PRIVATE, json.dumps(minimized))
        self.assertEqual(self.context(bundle), self.context(minimized))
        self.assertEqual(
            semantic(assess(bundle, self.catalog, at=AT, evidence_tiers=True)),
            semantic(assess(minimized, self.catalog, at=AT, evidence_tiers=True)),
        )
        directory = self.root / "candidate"
        with self.assertRaises(InputError):
            export_bundle(directory, bundle, self.catalog, at=AT, evidence_tiers=True)
        for version in (None, "2026-11-06.22"):
            catalog = load_catalog(
                str(ROOT / "src" / "alz_assessor" / "data" / f"catalog-{version}.json")
                if version
                else None,
            )
            directory = self.root / (version or "current")
            export_bundle(directory, bundle, catalog, at=AT, evidence_tiers=True)
            self.assertEqual(
                semantic(replay_bundle(directory)),
                semantic(assess(bundle, catalog, at=AT, evidence_tiers=True)),
            )

    def test_injected_budget_payload_is_minimized_before_session_persistence(self):
        bundle = self.bundle()
        props = bundle["resources"][0]["properties"]
        props["amount"] = PRIVATE
        props["contactEmails"] = [PRIVATE]
        props["budgetConfiguration"]["notifications"][0]["contactRoles"] = [PRIVATE]
        props["budgetConfiguration"]["invoice"] = PRIVATE
        session = ReviewSession(
            bundle,
            self.catalog,
            self.root / "private-session",
            clock=lambda: AT,
            evidence_tiers=True,
        )
        self.assertNotIn(PRIVATE, json.dumps(session.evidence))
        self.assertEqual(self.context(session.evidence), self.context(self.bundle()))
        for path in session.directory.rglob("*"):
            if path.is_file() and path.suffix in {".json", ".html", ".csv", ".md"}:
                self.assertNotIn(PRIVATE, path.read_text("utf-8"))
        self.assertIn(PRIVATE, json.dumps(bundle))

    def test_cli_saved_evidence_uses_same_seven_workflows(self):
        evidence, catalog, output = (
            self.root / p for p in ("evidence.json", "catalog.json", "report.json")
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
        self.assertEqual(sum(r["control_id"] in CONTROLS for r in report["results"]), 7)
        self.assertNotIn(PRIVATE, output.read_text())

    @unittest.skipUnless(os.environ.get("BICEP_COMPILER"), "No existing Bicep compiler supplied")
    def test_real_bicep_budget_configuration_without_restore(self):
        path = ROOT / "tests" / "fixtures" / "billing" / "main.bicep"
        compiled = compile_bicep(path, compiler=os.environ["BICEP_COMPILER"])
        self.assertEqual(len(compiled["template"]["resources"]), 1)
        bundle = arm_source(path, scope=RG, bicep=True, compiler=os.environ["BICEP_COMPILER"])
        self.assertEqual(bundle["resources"][0]["state"], "known")
        self.assertEqual(bundle["resources"][0]["arm_id"], ID)
        facts = self.context(bundle)["facts"]["budgetConfiguration"]
        self.assertEqual(facts["category"], "Cost")
        self.assertEqual(facts["timeGrain"], "Monthly")
        self.assertTrue(facts["notifications"][0]["enabled"])
        self.assertEqual(self.tier(bundle, at=bundle["collected_at"])["evidence_tier"], "signal")
