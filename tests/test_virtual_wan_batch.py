import copy
import hashlib
import json
import unittest
import zipfile
from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
from importlib.resources import files
from io import BytesIO, StringIO
from unittest.mock import patch

import test_virtual_wan_preparation as preparation

from alz_assessor.catalog import load_catalog
from alz_assessor.cli import main
from alz_assessor.contracts import digest, document, validate
from alz_assessor.diagnostics import guidance
from alz_assessor.engine import assess
from alz_assessor.interviews import BANK, compile_interview, prepare_interview, question_bank
from alz_assessor.replay import export_bundle, replay_bundle, semantic
from alz_assessor.reports import render, render_xlsx
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import prepare_reviews, review_context
from alz_assessor.terraform import InputError
from alz_assessor.tiers import prepared_signal

AT, SCOPE = preparation.AT, preparation.SCOPE
GUIDS = preparation.GUIDS
CONTROLS = {"ALZ-" + guid for guid in GUIDS.values()}
ASPATH = "ALZ-" + GUIDS["D10.07"]
QUESTION = "virtual-wan-topology-routing-capacity"


class VirtualWanBatchTests(unittest.TestCase):
    def setUp(self):
        self.fixture = preparation.VirtualWanPreparationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        data = files("alz_assessor").joinpath("data")
        frozen = data.joinpath("catalog-2026-11-06.12.json")
        self.catalog = load_catalog(str(frozen)) if frozen.is_file() else load_catalog()

    def report(self, bundle=None, **options):
        return assess(
            bundle if bundle is not None else self.fixture.bundle(),
            self.catalog,
            at=AT,
            evidence_tiers=True,
            **options,
        )

    def rows(self, report):
        return {r["control_id"]: r for r in report["results"] if r["control_id"] in CONTROLS}

    def body(self, bundle):
        return self.rows(self.report(bundle))[ASPATH][bundle["mode"]]

    def completed(self):
        response = prepare_interview(self.report(), self.catalog, QUESTION, SCOPE)
        response.update(
            answer="Authored fixture: review independent scenario and operational records.",
            reviewer="Fixture reviewer",
            evidence="fixture://redacted-requirements",
            rationale="Explicit separate fixture decisions, not actual tenant assurance.",
            valid_from=AT,
            valid_until="2026-11-07T00:00:00Z",
        )
        for index, row in enumerate(response["decisions"]):
            row["outcome"] = "pass" if index % 2 else "fail"
        return response

    def test_exact_predecessor_bytes_guids_controls_and_crosswalk_preserved(self):
        data = files("alz_assessor").joinpath("data")
        for name, expected in (
            (
                "catalog-2026-11-06.11.json",
                "4da9af73eda71cc3f672c16b53d650afb9464e6e3fed8762e777087401fb60ea",
            ),
            (
                "crosswalk-2026-11-06.11.json",
                "8e65fa7306ae0c7a57793575ec580d975bfaca552b71aee4d4128cdc29ce18ec",
            ),
        ):
            self.assertEqual(hashlib.sha256(data.joinpath(name).read_bytes()).hexdigest(), expected)
        previous = load_catalog(str(data.joinpath("catalog-2026-11-06.11.json")))
        before = {c["upstream_guid"]: c for c in previous["controls"]}
        self.assertEqual(self.catalog["catalog_version"], "2026-11-06.12")
        self.assertEqual(len(self.catalog["controls"]), 255)
        self.assertEqual(
            Counter(c["automation"] for c in self.catalog["controls"]),
            {"automated": 12, "assisted": 200, "manual": 43},
        )
        for control in self.catalog["controls"]:
            if control["upstream_guid"] not in GUIDS.values():
                self.assertEqual(control, before[control["upstream_guid"]])
        crosswalk = json.loads(data.joinpath("crosswalk.json").read_text("utf-8"))
        historical = json.loads(data.joinpath("crosswalk-2026-11-06.11.json").read_text("utf-8"))
        self.assertEqual(crosswalk["entries"], historical["entries"])
        self.assertEqual(crosswalk["sources"], historical["sources"])
        packaged = json.loads(data.joinpath("batch-matrix-2026-11-06.12.json").read_text("utf-8"))
        predecessor = json.loads(
            data.joinpath("batch-matrix-2026-11-06.11.json").read_text("utf-8")
        )
        self.assertEqual(packaged["batches"][:-1], predecessor["batches"])
        self.assertEqual(packaged["sources"][:-1], predecessor["sources"])
        matrix = json.loads((preparation.REFERENCE / "batch-20.json").read_text("utf-8"))
        self.assertEqual(packaged["batches"][-1], matrix)
        self.assertEqual({r["upstream_id"]: r["guid"] for r in matrix["recommendations"]}, GUIDS)
        self.assertEqual(
            packaged["sources"][-1]["sources"],
            json.loads((preparation.REFERENCE / "preparation-20-sources.json").read_text())[
                "sources"
            ],
        )

    def test_all_113_older_rows_and_thirteen_receipts_remain_exact(self):
        ledger = json.loads((preparation.REFERENCE / "ledger.json").read_text("utf-8"))
        batches = {"01", "17", "18", "19", "11", "04", "13", "22", "14", "12", "15", "08", "30"}
        rows = [r for r in ledger["recommendations"] if r["batch"] in batches]
        receipts = {key: value for key, value in ledger["deliveries"].items() if key in batches}
        self.assertEqual(len(rows), 113)
        self.assertEqual(len(receipts), 13)
        self.assertEqual(
            digest(rows), "52cf6f264525a34b3e85af5ebbecffca6fa1785e2ad0253db3902258b36c5734"
        )
        self.assertEqual(
            digest(receipts), "b83a304433173edb053f23529200ce0afc43b455d94d72438514dacbcc563672"
        )
        self.assertTrue(all(r["status"] == "merged" for r in rows))

    def test_actual_cohort20_receipt_binds_all_nine_immutable_guids(self):
        ledger = json.loads((preparation.REFERENCE / "ledger.json").read_text("utf-8"))
        receipt = ledger["deliveries"]["20"]
        self.assertEqual(receipt["pr"], "https://github.com/jonathan-vella/landinglens/pull/122")
        self.assertEqual(receipt["checked_head"], "e816aa6a2d68ff2aba45b01211f9989fef2ebb37")
        self.assertEqual(receipt["merge_commit"], "c63dd9b8de4927b72558643551e0eee229b2074d")
        self.assertEqual(receipt["merged_at"], "2026-11-06T15:12:55Z")
        self.assertEqual(
            receipt["checks"],
            [
                "https://github.com/jonathan-vella/landinglens/actions/runs/42239817936",
                "https://github.com/jonathan-vella/landinglens/actions/runs/42239859771",
            ],
        )
        self.assertEqual(
            receipt["wheel_sha256"],
            "8701d4f9e06619acd3dfb3e1489d9b56b7c78d74d698072b8fe3a0e7dd23be37",
        )
        self.assertEqual(
            receipt["local_installed_suite"], {"tests": 489, "passed": 488, "skipped": 1}
        )
        self.assertEqual(len(receipt["compiler_integration_cases"]), 11)
        self.assertEqual(
            receipt["compiler_integration_cases"][-1],
            "test_virtual_wan_preparation.VirtualWanPreparationTests."
            "test_real_bicep_virtual_wan_scoped_configuration_without_restore",
        )
        own = [r for r in ledger["recommendations"] if r["batch"] == "20"]
        self.assertEqual({r["guid"] for r in own}, set(GUIDS.values()))
        self.assertEqual(len(own), 9)
        for row in own:
            self.assertEqual(row["status"], "merged")
            self.assertEqual(row["pr"], receipt["pr"])
            self.assertEqual(row["merge_commit"], receipt["merge_commit"])
            self.assertIn(
                "deliveries.20: all eight CI jobs and four compiler artifacts verified",
                row["runtime_evidence"],
            )

    def test_explicit_scoped_aspath_both_modes_and_other_reviewed_preferences(self):
        for mode in ("planned", "observed"):
            for value in ("ASPath", "ExpressRoute", "VpnGateway"):
                bundle = self.fixture.bundle()
                bundle["mode"] = mode
                bundle["source"] = "arm" if mode == "planned" else "saved"
                bundle["resources"][1]["properties"]["hubRoutingPreference"] = value
                body = self.body(bundle)
                self.assertEqual(body["outcome"], "pass" if value == "ASPath" else "fail")
                self.assertEqual(body["fact"], value)
                self.assertEqual(body["evidence_tier"], "verified")
                self.assertEqual(body["confidence"], "explicit-configuration-only")
                self.assertEqual(
                    body["evidence_links"],
                    ["fixture://authored-vwan-configuration#hubRoutingPreference"],
                )

    def test_missing_unknown_or_malformed_preference_never_infers_default(self):
        for value in (
            None,
            "",
            "aspath",
            "AS-Path",
            "VPN",
            "Standard",
            True,
            1,
            [],
            {"unknown": preparation.PRIVATE},
            preparation.PRIVATE,
        ):
            bundle = self.fixture.bundle()
            bundle["resources"][1]["properties"]["hubRoutingPreference"] = value
            body = self.body(bundle)
            self.assertEqual(body["outcome"], "unknown")
            self.assertNotEqual(body["evidence_tier"], "verified")
            self.assertIsNone(body["fact"])
            self.assertEqual(body["reason"], "vwan_hub_identity_or_preference_unresolved")
            self.assertNotIn(preparation.PRIVATE, json.dumps(body))
        bundle = self.fixture.bundle()
        del bundle["resources"][1]["properties"]["hubRoutingPreference"]
        self.assertEqual(self.body(bundle)["outcome"], "unknown")

    def test_scope_identity_duplicates_missing_population_and_freshness_guards(self):
        for scope in (None, SCOPE.replace("/vwan", "/other")):
            bundle = self.fixture.bundle()
            bundle["scope"] = scope
            body = self.body(bundle)
            self.assertEqual(body["outcome"], "unknown")
            self.assertNotEqual(body["evidence_tier"], "verified")
        for identity in (None, preparation.WAN_ID.lower()):
            bundle = self.fixture.bundle()
            bundle["resources"][1]["arm_id"] = identity
            if identity is None:
                self.assertEqual(self.body(bundle)["outcome"], "unknown")
            else:
                with self.assertRaises(InputError):
                    self.body(bundle)
        for state in ("unknown", "inaccessible", "error"):
            bundle = self.fixture.bundle()
            bundle["resources"][1].update(state=state, reason="resource_unavailable")
            body = self.body(bundle)
            self.assertEqual(body["outcome"], "error" if state == "error" else "unknown")
            self.assertNotEqual(body["evidence_tier"], "verified")
        for collected_at in ("2000-01-01T00:00:00Z", "2028-01-01T00:00:00Z"):
            bundle = self.fixture.bundle()
            bundle["collected_at"] = collected_at
            self.assertEqual(self.body(bundle)["reason"], "stale_evidence")
        for complete in (True, False):
            bundle = self.fixture.bundle()
            bundle.update(resources=[], inventory_complete=complete)
            body = self.body(bundle)
            self.assertEqual(body["outcome"], "unknown")
            self.assertEqual(body["reason"], "vwan_hub_population_not_established")
            self.assertIn("Virtual WAN", guidance(body["reason"])["required_evidence"])
        bundle = self.fixture.bundle()
        duplicate = copy.deepcopy(bundle["resources"][1])
        duplicate["logical_id"] += ".duplicate"
        bundle["resources"].append(duplicate)
        with self.assertRaisesRegex(InputError, "ambiguous ARM"):
            self.body(bundle)

    def test_rule_is_guid_type_property_expected_and_operation_bound(self):
        for key, value in (
            ("expected", "ExpressRoute"),
            ("expected", True),
            ("property", "allowBranchToBranchTraffic"),
            ("resource_type", "Microsoft.Network/virtualNetworkGateways"),
            ("resource_type", "Microsoft.Network/routeTables"),
            ("operation", "enum-equals"),
            ("applicable_skus", ["Standard"]),
        ):
            catalog = copy.deepcopy(self.catalog)
            control = next(c for c in catalog["controls"] if c["control_id"] == ASPATH)
            control["rule"][key] = value
            with self.assertRaises(InputError):
                validate(catalog, "catalog")
        catalog = copy.deepcopy(self.catalog)
        control = next(c for c in catalog["controls"] if c["control_id"] == ASPATH)
        control["upstream_guid"] = GUIDS["D10.06"]
        with self.assertRaises(InputError):
            validate(catalog, "catalog")

    def test_assisted_context_signals_require_unique_typed_scoped_known_resource(self):
        bundle = self.fixture.bundle()
        rows = self.rows(self.report(bundle))
        for identity, row in rows.items():
            body = row["observed"]
            if identity != ASPATH:
                self.assertEqual(body["outcome"], "manual")
                self.assertEqual(body["evidence_tier"], "signal")
        for scope in (None, SCOPE.replace("/vwan", "/other")):
            bundle = self.fixture.bundle()
            bundle["scope"] = scope
            rows = self.rows(self.report(bundle))
            self.assertTrue(
                all(row["observed"]["evidence_tier"] == "needs_decision" for row in rows.values())
            )
        bundle = self.fixture.bundle()
        for resource in bundle["resources"]:
            resource["arm_id"] = None
        self.assertTrue(
            all(
                row["observed"]["evidence_tier"] == "needs_decision"
                for row in self.rows(self.report(bundle)).values()
            )
        )
        controls = {c["control_id"]: c for c in self.catalog["controls"]}
        bundle = self.fixture.bundle()
        bundle["resources"][0].update(state="inaccessible", reason="resource_unavailable")
        context = review_context(controls["ALZ-" + GUIDS["D10.03"]], bundle)
        self.assertIn("unknown", json.dumps(context))
        self.assertTrue(prepared_signal(controls["ALZ-" + GUIDS["D10.03"]], bundle))

    def test_eight_blank_interview_decisions_do_not_override_technical_predicate(self):
        response = prepare_interview(self.report(), self.catalog, QUESTION, SCOPE)
        self.assertEqual(len(response["decisions"]), 8)
        self.assertNotIn(ASPATH, {r["control_id"] for r in response["decisions"]})
        self.assertTrue(all(r["outcome"] is None for r in response["decisions"]))
        for field in ("answer", "reviewer", "evidence", "rationale", "valid_from", "valid_until"):
            self.assertIsNone(response[field])
        with self.assertRaises(InputError):
            compile_interview(response, self.catalog, at=AT)
        manual = compile_interview(self.completed(), self.catalog, at=AT)
        report = self.report(manual=manual)
        for entry in manual["entries"]:
            body = self.rows(report)[entry["control_id"]]["observed"]
            self.assertEqual(body["outcome"], entry["outcome"])
            self.assertEqual(body["reason"], "manual_attestation")
            self.assertEqual(body["evidence_tier"], "signal")
        self.assertEqual(self.rows(report)[ASPATH]["observed"]["outcome"], "pass")
        bundle = self.fixture.bundle()
        bundle["resources"][1]["properties"]["hubRoutingPreference"] = "ExpressRoute"
        report = self.report(bundle)
        prepared = prepare_reviews(report, self.catalog, [ASPATH], SCOPE)
        entry = {k: v for k, v in prepared["entries"][0].items() if k != "preparation"}
        entry.update(
            outcome="pass",
            reviewer="Fixture reviewer",
            evidence="fixture://review",
            rationale="Authored review cannot override the predicate.",
            valid_from=AT,
            valid_until="2026-11-07T00:00:00Z",
        )
        unchanged = self.report(
            bundle, manual=document("manual", schema_version="1.1", entries=[entry])
        )
        self.assertEqual(self.rows(unchanged)[ASPATH]["observed"]["outcome"], "fail")
        self.assertEqual(self.rows(unchanged)[ASPATH]["observed"]["evidence_tier"], "verified")

    def test_interview_content_scope_expiry_requirements_and_bank_binding(self):
        for key, value in (
            ("scope", SCOPE.replace("/vwan", "/other")),
            ("catalog_sha256", "0" * 64),
            ("bank_version", "old"),
            ("requirements_sha256", "0" * 64),
            ("answer", " "),
            ("reviewer", None),
            ("valid_until", AT),
            ("valid_from", "2027-01-01T00:00:00Z"),
        ):
            response = self.completed()
            response[key] = value
            with self.assertRaises(InputError):
                compile_interview(response, self.catalog, at=AT)
        for key, value in (("control_sha256", "0" * 64), ("outcome", None), ("control_id", ASPATH)):
            response = self.completed()
            response["decisions"][-1][key] = value
            with self.assertRaises(InputError):
                compile_interview(response, self.catalog, at=AT)
        bank = question_bank(self.catalog)
        self.assertIn(QUESTION, {q["id"] for q in bank["questions"]})
        self.assertTrue(
            {
                "development-lifecycle-sovereignty",
                "resource-cost-governance",
                "expressroute-monitoring-routing-failover",
            }
            <= BANK.keys()
        )
        response = self.completed()
        response["decisions"][-1] = response["decisions"][0]
        with self.assertRaises(InputError):
            compile_interview(response, self.catalog, at=AT)

    def test_real_packaged_successor_replay_keeps_times_facts_and_semantics(self):
        bundle = self.fixture.bundle()
        manual = compile_interview(self.completed(), self.catalog, at=AT)
        report = self.report(bundle, manual=manual)
        directory = self.root / "current-replay"
        export_bundle(directory, bundle, self.catalog, at=AT, manual=manual, evidence_tiers=True)
        replayed = replay_bundle(directory)
        self.assertEqual(semantic(report), semantic(replayed))
        self.assertEqual(replayed["catalog_version"], "2026-11-06.12")
        saved = json.loads((directory / "evidence.json").read_text("utf-8"))
        self.assertEqual(saved["collected_at"], AT)
        self.assertEqual(
            saved["resources"][1]["properties"]["hubPrefixSummary"], {"prefixLength": 22}
        )
        self.assertNotIn(preparation.PRIVATE, json.dumps(saved))
        self.assertNotIn("10.12.", json.dumps(saved))
        historical = self.fixture.catalog
        export_bundle(self.root / "historical", bundle, historical, at=AT, evidence_tiers=True)
        old = replay_bundle(self.root / "historical")
        self.assertEqual(old["catalog_version"], "2026-11-06.9")
        self.assertTrue(
            all(row["observed"]["outcome"] == "manual" for row in self.rows(old).values())
        )
        altered = copy.deepcopy(self.catalog)
        next(c for c in altered["controls"] if c["control_id"] == ASPATH)["rationale"] += " changed"
        with self.assertRaises(InputError):
            export_bundle(self.root / "unaccepted", bundle, altered, at=AT)

    def test_all_outputs_local_session_and_cli_share_current_technical_result(self):
        bundle = self.fixture.bundle()
        report = self.report(bundle)
        for fmt in ("json", "markdown", "html", "sarif", "csv", "pr-summary"):
            output = render(report, fmt)
            self.assertNotIn(preparation.PRIVATE, output)
            self.assertNotIn("10.12.", output)
        with zipfile.ZipFile(BytesIO(render_xlsx(report))) as archive:
            for name in archive.namelist():
                self.assertNotIn(preparation.PRIVATE.encode(), archive.read(name))
        session = ReviewSession(
            bundle, self.catalog, self.root / "session", clock=lambda: AT, evidence_tiers=True
        )
        self.assertEqual(session.state()["records"], [])
        self.assertEqual(self.rows(session.report)[ASPATH]["observed"]["outcome"], "pass")
        payload = {
            "revision": 0,
            "control_id": "ALZ-" + GUIDS["D10.06"],
            "kind": "manual",
            "decision": "fail",
            "replace_existing": False,
            "reviewer": "Fixture reviewer",
            "evidence": "fixture://branch-requirements",
            "rationale": "Authored independent requirements decision.",
            "valid_from": AT,
            "valid_until": "2026-11-07T00:00:00Z",
        }
        session.save(payload)
        self.assertEqual(len(session.state()["records"]), 1)
        self.assertEqual(self.rows(session.report)[ASPATH]["observed"]["outcome"], "pass")
        source = self.fixture.write("saved.json", bundle)
        output = self.root / "cli.json"
        with (
            redirect_stdout(StringIO()),
            redirect_stderr(StringIO()),
            patch(
                "sys.argv",
                [
                    "alz-assessor",
                    "assess",
                    str(source),
                    "--input",
                    "evidence",
                    "--at",
                    AT,
                    "--catalog",
                    str(files("alz_assessor").joinpath("data", "catalog-2026-11-06.12.json")),
                    "--evidence-tiers",
                    "--output",
                    str(output),
                ],
            ),
        ):
            result = main()
        self.assertEqual(result, 0)
        actual = json.loads(output.read_text("utf-8"))
        for value in (actual, report):
            value["results"].sort(
                key=lambda row: (
                    row["control_id"],
                    row.get("logical_id") or "",
                    row.get("arm_id") or "",
                )
            )
        self.assertEqual(semantic(actual), semantic(report))


if __name__ == "__main__":
    unittest.main()
