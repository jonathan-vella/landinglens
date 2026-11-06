import copy
import hashlib
import json
import unittest
import zipfile
from collections import Counter
from importlib.resources import files
from io import BytesIO
from pathlib import Path

import test_monitoring_preparation as preparation

from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import control_digest, document, validate
from alz_assessor.engine import assess
from alz_assessor.interviews import compile_interview, prepare_interview, question_bank
from alz_assessor.replay import export_bundle, replay_bundle, semantic
from alz_assessor.reports import render, render_xlsx
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import prepare_reviews, review_context
from alz_assessor.terraform import InputError

ROOT = Path(__file__).resolve().parents[1]
AT, SCOPE = preparation.AT, preparation.SCOPE
GUIDS = preparation.GUIDS
PROPAGATION = "ALZ-" + GUIDS[4]
QUESTION = "expressroute-monitoring-routing-failover"


class MonitoringBatchTests(unittest.TestCase):
    def setUp(self):
        self.fixture = preparation.MonitoringPreparationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        data = files("alz_assessor").joinpath("data")
        frozen = data.joinpath("catalog-2026-11-06.9.json")
        self.catalog = load_catalog(str(frozen)) if frozen.is_file() else load_catalog()

    def row(self, bundle):
        return next(
            row
            for row in assess(bundle, self.catalog, at=AT, evidence_tiers=True)["results"]
            if row["control_id"] == PROPAGATION
        )[bundle["mode"]]

    def test_exact_successor_predicate_and_all_predecessor_meanings(self):
        data = files("alz_assessor").joinpath("data")
        for filename, expected in (
            (
                "catalog-2026-11-06.8.json",
                "5c8f0d3331c6c6ffe1478de34395b33001e6b12ee5857394a5d6ff6b60b92ecc",
            ),
            (
                "crosswalk-2026-11-06.8.json",
                "75b123e331928af8e483b75632cf2e7ea834347389ef795ec3df7238af12aa6f",
            ),
        ):
            self.assertEqual(
                hashlib.sha256(data.joinpath(filename).read_bytes()).hexdigest(), expected
            )
        previous = load_catalog(str(data.joinpath("catalog-2026-11-06.8.json")))
        before = {control["upstream_guid"]: control for control in previous["controls"]}
        self.assertEqual(self.catalog["catalog_version"], "2026-11-06.9")
        self.assertEqual(len(self.catalog["controls"]), 255)
        self.assertEqual(
            Counter(control["automation"] for control in self.catalog["controls"]),
            {"automated": 11, "assisted": 201, "manual": 43},
        )
        for control in self.catalog["controls"]:
            if control["upstream_guid"] not in GUIDS:
                self.assertEqual(
                    control_digest(control), control_digest(before[control["upstream_guid"]])
                )
        matrix = json.loads((ROOT / "references/recommendation-batches/batch-15.json").read_text())
        sources = json.loads(
            (ROOT / "references/recommendation-batches/batch-15-sources.json").read_text()
        )
        source_ids = {source["id"] for source in sources["sources"]}
        self.assertEqual(len(sources["sources"]), 39)
        self.assertEqual([row["guid"] for row in matrix["recommendations"]], list(GUIDS))
        for row in matrix["recommendations"]:
            self.assertTrue(set(row["sources"]) <= source_ids)
            self.assertLessEqual(len(row["review_fact_paths"]), 8)
        rule = next(
            control for control in self.catalog["controls"] if control["control_id"] == PROPAGATION
        )["rule"]
        self.assertEqual(
            rule,
            {
                "operation": "gateway-route-propagation",
                "resource_type": "Microsoft.Network/virtualNetworkGateways",
                "property": "subnetReferences",
                "expected": True,
            },
        )

    def test_all_90_prior_guid_rows_and_ten_receipts_remain_exact(self):
        ledger = json.loads((ROOT / "references/recommendation-batches/ledger.json").read_text())
        earlier = {"01", "04", "11", "12", "13", "14", "17", "18", "19", "22"}
        receipts = {key: value for key, value in ledger["deliveries"].items() if key in earlier}
        rows = [row for row in ledger["recommendations"] if row["batch"] in earlier]
        for value, expected in (
            (receipts, "a48521c6b8bd951c83b53d496e651ba2bc837bfa71ede4944df0516ab060cc61"),
            (rows, "e2990778b66f689ebedefb0e0932f650e30455d4f3a153143a77d9a31023d529"),
        ):
            content = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            self.assertEqual(hashlib.sha256(content.encode()).hexdigest(), expected)
        self.assertEqual(len(rows), 90)
        self.assertTrue(all(row["status"] == "merged" for row in rows))

    def test_strict_joined_true_false_configuration_in_both_modes(self):
        for mode in ("planned", "observed"):
            for disabled in (False, True):
                bundle = self.fixture.bundle(disabled)
                bundle["mode"] = mode
                body = self.row(bundle)
                self.assertEqual(body["outcome"], "fail" if disabled else "pass")
                self.assertIs(body["fact"], not disabled)
                self.assertEqual(body["evidence_tier"], "verified")
                self.assertEqual(
                    body["reason"],
                    "joined_gateway_route_propagation_disabled"
                    if disabled
                    else "joined_gateway_route_propagation_enabled",
                )
                self.assertEqual(len(body["evidence_links"]), 3)
                self.assertEqual(
                    body["component_facts"]["gateway_subnet_routes"][0]["route_table_id"],
                    preparation.TABLE.lower(),
                )

    def test_missing_flags_arbitrary_tables_and_no_inventory_never_pass(self):
        for flag in (None, 0, 1, "false", {}, {"unknown": "missing"}, 0.0):
            bundle = self.fixture.bundle(flag)
            body = self.row(bundle)
            self.assertEqual(body["outcome"], "unknown")
            self.assertIsNone(body["fact"])
            self.assertNotEqual(body["evidence_tier"], "verified")
        for complete in (False, True):
            bundle = self.fixture.bundle()
            bundle["inventory_complete"] = complete
            bundle["resources"] = [bundle["resources"][2]]
            self.assertEqual(self.row(bundle)["outcome"], "unknown")
            bundle["resources"] = []
            self.assertEqual(self.row(bundle)["outcome"], "unknown")
        bundle = self.fixture.bundle()
        bundle["resources"][1]["properties"]["routeTable"]["id"] = preparation.TABLE + "-missing"
        self.assertEqual(self.row(bundle)["outcome"], "unknown")
        bundle = self.fixture.bundle()
        del bundle["resources"][2]["properties"]["disableBgpRoutePropagation"]
        self.assertEqual(self.row(bundle)["outcome"], "unknown")

    def test_scope_subnet_identity_type_and_bounds_are_not_defaults(self):
        for scope in (None, "/subscriptions/00000000-0000-0000-0000-000000000002"):
            bundle = self.fixture.bundle()
            bundle["scope"] = scope
            self.assertEqual(self.row(bundle)["outcome"], "unknown")
        bundle = self.fixture.bundle()
        other = preparation.TABLE.replace(
            "resourceGroups/monitoring", "resourceGroups/other"
        ).lower()
        bundle["resources"][2]["arm_id"] = other
        bundle["resources"][1]["properties"]["routeTable"]["id"] = other
        self.assertEqual(self.row(bundle)["outcome"], "unknown")
        for refs in ([], [None], [preparation.TABLE], [preparation.SUBNET] * 21):
            bundle = self.fixture.bundle()
            bundle["resources"][0]["properties"]["subnetReferences"] = refs
            self.assertEqual(self.row(bundle)["outcome"], "unknown")
        for kind in ("Vpn", "ExpressRoute", None, False, "VPN"):
            bundle = self.fixture.bundle()
            bundle["resources"][0]["properties"]["gatewayType"] = kind
            self.assertEqual(
                self.row(bundle)["outcome"],
                "pass" if kind in ("Vpn", "ExpressRoute") else "unknown",
            )
        bundle = self.fixture.bundle()
        bundle["resources"][0]["properties"]["subnetReferences"] = [
            preparation.SUBNET.replace("GatewaySubnet", "app")
        ]
        self.assertEqual(self.row(bundle)["outcome"], "unknown")
        bundle = self.fixture.bundle()
        duplicate = copy.deepcopy(bundle["resources"][2])
        duplicate["logical_id"] += ".duplicate"
        bundle["resources"].append(duplicate)
        with self.assertRaisesRegex(InputError, "ambiguous ARM"):
            self.row(bundle)

    def test_freshness_denied_and_partial_members_do_not_become_verified(self):
        for at in ("2000-01-01T00:00:00Z", "2028-01-01T00:00:00Z"):
            bundle = self.fixture.bundle()
            bundle["collected_at"] = at
            self.assertEqual(self.row(bundle)["reason"], "stale_evidence")
        for index in (0, 1, 2):
            for state in ("unknown", "inaccessible", "error"):
                bundle = self.fixture.bundle()
                bundle["resources"][index].update(state=state, reason="resource_unavailable")
                body = self.row(bundle)
                self.assertEqual(
                    body["outcome"], "error" if index == 0 and state == "error" else "unknown"
                )
                self.assertNotEqual(body["evidence_tier"], "verified")
        bundle = self.fixture.bundle(True)
        bundle["resources"][0]["properties"]["subnetReferences"].append(
            preparation.SUBNET + "-missing"
        )
        self.assertEqual(self.row(bundle)["outcome"], "unknown")

    def test_rule_shape_and_original_guid_guard_cannot_be_retargeted(self):
        for key, value in (
            ("expected", False),
            ("expected", 1),
            ("property", "disableBgpRoutePropagation"),
            ("resource_type", "Microsoft.Network/routeTables"),
        ):
            catalog = copy.deepcopy(self.catalog)
            control = next(row for row in catalog["controls"] if row["control_id"] == PROPAGATION)
            control["rule"][key] = value
            with self.assertRaisesRegex(InputError, "joined GatewaySubnet"):
                validate(catalog, "catalog")
        catalog = copy.deepcopy(self.catalog)
        control = next(row for row in catalog["controls"] if row["control_id"] == PROPAGATION)
        control["upstream_guid"] = GUIDS[0]
        with self.assertRaises(InputError):
            validate(catalog, "catalog")

    def test_interview_has_eight_blank_bound_decisions_and_no_technical_override(self):
        bundle = self.fixture.topology()
        report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        response = prepare_interview(report, self.catalog, QUESTION, SCOPE)
        self.assertEqual(len(response["decisions"]), 8)
        self.assertNotIn(PROPAGATION, {entry["control_id"] for entry in response["decisions"]})
        self.assertTrue(all(entry["outcome"] is None for entry in response["decisions"]))
        self.assertIsNone(response["answer"])
        self.assertTrue(
            any(question["id"] == QUESTION for question in question_bank(self.catalog)["questions"])
        )
        with self.assertRaises(InputError):
            compile_interview(response, self.catalog, at=AT)
        response.update(
            answer="Authored redacted topology review fixture.",
            reviewer="Fixture reviewer",
            rationale="Explicit decisions, not a live operational claim.",
            evidence="fixture://redacted-independent-record",
            valid_from=AT,
            valid_until="2026-11-07T00:00:00Z",
        )
        for index, entry in enumerate(response["decisions"]):
            entry["outcome"] = "pass" if index % 2 else "fail"
        manual = compile_interview(response, self.catalog, at=AT)
        confirmed = assess(bundle, self.catalog, at=AT, evidence_tiers=True, manual=manual)
        for entry in manual["entries"]:
            row = next(
                row for row in confirmed["results"] if row["control_id"] == entry["control_id"]
            )
            self.assertEqual(row["observed"]["outcome"], entry["outcome"])
            self.assertEqual(row["observed"]["evidence_tier"], "signal")
        changed = copy.deepcopy(response)
        changed["scope"] = "/subscriptions/00000000-0000-0000-0000-000000000002"
        with self.assertRaises(InputError):
            compile_interview(changed, self.catalog, at=AT)
        failed = self.fixture.bundle(True)
        prepared = prepare_reviews(
            assess(failed, self.catalog, at=AT), self.catalog, [PROPAGATION], SCOPE
        )
        entry = {
            key: value for key, value in prepared["entries"][0].items() if key != "preparation"
        }
        entry.update(
            reviewer="Fixture reviewer",
            evidence="fixture://review",
            rationale="Independent review",
            valid_from=AT,
            valid_until="2026-11-07T00:00:00Z",
            outcome="pass",
        )
        technical_manual = document("manual", schema_version="1.1", entries=[entry])
        exception_entry = {key: value for key, value in entry.items() if key != "outcome"}
        exception_entry["disposition"] = "accepted"
        exceptions = document("exceptions", schema_version="1.1", entries=[exception_entry])
        result = assess(failed, self.catalog, at=AT, manual=technical_manual, exceptions=exceptions)
        body = next(row for row in result["results"] if row["control_id"] == PROPAGATION)[
            "observed"
        ]
        self.assertEqual(body["outcome"], "fail")
        self.assertEqual(body["exception_disposition"], "accepted")

    def test_all_outputs_session_context_and_accepted_original_time_replay(self):
        bundle = self.fixture.topology()
        report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        for row in report["results"]:
            if row["control_id"] in {"ALZ-" + guid for guid in GUIDS if guid != GUIDS[4]}:
                self.assertEqual(row["observed"]["outcome"], "manual")
                self.assertEqual(row["observed"]["evidence_tier"], "signal")
        for format in ("json", "markdown", "html", "csv", "sarif", "pr-summary"):
            self.assertNotIn(preparation.PRIVATE, render(report, format))
        with zipfile.ZipFile(BytesIO(render_xlsx(report))) as archive:
            self.assertNotIn(
                preparation.PRIVATE,
                "".join(archive.read(name).decode() for name in archive.namelist()),
            )
        directory = self.root / "accepted"
        export_bundle(directory, bundle, self.catalog, at=AT, evidence_tiers=True)
        replayed = replay_bundle(directory)
        self.assertEqual(semantic(replayed), semantic(report))
        self.assertEqual(replayed["evidence"][0]["collected_at"], AT)
        saved = json.loads((directory / "evidence.json").read_text())
        control = next(
            control for control in self.catalog["controls"] if control["upstream_guid"] == GUIDS[8]
        )
        self.assertEqual(
            review_context(control, saved)["gateway_circuit_subchecks"],
            review_context(control, bundle)["gateway_circuit_subchecks"],
        )
        bundle["collected_at"] = "2000-01-01T00:00:00Z"
        session = ReviewSession(bundle, self.catalog, self.root / "session", clock=lambda: AT)
        technical = next(
            control for control in session.controls if control["control_id"] == PROPAGATION
        )
        self.assertEqual(technical["kinds"], ["exceptions"])
        self.assertEqual(session.reviews["manual"]["entries"], [])
        self.assertNotIn(preparation.PRIVATE, json.dumps(session.controls))


if __name__ == "__main__":
    unittest.main()
