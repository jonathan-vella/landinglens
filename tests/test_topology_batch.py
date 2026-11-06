import copy
import hashlib
import json
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path

import test_topology_preparation as preparation
from test_topology_preparation import AT, CONTROLS, IP, NET, PEER, PRIVATE, RG, ROUTING, SCOPE, SUB

from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import control_digest, digest, document
from alz_assessor.crosswalk import load_crosswalk
from alz_assessor.engine import assess
from alz_assessor.interviews import BANK, BANK_VERSION, compile_interview, prepare_interview
from alz_assessor.replay import export_bundle, replay_bundle, semantic
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import validate_reviews
from alz_assessor.terraform import InputError
from alz_assessor.topology_evidence import GUIDS, HUB, IPCONFIG, SUBNET, VNET

REFERENCE = preparation.ROOT / "references" / "recommendation-batches"


class TopologyBatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        frozen = files("alz_assessor").joinpath("data", "catalog-2026-11-06.20.json")
        self.catalog = load_catalog(str(frozen)) if frozen.is_file() else load_catalog()
        self.previous = preparation.previous_catalog()
        self.matrix = json.loads((REFERENCE / "batch-10.json").read_text("utf-8"))
        self.fixture = preparation.TopologyPreparationTests()
        self.fixture.root = self.root
        self.fixture.catalog = self.catalog
        self.fixture.matrix = self.matrix

    def response(self):
        report = assess(self.fixture.bundle(), self.catalog, at=AT, evidence_tiers=True)
        response = prepare_interview(report, self.catalog, self.matrix["interview"]["id"], SCOPE)
        response.update(
            answer="Authored fixture, not an actual owner approval.",
            reviewer="Authored fixture reviewer",
            rationale="Ten independently selected fixture decisions.",
            evidence="https://example.invalid/redacted",
            valid_from=AT,
            valid_until="2026-11-07T20:00:00Z",
        )
        for i, decision in enumerate(response["decisions"]):
            decision["outcome"] = "pass" if i % 2 else "fail"
        return response

    def test_exact_successor_ten_guids_nonown_objects_original_four_and_frozen_bytes(self):
        self.assertEqual(self.catalog["catalog_version"], "2026-11-06.20")
        self.assertEqual(self.matrix["catalog_version"], self.catalog["catalog_version"])
        self.assertEqual(self.matrix["review_state"], "owner-delegated-source-backed-matrix")
        rows = {r["guid"]: r for r in self.matrix["recommendations"]}
        self.assertEqual(set(rows), GUIDS)
        before = {c["control_id"]: c for c in self.previous["controls"]}
        for control in self.catalog["controls"]:
            if control["control_id"] not in CONTROLS:
                self.assertEqual(control, before[control["control_id"]])
                continue
            row = rows[control["upstream_guid"]]
            self.assertEqual(control["evidence_requirements"], row["evidence_requirements"])
            self.assertEqual(control["rationale"], row["limitations"])
            self.assertEqual(control["automation"], row["classification"])
            self.assertIsNone(control["rule"])
        baseline = load_catalog(
            str(files("alz_assessor").joinpath("data", "catalog-2026-11-04.2.json"))
        )
        for original in baseline["controls"]:
            if original["automation"] == "automated":
                actual = next(
                    c for c in self.catalog["controls"] if c["control_id"] == original["control_id"]
                )
                self.assertEqual(actual, before[actual["control_id"]])
                self.assertEqual(control_digest(actual), control_digest(original))
        for kind in ("catalog", "crosswalk"):
            raw = files("alz_assessor").joinpath("data", kind + "-2026-11-06.19.json").read_bytes()
            self.assertEqual(
                hashlib.sha256(raw).hexdigest(),
                self.matrix["preserved_" + kind + "_bytes"]["2026-11-06.19"],
            )
        self.assertEqual(len(self.catalog["controls"]), 255)
        self.assertEqual(
            {
                key: sum(c["automation"] == key for c in self.catalog["controls"])
                for key in ("automated", "assisted", "manual")
            },
            {"automated": 12, "assisted": 200, "manual": 43},
        )

    def test_all177_prior_rows_twentyone_receipts_sources_and_matrix_chain_preserved(self):
        ledger = json.loads((REFERENCE / "ledger.json").read_text("utf-8"))
        earlier = set(self.matrix["preserved_delivery_batches"])
        rows = [r for r in ledger["recommendations"] if r["batch"] in earlier]
        receipts = {key: value for key, value in ledger["deliveries"].items() if key in earlier}
        self.assertEqual((len(rows), len(receipts)), (177, 21))
        self.assertEqual(digest(rows), self.matrix["preserved_merged_recommendations_sha256"])
        self.assertEqual(digest(receipts), self.matrix["preserved_delivery_receipts_sha256"])
        for row in rows:
            self.assertEqual(row["status"], "merged")
            self.assertEqual(row["pr"], receipts[row["batch"]]["pr"])
            self.assertEqual(row["merge_commit"], receipts[row["batch"]]["merge_commit"])
        self.assertEqual(len(ledger["recommendations"]), 251)
        source = (REFERENCE / "preparation-10-sources.json").read_bytes()
        self.assertEqual(source, (REFERENCE / "batch-10-sources.json").read_bytes())
        self.assertEqual(len(json.loads(source)["sources"]), 32)
        current = json.loads(
            files("alz_assessor")
            .joinpath("data", "batch-matrix-2026-11-06.20.json")
            .read_text("utf-8")
        )
        previous = json.loads(
            files("alz_assessor")
            .joinpath("data", "batch-matrix-2026-11-06.19.json")
            .read_text("utf-8")
        )
        self.assertEqual(current["batches"][:-1], previous["batches"])
        self.assertEqual(current["sources"][:-1], previous["sources"])
        self.assertEqual(current["batches"][-1], self.matrix)
        self.assertEqual(current["sources"][-1], json.loads(source))

    def test_registered_bank_ten_independent_blank_outcomes_and_all_prior_questions(self):
        question = self.matrix["interview"]
        self.assertEqual(question, {"id": question["id"], **BANK[question["id"]]})
        report = assess(self.fixture.bundle(), self.catalog, at=AT, evidence_tiers=True)
        response = prepare_interview(report, self.catalog, question["id"], SCOPE)
        self.assertEqual(response["bank_version"], BANK_VERSION)
        self.assertEqual(len(response["decisions"]), 10)
        self.assertTrue(all(d["outcome"] is None for d in response["decisions"]))
        with self.assertRaises(InputError):
            compile_interview(response, self.catalog, at=AT)
        for batch in self.matrix["preserved_delivery_batches"]:
            matrix = json.loads((REFERENCE / f"batch-{batch}.json").read_text())
            if "interview" in matrix:
                prior = matrix["interview"]
                self.assertEqual(prior, {"id": prior["id"], **BANK[prior["id"]]})
        self.fixture.test_reports_prepared_interview_binding_expiry_session_and_atomic_failure()

    def test_actual_registered_scoped_context_thresholds_privacy_and_all_output_tiers(self):
        self.fixture.test_exact_current_source_sizing_boundary_not_old_checklist()
        self.fixture.test_existing_gateway_firewall_dns_relationships_not_service_placement_verdict()
        self.fixture.test_monitoring_existing_facts_are_signals_not_executed_end_to_end_health()
        self.fixture.test_no_whole_pass_verified_or_automatic_quota_threshold()
        self.fixture.test_cli_saved_evidence_uses_same_prepared_workflows_without_catalog_activation()

    def test_registered_session_explicit_exception_no_technical_verified_and_atomicity(self):
        session = ReviewSession(
            self.fixture.bundle(),
            self.catalog,
            self.root / "registered",
            clock=lambda: AT,
            evidence_tiers=True,
        )
        question = next(
            q for q in session.state()["interviews"] if q["id"] == self.matrix["interview"]["id"]
        )
        self.assertTrue(all(d["outcome"] is None for d in question["template"]["decisions"]))
        response = self.response()
        invalid = copy.deepcopy(response)
        invalid["decisions"][-1]["outcome"] = None
        with self.assertRaises(InputError):
            session.save_interview({"revision": 0, "response": invalid, "replace_existing": []})
        self.assertEqual(session.revision, 0)
        session.save_interview({"revision": 0, "response": response, "replace_existing": []})
        restored = ReviewSession.resume(
            session.directory / "revision-0001", self.root / "resumed", clock=lambda: AT
        )
        self.assertEqual(semantic(restored.report), semantic(session.report))
        manual = compile_interview(response, self.catalog, at=AT)
        exception = document(
            "exceptions",
            schema_version="1.1",
            entries=[
                {key: value for key, value in manual["entries"][0].items() if key != "outcome"}
                | {"disposition": "accepted"}
            ],
        )
        report = assess(
            self.fixture.bundle(),
            self.catalog,
            manual=manual,
            exceptions=exception,
            at=AT,
            evidence_tiers=True,
        )
        own = [r for r in report["results"] if r["control_id"] in CONTROLS]
        self.assertTrue(any(r["observed"].get("exception_disposition") == "accepted" for r in own))
        self.assertTrue(all(r["observed"]["evidence_tier"] != "verified" for r in own))

    def test_packaged_accepted_and_predecessor_original_time_replay_and_refused_rebinding(self):
        bundle = self.fixture.bundle()
        manual = compile_interview(self.response(), self.catalog, at=AT)
        report = assess(bundle, self.catalog, manual=manual, at=AT, evidence_tiers=True)
        export_bundle(
            self.root / "accepted", bundle, self.catalog, manual=manual, at=AT, evidence_tiers=True
        )
        replayed = replay_bundle(self.root / "accepted")
        self.assertEqual(semantic(replayed), semantic(report))
        self.assertEqual(replayed["evidence"][0]["collected_at"], AT)
        for path in (self.root / "accepted").iterdir():
            content = path.read_text("utf-8")
            self.assertNotIn(PRIVATE, content)
            self.assertNotIn("Authored fixture reviewer", content)
        export_bundle(self.root / "previous", bundle, self.previous, at=AT, evidence_tiers=True)
        self.assertEqual(
            semantic(replay_bundle(self.root / "previous")),
            semantic(assess(bundle, self.previous, at=AT, evidence_tiers=True)),
        )
        self.assertFalse(validate_reviews(manual, self.previous, SCOPE, AT)["ready_to_apply"])
        with self.assertRaises(InputError):
            export_bundle(
                self.root / "preparation",
                bundle,
                self.fixture.catalog | {"review_state": "candidate-unaccepted"},
                at=AT,
            )

    def test_strict_shared_rg_shape_helper_blocks_subscription_and_extension_id_lookalikes(self):
        for identity in (NET, SUB, ROUTING, IP, PEER):
            bundle = self.fixture.bundle()
            row = next(r for r in bundle["resources"] if r["arm_id"] == identity)
            malformed = identity.replace("/resourcegroups/network", "")
            row["arm_id"] = malformed
            config = self.fixture.config(bundle, malformed)
            self.assertIn("unknown", config)
        for kind in (VNET, SUBNET, HUB, IPCONFIG):
            bundle = self.fixture.bundle()
            row = next(r for r in bundle["resources"] if r["resource_type"] == kind)
            malformed = (
                SCOPE
                + "/providers/microsoft.fake/resources/extension/"
                + (row["arm_id"].split("/providers/")[-1])
            )
            row["arm_id"] = malformed
            self.assertIn("unknown", self.fixture.config(bundle, malformed))
        self.assertTrue(RG.startswith(SCOPE + "/"))

    def test_crosswalk_associations_do_not_expand_executable_queries_or_whole_predicates(self):
        frozen = files("alz_assessor").joinpath("data", "crosswalk-2026-11-06.20.json")
        crosswalk = load_crosswalk(self.catalog, Path(str(frozen)) if frozen.is_file() else None)
        own = [r for r in crosswalk["entries"] if r["guid"] in GUIDS]
        self.assertEqual(len(own), 10)
        self.assertEqual(sum(bool(r["targets"]) for r in own), 2)
        self.assertTrue(all(t["strength"] != "equivalent" for r in own for t in r["targets"]))
        for control in self.catalog["controls"]:
            if control["upstream_guid"] in GUIDS:
                self.assertIsNone(control["rule"])

    def test_actual_ten_own_receipts_bind_merged_head_runs_wheel_and_suite(self):
        ledger = json.loads((REFERENCE / "ledger.json").read_text("utf-8"))
        receipt = ledger["deliveries"]["10"]
        self.assertEqual(receipt["pr"], "https://github.com/jonathan-vella/landinglens/pull/146")
        self.assertEqual(receipt["checked_head"], "e93adc5bcbf00029256c41968809887488ebee22")
        self.assertEqual(receipt["merge_commit"], "a58982cc48652a6277d9b7bfcf89baf36f8cb621")
        self.assertEqual(receipt["merged_at"], "2026-11-06T22:44:46Z")
        self.assertEqual(
            receipt["wheel_sha256"],
            "defe7f7f901a98fe77bba32522e1c52169802666e8e42e4b693cb9e7a58b5967",
        )
        self.assertEqual(
            receipt["local_installed_suite"], {"tests": 694, "passed": 693, "skipped": 1}
        )
        self.assertEqual(
            receipt["checks"],
            [
                "https://github.com/jonathan-vella/landinglens/actions/runs/42305687967",
                "https://github.com/jonathan-vella/landinglens/actions/runs/42305715112",
            ],
        )
        self.assertEqual(len(receipt["compiler_integration_cases"]), 18)
        self.assertEqual(
            receipt["compiler_integration_cases"][-2:],
            [
                "test_hybrid_identity_preparation.HybridIdentityPreparationTests."
                "test_real_bicep_peering_and_vault_configuration_without_restore",
                "test_topology_preparation.TopologyPreparationTests."
                "test_real_bicep_vnet_routing_attachment_without_restore",
            ],
        )
        own = [r for r in ledger["recommendations"] if r["batch"] == "10"]
        self.assertEqual({r["guid"] for r in own}, GUIDS)
        self.assertEqual(len(own), 10)
        for row in own:
            self.assertEqual(row["status"], "merged")
            self.assertEqual(row["pr"], receipt["pr"])
            self.assertEqual(row["merge_commit"], receipt["merge_commit"])
            self.assertIn(
                "deliveries.10: all eight CI jobs and four compiler artifacts verified",
                row["runtime_evidence"],
            )
        prefix = set(self.matrix["preserved_delivery_batches"]) | {"10"}
        self.assertEqual(sum(r["batch"] in prefix for r in ledger["recommendations"]), 187)
        self.assertEqual(len([key for key in ledger["deliveries"] if key in prefix]), 22)
