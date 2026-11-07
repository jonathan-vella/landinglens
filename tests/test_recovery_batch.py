import copy
import hashlib
import json
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

import test_recovery_preparation as preparation
from test_recovery_preparation import AT, IDS, PRIVATE, REFERENCE, SCOPE

from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import control_digest, digest
from alz_assessor.crosswalk import load_crosswalk
from alz_assessor.engine import assess
from alz_assessor.interviews import BANK, BANK_VERSION, compile_interview, prepare_interview
from alz_assessor.recovery_evidence import GUIDS
from alz_assessor.replay import export_bundle, replay_bundle, semantic
from alz_assessor.review_session import ReviewSession
from alz_assessor.terraform import InputError


class RecoveryBatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        frozen = files("alz_assessor").joinpath("data", "catalog-2026-11-06.24.json")
        self.catalog = load_catalog(str(frozen)) if frozen.is_file() else load_catalog()
        self.previous = load_catalog(
            str(files("alz_assessor").joinpath("data", "catalog-2026-11-06.23.json"))
        )
        self.matrix = json.loads((REFERENCE / "batch-26.json").read_text("utf-8"))
        self.fixture = preparation.RecoveryPreparationTests()
        self.fixture.root = self.root
        self.fixture.catalog = self.catalog
        self.fixture.matrix = self.matrix
        self.fixture.question = self.matrix["interview"]["id"]
        network = patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden"))
        network.start()
        self.addCleanup(network.stop)

    def test_exact_successor_nonown_complete_objects_original_four_and_frozen_bytes(self):
        self.assertEqual(self.catalog["catalog_version"], "2026-11-06.24")
        rows = {r["guid"]: r for r in self.matrix["recommendations"]}
        self.assertEqual(set(rows), GUIDS)
        previous = {c["control_id"]: c for c in self.previous["controls"]}
        for control in self.catalog["controls"]:
            before = previous[control["control_id"]]
            if control["upstream_guid"] not in GUIDS:
                self.assertEqual(control, before)
            else:
                for key in ("recommendation", "upstream_guid", "upstream_id", "inventory_flags"):
                    self.assertEqual(control[key], before[key])
                row = rows[control["upstream_guid"]]
                for key in ("evidence_requirements", "review_resource_types", "review_fact_paths"):
                    self.assertEqual(control[key], row[key])
                self.assertEqual(control["rationale"], row["limitations"])
                self.assertEqual(control["automation"], "assisted")
                self.assertIsNone(control["rule"])
        original = load_catalog(
            str(files("alz_assessor").joinpath("data", "catalog-2026-11-04.2.json"))
        )
        for control in original["controls"]:
            if control["automation"] == "automated":
                actual = next(
                    c for c in self.catalog["controls"] if c["control_id"] == control["control_id"]
                )
                self.assertEqual(actual, previous[actual["control_id"]])
                self.assertEqual(control_digest(actual), control_digest(control))
        self.assertEqual(len(self.catalog["controls"]), 255)
        self.assertEqual(
            {
                key: sum(c["automation"] == key for c in self.catalog["controls"])
                for key in ("automated", "assisted", "manual")
            },
            {"automated": 12, "assisted": 200, "manual": 43},
        )
        for kind in ("catalog", "crosswalk"):
            raw = files("alz_assessor").joinpath("data", f"{kind}-2026-11-06.23.json").read_bytes()
            self.assertEqual(
                hashlib.sha256(raw).hexdigest(),
                self.matrix[f"preserved_{kind}_bytes"]["2026-11-06.23"],
            )

    def test_all212_prior_rows_25_receipts_bindings_fixed251_and_exact_sources(self):
        ledger = json.loads((REFERENCE / "ledger.json").read_text("utf-8"))
        earlier = set(self.matrix["preserved_delivery_batches"])
        rows = [r for r in ledger["recommendations"] if r["batch"] in earlier]
        receipts = {key: value for key, value in ledger["deliveries"].items() if key in earlier}
        self.assertEqual((len(rows), len(receipts)), (212, 25))
        self.assertEqual(digest(rows), self.matrix["preserved_merged_recommendations_sha256"])
        self.assertEqual(digest(receipts), self.matrix["preserved_delivery_receipts_sha256"])
        self.assertEqual(len(ledger["recommendations"]), 251)
        for row in rows:
            self.assertEqual(row["status"], "merged")
            self.assertEqual(row["pr"], receipts[row["batch"]]["pr"])
            self.assertEqual(row["merge_commit"], receipts[row["batch"]]["merge_commit"])
        own = [r for r in ledger["recommendations"] if r["batch"] == "26"]
        self.assertEqual({r["guid"] for r in own}, GUIDS)
        for row in own:
            if row["status"] == "merged":
                self.assertEqual(row["pr"], ledger["deliveries"]["26"]["pr"])
                self.assertEqual(row["merge_commit"], ledger["deliveries"]["26"]["merge_commit"])
            else:
                self.assertEqual(row["status"], "implementation-in-progress")
                self.assertIsNone(row["merge_commit"])
        source = (REFERENCE / "preparation-26-sources.json").read_bytes()
        self.assertEqual(source, (REFERENCE / "batch-26-sources.json").read_bytes())
        self.assertEqual(len(json.loads(source)["sources"]), 45)
        data = files("alz_assessor").joinpath("data")
        current = json.loads(data.joinpath("batch-matrix-2026-11-06.24.json").read_text("utf-8"))
        previous = json.loads(data.joinpath("batch-matrix-2026-11-06.23.json").read_text("utf-8"))
        self.assertEqual(current["batches"][:-1], previous["batches"])
        self.assertEqual(current["sources"][:-1], previous["sources"])
        self.assertEqual(current["batches"][-1], self.matrix)
        self.assertEqual(current["sources"][-1], json.loads(source))

    def test_registered_eight_independent_blank_decisions_and_prior_bank(self):
        question = self.matrix["interview"]
        self.assertEqual(question, {"id": question["id"], **BANK[question["id"]]})
        report = self.fixture.report()
        response = prepare_interview(report, self.catalog, question["id"], SCOPE)
        self.assertEqual(response["bank_version"], BANK_VERSION)
        self.assertEqual(len(response["decisions"]), 8)
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
            compile_interview(response, self.catalog, at=AT)
        for batch in self.matrix["preserved_delivery_batches"]:
            previous = json.loads((REFERENCE / f"batch-{batch}.json").read_text("utf-8"))
            if "interview" in previous:
                question = previous["interview"]
                self.assertEqual(question, {"id": question["id"], **BANK[question["id"]]})

    def test_registered_source_bound_facts_decisions_outputs_and_cli_session(self):
        self.fixture.test_service_qualified_redundancy_explicit_enums_and_no_defaults()
        self.fixture.test_guest_modes_exact_extension_pairs_instance_name_and_parent()
        self.fixture.test_waf_case_sensitive_categories_groups_duplicates_and_unknown_not_disabled()
        self.fixture.test_unsupported_source_qualification_cannot_supply_control_signals()
        self.fixture.test_tiers_no_scope_wrong_kind_stale_denied_partial_never_verified()
        self.fixture.test_interview_selection_binding_time_expiry_attribution_and_atomicity()
        self.fixture.test_all_outputs_human_confirmation_and_independent_exceptions()
        self.fixture.test_cli_candidate_and_local_session_atomic_save()

    def test_registered_session_atomic_disk_failure_and_original_time_resume(self):
        bundle = self.fixture.bundle()
        session = ReviewSession(
            bundle, self.catalog, self.root / "registered", clock=lambda: AT, evidence_tiers=True
        )
        question = next(
            q for q in session.state()["interviews"] if q["id"] == self.fixture.question
        )
        self.assertTrue(all(d["outcome"] is None for d in question["template"]["decisions"]))
        response = self.fixture.completed()
        with patch.object(Path, "rename", side_effect=OSError("authored disk failure")):
            with self.assertRaisesRegex(OSError, "authored disk failure"):
                session.save_interview(
                    {"revision": 0, "response": response, "replace_existing": []}
                )
        self.assertEqual(session.revision, 0)
        session.save_interview({"revision": 0, "response": response, "replace_existing": []})
        resumed = ReviewSession.resume(
            session.directory / "revision-0001", self.root / "resumed", clock=lambda: AT
        )
        self.assertEqual(semantic(resumed.report), semantic(session.report))
        self.assertNotIn(PRIVATE, json.dumps(resumed.state()))

    def test_accepted_predecessor_private_replay_and_rebinding_rejection(self):
        bundle = self.fixture.bundle()
        manual = compile_interview(self.fixture.completed(), self.catalog, at=AT)
        expected = assess(bundle, self.catalog, manual=manual, at=AT, evidence_tiers=True)
        export_bundle(
            self.root / "accepted", bundle, self.catalog, manual=manual, at=AT, evidence_tiers=True
        )
        replayed = replay_bundle(self.root / "accepted")
        self.assertEqual(semantic(replayed), semantic(expected))
        self.assertEqual(replayed["evidence"][0]["collected_at"], AT)
        for path in (self.root / "accepted").iterdir():
            self.assertNotIn(PRIVATE, path.read_text("utf-8"))
        export_bundle(self.root / "previous", bundle, self.previous, at=AT, evidence_tiers=True)
        self.assertEqual(
            semantic(replay_bundle(self.root / "previous")),
            semantic(assess(bundle, self.previous, at=AT, evidence_tiers=True)),
        )
        changed = copy.deepcopy(self.catalog)
        next(c for c in changed["controls"] if c["control_id"] in IDS)[
            "evidence_requirements"
        ].append("Unaccepted changed requirement")
        with self.assertRaises(InputError):
            export_bundle(self.root / "changed", bundle, changed, at=AT)

    def test_crosswalk_exact_successor_binding_and_unchanged_query_execution_set(self):
        frozen = files("alz_assessor").joinpath("data", "crosswalk-2026-11-06.24.json")
        current = load_crosswalk(self.catalog, Path(str(frozen)) if frozen.is_file() else None)
        self.assertEqual(current["crosswalk_version"], "2026-11-06.24")
        previous = load_crosswalk(
            self.previous,
            Path(str(files("alz_assessor").joinpath("data", "crosswalk-2026-11-06.23.json"))),
        )
        self.assertEqual(len(current["entries"]), 255)
        self.assertEqual(current["sources"], previous["sources"])
        for left, right in zip(current["entries"], previous["entries"], strict=True):
            self.assertEqual(left["guid"], right["guid"])
            self.assertEqual(left["targets"], right["targets"])
