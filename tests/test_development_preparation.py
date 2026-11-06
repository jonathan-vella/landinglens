import contextlib
import copy
import hashlib
import io
import json
import runpy
import subprocess
import sys
import tempfile
import unittest
import zipfile
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from alz_assessor import interviews
from alz_assessor.arm import properties
from alz_assessor.catalog import load_catalog
from alz_assessor.cli import main
from alz_assessor.contracts import control_digest, digest, document
from alz_assessor.engine import assess
from alz_assessor.interviews import compile_interview, prepare_interview, question_bank
from alz_assessor.replay import export_bundle, replay_bundle, sanitize_evidence, semantic
from alz_assessor.reports import render, render_xlsx, report_model
from alz_assessor.review_page import review_page
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import prepare_reviews, review_context, validate_reviews
from alz_assessor.terraform import InputError

ROOT = Path(__file__).resolve().parents[1]
REVIEWS = ROOT / "references" / "recommendation-batches"
AT = "2026-11-06T13:00:00Z"
UNTIL = "2026-11-07T13:00:00Z"
SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
OTHER = "/subscriptions/00000000-0000-0000-0000-000000000002"
PRIVATE = "PRIVATE-AUTHORED-PIPELINE-REGISTRY-CREDENTIAL"
GUIDS = {
    "H02.01": "cfe363b5-f579-4284-bc56-a42153e4c10b",
    "H02.02": "c7245dd4-af8a-403a-8bb7-890c1a7cfa9d",
    "H02.03": "12aeea20-9165-4b3e-bdf2-6795fcd3cdbe",
    "H02.04": "2676ae46-65ca-444e-8695-fdddeace4cb1",
    "H03.01": "2cdc9d99-dbcc-4ad4-97f5-e7d358bdfa73",
    "H04.01": "cc87a3bc-c572-4ad2-92ed-8cabab66160f",
    "H05.01": "047c91e2-6bb4-4a42-a0ef-ab06ad0062c9",
}
CONTROLS = {"ALZ-" + guid for guid in GUIDS.values()}


class DevelopmentPreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.matrix = json.loads((REVIEWS / "batch-30.json").read_text("utf-8"))
        self.sources = json.loads((REVIEWS / "batch-30-sources.json").read_text("utf-8"))
        self.accepted = load_catalog(
            str(files("alz_assessor").joinpath("data", "catalog-2026-11-06.10.json"))
        )
        self.catalog = load_catalog(
            str(files("alz_assessor").joinpath("data", "catalog-2026-11-06.11.json"))
        )
        question = self.matrix["interview"]
        self.question = question["id"]
        network = patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden"))
        network.start()
        self.addCleanup(network.stop)

    def bundle(self, *, mode="observed", complete=False, collected_at=AT, state="known"):
        return document(
            "evidence",
            schema_version="1.1",
            mode=mode,
            source="saved" if mode == "observed" else "arm",
            collected_at=collected_at,
            scope=SCOPE,
            inventory_complete=complete,
            artifact_hashes={"fixture": "0" * 64},
            diagnostics=[],
            resources=[
                {
                    "logical_id": "fixture-storage",
                    "arm_id": SCOPE + "/providers/Microsoft.Storage/storageAccounts/fixture",
                    "resource_type": "Microsoft.Storage/storageAccounts",
                    "state": state,
                    "reason": "detail_denied"
                    if state == "error"
                    else "unsupported_configuration"
                    if state == "unknown"
                    else "",
                    "source_location": "fixture://authored",
                    "properties": properties(
                        "Microsoft.Storage/storageAccounts",
                        {"supportsHttpsTrafficOnly": True, "pipeline": PRIVATE},
                    ),
                }
            ],
        )

    def report(self, *, manual=None, exceptions=None, at=AT):
        return assess(
            self.bundle(),
            self.catalog,
            at=at,
            evidence_tiers=True,
            manual=manual,
            exceptions=exceptions,
        )

    def prepared(self, selected=None):
        return prepare_interview(
            self.report(), self.catalog, self.question, SCOPE, selected=selected
        )

    def completed(self):
        response = self.prepared()
        response.update(
            answer="Authored fixture only: scoped evidence references, not a real approval.",
            reviewer="Authored fixture reviewer",
            rationale="Seven independent test decisions; no assessed organization claim.",
            evidence="https://example.invalid/redacted-evidence",
            valid_from=AT,
            valid_until=UNTIL,
        )
        outcomes = ("pass", "fail", "not_applicable", "fail", "pass", "fail", "pass")
        for decision, outcome in zip(response["decisions"], outcomes, strict=True):
            decision["outcome"] = outcome
        return response

    def rows(self, report):
        return [row for row in report["results"] if row["control_id"] in CONTROLS]

    def test_exact_seven_fixed_guids_manual_sources_and_predecessor_preservation(self):
        targets = json.loads((REVIEWS / "targets.json").read_text("utf-8"))
        fixed = [row for row in targets["targets"] if row["batch"] == "30"]
        self.assertEqual({row["upstream_id"]: row["guid"] for row in fixed}, GUIDS)
        self.assertEqual(
            {row["upstream_id"]: row["guid"] for row in self.matrix["recommendations"]}, GUIDS
        )
        self.assertEqual(set(self.matrix["interview"]["controls"]), CONTROLS)
        self.assertEqual(self.matrix["review_state"], "owner-delegated-source-backed-matrix")
        self.assertEqual(self.matrix["catalog_version"], "2026-11-06.11")
        self.assertEqual(self.catalog["catalog_version"], "2026-11-06.11")
        self.assertTrue(self.matrix["accepted_at"])
        for name, expected in (
            ("catalog", "fc697fd2e384b8216cf074ace62f5d950f76dac3a463aeef757a72e609586884"),
            ("crosswalk", "08dd03194246589c7a61a43b37022762f68d2cae4afd3a7c7649a333ecc41874"),
        ):
            self.assertEqual(
                hashlib.sha256(
                    files("alz_assessor")
                    .joinpath("data", name + "-2026-11-06.10.json")
                    .read_bytes()
                ).hexdigest(),
                expected,
            )
        self.assertEqual(len(self.catalog["controls"]), 255)
        before = {c["control_id"]: c for c in self.accepted["controls"]}
        for control in self.catalog["controls"]:
            if control["control_id"] in CONTROLS:
                self.assertEqual(control["automation"], "manual")
                self.assertIsNone(control["rule"])
                self.assertFalse(control.get("review_resource_types"))
                self.assertFalse(control.get("review_fact_paths"))
                self.assertEqual(len(control["evidence_requirements"]), 3)
                row = next(
                    r
                    for r in self.matrix["recommendations"]
                    if r["guid"] == control["upstream_guid"]
                )
                self.assertEqual(control["evidence_requirements"], row["evidence_requirements"])
                self.assertEqual(control["rationale"], row["limitations"])
            else:
                self.assertEqual(
                    control_digest(control), control_digest(before[control["control_id"]])
                )
        for automation in ("automated", "assisted", "manual"):
            self.assertEqual(
                sum(c["automation"] == automation for c in self.catalog["controls"]),
                sum(c["automation"] == automation for c in self.accepted["controls"]),
            )
        self.assertEqual(
            {c["control_id"]: control_digest(c) for c in self.catalog["controls"] if c["rule"]},
            {c["control_id"]: control_digest(c) for c in self.accepted["controls"] if c["rule"]},
        )
        ledger = json.loads((REVIEWS / "ledger.json").read_text("utf-8"))
        self.assertTrue(
            all(
                row["status"] in {"implementation-in-progress", "merged"}
                for row in ledger["recommendations"]
                if row["batch"] == "30"
            )
        )

    def test_actual_link_redirects_revisions_reuse_and_residency_boundaries(self):
        self.assertEqual(self.sources["review_state"], "preparation-only-reviewed")
        sources = {source["id"]: source for source in self.sources["sources"]}
        self.assertEqual(len(sources), 22)
        self.assertTrue(
            sources["caf-iac-linked"]["resolved_url"].endswith(
                "/landing-zone/implementation-options"
            )
        )
        for row in self.matrix["recommendations"]:
            self.assertTrue(set(row["sources"]) <= sources.keys())
            original = next(
                c for c in self.accepted["controls"] if c["upstream_guid"] == row["guid"]
            )["references"][0]["guidance"]
            self.assertIn(original, [sources[key]["url"] for key in row["sources"]])
        for source in sources.values():
            self.assertRegex(source["sha256"], r"^[0-9a-f]{64}$")
            self.assertTrue(source["retrieved_at"])
            self.assertTrue(source["resolved_url"].startswith("https://"))
            self.assertTrue(source["finding"])
            self.assertIn("only", source["reuse"])
            if source["id"] in {
                "azure-residency-linked",
                "github-residency-rendered",
                "github-storage-rendered",
                "microsoft-site-reuse",
            }:
                self.assertEqual(source["revision"], "retrieved-page")
            else:
                self.assertRegex(source["revision"], r"^[0-9a-f]{40}$")
        sovereignty = next(
            r for r in self.matrix["recommendations"] if r["upstream_id"] == "H05.01"
        )
        text = " ".join(sovereignty["evidence_requirements"])
        for boundary in (
            "storage",
            "processing",
            "macOS",
            "Brazil",
            "EFTA",
            "Norway",
            "Switzerland",
            "Japan",
            "Copilot",
            "replicas",
            "preview",
            "Linux-only",
            "external dependencies",
        ):
            self.assertIn(boundary, text)
        self.assertIn("not emergency-fix", sources["caf-management-linked"]["finding"])
        self.assertIn("backlog", sources["caf-automation"]["finding"])

    def test_specific_blank_grouped_and_individual_review_preparation(self):
        response = self.prepared()
        self.assertEqual({r["control_id"] for r in response["decisions"]}, CONTROLS)
        for field in ("answer", "reviewer", "rationale", "evidence", "valid_from", "valid_until"):
            self.assertIsNone(response[field])
        self.assertTrue(all(r["outcome"] is None for r in response["decisions"]))
        with self.assertRaises(InputError):
            compile_interview(response, self.catalog, at=AT)
        question = next(
            q for q in question_bank(self.catalog)["questions"] if q["id"] == self.question
        )
        self.assertEqual(len(question["controls"]), 7)
        self.assertIn("platform AND application", question["question"])
        prepared = prepare_reviews(self.report(), self.catalog, sorted(CONTROLS), SCOPE)
        self.assertTrue(prepared["is_template"])
        for entry in prepared["entries"]:
            preparation = entry["preparation"]
            self.assertEqual(preparation["evidence_tier"], "manual")
            self.assertEqual(len(preparation["evidence_requirements"]), 3)
            self.assertFalse(preparation["available_evidence"][0]["resources"])
            self.assertIsNone(entry["outcome"])
            self.assertIsNone(entry["reviewer"])
            self.assertNotIn(PRIVATE, json.dumps(entry))

    def test_selection_requires_unique_canonical_question_members_and_exact_scope(self):
        identity = "ALZ-" + GUIDS["H05.01"]
        response = self.prepared([identity])
        self.assertEqual([r["control_id"] for r in response["decisions"]], [identity])
        for selected in ([], ["H05.01"], [identity, identity], ["ALZ-unknown"], [True]):
            with self.subTest(selected=selected), self.assertRaises(InputError):
                self.prepared(selected)
        for scope in (OTHER, "organization", SCOPE + "/resourceGroups/unknown"):
            with self.assertRaises(InputError):
                prepare_interview(self.report(), self.catalog, self.question, scope)
        with self.assertRaises(InputError):
            prepare_interview(self.report(), self.catalog, "not-reviewed", SCOPE)

    def test_files_resources_complete_inventory_or_denial_never_prove_process(self):
        for mode in ("planned", "observed"):
            for complete in (False, True):
                for state in ("known", "unknown", "error"):
                    bundle = self.bundle(mode=mode, complete=complete, state=state)
                    report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
                    self.assertEqual(len(self.rows(report)), 7)
                    for row in self.rows(report):
                        self.assertEqual(row[mode]["outcome"], "manual")
                        self.assertEqual(row[mode]["reason"], "human_evidence_required")
                        self.assertEqual(row[mode]["evidence_tier"], "manual")
                        self.assertIsNone(row[mode]["fact"])
                        self.assertFalse(row[mode]["evidence_links"])
                    for control in self.catalog["controls"]:
                        if control["control_id"] in CONTROLS:
                            self.assertEqual(
                                review_context(control, bundle)["matching_resources"], 0
                            )
        stale = assess(
            self.bundle(collected_at="2000-01-01T00:00:00Z"),
            self.catalog,
            at=AT,
            evidence_tiers=True,
        )
        self.assertTrue(all(r["observed"]["freshness"] == "stale" for r in self.rows(stale)))
        self.assertTrue(all(r["observed"]["outcome"] == "manual" for r in self.rows(stale)))
        malformed = self.bundle()
        malformed["resources"][0]["state"] = "approved"
        with self.assertRaises(InputError):
            assess(malformed, self.catalog, at=AT)

    def test_atomic_explicit_independent_decisions_and_no_technical_verified(self):
        response = self.completed()
        manual = compile_interview(response, self.catalog, at=AT)
        self.assertEqual(len(manual["entries"]), 7)
        self.assertTrue(validate_reviews(manual, self.catalog, SCOPE, AT)["ready_to_apply"])
        report = self.report(manual=manual)
        self.assertEqual(
            {r["control_id"]: r["observed"]["outcome"] for r in self.rows(report)},
            {d["control_id"]: d["outcome"] for d in response["decisions"]},
        )
        self.assertTrue(
            all(r["observed"]["reason"] == "manual_attestation" for r in self.rows(report))
        )
        self.assertTrue(all(r["observed"]["evidence_tier"] == "manual" for r in self.rows(report)))
        self.assertEqual(
            report["evidence_tiers"]["counts"], self.report()["evidence_tiers"]["counts"]
        )
        partial = copy.deepcopy(response)
        partial["decisions"][-1]["outcome"] = None
        with self.assertRaises(InputError):
            compile_interview(partial, self.catalog, at=AT)
        shortened = copy.deepcopy(response)
        shortened["decisions"].pop()
        with self.assertRaisesRegex(InputError, "requirements binding"):
            compile_interview(shortened, self.catalog, at=AT)

    def test_scope_content_time_expiry_bank_requirements_and_privacy_bindings(self):
        for key, value in (
            ("scope", OTHER),
            ("catalog_sha256", "0" * 64),
            ("bank_version", "old-bank"),
            ("requirements_sha256", "0" * 64),
            ("answer", " "),
            ("reviewer", None),
            ("evidence", ""),
            ("valid_from", UNTIL),
            ("valid_until", AT),
            ("valid_until", "not-a-time"),
        ):
            response = self.completed()
            response[key] = value
            with self.subTest(key=key), self.assertRaises(InputError):
                compile_interview(response, self.catalog, at=AT)
        for key, value in (
            ("control_sha256", "0" * 64),
            ("outcome", True),
            ("outcome", "verified"),
            ("control_id", "H05.01"),
        ):
            response = self.completed()
            response["decisions"][-1][key] = value
            with self.assertRaises(InputError):
                compile_interview(response, self.catalog, at=AT)
        response = self.completed()
        response["decisions"][-1] = response["decisions"][0]
        with self.assertRaisesRegex(InputError, "duplicate"):
            compile_interview(response, self.catalog, at=AT)
        response = self.completed()
        response["raw_pipeline"] = PRIVATE
        with self.assertRaisesRegex(InputError, "exact fields"):
            compile_interview(response, self.catalog, at=AT)
        changed = copy.deepcopy(self.catalog)
        next(c for c in changed["controls"] if c["control_id"] in CONTROLS)[
            "evidence_requirements"
        ][0] += " Changed scope requirement."
        with self.assertRaisesRegex(InputError, "catalog changed"):
            compile_interview(self.completed(), changed, at=AT)
        manual = compile_interview(self.completed(), self.catalog, at=AT)
        self.assertTrue(
            all(
                r["observed"]["outcome"] == "manual"
                for r in self.rows(self.report(manual=manual, at=UNTIL))
            )
        )
        self.assertFalse(validate_reviews(manual, self.catalog, SCOPE, UNTIL)["ready_to_apply"])
        self.assertFalse(validate_reviews(manual, changed, SCOPE, AT)["ready_to_apply"])

    def test_exceptions_are_independent_and_never_human_confirmation(self):
        exceptions = document(
            "exceptions",
            schema_version="1.1",
            entries=[
                {
                    **{k: v for k, v in entry.items() if k != "outcome"},
                    "disposition": "accepted",
                }
                for entry in compile_interview(self.completed(), self.catalog, at=AT)["entries"]
            ],
        )
        report = self.report(exceptions=exceptions)
        self.assertTrue(all(r["observed"]["outcome"] == "manual" for r in self.rows(report)))
        self.assertTrue(
            all(r["observed"]["exception_disposition"] == "accepted" for r in self.rows(report))
        )
        manual = compile_interview(self.completed(), self.catalog, at=AT)
        both = self.report(manual=manual, exceptions=exceptions)
        for row in self.rows(both):
            self.assertEqual(row["observed"]["reason"], "manual_attestation")
            self.assertEqual(row["observed"]["exception_disposition"], "accepted")
            self.assertEqual(row["observed"]["evidence_tier"], "manual")

    def test_all_report_and_tracker_surfaces_preserve_manual_vs_confirmed_and_privacy(self):
        report = self.report(manual=compile_interview(self.completed(), self.catalog, at=AT))
        model = report_model(report)
        self.assertEqual(len([r for r in model["results"] if r["control_id"] in CONTROLS]), 7)
        self.assertEqual(sum(report["evidence_tiers"]["counts"].values()), 255)
        for format in ("json", "markdown", "html", "csv", "sarif", "pr-summary"):
            for minimize in (False, True):
                output = render(report, format, minimize)
                self.assertNotIn(PRIVATE, output)
                if format == "pr-summary":
                    self.assertIn("H03.01 High (observed)", output)
                    self.assertIn("Signals are not passes", output)
                    self.assertIn('"manual": 43', output)
                else:
                    for guid in GUIDS.values():
                        self.assertIn(guid, output)
                if minimize:
                    self.assertNotIn("Authored fixture reviewer", output)
                    self.assertNotIn(SCOPE, output)
        for minimize in (False, True):
            workbook = render_xlsx(report, minimize)
            with zipfile.ZipFile(io.BytesIO(workbook)) as archive:
                text = "\n".join(archive.read(name).decode("utf-8") for name in archive.namelist())
            self.assertIn(GUIDS["H05.01"], text)
            self.assertNotIn(PRIVATE, text)
            if minimize:
                self.assertNotIn("Authored fixture reviewer", text)
                self.assertNotIn(SCOPE, text)

    def session(self, name="session"):
        return ReviewSession(
            self.bundle(), self.catalog, self.root / name, clock=lambda: AT, evidence_tiers=True
        )

    def test_local_session_exposes_blank_source_questions_and_atomic_save_resume(self):
        session = self.session()
        before = (session.directory / "revision-0000" / "assessment.json").read_bytes()
        state = session.state()
        self.assertEqual(state["records"], [])
        question = next(item for item in state["interviews"] if item["id"] == self.question)
        self.assertEqual(len(question["template"]["decisions"]), 7)
        self.assertIsNone(question["template"]["answer"])
        self.assertTrue(all(d["outcome"] is None for d in question["template"]["decisions"]))
        page = review_page(state, "authored-token", "authored-nonce")
        self.assertIn("development-lifecycle-sovereignty", page)
        self.assertIn("backlog", page)
        self.assertNotIn(PRIVATE, page)
        state = session.save_interview(
            {"revision": 0, "response": self.completed(), "replace_existing": []}
        )
        self.assertEqual(session.revision, 1)
        self.assertEqual(len(state["records"]), 7)
        self.assertEqual(
            (session.directory / "revision-0000" / "assessment.json").read_bytes(), before
        )
        for name in (
            "manual.json",
            "exceptions.json",
            "report.json",
            "report.md",
            "report.html",
            "report-minimized.html",
            "tracker.csv",
            "tracker.xlsx",
            "session-manifest.json",
        ):
            self.assertTrue((session.directory / "revision-0001" / name).is_file(), name)
        resumed = ReviewSession.resume(
            session.directory / "revision-0001", self.root / "resumed", clock=lambda: AT
        )
        self.assertEqual(semantic(resumed.report), semantic(session.report))
        self.assertEqual(len(resumed.state()["records"]), 7)

    def test_session_invalid_partial_conflict_and_write_failure_publish_nothing(self):
        session = self.session()
        before = session.state()
        invalid = self.completed()
        invalid["decisions"][-1]["outcome"] = None
        with self.assertRaises(InputError):
            session.save_interview({"revision": 0, "response": invalid, "replace_existing": []})
        self.assertEqual(session.state(), before)
        with patch.object(Path, "rename", side_effect=OSError("authored disk failure")):
            with self.assertRaises(OSError):
                session.save_interview(
                    {"revision": 0, "response": self.completed(), "replace_existing": []}
                )
        self.assertEqual(session.state(), before)
        self.assertEqual([p.name for p in session.directory.iterdir()], ["revision-0000"])
        session.save_interview(
            {"revision": 0, "response": self.completed(), "replace_existing": []}
        )
        saved = session.state()
        with self.assertRaisesRegex(InputError, "another page"):
            session.save_interview(
                {"revision": 0, "response": self.completed(), "replace_existing": []}
            )
        with self.assertRaisesRegex(InputError, "confirm replacement"):
            session.save_interview(
                {"revision": 1, "response": self.completed(), "replace_existing": []}
            )
        self.assertEqual(session.state(), saved)

    def test_original_time_successor_and_predecessor_replay_with_unaccepted_guard(self):
        accepted_response = prepare_interview(
            assess(self.bundle(), self.accepted, at=AT, evidence_tiers=True),
            self.accepted,
            self.question,
            SCOPE,
        )
        completed = self.completed()
        for field in ("answer", "reviewer", "rationale", "evidence", "valid_from", "valid_until"):
            accepted_response[field] = completed[field]
        for decision in accepted_response["decisions"]:
            decision["outcome"] = "pass"
        manual = compile_interview(accepted_response, self.accepted, at=AT)
        export_bundle(
            self.root / "accepted",
            self.bundle(),
            self.accepted,
            at=AT,
            manual=manual,
            evidence_tiers=True,
        )
        replayed = replay_bundle(self.root / "accepted")
        expected = assess(self.bundle(), self.accepted, at=AT, manual=manual, evidence_tiers=True)
        self.assertEqual(semantic(replayed), semantic(expected))
        self.assertEqual(replayed["evidence"][0]["collected_at"], AT)
        self.assertTrue(
            all(r["observed"]["evidence_tier"] == "manual" for r in self.rows(replayed))
        )
        for path in (self.root / "accepted").iterdir():
            self.assertNotIn("Authored fixture reviewer", path.read_text("utf-8"))
            self.assertNotIn(PRIVATE, path.read_text("utf-8"))
        current_manual = compile_interview(self.completed(), self.catalog, at=AT)
        export_bundle(
            self.root / "successor",
            self.bundle(),
            self.catalog,
            at=AT,
            manual=current_manual,
            evidence_tiers=True,
        )
        current = replay_bundle(self.root / "successor")
        self.assertEqual(semantic(current), semantic(self.report(manual=current_manual)))
        self.assertEqual(current["catalog_version"], "2026-11-06.11")
        self.assertEqual(current["evidence"][0]["collected_at"], AT)
        unaccepted = copy.deepcopy(self.catalog)
        next(c for c in unaccepted["controls"] if c["control_id"] in CONTROLS)[
            "evidence_requirements"
        ][0] += " Unaccepted changed requirement."
        with self.assertRaises(InputError):
            export_bundle(self.root / "unaccepted", self.bundle(), unaccepted, at=AT)
        self.assertFalse((self.root / "unaccepted").exists())
        self.assertNotIn(PRIVATE, json.dumps(sanitize_evidence(self.bundle())))

    def test_individual_cli_preparation_is_blank_and_repeatable(self):
        catalog_path = self.root / "authored-candidate.json"
        report_path = self.root / "authored-report.json"
        output = self.root / "manual.json"
        catalog_path.write_text(json.dumps(self.catalog), encoding="utf-8")
        report_path.write_text(json.dumps(self.report()), encoding="utf-8")
        command = [
            sys.executable,
            "-m",
            "alz_assessor.cli",
            "review",
            "prepare",
            str(report_path),
            "--catalog",
            str(catalog_path),
            "--control",
            "H05.01",
            "--scope",
            SCOPE,
            "--output",
            str(output),
        ]
        result = subprocess.run(command, cwd=self.root, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        prepared = json.loads(output.read_text("utf-8"))
        self.assertEqual(len(prepared["entries"]), 1)
        entry = prepared["entries"][0]
        self.assertIsNone(entry["outcome"])
        self.assertIn("macOS", " ".join(entry["preparation"]["evidence_requirements"]))
        before = output.read_bytes()
        result = subprocess.run(command, cwd=self.root, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_bytes(), before)

    def test_grouped_cli_prepare_apply_is_explicit_and_never_overwrites(self):
        catalog_path = self.root / "authored-candidate.json"
        report_path = self.root / "authored-report.json"
        response_path = self.root / "response.json"
        output = self.root / "manual.json"
        catalog_path.write_text(json.dumps(self.catalog), encoding="utf-8")
        report_path.write_text(json.dumps(self.report()), encoding="utf-8")

        def invoke(arguments):
            with (
                patch.object(sys, "argv", ["alz-assessor", "interview", *arguments]),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                return main()

        prepare = [
            "prepare",
            str(report_path),
            "--catalog",
            str(catalog_path),
            "--question",
            self.question,
            "--scope",
            SCOPE,
            "--output",
            str(response_path),
        ]
        self.assertEqual(invoke(prepare), 0)
        response = json.loads(response_path.read_text("utf-8"))
        self.assertIsNone(response["answer"])
        self.assertTrue(all(d["outcome"] is None for d in response["decisions"]))
        before = response_path.read_bytes()
        self.assertEqual(invoke(prepare), 2)
        self.assertEqual(response_path.read_bytes(), before)
        apply = [
            "apply",
            str(response_path),
            "--catalog",
            str(catalog_path),
            "--at",
            AT,
            "--output",
            str(output),
        ]
        self.assertEqual(invoke(apply), 2)
        self.assertFalse(output.exists())
        response_path.write_text(json.dumps(self.completed()), encoding="utf-8")
        self.assertEqual(invoke(apply), 0)
        self.assertEqual(len(json.loads(output.read_text("utf-8"))["entries"]), 7)
        before = output.read_bytes()
        self.assertEqual(invoke(apply), 2)
        self.assertEqual(output.read_bytes(), before)

    def test_actual_bank_and_packaged_matrix_preserve_all_predecessor_questions(self):
        packaged = files("alz_assessor").joinpath("data")
        matrix = json.loads(
            packaged.joinpath(
                "batch-matrix-" + self.accepted["catalog_version"] + ".json"
            ).read_text("utf-8")
        )
        self.assertNotIn("30", {row["batch"] for row in matrix["batches"]})
        self.assertNotEqual(digest(self.catalog), digest(self.accepted))
        successor = json.loads(
            packaged.joinpath("batch-matrix-2026-11-06.11.json").read_text("utf-8")
        )
        self.assertEqual(successor["batches"][:-1], matrix["batches"])
        self.assertEqual(successor["sources"][:-1], matrix["sources"])
        self.assertEqual(successor["batches"][-1], self.matrix)
        self.assertEqual(successor["sources"][-1], self.sources)
        self.assertEqual(
            interviews.BANK[self.question],
            {key: self.matrix["interview"][key] for key in ("question", "controls")},
        )
        self.assertTrue(
            {
                "resource-cost-governance",
                "expressroute-monitoring-routing-failover",
                "dr-dns-bastion",
                "expressroute-cost-resilience",
                "sovereign-audit-workload-protection",
                "inbound-outbound-hybrid",
                "access-operating-model",
                "vault-operating-model",
                "private-service-paths",
                self.question,
            }
            <= {q["id"] for q in question_bank(self.catalog)["questions"]}
        )
        targets = json.loads((REVIEWS / "targets.json").read_text("utf-8"))
        controls = {c["control_id"]: c for c in self.catalog["controls"]}
        for identity, binding in targets["preserved_automated"].items():
            self.assertEqual(control_digest(controls[identity]), binding)

    def test_source_capture_requires_preparation_and_refuses_existing_capture(self):
        script = ROOT / "tools" / "review_batch_sources.py"
        for batch in ("12", "30"):
            with patch.object(sys, "argv", [str(script), "--batch", batch]):
                with self.assertRaisesRegex(ValueError, "preparation-only"):
                    runpy.run_path(str(script), run_name="__main__")
        with patch.object(sys, "argv", [str(script), "--batch", "30", "--preparation-only"]):
            with self.assertRaisesRegex(ValueError, "Frozen source review"):
                runpy.run_path(str(script), run_name="__main__")
