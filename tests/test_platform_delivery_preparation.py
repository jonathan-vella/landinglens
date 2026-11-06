import contextlib
import copy
import hashlib
import io
import json
import runpy
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
from alz_assessor.reports import render, render_xlsx
from alz_assessor.review_page import review_page
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import prepare_reviews, review_context, validate_reviews
from alz_assessor.terraform import InputError

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "references" / "recommendation-batches"
AT = "2026-11-06T18:30:00Z"
UNTIL = "2026-11-07T18:30:00Z"
SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
OTHER = "/subscriptions/00000000-0000-0000-0000-000000000002"
PRIVATE = "PRIVATE-AUTHORED-TEAM-PIPELINE-SECRET-BILLING-PAYLOAD"
GUIDS = {
    "H01.01": "e85f4226-bf06-4e35-8a8b-7aee4d2d633a",
    "H01.02": "634146bf-7085-4419-a7b5-f96d2726f6da",
    "H01.03": "a9e65070-c59e-4112-8bf6-c11364d4a2a5",
    "H01.04": "165eb5e9-b434-448a-9e24-178632186212",
    "H01.05": "0cadb8c7-8fa5-4fbf-8f39-d1fadb3b0460",
    "H01.06": "108d5099-a11d-4445-bd8b-e12a5e95412e",
    "H01.07": "a52e0c98-76b9-4a09-a1c9-6b2babf22ac4",
}
IDS = {"ALZ-" + guid for guid in GUIDS.values()}


class PlatformDeliveryPreparationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.matrix = json.loads((REFERENCE / "preparation-29.json").read_text("utf-8"))
        self.accepted = load_catalog(
            str(files("alz_assessor").joinpath("data", "catalog-2026-11-06.15.json"))
        )
        self.catalog = copy.deepcopy(self.accepted)
        updates = {row["guid"]: row for row in self.matrix["recommendations"]}
        for control in self.catalog["controls"]:
            if row := updates.get(control["upstream_guid"]):
                control.update(
                    evidence_requirements=row["evidence_requirements"],
                    rationale=row["limitations"],
                )
        self.question = self.matrix["interview"]["id"]
        bank = patch.dict(
            interviews.BANK,
            {
                self.question: {
                    key: self.matrix["interview"][key] for key in ("question", "controls")
                }
            },
        )
        bank.start()
        self.addCleanup(bank.stop)
        network = patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden"))
        network.start()
        self.addCleanup(network.stop)

    def bundle(self, *, mode="observed", complete=False, state="known", collected_at=AT):
        return document(
            "evidence",
            schema_version="1.1",
            mode=mode,
            source="saved" if mode == "observed" else "arm",
            scope=SCOPE,
            collected_at=collected_at,
            inventory_complete=complete,
            artifact_hashes={"fixture": "0" * 64},
            diagnostics=[],
            resources=[
                {
                    "logical_id": "authored-vault",
                    "arm_id": SCOPE + "/providers/Microsoft.KeyVault/vaults/authored",
                    "resource_type": "Microsoft.KeyVault/vaults",
                    "state": state,
                    "reason": "detail_denied"
                    if state == "error"
                    else "unsupported_configuration"
                    if state == "unknown"
                    else "",
                    "source_location": "fixture://authored",
                    "properties": properties(
                        "Microsoft.KeyVault/vaults",
                        {
                            "enableSoftDelete": True,
                            "enablePurgeProtection": True,
                            "raw_pipeline": PRIVATE,
                            "secretUri": PRIVATE,
                            "team": PRIVATE,
                            "billing": PRIVATE,
                            "humanConfirmed": True,
                        },
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

    def rows(self, report):
        return [r for r in report["results"] if r["control_id"] in IDS]

    def prepared(self, selected=None):
        return prepare_interview(
            self.report(), self.catalog, self.question, SCOPE, selected=selected
        )

    def completed(self):
        response = self.prepared()
        response.update(
            answer="Authored fixture: redacted references, not an assessed-team approval.",
            reviewer="Authored fixture reviewer",
            rationale="Seven explicit independent fixture decisions, not operating assurance.",
            evidence="https://example.invalid/redacted-platform-evidence",
            valid_from=AT,
            valid_until=UNTIL,
        )
        for decision, outcome in zip(
            response["decisions"],
            ("pass", "fail", "not_applicable", "fail", "pass", "fail", "pass"),
            strict=True,
        ):
            decision["outcome"] = outcome
        return response

    def test_exact_fixed_manual_guids_and_no_accepted_activation(self):
        targets = json.loads((REFERENCE / "targets.json").read_text("utf-8"))
        self.assertEqual(
            {r["upstream_id"]: r["guid"] for r in targets["targets"] if r["batch"] == "29"},
            GUIDS,
        )
        self.assertEqual(
            {r["upstream_id"]: r["guid"] for r in self.matrix["recommendations"]}, GUIDS
        )
        self.assertEqual(set(self.matrix["interview"]["controls"]), IDS)
        self.assertEqual(self.matrix["review_state"], "preparation-only-reviewed")
        self.assertNotIn("catalog_version", self.matrix)
        self.assertNotIn("accepted_at", self.matrix)
        self.assertEqual(self.accepted["catalog_version"], "2026-11-06.15")
        self.assertEqual(len(self.catalog["controls"]), 255)
        for old, candidate in zip(self.accepted["controls"], self.catalog["controls"], strict=True):
            if old["control_id"] in IDS:
                self.assertEqual(candidate["automation"], "manual")
                self.assertIsNone(candidate["rule"])
                self.assertFalse(candidate.get("review_resource_types"))
                self.assertFalse(candidate.get("review_fact_paths"))
                self.assertEqual(len(candidate["evidence_requirements"]), 3)
            else:
                self.assertEqual(control_digest(old), control_digest(candidate))
        builder = runpy.run_path(str(ROOT / "tools" / "build_batches.py"), run_name="prep")
        with self.assertRaisesRegex(ValueError, "Preparation"):
            builder["apply_batch"](self.accepted, self.accepted, targets, self.matrix, [], [])
        self.assertNotIn(
            "29",
            {
                row["batch"]
                for row in json.loads(
                    files("alz_assessor")
                    .joinpath("data", "batch-matrix-2026-11-06.15.json")
                    .read_text("utf-8")
                )["batches"]
            },
        )

    def test_source_links_revisions_redirects_and_conditional_qualifications(self):
        manifest = json.loads((REFERENCE / "preparation-29-sources.json").read_text("utf-8"))
        self.assertEqual(manifest["review_state"], "preparation-only-reviewed")
        sources = {r["id"]: r for r in manifest["sources"]}
        self.assertEqual(len(sources), 16)
        for source in sources.values():
            self.assertRegex(source["sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(source["revision"], r"^[0-9a-f]{40}$")
            self.assertTrue(source["retrieved_at"])
            self.assertTrue(source["finding"])
            self.assertIn("only", source["reuse"])
            self.assertTrue(source["resolved_url"].startswith("https://learn.microsoft.com/"))
        self.assertTrue(
            sources["iac-linked"]["resolved_url"].endswith("/landing-zone/implementation-options")
        )
        self.assertIn("no longer", sources["team-topology-linked"]["finding"])
        self.assertIn("not a universal", sources["rbac-custom-roles"]["finding"])
        self.assertIn("inconsistency", sources["vending-mpa"]["finding"])
        for row in self.matrix["recommendations"]:
            self.assertEqual(row["classification"], "manual")
            self.assertTrue(set(row["sources"]) <= sources.keys())
            original = next(
                c for c in self.accepted["controls"] if c["upstream_guid"] == row["guid"]
            )
            self.assertIn(
                original["references"][0]["guidance"], [sources[k]["url"] for k in row["sources"]]
            )
        text = self.matrix["interview"]["question"]
        for requirement in (
            "built-in",
            "custom",
            "inherited/conditional",
            "IaC AND application",
            "definition of done",
            "no detected data",
            "CCoE",
            "EA/MCA/MPA",
            "IPAM",
            "not hard caps",
            "DevTest",
            "handoff",
            "Terraform",
            "OIDC",
            "secret literals/URIs",
            "humanConfirmed",
        ):
            self.assertIn(requirement, text)

    def test_source_capture_is_preparation_only_and_frozen(self):
        capture = runpy.run_path(str(ROOT / "tools" / "review_batch_sources.py"), run_name="prep")
        for arguments, message in (
            (["--batch", "29"], "preparation-only"),
            (["--batch", "29", "--preparation-only"], "Frozen source review"),
        ):
            with patch.object(sys, "argv", ["capture", *arguments]):
                with self.assertRaisesRegex(ValueError, message):
                    capture["main"]()

    def test_seven_independently_blank_specific_reviews_and_grouped_template(self):
        response = self.prepared()
        self.assertEqual({d["control_id"] for d in response["decisions"]}, IDS)
        for field in ("answer", "reviewer", "rationale", "evidence", "valid_from", "valid_until"):
            self.assertIsNone(response[field])
        self.assertTrue(all(d["outcome"] is None for d in response["decisions"]))
        with self.assertRaises(InputError):
            compile_interview(response, self.catalog, at=AT)
        question = next(
            q for q in question_bank(self.catalog)["questions"] if q["id"] == self.question
        )
        self.assertEqual(len(question["controls"]), 7)
        template = prepare_reviews(self.report(), self.catalog, sorted(IDS), SCOPE)
        self.assertTrue(template["is_template"])
        for entry in template["entries"]:
            self.assertIsNone(entry["outcome"])
            self.assertIsNone(entry["reviewer"])
            self.assertEqual(entry["preparation"]["evidence_tier"], "manual")
            self.assertEqual(len(entry["preparation"]["evidence_requirements"]), 3)
            self.assertFalse(entry["preparation"]["available_evidence"][0]["resources"])
            self.assertNotIn(PRIVATE, json.dumps(entry))

    def test_selection_rejects_noncanonical_duplicate_foreign_and_wrong_scope(self):
        identity = "ALZ-" + GUIDS["H01.06"]
        self.assertEqual(
            [d["control_id"] for d in self.prepared([identity])["decisions"]], [identity]
        )
        for selected in ([], ["H01.06"], [identity, identity], ["ALZ-unknown"], [True]):
            with self.subTest(selected=selected), self.assertRaises(InputError):
                self.prepared(selected)
        for scope in (OTHER, "organization", SCOPE + "/resourceGroups/unknown"):
            with self.assertRaises(InputError):
                prepare_interview(self.report(), self.catalog, self.question, scope)
        with self.assertRaises(InputError):
            prepare_interview(self.report(), self.catalog, "not-reviewed", SCOPE)

    def test_configuration_inventory_human_flag_and_denial_never_prove_process(self):
        for mode in ("planned", "observed"):
            for complete in (False, True):
                for state in ("known", "unknown", "error"):
                    bundle = self.bundle(mode=mode, complete=complete, state=state)
                    result = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
                    self.assertEqual(len(self.rows(result)), 7)
                    for row in self.rows(result):
                        self.assertEqual(row[mode]["outcome"], "manual")
                        self.assertEqual(row[mode]["reason"], "human_evidence_required")
                        self.assertEqual(row[mode]["evidence_tier"], "manual")
                        self.assertIsNone(row[mode]["fact"])
                        self.assertFalse(row[mode]["evidence_links"])
                    for control in self.catalog["controls"]:
                        if control["control_id"] in IDS:
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

    def test_atomic_explicit_decisions_and_no_manufactured_verified(self):
        response = self.completed()
        manual = compile_interview(response, self.catalog, at=AT)
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
        for mutation in ("blank", "removed", "duplicate", "verified", "humanConfirmed"):
            invalid = copy.deepcopy(response)
            if mutation == "blank":
                invalid["decisions"][-1]["outcome"] = None
            elif mutation == "removed":
                invalid["decisions"].pop()
            elif mutation == "duplicate":
                invalid["decisions"][-1] = invalid["decisions"][0]
            elif mutation == "verified":
                invalid["decisions"][-1]["outcome"] = "verified"
            else:
                invalid["humanConfirmed"] = True
            with self.subTest(mutation=mutation), self.assertRaises(InputError):
                compile_interview(invalid, self.catalog, at=AT)

    def test_scope_content_time_expiry_attribution_and_privacy_bindings(self):
        for key, value in (
            ("scope", OTHER),
            ("catalog_sha256", "0" * 64),
            ("bank_version", "old"),
            ("requirements_sha256", "0" * 64),
            ("answer", " "),
            ("reviewer", None),
            ("evidence", ""),
            ("valid_from", UNTIL),
            ("valid_until", AT),
            ("valid_until", "bad-time"),
            ("raw_pipeline", PRIVATE),
        ):
            response = self.completed()
            response[key] = value
            with self.subTest(key=key), self.assertRaises(InputError):
                compile_interview(response, self.catalog, at=AT)
        response = self.completed()
        response["decisions"][-1]["control_sha256"] = "0" * 64
        with self.assertRaises(InputError):
            compile_interview(response, self.catalog, at=AT)
        manual = compile_interview(self.completed(), self.catalog, at=AT)
        changed = copy.deepcopy(self.catalog)
        next(c for c in changed["controls"] if c["control_id"] in IDS)["evidence_requirements"][
            0
        ] += " Authored changed requirement."
        self.assertFalse(validate_reviews(manual, changed, SCOPE, AT)["ready_to_apply"])
        self.assertFalse(validate_reviews(manual, self.catalog, SCOPE, UNTIL)["ready_to_apply"])
        self.assertTrue(
            all(
                r["observed"]["outcome"] == "manual"
                for r in self.rows(self.report(manual=manual, at=UNTIL))
            )
        )

    def test_independent_exceptions_do_not_confirm_human_decisions(self):
        manual = compile_interview(self.completed(), self.catalog, at=AT)
        exceptions = document(
            "exceptions",
            schema_version="1.1",
            entries=[
                {**{k: v for k, v in entry.items() if k != "outcome"}, "disposition": "accepted"}
                for entry in manual["entries"]
            ],
        )
        for row in self.rows(self.report(exceptions=exceptions)):
            self.assertEqual(row["observed"]["outcome"], "manual")
            self.assertEqual(row["observed"]["exception_disposition"], "accepted")
        for row in self.rows(self.report(manual=manual, exceptions=exceptions)):
            self.assertEqual(row["observed"]["reason"], "manual_attestation")
            self.assertEqual(row["observed"]["exception_disposition"], "accepted")
            self.assertEqual(row["observed"]["evidence_tier"], "manual")

    def test_every_report_tracker_preserves_manual_tier_and_withheld_payloads(self):
        report = self.report(manual=compile_interview(self.completed(), self.catalog, at=AT))
        self.assertEqual(sum(report["evidence_tiers"]["counts"].values()), 255)
        for format in ("json", "markdown", "html", "csv", "sarif", "pr-summary"):
            for minimize in (False, True):
                output = render(report, format, minimize)
                self.assertNotIn(PRIVATE, output)
                if format == "pr-summary":
                    self.assertIn("Signals are not passes", output)
                    self.assertIn('"manual": 43', output)
                elif format == "markdown":
                    for upstream in GUIDS:
                        self.assertIn(upstream, output)
                else:
                    for guid in GUIDS.values():
                        self.assertIn(guid, output)
                if minimize:
                    self.assertNotIn("Authored fixture reviewer", output)
                    self.assertNotIn(SCOPE, output)
        for minimize in (False, True):
            with zipfile.ZipFile(io.BytesIO(render_xlsx(report, minimize))) as archive:
                text = "\n".join(archive.read(name).decode("utf-8") for name in archive.namelist())
            self.assertIn(GUIDS["H01.07"], text)
            self.assertNotIn(PRIVATE, text)
            if minimize:
                self.assertNotIn("Authored fixture reviewer", text)
                self.assertNotIn(SCOPE, text)

    def session(self):
        return ReviewSession(
            self.bundle(),
            self.catalog,
            self.root / "session",
            clock=lambda: AT,
            evidence_tiers=True,
        )

    def test_local_session_blank_specific_preparation_save_and_resume(self):
        session = self.session()
        before = (session.directory / "revision-0000" / "assessment.json").read_bytes()
        state = session.state()
        question = next(q for q in state["interviews"] if q["id"] == self.question)
        self.assertEqual(len(question["template"]["decisions"]), 7)
        self.assertTrue(all(d["outcome"] is None for d in question["template"]["decisions"]))
        page = review_page(state, "authored-token", "authored-nonce")
        self.assertIn(self.question, page)
        self.assertIn("CCoE", page)
        self.assertNotIn(PRIVATE, page)
        state = session.save_interview(
            {"revision": 0, "response": self.completed(), "replace_existing": []}
        )
        self.assertEqual(len(state["records"]), 7)
        self.assertEqual(
            (session.directory / "revision-0000" / "assessment.json").read_bytes(), before
        )
        resumed = ReviewSession.resume(
            session.directory / "revision-0001", self.root / "resumed", clock=lambda: AT
        )
        self.assertEqual(semantic(resumed.report), semantic(session.report))
        self.assertEqual(len(resumed.state()["records"]), 7)
        for path in (session.directory / "revision-0001").iterdir():
            self.assertNotIn(PRIVATE.encode(), path.read_bytes())

    def test_session_partial_conflict_and_disk_failure_publish_nothing(self):
        session = self.session()
        before = session.state()
        response = self.completed()
        response["decisions"][-1]["outcome"] = None
        with self.assertRaises(InputError):
            session.save_interview({"revision": 0, "response": response, "replace_existing": []})
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
        for revision, message in ((0, "another page"), (1, "confirm replacement")):
            with self.assertRaisesRegex(InputError, message):
                session.save_interview(
                    {"revision": revision, "response": self.completed(), "replace_existing": []}
                )
        self.assertEqual(session.state(), saved)

    def test_accepted_original_time_replay_and_unaccepted_candidate_guard(self):
        original = assess(self.bundle(), self.accepted, at=AT, evidence_tiers=True)
        export_bundle(
            self.root / "accepted", self.bundle(), self.accepted, at=AT, evidence_tiers=True
        )
        replayed = replay_bundle(self.root / "accepted")
        self.assertEqual(semantic(replayed), semantic(original))
        self.assertEqual(replayed["evidence"][0]["collected_at"], AT)
        self.assertTrue(
            all(r["observed"]["evidence_tier"] == "manual" for r in self.rows(replayed))
        )
        with self.assertRaisesRegex(InputError, "packaged artifact"):
            export_bundle(self.root / "unaccepted", self.bundle(), self.catalog, at=AT)
        self.assertFalse((self.root / "unaccepted").exists())
        self.assertNotIn(PRIVATE, json.dumps(sanitize_evidence(self.bundle())))
        for path in (self.root / "accepted").iterdir():
            self.assertNotIn(PRIVATE, path.read_text("utf-8"))

    def test_cli_blank_grouped_and_individual_apply_never_overwrites(self):
        catalog = self.root / "candidate.json"
        report = self.root / "assessment.json"
        response = self.root / "response.json"
        output = self.root / "manual.json"
        catalog.write_text(json.dumps(self.catalog), encoding="utf-8")
        report.write_text(json.dumps(self.report()), encoding="utf-8")

        def invoke(arguments):
            with (
                patch.object(sys, "argv", ["alz-assessor", *arguments]),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                return main()

        prepare = [
            "interview",
            "prepare",
            str(report),
            "--catalog",
            str(catalog),
            "--question",
            self.question,
            "--scope",
            SCOPE,
            "--output",
            str(response),
        ]
        self.assertEqual(invoke(prepare), 0)
        blank = json.loads(response.read_text("utf-8"))
        self.assertIsNone(blank["answer"])
        self.assertTrue(all(d["outcome"] is None for d in blank["decisions"]))
        before = response.read_bytes()
        self.assertEqual(invoke(prepare), 2)
        self.assertEqual(response.read_bytes(), before)
        apply = [
            "interview",
            "apply",
            str(response),
            "--catalog",
            str(catalog),
            "--at",
            AT,
            "--output",
            str(output),
        ]
        self.assertEqual(invoke(apply), 2)
        self.assertFalse(output.exists())
        response.write_text(json.dumps(self.completed()), encoding="utf-8")
        self.assertEqual(invoke(apply), 0)
        before = output.read_bytes()
        self.assertEqual(invoke(apply), 2)
        self.assertEqual(output.read_bytes(), before)
        individual = self.root / "individual.json"
        self.assertEqual(
            invoke(
                [
                    "review",
                    "prepare",
                    str(report),
                    "--catalog",
                    str(catalog),
                    "--control",
                    "H01.06",
                    "--scope",
                    SCOPE,
                    "--output",
                    str(individual),
                ]
            ),
            0,
        )
        entry = json.loads(individual.read_text("utf-8"))["entries"][0]
        self.assertIsNone(entry["outcome"])
        self.assertIn("secret URIs", " ".join(entry["preparation"]["evidence_requirements"]))

    def test_all_146_earlier_rows_seventeen_receipts_and_baseline_bytes_preserved(self):
        ledger = json.loads((REFERENCE / "ledger.json").read_text("utf-8"))
        self.assertEqual(len(ledger["recommendations"]), 251)
        earlier = {
            "01",
            "04",
            "05",
            "08",
            "11",
            "12",
            "13",
            "14",
            "15",
            "16",
            "17",
            "18",
            "19",
            "20",
            "22",
            "23",
            "30",
        }
        receipts = {key: value for key, value in ledger["deliveries"].items() if key in earlier}
        rows = [r for r in ledger["recommendations"] if r["batch"] in earlier]
        self.assertEqual((len(rows), len(receipts)), (146, 17))
        self.assertTrue(all(r["status"] == "merged" for r in rows))
        self.assertEqual(
            digest(receipts), "bc563dfa7d514c2c1d159669eef95e7ebe16cad98cdb965529b51ab4c1ecbe92"
        )
        self.assertEqual(
            digest(rows), "b56f0606a0f368fd0a59c941183849f16059f5fab582616a247085f9f8193171"
        )
        for name, binding in (
            (
                "catalog-2026-11-06.15.json",
                "88bf9dffc2c9ae0efbd27acd2dcfefa34b7c15225a640cf35609ca4ea466321f",
            ),
            (
                "crosswalk-2026-11-06.15.json",
                "287a4495171c2d72db362c97e1528767af231ffd4046e17410d2bf1a328a3323",
            ),
        ):
            self.assertEqual(
                hashlib.sha256(
                    files("alz_assessor").joinpath("data", name).read_bytes()
                ).hexdigest(),
                binding,
            )
        controls = {c["control_id"]: c for c in self.catalog["controls"]}
        targets = json.loads((REFERENCE / "targets.json").read_text("utf-8"))
        for identity, binding in targets["preserved_automated"].items():
            self.assertEqual(control_digest(controls[identity]), binding)
