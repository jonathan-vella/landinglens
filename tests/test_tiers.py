import copy
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from alz_assessor.catalog import load_catalog
from alz_assessor.comparison import compare
from alz_assessor.contracts import control_digest, document, timestamp, validate
from alz_assessor.engine import assess
from alz_assessor.replay import export_bundle, replay_bundle, semantic
from alz_assessor.reports import render
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import prepare_reviews
from alz_assessor.terraform import InputError

AT = "2026-11-05T00:00:00Z"
SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-management"
STORAGE = SCOPE + "/providers/Microsoft.Storage/storageAccounts/store"
VAULT = SCOPE + "/providers/Microsoft.KeyVault/vaults/vault"


class EvidenceTierTests(unittest.TestCase):
    def setUp(self):
        self.catalog = load_catalog()
        self.bundle = document(
            "evidence",
            schema_version="1.1",
            mode="observed",
            source="saved",
            collected_at=AT,
            scope=SCOPE,
            inventory_complete=False,
            artifact_hashes={"fixture": "0" * 64},
            diagnostics=[],
            resources=[
                {
                    "logical_id": "storage",
                    "arm_id": STORAGE.lower(),
                    "resource_type": "Microsoft.Storage/storageAccounts",
                    "state": "known",
                    "reason": "",
                    "source_location": "fixture://storage",
                    "properties": {"supportsHttpsTrafficOnly": True},
                }
            ],
        )

    def assess(self, bundle=None, **options):
        return assess(
            bundle if bundle is not None else self.bundle,
            self.catalog,
            at=AT,
            evidence_tiers=True,
            **options,
        )

    def tier(self, report, display):
        identity = next(
            c["control_id"] for c in self.catalog["controls"] if c["upstream_id"] == display
        )
        return next(
            x["tier"] for x in report["evidence_tiers"]["controls"] if x["control_id"] == identity
        )

    def vault(self, value=False):
        return {
            "logical_id": "vault",
            "arm_id": VAULT.lower(),
            "resource_type": "Microsoft.KeyVault/vaults",
            "state": "known",
            "reason": "",
            "source_location": "fixture://vault",
            "properties": {"enableRbacAuthorization": value, "secret": "PRIVATE-NOT-FOR-REPORTING"},
        }

    def test_explicit_version_and_control_counts_not_resource_counts(self):
        report = self.assess()
        self.assertEqual(report["schema_version"], "1.2")
        self.assertEqual(sum(report["evidence_tiers"]["counts"].values()), 255)
        self.assertEqual(len(report["evidence_tiers"]["controls"]), 255)
        self.assertEqual(report["evidence_tiers"]["counts"]["manual"], 43)
        self.assertEqual(self.tier(report, "G04.01"), "verified")
        for value in (True, False):
            bundle = copy.deepcopy(self.bundle)
            second = copy.deepcopy(bundle["resources"][0])
            second.update(logical_id="other", arm_id=STORAGE.lower() + "2")
            second["properties"]["supportsHttpsTrafficOnly"] = value
            bundle["resources"].append(second)
            report = self.assess(bundle)
            self.assertEqual(self.tier(report, "G04.01"), "verified")
            self.assertEqual(sum(report["evidence_tiers"]["counts"].values()), 255)
            row = next(
                r
                for r in report["results"]
                if r["logical_id"] == "other" and r["upstream_id"] == "G04.01"
            )
            self.assertEqual(row["observed"]["outcome"], "pass" if value else "fail")

    def test_partial_predicate_population_is_signal_not_verified(self):
        for state in ("unknown", "inaccessible", "error"):
            bundle = copy.deepcopy(self.bundle)
            second = copy.deepcopy(bundle["resources"][0])
            second.update(
                logical_id="unavailable",
                arm_id=STORAGE.lower() + "2",
                state=state,
                reason="resource_configuration_unavailable",
            )
            bundle["resources"].append(second)
            self.assertEqual(self.tier(self.assess(bundle), "G04.01"), "signal")
        for value in (None, {}, "true", 1, {"unknown": "missing"}):
            bundle = copy.deepcopy(self.bundle)
            bundle["resources"][0]["properties"]["supportsHttpsTrafficOnly"] = value
            self.assertEqual(self.tier(self.assess(bundle), "G04.01"), "needs_decision")

    def test_typed_assisted_evidence_is_signal_without_automatic_outcome(self):
        for value, tier in (
            (False, "signal"),
            (True, "signal"),
            ("false", "needs_decision"),
            ({}, "needs_decision"),
        ):
            bundle = copy.deepcopy(self.bundle)
            bundle["resources"].append(self.vault(value))
            report = self.assess(bundle)
            self.assertEqual(self.tier(report, "G02.04"), tier)
            row = next(r for r in report["results"] if r["upstream_id"] == "G02.04")
            self.assertEqual(row["observed"]["outcome"], "manual")
            for format in ("json", "markdown", "html"):
                for minimize in (False, True):
                    output = render(report, format, minimize)
                    self.assertNotIn("PRIVATE-NOT-FOR-REPORTING", output)
                    self.assertIn("signal", output.lower())

    def test_presence_assignment_scanner_and_query_names_are_not_signals_or_passes(self):
        bundle = copy.deepcopy(self.bundle)
        vault = self.vault()
        vault["properties"] = {"unreviewed": True}
        bundle["resources"].append(vault)
        bundle["metadata"] = {
            "policy_assignments": [{"name": "looks-compliant"}],
            "scanner": {"passed": True},
            "query_result": [],
        }
        report = self.assess(bundle)
        self.assertEqual(self.tier(report, "G02.04"), "needs_decision")
        self.assertEqual(report["evidence_tiers"]["counts"]["signal"], 0)
        self.assertFalse(
            any(
                row["observed"]["outcome"] == "pass"
                for row in report["results"]
                if row["automation"] != "automated"
            )
        )

    def test_stale_future_and_denied_evidence_cannot_be_verified(self):
        for collected in ("2000-01-01T00:00:00Z", "2099-01-01T00:00:00Z"):
            bundle = copy.deepcopy(self.bundle)
            bundle["collected_at"] = collected
            bundle["resources"].append(self.vault())
            report = self.assess(bundle)
            self.assertEqual(self.tier(report, "G04.01"), "needs_decision")
            self.assertEqual(self.tier(report, "G02.04"), "needs_decision")
            self.assertEqual(report["evidence_tiers"]["counts"]["verified"], 0)
        for state in ("unknown", "inaccessible", "error"):
            bundle = copy.deepcopy(self.bundle)
            bundle["resources"][0].update(state=state, reason="resource_configuration_unavailable")
            self.assertEqual(self.tier(self.assess(bundle), "G04.01"), "needs_decision")

    def test_reviews_and_exceptions_do_not_create_verified_technical_evidence(self):
        control = next(c for c in self.catalog["controls"] if c["upstream_id"] == "G02.04")
        entry = {
            "control_id": control["control_id"],
            "control_sha256": control_digest(control),
            "scope": SCOPE,
            "reviewer": "fixture-reviewer",
            "evidence": "https://example.invalid/review",
            "rationale": "Authored fixture decision",
            "valid_from": "2026-11-04T00:00:00Z",
            "valid_until": "2026-11-06T00:00:00Z",
            "outcome": "pass",
        }
        report = self.assess(manual=document("manual", schema_version="1.1", entries=[entry]))
        self.assertEqual(self.tier(report, "G02.04"), "needs_decision")
        self.assertEqual(
            next(r for r in report["results"] if r["upstream_id"] == "G02.04")["observed"][
                "outcome"
            ],
            "pass",
        )
        bundle = copy.deepcopy(self.bundle)
        bundle["resources"][0]["properties"]["supportsHttpsTrafficOnly"] = False
        technical = next(c for c in self.catalog["controls"] if c["upstream_id"] == "G04.01")
        entry.update(control_id=technical["control_id"], control_sha256=control_digest(technical))
        entry.pop("outcome")
        entry["disposition"] = "accepted"
        report = self.assess(
            bundle, exceptions=document("exceptions", schema_version="1.1", entries=[entry])
        )
        self.assertEqual(self.tier(report, "G04.01"), "verified")
        self.assertEqual(
            next(r for r in report["results"] if r["upstream_id"] == "G04.01")["observed"][
                "outcome"
            ],
            "fail",
        )

    def test_strict_version_counts_and_tier_validation(self):
        for version in ("1.0", "1.1"):
            changed = self.assess()
            changed["schema_version"] = version
            with self.assertRaisesRegex(InputError, "explicit assessment contract"):
                validate(changed)
        for value in (True, -1, "1"):
            changed = self.assess()
            changed["evidence_tiers"]["counts"]["verified"] = value
            with self.assertRaises(InputError):
                validate(changed)
        changed = self.assess()
        changed["evidence_tiers"]["controls"].pop()
        with self.assertRaisesRegex(InputError, "counts or control"):
            validate(changed)
        for field, value in (("evidence_tier", "pass"), ("machine_evidence", "true")):
            changed = self.assess()
            changed["results"][0]["observed"][field] = value
            with self.assertRaises(InputError):
                validate(changed)
        for kind in ("catalog", "evidence", "manual", "exceptions", "identity-map"):
            with self.assertRaisesRegex(InputError, "tiered assessments only"):
                validate(document(kind, schema_version="1.2"))
        with self.assertRaisesRegex(InputError, "boolean"):
            assess(self.bundle, self.catalog, at=AT, evidence_tiers="true")

    def test_all_formats_and_legacy_rendering_remain_separate(self):
        legacy = assess(self.bundle, self.catalog, at=AT)
        self.assertEqual(legacy["schema_version"], "1.1")
        self.assertNotIn("evidence_tiers", legacy)
        for format in ("json", "markdown", "html"):
            self.assertNotIn("Evidence tiers", render(legacy, format))
        report = self.assess()
        self.assertEqual(json.loads(render(report))["evidence_tiers"], report["evidence_tiers"])
        self.assertIn("Evidence tiers:", render(report, "markdown"))
        output = render(report, "html")
        for label in ("Evidence tiers", "Verified", "Signal", "Needs decision", "Manual"):
            self.assertIn(label, output)
        self.assertIn("Verified includes technical failures", output)
        self.assertNotIn("https://cdn", output)

    def test_compare_recomputes_mixed_modes_and_freshness_without_drift(self):
        planned = copy.deepcopy(self.bundle)
        planned["mode"] = "planned"
        planned["resources"][0]["properties"]["supportsHttpsTrafficOnly"] = False
        result = compare(self.assess(planned), self.assess(), at=AT)
        self.assertEqual(result["schema_version"], "1.2")
        self.assertEqual(self.tier(result, "G04.01"), "verified")
        row = next(r for r in result["results"] if r["upstream_id"] == "G04.01")
        self.assertEqual(row["comparison"], "drift")
        planned["resources"][0]["properties"] = {}
        result = compare(self.assess(planned), self.assess(), at=AT)
        self.assertEqual(self.tier(result, "G04.01"), "signal")
        self.assertEqual(
            next(r for r in result["results"] if r["upstream_id"] == "G04.01")["comparison"],
            "not_comparable",
        )
        later = (timestamp(AT) + timedelta(days=2)).isoformat()
        result = compare(self.assess(planned), self.assess(), at=later)
        self.assertEqual(self.tier(result, "G04.01"), "needs_decision")
        with self.assertRaisesRegex(InputError, "matching contract"):
            compare(self.assess(planned), assess(self.bundle, self.catalog, at=AT), at=AT)

    def test_review_preparation_session_and_replay_retain_tier_selection(self):
        bundle = copy.deepcopy(self.bundle)
        bundle["resources"].append(self.vault())
        report = self.assess(bundle)
        prepared = prepare_reviews(report, self.catalog, ["G02.04"], SCOPE)
        self.assertEqual(prepared["entries"][0]["preparation"]["evidence_tier"], "signal")
        self.assertIsNone(prepared["entries"][0]["outcome"])
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            session = ReviewSession(
                bundle, self.catalog, root / "session", clock=lambda: AT, evidence_tiers=True
            )
            self.assertEqual(session.state()["evidence_tiers"], report["evidence_tiers"])
            self.assertEqual(session.state()["records"], [])
            invocation = json.loads(
                (root / "session" / "revision-0000" / "invocation.json").read_text()
            )
            self.assertIs(invocation["evidence_tiers"], True)
            export_bundle(root / "replay", bundle, self.catalog, at=AT, evidence_tiers=True)
            manifest = json.loads((root / "replay" / "manifest.json").read_text())
            self.assertEqual(manifest["schema_version"], "1.1")
            self.assertEqual(semantic(replay_bundle(root / "replay")), semantic(report))
            manifest["schema_version"] = "1.0"
            (root / "replay" / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(InputError, "unsupported options"):
                replay_bundle(root / "replay")

    def test_retired_controls_are_traceable_and_totals_still_cover_all_guids(self):
        catalog = copy.deepcopy(self.catalog)
        target = next(c for c in catalog["controls"] if c["upstream_id"] == "G04.01")
        target.update(lifecycle="retired", retired_at=AT, retirement_reason="Authored fixture")
        report = assess(self.bundle, catalog, at=AT, evidence_tiers=True)
        self.assertEqual(sum(report["evidence_tiers"]["counts"].values()), 255)
        self.assertEqual(report["coverage"]["controls"], 254)
        self.assertEqual(len(report["retired_controls"]), 1)

    def test_installed_cli_explicit_tier_flag_and_legacy_output(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "evidence.json"
            path.write_text(json.dumps(self.bundle), encoding="utf-8")
            command = [
                sys.executable,
                "-m",
                "alz_assessor.cli",
                "assess",
                str(path),
                "--input",
                "evidence",
                "--at",
                AT,
            ]
            for format in ("json", "markdown", "html"):
                result = subprocess.run(
                    [*command, "--evidence-tiers", "--format", format],
                    cwd=temp,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(
                    "evidence_tiers" if format == "json" else "Evidence tiers", result.stdout
                )
            result = subprocess.run(command, cwd=temp, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["schema_version"], "1.1")
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            self.assess()
