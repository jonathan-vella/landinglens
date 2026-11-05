import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from alz_assessor.catalog import load_catalog
from alz_assessor.comparison import compare
from alz_assessor.contracts import document, validate
from alz_assessor.engine import assess
from alz_assessor.replay import export_bundle, replay_bundle, semantic
from alz_assessor.reports import render
from alz_assessor.reviews import prepare_reviews
from alz_assessor.scanner_evidence import import_scanner
from alz_assessor.terraform import InputError

AT = "2026-11-05T00:00:00Z"
SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
RESOURCE = (
    SCOPE + "/resourceGroups/private-fixture/providers/Microsoft.Storage/storageAccounts/store"
)


class ScannerEvidenceTests(unittest.TestCase):
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
            resources=[],
        )
        self.export = {
            "schema_version": "1.0",
            "kind": "scanner-export",
            "format": "psrule-json",
            "scope": SCOPE,
            "mode": "observed",
            "evaluated_at": AT,
            "scanner": {
                "name": "PSRule.Rules.Azure",
                "version": "1.48.0-B0228",
                "baseline": "Azure.GA",
            },
            "complete": True,
            "artifact_hashes": {"scanner-input": "0" * 64},
            "identities": [{"index": 0, "arm_id": RESOURCE}],
            "output": [
                {
                    "ruleName": "Azure.Storage.SecureTransfer",
                    "ref": "AZR-000196",
                    "outcome": "Pass",
                    "info": {"moduleName": "PSRule.Rules.Azure"},
                    "targetName": "not-an-arm-id",
                    "targetType": "Microsoft.Storage/storageAccounts",
                    "detail": {"secret": "PRIVATE-NOT-FOR-REPORTING"},
                }
            ],
        }

    def report(self, export=None, bundle=None):
        bundle = import_scanner(bundle or self.bundle, export or self.export, self.catalog)
        return assess(bundle, self.catalog, at=AT, evidence_tiers=True)

    def row(self, report):
        return next(row for row in report["results"] if row["upstream_id"] == "G04.01")

    def sarif(self):
        export = copy.deepcopy(self.export)
        export.update(
            format="sarif-2.1.0",
            scanner={"name": "PSRule", "version": "2.9.0", "baseline": "Azure.GA"},
        )
        export["output"] = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {"name": "PSRule", "semanticVersion": "2.9.0"},
                        "extensions": [{"name": "PSRule.Rules.Azure", "version": "1.48.0-B0228"}],
                    },
                    "invocations": [{"executionSuccessful": True}],
                    "results": [
                        {
                            "ruleId": "AZR-000196",
                            "kind": "fail",
                            "message": {"text": "PRIVATE-NOT-FOR-REPORTING"},
                        }
                    ],
                }
            ],
        }
        return export

    def test_psrule_pass_fail_are_signals_not_outcomes(self):
        for status in ("Pass", "Fail"):
            export = copy.deepcopy(self.export)
            export["output"][0]["outcome"] = status
            report = self.report(export)
            self.assertEqual(report["scanner_signals"]["records"][0]["status"], status)
            self.assertIs(report["scanner_signals"]["records"][0]["usable"], True)
            self.assertEqual(self.row(report)["observed"]["outcome"], "unknown")
            self.assertEqual(self.row(report)["observed"]["evidence_tier"], "signal")
            self.assertEqual(sum(report["evidence_tiers"]["counts"].values()), 255)

    def test_sarif_rule_reference_and_defaults_suppressions(self):
        for kind, expected in (
            ("pass", "Pass"),
            ("fail", "Fail"),
            (None, "Fail"),
            ("review", "Unknown"),
            ({}, "Unknown"),
        ):
            export = self.sarif()
            if kind is None:
                export["output"]["runs"][0]["results"][0].pop("kind")
            else:
                export["output"]["runs"][0]["results"][0]["kind"] = kind
            record = self.report(export)["scanner_signals"]["records"][0]
            self.assertEqual(record["status"], expected)
            self.assertEqual(record["usable"], expected in ("Pass", "Fail"))
        export = self.sarif()
        export["output"]["runs"][0]["results"][0]["suppressions"] = [{"kind": "external"}]
        self.assertIs(self.report(export)["scanner_signals"]["records"][0]["usable"], False)

    def test_empty_unknown_rules_producers_and_names_never_prove_pass(self):
        export = copy.deepcopy(self.export)
        export["output"], export["identities"] = [], []
        report = self.report(export)
        self.assertEqual(report["scanner_signals"]["records"], [])
        self.assertEqual(self.row(report)["observed"]["evidence_tier"], "needs_decision")
        for info, rule in (
            ({}, "Azure.Storage.SecureTransfer"),
            ({"moduleName": "another-tool"}, "Azure.Storage.SecureTransfer"),
            ({"moduleName": "PSRule.Rules.Azure"}, "Unknown.Rule"),
        ):
            export = copy.deepcopy(self.export)
            export["output"][0].update(info=info, ruleName=rule, ref=None)
            report = self.report(export)
            self.assertEqual(report["scanner_signals"]["records"], [])
            self.assertEqual(len(report["scanner_signals"]["gaps"]), 1)
        export = copy.deepcopy(self.export)
        export["identities"] = []
        record = self.report(export)["scanner_signals"]["records"][0]
        self.assertIs(record["usable"], False)
        self.assertIsNone(record["resource_id"])
        export = self.sarif()
        export["output"]["runs"][0]["tool"]["extensions"] = []
        self.assertEqual(self.report(export)["scanner_signals"]["records"], [])

    def test_stale_partial_failed_error_and_conflicts_remain_visible(self):
        for field, value in (
            ("complete", False),
            ("evaluated_at", "2000-01-01T00:00:00Z"),
            ("evaluated_at", "2099-01-01T00:00:00Z"),
        ):
            export = copy.deepcopy(self.export)
            export[field] = value
            self.assertIs(self.report(export)["scanner_signals"]["records"][0]["usable"], False)
        for outcome in ("Error", "None", "Unknown", None, {}):
            export = copy.deepcopy(self.export)
            export["output"][0]["outcome"] = outcome
            self.assertIs(self.report(export)["scanner_signals"]["records"][0]["usable"], False)
        export = self.sarif()
        export["output"]["runs"][0]["invocations"] = [{"executionSuccessful": False}]
        self.assertIs(self.report(export)["scanner_signals"]["records"][0]["usable"], False)
        export = copy.deepcopy(self.export)
        duplicate = copy.deepcopy(export["output"][0])
        duplicate["outcome"] = "Fail"
        export["output"].append(duplicate)
        export["identities"].append({"index": 1, "arm_id": RESOURCE})
        report = self.report(export)
        self.assertTrue(
            all(not record["usable"] for record in report["scanner_signals"]["records"])
        )

    def test_strict_scope_mode_identity_formats_provenance_and_bounds(self):
        for field, value in (
            ("schema_version", "2"),
            ("format", "any-json"),
            ("mode", "planned"),
            ("complete", "true"),
            ("artifact_hashes", {}),
            ("output", [None]),
            ("scope", SCOPE + "/resourceGroups/other"),
            ("identities", [{"index": True, "arm_id": RESOURCE}]),
        ):
            export = copy.deepcopy(self.export)
            export[field] = value
            with self.assertRaises(InputError):
                import_scanner(self.bundle, export, self.catalog)
        for identity in ("store", RESOURCE.replace("000000000001", "000000000002")):
            export = copy.deepcopy(self.export)
            export["identities"][0]["arm_id"] = identity
            with self.assertRaises(InputError):
                import_scanner(self.bundle, export, self.catalog)
        export = copy.deepcopy(self.export)
        export["output"] *= 10001
        with self.assertRaisesRegex(InputError, "10,000"):
            import_scanner(self.bundle, export, self.catalog)
        export = self.sarif()
        export["output"]["runs"][0]["tool"]["driver"]["name"] = "other"
        with self.assertRaisesRegex(InputError, "identity"):
            import_scanner(self.bundle, export, self.catalog)
        export = copy.deepcopy(self.export)
        export["output"][0]["ref"] = "AZR-000289"
        with self.assertRaisesRegex(InputError, "conflicts"):
            import_scanner(self.bundle, export, self.catalog)
        export = self.sarif()
        export["output"]["runs"][0]["results"][0]["ruleIndex"] = 0
        export["output"]["runs"][0]["tool"]["driver"]["rules"] = [{"id": "Other.Rule"}]
        with self.assertRaisesRegex(InputError, "ruleIndex"):
            import_scanner(self.bundle, export, self.catalog)
        export = self.sarif()
        export["output"]["runs"][0]["invocations"][0]["endTimeUtc"] = "2020-01-01T00:00:00Z"
        with self.assertRaisesRegex(InputError, "time conflicts"):
            import_scanner(self.bundle, export, self.catalog)

    def test_no_external_file_fetch_or_traversal_and_privacy(self):
        for uri in (
            "https://example.invalid/private",
            "file:///C:/secret",
            "../secret",
            "%2e%2e/private",
            "C:\\secret",
            "/tmp/private",
        ):
            export = self.sarif()
            export["output"]["runs"][0]["artifacts"] = [
                {"location": {"artifactLocation": {"uri": uri}}}
            ]
            with self.assertRaisesRegex(InputError, "artifact path"):
                import_scanner(self.bundle, export, self.catalog)
        export = self.sarif()
        export["output"]["runs"][0]["externalPropertyFileReferences"] = {}
        with self.assertRaisesRegex(InputError, "External"):
            import_scanner(self.bundle, export, self.catalog)
        bundle = import_scanner(self.bundle, self.export, self.catalog)
        self.assertNotIn("PRIVATE-NOT-FOR-REPORTING", json.dumps(bundle))
        report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        for format in ("json", "markdown", "html"):
            self.assertNotIn("PRIVATE-NOT-FOR-REPORTING", render(report, format))
            self.assertNotIn("private-fixture", render(report, format, minimize=True))

    def test_review_replay_comparison_and_installed_cli(self):
        bundle = import_scanner(self.bundle, self.export, self.catalog)
        report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        records = prepare_reviews(report, self.catalog, ["G04.01"], SCOPE)
        self.assertIsNone(records["entries"][0]["outcome"])
        self.assertEqual(
            records["entries"][0]["preparation"]["scanner_signals"][0]["status"], "Pass"
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
                export_bundle(root / "replay", bundle, self.catalog, at=AT, evidence_tiers=True)
                self.assertEqual(semantic(replay_bundle(root / "replay")), semantic(report))
            source, scan = root / "evidence.json", root / "scanner.json"
            source.write_text(json.dumps(self.bundle), encoding="utf-8")
            scan.write_text(json.dumps(self.export), encoding="utf-8")
            command = [
                sys.executable,
                "-m",
                "alz_assessor.cli",
                "assess",
                str(source),
                "--input",
                "evidence",
                "--scanner-evidence",
                str(scan),
                "--at",
                AT,
            ]
            result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 2)
            result = subprocess.run(
                [*command, "--evidence-tiers"], cwd=root, capture_output=True, text=True, timeout=30
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(self.row(json.loads(result.stdout))["observed"]["outcome"], "unknown")
        planned = assess(
            {**self.bundle, "mode": "planned"}, self.catalog, at=AT, evidence_tiers=True
        )
        compared = compare(planned, report, at="2026-11-07T00:00:00Z")
        self.assertIs(compared["scanner_signals"]["records"][0]["usable"], False)
        self.assertEqual(self.row(compared)["observed"]["evidence_tier"], "needs_decision")
        self.assertEqual(self.row(compared)["comparison"], "not_comparable")
        planned_export = copy.deepcopy(self.export)
        planned_export["mode"] = "planned"
        planned_bundle = import_scanner(
            {**self.bundle, "mode": "planned"}, planned_export, self.catalog
        )
        planned = assess(planned_bundle, self.catalog, at=AT, evidence_tiers=True)
        combined = compare(planned, report, at=AT)
        self.assertEqual(len(combined["scanner_signal_runs"]), 2)
        self.assertNotIn("scanner_signals", combined)
        for mode in ("planned", "observed"):
            self.assertEqual(self.row(combined)[mode]["outcome"], "unknown")
            self.assertEqual(self.row(combined)[mode]["evidence_tier"], "signal")
        for format in ("json", "markdown", "html"):
            self.assertNotIn("private-fixture", render(combined, format, minimize=True))

    def test_normalized_signal_tampering_and_replacement_rejected(self):
        bundle = import_scanner(self.bundle, self.export, self.catalog)
        with self.assertRaisesRegex(InputError, "replaced"):
            import_scanner(bundle, self.export, self.catalog)
        report = self.report()
        for field, value in (("usable", "true"), ("flags", ["private-data"]), ("raw", "SECRET")):
            changed = copy.deepcopy(report)
            changed["scanner_signals"]["records"][0][field] = value
            with self.assertRaises(InputError):
                validate(changed)
