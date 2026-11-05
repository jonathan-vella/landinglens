import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from alz_assessor.azure import Collector, Response
from alz_assessor.catalog import load_catalog
from alz_assessor.comparison import compare
from alz_assessor.contracts import document, validate
from alz_assessor.engine import assess
from alz_assessor.policy_evidence import import_policy_export
from alz_assessor.replay import export_bundle, replay_bundle, semantic
from alz_assessor.reports import render
from alz_assessor.reviews import prepare_reviews
from alz_assessor.terraform import InputError

AT = "2026-11-05T00:00:00Z"
SUB = "00000000-0000-0000-0000-000000000001"
SCOPE = "/subscriptions/" + SUB
RESOURCE = (
    SCOPE + "/resourceGroups/private-fixture/providers/Microsoft.Storage/storageAccounts/store"
)
ASSIGNMENT = SCOPE + "/providers/Microsoft.Authorization/policyAssignments/private-assignment"
DEFINITION = (
    "/providers/Microsoft.Authorization/policyDefinitions/404c3081-a854-4457-ae30-26a93ef643f9"
)


class PolicyEvidenceTests(unittest.TestCase):
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
            "kind": "policy-export",
            "scope": SCOPE,
            "collected_at": AT,
            "assignments": [
                {
                    "id": ASSIGNMENT,
                    "properties": {
                        "scope": SCOPE,
                        "policyDefinitionId": DEFINITION,
                        "notScopes": [],
                        "parameters": {"secret": {"value": "PRIVATE-NOT-FOR-REPORTING"}},
                        "enforcementMode": "Default",
                    },
                }
            ],
            "states": [
                {
                    "resourceId": RESOURCE,
                    "policyAssignmentId": ASSIGNMENT,
                    "policyDefinitionId": DEFINITION,
                    "timestamp": AT,
                    "complianceState": "Compliant",
                    "policyDefinitionReferenceId": "PRIVATE-NOT-FOR-REPORTING",
                    "description": "PRIVATE-NOT-FOR-REPORTING",
                }
            ],
            "exemptions": [],
        }

    def assess(self, export=None):
        bundle = import_policy_export(self.bundle, self.export if export is None else export)
        return assess(bundle, self.catalog, at=AT, evidence_tiers=True)

    def row(self, report):
        return next(r for r in report["results"] if r["upstream_id"] == "G04.01")

    def test_compliant_and_noncompliant_are_signals_never_predicate_outcomes(self):
        for state in ("Compliant", "NonCompliant"):
            export = copy.deepcopy(self.export)
            export["states"][0]["complianceState"] = state
            report = self.assess(export)
            record = report["policy_signals"]["records"][0]
            self.assertIs(record["usable"], True)
            self.assertEqual(record["compliance_state"], state)
            self.assertEqual(record["mapping_strength"], "partial")
            self.assertEqual(self.row(report)["observed"]["outcome"], "unknown")
            self.assertEqual(self.row(report)["observed"]["evidence_tier"], "signal")
            self.assertFalse(report["coverage"]["inventory_complete"])
            self.assertEqual(sum(report["evidence_tiers"]["counts"].values()), 255)

    def test_assignment_alone_and_empty_evaluations_do_not_imply_compliance(self):
        export = copy.deepcopy(self.export)
        export["states"] = []
        report = self.assess(export)
        self.assertNotIn("policy_signals", report)
        self.assertEqual(self.row(report)["observed"]["evidence_tier"], "needs_decision")
        export["assignments"] = []
        export["states"] = self.export["states"]
        report = self.assess(export)
        self.assertIs(report["policy_signals"]["records"][0]["usable"], False)
        self.assertEqual(self.row(report)["observed"]["outcome"], "unknown")

    def test_original_evaluation_time_is_not_refreshed_by_import_collection_time(self):
        for value in ("2000-01-01T00:00:00Z", "2099-01-01T00:00:00Z", None, {}, "bad"):
            export = copy.deepcopy(self.export)
            export["states"][0]["timestamp"] = value
            report = self.assess(export)
            record = report["policy_signals"]["records"][0]
            self.assertIs(record["usable"], False)
            self.assertEqual(
                record["evaluated_at"], value if isinstance(value, str) and value != "bad" else None
            )
            self.assertEqual(self.row(report)["observed"]["evidence_tier"], "needs_decision")

    def test_duplicates_conflicts_and_unresolved_initiatives_never_select_a_pass(self):
        for population in ("assignments", "states"):
            export = copy.deepcopy(self.export)
            export[population].append(copy.deepcopy(export[population][0]))
            self.assertEqual(len(self.assess(export)["policy_signals"]["records"]), 1)
            if population == "states":
                export["states"][1]["complianceState"] = "NonCompliant"
            else:
                export["assignments"][1]["properties"]["notScopes"] = [RESOURCE]
            report = self.assess(export)
            self.assertIs(report["policy_signals"]["records"][0]["usable"], False)
        export = copy.deepcopy(self.export)
        export["assignments"][0]["properties"]["policyDefinitionId"] = (
            SCOPE + "/providers/Microsoft.Authorization/policySetDefinitions/initiative"
        )
        record = self.assess(export)["policy_signals"]["records"][0]
        self.assertIn("initiative_or_definition_relationship_unresolved", record["flags"])
        self.assertIs(record["usable"], False)

    def test_excluded_wrong_type_unsupported_and_unknown_records_remain_unusable(self):
        for update in (
            {"complianceState": "Exempt"},
            {"complianceState": {}},
            {
                "resourceId": RESOURCE.replace(
                    "Microsoft.Storage/storageAccounts", "Microsoft.KeyVault/vaults"
                )
            },
        ):
            export = copy.deepcopy(self.export)
            export["states"][0].update(update)
            record = self.assess(export)["policy_signals"]["records"][0]
            self.assertIs(record["usable"], False)
        export = copy.deepcopy(self.export)
        export["assignments"][0]["properties"]["notScopes"] = [RESOURCE]
        self.assertIn(
            "resource_excluded_by_assignment",
            self.assess(export)["policy_signals"]["records"][0]["flags"],
        )
        export["assignments"][0]["properties"].pop("notScopes")
        self.assertIn(
            "assignment_exclusions_unresolved",
            self.assess(export)["policy_signals"]["records"][0]["flags"],
        )
        export = copy.deepcopy(self.export)
        export["states"][0]["policyDefinitionId"] = DEFINITION.replace("404c3081", "00000000")
        report = self.assess(export)
        self.assertEqual(report["policy_signals"]["records"], [])
        self.assertIn("policy_definition_not_mapped", str(report["policy_signals"]["gaps"]))

    def test_export_scope_version_shape_and_replacement_guards(self):
        for field, value in (
            ("scope", SCOPE.replace(SUB, "00000000-0000-0000-0000-000000000002")),
            ("schema_version", "1.1"),
            ("states", {}),
            ("states", [None]),
            ("exemptions", [{}]),
            ("assignments", [{}]),
        ):
            export = copy.deepcopy(self.export)
            export[field] = value
            with self.assertRaises(InputError):
                import_policy_export(self.bundle, export)
        export = copy.deepcopy(self.export)
        export["states"][0]["resourceId"] = RESOURCE.replace(
            SUB, "00000000-0000-0000-0000-000000000002"
        )
        with self.assertRaisesRegex(InputError, "outside"):
            import_policy_export(self.bundle, export)
        with self.assertRaisesRegex(InputError, "observed"):
            import_policy_export({**self.bundle, "mode": "planned"}, self.export)
        imported = import_policy_export(self.bundle, self.export)
        with self.assertRaisesRegex(InputError, "replaced"):
            import_policy_export(imported, self.export)
        export = copy.deepcopy(self.export)
        export["states"] *= 10001
        with self.assertRaisesRegex(InputError, "10,000"):
            import_policy_export(self.bundle, export)

    def test_privacy_reports_review_and_replay_keep_typed_provenance(self):
        bundle = import_policy_export(self.bundle, self.export)
        self.assertNotIn("PRIVATE-NOT-FOR-REPORTING", json.dumps(bundle))
        report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        for format in ("json", "markdown", "html"):
            full = render(report, format)
            self.assertIn("Compliant", full)
            minimized = render(report, format, minimize=True)
            self.assertNotIn("private-fixture", minimized)
            self.assertNotIn("private-assignment", minimized)
            self.assertNotIn("PRIVATE-NOT-FOR-REPORTING", full)
        prepared = prepare_reviews(report, self.catalog, ["G04.01"], SCOPE)
        self.assertIsNone(prepared["entries"][0]["outcome"])
        self.assertIs(prepared["entries"][0]["preparation"]["policy_signals"][0]["usable"], True)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "replay"
            with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
                export_bundle(path, bundle, self.catalog, at=AT, evidence_tiers=True)
                self.assertEqual(semantic(replay_bundle(path)), semantic(report))
            for file in path.iterdir():
                self.assertNotIn("PRIVATE-NOT-FOR-REPORTING", file.read_text("utf-8"))

    def test_comparison_refreshes_policy_age_independently_of_resource_collection(self):
        export = copy.deepcopy(self.export)
        export["states"][0]["timestamp"] = "2026-11-04T01:00:00Z"
        bundle = import_policy_export(self.bundle, export)
        observed = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        planned = assess(
            {**self.bundle, "mode": "planned"}, self.catalog, at=AT, evidence_tiers=True
        )
        compared = compare(planned, observed, at="2026-11-05T02:00:00Z")
        self.assertEqual(self.row(compared)["observed"]["outcome"], "unknown")
        self.assertEqual(self.row(compared)["observed"]["evidence_tier"], "needs_decision")
        self.assertIs(compared["policy_signals"]["records"][0]["usable"], False)
        self.assertEqual(self.row(compared)["comparison"], "not_comparable")

    def test_injected_existing_collector_path_stays_read_only_and_denied_facts_unknown(self):
        calls = []

        def transport(method, url):
            calls.append((method, url))
            if "/resources?" in url:
                return Response(
                    200,
                    {"value": [{"id": RESOURCE, "type": "Microsoft.Storage/storageAccounts"}]},
                    {},
                )
            if "/storageaccounts/" in url.lower():
                return Response(403, {}, {})
            if "/policyAssignments?" in url:
                return Response(200, {"value": self.export["assignments"]}, {})
            if "/queryResults?" in url:
                self.assertEqual(method, "POST")
                return Response(200, {"value": self.export["states"]}, {})
            if "/policyDefinitions/404c" in url:
                return Response(200, {"id": DEFINITION, "properties": {"policyRule": {}}}, {})
            return Response(200, {"value": []}, {})

        with patch("alz_assessor.azure.now", return_value=AT):
            bundle = Collector(transport).collect(subscriptions=[SUB])
        report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        self.assertEqual(self.row(report)["observed"]["outcome"], "unknown")
        self.assertEqual(self.row(report)["observed"]["evidence_tier"], "signal")
        self.assertTrue(all(method in ("GET", "POST") for method, _ in calls))
        self.assertTrue(all("/queryResults?" in url for method, url in calls if method == "POST"))
        self.assertFalse(any("triggerEvaluation" in url for _, url in calls))

    def test_contract_guards_and_installed_cli_saved_export(self):
        report = self.assess()
        for field, value in (("usable", "true"), ("compliance_state", "pass"), ("raw", "PRIVATE")):
            changed = copy.deepcopy(report)
            changed["policy_signals"]["records"][0][field] = value
            with self.assertRaises(InputError):
                validate(changed)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            evidence, export = root / "evidence.json", root / "policy.json"
            evidence.write_text(json.dumps(self.bundle), encoding="utf-8")
            export.write_text(json.dumps(self.export), encoding="utf-8")
            command = [
                sys.executable,
                "-m",
                "alz_assessor.cli",
                "assess",
                str(evidence),
                "--input",
                "evidence",
                "--policy-evidence",
                str(export),
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
