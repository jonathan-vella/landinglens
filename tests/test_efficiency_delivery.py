import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from alz_assessor.arm import arm_source
from alz_assessor.azure import Response
from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import control_digest
from alz_assessor.engine import assess
from alz_assessor.interviews import compile_interview, prepare_interview
from alz_assessor.policy_evidence import import_policy_export
from alz_assessor.query_signals import execute_query
from alz_assessor.replay import export_bundle, replay_bundle, semantic
from alz_assessor.reports import render, render_xlsx
from alz_assessor.scanner_evidence import import_scanner

AT = "2026-11-05T00:00:00Z"
SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/delivery"
STORAGE = SCOPE + "/providers/Microsoft.Storage/storageAccounts/store"
DEFINITION = (
    "/providers/Microsoft.Authorization/policyDefinitions/404c3081-a854-4457-ae30-26a93ef643f9"
)
ASSIGNMENT = SCOPE + "/providers/Microsoft.Authorization/policyAssignments/authored"
SENTINEL = "PRIVATE-NOT-FOR-REPORTING"


def template():
    return {
        "resources": [
            {
                "type": "Microsoft.Storage/storageAccounts",
                "name": "store",
                "apiVersion": "2023-05-01",
                "properties": {
                    "supportsHttpsTrafficOnly": False,
                    "minimumTlsVersion": "TLS1_2",
                    "credentials": SENTINEL,
                },
            },
            {
                "type": "Microsoft.Storage/storageAccounts/blobServices",
                "name": "store/default",
                "apiVersion": "2023-05-01",
                "properties": {"containerDeleteRetentionPolicy": {"enabled": True}},
            },
            {
                "type": "Microsoft.KeyVault/vaults",
                "name": "vault",
                "apiVersion": "2024-11-01",
                "properties": {
                    "enableSoftDelete": True,
                    "enablePurgeProtection": False,
                    "enableRbacAuthorization": True,
                    "publicNetworkAccess": "Disabled",
                    "networkAcls": {"defaultAction": "Deny"},
                },
            },
            {
                "type": "Microsoft.Network/firewallPolicies",
                "name": "policy",
                "apiVersion": "2024-05-01",
                "properties": {
                    "sku": {"tier": "Premium"},
                    "dnsSettings": {"enableProxy": True},
                    "threatIntelMode": "Deny",
                    "intrusionDetection": {"mode": "Alert"},
                },
            },
            {
                "type": "Microsoft.Network/azureFirewalls",
                "name": "firewall",
                "apiVersion": "2024-05-01",
                "properties": {
                    "sku": {"tier": "Premium", "name": "AZFW_VNet"},
                    "ipConfigurations": [],
                },
            },
        ]
    }


def observed_with_signals(root, catalog):
    source = root / "authored.json"
    source.write_text(json.dumps(template()), encoding="utf-8")
    planned = arm_source(source, scope=SCOPE)
    planned["collected_at"] = AT
    observed = copy.deepcopy(planned)
    observed.update(mode="observed", source="saved", inventory_complete=False)
    observed = import_policy_export(
        observed,
        {
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
                        "parameters": {"secret": {"value": SENTINEL}},
                    },
                }
            ],
            "states": [
                {
                    "resourceId": STORAGE,
                    "policyAssignmentId": ASSIGNMENT,
                    "policyDefinitionId": DEFINITION,
                    "complianceState": "Compliant",
                    "timestamp": AT,
                }
            ],
            "exemptions": [],
        },
    )
    observed = import_scanner(
        observed,
        {
            "schema_version": "1.0",
            "kind": "scanner-export",
            "format": "psrule-json",
            "scope": SCOPE,
            "mode": "observed",
            "evaluated_at": AT,
            "complete": True,
            "scanner": {
                "name": "PSRule.Rules.Azure",
                "version": "1.48.0-B0228",
                "baseline": "Azure.GA",
            },
            "artifact_hashes": {"authored-input": "0" * 64},
            "identities": [{"index": 0, "arm_id": STORAGE}],
            "output": [
                {
                    "ruleName": "Azure.Storage.SecureTransfer",
                    "ref": "AZR-000196",
                    "outcome": "Pass",
                    "info": {"moduleName": "PSRule.Rules.Azure"},
                    "detail": {"secret": SENTINEL},
                }
            ],
        },
        catalog,
    )
    return planned, observed


class EfficiencyDeliveryTests(unittest.TestCase):
    def test_installed_authored_evidence_reuse_reviews_replay_and_every_export(self):
        catalog = load_catalog()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            planned, observed = observed_with_signals(root, catalog)
            report = assess(observed, catalog, at=AT, evidence_tiers=True)
            self.assertEqual(len({row["control_id"] for row in report["results"]}), 255)
            self.assertEqual(sum(report["evidence_tiers"]["counts"].values()), 255)
            self.assertEqual(report["evidence_tiers"]["counts"]["verified"], 7)
            storage = next(row for row in report["results"] if row["upstream_id"] == "G04.01")
            self.assertEqual(storage["observed"]["outcome"], "fail")
            self.assertEqual(
                report["policy_signals"]["records"][0]["compliance_state"], "Compliant"
            )
            self.assertEqual(report["scanner_signals"]["records"][0]["status"], "Pass")
            self.assertFalse(report["coverage"]["inventory_complete"])
            response = prepare_interview(report, catalog, "private-service-paths", SCOPE)
            response.update(
                answer="Authored fixture paths are unproven.",
                reviewer="Fixture reviewer",
                rationale="No live evidence claimed.",
                evidence="authored://efficiency-delivery",
                valid_from=AT,
                valid_until="2026-11-06T00:00:00Z",
            )
            for entry in response["decisions"]:
                entry["outcome"] = "unknown"
            manual = compile_interview(response, catalog, at=AT)
            reviewed = assess(observed, catalog, at=AT, evidence_tiers=True, manual=manual)
            export_bundle(
                root / "replay", observed, catalog, at=AT, evidence_tiers=True, manual=manual
            )
            self.assertEqual(semantic(replay_bundle(root / "replay")), semantic(reviewed))
            for format in ("json", "markdown", "html", "sarif", "pr-summary", "csv"):
                output = render(reviewed, format, minimize=True)
                self.assertNotIn(SENTINEL, output)
                self.assertNotIn(SCOPE, output)
            self.assertTrue(render_xlsx(reviewed, minimize=True).startswith(b"PK"))
            evidence = root / "observed.json"
            evidence.write_text(json.dumps(observed), encoding="utf-8")
            assessment = root / "assessment.json"
            command = [sys.executable, "-m", "alz_assessor.cli"]
            for args in (
                ["doctor", str(evidence), "--input", "evidence"],
                ["catalog", "crosswalk", "validate"],
                [
                    "assess",
                    str(evidence),
                    "--input",
                    "evidence",
                    "--at",
                    AT,
                    "--evidence-tiers",
                    "--output",
                    str(assessment),
                ],
            ):
                result = subprocess.run(
                    [*command, *args], cwd=root, capture_output=True, text=True, timeout=30
                )
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                json.loads(assessment.read_text())["evidence_tiers"]["counts"],
                report["evidence_tiers"]["counts"],
            )
            self.assertEqual(planned["mode"], "planned")

    def test_query_signals_and_fixed_baseline_hashes_remain_independent(self):
        catalog = load_catalog()
        guid = "e9c8f584-6d5e-473b-8dc5-acc9fbaab4e3"
        subscription = SCOPE.split("/")[2]
        bundle = execute_query(
            lambda *args: Response(
                200,
                {
                    "data": [
                        {
                            "id": SCOPE + "/providers/Microsoft.Network/firewallPolicies/policy",
                            "compliant": True,
                        }
                    ],
                    "count": 1,
                    "totalRecords": 1,
                    "resultTruncated": False,
                },
                {},
            ),
            guid,
            [subscription],
            at=AT,
        )
        report = assess(bundle, catalog, at=AT, evidence_tiers=True)
        row = next(row for row in report["results"] if row["upstream_id"] == "D07.06")
        self.assertEqual(row["observed"]["outcome"], "unknown")
        self.assertEqual(
            report["evidence_tiers"]["counts"],
            {"verified": 0, "signal": 1, "needs_decision": 211, "manual": 43},
        )
        repository = Path(__file__).parents[1]
        targets = json.loads(
            (repository / "references/recommendation-batches/targets.json").read_text()
        )
        controls = {control["control_id"]: control for control in catalog["controls"]}
        for identity, expected in targets["preserved_automated"].items():
            self.assertEqual(control_digest(controls[identity]), expected)
        ledger = json.loads(
            (repository / "references/recommendation-batches/ledger.json").read_text()
        )
        self.assertEqual(len(ledger["recommendations"]), 251)
        self.assertEqual(
            {row["batch"] for row in ledger["recommendations"] if row["status"] == "merged"},
            {"01", "17", "18"} | ({"19"} if "19" in ledger["deliveries"] else set()),
        )
        for row in ledger["recommendations"]:
            if row["status"] == "merged":
                receipt = ledger["deliveries"][row["batch"]]
                self.assertEqual(
                    (row["pr"], row["merge_commit"]), (receipt["pr"], receipt["merge_commit"])
                )
            elif row["batch"] == "19":
                self.assertEqual(row["status"], "implementation-in-progress")
                self.assertIsNone(row["merge_commit"])
            else:
                self.assertEqual(row["status"], "pending")
                self.assertIsNone(row["merge_commit"])
