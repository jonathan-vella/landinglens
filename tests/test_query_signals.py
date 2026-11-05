import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from alz_assessor.azure import ARG_URL, HttpTransport, Response, ResponseLimitError
from alz_assessor.catalog import load_catalog
from alz_assessor.comparison import compare
from alz_assessor.engine import assess
from alz_assessor.query_signals import execute_query, load_allowlist, selected_query
from alz_assessor.replay import export_bundle, replay_bundle, semantic
from alz_assessor.reports import render
from alz_assessor.reviews import prepare_reviews
from alz_assessor.terraform import InputError

AT = "2026-11-05T00:00:00Z"
SUB = "00000000-0000-0000-0000-000000000001"
GUID = "e9c8f584-6d5e-473b-8dc5-acc9fbaab4e3"
RESOURCE = (
    "/subscriptions/"
    + SUB
    + "/resourceGroups/private-fixture/providers/Microsoft.Network/firewallPolicies/policy"
)


class QuerySignalTests(unittest.TestCase):
    def setUp(self):
        self.catalog = load_catalog()

    def response(self, rows, token=None, truncated=False, total=None):
        return Response(
            200,
            {
                "data": rows,
                "count": len(rows),
                "totalRecords": len(rows) if total is None else total,
                "resultTruncated": truncated,
                **({"$skipToken": token} if token else {}),
            },
            {},
        )

    def collect(self, rows=None):
        response = self.response([{"id": RESOURCE, "compliant": True}] if rows is None else rows)
        return execute_query(Mock(return_value=response), GUID, [SUB], at=AT)

    def row(self, report):
        return next(row for row in report["results"] if row["upstream_id"] == "D07.06")

    def test_exact_review_membership_hashes_and_exclusion_reasons(self):
        allowlist = load_allowlist()
        self.assertEqual(len(allowlist["queries"]), 49)
        self.assertEqual(sum(row["allowed"] for row in allowlist["queries"]), 2)
        for row in allowlist["queries"]:
            self.assertTrue(row["rationale"])
            self.assertTrue(row["permission_profile"])
            if row["allowed"]:
                self.assertEqual(
                    hashlib.sha256(row["query"].encode()).hexdigest(), row["query_sha256"]
                )
                self.assertEqual(
                    row["expected_columns"],
                    {"id": "canonical-arm-id", "compliant": "boolean-or-null"},
                )
            else:
                self.assertIsNone(row["query"])
        for value in ("unknown", "0390417d-53dc-44d9-b3f4-c8832f359b41"):
            transport = Mock()
            with self.assertRaisesRegex(InputError, "allowlisted"):
                execute_query(transport, value, [SUB])
            transport.assert_not_called()
        with self.assertRaisesRegex(InputError, "allowlisted"):
            selected_query(GUID, selected_query(GUID)["query"] + " ")

    def test_scope_and_transport_exact_body_queries_and_options(self):
        calls = []

        def transport(method, url, body):
            calls.append((method, url, body))
            self.assertEqual((method, url), ("POST", ARG_URL))
            self.assertEqual(body["subscriptions"], [SUB])
            self.assertEqual(body["query"], selected_query(GUID)["query"])
            self.assertEqual(body["options"]["resultFormat"], "objectArray")
            return self.response(
                [
                    {
                        "id": RESOURCE,
                        "compliant": True,
                        "tags": {"secret": "PRIVATE-NOT-FOR-REPORTING"},
                    }
                ]
            )

        bundle = execute_query(transport, GUID, [SUB], at=AT)
        self.assertEqual(len(calls), 1)
        self.assertFalse(bundle["inventory_complete"])
        self.assertNotIn("PRIVATE-NOT-FOR-REPORTING", json.dumps(bundle))
        for scope in ([], [SUB, SUB], [None], ["name"], [SUB] * 101):
            with self.assertRaises(InputError):
                execute_query(Mock(), GUID, scope)
        transport = Mock()
        with patch("urllib.request.build_opener", return_value=transport):
            with self.assertRaisesRegex(InputError, "exact reviewed query"):
                HttpTransport("not-a-real-token")(
                    "POST",
                    ARG_URL,
                    {
                        "subscriptions": [SUB],
                        "query": "resources | project secrets",
                        "options": {"$top": 1000, "resultFormat": "objectArray"},
                    },
                )
        transport.open.assert_not_called()

    def test_both_booleans_unknowns_empty_and_no_configuration_pass(self):
        for value, tier in (
            (True, "signal"),
            (False, "signal"),
            (None, "needs_decision"),
            ("true", "needs_decision"),
            ({}, "needs_decision"),
        ):
            bundle = self.collect([{"id": RESOURCE, "compliant": value}])
            report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
            self.assertEqual(self.row(report)["observed"]["outcome"], "unknown")
            self.assertEqual(self.row(report)["observed"]["evidence_tier"], tier)
        report = assess(self.collect([]), self.catalog, at=AT, evidence_tiers=True)
        self.assertEqual(report["query_signals"]["records"], [])
        self.assertEqual(self.row(report)["observed"]["outcome"], "unknown")

    def test_paging_retries_partial_denials_and_conflicting_records(self):
        response = [
            Response(429, {}, {"Retry-After": "100"}),
            self.response(
                [{"id": RESOURCE, "compliant": True}], token="next", truncated=True, total=2
            ),
            self.response([{"id": RESOURCE + "2", "compliant": False}], total=2),
        ]
        sleep = Mock()
        transport = Mock(side_effect=response)
        bundle = execute_query(transport, GUID, [SUB], at=AT, sleep=sleep)
        self.assertEqual(len(bundle["metadata"]["query_evidence"]["records"]), 2)
        self.assertEqual(transport.call_args_list[-1].args[2]["options"]["$skipToken"], "next")
        sleep.assert_called_once_with(30.0)
        for bad in (Response(403, {}, {}), Response(500, {}, {})):
            bundle = execute_query(Mock(return_value=bad), GUID, [SUB], at=AT, sleep=Mock())
            self.assertTrue(bundle["metadata"]["query_evidence"]["partial"])
            self.assertTrue(bundle["diagnostics"])
        bundle = execute_query(Mock(side_effect=ResponseLimitError()), GUID, [SUB], at=AT)
        self.assertEqual(bundle["diagnostics"][0]["reason"], "response_byte_limit")
        bundle = execute_query(
            Mock(
                return_value=self.response(
                    [{"id": RESOURCE, "compliant": True}], truncated=True, total=2
                )
            ),
            GUID,
            [SUB],
            at=AT,
        )
        report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        self.assertIs(report["query_signals"]["records"][0]["usable"], False)
        bundle = self.collect(
            [{"id": RESOURCE, "compliant": True}, {"id": RESOURCE, "compliant": False}]
        )
        self.assertTrue(bundle["metadata"]["query_evidence"]["records"][0]["conflicted"])

    def test_foreign_malformed_wrong_type_and_token_guards(self):
        for response in (
            self.response(
                [
                    {
                        "id": RESOURCE.replace(SUB, "00000000-0000-0000-0000-000000000002"),
                        "compliant": True,
                    }
                ]
            ),
            self.response(
                [{"id": RESOURCE.replace("firewallPolicies", "azureFirewalls"), "compliant": True}]
            ),
            self.response([{"id": "name", "compliant": True}]),
            Response(
                200, {"data": [], "count": True, "totalRecords": 0, "resultTruncated": False}, {}
            ),
            Response(200, {"data": [], "count": 0, "totalRecords": 0, "resultTruncated": 1}, {}),
        ):
            with self.assertRaises(InputError):
                execute_query(Mock(return_value=response), GUID, [SUB], at=AT)
        bundle = execute_query(
            Mock(return_value=self.response([], token="repeated", truncated=True)),
            GUID,
            [SUB],
            at=AT,
        )
        self.assertTrue(bundle["metadata"]["query_evidence"]["partial"])
        self.assertIn("invalid_or_repeated_continuation", str(bundle["diagnostics"]))

    def test_stale_compare_review_replay_report_privacy_and_installed_saved_cli(self):
        bundle = self.collect()
        report = assess(bundle, self.catalog, at=AT, evidence_tiers=True)
        prepared = prepare_reviews(report, self.catalog, ["D07.06"], bundle["scope"])
        self.assertIsNone(prepared["entries"][0]["outcome"])
        self.assertEqual(prepared["entries"][0]["preparation"]["query_signals"]["guid"], GUID)
        planned = assess(
            {**bundle, "mode": "planned", "metadata": {}}, self.catalog, at=AT, evidence_tiers=True
        )
        compared = compare(planned, report, at="2026-11-07T00:00:00Z")
        self.assertEqual(self.row(compared)["observed"]["evidence_tier"], "needs_decision")
        self.assertEqual(self.row(compared)["comparison"], "not_comparable")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
                export_bundle(root / "replay", bundle, self.catalog, at=AT, evidence_tiers=True)
                self.assertEqual(semantic(replay_bundle(root / "replay")), semantic(report))
            source = root / "evidence.json"
            source.write_text(json.dumps(bundle), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "alz_assessor.cli",
                    "assess",
                    str(source),
                    "--input",
                    "evidence",
                    "--at",
                    AT,
                    "--evidence-tiers",
                ],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(self.row(json.loads(result.stdout))["observed"]["outcome"], "unknown")
        for format in ("json", "markdown", "html"):
            self.assertNotIn("private-fixture", render(report, format, minimize=True))
        changed = copy.deepcopy(bundle)
        changed["metadata"]["query_evidence"]["query_sha256"] = "0" * 64
        with self.assertRaisesRegex(InputError, "hash differs"):
            assess(changed, self.catalog, at=AT, evidence_tiers=True)
