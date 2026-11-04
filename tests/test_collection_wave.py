import contextlib
import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import test_collection as baseline

from alz_assessor.azure import (
    ARG_QUERY,
    ARG_URL,
    Collector,
    HttpTransport,
    Response,
    ResponseLimitError,
)
from alz_assessor.catalog import load_catalog
from alz_assessor.cli import main
from alz_assessor.engine import assess
from alz_assessor.terraform import InputError

SUB, SCOPE, STORAGE = baseline.SUB, baseline.SCOPE, baseline.RESOURCE
FIREWALL = (
    SCOPE + "/resourceGroups/rg-management/providers/Microsoft.Network/firewallPolicies/policy"
)


def graph(rows, total=None, token=None, truncated="false"):
    body = {
        "data": rows,
        "count": len(rows),
        "totalRecords": len(rows) if total is None else total,
        "resultTruncated": truncated,
    }
    if token is not None:
        body["$skipToken"] = token
    return Response(200, body, {})


class CollectionWaveTests(unittest.TestCase):
    def setUp(self):
        self.old = baseline.CollectionTests(
            "test_inventory_authorization_and_transport_failure_are_explicit",
        )

    def detail(self, method, url):
        if "/firewallPolicies/" in url:
            return Response(
                200,
                {
                    "id": FIREWALL,
                    "properties": {
                        "sku": {"tier": "Premium"},
                        "threatIntelMode": "Deny",
                        "intrusionDetection": {"mode": "Alert", "secret": "PRIVATE-sentinel"},
                        "dnsSettings": {"enableProxy": False},
                        "secret": "PRIVATE-sentinel",
                    },
                },
                {},
            )
        return self.old.transport(method, url)

    def test_arg_explicit_request_scope_paging_and_first_wave_detail_fields(self):
        calls = []

        def transport(method, url, body=None):
            if url == ARG_URL:
                self.assertEqual(method, "POST")
                calls.append(copy.deepcopy(body))
                if len(calls) == 1:
                    return graph(
                        [{"id": STORAGE, "type": "Microsoft.Storage/storageAccounts"}],
                        total=2,
                        token="opaque-next",
                        truncated="true",
                    )
                return graph(
                    [{"id": FIREWALL, "type": "Microsoft.Network/firewallPolicies"}], total=2
                )
            self.assertIsNone(body)
            self.assertNotIn("/resources?", url)
            return self.detail(method, url)

        bundle = Collector(transport).collect(
            subscriptions=[SUB],
            resource_graph=True,
            inventory_authorized=True,
        )
        self.assertTrue(bundle["inventory_complete"])
        self.assertEqual(len(bundle["resources"]), 2)
        self.assertEqual(calls[0]["subscriptions"], [SUB])
        self.assertEqual(calls[0]["query"], ARG_QUERY)
        self.assertEqual(calls[1]["options"]["$skipToken"], "opaque-next")
        firewall = next(r for r in bundle["resources"] if r["arm_id"] == FIREWALL.lower())
        self.assertEqual(firewall["properties"]["sku"]["tier"], "Premium")
        self.assertEqual(firewall["properties"]["threatIntelMode"], "Deny")
        self.assertEqual(firewall["properties"]["intrusionDetection"]["mode"], "Alert")
        self.assertNotIn("PRIVATE-sentinel", json.dumps(bundle))
        self.assertEqual(
            bundle["metadata"]["policy_compliance"][0]["timestamp"], "2000-01-01T00:00:00Z"
        )
        self.assertIn("eventually consistent", bundle["metadata"]["arg_warning"])
        report = assess(bundle, load_catalog())
        for control, expected in (("D07.06", "pass"), ("D07.07", "fail")):
            row = next(r for r in report["results"] if r["upstream_id"] == control)
            self.assertEqual(row["observed"]["outcome"], expected)
        self.assertEqual(
            next(r for r in report["results"] if r["upstream_id"] == "G04.01")["observed"][
                "outcome"
            ],
            "pass",
        )

    def test_truncation_denial_repeated_tokens_and_stale_saved_evidence(self):
        row = {"id": STORAGE, "type": "Microsoft.Storage/storageAccounts"}
        cases = [
            graph([row], total=2, truncated="true"),
            Response(403, {}, {}),
            graph([], token="repeated", truncated="true"),
        ]
        for reply in cases:

            def transport(method, url, body=None, reply=reply):
                return reply if url == ARG_URL else self.detail(method, url)

            bundle = Collector(transport).collect(
                subscriptions=[SUB],
                resource_graph=True,
                inventory_authorized=True,
            )
            self.assertFalse(bundle["inventory_complete"])
            self.assertTrue(bundle["diagnostics"])
            bundle["collected_at"] = "2000-01-01T00:00:00Z"
            report = assess(bundle, load_catalog())
            self.assertFalse(
                any(
                    row["observed"]["outcome"] == "pass"
                    for row in report["results"]
                    if row["automation"] == "automated"
                )
            )

    def test_arg_wrong_scope_schema_and_bounded_throttling(self):
        foreign = STORAGE.replace(SUB, "00000000-0000-0000-0000-000000000002")
        for reply in (
            graph([{"id": foreign, "type": "Microsoft.Storage/storageAccounts"}]),
            Response(200, {"data": [], "count": 0, "totalRecords": 0, "resultTruncated": 0}, {}),
        ):
            collector = Collector(lambda method, url, body=None, reply=reply: reply)
            with self.assertRaises(InputError):
                collector.graph_inventory([SCOPE])
        calls, sleeps = [], []

        def throttled(method, url, body=None):
            calls.append(body)
            return Response(429, {}, {"Retry-After": "1000"}) if len(calls) == 1 else graph([])

        collector = Collector(throttled, sleep=sleeps.append)
        self.assertEqual(collector.graph_inventory([SCOPE]), [])
        self.assertEqual(sleeps, [30])
        self.assertEqual(len(calls), 2)
        self.assertTrue(collector.facets["inventory"])
        self.assertEqual(Collector(throttled).graph_inventory([]), [])

    def test_http_transport_accepts_only_reviewed_arg_body_and_does_not_authenticate(self):
        body = {
            "subscriptions": [SUB],
            "query": ARG_QUERY,
            "options": {"$top": 1000, "resultFormat": "objectArray"},
        }
        transport = HttpTransport("fixture-token-not-real")
        invalid = [
            None,
            {**body, "query": "resources | project properties"},
            {**body, "subscriptions": []},
            {**body, "subscriptions": [False]},
            {**body, "options": {**body["options"], "allowPartialScopes": True}},
        ]
        with patch.object(transport.opener, "open", side_effect=AssertionError("network")):
            for value in invalid:
                with self.assertRaises(InputError):
                    transport("POST", ARG_URL, value)
            with self.assertRaises(InputError):
                transport("POST", "https://management.azure.com/triggerEvaluation", body)
        with patch.object(transport.opener, "open") as opened:
            response = opened.return_value.__enter__.return_value
            response.read.return_value = b'{"data":[]}'
            response.status, response.headers = 200, {}
            transport("POST", ARG_URL, body)
            request = opened.call_args.args[0]
            self.assertEqual(json.loads(request.data), body)
            self.assertEqual(request.full_url, ARG_URL)

    def test_hierarchy_bounds_child_group_policies_and_filtered_exemptions(self):
        selected = "/providers/Microsoft.Management/managementGroups/parent"
        child = selected.replace("/parent", "/child")
        foreign = "/subscriptions/00000000-0000-0000-0000-000000000002"
        calls = []

        def transport(method, url, body=None):
            calls.append(url)
            if "/descendants?" in url:
                return baseline.response(
                    [
                        {"id": child, "properties": {"parent": {"id": selected}}},
                        {"id": SCOPE, "properties": {"parent": {"id": child}}},
                        {
                            "id": foreign,
                            "properties": {
                                "parent": {
                                    "id": selected.replace("/parent", "/unverified"),
                                }
                            },
                        },
                    ]
                )
            return self.detail(method, url)

        bundle = Collector(transport).collect(management_group="parent", inventory_authorized=True)
        self.assertEqual(bundle["metadata"]["scopes"], [SCOPE])
        self.assertFalse(bundle["inventory_complete"])
        self.assertTrue(any("managementgroups/child/providers/" in url for url in calls))
        self.assertFalse(any(foreign in url for url in calls))
        exemptions = [
            url for url in calls if "managementgroups/" in url and "/policyExemptions?" in url
        ]
        self.assertTrue(exemptions)
        self.assertTrue(all("&$filter=atScope()" in url for url in exemptions))

    def test_definition_associations_hash_values_and_never_read_parent_scope(self):
        initiative = "/providers/Microsoft.Authorization/policySetDefinitions/set"
        definition = "/providers/Microsoft.Authorization/policyDefinitions/test"
        calls = []

        def transport(method, url, body=None):
            calls.append(url)
            if "policySetDefinitions" in url:
                return Response(
                    200,
                    {
                        "id": initiative,
                        "properties": {
                            "policyDefinitions": [
                                {
                                    "policyDefinitionId": definition,
                                    "policyDefinitionReferenceId": "PRIVATE-sentinel",
                                    "parameters": {"secret": {"value": "PRIVATE-sentinel"}},
                                }
                            ]
                        },
                    },
                    {},
                )
            return self.detail(method, url)

        collector = Collector(transport)
        definitions, initiatives = {}, {}
        collector.definition(initiative, [SCOPE], definitions, initiatives)
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(definitions), 1)
        self.assertEqual(initiatives[initiative.lower()]["members"][0]["definition_id"], definition)
        self.assertNotIn("PRIVATE-sentinel", json.dumps(initiatives))
        outside = (
            "/providers/Microsoft.Management/managementGroups/outside"
            "/providers/Microsoft.Authorization/policyDefinitions/custom"
        )
        collector.definition(outside, [SCOPE], definitions, initiatives)
        self.assertEqual(len(calls), 2)
        self.assertFalse(collector.facets["definitions"])
        self.assertIn("outside_requested_scope", collector.diagnostics[-1]["reason"])

    def test_paging_version_conflicts_and_collection_state_reset(self):
        url = "https://management.azure.com/test?api-version=1"
        collector = Collector(
            lambda method, url: baseline.response(
                nextLink=url.replace("api-version=1", "api-version=2"),
            )
        )
        collector.pages("GET", url, "inventory")
        self.assertFalse(collector.facets["inventory"])
        collector = Collector(self.detail)
        first = collector.collect(subscriptions=[SUB])
        self.assertFalse(first["inventory_complete"])
        second = collector.collect(subscriptions=[SUB], inventory_authorized=True)
        self.assertTrue(second["inventory_complete"])
        self.assertFalse(
            any(d["reason"] == "authorization_coverage_not_attested" for d in second["diagnostics"])
        )

    def test_conflicts_bounds_and_large_responses_remain_explicit(self):
        def transport(method, url, body=None):
            reply = self.detail(method, url)
            if "/policyAssignments?" in url and "&$filter=atScope()" in url:
                reply.body["value"][0]["properties"]["enforcementMode"] = "DoNotEnforce"
            return reply

        bundle = Collector(transport).collect(subscriptions=[SUB])
        self.assertFalse(bundle["metadata"]["completeness"]["assignments"])
        self.assertEqual(
            bundle["metadata"]["policy_assignments"][0],
            {"id": baseline.ASSIGNMENT, "conflict": True},
        )
        with patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("network")):
            collector = Collector(self.detail)
            definition = "/providers/Microsoft.Authorization/policyDefinitions/test"
            collector.definition(definition, [SCOPE], {}, {}, depth=16)
            self.assertFalse(collector.facets["definitions"])
        initiative = "/providers/Microsoft.Authorization/policySetDefinitions/set"

        def member_transport(method, url, body=None):
            return Response(
                200,
                {
                    "id": initiative,
                    "properties": {
                        "policyDefinitions": [
                            {
                                "policyDefinitionId": definition,
                            }
                        ]
                    },
                },
                {},
            )

        collector = Collector(member_transport)
        collector.definition_members = 10_000
        initiatives = {}
        collector.definition(initiative, [SCOPE], {}, initiatives)
        self.assertEqual(collector.definition_members, 10_000)
        self.assertFalse(initiatives[initiative.lower()]["members_complete"])
        self.assertEqual(collector.diagnostics[0]["reason"], "definition_member_limit")
        definitions = {str(index): {} for index in range(1000)}
        collector = Collector(member_transport)
        collector.definition(definition, [SCOPE], definitions, {})
        self.assertEqual(len(definitions), 1000)
        self.assertEqual(collector.diagnostics[0]["reason"], "definition_limit")

        def oversized(method, url):
            raise ResponseLimitError()

        collector = Collector(oversized)
        self.assertIsNone(
            collector.request("GET", "https://management.azure.com/test", "configuration")
        )
        self.assertEqual(collector.diagnostics[0]["reason"], "response_byte_limit")

    def test_installed_collection_and_saved_assessment_workflow(self):
        def transport(method, url, body=None):
            return (
                graph([{"id": STORAGE, "type": "Microsoft.Storage/storageAccounts"}])
                if url == ARG_URL
                else self.detail(method, url)
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "observed.json"
            stderr = io.StringIO()
            with (
                patch(
                    "sys.argv",
                    [
                        "alz-assessor",
                        "collect",
                        "--subscription",
                        SUB,
                        "--resource-graph",
                        "--output",
                        str(output),
                    ],
                ),
                patch.dict(os.environ, {"LANDINGLENS_ARM_TOKEN": "fixture-not-real"}),
                patch("alz_assessor.cli.HttpTransport", return_value=transport),
                contextlib.redirect_stderr(stderr),
            ):
                self.assertEqual(main(), 0)
            self.assertIn("partial", stderr.getvalue())
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "alz_assessor.cli",
                    "assess",
                    str(output),
                    "--input",
                    "evidence",
                ],
                cwd=root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=60,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["coverage"]["controls"], 255)
            self.assertFalse(report["coverage"]["inventory_complete"])
