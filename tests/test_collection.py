import json
import unittest
from unittest.mock import Mock, patch

from alz_assessor.azure import Collector, HttpTransport, Response, TransportError, safe_url
from alz_assessor.catalog import load_catalog
from alz_assessor.engine import assess
from alz_assessor.terraform import InputError

SUB = "00000000-0000-0000-0000-000000000001"
SCOPE = "/subscriptions/" + SUB
RESOURCE = SCOPE + "/resourceGroups/rg-management/providers/Microsoft.Storage/storageAccounts/logs"
ASSIGNMENT = (
    "/providers/Microsoft.Management/managementGroups/parent"
    "/providers/Microsoft.Authorization/policyAssignments/test"
)


def response(value=None, **extra):
    return Response(200, {"value": value or [], **extra}, {})


class CollectionTests(unittest.TestCase):
    def test_inventory_authorization_and_transport_failure_are_explicit(self):
        partial = Collector(self.transport).collect(subscriptions=[SUB])
        self.assertFalse(partial["inventory_complete"])
        self.assertTrue(
            any(
                item["reason"] == "authorization_coverage_not_attested"
                for item in partial["diagnostics"]
            )
        )
        complete = Collector(self.transport).collect(subscriptions=[SUB], inventory_authorized=True)
        self.assertTrue(complete["inventory_complete"])
        failed = Collector(Mock(side_effect=TransportError())).collect(
            subscriptions=[SUB], inventory_authorized=True
        )
        self.assertFalse(failed["inventory_complete"])
        self.assertTrue(
            all(item["reason"] == "transport_unavailable" for item in failed["diagnostics"])
        )

    def transport(self, method, url):
        if "/blobservices/default?" in url:
            return Response(
                200,
                {"id": RESOURCE + "/blobServices/default", "properties": {}},
                {},
            )
        if "/descendants?" in url:
            return response(
                [
                    {
                        "id": SCOPE,
                        "properties": {
                            "parent": {
                                "id": "/providers/Microsoft.Management/managementGroups/parent",
                            }
                        },
                    }
                ]
            )
        if "/resources?" in url:
            return response([{"id": RESOURCE, "type": "Microsoft.Storage/storageAccounts"}])
        if "/storageAccounts/" in url:
            return Response(
                200,
                {
                    "id": RESOURCE,
                    "properties": {
                        "supportsHttpsTrafficOnly": True,
                        "accessKeys": "must-not-export",
                        "connectionString": "must-not-export",
                    },
                },
                {},
            )
        if "/policyAssignments?" in url:
            return response(
                [
                    {
                        "id": ASSIGNMENT,
                        "properties": {
                            "scope": "/providers/Microsoft.Management/managementGroups/parent",
                            "policyDefinitionId": (
                                "/providers/Microsoft.Authorization/policyDefinitions/test"
                            ),
                            "parameters": {"hidden": {"value": "must-not-export"}},
                            "notScopes": [SCOPE + "/resourceGroups/excluded"],
                        },
                    }
                ]
            )
        if "/policyExemptions?" in url:
            return response(
                [
                    {
                        "id": SCOPE + "/providers/Microsoft.Authorization/policyExemptions/expired",
                        "properties": {
                            "expiresOn": "2000-01-01T00:00:00Z",
                            "policyAssignmentId": ASSIGNMENT,
                        },
                    }
                ]
            )
        if "/policyDefinitions?" in url or "/policySetDefinitions?" in url:
            return response()
        if "/policyDefinitions/test?" in url:
            return Response(
                200,
                {
                    "id": "/providers/Microsoft.Authorization/policyDefinitions/test",
                    "properties": {"policyRule": {"then": {"effect": "Audit"}}},
                },
                {},
            )
        if "/queryResults?" in url:
            self.assertEqual(method, "POST")
            return response(
                [
                    {
                        "resourceId": RESOURCE,
                        "policyAssignmentId": ASSIGNMENT,
                        "complianceState": "NonCompliant",
                        "timestamp": "2000-01-01T00:00:00Z",
                    }
                ]
            )
        self.fail("Unexpected request: " + method + " " + url)

    def test_saved_mocked_scope_policy_inheritance_expiry_and_configuration_are_distinct(self):
        transport = Mock(side_effect=self.transport)
        bundle = Collector(transport).collect(subscriptions=[SUB], inventory_authorized=True)
        self.assertTrue(bundle["inventory_complete"])
        self.assertTrue(bundle["metadata"]["run_complete"])
        self.assertEqual(len(bundle["metadata"]["policy_assignments"]), 1)
        self.assertEqual(
            bundle["metadata"]["policy_assignments"][0]["not_scopes"],
            [
                SCOPE + "/resourceGroups/excluded",
            ],
        )
        self.assertTrue(bundle["metadata"]["policy_exemptions"][0]["expired"])
        self.assertEqual(
            bundle["metadata"]["policy_compliance"][0]["timestamp"], "2000-01-01T00:00:00Z"
        )
        self.assertNotIn("must-not-export", json.dumps(bundle))
        report = assess(bundle, load_catalog())
        storage = next(row for row in report["results"] if row["upstream_id"] == "G04.01")
        self.assertEqual(storage["observed"]["outcome"], "pass")
        governance = [row for row in report["results"] if row["design_area"] == "Governance"]
        self.assertTrue(all(row["observed"]["outcome"] == "manual" for row in governance))
        self.assertTrue(all(call.args[0] in {"GET", "POST"} for call in transport.call_args_list))

    def test_pagination_throttling_and_retry_bounds(self):
        sleeps = []
        calls = 0

        def transport(method, url):
            nonlocal calls
            calls += 1
            if calls == 1:
                return Response(429, {}, {"Retry-After": "1000"})
            if calls == 2:
                return response([{"id": "a"}], nextLink=url + "&page=2")
            return response([{"id": "b"}])

        collector = Collector(transport, sleep=sleeps.append)
        result = collector.pages(
            "GET", "https://management.azure.com/test?api-version=1", "inventory"
        )
        self.assertEqual([row["id"] for row in result], ["a", "b"])
        self.assertEqual(sleeps, [30])
        denied = Collector(lambda method, url: Response(503, {}, {}), sleep=sleeps.append)
        self.assertEqual(denied.pages("GET", "https://management.azure.com/test", "inventory"), [])
        self.assertFalse(denied.facets["inventory"])
        self.assertEqual(denied.diagnostics[0]["reason"], "http_503")

    def test_denied_inventory_unknown_and_denied_properties_inaccessible(self):
        def denied_inventory(method, url):
            return Response(403, {}, {}) if "/resources?" in url else self.transport(method, url)

        bundle = Collector(denied_inventory).collect(subscriptions=[SUB])
        self.assertFalse(bundle["inventory_complete"])
        report = assess(bundle, load_catalog())
        self.assertTrue(
            all(
                row["observed"]["outcome"] == "unknown"
                for row in report["results"]
                if row["automation"] == "automated"
            )
        )

        def denied_properties(method, url):
            return (
                Response(403, {}, {}) if "/storageAccounts/" in url else self.transport(method, url)
            )

        bundle = Collector(denied_properties).collect(subscriptions=[SUB])
        self.assertEqual(bundle["resources"][0]["state"], "inaccessible")
        self.assertFalse(bundle["metadata"]["run_complete"])
        report = assess(bundle, load_catalog())
        self.assertEqual(
            next(row for row in report["results"] if row["upstream_id"] == "G04.01")["observed"][
                "outcome"
            ],
            "unknown",
        )

    def test_management_group_relationships_and_partial_descendants(self):
        bundle = Collector(self.transport).collect(management_group="parent")
        self.assertEqual(bundle["metadata"]["scopes"], [SCOPE])
        self.assertEqual(
            bundle["metadata"]["relationships"][0]["parent"],
            "/providers/microsoft.management/managementgroups/parent",
        )

        def partial(method, url):
            return Response(403, {}, {}) if "/descendants?" in url else response()

        bundle = Collector(partial).collect(management_group="parent")
        self.assertFalse(bundle["inventory_complete"])

    def test_stale_saved_evidence_never_passes_and_no_implicit_scope_or_authentication(self):
        bundle = Collector(self.transport).collect(subscriptions=[SUB])
        bundle["collected_at"] = "2000-01-01T00:00:00Z"
        report = assess(bundle, load_catalog())
        self.assertEqual(
            next(row for row in report["results"] if row["upstream_id"] == "G04.01")["observed"][
                "reason"
            ],
            "stale_evidence",
        )
        with self.assertRaises(InputError):
            Collector(self.transport).collect()
        with self.assertRaises(InputError):
            Collector(self.transport).collect(subscriptions=[SUB], management_group="parent")
        with self.assertRaises(InputError):
            HttpTransport("")
        with patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("network")):
            with self.assertRaises(InputError):
                HttpTransport("fake-fixture-only")("POST", "https://management.azure.com/deploy")

    def test_external_redirects_and_cyclic_or_cross_scope_paging_rejected(self):
        for url in (
            "http://management.azure.com/a",
            "https://evil.invalid/a",
            "https://management.azure.com@evil.invalid/a",
        ):
            with self.assertRaises(InputError):
                safe_url(url)
        url = "https://management.azure.com/test"
        collector = Collector(lambda method, requested: response(nextLink=url))
        self.assertEqual(collector.pages("GET", url, "inventory"), [])
        self.assertFalse(collector.facets["inventory"])


if __name__ == "__main__":
    unittest.main()
