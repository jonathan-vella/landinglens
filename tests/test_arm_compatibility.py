import copy
import json
import tempfile
import unittest
from pathlib import Path

from alz_assessor.arm import API_VERSIONS, PLANNED_API_VERSIONS, Expressions, arm_source
from alz_assessor.terraform import InputError

SUB = "/subscriptions/00000000-0000-0000-0000-000000000001"
GROUP = SUB + "/resourceGroups/rg-test"


class ArmCompatibilityTests(unittest.TestCase):
    def evaluate(self, value, variables=None, parameters=None):
        return Expressions(
            {"variables": variables or {}, "parameters": parameters or {}}, {}, GROUP
        ).value(value)

    def bundle(self, resources, *, scope=SUB, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "template.json"
            path.write_text(json.dumps({"resources": resources, **kwargs}), encoding="utf-8")
            return arm_source(path, scope=scope)

    def deployment(self, body, group="rg-test", parameters=None):
        return {
            "type": "Microsoft.Resources/deployments",
            "apiVersion": "2025-04-01",
            "name": "local-module",
            "resourceGroup": group,
            "properties": {
                "expressionEvaluationOptions": {"scope": "inner"},
                "template": body,
                "parameters": parameters or {},
            },
        }

    def storage(self, name="storage", secure=True):
        return {
            "type": "Microsoft.Storage/storageAccounts",
            "apiVersion": "2023-05-01",
            "name": name,
            "properties": {"supportsHttpsTrafficOnly": secure, "minimumTlsVersion": "TLS1_2"},
        }

    def test_variable_and_property_copies_preserve_outer_indices(self):
        context = Expressions(
            {
                "variables": {
                    "copy": [
                        {
                            "name": "names",
                            "count": 2,
                            "input": "[format('hub-{0}', copyIndex('names', 2))]",
                        }
                    ]
                }
            },
            {},
            GROUP,
        )
        context.index = 7
        self.assertEqual(context.value("[variables('names')]"), ["hub-2", "hub-3"])
        self.assertEqual(
            context.value(
                {
                    "copy": [
                        {
                            "name": "value",
                            "count": 2,
                            "input": "[createArray(copyIndex(), copyIndex('value'))]",
                        }
                    ]
                }
            ),
            {"value": [[7, 0], [7, 1]]},
        )
        self.assertEqual(context.indices, {})
        self.assertIn("unknown", context.value("[copyIndex('value')]"))

    def test_copy_bounds_cycles_and_malformed_shapes(self):
        for count in (257, -1, True, "[reference('remote')]"):
            with self.subTest(count=count):
                self.assertIn(
                    "unknown",
                    self.evaluate(
                        "[variables('x')]",
                        {
                            "copy": [{"name": "x", "count": count, "input": 1}],
                        },
                    ),
                )
        self.assertIn(
            "unknown",
            self.evaluate(
                "[variables('x')]",
                {
                    "copy": [{"name": "x", "count": 1, "input": "[variables('x')]"}],
                },
            )[0],
        )
        for variables in (
            {"copy": {}},
            {"copy": [{"name": "x"}, {"name": "x"}]},
            {"x": [], "copy": [{"name": "x"}]},
        ):
            with self.subTest(variables=variables), self.assertRaises(InputError):
                self.evaluate("[variables('x')]", variables)
        self.assertIn("unknown", self.evaluate({"copy": [{"count": 1}]}))

    def test_lambda_map_filter_reduce_and_nested_scope(self):
        self.assertEqual(
            self.evaluate(
                "[map(createArray(2, 3), lambda('x', 'i', createArray(lambdaVariables('x'), "
                "lambdaVariables('i'))))]"
            ),
            [[2, 0], [3, 1]],
        )
        self.assertEqual(
            self.evaluate(
                "[filter(createArray(1, 2), lambda('x', equals(lambdaVariables('x'), 2)))]"
            ),
            [2],
        )
        self.assertEqual(
            self.evaluate(
                "[reduce(createArray(createObject('a', 1), createObject('b', 2)), "
                "createObject(), lambda('cur', 'next', union(lambdaVariables('cur'), "
                "lambdaVariables('next'))))]"
            ),
            {"a": 1, "b": 2},
        )
        self.assertEqual(
            self.evaluate(
                "[map(createArray(1, 2), lambda('x', map(createArray(3), "
                "lambda('x', lambdaVariables('x')))))]"
            ),
            [[3], [3]],
        )
        self.assertIn("unknown", self.evaluate("[lambdaVariables('x')]"))
        for expression in (
            "[map(createArray(1), lambda('x', 'x', lambdaVariables('x')))]",
            "[filter(createArray(1), lambda('x', reference('runtime')))]",
            "[map(pickZones('Microsoft.Network', 'azureFirewalls', 'west', 3), "
            "lambda('x', lambdaVariables('x')))]",
        ):
            self.assertIn("unknown", self.evaluate(expression))

    def test_null_safe_access_does_not_hide_unknowns(self):
        self.assertIn("unknown", self.evaluate("[coalesce()]"))
        self.assertIn(
            "unknown",
            self.evaluate(
                "[variables('x')]",
                {
                    "copy": [{"name": "x", "count": 1}],
                },
            ),
        )
        self.assertIsNone(self.evaluate("[tryGet(null(), 'name')]"))
        self.assertEqual(
            self.evaluate("[coalesce(tryGet(null(), 'name'), 'fallback')]"), "fallback"
        )
        self.assertIn("unknown", self.evaluate("[coalesce(reference('runtime'), 'fallback')]"))
        self.assertIsNone(
            self.evaluate(
                "[parameters('optional')]",
                parameters={
                    "optional": {"type": "object", "nullable": True},
                },
            )
        )
        self.assertIn(
            "unknown",
            self.evaluate(
                "[parameters('required')]",
                parameters={
                    "required": {"type": "object"},
                },
            ),
        )
        self.assertIn(
            "unknown",
            self.evaluate(
                "[parameters('secret')]",
                parameters={
                    "secret": {"type": "secureObject", "defaultValue": {"sensitive": "withheld"}},
                },
            ),
        )
        with self.assertRaises(InputError):
            self.evaluate("", parameters={"invalid": {"nullable": "true"}})

    def test_null_uses_only_declared_nonnullable_defaults(self):
        context = Expressions(
            {
                "parameters": {
                    "name": {"type": "string", "defaultValue": "[format('peer-{0}', 'west')]"},
                    "optional": {"type": "string", "nullable": True},
                    "required": {"type": "string"},
                },
            },
            {"name": None, "optional": None, "required": None},
            GROUP,
        )
        self.assertEqual(context.value("[parameters('name')]"), "peer-west")
        self.assertIsNone(context.value("[parameters('optional')]"))
        self.assertIn("unknown", context.value("[parameters('required')]"))
        self.assertIn("unknown", context.value("[format('name-{0}', null())]"))

    def test_resource_id_overload_and_pure_network_address(self):
        self.assertEqual(
            self.evaluate(
                "[resourceId(subscription().subscriptionId, 'rg-remote', "
                "'Microsoft.Network/virtualNetworks', 'remote')]"
            ),
            SUB.lower()
            + "/resourcegroups/rg-remote/providers/microsoft.network/virtualnetworks/remote",
        )
        self.assertEqual(self.evaluate("[cidrHost('10.40.0.0/26', 3)]"), "10.40.0.3")
        self.assertIn("unknown", self.evaluate("[cidrHost('10.40.0.1/26', 3)]"))
        self.assertIn("unknown", self.evaluate("[cidrHost('10.40.0.0/26', 64)]"))
        self.assertEqual(self.evaluate("[indexOf(createArray('West', 'North'), 'North')]"), 1)
        self.assertEqual(self.evaluate("[indexOf(createArray('West'), 'west')]"), -1)

    def test_local_outputs_are_scoped_and_runtime_reference_is_unknown(self):
        producer = {
            "parameters": {"name": {"type": "string"}},
            "resources": {},
            "outputs": {
                "name": {"type": "string", "value": "[parameters('name')]"},
                "runtime": {"type": "string", "value": "[reference('external').customerId]"},
            },
        }
        resources = {
            "consumer": self.deployment(
                {
                    "parameters": {"name": {"type": "string"}},
                    "resources": {"storage": self.storage("[parameters('name')]")},
                },
                "rg-consumer",
                {"name": {"value": "[reference('producer').outputs.name.value]"}},
            ),
            "producer": self.deployment(producer, "rg-producer", {"name": {"value": "derived"}}),
        }
        bundle = self.bundle(resources)
        self.assertEqual(len(bundle["resources"]), 1)
        self.assertEqual(
            bundle["resources"][0]["arm_id"],
            SUB.lower() + "/resourcegroups/rg-consumer/providers/"
            "microsoft.storage/storageaccounts/derived",
        )
        resources["consumer"]["properties"]["parameters"]["name"]["value"] = (
            "[reference('producer').outputs.runtime.value]"
        )
        self.assertIsNone(self.bundle(resources)["resources"][0]["arm_id"])
        resources["producer"]["condition"] = False
        self.assertIsNone(self.bundle(resources)["resources"][0]["arm_id"])

    def test_conditional_copied_modules_do_not_use_first_instance_condition(self):
        deployment = self.deployment(
            {
                "parameters": {"name": {"type": "string"}},
                "resources": {"storage": self.storage("[parameters('name')]")},
            },
            parameters={"name": {"value": "[format('storage-{0}', copyIndex())]"}},
        )
        deployment["copy"] = {"name": "modules", "count": 2}
        deployment["condition"] = "[equals(copyIndex(), 1)]"
        bundle = self.bundle({"modules": deployment})
        self.assertEqual(len(bundle["resources"]), 1)
        self.assertTrue(bundle["resources"][0]["arm_id"].endswith("/storage-1"))

    def test_duplicate_projected_declarations_and_conflicts_are_explicit(self):
        first = self.deployment({"resources": [self.storage()]})
        bundle = self.bundle({"first": first, "second": copy.deepcopy(first)})
        self.assertEqual(len(bundle["resources"]), 1)
        self.assertEqual(bundle["resources"][0]["state"], "known")
        self.assertEqual(
            bundle["diagnostics"][-1]["reason"], "equivalent_projected_resource_declarations"
        )
        second = self.deployment({"resources": [self.storage(secure=False)]})
        bundle = self.bundle({"first": first, "second": second})
        self.assertEqual(bundle["resources"][0]["state"], "unknown")
        self.assertEqual(bundle["resources"][0]["properties"], {})
        self.assertEqual(bundle["diagnostics"][-1]["reason"], "conflicting_resource_declarations")

    def test_duplicate_identity_within_one_template_remains_invalid(self):
        resources = [self.storage(), self.storage()]
        with self.assertRaisesRegex(InputError, "Duplicate or ambiguous"):
            self.bundle(resources, scope=GROUP)
        with self.assertRaisesRegex(InputError, "Duplicate or ambiguous"):
            self.bundle({"module": self.deployment({"resources": resources})})
        with self.assertRaisesRegex(InputError, "Duplicate or ambiguous"):
            self.bundle(
                {
                    "first": self.deployment({"resources": [self.storage()]}),
                    "second": self.deployment({"resources": resources}),
                }
            )

    def test_unreviewed_api_remains_unknown(self):
        workspace = {
            "type": "Microsoft.OperationalInsights/workspaces",
            "apiVersion": "2099-01-01",
            "name": "workspace",
            "properties": {"retentionInDays": 90},
        }
        row = self.bundle({"module": self.deployment({"resources": [workspace]})})["resources"][0]
        self.assertEqual(row["state"], "unknown")
        self.assertEqual(row["properties"], {})

    def test_offline_api_support_does_not_change_observed_allowlists(self):
        for kind, version in (
            ("microsoft.network/virtualnetworks/virtualnetworkpeerings", "2024-01-01"),
            ("microsoft.network/routetables", "2024-07-01"),
            ("microsoft.network/azurefirewalls", "2024-10-01"),
            ("microsoft.network/firewallpolicies", "2024-10-01"),
        ):
            self.assertEqual(API_VERSIONS[kind], {"2024-05-01"})
            self.assertIn(version, PLANNED_API_VERSIONS[kind])

    def test_reviewed_workspace_perimeter_and_sku_boundaries(self):
        workspace = {
            "type": "Microsoft.OperationalInsights/workspaces",
            "apiVersion": "2025-07-01",
            "name": "workspace",
            "properties": {
                "sku": {"name": "Unlimited"},
                "retentionInDays": 90,
                "publicNetworkAccessForIngestion": "SecuredByPerimeter",
                "publicNetworkAccessForQuery": "Enabled",
            },
        }
        row = self.bundle({"module": self.deployment({"resources": [workspace]})})["resources"][0]
        facts = row["properties"]["logWorkspaceSummary"]
        self.assertEqual(facts["retentionInDays"], 90)
        self.assertIn("unknown", facts["sku"])
        self.assertIn("unknown", facts["publicNetworkAccessForIngestion"])
        self.assertEqual(facts["publicNetworkAccessForQuery"], "Enabled")

    def test_step_budget_remains_enforced(self):
        self.assertIn("unknown", self.evaluate("[split('" + "x/" * 257 + "', '/')]"))
        context = Expressions({}, {}, GROUP)
        context.steps = 10_000
        self.assertIn("unknown", context.value("[createArray()]"))

    def test_secure_and_unresolved_local_type_references_are_withheld(self):
        for definitions in (
            {"secret": {"type": "secureObject"}},
            {"secret": {"$ref": "#/definitions/secret"}},
        ):
            context = Expressions(
                {
                    "definitions": definitions,
                    "parameters": {"secret": {"$ref": "#/definitions/secret"}},
                },
                {"secret": {"name": "never-retained"}},
                GROUP,
            )
            result = context.value("[parameters('secret')]")
            self.assertIn("unknown", result)
            self.assertNotIn("never-retained", json.dumps(result))

    def test_module_reference_cycles_and_wrong_versions_remain_unknown(self):
        child = {
            "parameters": {"name": {"type": "string"}},
            "resources": {"storage": self.storage("[parameters('name')]")},
            "outputs": {"name": {"type": "string", "value": "[parameters('name')]"}},
        }
        resources = {
            "a": self.deployment(
                child,
                parameters={
                    "name": {"value": "[reference('b').outputs.name.value]"},
                },
            ),
            "b": self.deployment(
                child,
                "rg-other",
                {
                    "name": {"value": "[reference('a').outputs.name.value]"},
                },
            ),
        }
        bundle = self.bundle(resources)
        self.assertTrue(all(row["arm_id"] is None for row in bundle["resources"]))
        resources["b"]["properties"]["parameters"]["name"]["value"] = "known"
        resources["a"]["properties"]["parameters"]["name"]["value"] = (
            "[reference('b', '2099-01-01').outputs.name.value]"
        )
        bundle = self.bundle(resources)
        self.assertIsNone(bundle["resources"][0]["arm_id"])

    def test_empty_nested_deployment_expansion_is_globally_bounded(self):
        body = {"resources": {}}
        for _ in range(4):
            module = self.deployment(body)
            module["copy"] = {"name": "modules", "count": 256}
            body = {"resources": {"modules": module}}
        bundle = self.bundle(body["resources"])
        self.assertFalse(bundle["inventory_complete"])
        self.assertIn("arm_instance_limit", {row["reason"] for row in bundle["diagnostics"]})


if __name__ == "__main__":
    unittest.main()
