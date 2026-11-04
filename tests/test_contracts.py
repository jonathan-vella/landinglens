import unittest

from alz_assessor.contracts import (
    apply_identity_map,
    canonical_id,
    derive_id,
    digest,
    document,
    scope_id,
    validate,
)
from alz_assessor.terraform import InputError

SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/test"


def evidence(mode="planned", resources=None, complete=True):
    return document(
        "evidence",
        mode=mode,
        source="arm",
        collected_at="2026-11-04T00:00:00+00:00",
        scope=SCOPE,
        artifact_hashes={"fixture": digest("fixture")},
        diagnostics=[],
        inventory_complete=complete,
        resources=resources or [],
    )


def resource(identity=None, state="known"):
    return {
        "logical_id": "module.child[0].azurerm_storage_account.test",
        "resource_type": "Microsoft.Storage/storageAccounts",
        "properties": {},
        "source_location": "fixture.tf:1",
        "arm_id": identity,
        "state": state,
        "reason": "" if state == "known" else state,
    }


class ContractTests(unittest.TestCase):
    def test_scoped_identity_child_resources_and_case(self):
        first = derive_id(SCOPE, "Microsoft.Storage/storageAccounts", "test")
        self.assertEqual(canonical_id(first.upper()), first)
        second = derive_id(
            SCOPE.replace("test", "other"), "Microsoft.Storage/storageAccounts", "test"
        )
        self.assertNotEqual(first, second)
        child = derive_id(SCOPE, "Microsoft.Storage/storageAccounts/blobServices", "test/default")
        self.assertTrue(child.endswith("/storageaccounts/test/blobservices/default"))
        self.assertIsNone(derive_id(None, "Microsoft.Storage/storageAccounts", "test"))
        self.assertIsNone(
            derive_id(SCOPE, "Microsoft.Storage/storageAccounts/blobServices", "default")
        )
        with self.assertRaises(InputError):
            canonical_id("test")
        with self.assertRaises(InputError):
            scope_id(
                "/providers/Microsoft.Management/managementGroups/test"
                "/providers/Microsoft.Authorization/policyAssignments/test"
            )

    def test_states_are_distinct_and_absence_requires_completeness(self):
        identity = derive_id(SCOPE, "Microsoft.Storage/storageAccounts", "test")
        for state in ("unknown", "inaccessible", "error", "absent"):
            item = evidence(resources=[resource(identity, state)])
            self.assertEqual(validate(item)["resources"][0]["state"], state)
        with self.assertRaisesRegex(InputError, "complete inventory"):
            validate(evidence(resources=[resource(identity, "absent")], complete=False))

    def test_identity_maps_bind_artifacts_and_reject_duplicates_conflicts(self):
        identity = derive_id(SCOPE, "Microsoft.Storage/storageAccounts", "test")
        bundle = evidence(resources=[resource()])
        entry = {"logical_id": resource()["logical_id"], "arm_id": identity, "scope": SCOPE}
        mapping = document(
            "identity-map", artifact_hashes=bundle["artifact_hashes"], entries=[entry]
        )
        self.assertEqual(apply_identity_map(bundle, mapping)["resources"][0]["arm_id"], identity)
        mapping["entries"].append(entry)
        with self.assertRaisesRegex(InputError, "Duplicate"):
            validate(mapping)
        mapping["entries"] = [entry]
        mapping["artifact_hashes"] = {"other": digest("other")}
        with self.assertRaisesRegex(InputError, "hashes"):
            apply_identity_map(bundle, mapping)
        mapping["artifact_hashes"] = bundle["artifact_hashes"]
        bundle["resources"][0]["arm_id"] = identity.replace("/test", "/other")
        with self.assertRaisesRegex(InputError, "conflicts"):
            apply_identity_map(bundle, mapping)
        bundle["resources"][0]["arm_id"] = None
        mapping["entries"][0]["arm_id"] = derive_id(
            SCOPE, "Microsoft.Network/firewallPolicies", "test"
        )
        with self.assertRaisesRegex(InputError, "resource type"):
            apply_identity_map(bundle, mapping)

    def test_all_contracts_positive_negative_version_and_required_fields(self):
        control = {
            "control_id": "test",
            "design_area": "Security",
            "automation": "manual",
            "applicability": ["platform", "application"],
            "recommendation": "review",
            "method": "manual",
            "rationale": "review",
            "lifecycle": "active",
            "references": [],
            "evidence_requirements": ["review"],
            "baseline": "microsoft-recommendation",
        }
        entry = {
            "control_id": "test",
            "scope": SCOPE,
            "rationale": "reviewed",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
            "outcome": "manual",
            "evidence": "review://record",
            "disposition": "accepted",
        }
        fixtures = [
            evidence(),
            document(
                "catalog", catalog_version="test", design_areas=["Security"], controls=[control]
            ),
            document("manual", entries=[entry]),
            document("exceptions", entries=[entry]),
            document("identity-map", artifact_hashes={"x": digest("x")}, entries=[]),
            document(
                "assessment",
                catalog_version="test",
                coverage={},
                evidence=[evidence()],
                generated_at="2026-11-04T00:00:00Z",
                results=[
                    {
                        "control_id": "test",
                        "logical_id": "scope",
                        "design_area": "Security",
                        "recommendation": "review",
                        "applicability": ["platform"],
                        "planned": {
                            "outcome": "manual",
                            "reason": "review",
                            "evidence_links": [],
                            "freshness": "current",
                        },
                    }
                ],
            ),
        ]
        for fixture in fixtures:
            with self.subTest(kind=fixture["kind"]):
                self.assertEqual(validate(fixture), fixture)
                required = {
                    "evidence": "resources",
                    "catalog": "controls",
                    "manual": "entries",
                    "exceptions": "entries",
                    "identity-map": "entries",
                    "assessment": "results",
                }
                missing = dict(fixture)
                missing.pop(required[fixture["kind"]])
                with self.assertRaises(InputError):
                    validate(missing)
                fixture["schema_version"] = "999"
                with self.assertRaises(InputError):
                    validate(fixture)
        with self.assertRaises(InputError):
            validate(document("manual", entries=[{"control_id": "incomplete"}]))


if __name__ == "__main__":
    unittest.main()
