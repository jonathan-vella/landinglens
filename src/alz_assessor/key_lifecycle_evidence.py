"""Minimized key-management context, never renewal, effective access or sovereignty proof."""

from typing import Any

from .policy_strategy_evidence import ASSIGNMENT, DEFINITION, INITIATIVE, ROLE
from .policy_strategy_evidence import configuration_context as policy_context
from .policy_strategy_evidence import unique_known as policy_unique
from .sources import boolean, enumeration, property_at, unknown

GUIDS = {
    "b86ad884-08e3-4727-94b8-75ba18f20459",
    "01365d38-e43f-49cc-ad86-8266abca264f",
    "6d70ba6c-97be-4995-8904-83845c986cb2",
    "913156a1-2476-4e49-b541-acdce979377b",
    "b12308ca-5017-4f15-9e3a-b3693829e7e3",
    "16183687-a047-47a2-8994-5bda43334f24",
    "b48ade7f-50be-4d2e-9866-d57b17942fc2",
    "25d62688-6d70-4ba6-a97b-e99519048384",
}
VAULT = "microsoft.keyvault/vaults"
STORAGE = "microsoft.storage/storageaccounts"
POLICY_GUID = "b12308ca-5017-4f15-9e3a-b3693829e7e3"
PATHS = {"storageEncryptionSummary"}
FACTS = {
    VAULT: {"enableRbacAuthorization", "publicNetworkAccess"},
    STORAGE: PATHS,
    DEFINITION: {"policyDefinitionSummary"},
    INITIATIVE: {"policyInitiativeSummary"},
    ASSIGNMENT: {"policyAssignmentSummary"},
    ROLE: {"principalType", "roleDefinitionId"},
}
WARNING = (
    "Partial original-time configuration only, not public-CA renewal, key rotation, updated "
    "consumers, effective delegation/Policy enforcement, complete coverage, Zero Trust maturity, "
    "rehearsed incident response, CMK necessity, BYOK compatibility or sovereignty assurance. "
    "Key Vault and Managed HSM are distinct. No key/certificate/secret/URI/issuer/principal/"
    "incident payload retained; no operational action or live read."
)


def resource_paths(kind: str) -> set[str]:
    return FACTS.get(kind.lower(), set())


def encryption_facts(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("storage_encryption_not_explicit")
    return {
        "keySource": enumeration(
            value.get("keySource"), ("Microsoft.Storage", "Microsoft.Keyvault")
        ),
        "requireInfrastructureEncryption": boolean(value.get("requireInfrastructureEncryption")),
        "queueKeyType": enumeration(value.get("queueKeyType"), ("Service", "Account")),
        "tableKeyType": enumeration(value.get("tableKeyType"), ("Service", "Account")),
    }


def review_fact(values: dict[str, Any], path: str) -> Any:
    return encryption_facts(values.get(path))


def projected_properties(
    kind: str, values: dict[str, Any], *, terraform: bool = False
) -> dict[str, Any]:
    if kind.lower() != STORAGE:
        return {}
    if terraform:
        # A separate CMK resource can override the account. Neither block presence nor
        # absence establishes the final key source; private key references are withheld.
        facts = {
            "keySource": unknown(
                "terraform_account_key_source_requires_separate_cmk_reconciliation"
            ),
            "requireInfrastructureEncryption": values.get("infrastructure_encryption_enabled"),
            "queueKeyType": values.get("queue_encryption_key_type"),
            "tableKeyType": values.get("table_encryption_key_type"),
        }
    else:
        encryption = values.get("encryption")
        facts = {
            "keySource": property_at(encryption, "keySource"),
            "requireInfrastructureEncryption": property_at(
                encryption, "requireInfrastructureEncryption"
            ),
            "queueKeyType": property_at(encryption, "services.queue.keyType"),
            "tableKeyType": property_at(encryption, "services.table.keyType"),
        }
    return {"storageEncryptionSummary": encryption_facts(facts)}


def replay_properties(kind: str, values: dict[str, Any]) -> dict[str, Any]:
    return (
        {"storageEncryptionSummary": encryption_facts(values["storageEncryptionSummary"])}
        if kind.lower() == STORAGE and "storageEncryptionSummary" in values
        else {}
    )


def minimized_evidence(bundle: dict[str, Any]) -> dict[str, Any]:
    from .replay import sanitize_evidence

    relevant = [row for row in bundle["resources"] if row["resource_type"].lower() in FACTS]
    projected = iter(sanitize_evidence({**bundle, "resources": relevant})["resources"])
    resources = []
    for row in bundle["resources"]:
        if row["resource_type"].lower() in FACTS:
            safe = next(projected)["properties"]
            resources.append(
                {
                    **row,
                    "properties": {
                        key: value for key, value in safe.items() if key in row["properties"]
                    },
                }
            )
        else:
            resources.append(row)
    return {
        **bundle,
        "resources": resources,
    }


def configuration_context(
    resource: dict[str, Any],
    by_id: dict[str, list[dict[str, Any]]],
    bundle: dict[str, Any],
    paths: list[str],
) -> dict[str, Any]:
    from .network_evidence import review_fact as existing_fact

    kind = resource["resource_type"].lower()
    selected = resource_paths(kind).intersection(paths)
    if not selected or not policy_unique(resource, bundle, by_id):
        return unknown("key_management_resource_not_unique_known_typed_selected_scope")
    if kind in {VAULT, STORAGE} and len(resource["arm_id"].split("/")) != 9:
        return unknown("key_management_resource_not_top_level")
    if sum(r["resource_type"].lower() in FACTS for r in bundle["resources"]) > 100:
        return unknown("key_management_configuration_population_over_100")
    facts = {}
    for path in sorted(selected):
        if path in PATHS:
            facts[path] = review_fact(resource["properties"], path)
        elif path == "enableRbacAuthorization":
            facts[path] = boolean(resource["properties"].get(path))
        elif path == "publicNetworkAccess":
            facts[path] = enumeration(resource["properties"].get(path), ("Enabled", "Disabled"))
        else:
            facts[path] = existing_fact(resource["properties"], path)
    result: dict[str, Any] = {"facts": facts, "warning": WARNING}
    if kind in {DEFINITION, INITIATIVE, ASSIGNMENT, ROLE}:
        result["suppliedPolicyConfiguration"] = policy_context(resource, bundle, by_id)
    if kind == STORAGE:
        result["keyStoreRelationship"] = unknown("private_key_references_withheld_no_join_inferred")
    return result
