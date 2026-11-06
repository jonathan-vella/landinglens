"""Minimal identity/assignment context without directory identities or access claims."""

from typing import Any

from .contracts import canonical_id, identity_type
from .sources import enumeration, unknown
from .terraform import InputError

PATHS = {"identitySummary", "principalType", "roleDefinitionId"}
IDENTITY_KINDS = {"microsoft.storage/storageaccounts", "microsoft.network/expressrouteports"}
ROLE_KIND = "microsoft.authorization/roleassignments"
IDENTITY_TYPES = ("None", "SystemAssigned", "UserAssigned", "SystemAssigned, UserAssigned")
PRINCIPAL_TYPES = ("User", "Group", "ServicePrincipal", "ForeignGroup", "Device")


def managed_identity_reference(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return (
            identity_type(canonical_id(value)) == "microsoft.managedidentity/userassignedidentities"
        )
    except InputError:
        return False


def identity_summary(value: Any, *, terraform: bool, resource_type: str) -> Any:
    if terraform:
        value = value[0] if isinstance(value, list) and len(value) == 1 else None
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("identity_configuration_not_explicit")
    allowed = (
        ("UserAssigned",)
        if resource_type.lower() == "microsoft.network/expressrouteports"
        else IDENTITY_TYPES
    )
    if value.get("type") not in allowed:
        return unknown("identity_type_not_supported")
    kind = value["type"]
    identities = value.get("identity_ids" if terraform else "userAssignedIdentities")
    supplied = (
        identities if terraform else list(identities) if isinstance(identities, dict) else None
    )
    count: Any = unknown("user_assigned_bindings_not_explicit")
    if (
        isinstance(supplied, list)
        and len(supplied) <= 100
        and all(managed_identity_reference(identity) for identity in supplied)
    ):
        normalized = [canonical_id(identity) for identity in supplied]
        if len(set(normalized)) == len(normalized):
            count = len(normalized)
    if isinstance(kind, str) and type(count) is int:
        if (kind in {"None", "SystemAssigned"} and count != 0) or (
            "UserAssigned" in kind and count == 0
        ):
            return unknown("identity_type_and_bindings_conflict")
    return {"type": kind, "userAssignedCount": count}


def summary_facts(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("identity_summary_not_explicit")
    count = value.get("userAssignedCount")
    kind = enumeration(value.get("type"), IDENTITY_TYPES)
    if isinstance(kind, str) and type(count) is int and 0 <= count <= 100:
        if (kind in {"None", "SystemAssigned"} and count != 0) or (
            "UserAssigned" in kind and count == 0
        ):
            return unknown("identity_type_and_bindings_conflict")
    return {
        "type": kind,
        "userAssignedCount": count
        if type(count) is int and 0 <= count <= 100
        else unknown("identity_count_not_explicit"),
    }


def role_reference(value: Any) -> Any:
    if isinstance(value, str):
        try:
            identity = canonical_id(value)
            if identity_type(identity) == "microsoft.authorization/roledefinitions":
                return identity
        except InputError:
            pass
    return unknown("role_definition_identity_not_explicit")


def role_properties(values: dict[str, Any], *, terraform: bool) -> dict[str, Any]:
    return {
        "principalType": enumeration(
            values.get("principal_type" if terraform else "principalType"), PRINCIPAL_TYPES
        ),
        "roleDefinitionId": role_reference(
            values.get("role_definition_id" if terraform else "roleDefinitionId")
        ),
    }


def review_fact(properties: dict[str, Any], path: str) -> Any:
    value = properties.get(path)
    if path == "identitySummary":
        return summary_facts(value)
    if path == "principalType":
        return enumeration(value, PRINCIPAL_TYPES)
    return role_reference(value)


def replay_properties(kind: str, values: dict[str, Any]) -> dict[str, Any]:
    if kind.lower() == ROLE_KIND:
        return role_properties(values, terraform=False)
    if kind.lower() in IDENTITY_KINDS and "identitySummary" in values:
        return {"identitySummary": summary_facts(values["identitySummary"])}
    return {}
