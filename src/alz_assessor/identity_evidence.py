"""Minimal identity/assignment context without directory identities or access claims."""

from typing import Any

from .contracts import canonical_id, identity_type
from .sources import enumeration, property_at, unknown
from .terraform import InputError

PATHS = {
    "identitySummary",
    "principalType",
    "roleDefinitionId",
    "azureRoleType",
    "assignableScopeCount",
    "availabilitySetId",
    "platformFaultDomainCount",
    "platformUpdateDomainCount",
    "replicaConfiguration",
    "domainServiceSku",
}
IDENTITY_KINDS = {"microsoft.storage/storageaccounts", "microsoft.network/expressrouteports"}
ROLE_KIND = "microsoft.authorization/roleassignments"
IDENTITY_TYPES = ("None", "SystemAssigned", "UserAssigned", "SystemAssigned, UserAssigned")
PRINCIPAL_TYPES = ("User", "Group", "ServicePrincipal", "ForeignGroup", "Device")
DEFINITION_KIND = "microsoft.authorization/roledefinitions"
VM_KIND = "microsoft.compute/virtualmachines"
SET_KIND = "microsoft.compute/availabilitysets"
DOMAIN_KIND = "microsoft.aad/domainservices"
RESILIENCE_GUIDS = {
    "d98d954d-7d1c-4a07-92a7-cf3afe8dcbd2",
    "1559ab91-53e8-4908-ae28-c84c33b6b780",
    "e8aa1e41-870d-4968-94c6-77be14f510ac",
    "f5664b5e-984a-4859-a773-e7d261623a76",
    "8b9fe5c4-1049-4d40-9a92-3c3474d00018",
    "0dd4e625-9c4b-4a56-b54a-4357bac12761",
    "1cf0b8da-70bd-44d0-94af-8d99cfc89ae1",
    "984a859c-773e-47d2-9162-3a765a917e1f",
}


def explicit_count(value: Any, maximum: int) -> Any:
    return (
        value
        if type(value) is int and 1 <= value <= maximum
        else unknown("configured_domain_count_missing_invalid_or_over_bound")
    )


def assignable_scope_count(value: Any) -> Any:
    from .contracts import scope_id

    if not isinstance(value, list) or not 1 <= len(value) <= 100:
        return unknown("assignable_scopes_missing_invalid_or_over_100")
    normalized = []
    for entry in value:
        try:
            normalized.append(scope_id(entry))
        except (InputError, TypeError):
            return unknown("assignable_scope_unsupported_or_invalid")
    if len(set(normalized)) != len(normalized):
        return unknown("assignable_scopes_ambiguous")
    return len(normalized)


def replica_configuration(value: Any, population: Any) -> Any:
    from .dns_evidence import location
    from .protection_evidence import rows, typed_reference

    if not isinstance(population, str) or population not in {
        "supplied-arm-list",
        "terraform-initial-only",
    }:
        return unknown("replica_population_not_supported")
    if not rows(value, 5) or (population == "terraform-initial-only" and len(value) != 1):
        return unknown("replica_configuration_missing_invalid_or_over_five")
    result = []
    seen: set[str] = set()
    for entry in value:
        region = location(entry.get("location"))
        subnet = typed_reference(
            entry.get("subnetId"), ("microsoft.network/virtualnetworks/subnets",)
        )
        if not isinstance(region, str) or not isinstance(subnet, str) or subnet in seen:
            return unknown("replica_binding_missing_invalid_or_ambiguous")
        seen.add(subnet)
        result.append({"location": region, "subnetId": subnet})
    return {"population": population, "replicaCount": len(result), "replicas": result}


def replica_fact(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("replica_configuration_not_explicit")
    result = replica_configuration(value.get("replicas"), value.get("population"))
    if not isinstance(result, dict) or "unknown" in result:
        return result
    if (
        type(value.get("replicaCount")) is not int
        or value["replicaCount"] != result["replicaCount"]
    ):
        return unknown("replica_configuration_count_conflict")
    return result


def projected_properties(
    kind: str, values: dict[str, Any], *, root: Any = None, terraform: bool = False
) -> dict[str, Any]:
    from .dns_evidence import location
    from .network_evidence import configured_zones
    from .protection_evidence import block, typed_reference

    kind = kind.lower()
    top = values if terraform else root if isinstance(root, dict) else {}
    result: dict[str, Any] = {}
    if kind in {VM_KIND, SET_KIND, DOMAIN_KIND} and "location" in top:
        result["resourceLocation"] = location(top["location"])
    if kind == VM_KIND:
        zone_key = "zone" if terraform else "zones"
        if zone_key in top:
            zone = top[zone_key]
            result["configuredZones"] = configured_zones(
                [zone] if terraform and isinstance(zone, str) else zone if not terraform else None
            )
        key = "availability_set_id" if terraform else "availabilitySet"
        if key in values:
            result["availabilitySetId"] = typed_reference(
                values[key] if terraform else property_at(values, "availabilitySet.id"),
                (SET_KIND,),
            )
    if kind == SET_KIND:
        for path, key, bound in (
            ("platformFaultDomainCount", "platform_fault_domain_count", 3),
            ("platformUpdateDomainCount", "platform_update_domain_count", 20),
        ):
            result[path] = explicit_count(values.get(key if terraform else path), bound)
    if kind == DEFINITION_KIND:
        result["azureRoleType"] = (
            "CustomRole"
            if terraform
            else enumeration(values.get("type"), ("CustomRole", "BuiltInRole"))
        )
        result["assignableScopeCount"] = assignable_scope_count(
            values.get("assignable_scopes" if terraform else "assignableScopes")
        )
    if kind == DOMAIN_KIND:
        result["domainServiceSku"] = enumeration(
            values.get("sku"), ("Standard", "Enterprise", "Premium")
        )
        replicas = values.get("replicaSets")
        if terraform:
            initial = block(values.get("initial_replica_set"))
            replicas = [{"location": values.get("location"), "subnetId": initial.get("subnet_id")}]
        result["replicaConfiguration"] = replica_configuration(
            replicas, "terraform-initial-only" if terraform else "supplied-arm-list"
        )
    return result


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
    if path == "azureRoleType":
        return enumeration(value, ("CustomRole", "BuiltInRole"))
    if path == "assignableScopeCount":
        return explicit_count(value, 100)
    if path in {"platformFaultDomainCount", "platformUpdateDomainCount"}:
        return explicit_count(value, 3 if path == "platformFaultDomainCount" else 20)
    if path == "availabilitySetId":
        from .protection_evidence import typed_reference

        return typed_reference(value, (SET_KIND,))
    if path == "domainServiceSku":
        return enumeration(value, ("Standard", "Enterprise", "Premium"))
    if path == "replicaConfiguration":
        return replica_fact(value)
    return role_reference(value)


def replay_properties(kind: str, values: dict[str, Any]) -> dict[str, Any]:
    kind = kind.lower()
    if kind.lower() == ROLE_KIND:
        return role_properties(values, terraform=False)
    if kind.lower() in IDENTITY_KINDS and "identitySummary" in values:
        return {"identitySummary": summary_facts(values["identitySummary"])}
    paths = {
        VM_KIND: {"availabilitySetId"},
        SET_KIND: {"platformFaultDomainCount", "platformUpdateDomainCount"},
        DEFINITION_KIND: {"azureRoleType", "assignableScopeCount"},
        DOMAIN_KIND: {"domainServiceSku", "replicaConfiguration"},
    }.get(kind, set())
    result = {path: review_fact(values, path) for path in sorted(paths) if path in values}
    if kind in {VM_KIND, SET_KIND, DOMAIN_KIND}:
        from .dns_evidence import location
        from .network_evidence import configured_zones

        if "resourceLocation" in values:
            result["resourceLocation"] = location(values["resourceLocation"])
        if kind == VM_KIND and "configuredZones" in values:
            result["configuredZones"] = configured_zones(values["configuredZones"])
    return result
