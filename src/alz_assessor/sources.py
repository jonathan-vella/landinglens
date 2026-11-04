"""Normalize planned sources to a deliberately small, explicit ARM-property vocabulary."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .contracts import derive_id, digest, document, now, scope_id, validate
from .terraform import Analyzer

PROVIDER_VERSION = "4.50.0"
TF_TYPES = {
    "azurerm_storage_account": "Microsoft.Storage/storageAccounts",
    "azurerm_firewall_policy": "Microsoft.Network/firewallPolicies",
    "azurerm_resource_group": "Microsoft.Resources/resourceGroups",
    "azurerm_log_analytics_workspace": "Microsoft.OperationalInsights/workspaces",
    "azurerm_virtual_network": "Microsoft.Network/virtualNetworks",
    "azurerm_management_group": "Microsoft.Management/managementGroups",
}


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def unknown(reason: str) -> dict[str, str]:
    return {"unknown": reason}


def boolean(value: Any) -> Any:
    return value if type(value) is bool else unknown("boolean_missing_unresolved_or_invalid")


def property_at(properties: Any, path: str) -> Any:
    current = properties
    for key in path.split("."):
        if isinstance(current, dict) and "unknown" in current:
            return current
        if not isinstance(current, dict) or key not in current:
            return unknown("property_not_supplied")
        current = current[key]
    return current


def tf_properties(kind: str, properties: dict[str, Any]) -> dict[str, Any]:
    if kind == "azurerm_storage_account":
        return {"supportsHttpsTrafficOnly": boolean(properties.get("https_traffic_only_enabled"))}
    if kind == "azurerm_firewall_policy":
        dns = properties.get("dns")
        value = (
            dns[0].get("proxy_enabled")
            if (isinstance(dns, list) and len(dns) == 1 and isinstance(dns[0], dict))
            else None
        )
        return {
            "dnsSettings": {"enableProxy": boolean(value)},
        }
    return {}


def resource_scope(scope: str | None, properties: dict[str, Any]) -> str | None:
    if not scope:
        return None
    normalized = scope_id(scope)
    group = properties.get("resource_group_name")
    if "/resourcegroups/" in normalized:
        actual = normalized.split("/resourcegroups/")[1]
        return (
            normalized
            if not group or (isinstance(group, str) and group.lower() == actual)
            else None
        )
    if normalized.startswith("/subscriptions/") and isinstance(group, str) and "/" not in group:
        return normalized + "/resourceGroups/" + group
    return None


def terraform_source(
    root: Path,
    *,
    scope: str | None = None,
    provider_version: str | None = None,
    snapshots: Path | None = None,
    authorized_roots: list[Path] | None = None,
    variable_inputs: list[tuple[str, Any]] | None = None,
) -> dict[str, Any]:
    result = Analyzer(
        root,
        manifest=snapshots,
        authorized_roots=authorized_roots,
    ).analyze(variable_inputs=variable_inputs)
    records = []
    supported = provider_version == PROVIDER_VERSION
    for item in result["resources"]:
        kind = item.get("resource_type") or item["address"].split(".")[-2]
        properties = item["properties"]
        symbolic = "unknown" in properties
        arm_type = TF_TYPES.get(kind, kind)
        name = properties.get("name")
        identity = (
            derive_id(
                resource_scope(scope, properties),
                arm_type,
                name,
            )
            if supported and not symbolic and item.get("scope_binding_safe", False)
            else None
        )
        records.append(
            {
                "logical_id": item["address"],
                "resource_type": arm_type,
                "properties": tf_properties(kind, properties) if supported and not symbolic else {},
                "arm_id": identity,
                "source_location": item["file"],
                "state": "unknown" if symbolic or not supported else "known",
                "reason": properties.get("unknown", "")
                if supported
                else "unverified_provider_version",
            }
        )
    artifacts = dict(result["input_sha256"])
    artifacts["scope-provider-bindings"] = digest({"scope": scope, "azurerm": provider_version})
    return validate(
        document(
            "evidence",
            mode="planned",
            source="terraform",
            collected_at=now(),
            scope=scope,
            artifact_hashes=artifacts,
            inventory_complete=not result["diagnostics"] and supported,
            resources=records,
            diagnostics=result["diagnostics"],
            metadata={"provider_version": provider_version, "limitations": result["coverage"]},
        )
    )
