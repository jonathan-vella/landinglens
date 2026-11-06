"""Scope-local security configuration, never audit contents or protection health."""

from typing import Any

from .sources import boolean, enumeration, property_at, unknown

PATHS = {"defenderPricing", "activityLogRouting", "hsmConfiguration", "patchConfiguration"}
KINDS = {
    "microsoft.security/pricings",
    "microsoft.keyvault/managedhsms",
    "microsoft.compute/virtualmachines",
}
PLANS = (
    "AI",
    "Api",
    "AppServices",
    "ContainerRegistry",
    "KeyVaults",
    "KubernetesService",
    "SqlServers",
    "SqlServerVirtualMachines",
    "StorageAccounts",
    "VirtualMachines",
    "Arm",
    "Dns",
    "OpenSourceRelationalDatabases",
    "Containers",
    "CosmosDbs",
    "CloudPosture",
)
EXTENSIONS = (
    "AgentlessDiscoveryForKubernetes",
    "OnUploadMalwareScanning",
    "SensitiveDataDiscovery",
    "ContainerRegistriesVulnerabilityAssessments",
    "MdeDesignatedSubscription",
    "AgentlessVmScanning",
    "EntraPermissionsManagement",
    "FileIntegrityMonitoring",
    "ContainerSensor",
    "AIPromptEvidence",
)
ACTIVITY_CATEGORIES = (
    "Administrative",
    "Security",
    "ServiceHealth",
    "Alert",
    "Recommendation",
    "Policy",
    "Autoscale",
    "ResourceHealth",
)


def extension_facts(value: Any) -> Any:
    if not isinstance(value, list) or len(value) > 100:
        return unknown("pricing_extensions_missing_or_over_100")
    result = []
    seen = set()
    for row in value:
        if not isinstance(row, dict) or "unknown" in row:
            return unknown("pricing_extension_invalid")
        name = enumeration(row.get("name"), EXTENSIONS)
        if not isinstance(name, str) or name in seen:
            return unknown("pricing_extension_unsupported_or_duplicate")
        seen.add(name)
        result.append(
            {
                "name": name,
                "isEnabled": enumeration(row.get("isEnabled"), ("True", "False")),
            }
        )
    return result


def pricing_facts(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("pricing_configuration_not_explicit")
    return {
        "plan": enumeration(value.get("plan"), PLANS),
        "pricingTier": enumeration(value.get("pricingTier"), ("Free", "Standard")),
        "subPlan": enumeration(value.get("subPlan"), ("P1", "P2", "DefenderForStorageV2")),
        "enforce": enumeration(value.get("enforce"), ("True", "False")),
        "extensions": extension_facts(value.get("extensions")),
    }


def routing_facts(value: Any) -> Any:
    from .contracts import identity_type
    from .network_evidence import reference

    if not isinstance(value, dict) or "unknown" in value:
        return unknown("activity_routing_not_explicit")
    logs = value.get("logs")
    prepared: Any = unknown("activity_logs_missing_or_over_100")
    if isinstance(logs, list) and len(logs) <= 100:
        prepared = []
        seen = set()
        for row in logs:
            if not isinstance(row, dict) or "unknown" in row:
                prepared = unknown("activity_log_entry_invalid")
                break
            category, group = row.get("category"), row.get("categoryGroup")
            if (category is None) == (group is None):
                prepared = unknown("activity_category_ambiguous_or_missing")
                break
            label = enumeration(
                category if category is not None else group,
                ACTIVITY_CATEGORIES if category is not None else ("allLogs", "audit"),
            )
            if not isinstance(label, str) or (category is not None, label) in seen:
                prepared = unknown("activity_category_unsupported_or_duplicate")
                break
            seen.add((category is not None, label))
            prepared.append(
                {
                    "category" if category is not None else "categoryGroup": label,
                    "enabled": boolean(row.get("enabled")),
                }
            )
    result = {"logs": prepared}
    for key, kind in (
        ("workspaceId", "microsoft.operationalinsights/workspaces"),
        ("storageAccountId", "microsoft.storage/storageaccounts"),
    ):
        identity = reference(value.get(key))
        result[key] = (
            identity
            if isinstance(identity, str) and identity_type(identity) == kind
            else unknown("activity_destination_missing_or_wrong_type")
        )
    return result


def hsm_facts(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("hsm_configuration_not_explicit")
    return {
        "publicNetworkAccess": enumeration(
            value.get("publicNetworkAccess"), ("Enabled", "Disabled")
        ),
        "enablePurgeProtection": boolean(value.get("enablePurgeProtection")),
    }


def patch_facts(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("patch_configuration_not_explicit")
    os = value.get("os")
    if os not in ("Linux", "Windows"):
        return unknown("patch_os_missing_or_ambiguous")
    return {
        "os": os,
        "assessmentMode": enumeration(
            value.get("assessmentMode"), ("ImageDefault", "AutomaticByPlatform")
        ),
        "patchMode": enumeration(
            value.get("patchMode"),
            ("ImageDefault", "AutomaticByPlatform")
            if os == "Linux"
            else ("Manual", "AutomaticByOS", "AutomaticByPlatform"),
        ),
        "provisionVMAgent": boolean(value.get("provisionVMAgent")),
    }


def review_fact(properties: dict[str, Any], path: str) -> Any:
    value = properties.get(path)
    return {
        "defenderPricing": pricing_facts,
        "activityLogRouting": routing_facts,
        "hsmConfiguration": hsm_facts,
        "patchConfiguration": patch_facts,
    }[path](value)


def projected_properties(
    kind: str,
    values: dict[str, Any],
    *,
    terraform: bool = False,
    root: Any = None,
    terraform_kind: str | None = None,
) -> dict[str, Any]:
    kind = kind.lower()
    if kind == "microsoft.security/pricings":
        extensions = values.get("extension" if terraform else "extensions")
        if terraform and isinstance(extensions, list) and len(extensions) <= 100:
            extensions = [
                {"name": row.get("name"), "isEnabled": "True"}
                if isinstance(row, dict) and "unknown" not in row
                else None
                for row in extensions
            ]
        return {
            "defenderPricing": pricing_facts(
                {
                    "plan": values.get("resource_type")
                    if terraform
                    else root.get("name")
                    if isinstance(root, dict)
                    else None,
                    "pricingTier": values.get("tier" if terraform else "pricingTier"),
                    "subPlan": values.get("subplan" if terraform else "subPlan"),
                    "enforce": None if terraform else values.get("enforce"),
                    "extensions": extensions,
                }
            )
        }
    if kind == "microsoft.insights/diagnosticsettings":
        logs = values.get("enabled_log" if terraform else "logs")
        if terraform and isinstance(logs, list) and len(logs) <= 100:
            logs = [
                {
                    "category": row.get("category"),
                    "categoryGroup": row.get("category_group"),
                    "enabled": True,
                }
                if isinstance(row, dict) and "unknown" not in row
                else None
                for row in logs
            ]
        return {
            "activityLogRouting": routing_facts(
                {
                    "logs": logs,
                    "workspaceId": values.get(
                        "log_analytics_workspace_id" if terraform else "workspaceId"
                    ),
                    "storageAccountId": values.get(
                        "storage_account_id" if terraform else "storageAccountId"
                    ),
                }
            )
        }
    if kind == "microsoft.keyvault/managedhsms":
        public = values.get("public_network_access_enabled")
        return {
            "hsmConfiguration": hsm_facts(
                {
                    "publicNetworkAccess": ("Enabled" if public else "Disabled")
                    if terraform and type(public) is bool
                    else None
                    if terraform
                    else values.get("publicNetworkAccess"),
                    "enablePurgeProtection": values.get(
                        "purge_protection_enabled" if terraform else "enablePurgeProtection"
                    ),
                }
            )
        }
    if kind == "microsoft.compute/virtualmachines":
        if terraform:
            os = {
                "azurerm_linux_virtual_machine": "Linux",
                "azurerm_windows_virtual_machine": "Windows",
            }.get(terraform_kind or "")
            return {
                "patchConfiguration": patch_facts(
                    {
                        "os": os,
                        "assessmentMode": values.get("patch_assessment_mode"),
                        "patchMode": values.get("patch_mode"),
                        "provisionVMAgent": values.get("provision_vm_agent"),
                    }
                )
            }
        profile = values.get("osProfile")
        present = [
            (os, profile[key])
            for os, key in (("Linux", "linuxConfiguration"), ("Windows", "windowsConfiguration"))
            if isinstance(profile, dict) and key in profile
        ]
        if len(present) != 1 or not isinstance(present[0][1], dict):
            return {"patchConfiguration": unknown("patch_os_missing_or_ambiguous")}
        os, config = present[0]
        return {
            "patchConfiguration": patch_facts(
                {
                    "os": os,
                    "assessmentMode": property_at(config, "patchSettings.assessmentMode"),
                    "patchMode": property_at(config, "patchSettings.patchMode"),
                    "provisionVMAgent": config.get("provisionVMAgent"),
                }
            )
        }
    return {}


def replay_properties(kind: str, values: dict[str, Any]) -> dict[str, Any]:
    paths = {
        "microsoft.security/pricings": "defenderPricing",
        "microsoft.insights/diagnosticsettings": "activityLogRouting",
        "microsoft.keyvault/managedhsms": "hsmConfiguration",
        "microsoft.compute/virtualmachines": "patchConfiguration",
    }
    path = paths.get(kind.lower())
    return {path: review_fact(values, path)} if path and path in values else {}
