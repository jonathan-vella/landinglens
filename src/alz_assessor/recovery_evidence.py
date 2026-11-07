"""Offline recovery, guest configuration and WAF routing; never runtime assurance."""

from typing import Any

from .contracts import canonical_id, identity_type, scope_id
from .logging_evidence import DIAGNOSTIC, ONBOARDING, WORKSPACE, references, scoped_identity
from .policy_strategy_evidence import ASSIGNMENT, DEFINITION, INITIATIVE
from .protection_evidence import block, rows, typed_reference
from .sources import boolean, enumeration, property_at, unknown
from .terraform import InputError

VAULT = "microsoft.recoveryservices/vaults"
STORAGE_CONFIG = VAULT + "/backupstorageconfig"
BACKUP_ITEM = VAULT + "/backupfabrics/protectioncontainers/protecteditems"
ASR_ITEM = VAULT + "/replicationfabrics/replicationprotectioncontainers/replicationprotecteditems"
BACKUP_VAULT = "microsoft.dataprotection/backupvaults"
VM = "microsoft.compute/virtualmachines"
EXTENSION = VM + "/extensions"
GUEST = "microsoft.guestconfiguration/guestconfigurationassignments"
SQL = "microsoft.sql/servers"
FAILOVER = SQL + "/failovergroups"
PROFILE = "microsoft.cdn/profiles"
GATEWAY = "microsoft.network/applicationgateways"
STORAGE = "microsoft.storage/storageaccounts"
REDUNDANCIES = ("GeoRedundant", "LocallyRedundant", "ZoneRedundant")
DATASTORES = ("ArchiveStore", "OperationalStore", "VaultStore")
ASSIGNMENT_TYPES = ("Audit", "ApplyAndMonitor", "ApplyAndAutoCorrect", "DeployAndAutoCorrect")
CATEGORIES = (
    "ApplicationGatewayFirewallLog",
    "FrontDoorWebApplicationFirewallLog",
    "FrontdoorWebApplicationFirewallLog",
)
GUEST_GUIDS = {
    "f541acdc-e979-4377-acdb-3751ab2ab13a",
    "da6e55d7-d8a2-4adb-817d-6326af625ca4",
}
GUIDS = GUEST_GUIDS | {
    "7ea02e1c-7166-45a3-bdf5-098891367fcb",
    "eba8cf22-45c6-4dc1-9b57-2cceb3b97ce5",
    "b2ab13ad-a6e5-45d7-b8a2-adb117d6326a",
    "f625ca44-e569-45f2-823a-ce8cb12308ca",
    "89cc5e11-aa4d-4c3b-893d-feb99215266a",
    "7f408960-c626-44cb-a018-347c8d790cdf",
}
WARNING = (
    "Supplied original-time configuration only; not complete protection/coverage, successful "
    "backup/restore/replication/failover, achieved RPO/RTO, installed/compliant guest settings, "
    "operating drift monitoring, universal PaaS DR, WAF ingestion/review/detection or Sentinel "
    "operation. Requirements, retention, support, testing and operating decisions remain human."
)


def recovery_storage_facts(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("recovery_storage_configuration_not_explicit")
    return {
        "storageModelType": enumeration(value.get("storageModelType"), REDUNDANCIES),
        "crossRegionRestoreFlag": boolean(value.get("crossRegionRestoreFlag")),
    }


def backup_vault_facts(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("backup_vault_configuration_not_explicit")
    settings = value.get("storageSettings")
    valid = (
        rows(settings, 3)
        and bool(settings)
        and all(row.get("datastoreType") in DATASTORES for row in settings)
        and len({row["datastoreType"] for row in settings}) == len(settings)
    )
    return {
        "storageSettings": [
            {
                "datastoreType": row["datastoreType"],
                "type": enumeration(row.get("type"), REDUNDANCIES),
            }
            for row in settings
        ]
        if valid and rows(settings, 3)
        else unknown("datastore_settings_missing_invalid_duplicate_or_over_three"),
        "crossRegionRestore": enumeration(value.get("crossRegionRestore"), ("Enabled", "Disabled")),
    }


def backup_item_facts(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("vm_backup_configuration_not_explicit")
    return {
        "sourceVmId": typed_reference(value.get("sourceVmId"), (VM,)),
        "policyId": typed_reference(value.get("policyId"), (VAULT + "/backuppolicies",)),
    }


def asr_facts(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("a2a_replication_configuration_not_explicit")
    return {
        "sourceVmId": typed_reference(value.get("sourceVmId"), (VM,)),
        "policyId": typed_reference(value.get("policyId"), (VAULT + "/replicationpolicies",)),
        "recoveryResourceGroupId": typed_reference(
            value.get("recoveryResourceGroupId"), ("microsoft.resources/resourcegroups",)
        ),
    }


def guest_facts(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("guest_assignment_configuration_not_explicit")
    return {"assignmentType": enumeration(value.get("assignmentType"), ASSIGNMENT_TYPES)}


def extension_facts(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("machine_configuration_extension_not_explicit")
    if value.get("publisher") != "Microsoft.GuestConfiguration" or value.get("type") not in (
        "ConfigurationForLinux",
        "ConfigurationforWindows",
    ):
        return unknown("extension_not_reviewed_machine_configuration_publisher_type")
    return {
        "publisher": "Microsoft.GuestConfiguration",
        "type": value["type"],
        "autoUpgradeMinorVersion": boolean(value.get("autoUpgradeMinorVersion")),
        "enableAutomaticUpgrade": boolean(value.get("enableAutomaticUpgrade")),
    }


def failover_facts(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("sql_failover_configuration_not_explicit")
    return {
        "readWriteFailoverPolicy": enumeration(
            value.get("readWriteFailoverPolicy"), ("Automatic", "Manual")
        ),
        "databaseIds": references(value.get("databaseIds"), SQL + "/databases"),
        "partnerServerIds": references(value.get("partnerServerIds"), SQL),
    }


def profile_facts(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("frontdoor_profile_configuration_not_explicit")
    return {
        "sku": enumeration(value.get("sku"), ("Standard_AzureFrontDoor", "Premium_AzureFrontDoor"))
    }


def diagnostic_facts(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("waf_diagnostic_configuration_not_explicit")
    categories = value.get("categories")
    return {
        "categories": {
            category: boolean(categories.get(category) if isinstance(categories, dict) else None)
            for category in CATEGORIES
        },
        "storageAccountId": typed_reference(value.get("storageAccountId"), (STORAGE,)),
    }


FACTS = {
    "recoveryStorageSummary": recovery_storage_facts,
    "backupVaultSummary": backup_vault_facts,
    "vmBackupSummary": backup_item_facts,
    "a2aReplicationSummary": asr_facts,
    "guestAssignmentSummary": guest_facts,
    "machineConfigurationExtension": extension_facts,
    "sqlFailoverSummary": failover_facts,
    "frontDoorProfileSummary": profile_facts,
    "wafDiagnosticSummary": diagnostic_facts,
}
PATHS = set(FACTS)
KIND_PATHS = {
    VAULT: "recoveryStorageSummary",
    STORAGE_CONFIG: "recoveryStorageSummary",
    BACKUP_VAULT: "backupVaultSummary",
    BACKUP_ITEM: "vmBackupSummary",
    ASR_ITEM: "a2aReplicationSummary",
    GUEST: "guestAssignmentSummary",
    EXTENSION: "machineConfigurationExtension",
    FAILOVER: "sqlFailoverSummary",
    PROFILE: "frontDoorProfileSummary",
    DIAGNOSTIC: "wafDiagnosticSummary",
    ASSIGNMENT: "policyAssignmentSummary",
    DEFINITION: "policyDefinitionSummary",
    INITIATIVE: "policyInitiativeSummary",
    WORKSPACE: "logWorkspaceSummary",
    ONBOARDING: "sentinelOnboardingSummary",
    GATEWAY: "firewallPolicy.id",
}


def resource_paths(kind: str) -> set[str]:
    path = KIND_PATHS.get(kind.lower())
    return (
        {path, "targetResourceId", "workspaceId", "logAnalyticsDestinationType"}
        if kind.lower() == DIAGNOSTIC and path
        else {path}
        if path
        else set()
    )


def review_fact(properties: dict[str, Any], path: str) -> Any:
    return FACTS[path](properties.get(path))


def projected_properties(
    kind: str, values: dict[str, Any], *, root: Any = None, terraform: bool = False
) -> dict[str, Any]:
    kind = kind.lower()
    if kind == VAULT:
        return {
            "recoveryStorageSummary": recovery_storage_facts(
                {
                    "storageModelType": values.get("storage_mode_type"),
                    "crossRegionRestoreFlag": values.get("cross_region_restore_enabled"),
                }
                if terraform
                else None
            )
        }
    if kind == STORAGE_CONFIG:
        return {"recoveryStorageSummary": recovery_storage_facts(values)}
    if kind == BACKUP_VAULT:
        cross = values.get("cross_region_restore_enabled")
        return {
            "backupVaultSummary": backup_vault_facts(
                {
                    "storageSettings": [
                        {
                            "datastoreType": values.get("datastore_type"),
                            "type": values.get("redundancy"),
                        }
                    ]
                    if terraform
                    else values.get("storageSettings"),
                    "crossRegionRestore": ("Enabled" if cross else "Disabled")
                    if terraform and type(cross) is bool
                    else None
                    if terraform
                    else property_at(values, "featureSettings.crossRegionRestoreSettings.state"),
                }
            )
        }
    if kind == BACKUP_ITEM:
        return {
            "vmBackupSummary": backup_item_facts(
                {
                    "sourceVmId": values.get("source_vm_id" if terraform else "sourceResourceId"),
                    "policyId": values.get("backup_policy_id" if terraform else "policyId"),
                }
                if terraform
                or values.get("protectedItemType") == "Microsoft.Compute/virtualMachines"
                else None
            )
        }
    if kind == ASR_ITEM:
        details = values.get("providerSpecificDetails")
        details = details if isinstance(details, dict) else {}
        return {
            "a2aReplicationSummary": asr_facts(
                {
                    "sourceVmId": values.get("source_vm_id")
                    if terraform
                    else details.get("fabricObjectId"),
                    "policyId": values.get(
                        "recovery_replication_policy_id" if terraform else "policyId"
                    ),
                    "recoveryResourceGroupId": values.get("target_resource_group_id")
                    if terraform
                    else details.get("recoveryResourceGroupId"),
                }
                if terraform or (isinstance(details, dict) and details.get("instanceType") == "A2A")
                else None
            )
        }
    if kind == GUEST:
        from .operations_evidence import projected_properties as operations_properties

        configuration = operations_properties(kind, values, terraform=terraform)
        return {
            "guestAssignmentSummary": guest_facts(
                {"assignmentType": configuration["operationsGuestAssignment"].get("assignmentType")}
            )
        }
    if kind == EXTENSION:
        return {
            "machineConfigurationExtension": extension_facts(
                {
                    "publisher": values.get("publisher"),
                    "type": values.get("type"),
                    "autoUpgradeMinorVersion": values.get(
                        "auto_upgrade_minor_version" if terraform else "autoUpgradeMinorVersion"
                    ),
                    "enableAutomaticUpgrade": values.get(
                        "automatic_upgrade_enabled" if terraform else "enableAutomaticUpgrade"
                    ),
                }
            )
        }
    if kind == FAILOVER:
        partners = values.get("partner_server" if terraform else "partnerServers")
        return {
            "sqlFailoverSummary": failover_facts(
                {
                    "readWriteFailoverPolicy": block(
                        values.get("read_write_endpoint_failover_policy")
                    ).get("mode")
                    if terraform
                    else property_at(values, "readWriteEndpoint.failoverPolicy"),
                    "databaseIds": values.get("databases"),
                    "partnerServerIds": [row.get("id") for row in partners]
                    if rows(partners)
                    else None,
                }
            )
        }
    if kind == PROFILE:
        return {
            "frontDoorProfileSummary": profile_facts(
                {"sku": values.get("sku_name") if terraform else property_at(root, "sku.name")}
            )
        }
    if kind == DIAGNOSTIC:
        logs = values.get("enabled_log" if terraform else "logs")
        categories = {}
        for category in CATEGORIES:
            matches = (
                [
                    row
                    for row in logs
                    if row.get("category") == category
                    and "categoryGroup" not in row
                    and "category_group" not in row
                ]
                if rows(logs)
                else []
            )
            categories[category] = (
                (True if terraform else boolean(matches[0].get("enabled")))
                if len(matches) == 1
                else unknown("waf_category_not_unique_explicit")
            )
        return {
            "wafDiagnosticSummary": diagnostic_facts(
                {
                    "categories": categories,
                    "storageAccountId": values.get(
                        "storage_account_id" if terraform else "storageAccountId"
                    ),
                }
            )
        }
    return {}


def replay_properties(kind: str, values: dict[str, Any]) -> dict[str, Any]:
    path = KIND_PATHS.get(kind.lower())
    return {path: review_fact(values, path)} if path in PATHS and path in values else {}


def unique_known(
    resource: dict[str, Any], bundle: dict[str, Any], by_id: dict[str, list[dict[str, Any]]]
) -> bool:
    if resource["resource_type"].lower() in {ASSIGNMENT, DEFINITION, INITIATIVE}:
        from .policy_strategy_evidence import unique_known as policy_unique_known

        return policy_unique_known(resource, bundle, by_id)
    identity = scoped_identity(resource, bundle.get("scope"))
    if resource["resource_type"].lower() == "microsoft.resources/resourcegroups":
        supplied, selected = resource.get("arm_id"), bundle.get("scope")
        if not isinstance(supplied, str) or not isinstance(selected, str):
            return False
        try:
            candidate = canonical_id(supplied)
            boundary = scope_id(selected)
        except InputError:
            return False
        if candidate == boundary or candidate.startswith(boundary + "/"):
            identity = candidate
    if not identity or resource["state"] != "known" or by_id.get(identity) != [resource]:
        return False
    parent = identity.split("/providers/", 1)[0]
    valid = (
        len(parent.split("/")) == 5
        and identity_type(parent) == "microsoft.resources/resourcegroups"
        and identity_type(identity) == resource["resource_type"].lower()
        and sum(row["resource_type"].lower() in KIND_PATHS for row in bundle["resources"]) <= 100
    )
    kind = resource["resource_type"].lower()
    if not valid:
        return False
    if kind == STORAGE_CONFIG:
        return identity.endswith("/backupstorageconfig/vaultstorageconfig")
    if kind == GUEST:
        return identity_type(identity.rsplit("/providers/" + GUEST + "/", 1)[0]) == VM
    if kind == DIAGNOSTIC:
        target = typed_reference(resource["properties"].get("targetResourceId"), (PROFILE, GATEWAY))
        if target != identity.rsplit("/providers/" + DIAGNOSTIC + "/", 1)[0]:
            return False
        candidates = by_id.get(target, []) if isinstance(target, str) else []
        if len(candidates) != 1 or not unique_known(candidates[0], bundle, by_id):
            return False
        return identity_type(target) == GATEWAY or isinstance(
            profile_facts(candidates[0]["properties"].get("frontDoorProfileSummary")).get("sku"),
            str,
        )
    return True


def linked_context(
    resource: dict[str, Any], bundle: dict[str, Any], by_id: dict[str, list[dict[str, Any]]]
) -> dict[str, Any]:
    if not unique_known(resource, bundle, by_id):
        return unknown("recovery_source_not_unique_known_typed_in_scope_or_over_100")
    kind, identity = resource["resource_type"].lower(), resource["arm_id"].lower()

    def link(ref: Any, expected: str) -> dict[str, Any]:
        ref = typed_reference(ref, (expected,))
        matches = by_id.get(ref, []) if isinstance(ref, str) else []
        if len(matches) != 1 or not unique_known(matches[0], bundle, by_id):
            return unknown("recovery_target_not_unique_known_typed_in_scope_or_over_bound")
        return {"arm_id": ref, "resource_type": expected}

    result: dict[str, Any] = {"warning": WARNING}
    path = KIND_PATHS.get(kind)
    facts = review_fact(resource["properties"], path) if path in PATHS else {}
    if not isinstance(facts, dict) or "unknown" in facts:
        return {**result, "configuration": unknown("recovery_configuration_unsupported_or_missing")}
    if kind in {BACKUP_ITEM, ASR_ITEM}:
        result["sourceVm"] = link(facts.get("sourceVmId"), VM)
        vault = identity.split("/" + kind.split("/")[2] + "/", 1)[0]
        policy_kind = VAULT + ("/backuppolicies" if kind == BACKUP_ITEM else "/replicationpolicies")
        policy = facts.get("policyId")
        result["policy"] = (
            link(policy, policy_kind)
            if isinstance(policy, str)
            and policy.rsplit("/" + policy_kind.rsplit("/", 1)[1] + "/", 1)[0] == vault
            else unknown("recovery_policy_not_in_item_vault")
        )
        result["vault"] = link(vault, VAULT)
        if kind == ASR_ITEM:
            ref = typed_reference(
                facts.get("recoveryResourceGroupId"), ("microsoft.resources/resourcegroups",)
            )
            result["recoveryResourceGroup"] = link(ref, "microsoft.resources/resourcegroups")
    elif kind == STORAGE_CONFIG:
        result["vault"] = (
            link(identity.rsplit("/backupstorageconfig/", 1)[0], VAULT)
            if identity.endswith("/backupstorageconfig/vaultstorageconfig")
            else unknown("recovery_storage_child_must_be_vaultstorageconfig")
        )
    elif kind in {GUEST, EXTENSION}:
        parent = identity.rsplit(
            "/providers/" + GUEST + "/" if kind == GUEST else "/extensions/", 1
        )[0]
        result["machine"] = link(parent, VM)
        if kind == EXTENSION:
            expected_name = {
                "ConfigurationForLinux": "azurepolicyforlinux",
                "ConfigurationforWindows": "azurepolicyforwindows",
            }.get(facts.get("type", ""))
            result["baselineInstanceNameMatches"] = identity.rsplit("/", 1)[-1] == expected_name
    elif kind == FAILOVER:
        parent = identity.rsplit("/failovergroups/", 1)[0]
        result["primaryServer"] = link(parent, SQL)
        for field, expected in (("partnerServerIds", SQL), ("databaseIds", SQL + "/databases")):
            refs = facts.get(field)
            result[field] = (
                [
                    unknown("sql_database_not_on_primary_server")
                    if expected.endswith("/databases") and ref.rsplit("/databases/", 1)[0] != parent
                    else unknown("sql_partner_is_primary_server")
                    if expected == SQL and ref == parent
                    else link(ref, expected)
                    for ref in refs
                ]
                if isinstance(refs, list)
                else unknown("sql_references_not_explicit")
            )
    elif kind == DIAGNOSTIC:
        from .network_evidence import reference

        parent = identity.rsplit("/providers/" + DIAGNOSTIC + "/", 1)[0]
        target = reference(resource["properties"].get("targetResourceId"))
        if target != parent or identity_type(parent) not in {PROFILE, GATEWAY}:
            return unknown("waf_diagnostic_target_identity_mismatch_or_unsupported_service")
        target_kind = identity_type(parent)
        result["target"] = link(parent, target_kind)
        category: Any = CATEGORIES[0] if target_kind == GATEWAY else CATEGORIES[1]
        if target_kind == PROFILE and "unknown" not in result["target"]:
            profile = review_fact(by_id[parent][0]["properties"], "frontDoorProfileSummary")
            if not isinstance(profile.get("sku"), str):
                category = None
        if "unknown" in result["target"]:
            category = None
        result["configuredWafLog"] = (
            {"category": category, "enabled": facts["categories"][category]}
            if category
            else unknown("waf_target_service_sku_not_bound")
        )
        result["workspace"] = link(resource["properties"].get("workspaceId"), WORKSPACE)
        result["storage"] = link(facts.get("storageAccountId"), STORAGE)
        workspace = result["workspace"].get("arm_id")
        onboarding = workspace + "/providers/" + ONBOARDING + "/default" if workspace else None
        result["sentinelOnboarding"] = link(onboarding, ONBOARDING)
    return result


def tf_resource_id(scope: str | None, kind: str, values: dict[str, Any]) -> str | None:
    from .contracts import derive_id, scope_id
    from .sources import resource_scope

    name = values.get("name")
    if not scope or not isinstance(name, str) or not name or "/" in name:
        return None
    boundary = scope_id(scope)
    parents = {
        "azurerm_virtual_machine_extension": ("virtual_machine_id", VM, "/extensions/"),
        "azurerm_mssql_failover_group": ("server_id", SQL, "/failovergroups/"),
    }
    if kind in parents:
        field, expected, suffix = parents[kind]
        parent = typed_reference(values.get(field), (expected,))
        return (
            canonical_id(parent + suffix + name)
            if isinstance(parent, str) and parent.startswith(boundary + "/")
            else None
        )
    if kind == "azurerm_site_recovery_replicated_vm":
        names: list[Any] = [
            values.get(key)
            for key in (
                "recovery_vault_name",
                "source_recovery_fabric_name",
                "source_recovery_protection_container_name",
            )
        ]
        if all(isinstance(item, str) and item and "/" not in item for item in names):
            return derive_id(
                resource_scope(scope, values),
                "Microsoft." + ASR_ITEM.removeprefix("microsoft."),
                "/".join([*names, name]),
            )
    return None
