"""Original-time operations configuration, never guest, traffic or retention assurance."""

import re
from typing import Any

from .contracts import canonical_id, digest, identity_type, scope_id
from .identity_evidence import known_scoped_resource
from .logging_evidence import WORKSPACE
from .policy_strategy_evidence import ASSIGNMENT, DEFINITION, ROLE
from .policy_strategy_evidence import configuration_context as policy_context
from .policy_strategy_evidence import location as extension_parent
from .policy_strategy_evidence import unique_known as policy_unique
from .protection_evidence import block, typed_reference
from .sources import boolean, enumeration, property_at, unknown
from .terraform import InputError

TABLE = WORKSPACE + "/tables"
EXPORT = WORKSPACE + "/dataexports"
STORAGE = "microsoft.storage/storageaccounts"
IMMUTABLE = STORAGE + "/blobservices/containers/immutabilitypolicies"
GUEST = "microsoft.guestconfiguration/guestconfigurationassignments"
VM = "microsoft.compute/virtualmachines"
ARC = "microsoft.hybridcompute/machines"
LOCK = "microsoft.authorization/locks"
FLOW = "microsoft.network/networkwatchers/flowlogs"
GUIDS = {
    "67e7a8ed-4b30-4e38-a3f2-9812b2363cef",
    "7418ada9-4199-4c28-8286-d15e9433e8f3",
    "5e6c4cfd-3e50-4454-9c24-47ec66138a72",
    "e7d7e484-3276-4d8b-bc05-5bcf619e8a13",
    "f9887952-5d62-4688-9d70-ba6c97be9951",
    "c806c048-26b7-4ddf-b4c2-b4f0c476925d",
    "90483845-c986-4cb2-a131-56a12476e49f",
    "541acdce-9793-477b-adb3-751ab2ab13ad",
    "a6e55d7d-8a2a-4db1-87d6-326af625ca44",
}
PATHS = {
    "operationsTableRetention",
    "operationsExport",
    "operationsImmutability",
    "operationsGuestAssignment",
    "operationsArcPatch",
    "operationsLock",
}
KIND_PATHS = {
    TABLE: "operationsTableRetention",
    EXPORT: "operationsExport",
    IMMUTABLE: "operationsImmutability",
    GUEST: "operationsGuestAssignment",
    ARC: "operationsArcPatch",
    LOCK: "operationsLock",
}
WARNING = (
    "Supplied original-time configuration only. No complete ingestion, approved workspace/"
    "regional/sovereignty/cost design, required-data retention, effective export, legal WORM "
    "sufficiency, guest audit, installed patches, fleet compliance, executed traffic analysis "
    "or effective access/protection inferred. Policy deny is not an RBAC deny assignment. "
    "Criticality, requirements, applicability and exceptions remain independent human decisions."
)
TF_TOTAL = {1095, 1460, 1826, 2191, 2556, 2922, 3288, 3653, 4018, 4383}
TF_KINDS = {
    "azurerm_log_analytics_workspace_table": ("workspace_id", WORKSPACE, "/tables/"),
    "azurerm_log_analytics_data_export_rule": (
        "workspace_resource_id",
        WORKSPACE,
        "/dataexports/",
    ),
    "azurerm_policy_virtual_machine_configuration_assignment": (
        "virtual_machine_id",
        VM,
        "/providers/" + GUEST + "/",
    ),
    "azurerm_storage_container_immutability_policy": (
        "storage_container_resource_manager_id",
        STORAGE + "/blobservices/containers",
        "/immutabilitypolicies/",
    ),
    "azurerm_management_lock": ("scope", "", "/providers/" + LOCK + "/"),
}


def days(value: Any, minimum: int, maximum: int, *, inherit: bool = False) -> Any:
    if inherit and type(value) is int and value == -1:
        return {"inherits": "parent"}
    if inherit and value == {"inherits": "parent"}:
        return {"inherits": "parent"}
    return (
        value
        if type(value) is int and minimum <= value <= maximum
        else unknown("retention_days_missing_invalid_or_outside_source_range")
    )


def table_facts(value: dict[str, Any]) -> Any:
    source = enumeration(value.get("source"), ("ARM2023-09-01", "AzureRM4.50.0"))
    if not isinstance(source, str):
        return unknown("table_retention_source_not_supported")
    plan = enumeration(value.get("plan"), ("Analytics", "Basic"))
    analytics = days(value.get("analyticsDays"), 4, 730, inherit=source == "ARM2023-09-01")
    total = days(value.get("totalDays"), 4, 4383, inherit=source == "ARM2023-09-01")
    if source == "AzureRM4.50.0" and type(total) is int and total > 730 and total not in TF_TOTAL:
        total = unknown("provider_total_days_not_reviewed_discrete_value")
    if type(analytics) is int and type(total) is int and total < analytics:
        return unknown("total_retention_less_than_analytics")
    if plan != "Analytics":
        analytics = unknown("basic_or_unknown_plan_analytics_not_inferred")
    return {"source": source, "plan": plan, "analyticsDays": analytics, "totalDays": total}


def table_selection(value: Any, *, normalized: bool = False) -> Any:
    if not isinstance(value, list) or not 1 <= len(value) <= 100:
        return unknown("export_tables_missing_empty_or_over_100")
    if any(
        not isinstance(item, str)
        or not re.fullmatch("[0-9a-f]{64}" if normalized else "[A-Za-z0-9_]{1,63}", item)
        for item in value
    ):
        return unknown("export_table_selection_invalid")
    if len(set(value)) != len(value):
        return unknown("export_table_selection_duplicate")
    return sorted(value if normalized else [digest(item) for item in value])


def review_fact(properties: dict[str, Any], path: str) -> Any:
    value = properties.get(path)
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("operations_configuration_not_explicit")
    if path == "operationsTableRetention":
        return table_facts(value)
    if path == "operationsExport":
        return {
            "enabled": boolean(value.get("enabled")),
            "destinationId": typed_reference(value.get("destinationId"), (STORAGE,)),
            "tableFingerprints": table_selection(value.get("tableFingerprints"), normalized=True),
        }
    if path == "operationsImmutability":
        return {
            "days": days(value.get("days"), 1, 146000),
            "state": enumeration(value.get("state"), ("Locked", "Unlocked")),
            "allowProtectedAppendWrites": boolean(value.get("allowProtectedAppendWrites")),
            "allowProtectedAppendWritesAll": boolean(value.get("allowProtectedAppendWritesAll")),
        }
    if path == "operationsGuestAssignment":
        return {
            "assignmentType": enumeration(
                value.get("assignmentType"),
                ("Audit", "ApplyAndMonitor", "ApplyAndAutoCorrect", "DeployAndAutoCorrect"),
            ),
            "kind": enumeration(value.get("kind"), ("DSC",)),
        }
    if path == "operationsArcPatch":
        if value.get("os") not in ("linux", "windows"):
            return unknown("arc_os_not_explicit")
        return {
            "os": enumeration(value.get("os"), ("linux", "windows")),
            "assessmentMode": enumeration(
                value.get("assessmentMode"), ("ImageDefault", "AutomaticByPlatform")
            ),
            "patchMode": enumeration(
                value.get("patchMode"),
                ("ImageDefault", "AutomaticByPlatform", "AutomaticByOS", "Manual"),
            ),
        }
    return {"level": enumeration(value.get("level"), ("CanNotDelete", "ReadOnly"))}


def projected_properties(
    kind: str, values: dict[str, Any], *, terraform: bool = False
) -> dict[str, Any]:
    path = KIND_PATHS.get(kind.lower())
    if path is None:
        return {}
    if kind.lower() == TABLE:
        summary = {
            "source": "AzureRM4.50.0" if terraform else "ARM2023-09-01",
            "plan": values.get("plan"),
            "analyticsDays": values.get("retention_in_days" if terraform else "retentionInDays"),
            "totalDays": values.get(
                "total_retention_in_days" if terraform else "totalRetentionInDays"
            ),
        }
    elif kind.lower() == EXPORT:
        summary = {
            "enabled": values.get("enabled" if terraform else "enable"),
            "destinationId": values.get("destination_resource_id")
            if terraform
            else property_at(values, "destination.resourceId"),
            "tableFingerprints": table_selection(
                values.get("table_names" if terraform else "tableNames")
            ),
        }
    elif kind.lower() == IMMUTABLE:
        locked = values.get("locked")
        summary = {
            "days": values.get(
                "immutability_period_in_days"
                if terraform
                else "immutabilityPeriodSinceCreationInDays"
            ),
            "state": ("Locked" if locked else "Unlocked")
            if terraform and type(locked) is bool
            else None
            if terraform
            else values.get("state"),
            "allowProtectedAppendWrites": values.get(
                "protected_append_writes_enabled" if terraform else "allowProtectedAppendWrites"
            ),
            "allowProtectedAppendWritesAll": values.get(
                "protected_append_writes_all_enabled"
                if terraform
                else "allowProtectedAppendWritesAll"
            ),
        }
    elif kind.lower() == GUEST:
        config = (
            block(values.get("configuration")) if terraform else values.get("guestConfiguration")
        )
        summary = {
            "assignmentType": property_at(
                config, "assignment_type" if terraform else "assignmentType"
            ),
            "kind": None if terraform else property_at(config, "kind"),
        }
    elif kind.lower() == ARC:
        if terraform:
            return {path: unknown("pinned_provider_does_not_expose_arc_patch_settings")}
        os = values.get("osType")
        profile = values.get("osProfile")
        key = (
            {"linux": "linuxConfiguration", "windows": "windowsConfiguration"}.get(os)
            if isinstance(os, str)
            else None
        )
        if (
            not key
            or not isinstance(profile, dict)
            or set(profile).intersection({"linuxConfiguration", "windowsConfiguration"}) != {key}
        ):
            return {path: unknown("arc_os_profile_missing_ambiguous_or_mismatched")}
        summary = {
            "os": os,
            "assessmentMode": property_at(profile, key + ".patchSettings.assessmentMode"),
            "patchMode": property_at(profile, key + ".patchSettings.patchMode"),
        }
    else:
        summary = {"level": values.get("lock_level" if terraform else "level")}
    return {path: review_fact({path: summary}, path)}


def replay_properties(kind: str, values: dict[str, Any]) -> dict[str, Any]:
    path = KIND_PATHS.get(kind.lower())
    return {path: review_fact(values, path)} if path and path in values else {}


def resource_paths(kind: str) -> set[str]:
    path = KIND_PATHS.get(kind.lower())
    if path:
        return {path}
    return {
        WORKSPACE: {"logWorkspaceSummary", "resourceLocation"},
        VM: {"patchConfiguration"},
        FLOW: {
            "enabled",
            "storageId",
            "targetResourceId",
            "trafficAnalytics.enabled",
            "trafficAnalytics.workspaceResourceId",
        },
        ASSIGNMENT: {"policyAssignmentSummary"},
        DEFINITION: {"policyDefinitionSummary"},
        ROLE: {"principalType", "roleDefinitionId"},
    }.get(kind.lower(), set())


def lock_scope(value: Any) -> str | None:
    try:
        identity = canonical_id(value)
    except InputError:
        return None
    parts = identity.split("/")
    if len(parts) == 3 and identity_type(identity) == "microsoft.resources/subscriptions":
        return identity
    if len(parts) == 5 and identity_type(identity) == "microsoft.resources/resourcegroups":
        return identity
    kind = identity_type(identity)
    if (
        len(parts) >= 9
        and parts[1] == "subscriptions"
        and parts[3] == "resourcegroups"
        and parts[5] == "providers"
        and kind
        and len(parts) == 5 + 2 * len(kind.split("/"))
    ):
        return identity
    return None


def terraform_identity(scope: str | None, kind: str, values: dict[str, Any]) -> str | None:
    key, parent_kind, suffix = TF_KINDS[kind]
    parent = (
        lock_scope(values.get(key))
        if not parent_kind
        else typed_reference(values.get(key), (parent_kind,))
    )
    name = (
        "default" if kind == "azurerm_storage_container_immutability_policy" else values.get("name")
    )
    if (
        not isinstance(parent, str)
        or not isinstance(name, str)
        or not re.fullmatch("[A-Za-z0-9_.-]{1,90}", name)
        or not scope
    ):
        return None
    boundary = scope_id(scope)
    if parent == boundary or parent.startswith(boundary + "/"):
        return canonical_id(parent + suffix + name)
    return None


def unique_known(
    resource: dict[str, Any],
    bundle: dict[str, Any],
    by_id: dict[str, list[dict[str, Any]]],
) -> bool:
    if sum(bool(resource_paths(row["resource_type"])) for row in bundle["resources"]) > 100:
        return False
    kind, identity = resource["resource_type"].lower(), resource.get("arm_id")
    if kind in {ASSIGNMENT, DEFINITION, ROLE}:
        return (
            policy_unique(resource, bundle, by_id) and extension_parent(identity, kind) is not None
        )
    if kind not in {LOCK, GUEST}:
        return known_scoped_resource(identity, kind, by_id, bundle) is resource
    parent = extension_parent(identity, kind)
    if parent is None or not policy_unique(resource, bundle, by_id):
        return False
    if kind == LOCK:
        parent_kind = identity_type(parent)
        return lock_scope(parent) is not None and (
            parent_kind
            in {"microsoft.resources/subscriptions", "microsoft.resources/resourcegroups"}
            or known_scoped_resource(parent, parent_kind, by_id, bundle) is not None
        )
    parent_kind = identity_type(parent)
    return (
        parent_kind in {VM, ARC}
        and known_scoped_resource(parent, parent_kind, by_id, bundle) is not None
    )


def configuration_context(
    resource: dict[str, Any],
    bundle: dict[str, Any],
    by_id: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    if not unique_known(resource, bundle, by_id):
        return unknown("operations_resource_not_unique_known_in_selected_scope")
    kind, identity = resource["resource_type"].lower(), resource["arm_id"].lower()
    result: dict[str, Any] = {"warning": WARNING}

    def joined(ref: Any, target_kind: str) -> Any:
        row = known_scoped_resource(ref, target_kind, by_id, bundle)
        return (
            {"arm_id": row["arm_id"], "resource_type": target_kind}
            if row
            else unknown("operations_relationship_not_unique_known_in_selected_scope")
        )

    if kind in {TABLE, EXPORT}:
        parent = identity.rsplit("/tables/" if kind == TABLE else "/dataexports/", 1)[0]
        result["workspace"] = joined(parent, WORKSPACE)
        if kind == EXPORT:
            facts = review_fact(resource["properties"], "operationsExport")
            result["storageDestination"] = joined(facts.get("destinationId"), STORAGE)
            result["containerPolicyBinding"] = unknown(
                "export_account_reference_does_not_identify_effective_container_worm"
            )
    if kind == IMMUTABLE:
        result["storageAccount"] = joined(identity.split("/blobservices/", 1)[0], STORAGE)
        result["coverage"] = unknown("required_data_and_export_container_coverage_not_established")
    if kind in {LOCK, GUEST}:
        parent = extension_parent(identity, kind)
        result["configuredScope"] = parent
        if kind == GUEST:
            result["machine"] = (
                joined(parent, identity_type(parent))
                if parent
                else unknown("guest_machine_scope_not_bound")
            )
        else:
            result["effectiveProtection"] = unknown(
                "criticality_inheritance_and_applicability_require_review"
            )
    if kind == FLOW:
        from .network_evidence import review_fact as network_fact

        for path, target_kind in (
            ("storageId", STORAGE),
            ("trafficAnalytics.workspaceResourceId", WORKSPACE),
        ):
            result[path] = joined(network_fact(resource["properties"], path), target_kind)
        target = network_fact(resource["properties"], "targetResourceId")
        flow_target_kind = identity_type(target) if isinstance(target, str) else None
        result["trafficTarget"] = (
            joined(target, flow_target_kind)
            if flow_target_kind
            in {"microsoft.network/virtualnetworks", "microsoft.network/networksecuritygroups"}
            else unknown("flow_target_type_not_supported")
        )
    if kind in {ASSIGNMENT, DEFINITION}:
        result["policy"] = policy_context(resource, bundle, by_id)
    return result
