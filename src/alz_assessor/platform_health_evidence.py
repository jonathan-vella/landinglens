"""Offline monitoring configuration, never emitted events or operational assurance."""

from typing import Any

from .contracts import canonical_id, identity_type
from .logging_evidence import LOG_ALERT, METRIC_ALERT, WORKSPACE, references, scoped_identity
from .policy_strategy_evidence import ASSIGNMENT, DEFINITION, INITIATIVE
from .protection_evidence import rows
from .sources import boolean, enumeration, property_at, unknown
from .terraform import InputError

ACTIVITY_ALERT = "microsoft.insights/activitylogalerts"
ACTION_GROUP = "microsoft.insights/actiongroups"
STORAGE = "microsoft.storage/storageaccounts"
GUIDS = {
    "e5695f22-23ac-4e8c-a123-08ca5017f154",
    "d5f345bf-97ab-41a7-819c-6104baa7d48c",
    "e3ab3693-829e-47e3-8618-3687a0477a20",
    "6944008b-e7d7-4e48-9327-6d8bdc055bcf",
    "619e8a13-f988-4795-85d6-26886d70ba6c",
    "97be9951-9048-4384-9c98-6cb2913156a1",
    "859c3900-4514-41eb-b010-475d695abd74",
    "aa45be6a-8f2d-4896-b0e3-775e6e94e610",
    "0d83fd81-952c-4d47-a6cb-3a930925ef2e",
}
CATEGORIES = (
    "Administrative",
    "Autoscale",
    "Policy",
    "Recommendation",
    "ResourceHealth",
    "Security",
    "ServiceHealth",
)
SKUS = {
    "Standard_LRS": "local",
    "Standard_ZRS": "zone",
    "Standard_GRS": "region",
    "Standard_RAGRS": "region",
    "Standard_GZRS": "zone_and_region",
    "Standard_RAGZRS": "zone_and_region",
    "Premium_LRS": "local",
    "Premium_ZRS": "zone",
}
RECEIVERS = {
    "email": ("emailReceivers", "email_receiver"),
    "sms": ("smsReceivers", "sms_receiver"),
    "voice": ("voiceReceivers", "voice_receiver"),
    "appPush": ("azureAppPushReceivers", "azure_app_push_receiver"),
    "armRole": ("armRoleReceivers", "arm_role_receiver"),
    "runbook": ("automationRunbookReceivers", "automation_runbook_receiver"),
    "function": ("azureFunctionReceivers", "azure_function_receiver"),
    "eventHub": ("eventHubReceivers", "event_hub_receiver"),
    "itsm": ("itsmReceivers", "itsm_receiver"),
    "logicApp": ("logicAppReceivers", "logic_app_receiver"),
    "webhook": ("webhookReceivers", "webhook_receiver"),
}
WARNING = (
    "Supplied original-time configuration only; not event emission, recipient verification, "
    "notification delivery, response, log ingestion/report quality, absence of export, "
    "AMBA origin/version/remediation/complete coverage, availability, failover or residency."
)


def count(value: Any, *, minimum: int = 0, maximum: int = 100) -> Any:
    return (
        value
        if type(value) is int and minimum <= value <= maximum
        else unknown("platform_count_missing_invalid_or_over_bound")
    )


def object_count(value: Any) -> Any:
    return (
        len(value)
        if rows(value) and all("unknown" not in row for row in value)
        else unknown("platform_array_missing_invalid_or_over_100")
    )


def scopes(value: Any) -> Any:
    if not isinstance(value, list) or not 1 <= len(value) <= 100:
        return unknown("alert_scopes_missing_empty_or_over_100")
    try:
        result = [canonical_id(item) for item in value]
    except InputError:
        return unknown("alert_scope_not_literal_arm_identity")
    if any(not item.startswith("/subscriptions/") for item in result):
        return unknown("alert_scope_not_subscription_bound")
    return result if len(set(result)) == len(result) else unknown("alert_scopes_duplicate")


def action_ids(value: Any) -> Any:
    result = references(value, ACTION_GROUP, empty=True)
    return (
        unknown("alert_actions_over_five")
        if isinstance(result, list) and len(result) > 5
        else result
    )


def activity_facts(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("activity_alert_configuration_not_explicit")
    return {
        "enabled": boolean(value.get("enabled")),
        "category": enumeration(value.get("category"), CATEGORIES),
        "conditionCount": count(value.get("conditionCount"), minimum=1),
        "scopes": scopes(value.get("scopes")),
        "actionIds": action_ids(value.get("actionIds")),
    }


def action_facts(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("action_group_configuration_not_explicit")
    counts = value.get("receiverCounts")
    return {
        "enabled": boolean(value.get("enabled")),
        "globalProcessing": boolean(value.get("globalProcessing")),
        "receiverCounts": {
            key: count(counts.get(key) if isinstance(counts, dict) else None) for key in RECEIVERS
        },
    }


def metric_facts(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("operational_metric_configuration_not_explicit")
    return {
        "enabled": boolean(value.get("enabled")),
        "scopes": scopes(value.get("scopes")),
        "staticConditionCount": count(value.get("staticConditionCount"), minimum=1),
        "evaluationFrequency": enumeration(
            value.get("evaluationFrequency"), ("PT1M", "PT5M", "PT15M", "PT30M", "PT1H")
        ),
        "windowSize": enumeration(
            value.get("windowSize"),
            ("PT1M", "PT5M", "PT15M", "PT30M", "PT1H", "PT6H", "PT12H", "P1D"),
        ),
        "actionIds": action_ids(value.get("actionIds")),
    }


def storage_facts(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("storage_redundancy_configuration_not_explicit")
    sku = enumeration(value.get("sku"), tuple(SKUS))
    return {
        "sku": sku,
        "kind": enumeration(
            value.get("kind"),
            ("Storage", "StorageV2", "BlobStorage", "BlockBlobStorage", "FileStorage"),
        ),
        "configuredRedundancy": SKUS[sku] if isinstance(sku, str) else sku,
    }


FACTS = {
    "activityAlertSummary": activity_facts,
    "actionGroupSummary": action_facts,
    "operationalMetricAlertSummary": metric_facts,
    "storageRedundancySummary": storage_facts,
}
PATHS = set(FACTS)
KIND_PATHS = {
    ACTIVITY_ALERT: "activityAlertSummary",
    ACTION_GROUP: "actionGroupSummary",
    METRIC_ALERT: "operationalMetricAlertSummary",
    STORAGE: "storageRedundancySummary",
    WORKSPACE: "logWorkspaceSummary",
    LOG_ALERT: "logAlertSummary",
    DEFINITION: "policyDefinitionSummary",
    INITIATIVE: "policyInitiativeSummary",
    ASSIGNMENT: "policyAssignmentSummary",
}


def resource_paths(kind: str) -> set[str]:
    path = KIND_PATHS.get(kind.lower())
    return {path} if path else set()


def review_fact(properties: dict[str, Any], path: str) -> Any:
    return FACTS[path](properties.get(path))


def projected_properties(
    kind: str, values: dict[str, Any], *, root: Any = None, terraform: bool = False
) -> dict[str, Any]:
    kind = kind.lower()
    if kind == STORAGE:
        tier, replication = values.get("account_tier"), values.get("account_replication_type")
        sku = (
            f"{tier}_{replication}"
            if isinstance(tier, str) and isinstance(replication, str)
            else None
        )
        return {
            "storageRedundancySummary": storage_facts(
                {
                    "sku": sku if terraform else property_at(root, "sku.name"),
                    "kind": values.get("account_kind") if terraform else property_at(root, "kind"),
                }
            )
        }
    if kind == ACTION_GROUP:
        location = values.get("location") if terraform else property_at(root, "location")
        return {
            "actionGroupSummary": action_facts(
                {
                    "enabled": values.get("enabled"),
                    "globalProcessing": location.lower() == "global"
                    if isinstance(location, str)
                    and 1 <= len(location) <= 80
                    and location.replace(" ", "").isalnum()
                    else None,
                    "receiverCounts": {
                        key: object_count(values.get(tf if terraform else arm))
                        for key, (arm, tf) in RECEIVERS.items()
                    },
                }
            )
        }
    if kind == ACTIVITY_ALERT:
        conditions = values.get("criteria") if terraform else property_at(values, "condition.allOf")
        category: Any = None
        if terraform and rows(conditions) and len(conditions) == 1:
            category = conditions[0].get("category")
        elif not terraform and rows(conditions) and conditions:
            categories = [
                row
                for row in conditions
                if isinstance(row.get("field"), str) and row["field"].lower() == "category"
            ]
            if len(categories) == 1 and set(categories[0]) == {"field", "equals"}:
                category = categories[0]["equals"]
        actions = values.get("action") if terraform else property_at(values, "actions.actionGroups")
        return {
            "activityAlertSummary": activity_facts(
                {
                    "enabled": values.get("enabled"),
                    "category": category,
                    "conditionCount": unknown("terraform_criteria_block_not_arm_condition_count")
                    if terraform
                    else object_count(conditions),
                    "scopes": values.get("scopes"),
                    "actionIds": [
                        row.get("action_group_id" if terraform else "actionGroupId")
                        for row in actions
                    ]
                    if rows(actions)
                    else None,
                }
            )
        }
    if kind == METRIC_ALERT:
        conditions = values.get("criteria") if terraform else property_at(values, "criteria.allOf")
        supported = (
            rows(conditions)
            and bool(conditions)
            and (
                not any(
                    key in values
                    for key in (
                        "dynamic_criteria",
                        "application_insights_web_test_location_availability_criteria",
                    )
                )
                if terraform
                else (
                    values.get("criteria", {}).get("odata.type")
                    == "Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria"
                    and all(
                        row.get("criterionType") == "StaticThresholdCriterion" for row in conditions
                    )
                )
            )
            and isinstance(values.get("scopes"), list)
            and len(values["scopes"]) == 1
        )
        actions = values.get("action" if terraform else "actions")
        return {
            "operationalMetricAlertSummary": metric_facts(
                {
                    "enabled": values.get("enabled"),
                    "scopes": values.get("scopes"),
                    "staticConditionCount": object_count(conditions) if supported else None,
                    "evaluationFrequency": values.get(
                        "frequency" if terraform else "evaluationFrequency"
                    ),
                    "windowSize": values.get("window_size" if terraform else "windowSize"),
                    "actionIds": [
                        row.get("action_group_id" if terraform else "actionGroupId")
                        for row in actions
                    ]
                    if rows(actions)
                    else None,
                }
            )
        }
    return {}


def replay_properties(kind: str, values: dict[str, Any]) -> dict[str, Any]:
    path = KIND_PATHS.get(kind.lower())
    return {path: review_fact(values, path)} if path in PATHS and path in values else {}


def linked_context(
    resource: dict[str, Any], by_id: dict[str, list[dict[str, Any]]], scope: str | None
) -> dict[str, Any]:
    identity = scoped_identity(resource, scope)
    if not identity or resource["state"] != "known" or len(by_id.get(identity, [])) != 1:
        return unknown("platform_source_not_unique_known_typed_in_scope")
    path = KIND_PATHS.get(resource["resource_type"].lower())
    if path not in {"activityAlertSummary", "operationalMetricAlertSummary", "logAlertSummary"}:
        return {"actionGroups": [], "warning": WARNING}
    if path == "logAlertSummary":
        from .logging_evidence import review_fact as logging_fact

        facts = logging_fact(resource["properties"], path)
    else:
        facts = review_fact(resource["properties"], path)
    ids = action_ids(facts.get("actionIds"))
    if not isinstance(ids, list):
        return unknown("platform_action_references_missing_invalid_or_over_five")
    links: list[dict[str, Any]] = []
    for ref in ids:
        candidates = by_id.get(ref, [])
        if (
            len(candidates) != 1
            or candidates[0]["state"] != "known"
            or candidates[0]["resource_type"].lower() != ACTION_GROUP
            or identity_type(ref) != ACTION_GROUP
            or scoped_identity(candidates[0], scope) != ref
        ):
            links.append(unknown("platform_action_not_unique_known_typed_in_scope"))
        else:
            links.append(
                {
                    "arm_id": ref,
                    "facts": review_fact(candidates[0]["properties"], "actionGroupSummary"),
                }
            )
    targets: list[dict[str, Any]] = []
    configured = scopes(facts.get("scopes" if path != "logAlertSummary" else "workspaceIds"))
    if isinstance(configured, list):
        for ref in configured:
            if identity_type(ref) in {
                "microsoft.resources/subscriptions",
                "microsoft.resources/resourcegroups",
            }:
                targets.append(
                    {
                        "configuredScope": ref,
                        "coverage": unknown("scope_configuration_not_resource_population"),
                    }
                )
                continue
            matches = by_id.get(ref, [])
            if (
                len(matches) != 1
                or matches[0]["state"] != "known"
                or scoped_identity(matches[0], scope) != ref
            ):
                targets.append(unknown("platform_target_not_unique_known_typed_in_scope"))
            else:
                targets.append({"arm_id": ref, "resource_type": matches[0]["resource_type"]})
    return {
        "actionGroups": links,
        "configuredTargets": targets if isinstance(configured, list) else configured,
        "warning": WARNING,
    }
