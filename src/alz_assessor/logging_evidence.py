"""Minimized logging preparation, never ingestion, correlation or support-access assurance."""

from typing import Any

from .contracts import canonical_id, identity_type, scope_id
from .protection_evidence import rows, typed_reference
from .sources import boolean, enumeration, property_at, unknown
from .terraform import InputError

WORKSPACE = "microsoft.operationalinsights/workspaces"
ONBOARDING = "microsoft.securityinsights/onboardingstates"
LOG_ALERT = "microsoft.insights/scheduledqueryrules"
METRIC_ALERT = "microsoft.insights/metricalerts"
TOPIC = "microsoft.eventgrid/topics"
DIAGNOSTIC = "microsoft.insights/diagnosticsettings"
PATHS = {
    "logWorkspaceSummary",
    "sentinelOnboardingSummary",
    "logAlertSummary",
    "eventGridTopicSummary",
    "eventGridMetricAlertSummary",
}
GUIDS = {
    "e5f8d79f-2e87-4768-924c-516775c6ea95",
    "a56888b2-7e83-4404-bd31-b886528502d1",
    "d21a922d-5ca7-427a-82a6-35f7b21f1bfc",
    "874a748b-662d-46d1-9051-2a66498f6dfe",
    "6f704104-85c1-441f-96d3-c9819911645e",
    "9a19bf39-c95d-444c-9c89-19ca1f6d5215",
    "ae514b93-3d45-485e-8112-9bd7ba012f7b",
}
SKUS = (
    "Free",
    "Standard",
    "Premium",
    "PerNode",
    "PerGB2018",
    "Standalone",
    "CapacityReservation",
    "LACluster",
    "Unlimited",
)
TOPIC_METRICS = ("DeadLetteredCount", "DeliveryAttemptFailCount", "PublishFailCount")
DURATIONS = ("PT1M", "PT5M", "PT10M", "PT15M", "PT30M", "PT1H", "PT6H", "PT12H", "P1D", "P2D")


def references(value: Any, kind: str, *, empty: bool = False) -> Any:
    if not isinstance(value, list) or not (0 if empty else 1) <= len(value) <= 100:
        return unknown("logging_references_missing_empty_or_over_100")
    prepared = [typed_reference(item, (kind,)) for item in value]
    if any(not isinstance(item, str) for item in prepared):
        return unknown("logging_reference_type_invalid_or_unresolved")
    if len(set(prepared)) != len(prepared):
        return unknown("logging_references_duplicate")
    return prepared


def workspace_facts(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("log_workspace_configuration_not_explicit")
    days = value.get("retentionInDays")
    return {
        "sku": enumeration(value.get("sku"), SKUS),
        "retentionInDays": days
        if type(days) is int and 30 <= days <= 730
        else unknown("workspace_retention_missing_or_outside_reviewed_range"),
        "publicNetworkAccessForIngestion": enumeration(
            value.get("publicNetworkAccessForIngestion"), ("Enabled", "Disabled")
        ),
        "publicNetworkAccessForQuery": enumeration(
            value.get("publicNetworkAccessForQuery"), ("Enabled", "Disabled")
        ),
    }


def onboarding_facts(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("sentinel_onboarding_configuration_not_explicit")
    return {"customerManagedKey": boolean(value.get("customerManagedKey"))}


def topic_facts(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("event_grid_topic_configuration_not_explicit")
    return {
        "inputSchema": enumeration(
            value.get("inputSchema"),
            ("EventGridSchema", "CustomEventSchema", "CloudEventSchemaV1_0"),
        ),
        "publicNetworkAccess": enumeration(
            value.get("publicNetworkAccess"), ("Enabled", "Disabled")
        ),
    }


def log_alert_facts(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("log_alert_configuration_not_explicit")
    count = value.get("conditionCount")
    return {
        "kind": enumeration(value.get("kind"), ("LogAlert",)),
        "enabled": boolean(value.get("enabled")),
        "workspaceIds": references(value.get("workspaceIds"), WORKSPACE),
        "evaluationFrequency": enumeration(value.get("evaluationFrequency"), DURATIONS),
        "windowSize": enumeration(value.get("windowSize"), DURATIONS),
        "conditionCount": count
        if type(count) is int and 1 <= count <= 100
        else unknown("log_alert_conditions_missing_empty_or_over_100"),
        "actionIds": references(
            value.get("actionIds"), "microsoft.insights/actiongroups", empty=True
        ),
    }


def metric_alert_facts(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("event_grid_metric_alert_configuration_not_explicit")
    criteria = value.get("criteria")
    topics = references(value.get("topicIds"), TOPIC)
    return {
        "enabled": boolean(value.get("enabled")),
        "topicIds": topics
        if isinstance(topics, list) and len(topics) == 1
        else unknown("event_grid_metric_requires_one_custom_topic"),
        "criteria": [
            {
                "metricNamespace": enumeration(
                    row.get("metricNamespace"), ("Microsoft.EventGrid/topics",)
                ),
                "metricName": enumeration(row.get("metricName"), TOPIC_METRICS),
                "timeAggregation": enumeration(row.get("timeAggregation"), ("Total",)),
            }
            for row in criteria
        ]
        if rows(criteria) and criteria and isinstance(topics, list) and len(topics) == 1
        else unknown("event_grid_metric_criteria_unsupported"),
        "actionIds": references(
            value.get("actionIds"), "microsoft.insights/actiongroups", empty=True
        ),
    }


FACTS = {
    "logWorkspaceSummary": workspace_facts,
    "sentinelOnboardingSummary": onboarding_facts,
    "logAlertSummary": log_alert_facts,
    "eventGridTopicSummary": topic_facts,
    "eventGridMetricAlertSummary": metric_alert_facts,
}
KIND_PATHS = {
    WORKSPACE: "logWorkspaceSummary",
    ONBOARDING: "sentinelOnboardingSummary",
    LOG_ALERT: "logAlertSummary",
    TOPIC: "eventGridTopicSummary",
    METRIC_ALERT: "eventGridMetricAlertSummary",
}


def resource_paths(kind: str) -> set[str]:
    if kind.lower() == DIAGNOSTIC:
        return {
            "targetResourceId",
            "workspaceId",
            "activityLogRouting",
            "logAnalyticsDestinationType",
        }
    path = KIND_PATHS.get(kind.lower())
    return {path} if path else set()


def review_fact(properties: dict[str, Any], path: str) -> Any:
    return FACTS[path](properties.get(path))


def projected_properties(
    kind: str, values: dict[str, Any], *, root: Any = None, terraform: bool = False
) -> dict[str, Any]:
    kind = kind.lower()
    if kind == WORKSPACE:

        def network_flag(key: str) -> Any:
            value = values.get(key)
            return ("Enabled" if value else "Disabled") if type(value) is bool else None

        sku = values.get("sku") if terraform else property_at(values, "sku.name")
        if (
            not terraform
            and isinstance(root, dict)
            and root.get("apiVersion") == "2025-07-01"
            and (
                not isinstance(sku, str)
                or sku
                not in {
                    "CapacityReservation",
                    "Free",
                    "LACluster",
                    "PerGB2018",
                    "PerNode",
                    "Premium",
                    "Standalone",
                    "Standard",
                }
            )
        ):
            sku = unknown("workspace_sku_outside_reviewed_api_subset")
        return {
            "logWorkspaceSummary": workspace_facts(
                {
                    "sku": sku,
                    "retentionInDays": values.get(
                        "retention_in_days" if terraform else "retentionInDays"
                    ),
                    "publicNetworkAccessForIngestion": network_flag("internet_ingestion_enabled")
                    if terraform
                    else values.get("publicNetworkAccessForIngestion"),
                    "publicNetworkAccessForQuery": network_flag("internet_query_enabled")
                    if terraform
                    else values.get("publicNetworkAccessForQuery"),
                }
            )
        }
    if kind == ONBOARDING:
        return {
            "sentinelOnboardingSummary": onboarding_facts(
                {
                    "customerManagedKey": values.get(
                        "customer_managed_key_enabled" if terraform else "customerManagedKey"
                    )
                }
            )
        }
    if terraform:
        return {}
    if kind == TOPIC:
        return {"eventGridTopicSummary": topic_facts(values)}
    if kind == LOG_ALERT:
        conditions = property_at(values, "criteria.allOf")
        return {
            "logAlertSummary": log_alert_facts(
                {
                    "kind": root.get("kind") if isinstance(root, dict) else None,
                    "enabled": values.get("enabled"),
                    "workspaceIds": values.get("scopes"),
                    "evaluationFrequency": values.get("evaluationFrequency"),
                    "windowSize": values.get("windowSize"),
                    "conditionCount": len(conditions) if rows(conditions) and conditions else None,
                    "actionIds": property_at(values, "actions.actionGroups"),
                }
            )
        }
    if kind == METRIC_ALERT:
        criteria = values.get("criteria")
        all_of = property_at(values, "criteria.allOf")
        supported = (
            isinstance(criteria, dict)
            and criteria.get("odata.type")
            == "Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria"
            and rows(all_of)
            and all_of
            and all(row.get("criterionType") == "StaticThresholdCriterion" for row in all_of)
            and isinstance(values.get("scopes"), list)
            and len(values["scopes"]) == 1
        )
        actions = values.get("actions")
        return {
            "eventGridMetricAlertSummary": metric_alert_facts(
                {
                    "enabled": values.get("enabled"),
                    "topicIds": values.get("scopes"),
                    "criteria": all_of if supported else None,
                    "actionIds": [row.get("actionGroupId") for row in actions]
                    if rows(actions)
                    else None,
                }
            )
        }
    return {}


def replay_properties(kind: str, values: dict[str, Any]) -> dict[str, Any]:
    path = KIND_PATHS.get(kind.lower())
    return {path: review_fact(values, path)} if path and path in values else {}


def scoped_identity(resource: dict[str, Any], scope: str | None) -> str | None:
    identity = resource.get("arm_id")
    if not isinstance(identity, str) or not isinstance(scope, str):
        return None
    try:
        boundary, identity = scope_id(scope), canonical_id(identity)
    except InputError:
        return None
    if not boundary.startswith("/subscriptions/") or not identity.startswith(boundary + "/"):
        return None
    return identity if identity_type(identity) == resource["resource_type"].lower() else None


def linked_context(
    resource: dict[str, Any], by_id: dict[str, list[dict[str, Any]]], scope: str | None
) -> dict[str, Any]:
    """Only join supplied unique known in-bound records, not an estate coverage predicate."""
    identity = scoped_identity(resource, scope)
    if not identity or resource["state"] != "known" or len(by_id.get(identity, [])) != 1:
        return unknown("logging_source_not_unique_known_typed_in_scope")
    kind, values = resource["resource_type"].lower(), resource["properties"]
    refs: Any = []
    target_kind = WORKSPACE
    if kind == DIAGNOSTIC:
        from .network_evidence import reference

        target = reference(values.get("targetResourceId"))
        actual = identity.rsplit("/providers/microsoft.insights/diagnosticsettings/", 1)[0]
        if target != actual:
            return unknown("diagnostic_target_identity_mismatch")
        refs = [typed_reference(values.get("workspaceId"), (WORKSPACE,))]
    elif kind == ONBOARDING:
        suffix = "/providers/microsoft.securityinsights/onboardingstates/default"
        if not identity.endswith(suffix):
            return unknown("sentinel_onboarding_requires_default_workspace_extension")
        refs = [typed_reference(identity[: -len(suffix)], (WORKSPACE,))]
    elif kind == LOG_ALERT:
        refs = review_fact(values, "logAlertSummary").get("workspaceIds")
    elif kind == METRIC_ALERT:
        refs = review_fact(values, "eventGridMetricAlertSummary").get("topicIds")
        target_kind = TOPIC
    else:
        return {"links": [], "warning": "Configuration only; no runtime assurance."}
    if not isinstance(refs, list) or not refs:
        return unknown("logging_relationships_not_explicit")
    links: list[dict[str, Any]] = []
    for ref in refs:
        matches = by_id.get(ref, []) if isinstance(ref, str) else []
        if (
            len(matches) != 1
            or matches[0]["state"] != "known"
            or matches[0]["resource_type"].lower() != target_kind
            or scoped_identity(matches[0], scope) != ref
        ):
            links.append({"unknown": "logging_target_not_unique_known_typed_in_scope"})
        else:
            path = KIND_PATHS[target_kind]
            links.append(
                {"arm_id": ref, "facts": {path: review_fact(matches[0]["properties"], path)}}
            )
    return {
        "links": links,
        "warning": "Supplied configuration links only; not ingestion, correlation, detection, "
        "delivery latency, tenant equivalence, complete coverage or support approval.",
    }
