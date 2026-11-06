"""Minimized monitoring configuration, never probe health, ingestion or failover."""

from typing import Any

from .network_evidence import bounded_count
from .protection_evidence import rows, typed_reference
from .sources import boolean, enumeration, property_at, unknown

KINDS = {
    "microsoft.network/networkwatchers/connectionmonitors",
    "microsoft.insights/metricalerts",
}
PATHS = {"connectionMonitorSummary", "expressRouteAlertSummary"}
ENDPOINT_TYPES = (
    "AzureVM",
    "AzureVNet",
    "AzureSubnet",
    "ExternalAddress",
    "MMAWorkspaceMachine",
    "MMAWorkspaceNetwork",
    "AzureArcVM",
    "AzureVMSS",
    "AzureArcNetwork",
)
METRICS = (
    "ArpAvailability",
    "BgpAvailability",
    "BitsInPerSecond",
    "BitsOutPerSecond",
    "IngressBandwidthUtilization",
    "EgressBandwidthUtilization",
    "QosDropBitsInPerSecond",
    "QosDropBitsOutPerSecond",
)


def names(value: Any) -> Any:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= 100
        or any(not isinstance(item, str) or not item.strip() or len(item) > 256 for item in value)
        or len(set(value)) != len(value)
    ):
        return unknown("monitor_names_missing_duplicate_invalid_or_over_100")
    return value


def frequency(value: Any) -> Any:
    return (
        value
        if type(value) is int and 30 <= value <= 1800
        else unknown("monitor_frequency_not_explicit_supported_30_to_1800")
    )


def monitor_facts(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("connection_monitor_summary_not_explicit")
    endpoints, configs, groups = (
        value.get("endpointTypes"),
        value.get("testConfigurations"),
        value.get("testGroups"),
    )
    if (
        not isinstance(endpoints, list)
        or not 1 <= len(endpoints) <= 100
        or not rows(configs)
        or not configs
        or not rows(groups)
        or not groups
    ):
        return unknown("monitor_population_missing_invalid_empty_or_over_100")
    outputs = value.get("workspaceIds")
    return {
        "endpointTypes": [enumeration(item, ENDPOINT_TYPES) for item in endpoints],
        "testConfigurations": [
            {
                "protocol": enumeration(row.get("protocol"), ("Tcp", "Http", "Icmp")),
                "testFrequencySec": frequency(row.get("testFrequencySec")),
            }
            for row in configs
        ],
        "testGroups": [
            {
                "disable": boolean(row.get("disable")),
                "sourceCount": bounded_count(row.get("sourceCount"), 100),
                "destinationCount": bounded_count(row.get("destinationCount"), 100),
                "testConfigurationCount": bounded_count(row.get("testConfigurationCount"), 100),
                "referencesResolved": boolean(row.get("referencesResolved")),
            }
            for row in groups
        ],
        "workspaceIds": [
            typed_reference(item, ("microsoft.operationalinsights/workspaces",)) for item in outputs
        ]
        if isinstance(outputs, list) and len(outputs) <= 100
        else unknown("monitor_outputs_missing_invalid_or_over_100"),
    }


def monitor_properties(values: dict[str, Any], terraform: bool) -> Any:
    endpoints = values.get("endpoint" if terraform else "endpoints")
    configs = values.get("test_configuration" if terraform else "testConfigurations")
    groups = values.get("test_group" if terraform else "testGroups")
    if (
        not rows(endpoints)
        or not endpoints
        or not rows(configs)
        or not configs
        or not rows(groups)
        or not groups
    ):
        return unknown("monitor_population_missing_invalid_empty_or_over_100")
    endpoint_names = names([row.get("name") for row in endpoints])
    config_names = names([row.get("name") for row in configs])
    group_names = names([row.get("name") for row in groups])
    if any(
        isinstance(population, dict) for population in (endpoint_names, config_names, group_names)
    ):
        return unknown("monitor_names_missing_duplicate_invalid_or_over_100")
    prepared = []
    for group in groups:
        refs = [
            names(group.get(tf_key if terraform else arm_key))
            for tf_key, arm_key in (
                ("source_endpoints", "sources"),
                ("destination_endpoints", "destinations"),
                ("test_configuration_names", "testConfigurations"),
            )
        ]
        resolved = (
            all(name in endpoint_names for ref in refs[:2] for name in ref)
            and all(name in config_names for name in refs[2])
            if all(isinstance(ref, list) for ref in refs)
            else unknown("monitor_group_references_not_explicit")
        )
        enabled = group.get("enabled")
        prepared.append(
            {
                "disable": not enabled
                if terraform and type(enabled) is bool
                else unknown("monitor_group_enabled_not_explicit")
                if terraform
                else group.get("disable"),
                **{
                    key: len(ref) if isinstance(ref, list) else ref
                    for key, ref in zip(
                        ("sourceCount", "destinationCount", "testConfigurationCount"),
                        refs,
                        strict=True,
                    )
                },
                "referencesResolved": resolved,
            }
        )
    outputs = values.get("outputs")
    return monitor_facts(
        {
            "endpointTypes": [
                row.get("target_resource_type" if terraform else "type") for row in endpoints
            ],
            "testConfigurations": [
                {
                    "protocol": row.get("protocol"),
                    "testFrequencySec": row.get(
                        "test_frequency_in_seconds" if terraform else "testFrequencySec"
                    ),
                }
                for row in configs
            ],
            "testGroups": prepared,
            "workspaceIds": values.get("output_workspace_resource_ids")
            if terraform
            else [
                property_at(row, "workspaceSettings.workspaceResourceId")
                if row.get("type") == "Workspace"
                else unknown("monitor_output_type_unsupported")
                for row in outputs
            ]
            if rows(outputs)
            else None,
        }
    )


def alert_facts(value: Any, *, gateway: bool = False) -> Any:
    from .network_policy_evidence import GATEWAY_METRICS

    if not isinstance(value, dict) or "unknown" in value:
        return unknown("expressroute_alert_summary_not_explicit")
    scopes, criteria, actions = (
        value.get("gatewayIds" if gateway else "circuitIds"),
        value.get("criteria"),
        value.get("actionIds"),
    )
    return {
        "enabled": boolean(value.get("enabled")),
        "gatewayIds" if gateway else "circuitIds": [
            typed_reference(
                item,
                ("microsoft.network/virtualnetworkgateways",)
                if gateway
                else ("microsoft.network/expressroutecircuits",),
            )
            for item in scopes
        ]
        if isinstance(scopes, list) and 1 <= len(scopes) <= 100
        else unknown("alert_scopes_missing_invalid_empty_or_over_100"),
        "criteria": [
            {
                "metricName": enumeration(
                    row.get("metricName"), GATEWAY_METRICS if gateway else METRICS
                ),
                "metricNamespace": enumeration(
                    row.get("metricNamespace"),
                    ("Microsoft.Network/virtualNetworkGateways",)
                    if gateway
                    else ("Microsoft.Network/expressRouteCircuits",),
                ),
                "timeAggregation": enumeration(
                    row.get("timeAggregation"), ("Average", "Count", "Minimum", "Maximum", "Total")
                ),
            }
            for row in criteria
        ]
        if rows(criteria) and criteria and isinstance(scopes, list) and len(scopes) == 1
        else unknown("alert_criteria_missing_or_unsupported"),
        "actionIds": [
            typed_reference(item, ("microsoft.insights/actiongroups",)) for item in actions
        ]
        if isinstance(actions, list) and len(actions) <= 100
        else unknown("alert_actions_missing_invalid_or_over_100"),
    }


def review_fact(properties: dict[str, Any], path: str) -> Any:
    value = property_at(properties, path)
    return monitor_facts(value) if path == "connectionMonitorSummary" else alert_facts(value)


def projected_properties(kind: str, values: dict[str, Any], *, terraform: bool) -> dict[str, Any]:
    if kind == "microsoft.network/networkwatchers/connectionmonitors":
        return {"connectionMonitorSummary": monitor_properties(values, terraform)}
    if kind == "microsoft.insights/metricalerts" and not terraform:
        criteria = values.get("criteria")
        all_of = criteria.get("allOf") if isinstance(criteria, dict) else None
        supported = (
            isinstance(criteria, dict)
            and criteria.get("odata.type")
            == "Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria"
            and rows(all_of)
            and all_of
            and all(row.get("criterionType") == "StaticThresholdCriterion" for row in all_of)
        )
        actions = values.get("actions")
        return {
            name: alert_facts(
                {
                    "enabled": values.get("enabled"),
                    "gatewayIds" if gateway else "circuitIds": values.get("scopes"),
                    "criteria": all_of if supported else None,
                    "actionIds": [row.get("actionGroupId") for row in actions]
                    if rows(actions)
                    else None,
                },
                gateway=gateway,
            )
            for name, gateway in (
                ("expressRouteAlertSummary", False),
                ("gatewayMetricAlertSummary", True),
            )
        }
    return {}
