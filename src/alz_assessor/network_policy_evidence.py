"""Original-time network policy preparation, never effective routing or inspection."""

from typing import Any

from .contracts import canonical_id
from .protection_evidence import rows, typed_reference
from .sources import boolean, enumeration, property_at, unknown

POLICY = "microsoft.network/firewallpolicies"
FIREWALL = "microsoft.network/azurefirewalls"
GATEWAY = "microsoft.network/virtualnetworkgateways"
DIAGNOSTIC = "microsoft.insights/diagnosticsettings"
ALERT = "microsoft.insights/metricalerts"
PARTNER = "microsoft.network/securitypartnerproviders"
GUIDS = {
    "3f79ed00-203b-4c95-9efd-691505f5a1f9",
    "5234c93f-b651-41dd-80c1-234177b91ced",
    "8ac6a9e0-1e6a-483d-b5de-32c199248160",
    "4cc8ca4e-a503-4bac-9b1e-82283a711043",
    "8b517d94-c9d0-42c4-9803-d93ed0a46bc0",
    "e6c4cfd3-e504-4547-a244-7ec66138a720",
    "5a4b1511-e43a-458a-ac22-99c4d7b57d0c",
    "655562f2-b3e4-4563-a4d8-739748b662d6",
    "14d99880-2f88-47e8-a134-62a7d85c94af",
}
PATHS = {
    "basePolicy.id",
    "dnsSettings.enableProxy",
    "allowRemoteVnetTraffic",
    "allowVirtualWanTraffic",
    "gatewayDiagnosticSummary",
    "gatewayMetricAlertSummary",
    "fqdnRuleSummary",
    "partnerConfiguration",
}
GATEWAY_METRICS = (
    "ExpressRouteGatewayBitsPerSecond",
    "ExpressRouteGatewayCpuUtilization",
    "ExpressRouteGatewayPacketsPerSecond",
    "ExpressRouteGatewayCountOfRoutesAdvertisedToPeer",
    "ExpressRouteGatewayCountOfRoutesLearnedFromPeer",
    "ExpressRouteGatewayFrequencyOfRoutesChanged",
    "ExpressRouteGatewayNumberOfVmInVnet",
    "ExpressRouteGatewayActiveFlows",
    "ExpressRouteGatewayMaxFlowsCreationRate",
    "ScalableExpressRouteGatewayBitsPerSecond",
    "ScalableExpressRouteGatewayCpuUtilization",
    "ScalableExpressRouteGatewayPacketsPerSecond",
    "ScalableExpressRouteGatewayActiveFlows",
    "ScalableExpressRouteGatewayCountOfRoutesAdvertisedToPeer",
    "ScalableExpressRouteGatewayCountOfRoutesLearnedFromPeer",
    "ScalableExpressRouteGatewayFrequencyOfRoutesChanged",
    "ScalableExpressRouteGatewayMaxFlowsCreationRate",
    "ScalableExpressRouteGatewayNumberOfVmInVnet",
)


def diagnostic_facts(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("gateway_diagnostic_summary_not_explicit")
    logs = value.get("logs")
    prepared: Any = unknown("gateway_log_population_missing_invalid_or_over_100")
    if rows(logs):
        prepared, seen = [], set()
        for row in logs:
            category, group = row.get("category"), row.get("categoryGroup")
            if (category is None) == (group is None):
                return unknown("gateway_log_category_missing_or_ambiguous")
            label = enumeration(
                category if category is not None else group,
                (
                    "GatewayDiagnosticLog",
                    "RouteDiagnosticLog",
                    "IKEDiagnosticLog",
                    "P2SDiagnosticLog",
                    "TunnelDiagnosticLog",
                )
                if category is not None
                else ("allLogs", "audit"),
            )
            if not isinstance(label, str) or (category is not None, label) in seen:
                return unknown("gateway_log_category_duplicate_or_unsupported")
            seen.add((category is not None, label))
            prepared.append(
                {
                    "category" if category is not None else "categoryGroup": label,
                    "enabled": boolean(row.get("enabled")),
                }
            )
    return {
        "logs": prepared,
        "workspaceId": typed_reference(
            value.get("workspaceId"), ("microsoft.operationalinsights/workspaces",)
        ),
        "storageAccountId": typed_reference(
            value.get("storageAccountId"), ("microsoft.storage/storageaccounts",)
        ),
    }


def gateway_alert_facts(value: Any) -> Any:
    from .monitoring_evidence import alert_facts

    result = alert_facts(value, gateway=True)
    if isinstance(result, dict):
        refs = result.get("gatewayIds")
        if isinstance(refs, list) and (
            any(not isinstance(ref, str) for ref in refs)
            or len(set(ref for ref in refs if isinstance(ref, str))) != len(refs)
        ):
            result["gatewayIds"] = unknown("gateway_alert_scope_invalid_or_duplicate")
    return result


def partner_facts(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("partner_configuration_not_explicit")
    return {
        "schemaProviderName": enumeration(
            value.get("schemaProviderName"), ("ZScaler", "IBoss", "CheckPoint")
        ),
        "virtualHubId": typed_reference(
            value.get("virtualHubId"), ("microsoft.network/virtualhubs",)
        ),
        "current_service_support": unknown("historical_schema_enum_not_current_service_support"),
    }


def fqdn_facts(value: Any) -> Any:
    from .network_evidence import egress_facts

    facts = egress_facts(value)
    if not isinstance(facts, list):
        return facts
    for fact, row in zip(facts, value, strict=True):
        protocols = row.get("protocols")
        allowed = (
            ("Http", "Https", "Mssql")
            if fact["kind"] == "ApplicationRule"
            else ("TCP", "UDP", "ICMP", "Any")
        )
        fact["protocols"] = (
            [enumeration(item, allowed) for item in protocols]
            if isinstance(protocols, list) and 1 <= len(protocols) <= 10
            else unknown("fqdn_rule_protocols_missing_invalid_or_over_10")
        )
    return facts


def fqdn_rules(values: dict[str, Any], *, terraform: bool) -> Any:
    from .network_evidence import egress_rules

    facts = egress_rules(values, terraform=terraform)
    if not isinstance(facts, list):
        return facts
    if terraform:
        groups = [
            row
            for key in ("application_rule_collection", "network_rule_collection")
            for row in (values.get(key) or [])
        ]
    else:
        groups = values["ruleCollections"]
    rules = [
        row
        for group in groups
        for row in group["rule" if terraform else "rules"]
        if terraform or row.get("ruleType") != "NatRule"
    ]
    for fact, row in zip(facts, rules, strict=True):
        protocols = row.get(
            "protocols" if terraform or fact["kind"] == "ApplicationRule" else "ipProtocols"
        )
        fact["protocols"] = (
            [item.get("type" if terraform else "protocolType") for item in protocols]
            if fact["kind"] == "ApplicationRule" and rows(protocols, 10)
            else protocols
            if fact["kind"] == "NetworkRule"
            else None
        )
    return fqdn_facts(facts)


def review_fact(properties: dict[str, Any], path: str) -> Any:
    value = property_at(properties, path)
    if path == "basePolicy.id":
        return typed_reference(value, (POLICY,))
    if path == "gatewayDiagnosticSummary":
        return diagnostic_facts(value)
    if path == "gatewayMetricAlertSummary":
        return gateway_alert_facts(value)
    if path == "fqdnRuleSummary":
        return fqdn_facts(value)
    if path == "partnerConfiguration":
        return partner_facts(value)
    return boolean(value)


def projected_properties(
    kind: str, values: dict[str, Any], *, terraform: bool = False
) -> dict[str, Any]:
    kind = kind.lower()
    if kind == PARTNER and not terraform:
        return {
            "partnerConfiguration": partner_facts(
                {
                    "schemaProviderName": values.get("securityProviderName"),
                    "virtualHubId": property_at(values, "virtualHub.id"),
                }
            )
        }
    if kind == POLICY:
        return {
            "basePolicy": {
                "id": typed_reference(
                    values.get("base_policy_id")
                    if terraform
                    else property_at(values, "basePolicy.id"),
                    (POLICY,),
                )
            }
        }
    if kind == GATEWAY:
        return {
            path: boolean(values.get(tf_path if terraform else path))
            for path, tf_path in (
                ("allowRemoteVnetTraffic", "remote_vnet_traffic_enabled"),
                ("allowVirtualWanTraffic", "virtual_wan_traffic_enabled"),
            )
        }
    if kind == POLICY + "/rulecollectiongroups":
        return {"fqdnRuleSummary": fqdn_rules(values, terraform=terraform)}
    if kind == DIAGNOSTIC:
        logs = values.get("enabled_log") if terraform else values.get("logs")
        return {
            "gatewayDiagnosticSummary": diagnostic_facts(
                {
                    "logs": [
                        {
                            "category": row.get("category"),
                            "categoryGroup": row.get("category_group"),
                            "enabled": True,
                        }
                        for row in logs
                    ]
                    if terraform and rows(logs)
                    else logs,
                    "workspaceId": values.get("log_analytics_workspace_id")
                    if terraform
                    else values.get("workspaceId"),
                    "storageAccountId": values.get("storage_account_id")
                    if terraform
                    else values.get("storageAccountId"),
                }
            )
        }
    return {}


def unique_known(
    identity: Any, kind: str, bundle: dict[str, Any], by_id: dict[str, list[dict[str, Any]]]
) -> dict[str, Any] | None:
    from .governance_evidence import resource_in_scope

    ref = typed_reference(identity, (kind,))
    matches = by_id.get(ref, []) if isinstance(ref, str) else []
    if (
        len(matches) != 1
        or matches[0]["state"] != "known"
        or matches[0]["resource_type"].lower() != kind
        or not resource_in_scope(matches[0], bundle)
    ):
        return None
    return matches[0]


def policy_context(
    firewall: dict[str, Any],
    bundle: dict[str, Any],
    by_id: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    identity = firewall.get("arm_id")
    if unique_known(identity, FIREWALL, bundle, by_id) is not firewall:
        return unknown("firewall_not_unique_known_in_selected_scope")
    ref = typed_reference(property_at(firewall["properties"], "firewallPolicy.id"), (POLICY,))
    chain: list[dict[str, Any]] = []
    seen: set[str] = set()
    for _ in range(20):
        policy = unique_known(ref, POLICY, bundle, by_id)
        if policy is None:
            return {
                "policies": chain,
                "termination": unknown("parent_or_associated_policy_missing_ambiguous_or_unbound"),
            }
        identity = canonical_id(policy["arm_id"])
        if identity in seen:
            return unknown("policy_inheritance_cycle")
        seen.add(identity)
        chain.append(
            {
                "arm_id": identity,
                "dns_proxy_explicit": boolean(
                    property_at(policy["properties"], "dnsSettings.enableProxy")
                ),
                "local_rule_groups": policy_rule_context(identity, bundle, by_id),
            }
        )
        ref = review_fact(policy["properties"], "basePolicy.id")
        if not isinstance(ref, str):
            return {
                "policies": chain,
                "termination": unknown("base_policy_not_explicit_no_root_inferred"),
            }
    return unknown("policy_chain_over_20")


def policy_rule_context(
    identity: str, bundle: dict[str, Any], by_id: dict[str, list[dict[str, Any]]]
) -> Any:
    kind = POLICY + "/rulecollectiongroups"
    groups = [row for row in bundle["resources"] if row["resource_type"].lower() == kind]
    if len(groups) > 100:
        return unknown("policy_rule_group_population_over_100")
    linked, unresolved = [], 0
    for row in groups:
        ref = typed_reference(row.get("arm_id"), (kind,))
        if unique_known(ref, kind, bundle, by_id) is not row:
            unresolved += 1
        elif isinstance(ref, str) and ref.rsplit("/rulecollectiongroups/", 1)[0] == identity:
            linked.append(
                {"arm_id": ref, "rules": review_fact(row["properties"], "fqdnRuleSummary")}
            )
    return {
        "groups": linked,
        "unresolved_groups": unresolved,
        "coverage": unknown("supplied_local_groups_not_complete_or_effective_inherited_rules"),
    }


def gateway_context(
    gateway: dict[str, Any],
    bundle: dict[str, Any],
    by_id: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    from .governance_evidence import resource_in_scope

    identity = gateway.get("arm_id")
    if (
        not isinstance(identity, str)
        or unique_known(identity, GATEWAY, bundle, by_id) is not gateway
        or property_at(gateway["properties"], "gatewayType") != "ExpressRoute"
    ):
        return unknown("expressroute_gateway_not_unique_known_in_selected_scope")
    diagnostics, alerts = [], []
    related = [
        row for row in bundle["resources"] if row["resource_type"].lower() in (DIAGNOSTIC, ALERT)
    ]
    if len(related) > 100:
        return unknown("gateway_monitoring_population_over_100")
    unresolved = 0
    for row in related:
        kind = row["resource_type"].lower()
        if unique_known(row.get("arm_id"), kind, bundle, by_id) is not row or not resource_in_scope(
            row, bundle
        ):
            unresolved += 1
            continue
        if kind == DIAGNOSTIC:
            target = typed_reference(property_at(row["properties"], "targetResourceId"), (GATEWAY,))
            if not isinstance(target, str):
                unresolved += 1
            elif target == canonical_id(identity):
                diagnostics.append(
                    {
                        "arm_id": canonical_id(row["arm_id"]),
                        "configuration": review_fact(row["properties"], "gatewayDiagnosticSummary"),
                    }
                )
        else:
            fact = gateway_alert_facts(property_at(row["properties"], "gatewayMetricAlertSummary"))
            refs = fact.get("gatewayIds") if isinstance(fact, dict) else None
            if not isinstance(refs, list) or any(not isinstance(ref, str) for ref in refs):
                unresolved += 1
            elif canonical_id(identity) in refs:
                alerts.append({"arm_id": canonical_id(row["arm_id"]), "configuration": fact})
    return {
        "diagnostics": diagnostics,
        "metric_alerts": alerts,
        "unresolved_monitoring_resources": unresolved,
        "coverage": unknown("supplied_configuration_not_complete_coverage_or_health"),
        "category_applicability": unknown("shared_gateway_log_index_not_expressroute_support"),
    }
