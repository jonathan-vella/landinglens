"""Bounded ingress, outbound and hybrid configuration; never effective-path claims."""

from typing import Any, TypeGuard

from .contracts import identity_type
from .sources import boolean, enumeration, property_at, unknown

KINDS = {
    "microsoft.network/frontdoorwebapplicationfirewallpolicies",
    "microsoft.cdn/profiles/securitypolicies",
    "microsoft.network/applicationgateways",
    "microsoft.network/applicationgatewaywebapplicationfirewallpolicies",
    "microsoft.network/publicipaddresses",
    "microsoft.network/networkinterfaces",
}
PATHS = {
    "wafMode",
    "wafEnabled",
    "frontDoorSku",
    "customRuleCount",
    "managedRuleSetCount",
    "wafPolicyId",
    "wafAssociations",
    "fdidRuleSummary",
    "inboundRuleSummary",
    "applicationBackendSummary",
    "ddosProtectionMode",
    "ipConfigurationId",
    "nicIpConfigurations",
    "virtualMachineId",
    "defaultOutboundAccess",
    "ddosLogCategories",
    "diagnosticStorageId",
    "enableBgp",
    "activeActive",
    "routingWeight",
    "expressRouteCircuitId",
    "localNetworkGatewayId",
    "gatewaySku",
    "vpnGatewayGeneration",
}
DDOS_CATEGORIES = (
    "DDoSProtectionNotifications",
    "DDoSMitigationFlowLogs",
    "DDoSMitigationReports",
)
GATEWAY_SKUS = (
    "Basic",
    "Standard",
    "HighPerformance",
    "UltraPerformance",
    "ErGw1AZ",
    "ErGw2AZ",
    "ErGw3AZ",
    "ErGwScale",
    "VpnGw1",
    "VpnGw2",
    "VpnGw3",
    "VpnGw4",
    "VpnGw5",
    "VpnGw1AZ",
    "VpnGw2AZ",
    "VpnGw3AZ",
    "VpnGw4AZ",
    "VpnGw5AZ",
)
REF_TYPES = {
    "wafPolicyId": ("microsoft.network/frontdoorwebapplicationfirewallpolicies",),
    "virtualMachineId": ("microsoft.compute/virtualmachines",),
    "expressRouteCircuitId": ("microsoft.network/expressroutecircuits",),
    "localNetworkGatewayId": ("microsoft.network/localnetworkgateways",),
    "diagnosticStorageId": ("microsoft.storage/storageaccounts",),
    "ipConfigurationId": (
        "microsoft.network/networkinterfaces/ipconfigurations",
        "microsoft.network/applicationgateways/frontendipconfigurations",
        "microsoft.network/loadbalancers/frontendipconfigurations",
        "microsoft.network/virtualnetworkgateways/ipconfigurations",
    ),
}


def typed_reference(value: Any, kinds: tuple[str, ...]) -> Any:
    from .network_evidence import reference

    result = reference(value)
    return (
        result
        if isinstance(result, str) and identity_type(result) in kinds
        else unknown("relationship_missing_invalid_or_wrong_type")
    )


def rows(value: Any, maximum: int = 100) -> TypeGuard[list[dict[str, Any]]]:
    return (
        isinstance(value, list)
        and len(value) <= maximum
        and all(isinstance(row, dict) and "unknown" not in row for row in value)
    )


def object_count(value: Any) -> Any:
    return len(value) if rows(value) else unknown("supplied_objects_missing_invalid_or_over_100")


def block(value: Any) -> dict[str, Any]:
    return value[0] if rows(value, 1) and len(value) == 1 else {}


def association_facts(value: Any) -> Any:
    from .network_evidence import references

    if not rows(value, 20):
        return unknown("waf_associations_missing_invalid_or_over_20")
    result = []
    for row in value:
        domains = references(row.get("domainIds"))
        if isinstance(domains, list):
            domains = [
                typed_reference(
                    domain,
                    ("microsoft.cdn/profiles/customdomains", "microsoft.cdn/profiles/afdendpoints"),
                )
                for domain in domains
            ]
        result.append({"domainIds": domains, "allPaths": boolean(row.get("allPaths"))})
    return result


def nic_facts(value: Any) -> Any:
    if not rows(value, 20):
        return unknown("nic_ip_configurations_missing_invalid_or_over_20")
    return [
        {
            "subnetId": typed_reference(
                row.get("subnetId"), ("microsoft.network/virtualnetworks/subnets",)
            ),
            "publicIpId": typed_reference(
                row.get("publicIpId"), ("microsoft.network/publicipaddresses",)
            ),
        }
        for row in value
    ]


def fdid_facts(value: Any) -> Any:
    from .network_evidence import bounded_count

    if not rows(value):
        return unknown("fdid_rules_missing_invalid_or_over_100")
    return [
        {
            "priority": bounded_count(row.get("priority"), 100)
            if type(row.get("priority")) is int and row["priority"] >= 1
            else unknown("waf_priority_invalid"),
            "action": enumeration(row.get("action"), ("Allow", "Block", "Log", "JSChallenge")),
            "enabled": boolean(row.get("enabled")),
            "fdidConditions": bounded_count(row.get("fdidConditions"), 10),
            "negatedEqualFdidConditions": bounded_count(row.get("negatedEqualFdidConditions"), 10),
        }
        for row in value
    ]


def inbound_facts(value: Any) -> Any:
    from .network_evidence import bounded_count

    if not rows(value):
        return unknown("inbound_rules_missing_invalid_or_over_100")
    return [
        {
            "priority": bounded_count(row.get("priority"), 4096)
            if type(row.get("priority")) is int and row["priority"] >= 100
            else unknown("nsg_priority_invalid"),
            "direction": enumeration(row.get("direction"), ("Inbound", "Outbound")),
            "access": enumeration(row.get("access"), ("Allow", "Deny")),
            "protocol": enumeration(row.get("protocol"), ("Tcp", "Udp", "Icmp", "Esp", "*", "Ah")),
            "source": enumeration(row.get("source"), ("AzureFrontDoor.Backend", "Internet")),
            "destinationPorts": enumeration(row.get("destinationPorts"), ("80", "443", "80,443")),
        }
        for row in value
    ]


def review_fact(properties: dict[str, Any], path: str) -> Any:
    from .network_evidence import bounded_count

    value = property_at(properties, path)
    if path in REF_TYPES:
        return typed_reference(value, REF_TYPES[path])
    if path in {"wafEnabled", "defaultOutboundAccess", "enableBgp", "activeActive"}:
        return boolean(value)
    if path == "wafMode":
        return enumeration(value, ("Detection", "Prevention"))
    if path == "frontDoorSku":
        return enumeration(value, ("Standard_AzureFrontDoor", "Premium_AzureFrontDoor"))
    if path in {"customRuleCount", "managedRuleSetCount"}:
        return bounded_count(value, 100)
    if path == "routingWeight":
        return bounded_count(value, 32000)
    if path == "gatewaySku":
        return enumeration(value, GATEWAY_SKUS)
    if path == "vpnGatewayGeneration":
        return enumeration(value, ("None", "Generation1", "Generation2"))
    if path == "ddosProtectionMode":
        return enumeration(value, ("Disabled", "Enabled", "VirtualNetworkInherited"))
    if path == "wafAssociations":
        return association_facts(value)
    if path == "nicIpConfigurations":
        return nic_facts(value)
    if path == "fdidRuleSummary":
        return fdid_facts(value)
    if path == "inboundRuleSummary":
        return inbound_facts(value)
    if path == "applicationBackendSummary":
        if not rows(value):
            return unknown("backend_summary_missing_invalid_or_over_100")
        return [
            {"suppliedAddressCount": bounded_count(row.get("suppliedAddressCount"), 100)}
            for row in value
        ]
    if path == "ddosLogCategories":
        return {
            category: boolean(value.get(category) if isinstance(value, dict) else None)
            for category in DDOS_CATEGORIES
        }
    return unknown("unreviewed_protection_fact")


def fdid_rules(value: Any, terraform: bool) -> Any:
    if not rows(value):
        return unknown("custom_rules_missing_invalid_or_over_100")
    result = []
    for row in value:
        conditions = row.get("match_conditions" if terraform else "matchConditions")
        known = rows(conditions, 10)
        found, negated = 0, 0
        for condition in conditions if rows(conditions, 10) else []:
            variables = condition.get("match_variables" if terraform else "matchVariables")
            if not rows(variables, 10):
                known = False
                continue
            if not any(
                variable.get("variable_name" if terraform else "variableName") == "RequestHeaders"
                and isinstance(variable.get("selector"), str)
                and variable["selector"].casefold() == "x-azure-fdid"
                for variable in variables
            ):
                continue
            found += 1
            values = condition.get("match_values" if terraform else "matchValues")
            if (
                condition.get("operator") == "Equal"
                and condition.get("negation_condition" if terraform else "negationConditon") is True
                and isinstance(values, list)
                and len(values) == 1
                and isinstance(values[0], str)
                and 1 <= len(values[0]) <= 256
            ):
                negated += 1
        result.append(
            {
                "priority": row.get("priority"),
                "action": row.get("action"),
                "enabled": row.get("enabled")
                if terraform
                else True
                if row.get("state") == "Enabled"
                else False
                if row.get("state") == "Disabled"
                else None,
                "fdidConditions": found if known else None,
                "negatedEqualFdidConditions": negated if known else None,
            }
        )
    return fdid_facts(result)


def log_categories(values: dict[str, Any], terraform: bool) -> dict[str, Any]:
    entries: Any = values.get("enabled_log" if terraform else "logs")
    known = rows(entries)
    result = {}
    for category in DDOS_CATEGORIES:
        matches = [row for row in entries if row.get("category") == category] if known else []
        result[category] = (
            (True if terraform else boolean(matches[0].get("enabled")))
            if len(matches) == 1
            else unknown("exact_log_category_not_unique_explicit")
        )
    return result


def inbound_rules(value: Any, terraform: bool) -> Any:
    if not rows(value):
        return unknown("supplied_rules_missing_invalid_or_over_100")
    result = []
    for row in value:
        body = row if terraform else row.get("properties")
        if not isinstance(body, dict):
            return unknown("rule_body_not_explicit")
        source = body.get("source_address_prefix" if terraform else "sourceAddressPrefix")
        plural = body.get("source_address_prefixes" if terraform else "sourceAddressPrefixes")
        if plural is not None:
            source = None
        port = body.get("destination_port_range" if terraform else "destinationPortRange")
        ports = body.get("destination_port_ranges" if terraform else "destinationPortRanges")
        if port is not None and ports is not None:
            port = None
        elif ports is not None:
            port = (
                "80,443"
                if (
                    isinstance(ports, list)
                    and len(ports) == 2
                    and all(isinstance(p, str) for p in ports)
                    and set(ports) == {"80", "443"}
                )
                else None
            )
        result.append(
            {
                **{key: body.get(key) for key in ("priority", "direction", "access", "protocol")},
                "source": source,
                "destinationPorts": port,
            }
        )
    return inbound_facts(result)


def projected_properties(
    kind: str, values: dict[str, Any], *, terraform: bool, root: Any
) -> dict[str, Any]:
    from .network_evidence import supplied_string_count

    result: dict[str, Any] = {}
    if kind in {
        "microsoft.network/frontdoorwebapplicationfirewallpolicies",
        "microsoft.network/applicationgatewaywebapplicationfirewallpolicies",
    }:
        frontdoor = kind == "microsoft.network/frontdoorwebapplicationfirewallpolicies"
        settings = (
            (values if frontdoor else block(values.get("policy_settings")))
            if terraform
            else values.get("policySettings")
        )
        settings = settings if isinstance(settings, dict) else {}
        result["wafMode"] = settings.get("mode")
        enabled = (
            settings.get("enabled")
            if terraform
            else settings.get("enabledState" if frontdoor else "state")
        )
        result["wafEnabled"] = (
            enabled
            if terraform
            else (True if enabled == "Enabled" else False if enabled == "Disabled" else None)
        )
        result["customRuleCount"] = object_count(
            values.get("custom_rule" if frontdoor else "custom_rules")
            if terraform
            else property_at(values, "customRules.rules")
            if frontdoor
            else values.get("customRules")
        )
        result["managedRuleSetCount"] = object_count(
            values.get("managed_rule")
            if terraform and frontdoor
            else block(values.get("managed_rules")).get("managed_rule_set")
            if terraform
            else property_at(values, "managedRules.managedRuleSets")
        )
        if frontdoor:
            result["frontDoorSku"] = (
                values.get("sku_name") if terraform else property_at(root, "sku.name")
            )
        else:
            result["fdidRuleSummary"] = fdid_rules(
                values.get("custom_rules" if terraform else "customRules"), terraform
            )
    elif kind == "microsoft.cdn/profiles/securitypolicies":
        parameters = (
            block(block(values.get("security_policies")).get("firewall"))
            if terraform
            else values.get("parameters")
        )
        parameters = parameters if isinstance(parameters, dict) else {}
        valid = terraform or parameters.get("type") == "WebApplicationFirewall"
        result["wafPolicyId"] = (
            parameters.get("cdn_frontdoor_firewall_policy_id")
            if terraform
            else property_at(parameters, "wafPolicy.id")
            if valid
            else None
        )
        associations = parameters.get("association" if terraform else "associations")
        prepared = None
        if valid and rows(associations, 20):
            prepared = []
            for row in associations:
                domains = row.get("domain" if terraform else "domains")
                patterns = row.get("patterns_to_match" if terraform else "patternsToMatch")
                prepared.append(
                    {
                        "domainIds": [
                            domain.get("cdn_frontdoor_domain_id" if terraform else "id")
                            for domain in domains
                        ]
                        if rows(domains)
                        else None,
                        "allPaths": "/*" in patterns
                        if isinstance(patterns, list)
                        and isinstance(supplied_string_count(patterns), int)
                        else None,
                    }
                )
        result["wafAssociations"] = association_facts(prepared)
    elif kind == "microsoft.network/applicationgateways":
        configs = values.get("gateway_ip_configuration" if terraform else "gatewayIPConfigurations")
        result["subnetReferences"] = (
            [
                typed_reference(
                    row.get("subnet_id") if terraform else property_at(row, "properties.subnet.id"),
                    ("microsoft.network/virtualnetworks/subnets",),
                )
                for row in configs
            ]
            if rows(configs, 20)
            else unknown("gateway_subnets_not_explicit")
        )
        result["firewallPolicy"] = {
            "id": typed_reference(
                values.get("firewall_policy_id")
                if terraform
                else property_at(values, "firewallPolicy.id"),
                ("microsoft.network/applicationgatewaywebapplicationfirewallpolicies",),
            )
        }
        pools = values.get("backend_address_pool" if terraform else "backendAddressPools")
        result["applicationBackendSummary"] = (
            [
                {
                    "suppliedAddressCount": (
                        supplied_string_count(row.get("fqdns"))
                        + supplied_string_count(row.get("ip_addresses"))
                        if isinstance(supplied_string_count(row.get("fqdns")), int)
                        and isinstance(supplied_string_count(row.get("ip_addresses")), int)
                        else unknown("separate_or_missing_backend_entries")
                    )
                    if terraform
                    else object_count(property_at(row, "properties.backendAddresses"))
                }
                for row in pools
            ]
            if rows(pools)
            else unknown("backend_pools_not_explicit")
        )
    elif kind == "microsoft.network/publicipaddresses":
        result = {
            "ddosProtectionMode": values.get("ddos_protection_mode")
            if terraform
            else property_at(values, "ddosSettings.protectionMode"),
            "ddosProtectionPlan": {
                "id": typed_reference(
                    values.get("ddos_protection_plan_id")
                    if terraform
                    else property_at(values, "ddosSettings.ddosProtectionPlan.id"),
                    ("microsoft.network/ddosprotectionplans",),
                )
            },
            "ipConfigurationId": values.get("ip_configuration_id")
            if terraform
            else property_at(values, "ipConfiguration.id"),
        }
        if terraform:
            result["ipConfigurationId"] = unknown("terraform_ip_attachment_not_exposed")
    elif kind == "microsoft.network/networkinterfaces":
        configs = values.get("ip_configuration" if terraform else "ipConfigurations")
        result["virtualMachineId"] = (
            values.get("virtual_machine_id")
            if terraform
            else property_at(values, "virtualMachine.id")
        )
        result["nicIpConfigurations"] = nic_facts(
            [
                {
                    "subnetId": row.get("subnet_id")
                    if terraform
                    else property_at(row, "properties.subnet.id"),
                    "publicIpId": row.get("public_ip_address_id")
                    if terraform
                    else property_at(row, "properties.publicIPAddress.id"),
                }
                for row in configs
            ]
            if rows(configs, 20)
            else None
        )
    elif kind == "microsoft.network/virtualnetworks/subnets":
        result["defaultOutboundAccess"] = values.get(
            "default_outbound_access_enabled" if terraform else "defaultOutboundAccess"
        )
    elif kind in {
        "microsoft.network/networksecuritygroups",
        "microsoft.network/networksecuritygroups/securityrules",
    }:
        result["inboundRuleSummary"] = inbound_rules(
            [values]
            if terraform and kind.endswith("/securityrules")
            else [{"properties": values}]
            if kind.endswith("/securityrules")
            else values.get("security_rule" if terraform else "securityRules"),
            terraform,
        )
    elif kind == "microsoft.insights/diagnosticsettings":
        result["ddosLogCategories"] = log_categories(values, terraform)
        result["diagnosticStorageId"] = values.get(
            "storage_account_id" if terraform else "storageAccountId"
        )
    elif kind == "microsoft.network/connections":
        result = {
            "enableBgp": values.get("enable_bgp" if terraform else "enableBgp"),
            "routingWeight": values.get("routing_weight" if terraform else "routingWeight"),
            "expressRouteCircuitId": values.get("express_route_circuit_id")
            if terraform
            else property_at(values, "peer.id"),
            "localNetworkGatewayId": values.get("local_network_gateway_id")
            if terraform
            else property_at(values, "localNetworkGateway2.id"),
        }
    elif kind == "microsoft.network/virtualnetworkgateways":
        result = {
            "gatewaySku": values.get("sku") if terraform else property_at(values, "sku.name"),
            "vpnGatewayGeneration": values.get(
                "generation" if terraform else "vpnGatewayGeneration"
            ),
            "enableBgp": values.get("enable_bgp" if terraform else "enableBgp"),
            "activeActive": values.get("active_active" if terraform else "activeActive"),
        }
        if not terraform and result["gatewaySku"] in ("ErGw1Az", "ErGw2Az", "ErGw3Az"):
            result["gatewaySku"] = result["gatewaySku"][:-2] + "AZ"
        if terraform and result["gatewaySku"] == "ErGwScale":
            result["gatewaySku"] = unknown("terraform_ergwscale_not_reviewed")
    for path in set(result) & PATHS:
        result[path] = review_fact(result, path)
    return result
