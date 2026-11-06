"""Bounded typed network facts for review; no effective-path or policy claims."""

from ipaddress import ip_address, ip_network
from typing import Any

from .contracts import canonical_id, identity_type
from .dns_evidence import KINDS as DNS_KINDS
from .dns_evidence import PATHS as DNS_PATHS
from .expressroute_evidence import CIRCUIT_KIND, PORT_KIND
from .expressroute_evidence import PATHS as EXPRESSROUTE_PATHS
from .governance_evidence import PATHS as GOVERNANCE_PATHS
from .identity_evidence import PATHS as IDENTITY_PATHS
from .protection_evidence import KINDS as PROTECTION_KINDS
from .protection_evidence import PATHS as PROTECTION_PATHS
from .routing_evidence import KINDS as ROUTING_KINDS
from .routing_evidence import PATHS as ROUTING_PATHS
from .security_evidence import PATHS as SECURITY_PATHS
from .sources import boolean, enumeration, property_at, unknown
from .tenant_evidence import PATHS as TENANT_PATHS
from .terraform import InputError
from .virtual_wan_evidence import KINDS as VWAN_KINDS
from .virtual_wan_evidence import PATHS as VWAN_PATHS

REVIEW_PATHS = (
    {
        "sku.tier",
        "sku.name",
        "subnetReferences",
        "firewallPolicy.id",
        "addressPrefixes",
        "routeTable.id",
        "natGateway.id",
        "targetResourceId",
        "workspaceId",
        "logAnalyticsDestinationType",
        "natRuleCollections",
        "ipAddresses",
        "configuredZones",
        "applicationRules",
        "enableDdosProtection",
        "ddosProtectionPlan.id",
        "privateConnections",
        "subnet.id",
        "networkSecurityGroup.id",
        "serviceEndpointCount",
        "serviceEndpointNetworkIdentifiers",
        "privateEndpointNetworkPolicies",
        "gatewayType",
        "securityRuleCount",
        "securityRuleSummary",
        "defaultRuleSummary",
        "egressRules",
        "enabled",
        "storageId",
        "trafficAnalytics.enabled",
        "trafficAnalytics.workspaceResourceId",
        "filteringConfigured",
    }
    | ROUTING_PATHS
    | IDENTITY_PATHS
    | EXPRESSROUTE_PATHS
    | SECURITY_PATHS
    | PROTECTION_PATHS
    | GOVERNANCE_PATHS
    | TENANT_PATHS
    | {"connectionMonitorSummary", "expressRouteAlertSummary"}
    | DNS_PATHS
    | VWAN_PATHS
)


def bounded_count(value: Any, maximum: int) -> Any:
    return (
        value
        if type(value) is int and 0 <= value <= maximum
        else unknown("count_missing_unresolved_or_invalid")
    )


def supplied_string_count(value: Any) -> Any:
    if (
        not isinstance(value, list)
        or len(value) > 100
        or any(not isinstance(item, str) or not item.strip() or len(item) > 253 for item in value)
    ):
        return unknown("string_list_missing_invalid_or_over_100")
    return len(value)


def asg_references(value: Any) -> Any:
    result = references(value)
    if not isinstance(result, list) or len(result) > 10:
        return unknown("asg_references_missing_invalid_or_over_10")
    return [
        item
        if isinstance(item, str)
        and identity_type(item) == "microsoft.network/applicationsecuritygroups"
        else unknown("asg_reference_wrong_type")
        for item in result
    ]


def virtual_network_tag(singular: Any, plural: Any) -> Any:
    if singular is not None and plural is not None:
        return unknown("conflicting_address_prefix_fields")
    entries = [singular] if singular is not None else plural
    if isinstance(supplied_string_count(entries), dict):
        return unknown("address_prefix_entries_not_explicit")
    return any(item.casefold() == "virtualnetwork" for item in entries)


def rule_summary_facts(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("rule_summary_not_explicit")
    count, rules = value.get("suppliedCount"), value.get("rules")
    if (
        type(count) is not int
        or not 0 <= count <= 2000
        or not isinstance(rules, list)
        or len(rules) != min(count, 20)
        or type(value.get("truncated")) is not bool
        or value["truncated"] != (count > 20)
    ):
        return unknown("rule_summary_invalid_or_over_bound")
    result = []
    for rule in rules:
        if not isinstance(rule, dict):
            return unknown("rule_summary_entry_not_object")
        priority = rule.get("priority")
        result.append(
            {
                "priority": priority
                if type(priority) is int and 100 <= priority <= 65500
                else unknown("rule_priority_not_explicit"),
                "direction": enumeration(rule.get("direction"), ("Inbound", "Outbound")),
                "access": enumeration(rule.get("access"), ("Allow", "Deny")),
                "sourceVirtualNetwork": boolean(rule.get("sourceVirtualNetwork")),
                "destinationVirtualNetwork": boolean(rule.get("destinationVirtualNetwork")),
                "sourceAsgs": asg_references(rule.get("sourceAsgs")),
                "destinationAsgs": asg_references(rule.get("destinationAsgs")),
            }
        )
    return {"suppliedCount": count, "truncated": count > 20, "rules": result}


def rule_summary(value: Any, *, terraform: bool) -> Any:
    if not isinstance(value, list) or len(value) > 2000:
        return unknown("rules_missing_or_over_2000")
    result: list[dict[str, Any]] = []
    for rule in value[:20]:
        body = rule if terraform else rule.get("properties") if isinstance(rule, dict) else None
        if not isinstance(body, dict):
            result.append({})
            continue
        summary = {key: body.get(key) for key in ("priority", "direction", "access")}
        for side in ("source", "destination"):
            summary[side + "VirtualNetwork"] = virtual_network_tag(
                body.get(side + "_address_prefix" if terraform else side + "AddressPrefix"),
                body.get(side + "_address_prefixes" if terraform else side + "AddressPrefixes"),
            )
            groups = body.get(
                side + "_application_security_group_ids"
                if terraform
                else side + "ApplicationSecurityGroups"
            )
            summary[side + "Asgs"] = (
                groups
                if terraform
                else [group.get("id") if isinstance(group, dict) else None for group in groups]
                if isinstance(groups, list) and len(groups) <= 10
                else None
            )
        result.append(summary)
    return rule_summary_facts(
        {"suppliedCount": len(value), "truncated": len(value) > 20, "rules": result}
    )


def observed_rule_count(values: dict[str, Any], *, observed: bool) -> Any:
    rules = values.get("securityRules")
    if (
        not observed
        or values.get("provisioningState") != "Succeeded"
        or not isinstance(rules, list)
        or len(rules) > 2000
    ):
        return unknown("complete_succeeded_observed_custom_rules_required")
    names, priorities = set(), set()
    for rule in rules:
        body = rule.get("properties") if isinstance(rule, dict) else None
        name = rule.get("name") if isinstance(rule, dict) else None
        if (
            not isinstance(body, dict)
            or not isinstance(name, str)
            or not name.strip()
            or len(name) > 256
        ):
            return unknown("custom_rule_identity_or_body_invalid")
        priority, direction = body.get("priority"), body.get("direction")
        if (
            type(priority) is not int
            or not 100 <= priority <= 4096
            or not isinstance(direction, str)
            or direction not in ("Inbound", "Outbound")
            or body.get("access") not in ("Allow", "Deny")
            or body.get("protocol") not in ("Tcp", "Udp", "Icmp", "Esp", "*", "Ah")
            or body.get("provisioningState", "Succeeded") != "Succeeded"
            or name.casefold() in names
            or (direction, priority) in priorities
        ):
            return unknown("custom_rules_invalid_duplicate_or_transient")
        names.add(name.casefold())
        priorities.add((direction, priority))
    return len(rules)


def egress_facts(value: Any) -> Any:
    if not isinstance(value, list) or len(value) > 100:
        return unknown("egress_rules_missing_or_over_100")
    result = []
    for rule in value:
        if not isinstance(rule, dict):
            return unknown("egress_rule_not_object")
        result.append(
            {
                "kind": enumeration(rule.get("kind"), ("ApplicationRule", "NetworkRule")),
                "action": enumeration(rule.get("action"), ("Allow", "Deny")),
                "fqdnCount": bounded_count(rule.get("fqdnCount"), 100),
                "ipv4AddressCount": bounded_count(rule.get("ipv4AddressCount"), 100),
            }
        )
    return result


def egress_rules(values: dict[str, Any], *, terraform: bool) -> Any:
    collections = values.get("ruleCollections")
    if terraform:
        application = values.get("application_rule_collection")
        network = values.get("network_rule_collection")
        if application is None and network is None:
            return unknown("egress_collections_not_explicit")
        if any(
            items is not None and not isinstance(items, list) for items in (application, network)
        ):
            return unknown("egress_collections_not_explicit")
        collections = [
            {"kind": kind, "action": entry.get("action"), "rules": entry.get("rule")}
            if isinstance(entry, dict)
            else None
            for kind, entries in (
                ("ApplicationRule", application or []),
                ("NetworkRule", network or []),
            )
            for entry in entries[:21]
        ]
    if not isinstance(collections, list) or len(collections) > 20:
        return unknown("egress_collections_missing_or_over_20")
    result = []
    for collection in collections:
        if not isinstance(collection, dict):
            return unknown("egress_collection_not_object")
        rules, action = collection.get("rules"), collection.get("action")
        action = action if terraform else action.get("type") if isinstance(action, dict) else None
        if not isinstance(rules, list) or len(rules) > 100:
            return unknown("egress_rules_missing_or_over_100")
        for rule in rules:
            if not isinstance(rule, dict):
                return unknown("egress_rule_not_object")
            kind = collection.get("kind") if terraform else rule.get("ruleType")
            if kind == "NatRule":
                continue
            addresses = address_list(
                rule.get("destination_addresses" if terraform else "destinationAddresses"),
                wildcards=True,
            )
            result.append(
                {
                    "kind": kind,
                    "action": action,
                    "fqdnCount": supplied_string_count(
                        rule.get("destination_fqdns" if terraform else "destinationFqdns")
                        if kind == "NetworkRule"
                        else rule.get("destination_fqdns" if terraform else "targetFqdns")
                    ),
                    "ipv4AddressCount": len(addresses)
                    if isinstance(addresses, list) and all(isinstance(a, str) for a in addresses)
                    else unknown("destination_ipv4_entries_not_explicit"),
                }
            )
            if len(result) > 100:
                return unknown("egress_rules_missing_or_over_100")
    return egress_facts(result)


def reference(value: Any) -> Any:
    if not isinstance(value, str):
        return unknown("relationship_identity_not_explicit")
    try:
        return canonical_id(value)
    except InputError:
        return unknown("relationship_identity_invalid")


def address(value: Any, *, prefix_only: bool = False, wildcards: bool = False) -> Any:
    if not isinstance(value, str):
        return unknown("ip_address_or_prefix_not_explicit")
    if wildcards and not prefix_only and value.lower() in {"*", "any"}:
        return value.lower()
    try:
        if "/" in value:
            parsed = ip_network(value, strict=True)
            return str(parsed) if parsed.version == 4 else unknown("ipv6_not_reviewed")
        if not prefix_only and "-" in value:
            first, last = (ip_address(part) for part in value.split("-"))
            if first.version == last.version == 4 and int(first) <= int(last):
                return f"{first}-{last}"
        elif not prefix_only:
            single = ip_address(value)
            if single.version == 4:
                return str(single)
    except ValueError:
        return unknown("ip_address_or_prefix_invalid")
    return unknown("ip_address_or_prefix_not_reviewed")


def address_list(value: Any, *, prefix_only: bool = False, wildcards: bool = False) -> Any:
    if not isinstance(value, list) or len(value) > 100:
        return unknown("address_list_missing_or_over_100")
    return [address(item, prefix_only=prefix_only, wildcards=wildcards) for item in value]


def references(value: Any) -> Any:
    if not isinstance(value, list) or len(value) > 100:
        return unknown("reference_list_missing_or_over_100")
    return [reference(item) for item in value]


def nat_collections(value: Any) -> Any:
    if not isinstance(value, list) or len(value) > 20:
        return unknown("nat_collections_missing_or_over_20")
    result = []
    for collection in value:
        body = collection.get("properties") if isinstance(collection, dict) else None
        if not isinstance(body, dict):
            return unknown("nat_collection_not_object")
        rules = body.get("rules")
        if not isinstance(rules, list) or len(rules) > 100:
            return unknown("nat_rules_missing_or_over_100")
        action = body.get("action")
        result.append(
            {
                "properties": {
                    "action": {
                        "type": enumeration(
                            action.get("type") if isinstance(action, dict) else None,
                            ("Dnat", "Snat"),
                        )
                    },
                    "rules": [
                        {
                            "sourceAddresses": address_list(
                                rule.get("sourceAddresses"), wildcards=True
                            ),
                            "sourceIpGroups": references(rule.get("sourceIpGroups")),
                        }
                        if isinstance(rule, dict)
                        else {"unknown": "nat_rule_not_object"}
                        for rule in rules
                    ],
                }
            }
        )
    return result


def configured_zones(value: Any) -> Any:
    if (
        not isinstance(value, list)
        or len(value) > 3
        or any(not isinstance(item, str) or item not in {"1", "2", "3"} for item in value)
        or len(set(value)) != len(value)
    ):
        return unknown("configured_zones_not_explicit_or_invalid")
    return value


def category_count(value: Any) -> Any:
    if (
        not isinstance(value, list)
        or len(value) > 100
        or any(not isinstance(item, str) or not item.strip() or len(item) > 128 for item in value)
    ):
        return unknown("category_list_missing_invalid_or_over_100")
    return len(value)


def application_facts(value: Any) -> Any:
    if not isinstance(value, list) or len(value) > 100:
        return unknown("application_rules_missing_or_over_100")
    result: list[dict[str, Any]] = []
    for rule in value:
        if not isinstance(rule, dict) or "unknown" in rule:
            result.append(unknown("application_rule_not_explicit"))
            continue
        count = rule.get("webCategoryCount")
        result.append(
            {
                "action": enumeration(rule.get("action"), ("Allow", "Deny")),
                "terminateTLS": boolean(rule.get("terminateTLS")),
                "webCategoryCount": count
                if type(count) is int and 0 <= count <= 100
                else unknown("category_count_not_explicit"),
            }
        )
    return result


def application_rules(values: dict[str, Any], *, terraform: bool) -> Any:
    collections = values.get("application_rule_collection" if terraform else "ruleCollections")
    if not isinstance(collections, list) or len(collections) > 20:
        return unknown("application_collections_missing_or_over_20")
    result: list[dict[str, Any]] = []
    for collection in collections:
        if not isinstance(collection, dict):
            return unknown("application_collection_not_object")
        rules = collection.get("rule" if terraform else "rules")
        if not isinstance(rules, list) or len(rules) > 100:
            return unknown("collection_rules_missing_or_over_100")
        action = collection.get("action")
        action = action if terraform else action.get("type") if isinstance(action, dict) else None
        for rule in rules:
            if not isinstance(rule, dict):
                result.append(unknown("application_rule_not_explicit"))
            elif not terraform and rule.get("ruleType") in ("NetworkRule", "NatRule"):
                continue
            elif not terraform and rule.get("ruleType") != "ApplicationRule":
                result.append(unknown("application_rule_not_explicit"))
            else:
                result.append(
                    {
                        "action": action,
                        "terminateTLS": rule.get("terminate_tls" if terraform else "terminateTLS"),
                        "webCategoryCount": category_count(
                            rule.get("web_categories" if terraform else "webCategories")
                        ),
                    }
                )
            if len(result) > 100:
                return unknown("application_rules_missing_or_over_100")
    return application_facts(result)


def private_connection_facts(value: Any) -> Any:
    if not isinstance(value, list) or len(value) > 20:
        return unknown("private_connections_missing_or_over_20")
    result = []
    for connection in value:
        if not isinstance(connection, dict):
            return unknown("private_connection_not_object")
        result.append(
            {
                "resourceId": reference(connection.get("resourceId")),
                "status": enumeration(
                    connection.get("status"), ("Approved", "Pending", "Rejected", "Disconnected")
                ),
            }
        )
    return result


def private_connections(values: dict[str, Any], *, terraform: bool) -> Any:
    if terraform:
        connections = values.get("private_service_connection")
        if (
            not isinstance(connections, list)
            or len(connections) != 1
            or not isinstance(connections[0], dict)
        ):
            return unknown("terraform_service_connection_not_explicit")
        connection = connections[0]
        alias = connection.get("private_connection_resource_alias")
        target = (
            reference(connection.get("private_connection_resource_id"))
            if alias is None
            else unknown("private_target_alias_or_conflicting_binding")
        )
        return [{"resourceId": target, "status": unknown("terraform_approval_state_not_exposed")}]
    fields = ("privateLinkServiceConnections", "manualPrivateLinkServiceConnections")
    if not any(key in values for key in fields):
        return unknown("private_connections_not_supplied")
    result = []
    for key in fields:
        if key not in values:
            continue
        entries = values[key]
        if not isinstance(entries, list) or len(entries) > 20:
            return unknown("private_connections_missing_or_over_20")
        for entry in entries:
            body = entry.get("properties") if isinstance(entry, dict) else None
            if not isinstance(body, dict):
                return unknown("private_connection_not_object")
            result.append(
                {
                    "resourceId": body.get("privateLinkServiceId"),
                    "status": property_at(body, "privateLinkServiceConnectionState.status"),
                }
            )
            if len(result) > 20:
                return unknown("private_connections_missing_or_over_20")
    return private_connection_facts(result)


def review_fact(properties: dict[str, Any], path: str) -> Any:
    if path in TENANT_PATHS:
        from .tenant_evidence import review_fact as tenant_fact

        return tenant_fact(properties, path)
    if path in VWAN_PATHS:
        from .virtual_wan_evidence import review_fact as vwan_fact

        return vwan_fact(properties, path)
    if path in GOVERNANCE_PATHS:
        from .governance_evidence import review_fact as governance_fact

        return governance_fact(properties, path)
    if path in {"connectionMonitorSummary", "expressRouteAlertSummary"}:
        from .monitoring_evidence import review_fact as monitoring_fact

        return monitoring_fact(properties, path)
    if path in DNS_PATHS:
        from .dns_evidence import review_fact as dns_fact

        return dns_fact(properties, path)
    if path in EXPRESSROUTE_PATHS:
        from .expressroute_evidence import review_fact as expressroute_fact

        return expressroute_fact(properties, path)
    if path in SECURITY_PATHS:
        from .security_evidence import review_fact as security_fact

        return security_fact(properties, path)
    if path in PROTECTION_PATHS:
        from .protection_evidence import review_fact as protection_fact

        return protection_fact(properties, path)
    if path in IDENTITY_PATHS:
        from .identity_evidence import review_fact as identity_fact

        return identity_fact(properties, path)
    if path in ROUTING_PATHS:
        from .routing_evidence import review_fact as routing_fact

        return routing_fact(properties, path)
    value = property_at(properties, path)
    if path == "sku.tier":
        return enumeration(value, ("Basic", "Standard", "Premium"))
    if path == "sku.name":
        return enumeration(value, ("AZFW_Hub", "AZFW_VNet"))
    if path == "subnetReferences":
        return references(value)
    if path == "addressPrefixes":
        return address_list(value, prefix_only=True)
    if path == "ipAddresses":
        return address_list(value)
    if path == "natRuleCollections":
        return nat_collections(value)
    if path == "logAnalyticsDestinationType":
        return enumeration(value, ("Dedicated", "AzureDiagnostics"))
    if path == "configuredZones":
        return configured_zones(value)
    if path == "applicationRules":
        return application_facts(value)
    if path == "enableDdosProtection":
        return boolean(value)
    if path == "privateConnections":
        return private_connection_facts(value)
    if path == "securityRuleCount":
        return bounded_count(value, 2000)
    if path == "serviceEndpointCount":
        return bounded_count(value, 100)
    if path == "serviceEndpointNetworkIdentifiers":
        return references(value)
    if path == "privateEndpointNetworkPolicies":
        return enumeration(
            value, ("Disabled", "Enabled", "NetworkSecurityGroupEnabled", "RouteTableEnabled")
        )
    if path == "gatewayType":
        return enumeration(value, ("Vpn", "ExpressRoute"))
    if path in {"securityRuleSummary", "defaultRuleSummary"}:
        return rule_summary_facts(value)
    if path == "egressRules":
        return egress_facts(value)
    if path in {"enabled", "trafficAnalytics.enabled", "filteringConfigured"}:
        return boolean(value)
    return reference(value)


def projected_properties(
    kind: str,
    values: dict[str, Any],
    *,
    terraform: bool = False,
    root: Any = None,
    observed: bool = False,
) -> dict[str, Any]:
    from .dns_evidence import projected_properties as dns_properties
    from .monitoring_evidence import projected_properties as monitoring_properties
    from .protection_evidence import projected_properties as protection_properties
    from .virtual_wan_evidence import projected_properties as vwan_properties

    result = (
        _projected_properties(kind, values, terraform=terraform, root=root, observed=observed)
        | protection_properties(kind.lower(), values, terraform=terraform, root=root)
        | dns_properties(kind.lower(), values, terraform=terraform, root=root)
        | monitoring_properties(kind.lower(), values, terraform=terraform)
        | vwan_properties(kind.lower(), values, terraform=terraform, root=root)
    )
    if kind.lower() == "microsoft.network/connections":
        from .expressroute_evidence import fastpath_properties

        result.update(fastpath_properties(values, terraform=terraform))
    if kind.lower() == "microsoft.network/virtualnetworkgateways":
        from .expressroute_evidence import gateway_properties

        result.update(gateway_properties(values, terraform=terraform))
    if kind.lower() == "microsoft.network/publicipaddresses":
        result["publicIpSku"] = enumeration(
            values.get("sku") if terraform else property_at(root, "sku.name"),
            ("Basic", "Standard"),
        )
        result["configuredZones"] = configured_zones(
            values.get("zones") if terraform else property_at(root, "zones")
        )
    return result


def _projected_properties(
    kind: str,
    values: dict[str, Any],
    *,
    terraform: bool,
    root: Any,
    observed: bool,
) -> dict[str, Any]:
    kind = kind.lower()
    if kind == "microsoft.network/azurefirewalls":
        sku = values.get("sku")
        configs = values.get("ip_configuration" if terraform else "ipConfigurations")
        management = values.get(
            "management_ip_configuration" if terraform else "managementIpConfiguration"
        )
        refs: Any = unknown("firewall_subnet_configuration_not_explicit")
        if isinstance(configs, list) and len(configs) <= 100:
            refs = []
            for entry in configs:
                body = (
                    entry
                    if terraform
                    else entry.get("properties")
                    if isinstance(entry, dict)
                    else None
                )
                if not isinstance(body, dict):
                    refs.append(unknown("firewall_ip_configuration_invalid"))
                elif terraform and "subnet_id" in body:
                    refs.append(reference(body["subnet_id"]))
                elif not terraform and "subnet" in body:
                    refs.append(reference(property_at(body, "subnet.id")))
            if management is not None:
                entries = management if terraform else [management]
                if not isinstance(entries, list) or len(entries) > 1:
                    refs.append(unknown("firewall_management_configuration_invalid"))
                for entry in entries if isinstance(entries, list) and len(entries) <= 1 else []:
                    refs.append(
                        reference(
                            entry.get("subnet_id")
                            if terraform and isinstance(entry, dict)
                            else property_at(entry, "properties.subnet.id")
                        )
                    )
        return {
            "sku": {
                "tier": enumeration(
                    values.get("sku_tier")
                    if terraform
                    else sku.get("tier")
                    if isinstance(sku, dict)
                    else None,
                    ("Basic", "Standard", "Premium"),
                ),
                "name": enumeration(
                    values.get("sku_name")
                    if terraform
                    else sku.get("name")
                    if isinstance(sku, dict)
                    else None,
                    ("AZFW_Hub", "AZFW_VNet"),
                ),
            },
            "subnetReferences": refs,
            "firewallPolicy": {
                "id": reference(
                    values.get("firewall_policy_id")
                    if terraform
                    else property_at(values, "firewallPolicy.id")
                )
            },
            "natRuleCollections": nat_collections(values.get("natRuleCollections"))
            if not terraform
            else unknown("classic_nat_collections_are_separate_tf_resources"),
            "configuredZones": configured_zones(
                values.get("zones")
                if terraform
                else root.get("zones")
                if isinstance(root, dict)
                else None
            ),
        }
    if kind == "microsoft.network/virtualnetworks":
        plan = values.get("ddos_protection_plan")
        plan = (
            plan[0]
            if isinstance(plan, list) and len(plan) == 1 and isinstance(plan[0], dict)
            else {}
        )
        return {
            "virtualNetworkPrefixes": address_list(
                values.get("address_space")
                if terraform
                else property_at(values, "addressSpace.addressPrefixes"),
                prefix_only=True,
            ),
            "enableDdosProtection": boolean(
                plan.get("enable") if terraform else values.get("enableDdosProtection")
            ),
            "ddosProtectionPlan": {
                "id": reference(
                    plan.get("id") if terraform else property_at(values, "ddosProtectionPlan.id")
                )
            },
        }
    if kind == "microsoft.network/privateendpoints":
        return {
            "subnet": {
                "id": reference(
                    values.get("subnet_id") if terraform else property_at(values, "subnet.id")
                )
            },
            "privateConnections": private_connections(values, terraform=terraform),
        }
    if kind == "microsoft.network/firewallpolicies/rulecollectiongroups":
        return {
            "applicationRules": application_rules(values, terraform=terraform),
            "egressRules": egress_rules(values, terraform=terraform),
        }
    if kind == "microsoft.network/networksecuritygroups":
        return {
            "securityRuleCount": observed_rule_count(values, observed=observed and not terraform),
            "securityRuleSummary": rule_summary(
                values.get("security_rule" if terraform else "securityRules"), terraform=terraform
            ),
            "defaultRuleSummary": rule_summary(
                values.get("defaultSecurityRules") if observed and not terraform else None,
                terraform=False,
            ),
        }
    if kind == "microsoft.network/networksecuritygroups/securityrules":
        return {
            "securityRuleSummary": rule_summary(
                [values] if terraform else [{"properties": values}], terraform=terraform
            )
        }
    if kind == "microsoft.network/virtualnetworkgateways":
        configs = values.get("ip_configuration" if terraform else "ipConfigurations")
        return {
            "gatewayType": enumeration(
                values.get("type" if terraform else "gatewayType"), ("Vpn", "ExpressRoute")
            ),
            "subnetReferences": [
                reference(
                    entry.get("subnet_id")
                    if terraform and isinstance(entry, dict)
                    else property_at(entry, "properties.subnet.id")
                )
                for entry in configs
            ]
            if isinstance(configs, list) and 1 <= len(configs) <= 3
            else unknown("gateway_ip_configurations_missing_or_over_3"),
        }
    if kind == "microsoft.network/networkwatchers/flowlogs":
        analytics = (
            values.get("traffic_analytics")
            if terraform
            else property_at(
                values, "flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration"
            )
        )
        if terraform:
            analytics = (
                analytics[0] if isinstance(analytics, list) and len(analytics) == 1 else None
            )
        analytics = analytics if isinstance(analytics, dict) else {}
        filtering = values.get("enabledFilteringCriteria") if not terraform else None
        return {
            "enabled": boolean(values.get("enabled")),
            "targetResourceId": reference(
                values.get("target_resource_id" if terraform else "targetResourceId")
            ),
            "storageId": reference(values.get("storage_account_id" if terraform else "storageId")),
            "trafficAnalytics": {
                "enabled": boolean(analytics.get("enabled")),
                "workspaceResourceId": reference(
                    analytics.get("workspace_resource_id" if terraform else "workspaceResourceId")
                ),
            },
            "filteringConfigured": bool(filtering.strip())
            if isinstance(filtering, str) and len(filtering) <= 1000
            else unknown("filter_configuration_not_explicit"),
        }
    if kind == "microsoft.network/virtualnetworks/subnets":
        prefixes = (
            values.get("address_prefixes")
            if terraform
            else values.get(
                "addressPrefixes", [values["addressPrefix"]] if "addressPrefix" in values else None
            )
        )
        if not terraform and "addressPrefixes" in values and "addressPrefix" in values:
            prefixes = None
        if terraform and values.get("ip_address_pool") not in (None, []):
            prefixes = None
        endpoints = values.get("service_endpoints" if terraform else "serviceEndpoints")
        services = (
            endpoints
            if terraform
            else [entry.get("service") if isinstance(entry, dict) else None for entry in endpoints]
            if isinstance(endpoints, list) and len(endpoints) <= 100
            else None
        )
        return {
            "addressPrefixes": address_list(prefixes, prefix_only=True),
            "serviceEndpointCount": supplied_string_count(services),
            "serviceEndpointNetworkIdentifiers": [
                reference(property_at(entry, "networkIdentifier.id")) for entry in endpoints
            ]
            if not terraform and isinstance(endpoints, list) and len(endpoints) <= 100
            else unknown("endpoint_network_identifiers_not_explicit"),
            "privateEndpointNetworkPolicies": enumeration(
                values.get(
                    "private_endpoint_network_policies"
                    if terraform
                    else "privateEndpointNetworkPolicies"
                ),
                ("Disabled", "Enabled", "NetworkSecurityGroupEnabled", "RouteTableEnabled"),
            ),
            "routeTable": {"id": reference(property_at(values, "routeTable.id"))}
            if not terraform
            else {"id": unknown("association_requires_separate_evidence")},
            "natGateway": {"id": reference(property_at(values, "natGateway.id"))}
            if not terraform
            else {"id": unknown("association_requires_separate_evidence")},
            "networkSecurityGroup": {
                "id": reference(property_at(values, "networkSecurityGroup.id"))
            }
            if not terraform
            else {"id": unknown("association_requires_separate_evidence")},
        }
    if kind == "microsoft.insights/diagnosticsettings":
        return {
            "targetResourceId": reference(
                values.get("target_resource_id")
                if terraform
                else root.get("scope")
                if isinstance(root, dict) and root.get("scope")
                else root.get("id", "").rsplit("/providers/Microsoft.Insights/", 1)[0]
                if isinstance(root, dict)
                and isinstance(root.get("id"), str)
                and "/providers/Microsoft.Insights/" in root["id"]
                else values.get("targetResourceId")
            ),
            "workspaceId": reference(
                values.get("log_analytics_workspace_id") if terraform else values.get("workspaceId")
            ),
            "logAnalyticsDestinationType": enumeration(
                values.get("log_analytics_destination_type")
                if terraform
                else values.get("logAnalyticsDestinationType"),
                ("Dedicated", "AzureDiagnostics"),
            ),
        }
    if kind == "microsoft.network/ipgroups":
        return {
            "ipAddresses": address_list(
                values.get("cidrs") if terraform else values.get("ipAddresses")
            )
        }
    if kind == "microsoft.network/azurefirewalls/natrulecollections" and terraform:
        rules = values.get("rule")
        return {
            "natRuleCollections": nat_collections(
                [
                    {
                        "properties": {
                            "action": {"type": values.get("action")},
                            "rules": [
                                {
                                    "sourceAddresses": item.get("source_addresses"),
                                    "sourceIpGroups": item.get("source_ip_groups"),
                                }
                                if isinstance(item, dict)
                                else None
                                for item in rules
                            ]
                            if isinstance(rules, list)
                            else None,
                        }
                    }
                ]
            )
        }
    from .routing_evidence import projected_properties as routing_properties

    if kind == CIRCUIT_KIND:
        from .expressroute_evidence import circuit_properties

        return circuit_properties(values, terraform=terraform, root=root)
    if kind == PORT_KIND:
        from .expressroute_evidence import port_properties

        return {
            **routing_properties(kind, values, terraform=terraform, observed=observed, root=root),
            **port_properties(values, terraform=terraform),
        }
    return routing_properties(kind, values, terraform=terraform, observed=observed, root=root)


def replay_properties(kind: str, properties: dict[str, Any]) -> dict[str, Any]:
    if kind.lower() not in {
        "microsoft.network/azurefirewalls",
        "microsoft.network/virtualnetworks/subnets",
        "microsoft.network/ipgroups",
        "microsoft.network/azurefirewalls/natrulecollections",
        "microsoft.insights/diagnosticsettings",
        "microsoft.network/virtualnetworks",
        "microsoft.network/privateendpoints",
        "microsoft.network/firewallpolicies/rulecollectiongroups",
        "microsoft.network/networksecuritygroups",
        "microsoft.network/networksecuritygroups/securityrules",
        "microsoft.network/virtualnetworkgateways",
        "microsoft.network/networkwatchers/flowlogs",
        "microsoft.network/networkwatchers/connectionmonitors",
        "microsoft.insights/metricalerts",
    } | ROUTING_KINDS | PROTECTION_KINDS | DNS_KINDS | VWAN_KINDS | {CIRCUIT_KIND, PORT_KIND}:
        return {}
    result: dict[str, Any] = {}
    for path in sorted(REVIEW_PATHS - SECURITY_PATHS - GOVERNANCE_PATHS - TENANT_PATHS):
        parts = path.split(".")
        target = result
        for part in parts[:-1]:
            target = target.setdefault(part, {})
        target[parts[-1]] = review_fact(properties, path)
    return result
