"""Bounded typed network facts for review; no effective-path or policy claims."""

from ipaddress import ip_address, ip_network
from typing import Any

from .contracts import canonical_id
from .sources import boolean, enumeration, property_at, unknown
from .terraform import InputError

REVIEW_PATHS = {
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
}


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
    return reference(value)


def projected_properties(
    kind: str, values: dict[str, Any], *, terraform: bool = False, root: Any = None
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
        return {"applicationRules": application_rules(values, terraform=terraform)}
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
        return {
            "addressPrefixes": address_list(prefixes, prefix_only=True),
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
                values.get("target_resource_id") if terraform else values.get("targetResourceId")
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
    return {}


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
    }:
        return {}
    result: dict[str, Any] = {}
    for path in sorted(REVIEW_PATHS):
        parts = path.split(".")
        target = result
        for part in parts[:-1]:
            target = target.setdefault(part, {})
        target[parts[-1]] = review_fact(properties, path)
    return result
