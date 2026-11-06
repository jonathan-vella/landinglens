"""Normalize planned sources to a deliberately small, explicit ARM-property vocabulary."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .contracts import (
    canonical_id,
    derive_id,
    digest,
    document,
    identity_type,
    now,
    scope_id,
    validate,
)
from .terraform import Analyzer

PROVIDER_VERSION = "4.50.0"
TF_TYPES = {
    "azurerm_storage_account": "Microsoft.Storage/storageAccounts",
    "azurerm_firewall_policy": "Microsoft.Network/firewallPolicies",
    "azurerm_resource_group": "Microsoft.Resources/resourceGroups",
    "azurerm_log_analytics_workspace": "Microsoft.OperationalInsights/workspaces",
    "azurerm_virtual_network": "Microsoft.Network/virtualNetworks",
    "azurerm_management_group": "Microsoft.Management/managementGroups",
    "azurerm_key_vault": "Microsoft.KeyVault/vaults",
    "azurerm_firewall": "Microsoft.Network/azureFirewalls",
    "azurerm_subnet": "Microsoft.Network/virtualNetworks/subnets",
    "azurerm_firewall_nat_rule_collection": "Microsoft.Network/azureFirewalls/natRuleCollections",
    "azurerm_monitor_diagnostic_setting": "Microsoft.Insights/diagnosticSettings",
    "azurerm_ip_group": "Microsoft.Network/ipGroups",
    "azurerm_private_endpoint": "Microsoft.Network/privateEndpoints",
    "azurerm_network_security_group": "Microsoft.Network/networkSecurityGroups",
    "azurerm_network_security_rule": "Microsoft.Network/networkSecurityGroups/securityRules",
    "azurerm_virtual_network_gateway": "Microsoft.Network/virtualNetworkGateways",
    "azurerm_network_watcher_flow_log": "Microsoft.Network/networkWatchers/flowLogs",
    "azurerm_network_connection_monitor": "Microsoft.Network/networkWatchers/connectionMonitors",
    "azurerm_application_security_group": "Microsoft.Network/applicationSecurityGroups",
    "azurerm_route_table": "Microsoft.Network/routeTables",
    "azurerm_virtual_network_peering": "Microsoft.Network/virtualNetworks/virtualNetworkPeerings",
    "azurerm_lb": "Microsoft.Network/loadBalancers",
    "azurerm_lb_backend_address_pool": "Microsoft.Network/loadBalancers/backendAddressPools",
    "azurerm_express_route_port": "Microsoft.Network/expressRoutePorts",
    "azurerm_express_route_circuit": "Microsoft.Network/expressRouteCircuits",
    "azurerm_virtual_wan": "Microsoft.Network/virtualWans",
    "azurerm_virtual_hub": "Microsoft.Network/virtualHubs",
    "azurerm_virtual_hub_connection": "Microsoft.Network/virtualHubs/hubVirtualNetworkConnections",
    "azurerm_virtual_hub_route_table": "Microsoft.Network/virtualHubs/hubRouteTables",
    "azurerm_virtual_hub_routing_intent": "Microsoft.Network/virtualHubs/routingIntent",
    "azurerm_virtual_network_gateway_connection": "Microsoft.Network/connections",
    "azurerm_role_assignment": "Microsoft.Authorization/roleAssignments",
    "azurerm_security_center_subscription_pricing": "Microsoft.Security/pricings",
    "azurerm_key_vault_managed_hardware_security_module": "Microsoft.KeyVault/managedHSMs",
    "azurerm_linux_virtual_machine": "Microsoft.Compute/virtualMachines",
    "azurerm_windows_virtual_machine": "Microsoft.Compute/virtualMachines",
    "azurerm_cdn_frontdoor_firewall_policy": (
        "Microsoft.Network/FrontDoorWebApplicationFirewallPolicies"
    ),
    "azurerm_cdn_frontdoor_security_policy": "Microsoft.Cdn/profiles/securityPolicies",
    "azurerm_application_gateway": "Microsoft.Network/applicationGateways",
    "azurerm_web_application_firewall_policy": (
        "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies"
    ),
    "azurerm_public_ip": "Microsoft.Network/publicIPAddresses",
    "azurerm_network_interface": "Microsoft.Network/networkInterfaces",
    "azurerm_private_dns_zone": "Microsoft.Network/privateDnsZones",
    "azurerm_private_dns_zone_virtual_network_link": (
        "Microsoft.Network/privateDnsZones/virtualNetworkLinks"
    ),
    "azurerm_private_dns_resolver": "Microsoft.Network/dnsResolvers",
    "azurerm_private_dns_resolver_inbound_endpoint": (
        "Microsoft.Network/dnsResolvers/inboundEndpoints"
    ),
    "azurerm_private_dns_resolver_outbound_endpoint": (
        "Microsoft.Network/dnsResolvers/outboundEndpoints"
    ),
    "azurerm_private_dns_resolver_dns_forwarding_ruleset": (
        "Microsoft.Network/dnsForwardingRulesets"
    ),
    "azurerm_private_dns_resolver_forwarding_rule": (
        "Microsoft.Network/dnsForwardingRulesets/forwardingRules"
    ),
    "azurerm_private_dns_resolver_virtual_network_link": (
        "Microsoft.Network/dnsForwardingRulesets/virtualNetworkLinks"
    ),
    "azurerm_bastion_host": "Microsoft.Network/bastionHosts",
    "azurerm_firewall_policy_rule_collection_group": (
        "Microsoft.Network/firewallPolicies/ruleCollectionGroups"
    ),
}
BLOB_SERVICE_TYPE = "Microsoft.Storage/storageAccounts/blobServices"


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def unknown(reason: str) -> dict[str, str]:
    return {"unknown": reason}


def boolean(value: Any) -> Any:
    return value if type(value) is bool else unknown("boolean_missing_unresolved_or_invalid")


def enumeration(value: Any, allowed: tuple[str, ...]) -> Any:
    return (
        value
        if isinstance(value, str) and value in allowed
        else unknown("enum_missing_unresolved_or_invalid")
    )


def property_at(properties: Any, path: str) -> Any:
    current = properties
    for key in path.split("."):
        if isinstance(current, dict) and "unknown" in current:
            return current
        if not isinstance(current, dict) or key not in current:
            return unknown("property_not_supplied")
        current = current[key]
    return current


def tf_properties(kind: str, properties: dict[str, Any]) -> dict[str, Any]:
    from .identity_evidence import IDENTITY_KINDS, identity_summary, role_properties
    from .security_evidence import projected_properties as security_properties

    if kind == "azurerm_role_assignment":
        return role_properties(properties, terraform=True)
    result = _tf_properties(kind, properties)
    if TF_TYPES.get(kind, "").lower() in IDENTITY_KINDS and "identity" in properties:
        result["identitySummary"] = identity_summary(
            properties["identity"], terraform=True, resource_type=TF_TYPES[kind]
        )
    result.update(
        security_properties(
            TF_TYPES.get(kind, kind), properties, terraform=True, terraform_kind=kind
        )
    )
    return result


def _tf_properties(kind: str, properties: dict[str, Any]) -> dict[str, Any]:
    if kind == "azurerm_storage_account":
        return {
            "supportsHttpsTrafficOnly": boolean(properties.get("https_traffic_only_enabled")),
            "minimumTlsVersion": enumeration(
                properties.get("min_tls_version"), ("TLS1_0", "TLS1_1", "TLS1_2")
            ),
        }
    if kind == "azurerm_key_vault":
        rbac_keys = [
            key
            for key in ("rbac_authorization_enabled", "enable_rbac_authorization")
            if key in properties
        ]
        public = properties.get("public_network_access_enabled")
        acls = properties.get("network_acls")
        return {
            "enableSoftDelete": unknown("terraform_vault_creation_or_import_not_established"),
            "enablePurgeProtection": boolean(properties.get("purge_protection_enabled")),
            "enableRbacAuthorization": boolean(properties[rbac_keys[0]])
            if len(rbac_keys) == 1
            else unknown("rbac_alias_missing_or_conflicting"),
            "publicNetworkAccess": ("Enabled" if public else "Disabled")
            if type(public) is bool
            else unknown("public_network_access_not_explicit"),
            "networkAcls": {
                "defaultAction": enumeration(
                    acls[0].get("default_action")
                    if isinstance(acls, list) and len(acls) == 1 and isinstance(acls[0], dict)
                    else None,
                    ("Allow", "Deny"),
                )
            },
        }
    if kind == "azurerm_firewall_policy":
        dns = properties.get("dns")
        intrusion = properties.get("intrusion_detection")
        value = (
            dns[0].get("proxy_enabled")
            if (isinstance(dns, list) and len(dns) == 1 and isinstance(dns[0], dict))
            else None
        )
        return {
            "dnsSettings": {"enableProxy": boolean(value)},
            "sku": {"tier": enumeration(properties.get("sku"), ("Basic", "Standard", "Premium"))},
            "threatIntelMode": enumeration(
                properties.get("threat_intelligence_mode"),
                ("Alert", "Deny", "Off"),
            ),
            "intrusionDetection": {
                "mode": enumeration(
                    intrusion[0].get("mode")
                    if isinstance(intrusion, list)
                    and len(intrusion) == 1
                    and isinstance(intrusion[0], dict)
                    else None,
                    ("Alert", "Deny", "Off"),
                ),
            },
        }
    from .network_evidence import projected_properties

    return projected_properties(TF_TYPES.get(kind, kind), properties, terraform=True)


def blob_service_record(parent: dict[str, Any]) -> dict[str, Any]:
    identity = canonical_id(parent["arm_id"]) if parent.get("arm_id") else None
    return {
        "logical_id": parent["logical_id"] + ".blobServices.default",
        "resource_type": BLOB_SERVICE_TYPE,
        "arm_id": identity + "/blobservices/default" if identity else None,
        "source_location": parent["source_location"] + "#blobServices/default",
        "state": "unknown",
        "reason": "blob_service_configuration_not_supplied",
        "properties": {},
    }


def tf_blob_service(parent: dict[str, Any], values: dict[str, Any]) -> dict[str, Any]:
    child = blob_service_record(parent)
    blob = values.get("blob_properties")
    retention = (
        blob[0].get("container_delete_retention_policy")
        if isinstance(blob, list) and len(blob) == 1 and isinstance(blob[0], dict)
        else None
    )
    days = (
        retention[0].get("days")
        if isinstance(retention, list) and len(retention) == 1 and isinstance(retention[0], dict)
        else None
    )
    if parent["state"] == "known" and type(days) is int and 1 <= days <= 365:
        child.update(
            state="known",
            reason="",
            properties={"containerDeleteRetentionPolicy": {"enabled": True}},
        )
    return child


def complete_blob_services(records: list[dict[str, Any]], limit: int) -> None:
    """Keep missing child configuration unknown even when account inventory is complete."""
    identities = {
        canonical_id(record["arm_id"])
        for record in records
        if record.get("arm_id") and record["resource_type"].lower() == BLOB_SERVICE_TYPE.lower()
    }
    logical_ids = {
        record["logical_id"]
        for record in records
        if record["resource_type"].lower() == BLOB_SERVICE_TYPE.lower()
    }
    for parent in list(records):
        if parent["resource_type"].lower() != "microsoft.storage/storageaccounts":
            continue
        child = blob_service_record(parent)
        if child["arm_id"] in identities or child["logical_id"] in logical_ids:
            continue
        if len(records) >= limit:
            from .terraform import InputError

            raise InputError("Resource limit includes unresolved default blob-service children")
        records.append(child)


def resource_scope(scope: str | None, properties: dict[str, Any]) -> str | None:
    if not scope:
        return None
    normalized = scope_id(scope)
    group = properties.get("resource_group_name")
    if "/resourcegroups/" in normalized:
        actual = normalized.split("/resourcegroups/")[1]
        return (
            normalized
            if not group or (isinstance(group, str) and group.lower() == actual)
            else None
        )
    if normalized.startswith("/subscriptions/") and isinstance(group, str) and "/" not in group:
        return normalized + "/resourceGroups/" + group
    return None


def tf_resource_id(scope: str | None, kind: str, values: dict[str, Any]) -> str | None:
    name = values.get("name")
    if kind in {
        "azurerm_virtual_hub_connection",
        "azurerm_virtual_hub_route_table",
        "azurerm_virtual_hub_routing_intent",
    }:
        from .protection_evidence import typed_reference

        parent = typed_reference(values.get("virtual_hub_id"), ("microsoft.network/virtualhubs",))
        boundary = scope_id(scope) if scope else None
        if (
            boundary
            and isinstance(parent, str)
            and parent.startswith(boundary + "/")
            and isinstance(name, str)
            and name
            and "/" not in name
        ):
            return canonical_id(parent + "/" + TF_TYPES[kind].rsplit("/", 1)[1] + "/" + name)
        return None
    dns_parent = {
        "azurerm_private_dns_resolver_inbound_endpoint": (
            "private_dns_resolver_id",
            "microsoft.network/dnsresolvers",
            "inboundEndpoints",
        ),
        "azurerm_private_dns_resolver_outbound_endpoint": (
            "private_dns_resolver_id",
            "microsoft.network/dnsresolvers",
            "outboundEndpoints",
        ),
        "azurerm_private_dns_resolver_forwarding_rule": (
            "dns_forwarding_ruleset_id",
            "microsoft.network/dnsforwardingrulesets",
            "forwardingRules",
        ),
        "azurerm_private_dns_resolver_virtual_network_link": (
            "dns_forwarding_ruleset_id",
            "microsoft.network/dnsforwardingrulesets",
            "virtualNetworkLinks",
        ),
    }.get(kind)
    if dns_parent:
        from .protection_evidence import typed_reference

        key, parent_kind, child_kind = dns_parent
        parent = typed_reference(values.get(key), (parent_kind,))
        boundary = scope_id(scope) if scope else None
        if (
            boundary
            and isinstance(parent, str)
            and parent.startswith(boundary + "/")
            and isinstance(name, str)
            and name
            and "/" not in name
        ):
            return canonical_id(parent + "/" + child_kind + "/" + name)
        return None
    if kind == "azurerm_security_center_subscription_pricing":
        from .security_evidence import PLANS

        boundary = scope_id(scope) if scope else None
        plan = values.get("resource_type")
        if boundary and boundary.count("/") == 2 and isinstance(plan, str) and plan in PLANS:
            return canonical_id(boundary + "/providers/Microsoft.Security/pricings/" + plan)
        return None
    if kind in {"azurerm_cdn_frontdoor_security_policy", "azurerm_network_connection_monitor"}:
        from .protection_evidence import typed_reference

        monitor = kind == "azurerm_network_connection_monitor"
        parent = typed_reference(
            values.get("network_watcher_id" if monitor else "cdn_frontdoor_profile_id"),
            ("microsoft.network/networkwatchers",) if monitor else ("microsoft.cdn/profiles",),
        )
        boundary = scope_id(scope) if scope else None
        if (
            boundary
            and isinstance(parent, str)
            and parent.startswith(boundary + "/")
            and isinstance(name, str)
            and name
            and "/" not in name
        ):
            return canonical_id(
                parent + ("/connectionMonitors/" if monitor else "/securityPolicies/") + name
            )
        return None
    if kind == "azurerm_role_assignment":
        from .network_evidence import reference

        target = reference(values.get("scope"))
        boundary = scope_id(scope) if scope else None
        if (
            boundary
            and isinstance(target, str)
            and (target == boundary or target.startswith(boundary + "/"))
            and isinstance(name, str)
            and name
            and "/" not in name
        ):
            return canonical_id(
                target + "/providers/Microsoft.Authorization/roleAssignments/" + name
            )
        return None
    if kind == "azurerm_firewall_policy_rule_collection_group":
        from .network_evidence import reference

        parent = reference(values.get("firewall_policy_id"))
        boundary = scope_id(scope) if scope else None
        if (
            boundary
            and isinstance(parent, str)
            and parent.startswith(boundary + "/")
            and identity_type(parent) == "microsoft.network/firewallpolicies"
            and isinstance(name, str)
            and name
            and "/" not in name
        ):
            return canonical_id(parent + "/ruleCollectionGroups/" + name)
        return None
    if kind == "azurerm_monitor_diagnostic_setting":
        from .network_evidence import reference

        target = reference(values.get("target_resource_id"))
        boundary = scope_id(scope) if scope else None
        if (
            boundary
            and isinstance(target, str)
            and (target == boundary or target.startswith(boundary + "/"))
            and isinstance(name, str)
            and name
            and "/" not in name
        ):
            return canonical_id(target + "/providers/Microsoft.Insights/diagnosticSettings/" + name)
        return None
    parent_key = {
        "azurerm_subnet": "virtual_network_name",
        "azurerm_firewall_nat_rule_collection": "azure_firewall_name",
        "azurerm_network_security_rule": "network_security_group_name",
        "azurerm_network_watcher_flow_log": "network_watcher_name",
        "azurerm_virtual_network_peering": "virtual_network_name",
        "azurerm_private_dns_zone_virtual_network_link": "private_dns_zone_name",
    }.get(kind)
    if parent_key:
        parent = values.get(parent_key)
        if not isinstance(parent, str) or not parent or "/" in parent or not isinstance(name, str):
            return None
        name = parent + "/" + name
    return derive_id(resource_scope(scope, values), TF_TYPES.get(kind, kind), name)


def terraform_source(
    root: Path,
    *,
    scope: str | None = None,
    provider_version: str | None = None,
    snapshots: Path | None = None,
    authorized_roots: list[Path] | None = None,
    variable_inputs: list[tuple[str, Any]] | None = None,
) -> dict[str, Any]:
    result = Analyzer(
        root,
        manifest=snapshots,
        authorized_roots=authorized_roots,
    ).analyze(variable_inputs=variable_inputs)
    records = []
    supported = provider_version == PROVIDER_VERSION
    for item in result["resources"]:
        kind = item.get("resource_type") or item["address"].split(".")[-2]
        properties = item["properties"]
        symbolic = "unknown" in properties
        arm_type = TF_TYPES.get(kind, kind)
        identity = (
            tf_resource_id(scope, kind, properties)
            if supported and not symbolic and item.get("scope_binding_safe", False)
            else None
        )
        records.append(
            {
                "logical_id": item["address"],
                "resource_type": arm_type,
                "properties": tf_properties(kind, properties) if supported and not symbolic else {},
                "arm_id": identity,
                "source_location": item["file"],
                "state": "unknown" if symbolic or not supported else "known",
                "reason": properties.get("unknown", "")
                if supported
                else "unverified_provider_version",
            }
        )
        if kind == "azurerm_storage_account":
            records.append(tf_blob_service(records[-1], properties))
        if len(records) > 256:
            from .terraform import InputError

            raise InputError("Terraform resource limit includes default blob-service children")
    artifacts = dict(result["input_sha256"])
    artifacts["scope-provider-bindings"] = digest({"scope": scope, "azurerm": provider_version})
    return validate(
        document(
            "evidence",
            mode="planned",
            source="terraform",
            collected_at=now(),
            scope=scope,
            artifact_hashes=artifacts,
            inventory_complete=not result["diagnostics"] and supported,
            resources=records,
            diagnostics=result["diagnostics"],
            metadata={"provider_version": provider_version, "limitations": result["coverage"]},
        )
    )
