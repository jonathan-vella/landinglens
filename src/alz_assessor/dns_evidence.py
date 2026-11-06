"""Minimized DNS/Bastion configuration, not resolution, failover or secure access."""

import re
from ipaddress import ip_address
from typing import Any

from .protection_evidence import block, rows, typed_reference
from .sources import boolean, enumeration, property_at, unknown

KINDS = {
    "microsoft.network/privatednszones",
    "microsoft.network/privatednszones/virtualnetworklinks",
    "microsoft.network/dnsresolvers",
    "microsoft.network/dnsresolvers/inboundendpoints",
    "microsoft.network/dnsresolvers/outboundendpoints",
    "microsoft.network/dnsforwardingrulesets",
    "microsoft.network/dnsforwardingrulesets/forwardingrules",
    "microsoft.network/dnsforwardingrulesets/virtualnetworklinks",
    "microsoft.network/bastionhosts",
}
BASTION_FLAGS = {
    "disableCopyPaste": "copy_paste_enabled",
    "enableFileCopy": "file_copy_enabled",
    "enableIpConnect": "ip_connect_enabled",
    "enableKerberos": "kerberos_enabled",
    "enablePrivateOnlyBastion": None,
    "enableSessionRecording": "session_recording_enabled",
    "enableShareableLink": "shareable_link_enabled",
    "enableTunneling": "tunneling_enabled",
}
PATHS = {
    "resourceLocation",
    "publicIpSku",
    "publicIpTier",
    "publicIpAllocationMethod",
    "publicIpVersion",
    "dnsVirtualNetworkId",
    "dnsServerSummary",
    "dnsResolverDelegation",
    "vnetEncryptionEnabled",
    "vnetEncryptionEnforcement",
    "registrationEnabled",
    "dnsLinkState",
    "resolutionPolicy",
    "resolverIpConfigurations",
    "resolverOutboundEndpointIds",
    "forwardingRuleState",
    "forwardingDomainSummary",
    "forwardingTargetSummary",
    "bastionSku",
    "bastionScaleUnits",
    "bastionVirtualNetworkId",
    "bastionPublicIpIds",
    "bastionFeatureSummary",
    *BASTION_FLAGS,
}
ENUMS = {
    "publicIpSku": ("Basic", "Standard"),
    "publicIpTier": ("Regional", "Global"),
    "publicIpAllocationMethod": ("Dynamic", "Static"),
    "publicIpVersion": ("IPv4", "IPv6"),
    "dnsLinkState": ("InProgress", "Completed"),
    "resolutionPolicy": ("Default", "NxDomainRedirect"),
    "forwardingRuleState": ("Disabled", "Enabled"),
    "bastionSku": ("Developer", "Basic", "Standard", "Premium"),
    "vnetEncryptionEnforcement": ("AllowUnencrypted", "DropUnencrypted"),
}


def location(value: Any) -> Any:
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9 ]{1,39}", value):
        return unknown("resource_location_missing_invalid_or_unsupported")
    return value.lower().replace(" ", "")


def typed_references(value: Any, kind: str, maximum: int) -> Any:
    if not isinstance(value, list) or len(value) > maximum:
        return unknown("typed_relationships_missing_invalid_or_over_bound")
    return [typed_reference(item, (kind,)) for item in value]


def ip_shape(value: Any) -> Any:
    if not isinstance(value, str) or not 1 <= len(value) <= 45 or "%" in value:
        return unknown("dns_target_address_missing_invalid_or_withheld")
    try:
        address = ip_address(value)
    except ValueError:
        return unknown("dns_target_address_missing_invalid_or_withheld")
    return {
        "addressFamily": "IPv4" if address.version == 4 else "IPv6",
        "isAzureProvidedDns": str(address) == "168.63.129.16",
    }


def server_summary(value: Any) -> Any:
    if (
        not isinstance(value, list)
        or len(value) > 20
        or any("unknown" in ip_shape(item) for item in value)
    ):
        return unknown("dns_server_list_missing_invalid_or_over_20")
    return {"suppliedCount": len(value), "usesCustomServers": bool(value)}


def domain_summary(value: Any) -> Any:
    if not isinstance(value, str) or not 1 <= len(value) <= 253 or not value.endswith("."):
        return unknown("forwarding_domain_missing_invalid_or_unsupported")
    labels = value[:-1].split(".") if value != "." else []
    if len(labels) > 34 or any(
        not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label)
        for label in labels
    ):
        return unknown("forwarding_domain_missing_invalid_or_unsupported")
    return {"labelCount": len(labels), "wildcard": not labels}


def target_summary(value: Any, *, terraform: bool) -> Any:
    if not rows(value, 6) or not value:
        return unknown("dns_targets_missing_invalid_or_over_6")
    result = []
    for row in value:
        shape = ip_shape(row.get("ip_address" if terraform else "ipAddress"))
        result.append(
            {
                "addressFamily": shape.get("addressFamily", shape),
                "isAzureProvidedDns": shape.get("isAzureProvidedDns", shape),
                "port": port
                if type(port := row.get("port")) is int and 1 <= port <= 65535
                else unknown("dns_target_port_missing_or_invalid"),
            }
        )
    return result


def configuration_facts(value: Any) -> Any:
    if not rows(value, 20) or not value:
        return unknown("resolver_ip_configurations_missing_invalid_or_over_20")
    return [
        {
            "subnetId": typed_reference(
                row.get("subnetId"), ("microsoft.network/virtualnetworks/subnets",)
            ),
            "allocationMethod": enumeration(row.get("allocationMethod"), ("Dynamic", "Static")),
        }
        for row in value
    ]


def delegation(value: Any, *, terraform: bool) -> Any:
    if not rows(value, 20):
        return unknown("subnet_delegations_missing_invalid_or_over_20")
    services = [
        block(row.get("service_delegation")).get("name")
        if terraform
        else property_at(row, "properties.serviceName")
        for row in value
    ]
    if any(not isinstance(service, str) or not service.strip() for service in services):
        return unknown("subnet_delegation_service_missing_or_invalid")
    return {
        "suppliedCount": len(services),
        "exclusivelyDnsResolver": services == ["Microsoft.Network/dnsResolvers"],
    }


def review_fact(properties: dict[str, Any], path: str) -> Any:
    from .network_evidence import bounded_count

    value = property_at(properties, path)
    if path == "bastionFeatureSummary":
        return {
            **{key: boolean(properties.get(key)) for key in BASTION_FLAGS},
            "scaleUnits": review_fact(properties, "bastionScaleUnits"),
        }
    if path in ENUMS:
        return enumeration(value, ENUMS[path])
    if path in BASTION_FLAGS or path in {"registrationEnabled", "vnetEncryptionEnabled"}:
        return boolean(value)
    if path == "resourceLocation":
        return location(value)
    if path in {"dnsVirtualNetworkId", "bastionVirtualNetworkId"}:
        return typed_reference(value, ("microsoft.network/virtualnetworks",))
    if path == "bastionPublicIpIds":
        return typed_references(value, "microsoft.network/publicipaddresses", 20)
    if path == "resolverOutboundEndpointIds":
        return typed_references(value, "microsoft.network/dnsresolvers/outboundendpoints", 2)
    if path == "bastionScaleUnits":
        return (
            bounded_count(value, 50)
            if type(value) is int and value >= 2
            else unknown("bastion_scale_units_missing_invalid_or_outside_2_50")
        )
    if path == "resolverIpConfigurations":
        return configuration_facts(value)
    if path in {"dnsServerSummary", "dnsResolverDelegation", "forwardingDomainSummary"}:
        count_key, flag_key, maximum = {
            "dnsServerSummary": ("suppliedCount", "usesCustomServers", 20),
            "dnsResolverDelegation": ("suppliedCount", "exclusivelyDnsResolver", 20),
            "forwardingDomainSummary": ("labelCount", "wildcard", 34),
        }[path]
        if not isinstance(value, dict) or "unknown" in value:
            return unknown("dns_summary_missing_invalid_or_withheld")
        count, flag = value.get(count_key), value.get(flag_key)
        if (
            type(count) is not int
            or not 0 <= count <= maximum
            or type(flag) is not bool
            or (path == "dnsServerSummary" and flag != bool(count))
            or (path == "forwardingDomainSummary" and flag != (count == 0))
            or (path == "dnsResolverDelegation" and flag and count != 1)
        ):
            return unknown("dns_summary_missing_invalid_or_over_bound")
        return {count_key: count, flag_key: flag}
    if path == "forwardingTargetSummary":
        if not rows(value, 6) or not value:
            return unknown("dns_targets_missing_invalid_or_over_6")
        return [
            {
                "addressFamily": enumeration(row.get("addressFamily"), ("IPv4", "IPv6")),
                "isAzureProvidedDns": boolean(row.get("isAzureProvidedDns")),
                "port": port
                if type(port := row.get("port")) is int and 1 <= port <= 65535
                else unknown("dns_target_port_missing_or_invalid"),
            }
            for row in value
        ]
    return unknown("unreviewed_dns_fact")


def projected_properties(
    kind: str, values: dict[str, Any], *, terraform: bool, root: Any
) -> dict[str, Any]:
    from .network_evidence import configured_zones

    result: dict[str, Any] = {}
    if kind in KINDS | {"microsoft.network/publicipaddresses", "microsoft.network/virtualnetworks"}:
        result["resourceLocation"] = location(
            values.get("location")
            if terraform
            else root.get("location")
            if isinstance(root, dict)
            else None
        )
    if kind == "microsoft.network/publicipaddresses":
        result |= {
            "configuredZones": configured_zones(
                values.get("zones")
                if terraform
                else root.get("zones")
                if isinstance(root, dict)
                else None
            ),
            "publicIpSku": values.get("sku") if terraform else property_at(root, "sku.name"),
            "publicIpTier": values.get("sku_tier") if terraform else property_at(root, "sku.tier"),
            "publicIpAllocationMethod": values.get(
                "allocation_method" if terraform else "publicIPAllocationMethod"
            ),
            "publicIpVersion": values.get("ip_version" if terraform else "publicIPAddressVersion"),
        }
    elif kind == "microsoft.network/virtualnetworks":
        result |= {
            "dnsServerSummary": server_summary(
                values.get("dns_servers")
                if terraform
                else property_at(values, "dhcpOptions.dnsServers")
            ),
            "vnetEncryptionEnabled": unknown("terraform_encryption_enabled_not_exposed")
            if terraform
            else property_at(values, "encryption.enabled"),
            "vnetEncryptionEnforcement": enumeration(
                block(values.get("encryption")).get("enforcement"), ("AllowUnencrypted",)
            )
            if terraform
            else property_at(values, "encryption.enforcement"),
        }
    elif kind == "microsoft.network/virtualnetworks/subnets":
        result["dnsResolverDelegation"] = delegation(
            values.get("delegation" if terraform else "delegations"), terraform=terraform
        )
    elif kind in {
        "microsoft.network/privatednszones/virtualnetworklinks",
        "microsoft.network/dnsresolvers",
        "microsoft.network/dnsforwardingrulesets/virtualnetworklinks",
    }:
        result["dnsVirtualNetworkId"] = (
            values.get("virtual_network_id")
            if terraform
            else property_at(values, "virtualNetwork.id")
        )
        if kind == "microsoft.network/privatednszones/virtualnetworklinks":
            result |= {
                "registrationEnabled": values.get(
                    "registration_enabled" if terraform else "registrationEnabled"
                ),
                "resolutionPolicy": values.get(
                    "resolution_policy" if terraform else "resolutionPolicy"
                ),
                "dnsLinkState": unknown("terraform_link_state_not_exposed")
                if terraform
                else values.get("virtualNetworkLinkState"),
            }
    elif kind == "microsoft.network/dnsresolvers/inboundendpoints":
        configs = values.get("ip_configurations" if terraform else "ipConfigurations")
        result["resolverIpConfigurations"] = configuration_facts(
            [
                {
                    "subnetId": row.get("subnet_id")
                    if terraform
                    else property_at(row, "subnet.id"),
                    "allocationMethod": row.get(
                        "private_ip_allocation_method" if terraform else "privateIpAllocationMethod"
                    ),
                }
                for row in configs
            ]
            if rows(configs, 1 if terraform else 20)
            else None
        )
        facts = result["resolverIpConfigurations"]
        result["subnetReferences"] = (
            [row["subnetId"] for row in facts]
            if isinstance(facts, list)
            else unknown("resolver_subnets_not_explicit")
        )
    elif kind == "microsoft.network/dnsresolvers/outboundendpoints":
        result["subnetReferences"] = [
            typed_reference(
                values.get("subnet_id") if terraform else property_at(values, "subnet.id"),
                ("microsoft.network/virtualnetworks/subnets",),
            )
        ]
    elif kind == "microsoft.network/dnsforwardingrulesets":
        endpoints = values.get(
            "private_dns_resolver_outbound_endpoint_ids"
            if terraform
            else "dnsResolverOutboundEndpoints"
        )
        result["resolverOutboundEndpointIds"] = (
            endpoints
            if terraform
            else [row.get("id") for row in endpoints]
            if rows(endpoints, 2)
            else None
        )
    elif kind == "microsoft.network/dnsforwardingrulesets/forwardingrules":
        enabled = values.get("enabled")
        result |= {
            "forwardingRuleState": ("Enabled" if enabled else "Disabled")
            if terraform and type(enabled) is bool
            else unknown("rule_enabled_not_explicit")
            if terraform
            else values.get("forwardingRuleState"),
            "forwardingDomainSummary": domain_summary(
                values.get("domain_name" if terraform else "domainName")
            ),
            "forwardingTargetSummary": target_summary(
                values.get("target_dns_servers" if terraform else "targetDnsServers"),
                terraform=terraform,
            ),
        }
    elif kind == "microsoft.network/bastionhosts":
        result |= {
            "configuredZones": configured_zones(
                values.get("zones")
                if terraform
                else root.get("zones")
                if isinstance(root, dict)
                else None
            ),
            "bastionSku": values.get("sku") if terraform else property_at(root, "sku.name"),
            "bastionScaleUnits": values.get("scale_units" if terraform else "scaleUnits"),
            "bastionVirtualNetworkId": values.get("virtual_network_id")
            if terraform
            else property_at(values, "virtualNetwork.id"),
        }
        for path, tf_path in BASTION_FLAGS.items():
            flag = values.get(tf_path) if terraform and tf_path else values.get(path)
            if terraform and path == "disableCopyPaste":
                flag = not flag if type(flag) is bool else None
            result[path] = (
                unknown("terraform_private_only_not_exposed")
                if (terraform and path == "enablePrivateOnlyBastion")
                else flag
            )
        configs = values.get("ip_configuration" if terraform else "ipConfigurations")
        for path, tf_path, arm_path, resource_kind in (
            (
                "subnetReferences",
                "subnet_id",
                "subnet.id",
                "microsoft.network/virtualnetworks/subnets",
            ),
            (
                "bastionPublicIpIds",
                "public_ip_address_id",
                "publicIPAddress.id",
                "microsoft.network/publicipaddresses",
            ),
        ):
            result[path] = typed_references(
                [
                    row.get(tf_path) if terraform else property_at(row, "properties." + arm_path)
                    for row in configs
                ]
                if rows(configs, 1 if terraform else 20)
                else None,
                resource_kind,
                20,
            )
    return {
        key: review_fact({key: value}, key) if key in PATHS else value
        for key, value in result.items()
    }
