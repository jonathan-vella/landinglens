"""Supplied VNet relationships, not hub designation, effective transit or estate quotas."""

from ipaddress import ip_network
from typing import Any

from .dns_evidence import location, typed_references
from .identity_evidence import known_scoped_resource
from .protection_evidence import block, typed_reference
from .sources import boolean, enumeration, property_at, unknown

VNET = "microsoft.network/virtualnetworks"
SUBNET = VNET + "/subnets"
PEERING = VNET + "/virtualnetworkpeerings"
HUB = "microsoft.network/virtualhubs"
IPCONFIG = HUB + "/ipconfigurations"
GATEWAY = "microsoft.network/virtualnetworkgateways"
FIREWALL = "microsoft.network/azurefirewalls"
RESOLVER = "microsoft.network/dnsresolvers"
GUIDS = {
    "373f482f-3e39-4d39-8aa4-7e566f6082b6",
    "e8bbac75-7155-49ab-a153-e8908ae28c84",
    "7bc1c396-2461-4698-b57f-30ca69525252",
    "7dd61623-a364-4a90-9eca-e48ebd54cd7d",
    "e2e8abac-3571-4559-ab91-53e89f89dc7b",
    "ce463dbb-bc8a-4c2a-aebc-92a43da1dae2",
    "91b9d7d5-91e1-4dcb-8f1f-fa7e465646cc",
    "cc881471-607c-41cc-a0e6-14658dd558f9",
    "4722d929-c1b1-4cd6-81f5-4b29bade39ad",
    "0e7c28ec-9366-4572-83b0-f4664b1d944a",
}
PATHS = {
    "routingSubnetReferences",
    "routingIpConfigurationIds",
    "routingSubnetId",
    "routingSubnetPrefixSummary",
    "peeringTransitSummary",
    "gatewayTransitSummary",
}
KINDS = {VNET, SUBNET, PEERING, HUB, IPCONFIG, GATEWAY, FIREWALL, RESOLVER}
WARNING = (
    "Original-time supplied configuration only. No hub/spoke designation, complete estate, "
    "physical/regional independence, effective transit, partner support, monitoring operation "
    "or current quota/headroom inferred. virtualHubs ARM identity alone is not Route Server "
    "or Virtual WAN designation. All applicability and whole decisions remain independent."
)
SIZING_SOURCE = (
    "https://learn.microsoft.com/en-us/azure/route-server/quickstart-create-route-server-portal"
)


def prefix_summary(value: Any) -> Any:
    if not isinstance(value, list) or not 1 <= len(value) <= 20:
        return unknown("routing_subnet_prefixes_missing_invalid_or_over_20")
    networks = []
    for item in value:
        if not isinstance(item, str) or not 1 <= len(item) <= 49 or "%" in item:
            return unknown("routing_subnet_prefix_not_explicit")
        try:
            networks.append(ip_network(item, strict=True))
        except ValueError:
            return unknown("routing_subnet_prefix_not_explicit")
    if len(set(networks)) != len(networks):
        return unknown("routing_subnet_prefix_duplicate")
    return [{"family": net.version, "prefixLength": net.prefixlen} for net in networks]


def prefix_fact(value: Any) -> Any:
    if not isinstance(value, list) or not 1 <= len(value) <= 20:
        return unknown("routing_subnet_summary_missing_invalid_or_over_20")
    result = []
    for row in value:
        family = row.get("family") if isinstance(row, dict) else None
        length = row.get("prefixLength") if isinstance(row, dict) else None
        if (
            not isinstance(row, dict)
            or "unknown" in row
            or type(family) is not int
            or family not in (4, 6)
            or type(length) is not int
            or not 0 <= length <= (32 if family == 4 else 128)
        ):
            return unknown("routing_subnet_summary_invalid")
        result.append({"family": family, "prefixLength": length})
    return result


def review_fact(properties: dict[str, Any], path: str) -> Any:
    value = property_at(properties, path)
    if isinstance(value, dict) and "unknown" in value:
        return unknown("topology_fact_not_explicit")
    if path == "routingSubnetPrefixSummary":
        return prefix_fact(value)
    if path == "routingSubnetId":
        return typed_reference(value, (SUBNET,))
    if path == "gatewayTransitSummary":
        return {
            "vpnType": enumeration(property_at(value, "vpnType"), ("RouteBased", "PolicyBased")),
            "asnIs65515": boolean(property_at(value, "asnIs65515")),
        }
    if path == "peeringTransitSummary":
        return {
            key: boolean(value.get(key) if isinstance(value, dict) else None)
            for key in ("allowForwardedTraffic", "allowGatewayTransit", "useRemoteGateways")
        }
    return typed_references(value, SUBNET if path == "routingSubnetReferences" else IPCONFIG, 20)


def projected_properties(
    kind: str, values: dict[str, Any], *, terraform: bool = False, terraform_kind: str = ""
) -> dict[str, Any]:
    kind = kind.lower()
    if kind == GATEWAY:
        asn = (
            block(values.get("bgp_settings")).get("asn")
            if terraform
            else property_at(values, "bgpSettings.asn")
        )
        return {
            "gatewayTransitSummary": {
                "vpnType": enumeration(
                    values.get("vpn_type" if terraform else "vpnType"),
                    ("RouteBased", "PolicyBased"),
                ),
                "asnIs65515": asn == 65515
                if type(asn) is int and 0 <= asn <= 4294967295
                else unknown("gateway_asn_not_explicit_or_invalid"),
            }
        }
    if kind == SUBNET:
        singular, plural = values.get("addressPrefix"), values.get("addressPrefixes")
        return {
            "routingSubnetPrefixSummary": prefix_summary(
                values.get("address_prefixes")
                if terraform
                else [singular]
                if singular is not None and plural is None
                else plural
                if singular is None
                else None
            )
        }
    if kind == PEERING:
        return {
            "peeringTransitSummary": {
                key: boolean(values.get(tf_key if terraform else key))
                for key, tf_key in (
                    ("allowForwardedTraffic", "allow_forwarded_traffic"),
                    ("allowGatewayTransit", "allow_gateway_transit"),
                    ("useRemoteGateways", "use_remote_gateways"),
                )
            }
        }
    if kind == IPCONFIG and not terraform:
        return {"routingSubnetId": typed_reference(property_at(values, "subnet.id"), (SUBNET,))}
    if kind == HUB:
        if terraform_kind == "azurerm_route_server":
            return {
                "routingSubnetReferences": typed_references([values.get("subnet_id")], SUBNET, 20),
                "hubBranchTrafficAllowed": boolean(values.get("branch_to_branch_traffic_enabled")),
                "hubRoutingPreference": enumeration(
                    values.get("hub_routing_preference"), ("ExpressRoute", "ASPath", "VpnGateway")
                ),
            }
        if not terraform:
            refs = values.get("ipConfigurations")
            return {
                "routingIpConfigurationIds": typed_references(
                    [row.get("id") if isinstance(row, dict) else None for row in refs]
                    if isinstance(refs, list) and len(refs) <= 20
                    else None,
                    IPCONFIG,
                    20,
                )
            }
    return {}


def resource_paths(kind: str) -> set[str]:
    return {
        "microsoft.network/networkwatchers/connectionmonitors": {"connectionMonitorSummary"},
        "microsoft.network/networkwatchers/flowlogs": {
            "enabled",
            "trafficAnalytics.enabled",
            "trafficAnalytics.workspaceResourceId",
        },
        "microsoft.insights/metricalerts": {"expressRouteAlertSummary"},
        HUB: {
            "routingSubnetReferences",
            "routingIpConfigurationIds",
            "hubBranchTrafficAllowed",
            "hubRoutingPreference",
        },
        IPCONFIG: {"routingSubnetId"},
        SUBNET: {"routingSubnetPrefixSummary"},
        PEERING: {"peeringTransitSummary", "allowVirtualNetworkAccess", "remoteVirtualNetwork.id"},
        GATEWAY: {
            "subnetReferences",
            "gatewayType",
            "gatewaySku",
            "vpnType",
            "activeActive",
            "gatewayTransitSummary",
        },
        FIREWALL: {"subnetReferences"},
        RESOLVER: {"dnsVirtualNetworkId"},
        VNET: {"resourceLocation", "dnsServerSummary"},
    }.get(kind.lower(), set())


def unique_known(
    resource: dict[str, Any], bundle: dict[str, Any], by_id: dict[str, list[dict[str, Any]]]
) -> bool:
    return (
        known_scoped_resource(
            resource.get("arm_id"), resource["resource_type"].lower(), by_id, bundle
        )
        is resource
    )


def joined(
    identity: Any, kind: str, bundle: dict[str, Any], by_id: dict[str, list[dict[str, Any]]]
) -> dict[str, Any] | None:
    identity = typed_reference(identity, (kind,))
    candidates = by_id.get(identity, []) if isinstance(identity, str) else []
    if len(candidates) != 1 or not unique_known(candidates[0], bundle, by_id):
        return None
    return candidates[0]


def subnet_context(
    identity: Any, bundle: dict[str, Any], by_id: dict[str, list[dict[str, Any]]]
) -> dict[str, Any]:
    subnet = joined(identity, SUBNET, bundle, by_id)
    if subnet is None:
        return unknown("routing_subnet_not_unique_known_in_scope")
    identity = subnet["arm_id"].lower()
    parent = joined(identity.rsplit("/subnets/", 1)[0], VNET, bundle, by_id)
    if parent is None:
        return unknown("routing_subnet_vnet_not_unique_known_in_scope")
    summary = review_fact(subnet["properties"], "routingSubnetPrefixSummary")
    current: Any = unknown("single_explicit_ipv4_prefix_required")
    if isinstance(summary, list) and len(summary) == 1 and summary[0]["family"] == 4:
        current = summary[0]["prefixLength"] <= 26
    return {
        "subnetId": identity,
        "virtualNetworkId": parent["arm_id"],
        "resourceLocation": location(parent["properties"].get("resourceLocation")),
        "prefixSummary": summary,
        "routeServerReservedSubnetName": identity.endswith("/subnets/routeserversubnet"),
        "currentRouteServerMinimumSize": {
            "source": SIZING_SOURCE,
            "maximumPrefixLength": 26,
            "matches": current,
            "warning": "Conditional Route Server sizing only; immutable checklist says /27. "
            "Dedicated use, NSG/UDR restrictions, service identity and applicability need review.",
        },
    }


def configuration_context(
    resource: dict[str, Any], bundle: dict[str, Any], by_id: dict[str, list[dict[str, Any]]]
) -> dict[str, Any]:
    if sum(row["resource_type"].lower() in KINDS for row in bundle["resources"]) > 100:
        return unknown("topology_configuration_population_over_100")
    if not unique_known(resource, bundle, by_id):
        return unknown("topology_resource_not_unique_known_in_scope")
    kind, identity, props = (
        resource["resource_type"].lower(),
        resource["arm_id"].lower(),
        resource["properties"],
    )
    result: dict[str, Any] = {"warning": WARNING}
    if kind == PEERING:
        local_id = identity.rsplit("/virtualnetworkpeerings/", 1)[0]
        remote_id = typed_reference(property_at(props, "remoteVirtualNetwork.id"), (VNET,))
        local = joined(local_id, VNET, bundle, by_id)
        remote = joined(remote_id, VNET, bundle, by_id)
        if local is None or remote is None or local_id == remote_id:
            return unknown("peering_endpoints_not_distinct_unique_known_in_scope")
        regions = [location(row["properties"].get("resourceLocation")) for row in (local, remote)]
        reverse = [
            row
            for row in bundle["resources"]
            if row["resource_type"].lower() == PEERING
            and isinstance(row.get("arm_id"), str)
            and row["arm_id"].lower().rsplit("/virtualnetworkpeerings/", 1)[0] == remote_id
            and property_at(row["properties"], "remoteVirtualNetwork.id") == local_id
        ]
        result.update(
            localVirtualNetworkId=local_id,
            remoteVirtualNetworkId=remote_id,
            locations=regions,
            differentConfiguredRegions=regions[0] != regions[1]
            if all(isinstance(value, str) for value in regions)
            else unknown("peering_locations_not_explicit"),
            reciprocalConfiguration=(
                {
                    "arm_id": reverse[0]["arm_id"],
                    "flags": review_fact(reverse[0]["properties"], "peeringTransitSummary"),
                }
                if len(reverse) == 1 and unique_known(reverse[0], bundle, by_id)
                else unknown("reciprocal_peering_not_unique_known_in_scope")
            ),
        )
    elif kind == RESOLVER:
        parent = joined(props.get("dnsVirtualNetworkId"), VNET, bundle, by_id)
        result["configuredVirtualNetwork"] = (
            {
                "arm_id": parent["arm_id"],
                "resourceLocation": location(parent["properties"].get("resourceLocation")),
            }
            if parent is not None
            else unknown("dns_vnet_not_unique_known_in_scope")
        )
    elif kind in {HUB, IPCONFIG, GATEWAY, FIREWALL, SUBNET}:
        refs: Any = None
        if kind == SUBNET:
            refs = [identity]
        elif kind == IPCONFIG:
            parent_id = identity.rsplit("/ipconfigurations/", 1)[0]
            if joined(parent_id, HUB, bundle, by_id) is None:
                return unknown("routing_ipconfiguration_parent_not_unique_known_in_scope")
            refs = [review_fact(props, "routingSubnetId")]
        elif kind == HUB:
            if isinstance(props.get("virtualWanId"), str):
                return unknown("virtual_wan_attachment_not_vnet_route_server_configuration")
            refs = review_fact(props, "routingSubnetReferences")
            if "routingSubnetReferences" not in props:
                configs = review_fact(props, "routingIpConfigurationIds")
                refs = []
                if not isinstance(configs, list) or not configs:
                    return unknown("routing_attachment_not_explicit")
                for ref in configs:
                    child = joined(ref, IPCONFIG, bundle, by_id)
                    if child is None or ref.rsplit("/ipconfigurations/", 1)[0] != identity:
                        return unknown("routing_ipconfiguration_missing_ambiguous_or_wrong_parent")
                    refs.append(review_fact(child["properties"], "routingSubnetId"))
        else:
            refs = props.get("subnetReferences")
        refs = typed_references(refs, SUBNET, 20)
        if not isinstance(refs, list) or not refs or any(not isinstance(ref, str) for ref in refs):
            return unknown("topology_subnet_relationship_missing_invalid_or_over_bound")
        if len(set(refs)) != len(refs):
            return unknown("topology_subnet_relationship_duplicate")
        result["configuredSubnets"] = [subnet_context(ref, bundle, by_id) for ref in refs]
    return result


def replay_properties(kind: str, properties: dict[str, Any]) -> dict[str, Any]:
    return {
        path: review_fact(properties, path)
        for path in resource_paths(kind) & PATHS
        if path in properties
    }
