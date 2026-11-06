"""Reviewed local routing/resilience facts, not effective-path or encryption tests."""

from ipaddress import IPv4Network
from typing import Any

from .sources import boolean, enumeration, property_at, unknown

PATHS = {
    "routeCount",
    "allowVirtualNetworkAccess",
    "remoteVirtualNetwork.id",
    "loadBalancerSku",
    "frontendSummary",
    "backendSummary",
    "macsecLinks",
    "connectionType",
    "useLocalAzureIpAddress",
    "virtualNetworkGateway1.id",
    "virtualNetworkGateway2.id",
    "virtualNetworkPrefixes",
    "disableBgpRoutePropagation",
}
KINDS = {
    "microsoft.network/routetables",
    "microsoft.network/virtualnetworks/virtualnetworkpeerings",
    "microsoft.network/loadbalancers",
    "microsoft.network/loadbalancers/backendaddresspools",
    "microsoft.network/expressrouteports",
    "microsoft.network/connections",
}
NEXT_HOPS = ("VirtualNetworkGateway", "VnetLocal", "Internet", "VirtualAppliance", "None")


def observed_route_count(values: dict[str, Any], observed: bool) -> Any:
    routes = values.get("routes")
    if (
        not observed
        or values.get("provisioningState") != "Succeeded"
        or not isinstance(routes, list)
        or len(routes) > 1000
    ):
        return unknown("complete_succeeded_observed_custom_routes_required")
    names = set()
    for route in routes:
        body = route.get("properties") if isinstance(route, dict) else None
        name = route.get("name") if isinstance(route, dict) else None
        if (
            not isinstance(name, str)
            or not name.strip()
            or len(name) > 256
            or name.casefold() in names
            or not isinstance(body, dict)
            or body.get("provisioningState", "Succeeded") != "Succeeded"
            or body.get("nextHopType") not in NEXT_HOPS
            or not isinstance(body.get("addressPrefix"), str)
            or not 1 <= len(body["addressPrefix"]) <= 128
        ):
            return unknown("custom_routes_invalid_duplicate_or_transient")
        names.add(name.casefold())
    return len(routes)


def frontend_facts(value: Any) -> Any:
    from .network_evidence import configured_zones, reference

    if not isinstance(value, list) or len(value) > 20:
        return unknown("frontend_summary_missing_or_over_20")
    return [
        {
            "zones": configured_zones(row.get("zones")),
            "publicIpId": reference(row.get("publicIpId")),
            "subnetId": reference(row.get("subnetId")),
        }
        if isinstance(row, dict)
        else unknown("frontend_not_explicit")
        for row in value
    ]


def backend_facts(value: Any) -> Any:
    from .network_evidence import bounded_count

    if not isinstance(value, list) or len(value) > 100:
        return unknown("backend_summary_missing_or_over_100")
    return [
        {
            "suppliedAddressCount": bounded_count(row.get("suppliedAddressCount"), 1000),
            "suppliedIpConfigCount": bounded_count(row.get("suppliedIpConfigCount"), 1000),
        }
        if isinstance(row, dict)
        else unknown("backend_not_explicit")
        for row in value
    ]


def macsec_facts(value: Any) -> Any:
    if not isinstance(value, list) or not 1 <= len(value) <= 2:
        return unknown("macsec_links_not_explicit")
    return [
        {
            "cipher": enumeration(
                row.get("cipher"), ("GcmAes128", "GcmAes256", "GcmAesXpn128", "GcmAesXpn256")
            ),
            "sciState": enumeration(row.get("sciState"), ("Disabled", "Enabled")),
        }
        if isinstance(row, dict)
        else unknown("macsec_link_not_explicit")
        for row in value
    ]


def review_fact(properties: dict[str, Any], path: str) -> Any:
    from .network_evidence import address_list, bounded_count, reference

    value = property_at(properties, path)
    if path == "routeCount":
        return bounded_count(value, 1000)
    if path in {
        "allowVirtualNetworkAccess",
        "useLocalAzureIpAddress",
        "disableBgpRoutePropagation",
    }:
        return boolean(value)
    if path == "loadBalancerSku":
        return enumeration(value, ("Basic", "Standard", "Gateway"))
    if path == "connectionType":
        return enumeration(value, ("IPsec", "ExpressRoute", "Vnet2Vnet"))
    if path == "frontendSummary":
        return frontend_facts(value)
    if path == "backendSummary":
        return backend_facts(value)
    if path == "macsecLinks":
        return macsec_facts(value)
    if path == "virtualNetworkPrefixes":
        return address_list(value, prefix_only=True)
    return reference(value)


def count_entries(value: Any) -> Any:
    if (
        not isinstance(value, list)
        or len(value) > 1000
        or any(not isinstance(row, dict) for row in value)
    ):
        return unknown("supplied_entries_missing_invalid_or_over_1000")
    return len(value)


def gateway_route_subchecks(
    resource: dict[str, Any], by_id: dict[str, list[dict[str, Any]]]
) -> dict[str, Any]:
    from .network_evidence import references
    from .protection_evidence import typed_reference

    identity = typed_reference(
        resource.get("arm_id"), ("microsoft.network/virtualnetworkgateways",)
    )
    if (
        resource.get("state") != "known"
        or resource.get("resource_type", "").lower() != "microsoft.network/virtualnetworkgateways"
        or not isinstance(identity, str)
        or len(by_id.get(identity, [])) != 1
    ):
        return {"unknown": "gateway_not_unique_known"}
    refs = references(resource["properties"].get("subnetReferences"))
    if not isinstance(refs, list) or not refs:
        return {"unknown": "gateway_subnet_references_not_explicit"}
    links: list[dict[str, Any]] = []
    for ref in refs[:20]:
        subnet_id = typed_reference(ref, ("microsoft.network/virtualnetworks/subnets",))
        subnets = by_id.get(subnet_id, []) if isinstance(subnet_id, str) else []
        if (
            not isinstance(subnet_id, str)
            or not subnet_id.endswith("/subnets/gatewaysubnet")
            or len(subnets) != 1
            or subnets[0]["state"] != "known"
            or subnets[0]["resource_type"].lower() != "microsoft.network/virtualnetworks/subnets"
        ):
            links.append({"unknown": "gateway_subnet_not_unique_known"})
            continue
        table_id = typed_reference(
            property_at(subnets[0]["properties"], "routeTable.id"),
            ("microsoft.network/routetables",),
        )
        tables = by_id.get(table_id, []) if isinstance(table_id, str) else []
        propagation: Any = unknown("gateway_route_table_not_unique_known")
        if (
            len(tables) == 1
            and tables[0]["state"] == "known"
            and tables[0]["resource_type"].lower() == "microsoft.network/routetables"
        ):
            disabled = boolean(tables[0]["properties"].get("disableBgpRoutePropagation"))
            propagation = not disabled if type(disabled) is bool else disabled
        links.append(
            {
                "subnet_id": subnet_id,
                "route_table_id": table_id,
                "route_propagation_enabled": propagation,
            }
        )
    return {"gateway_subnet_routes": links, "truncated": len(refs) > 20}


def projected_properties(
    kind: str,
    values: dict[str, Any],
    *,
    terraform: bool,
    observed: bool,
    root: Any,
) -> dict[str, Any]:
    from .network_evidence import reference

    if kind == "microsoft.network/routetables":
        enabled = values.get("bgp_route_propagation_enabled")
        return {
            "routeCount": observed_route_count(values, observed and not terraform),
            "disableBgpRoutePropagation": boolean(not enabled)
            if terraform and type(enabled) is bool
            else unknown("terraform_bgp_propagation_not_explicit")
            if terraform
            else boolean(values.get("disableBgpRoutePropagation")),
        }
    if kind == "microsoft.network/virtualnetworks/virtualnetworkpeerings":
        return {
            "allowVirtualNetworkAccess": boolean(
                values.get(
                    "allow_virtual_network_access" if terraform else "allowVirtualNetworkAccess"
                )
            ),
            "remoteVirtualNetwork": {
                "id": reference(
                    values.get("remote_virtual_network_id")
                    if terraform
                    else property_at(values, "remoteVirtualNetwork.id")
                )
            },
        }
    if kind == "microsoft.network/loadbalancers":
        configs = values.get(
            "frontend_ip_configuration" if terraform else "frontendIPConfigurations"
        )
        frontends = None
        if isinstance(configs, list) and len(configs) <= 20:
            frontends = []
            for entry in configs:
                body = (
                    entry
                    if terraform
                    else entry.get("properties")
                    if isinstance(entry, dict)
                    else None
                )
                frontends.append(
                    {
                        "zones": entry.get("zones") if isinstance(entry, dict) else None,
                        "publicIpId": body.get("public_ip_address_id")
                        if terraform and isinstance(body, dict)
                        else property_at(body, "publicIPAddress.id"),
                        "subnetId": body.get("subnet_id")
                        if terraform and isinstance(body, dict)
                        else property_at(body, "subnet.id"),
                    }
                )
        pools = values.get("backendAddressPools") if not terraform else None
        return {
            "loadBalancerSku": enumeration(
                values.get("sku")
                if terraform
                else root.get("sku", {}).get("name")
                if isinstance(root, dict) and isinstance(root.get("sku"), dict)
                else None,
                ("Basic", "Standard", "Gateway"),
            ),
            "frontendSummary": frontend_facts(frontends),
            "backendSummary": backend_pools(pools),
        }
    if kind == "microsoft.network/loadbalancers/backendaddresspools":
        return {
            "backendSummary": unknown("terraform_separate_backend_members_not_complete")
            if terraform
            else backend_pools([{"properties": values}])
        }
    if kind == "microsoft.network/expressrouteports":
        links = values.get("links")
        prepared = None
        if terraform:
            first, second = values.get("link1"), values.get("link2")
            if (
                isinstance(first, list)
                and len(first) == 1
                and isinstance(second, list)
                and len(second) == 1
            ):
                prepared = [
                    {
                        "cipher": link[0].get("macsec_cipher")
                        if isinstance(link[0], dict)
                        else None,
                        "sciState": ("Enabled" if link[0]["macsec_sci_enabled"] else "Disabled")
                        if isinstance(link[0], dict)
                        and type(link[0].get("macsec_sci_enabled")) is bool
                        else None,
                    }
                    for link in (first, second)
                ]
        elif isinstance(links, list) and len(links) <= 2:
            prepared = [property_at(entry, "properties.macSecConfig") for entry in links]
        return {"macsecLinks": macsec_facts(prepared)}
    if kind == "microsoft.network/connections":
        return {
            "connectionType": enumeration(
                values.get("type" if terraform else "connectionType"),
                ("IPsec", "ExpressRoute", "Vnet2Vnet"),
            ),
            "useLocalAzureIpAddress": boolean(
                values.get(
                    "local_azure_ip_address_enabled" if terraform else "useLocalAzureIpAddress"
                )
            ),
            "virtualNetworkGateway1": {
                "id": reference(
                    values.get("virtual_network_gateway_id")
                    if terraform
                    else property_at(values, "virtualNetworkGateway1.id")
                )
            },
            "virtualNetworkGateway2": {
                "id": reference(
                    values.get("peer_virtual_network_gateway_id")
                    if terraform
                    else property_at(values, "virtualNetworkGateway2.id")
                )
            },
        }
    return {}


def backend_pools(value: Any) -> Any:
    if not isinstance(value, list) or len(value) > 100:
        return unknown("backend_pools_missing_or_over_100")
    result = []
    for pool in value:
        body = pool.get("properties") if isinstance(pool, dict) else None
        if not isinstance(body, dict):
            return unknown("backend_pool_not_explicit")
        result.append(
            {
                "suppliedAddressCount": count_entries(body.get("loadBalancerBackendAddresses")),
                "suppliedIpConfigCount": count_entries(body.get("backendIPConfigurations")),
            }
        )
    return backend_facts(result)


def address_subchecks(value: Any) -> dict[str, Any]:
    from .network_evidence import address_list

    prefixes = address_list(value, prefix_only=True)
    known = (
        isinstance(prefixes, list)
        and bool(prefixes)
        and all(isinstance(prefix, str) for prefix in prefixes)
    )
    if not known:
        return {
            "supplied_vnet_ipv4_prefixes_are_rfc1918": unknown("explicit_ipv4_prefixes_required"),
            "supplied_vnet_ipv4_prefixes_do_not_overlap": unknown(
                "explicit_ipv4_prefixes_required"
            ),
        }
    networks = [IPv4Network(prefix) for prefix in prefixes]
    private = [IPv4Network(prefix) for prefix in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    return {
        "supplied_vnet_ipv4_prefixes_are_rfc1918": all(
            any(network.subnet_of(boundary) for boundary in private) for network in networks
        ),
        "supplied_vnet_ipv4_prefixes_do_not_overlap": all(
            not first.overlaps(second)
            for index, first in enumerate(networks)
            for second in networks[index + 1 :]
        ),
    }
