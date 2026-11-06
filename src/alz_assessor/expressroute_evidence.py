"""Explicit ExpressRoute configuration facts, not billing, capacity or path verdicts."""

import math
import re
from typing import Any

from .contracts import canonical_id, digest, identity_type
from .sources import boolean, enumeration, property_at, unknown
from .terraform import InputError

PATHS = {
    "circuitSku.tier",
    "circuitSku.family",
    "providerCircuitBandwidthMbps",
    "directCircuitBandwidthGbps",
    "expressRoutePort.id",
    "directPortRateLimit",
    "directPortBandwidthGbps",
    "directPortBillingType",
    "directPortEncapsulation",
    "peeringLocationConfigured",
    "peeringLocationFingerprint",
    "expressRouteGatewayBypass",
    "enablePrivateLinkFastPath",
    "gatewayScaleBounds",
    "gatewayPublicIpReferences",
    "publicIpSku",
}
CIRCUIT_KIND = "microsoft.network/expressroutecircuits"
PORT_KIND = "microsoft.network/expressrouteports"
BILLING_TYPES = ("MeteredData", "UnlimitedData")
CIRCUIT_TIERS = ("Basic", "Local", "Standard", "Premium")


def bandwidth(value: Any, *, direct: bool) -> Any:
    maximum = 400 if direct else 10000
    numeric = type(value) in (int, float) if direct else type(value) is int
    if numeric and 0 < value <= maximum and math.isfinite(value):
        return value
    return unknown("bandwidth_missing_unresolved_invalid_or_outside_reviewed_bound")


def port_reference(value: Any) -> Any:
    if isinstance(value, str):
        try:
            identity = canonical_id(value)
            if identity_type(identity) == PORT_KIND:
                return identity
        except InputError:
            pass
    return unknown("direct_port_reference_not_explicit_or_wrong_type")


def location_configured(value: Any) -> Any:
    if (
        isinstance(value, str)
        and 1 <= len(value) <= 128
        and value.strip()
        and not value.startswith("[")
        and all(32 <= ord(character) <= 126 for character in value)
    ):
        return True
    return unknown("peering_location_not_explicit")


def location_fingerprint(value: Any) -> Any:
    return (
        digest(value.strip().casefold())
        if location_configured(value) is True
        else unknown("peering_location_not_explicit")
    )


def fingerprint_fact(value: Any) -> Any:
    return (
        value
        if isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value)
        else unknown("peering_location_fingerprint_not_explicit")
    )


def circuit_properties(
    values: dict[str, Any], *, terraform: bool, root: Any = None
) -> dict[str, Any]:
    sku = values.get("sku") if terraform else root.get("sku") if isinstance(root, dict) else None
    if terraform:
        sku = sku[0] if isinstance(sku, list) and len(sku) == 1 else None
    provider = values if terraform else values.get("serviceProviderProperties")
    provider = provider if isinstance(provider, dict) else {}
    result = {
        "circuitSku": {
            "tier": enumeration(property_at(sku, "tier"), CIRCUIT_TIERS),
            "family": enumeration(property_at(sku, "family"), BILLING_TYPES),
        },
        "providerCircuitBandwidthMbps": bandwidth(
            provider.get("bandwidth_in_mbps" if terraform else "bandwidthInMbps"), direct=False
        ),
        "directCircuitBandwidthGbps": bandwidth(
            values.get("bandwidth_in_gbps" if terraform else "bandwidthInGbps"), direct=True
        ),
        "expressRoutePort": {
            "id": port_reference(
                values.get("express_route_port_id")
                if terraform
                else property_at(values, "expressRoutePort.id")
            )
        },
        "directPortRateLimit": boolean(
            values.get("rate_limiting_enabled" if terraform else "enableDirectPortRateLimit")
        ),
        "peeringLocationConfigured": location_configured(
            provider.get("peering_location" if terraform else "peeringLocation")
        ),
        "peeringLocationFingerprint": location_fingerprint(
            provider.get("peering_location" if terraform else "peeringLocation")
        ),
    }
    provider_supplied = (
        any(
            values.get(key) is not None
            for key in ("service_provider_name", "peering_location", "bandwidth_in_mbps")
        )
        if terraform
        else values.get("serviceProviderProperties") is not None
    )
    direct_supplied = (
        any(values.get(key) is not None for key in ("express_route_port_id", "bandwidth_in_gbps"))
        if terraform
        else any(values.get(key) is not None for key in ("expressRoutePort", "bandwidthInGbps"))
    )
    if provider_supplied and direct_supplied:
        conflict = unknown("provider_and_direct_circuit_configuration_conflict")
        for path in (
            "providerCircuitBandwidthMbps",
            "directCircuitBandwidthGbps",
            "directPortRateLimit",
            "peeringLocationConfigured",
            "peeringLocationFingerprint",
        ):
            result[path] = conflict
        result["expressRoutePort"] = {"id": conflict}
    return result


def port_properties(values: dict[str, Any], *, terraform: bool) -> dict[str, Any]:
    value = values.get("bandwidth_in_gbps" if terraform else "bandwidthInGbps")
    return {
        "directPortBandwidthGbps": value
        if type(value) is int and value in (10, 100, 400)
        else unknown("direct_port_bandwidth_not_reviewed"),
        "directPortBillingType": enumeration(
            values.get("billing_type" if terraform else "billingType"), BILLING_TYPES
        ),
        "directPortEncapsulation": enumeration(values.get("encapsulation"), ("Dot1Q", "QinQ")),
        "peeringLocationConfigured": location_configured(
            values.get("peering_location" if terraform else "peeringLocation")
        ),
        "peeringLocationFingerprint": location_fingerprint(
            values.get("peering_location" if terraform else "peeringLocation")
        ),
    }


def fastpath_properties(values: dict[str, Any], *, terraform: bool) -> dict[str, Any]:
    return {
        "expressRouteGatewayBypass": boolean(
            values.get("express_route_gateway_bypass" if terraform else "expressRouteGatewayBypass")
        ),
        "enablePrivateLinkFastPath": boolean(
            values.get(
                "private_link_fast_path_enabled" if terraform else "enablePrivateLinkFastPath"
            )
        ),
    }


def scale_bounds(value: Any) -> Any:
    if not isinstance(value, dict):
        return unknown("gateway_scale_bounds_not_explicit")
    minimum, maximum = value.get("min"), value.get("max")
    if (
        type(minimum) is int
        and type(maximum) is int
        and 1 <= minimum <= maximum <= 40
        and (minimum != 1 or maximum == 1)
    ):
        return {"min": minimum, "max": maximum}
    return unknown("gateway_scale_bounds_invalid_or_outside_reviewed_range")


def gateway_properties(values: dict[str, Any], *, terraform: bool) -> dict[str, Any]:
    from .protection_evidence import typed_reference

    configs = values.get("ip_configuration" if terraform else "ipConfigurations")
    refs = (
        [
            typed_reference(
                property_at(
                    entry, "public_ip_address_id" if terraform else "properties.publicIPAddress.id"
                ),
                ("microsoft.network/publicipaddresses",),
            )
            for entry in configs
        ]
        if isinstance(configs, list) and 1 <= len(configs) <= 3
        else unknown("gateway_ip_configurations_missing_or_over_3")
    )
    return {
        "gatewayPublicIpReferences": refs,
        "gatewayScaleBounds": unknown("terraform_gateway_scale_bounds_not_reviewed")
        if terraform
        else scale_bounds(property_at(values, "autoScaleConfiguration.bounds")),
    }


def fastpath_subchecks(properties: dict[str, Any]) -> dict[str, Any]:
    from .protection_evidence import GATEWAY_SKUS

    result: dict[str, Any] = {}
    if "gatewaySku" in properties:
        sku = property_at(properties, "gatewaySku")
        kind = property_at(properties, "gatewayType")
        supported: Any = unknown("explicit_gateway_type_and_supported_sku_required")
        if kind in ("Vpn", "ExpressRoute") and isinstance(sku, str) and sku in GATEWAY_SKUS:
            supported = kind == "ExpressRoute" and sku in ("UltraPerformance", "ErGw3AZ")
            if kind == "ExpressRoute" and sku == "ErGwScale":
                bounds = scale_bounds(property_at(properties, "gatewayScaleBounds"))
                supported = (
                    bounds["min"] >= 10
                    if isinstance(bounds, dict) and "unknown" not in bounds
                    else unknown("explicit_ergwscale_minimum_required")
                )
        result["configured_gateway_meets_fastpath_sku_and_minimum_scale_requirement"] = supported
    if "expressRouteGatewayBypass" in properties or "enablePrivateLinkFastPath" in properties:
        bypass = property_at(properties, "expressRouteGatewayBypass")
        private = property_at(properties, "enablePrivateLinkFastPath")
        result["configured_private_link_fastpath_flags_are_consistent"] = (
            not private or bypass
            if type(bypass) is bool and type(private) is bool
            else unknown("both_explicit_fastpath_flags_required")
        )
    return result


def review_fact(properties: dict[str, Any], path: str) -> Any:
    value = property_at(properties, path)
    if path == "circuitSku.tier":
        return enumeration(value, CIRCUIT_TIERS)
    if path in {"circuitSku.family", "directPortBillingType"}:
        return enumeration(value, BILLING_TYPES)
    if path in {"providerCircuitBandwidthMbps", "directCircuitBandwidthGbps"}:
        return bandwidth(value, direct=path == "directCircuitBandwidthGbps")
    if path == "directPortBandwidthGbps":
        return port_properties({"bandwidthInGbps": value}, terraform=False)[path]
    if path == "directPortEncapsulation":
        return enumeration(value, ("Dot1Q", "QinQ"))
    if path == "publicIpSku":
        return enumeration(value, ("Basic", "Standard"))
    if path == "gatewayScaleBounds":
        return scale_bounds(value)
    if path == "gatewayPublicIpReferences":
        from .protection_evidence import typed_reference

        return (
            [typed_reference(item, ("microsoft.network/publicipaddresses",)) for item in value]
            if isinstance(value, list) and 1 <= len(value) <= 3
            else unknown("gateway_public_ip_references_missing_or_over_3")
        )
    if path == "expressRoutePort.id":
        return port_reference(value)
    if path in {
        "directPortRateLimit",
        "expressRouteGatewayBypass",
        "enablePrivateLinkFastPath",
    }:
        return boolean(value)
    if path == "peeringLocationConfigured":
        return True if value is True else unknown("peering_location_not_explicit")
    if path == "peeringLocationFingerprint":
        return fingerprint_fact(value)
    raise ValueError("Unsupported ExpressRoute review fact path")


def known_resource(
    identity: Any, kind: str, by_id: dict[str, list[dict[str, Any]]]
) -> dict[str, Any] | None:
    from .protection_evidence import typed_reference

    reference = typed_reference(identity, (kind,))
    matches = by_id.get(reference, []) if isinstance(reference, str) else []
    if (
        len(matches) == 1
        and matches[0]["state"] == "known"
        and matches[0]["resource_type"].lower() == kind
    ):
        return matches[0]
    return None


def circuit_location_fingerprint(
    circuit: dict[str, Any], by_id: dict[str, list[dict[str, Any]]]
) -> Any:
    if known_resource(circuit.get("arm_id"), CIRCUIT_KIND, by_id) is None:
        return unknown("circuit_not_unique_known")
    provider = fingerprint_fact(circuit["properties"].get("peeringLocationFingerprint"))
    port_id = property_at(circuit["properties"], "expressRoutePort.id")
    if isinstance(port_id, str):
        if isinstance(provider, str):
            return unknown("provider_and_direct_location_bindings_ambiguous")
        port = known_resource(port_id, PORT_KIND, by_id)
        return (
            fingerprint_fact(port["properties"].get("peeringLocationFingerprint"))
            if port
            else unknown("direct_port_not_unique_known")
        )
    return provider


def circuit_location_subchecks(
    circuits: list[dict[str, Any]], by_id: dict[str, list[dict[str, Any]]]
) -> dict[str, Any]:
    if not circuits or len(circuits) > 100:
        return {"unknown": "supplied_circuit_population_empty_or_over_100"}
    from .protection_evidence import typed_reference

    identities = [typed_reference(circuit.get("arm_id"), (CIRCUIT_KIND,)) for circuit in circuits]
    if any(not isinstance(identity, str) for identity in identities) or len(set(identities)) != len(
        identities
    ):
        return {"unknown": "supplied_circuit_identities_missing_or_duplicate"}
    fingerprints = [circuit_location_fingerprint(circuit, by_id) for circuit in circuits]
    if any(not isinstance(value, str) for value in fingerprints):
        return {"unknown": "supplied_circuit_or_location_binding_not_unique_known"}
    count = len(set(fingerprints))
    return {
        "supplied_distinct_circuit_count": len(circuits),
        "supplied_distinct_configured_location_count": count,
        "supplied_circuits_include_different_location_labels": count >= 2,
    }


def gateway_circuit_subchecks(
    gateway: dict[str, Any],
    resources: list[dict[str, Any]],
    by_id: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    from .protection_evidence import typed_reference

    gateway_id = typed_reference(
        gateway.get("arm_id"), ("microsoft.network/virtualnetworkgateways",)
    )
    if (
        known_resource(gateway_id, "microsoft.network/virtualnetworkgateways", by_id) is None
        or property_at(gateway["properties"], "gatewayType") != "ExpressRoute"
    ):
        return {"unknown": "expressroute_gateway_not_unique_known"}
    connections = [
        resource
        for resource in resources
        if resource["resource_type"].lower() == "microsoft.network/connections"
    ]
    if not connections or len(connections) > 100:
        return {"unknown": "supplied_connection_population_empty_or_over_100"}
    circuits: dict[str, dict[str, Any]] = {}
    count = 0
    for connection in connections:
        props = connection["properties"]
        kind = property_at(props, "connectionType")
        if connection["state"] != "known" or kind not in ("ExpressRoute", "IPsec", "Vnet2Vnet"):
            return {"unknown": "supplied_connection_type_or_state_not_known"}
        if kind != "ExpressRoute":
            continue
        bound_gateway = typed_reference(
            property_at(props, "virtualNetworkGateway1.id"),
            ("microsoft.network/virtualnetworkgateways",),
        )
        if not isinstance(bound_gateway, str):
            return {"unknown": "supplied_connection_gateway_binding_not_explicit"}
        if bound_gateway != gateway_id:
            continue
        if known_resource(connection.get("arm_id"), "microsoft.network/connections", by_id) is None:
            return {"unknown": "supplied_gateway_connection_not_unique_known"}
        circuit_id = typed_reference(props.get("expressRouteCircuitId"), (CIRCUIT_KIND,))
        circuit = known_resource(circuit_id, CIRCUIT_KIND, by_id)
        if circuit is None:
            return {"unknown": "supplied_gateway_circuit_not_unique_known"}
        circuits[canonical_id(circuit["arm_id"])] = circuit
        count += 1
    result = circuit_location_subchecks(list(circuits.values()), by_id)
    return {"supplied_gateway_connection_count": count, **result}
