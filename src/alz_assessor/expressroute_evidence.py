"""Explicit ExpressRoute configuration facts, not billing, capacity or path verdicts."""

import math
from typing import Any

from .contracts import canonical_id, identity_type
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
    "expressRouteGatewayBypass",
    "enablePrivateLinkFastPath",
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
    raise ValueError("Unsupported ExpressRoute review fact path")
