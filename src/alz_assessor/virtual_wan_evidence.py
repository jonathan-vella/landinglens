"""Minimized supplied Virtual WAN configuration, not effective topology or capacity."""

import re
from ipaddress import IPv4Network
from typing import Any

from .contracts import digest, scope_id
from .dns_evidence import location, typed_references
from .protection_evidence import block, rows, typed_reference
from .sources import boolean, enumeration, property_at, unknown

WAN = "microsoft.network/virtualwans"
HUB = "microsoft.network/virtualhubs"
CONNECTION = HUB + "/hubvirtualnetworkconnections"
TABLE = HUB + "/hubroutetables"
INTENT = HUB + "/routingintent"
FIREWALL = "microsoft.network/azurefirewalls"
KINDS = {WAN, HUB, CONNECTION, TABLE, INTENT}
GUIDS = {
    "412e7f98-3f63-4047-82dd-69c5b5c2622f",
    "54b69bad-33aa-4d5e-ac68-e1d76667313b",
    "7d5d1e4e-6146-458d-9558-fd77249b8211",
    "6667313b-4f56-464b-9e98-4a859c773e7d",
    "261623a7-65a9-417e-8f34-8ef254c27d42",
    "727c77e1-b9aa-4a37-a024-129d042422c1",
    "d49ac006-6670-4bc9-9948-d3e0a3a94f4d",
    "2586b854-237e-47f1-84a1-d45d4cd2310d",
    "9c75dfef-573c-461c-a698-68598595581a",
}
PATHS = {
    "virtualWanType",
    "wanBranchTrafficAllowed",
    "hubBranchTrafficAllowed",
    "virtualWanId",
    "virtualWanHubId",
    "hubFirewallId",
    "hubRoutingPreference",
    "hubPrefixSummary",
    "hubRouterMinCapacity",
    "hubRouteLabels",
    "hubConnectionRouting",
    "hubInternetSecurityEnabled",
    "hubRemoteVirtualNetworkId",
    "hubRoutingPolicies",
}


def prefix_summary(value: Any) -> Any:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9.]{7,15}/(?:0|[1-9][0-9]?)", value):
        return unknown("hub_ipv4_network_prefix_missing_invalid_or_withheld")
    try:
        prefix = IPv4Network(value, strict=True)
    except ValueError:
        return unknown("hub_ipv4_network_prefix_missing_invalid_or_withheld")
    return {"prefixLength": prefix.prefixlen}


def prefix_fact(value: Any) -> Any:
    length = value.get("prefixLength") if isinstance(value, dict) else None
    return (
        {"prefixLength": length}
        if type(length) is int and 0 <= length <= 32
        else unknown("hub_prefix_length_missing_invalid_or_withheld")
    )


def label_summary(value: Any) -> Any:
    if (
        not isinstance(value, list)
        or len(value) > 100
        or any(
            not isinstance(label, str)
            or not 1 <= len(label) <= 256
            or not label.strip()
            or any(ord(char) < 32 or ord(char) > 126 for char in label)
            for label in value
        )
        or len(set(value)) != len(value)
    ):
        return unknown("hub_labels_missing_invalid_duplicate_or_over_100")
    # Exact-label equality only. Fingerprints are not anonymous or case-insensitive identities.
    return {
        "suppliedCount": len(value),
        "defaultLabelExplicit": "Default" in value,
        "fingerprints": sorted(digest(label) for label in value),
    }


def label_fact(value: Any) -> Any:
    count = value.get("suppliedCount") if isinstance(value, dict) else None
    fingerprints = value.get("fingerprints") if isinstance(value, dict) else None
    default = value.get("defaultLabelExplicit") if isinstance(value, dict) else None
    if (
        type(count) is not int
        or not 0 <= count <= 100
        or type(default) is not bool
        or not isinstance(fingerprints, list)
        or len(fingerprints) != count
        or any(
            not isinstance(item, str) or not re.fullmatch(r"[0-9a-f]{64}", item)
            for item in fingerprints
        )
        or len(set(fingerprints)) != count
        or default != (digest("Default") in fingerprints)
    ):
        return unknown("hub_label_summary_missing_invalid_or_over_100")
    return {
        "suppliedCount": count,
        "defaultLabelExplicit": default,
        "fingerprints": sorted(fingerprints),
    }


def routing_fact(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("hub_connection_routing_not_explicit")
    return {
        "associatedTableId": typed_reference(value.get("associatedTableId"), (TABLE,)),
        "propagatedTableIds": typed_references(value.get("propagatedTableIds"), TABLE, 100),
        "labels": label_fact(value.get("labels")),
    }


def policy_fact(value: Any) -> Any:
    if not rows(value, 2) or not value:
        return unknown("hub_routing_policies_missing_invalid_or_over_two")
    destinations = [row.get("destination") for row in value]
    if any(item not in ("Internet", "PrivateTraffic") for item in destinations) or len(
        set(destinations)
    ) != len(destinations):
        return unknown("hub_routing_policy_destination_duplicate_or_unsupported")
    return [
        {
            "destination": row["destination"],
            "firewallId": typed_reference(row.get("firewallId"), (FIREWALL,)),
        }
        for row in value
    ]


def policy_summary(value: Any, *, terraform: bool) -> Any:
    if not rows(value, 2) or not value:
        return unknown("hub_routing_policies_missing_invalid_or_over_two")
    names = [row.get("name") for row in value]
    if any(
        not isinstance(name, str) or not name.strip() or len(name) > 256 for name in names
    ) or len(set(names)) != len(names):
        return unknown("hub_routing_policy_identity_missing_invalid_or_duplicate")
    prepared = []
    for row in value:
        destinations = row.get("destinations")
        if not isinstance(destinations, list) or len(destinations) != 1:
            return unknown("hub_routing_policy_destinations_unsupported")
        prepared.append(
            {
                "destination": destinations[0],
                "firewallId": row.get("next_hop" if terraform else "nextHop"),
            }
        )
    return policy_fact(prepared)


def review_fact(properties: dict[str, Any], path: str) -> Any:
    value = property_at(properties, path)
    if path == "virtualWanType":
        return enumeration(value, ("Basic", "Standard"))
    if path == "hubRoutingPreference":
        return enumeration(value, ("ExpressRoute", "ASPath", "VpnGateway"))
    if path in {"wanBranchTrafficAllowed", "hubBranchTrafficAllowed", "hubInternetSecurityEnabled"}:
        return boolean(value)
    if path == "hubPrefixSummary":
        return prefix_fact(value)
    if path == "hubRouterMinCapacity":
        return (
            value
            if type(value) is int and 2 <= value <= 50
            else unknown("hub_riu_outside_reviewed_2_50_table_or_missing")
        )
    if path == "hubRouteLabels":
        return label_fact(value)
    if path == "hubConnectionRouting":
        return routing_fact(value)
    if path == "hubRoutingPolicies":
        return policy_fact(value)
    return typed_reference(
        value,
        {
            "virtualWanId": (WAN,),
            "virtualWanHubId": (HUB,),
            "hubFirewallId": (FIREWALL,),
            "hubRemoteVirtualNetworkId": ("microsoft.network/virtualnetworks",),
        }[path],
    )


def projected_properties(
    kind: str, values: dict[str, Any], *, terraform: bool, root: Any = None
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if kind == WAN:
        result = {
            "virtualWanType": values.get("type"),
            "wanBranchTrafficAllowed": values.get(
                "allow_branch_to_branch_traffic" if terraform else "allowBranchToBranchTraffic"
            ),
        }
    elif kind == HUB:
        result = {
            "virtualWanId": values.get("virtual_wan_id")
            if terraform
            else property_at(values, "virtualWan.id"),
            "hubBranchTrafficAllowed": values.get(
                "branch_to_branch_traffic_enabled" if terraform else "allowBranchToBranchTraffic"
            ),
            "hubRoutingPreference": values.get(
                "hub_routing_preference" if terraform else "hubRoutingPreference"
            ),
            "hubPrefixSummary": prefix_summary(
                values.get("address_prefix" if terraform else "addressPrefix")
            ),
            "hubRouterMinCapacity": values.get("virtual_router_auto_scale_min_capacity")
            if terraform
            else property_at(values, "virtualRouterAutoScaleConfiguration.minCapacity"),
            "hubFirewallId": unknown("terraform_hub_firewall_reverse_join_required")
            if terraform
            else property_at(values, "azureFirewall.id"),
        }
    elif kind == FIREWALL:
        result["virtualWanHubId"] = (
            block(values.get("virtual_hub")).get("virtual_hub_id")
            if terraform
            else property_at(values, "virtualHub.id")
        )
    elif kind == TABLE:
        result["hubRouteLabels"] = label_summary(values.get("labels"))
    elif kind == INTENT:
        result["hubRoutingPolicies"] = policy_summary(
            values.get("routing_policy" if terraform else "routingPolicies"), terraform=terraform
        )
    elif kind == CONNECTION:
        routing = block(values.get("routing")) if terraform else values.get("routingConfiguration")
        routing = routing if isinstance(routing, dict) and "unknown" not in routing else {}
        propagated = (
            block(routing.get("propagated_route_table"))
            if terraform
            else routing.get("propagatedRouteTables")
        )
        propagated = propagated if isinstance(propagated, dict) else {}
        ids = propagated.get("route_table_ids" if terraform else "ids")
        result = {
            "hubInternetSecurityEnabled": values.get(
                "internet_security_enabled" if terraform else "enableInternetSecurity"
            ),
            "hubRemoteVirtualNetworkId": values.get("remote_virtual_network_id")
            if terraform
            else property_at(values, "remoteVirtualNetwork.id"),
            "hubConnectionRouting": {
                "associatedTableId": routing.get("associated_route_table_id")
                if terraform
                else property_at(routing, "associatedRouteTable.id"),
                "propagatedTableIds": ids
                if terraform
                else [row.get("id") if isinstance(row, dict) else None for row in ids]
                if isinstance(ids, list) and len(ids) <= 100
                else None,
                "labels": label_summary(propagated.get("labels")),
            },
        }
    result = {path: review_fact(result, path) for path in result}
    if kind in {WAN, HUB}:
        result["resourceLocation"] = location(
            values.get("location") if terraform else property_at(root, "location")
        )
    return result


def subchecks(properties: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if "hubPrefixSummary" in properties:
        length = prefix_fact(properties["hubPrefixSummary"]).get("prefixLength")
        for prefix in (24, 23, 22):
            result[f"configured_hub_ipv4_prefix_at_least_{prefix}"] = (
                length <= prefix
                if type(length) is int
                else unknown("explicit_valid_hub_ipv4_prefix_required")
            )
    if "hubRoutingPreference" in properties:
        preference = review_fact(properties, "hubRoutingPreference")
        result["configured_hub_routing_preference_is_aspath"] = (
            preference == "ASPath" if isinstance(preference, str) else preference
        )
    return result


def known_resource(
    identity: Any, kind: str, by_id: dict[str, list[dict[str, Any]]], scope: str | None
) -> dict[str, Any] | None:
    ref = typed_reference(identity, (kind,))
    boundary = scope_id(scope) if scope else None
    matches = by_id.get(ref, []) if isinstance(ref, str) else []
    if (
        boundary is None
        or not isinstance(ref, str)
        or not ref.startswith(boundary + "/")
        or len(matches) != 1
        or matches[0].get("state") != "known"
        or matches[0].get("resource_type", "").lower() != kind
        or typed_reference(matches[0].get("arm_id"), (kind,)) != ref
    ):
        return None
    return matches[0]


def hub_context(
    resource: dict[str, Any], by_id: dict[str, list[dict[str, Any]]], scope: str | None
) -> dict[str, Any]:
    kind = resource.get("resource_type", "").lower()
    if (
        kind not in {HUB, CONNECTION, TABLE, INTENT, FIREWALL}
        or known_resource(resource.get("arm_id"), kind, by_id, scope) is not resource
    ):
        return unknown("vwan_resource_not_unique_known_typed_scoped")
    identity = typed_reference(resource["arm_id"], (kind,))
    hub_id = (
        identity
        if kind == HUB
        else (
            review_fact(resource["properties"], "virtualWanHubId")
            if kind == FIREWALL
            else identity.rsplit("/", 2)[0]
        )
    )
    hub = known_resource(hub_id, HUB, by_id, scope)
    wan = known_resource(
        review_fact(hub["properties"], "virtualWanId") if hub else None, WAN, by_id, scope
    )
    if hub is None or wan is None:
        return unknown("vwan_hub_wan_join_not_unique_known_typed_scoped")
    result: dict[str, Any] = {
        "hub_id": hub_id,
        "wan_id": wan["arm_id"],
        "virtualWanType": review_fact(wan["properties"], "virtualWanType"),
        "wanBranchTrafficAllowed": review_fact(wan["properties"], "wanBranchTrafficAllowed"),
        "hubBranchTrafficAllowed": review_fact(hub["properties"], "hubBranchTrafficAllowed"),
    }
    if kind in {HUB, FIREWALL, INTENT}:
        firewall_id = review_fact(hub["properties"], "hubFirewallId")
        firewall = known_resource(firewall_id, FIREWALL, by_id, scope)
        if (
            firewall is None
            or (kind == FIREWALL and firewall is not resource)
            or (
                review_fact(firewall["properties"], "virtualWanHubId") != hub_id
                or property_at(firewall["properties"], "sku.name") != "AZFW_Hub"
            )
        ):
            result["local_azure_firewall_join"] = unknown(
                "bidirectional_known_local_hub_firewall_join_required"
            )
        else:
            result["local_azure_firewall_join"] = firewall_id
            result["firewall_hub_prefix_at_least_22"] = subchecks(hub["properties"]).get(
                "configured_hub_ipv4_prefix_at_least_22",
                unknown("explicit_valid_hub_ipv4_prefix_required"),
            )
        if kind == INTENT:
            policies = review_fact(resource["properties"], "hubRoutingPolicies")
            internet = (
                [row for row in policies if row["destination"] == "Internet"]
                if isinstance(policies, list)
                else []
            )
            result["explicit_internet_intent_to_joined_local_firewall"] = (
                internet[0]["firewallId"] == firewall_id
                if len(internet) == 1
                and isinstance(internet[0]["firewallId"], str)
                and isinstance(result["local_azure_firewall_join"], str)
                else unknown("explicit_internet_policy_and_known_local_firewall_required")
            )
    if kind == CONNECTION:
        routing = review_fact(resource["properties"], "hubConnectionRouting")
        table_id = routing.get("associatedTableId")
        table = known_resource(table_id, TABLE, by_id, scope)
        result["associated_local_hub_table_known"] = (
            True
            if table and table_id.rsplit("/", 2)[0] == hub_id
            else unknown("associated_table_not_unique_known_in_same_hub")
        )
        labels = label_fact(routing.get("labels"))
        result["explicit_propagation_labels_supplied"] = (
            labels["suppliedCount"] > 0 if "unknown" not in labels else labels
        )
        ids = routing.get("propagatedTableIds")
        matches = (
            [known_resource(ref, TABLE, by_id, scope) for ref in ids]
            if isinstance(ids, list)
            else []
        )
        result["supplied_propagation_tables_known_local"] = (
            True
            if isinstance(ids, list)
            and ids
            and all(isinstance(ref, str) and ref.rsplit("/", 2)[0] == hub_id for ref in ids)
            and len(set(ids)) == len(ids)
            and all(matches)
            else unknown("explicit_distinct_known_local_propagation_tables_required")
        )
        table_labels = [
            review_fact(table["properties"], "hubRouteLabels") for table in matches if table
        ]
        result["supplied_propagation_tables_share_explicit_label"] = (
            all(
                bool(set(labels["fingerprints"]).intersection(item["fingerprints"]))
                for item in table_labels
            )
            if result["supplied_propagation_tables_known_local"] is True
            and "unknown" not in labels
            and all("unknown" not in item for item in table_labels)
            else unknown("known_local_tables_and_explicit_label_summaries_required")
        )
    return result


def wan_hub_population(
    resource: dict[str, Any], by_id: dict[str, list[dict[str, Any]]], scope: str | None
) -> dict[str, Any]:
    if known_resource(resource.get("arm_id"), WAN, by_id, scope) is not resource:
        return unknown("wan_not_unique_known_typed_scoped")
    hubs = [
        row
        for matches in by_id.values()
        for row in matches
        if row.get("resource_type", "").lower() == HUB
    ]
    if not hubs or len(hubs) > 100:
        return unknown("supplied_hub_population_empty_or_over_100")
    selected = []
    for hub in hubs:
        if known_resource(hub.get("arm_id"), HUB, by_id, scope) is not hub:
            return unknown("supplied_hub_not_unique_known_typed_scoped")
        ref = review_fact(hub["properties"], "virtualWanId")
        if not isinstance(ref, str):
            return unknown("supplied_hub_wan_binding_unknown")
        if ref != resource["arm_id"]:
            continue
        region = location(property_at(hub["properties"], "resourceLocation"))
        if not isinstance(region, str):
            return unknown("supplied_hub_region_unknown")
        selected.append(region)
    if not selected:
        return unknown("no_known_hubs_bound_to_this_wan_in_supplied_subset")
    return {
        "suppliedDistinctKnownHubCount": len(selected),
        "suppliedDistinctConfiguredRegionCount": len(set(selected)),
        "warning": "Supplied subset only; no complete regional inventory, eligibility, "
        "global reachability, suitability or available capacity is established.",
    }
