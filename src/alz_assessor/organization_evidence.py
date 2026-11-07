"""Partial organization configuration, never naming policy, purpose or effective authority."""

from typing import Any

from .contracts import canonical_id, identity_type, scope_id
from .governance_evidence import MG_KIND, hierarchy_context, typed_reference
from .sources import boolean, unknown
from .terraform import InputError

SUB_KIND = "microsoft.resources/subscriptions"
SETTINGS = MG_KIND + "/settings"
PATHS = {"defaultManagementGroup", "requireAuthorizationForGroupCreation"}
GUIDS = {
    "cacf55bc-e4e4-46be-96bc-57a5f23a269a",
    "2df27ee4-12e7-4f98-9f63-04722dd69c5b",
    "667313b4-f566-44b5-b984-a859c773e7d2",
    "61623a76-5a91-47e1-b348-ef254c27d42e",
    "8bbac757-1559-4ab9-853e-8908ae28c84c",
    "33b6b780-8b9f-4e5c-9104-9d403a923c34",
    "74d00018-ac6a-49e0-8e6a-83de5de32c19",
    "92481607-d5d1-4e4e-9146-58d3558fd772",
}
WARNING = (
    "Original-time positive configuration only, not a complete estate. Selected scope is "
    "not designated tenant root or intermediate root. Depth counts management-group edges "
    "below the selected anchor, excluding subscriptions; CAF ideally three to four levels "
    "is not the service maximum six below tenant root. No naming standard, sandbox/platform/"
    "connectivity/workload purpose, root-subscription absence, enforced Policy or effective "
    "privileged-operation authorization is inferred."
)


def explicit_identity(kind: str, name: Any, selected: str | None) -> str | None:
    """Tenant resource keys are explicit IDs, not inferred organizational designations."""
    if not selected or identity_type(scope_id(selected)) != MG_KIND or not isinstance(name, str):
        return None
    parts = name.split("/")
    if kind.lower() == MG_KIND and len(parts) == 1 and parts[0]:
        suffix = parts[0]
    elif kind.lower() == SETTINGS and len(parts) == 2 and parts[0] and parts[1] == "default":
        suffix = parts[0] + "/settings/default"
    else:
        return None
    try:
        return canonical_id("/providers/Microsoft.Management/managementGroups/" + suffix)
    except InputError:
        return None


def projected_properties(kind: str, values: dict[str, Any]) -> dict[str, Any]:
    if kind.lower() != SETTINGS:
        return {}
    return {
        "defaultManagementGroup": typed_reference(values.get("defaultManagementGroup"), MG_KIND),
        "requireAuthorizationForGroupCreation": boolean(
            values.get("requireAuthorizationForGroupCreation")
        ),
    }


def review_fact(properties: dict[str, Any], path: str) -> Any:
    value = properties.get(path)
    return (
        boolean(value)
        if path == "requireAuthorizationForGroupCreation"
        else typed_reference(value, MG_KIND)
    )


def replay_properties(kind: str, values: dict[str, Any]) -> dict[str, Any]:
    return (
        {path: review_fact(values, path) for path in sorted(PATHS) if path in values}
        if kind.lower() == SETTINGS
        else {}
    )


def configuration_context(bundle: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"warning": WARNING}

    def missing(reason: str) -> dict[str, Any]:
        return {**result, "unknown": reason}

    selected = bundle.get("scope")
    if not isinstance(selected, str) or identity_type(selected) != MG_KIND:
        return missing("organization_selected_management_group_required")
    selected = scope_id(selected)
    rows = [
        row
        for row in bundle.get("resources", [])
        if row["resource_type"].lower() in {MG_KIND, SUB_KIND, SETTINGS}
    ]
    if not rows or len(rows) > 100:
        return missing("organization_population_missing_or_over_100")
    by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        identity = row.get("arm_id")
        if not isinstance(identity, str):
            return missing("organization_identity_missing")
        try:
            identity = canonical_id(identity)
        except InputError:
            return missing("organization_identity_invalid")
        kind = row["resource_type"].lower()
        if (
            row.get("state") != "known"
            or identity_type(identity) != kind
            or identity in by_id
            or (kind == MG_KIND and len(identity.split("/")) != 5)
            or (kind == SUB_KIND and len(identity.split("/")) != 3)
            or (kind == SETTINGS and not identity.endswith("/settings/default"))
            or (kind == SETTINGS and len(identity.split("/")) != 7)
            or (kind == SETTINGS and row.get("api_version") != "2020-05-01")
        ):
            return missing("organization_resource_not_unique_known_typed_supported_version")
        by_id[identity] = row
    if selected not in by_id or by_id[selected]["resource_type"].lower() != MG_KIND:
        return missing("organization_anchor_not_unique_known")
    anchor_parent = by_id[selected]["properties"].get("managementParentId")
    if isinstance(anchor_parent, str) and anchor_parent.lower() in by_id:
        return missing("organization_anchor_parent_conflicts_with_supplied_graph")
    parents: dict[str, str] = {}
    if "relationships" in (bundle.get("metadata") or {}):
        hierarchy = hierarchy_context(bundle)
        if "unknown" in hierarchy:
            return missing("organization_saved_hierarchy_invalid_or_over_bound")
        for edge in hierarchy["relationships"]:
            parents[edge["id"]] = edge["parent"]
    for identity, row in by_id.items():
        if row["resource_type"].lower() != MG_KIND or identity == selected:
            continue
        parent = typed_reference(row["properties"].get("managementParentId"), MG_KIND)
        if not isinstance(parent, str) or (identity in parents and parents[identity] != parent):
            return missing("organization_parent_missing_or_conflicting")
        parents[identity] = parent
    if any(child not in by_id or parent not in by_id for child, parent in parents.items()):
        return missing("organization_parent_join_missing")
    depths: dict[str, int] = {selected: 0}
    for identity, row in by_id.items():
        kind = row["resource_type"].lower()
        if kind == SETTINGS:
            continue
        visited: set[str] = set()
        ancestor = identity
        depth = 0
        while ancestor != selected:
            if ancestor in visited or ancestor not in parents:
                return missing("organization_hierarchy_cyclic_unbound_or_partial")
            visited.add(ancestor)
            ancestor = parents[ancestor]
            depth += 1
        depths[identity] = depth - (kind == SUB_KIND)
    relationships = [
        {
            "id": child,
            "parent": parent,
            "management_group_edges_below_selected": depths[child],
        }
        for child, parent in sorted(parents.items())
    ]
    settings = []
    for identity, row in sorted(by_id.items()):
        if row["resource_type"].lower() != SETTINGS:
            continue
        parent = identity.removesuffix("/settings/default")
        if parent != selected:
            return missing("organization_settings_not_attached_to_selected_anchor")
        facts = replay_properties(SETTINGS, row["properties"])
        target = facts.get("defaultManagementGroup")
        if (
            not isinstance(target, str)
            or target not in depths
            or (by_id[target]["resource_type"].lower() != MG_KIND)
        ):
            facts["defaultManagementGroup"] = unknown(
                "default_management_group_not_unique_known_in_supplied_hierarchy"
            )
        settings.append({"id": identity, "facts": facts})
    return {
        **result,
        "relationships": relationships,
        "settings": settings,
        "maximum_supplied_management_group_edges_below_selected": max(
            depth
            for identity, depth in depths.items()
            if by_id[identity]["resource_type"].lower() == MG_KIND
        ),
        "complete_estate": False,
        "tenant_root_designation": unknown("independent_root_designation_required"),
        "root_subscription_absence": unknown("complete_authoritative_population_required"),
        "effective_authorization": unknown("independent_privileged_operations_review_required"),
    }
