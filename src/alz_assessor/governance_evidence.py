"""Minimized governance preparation; configuration never supplies an operating decision."""

from typing import Any

from .contracts import canonical_id, identity_type, parse_document, scope_id
from .sources import property_at, unknown
from .terraform import InputError

PATHS = {"tagCount", "dashboardSummary", "capacityReservationGroupId", "managementParentId"}
VM_KIND = "microsoft.compute/virtualmachines"
MG_KIND = "microsoft.management/managementgroups"
DASHBOARD_KIND = "microsoft.portal/dashboards"
TAG_KINDS = {
    VM_KIND,
    DASHBOARD_KIND,
    "microsoft.storage/storageaccounts",
    "microsoft.resources/resourcegroups",
    "microsoft.resources/subscriptions",
}
METRICS_PART = "Extension/Microsoft_Azure_Monitoring/PartType/MetricsChartPart"
MARKDOWN_PART = "Extension/HubsExtension/PartType/MarkdownPart"


def typed_reference(value: Any, kind: str) -> Any:
    from .protection_evidence import typed_reference as reference

    return reference(value, (kind,))


def tag_count(value: Any, *, storage: bool = False) -> Any:
    if not isinstance(value, dict) or "unknown" in value or len(value) > 50:
        return unknown("tags_missing_unresolved_or_over_50")
    names: set[str] = set()
    for key, entry in value.items():
        if (
            not isinstance(key, str)
            or not key.strip()
            or len(key) > (128 if storage else 512)
            or any(c in key for c in "<>%&\\?/")
            or key.casefold() in names
            or not isinstance(entry, str)
            or len(entry) > 256
        ):
            return unknown("tag_pair_invalid_or_ambiguous")
        names.add(key.casefold())
    return len(value)


def dashboard_summary(value: Any, *, terraform: bool = False) -> Any:
    if terraform:
        if not isinstance(value, str) or len(value.encode("utf-8")) > 100_000:
            return unknown("dashboard_literal_json_missing_or_over_bound")
        try:
            value = parse_document(value)
        except InputError:
            return unknown("dashboard_json_invalid_duplicate_or_over_bound")
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("dashboard_configuration_not_explicit")
    lenses = value.get("lenses")
    if terraform and isinstance(lenses, dict) and "unknown" not in lenses:
        lenses = list(lenses.values())
    if not isinstance(lenses, list) or len(lenses) > 20:
        return unknown("dashboard_lenses_invalid_or_over_20")
    metrics, markdown, other, total = 0, 0, 0, 0
    for lens in lenses:
        if not isinstance(lens, dict) or "unknown" in lens:
            return unknown("dashboard_lens_not_explicit")
        parts = lens.get("parts")
        if terraform and isinstance(parts, dict) and "unknown" not in parts:
            parts = list(parts.values())
        if not isinstance(parts, list) or len(parts) > 100 or total + len(parts) > 100:
            return unknown("dashboard_parts_invalid_or_over_100")
        total += len(parts)
        for part in parts:
            if not isinstance(part, dict) or "unknown" in part:
                return unknown("dashboard_part_not_explicit")
            metadata = part.get("metadata")
            kind = (
                metadata.get("type")
                if isinstance(metadata, dict) and "unknown" not in metadata
                else None
            )
            if not isinstance(kind, str) or not kind.strip() or len(kind) > 256:
                return unknown("dashboard_part_type_not_explicit")
            metrics += kind == METRICS_PART
            markdown += kind == MARKDOWN_PART
            other += kind not in {METRICS_PART, MARKDOWN_PART}
    return {
        "lensCount": len(lenses),
        "tileCount": total,
        "metricsChartCount": metrics,
        "markdownCount": markdown,
        "otherTileCount": other,
    }


def summary_fact(value: Any) -> Any:
    fields = {
        "lensCount": 20,
        "tileCount": 100,
        "metricsChartCount": 100,
        "markdownCount": 100,
        "otherTileCount": 100,
    }
    if (
        not isinstance(value, dict)
        or "unknown" in value
        or any(
            type(value.get(key)) is not int or not 0 <= value[key] <= bound
            for key, bound in fields.items()
        )
    ):
        return unknown("dashboard_summary_missing_invalid_or_over_bound")
    if value["tileCount"] != value["metricsChartCount"] + value["markdownCount"] + value[
        "otherTileCount"
    ] or (value["lensCount"] == 0 and value["tileCount"] != 0):
        return unknown("dashboard_summary_counts_conflict")
    return {key: value[key] for key in fields}


def projected_properties(
    kind: str,
    values: dict[str, Any],
    *,
    root: Any = None,
    terraform: bool = False,
) -> dict[str, Any]:
    kind = kind.lower()
    result: dict[str, Any] = {}
    top = values if terraform else root if isinstance(root, dict) else {}
    if kind in TAG_KINDS and "tags" in top:
        result["tagCount"] = tag_count(
            top["tags"], storage=kind == "microsoft.storage/storageaccounts"
        )
    if kind == VM_KIND:
        key = "capacity_reservation_group_id" if terraform else "capacityReservation"
        if key in values:
            result["capacityReservationGroupId"] = typed_reference(
                values[key]
                if terraform
                else property_at(values, "capacityReservation.capacityReservationGroup.id"),
                "microsoft.compute/capacityreservationgroups",
            )
    if kind == MG_KIND:
        result["managementParentId"] = typed_reference(
            values.get("parent_management_group_id")
            if terraform
            else property_at(values, "details.parent.id"),
            MG_KIND,
        )
    if kind == DASHBOARD_KIND:
        result["dashboardSummary"] = dashboard_summary(
            values.get("dashboard_properties") if terraform else values,
            terraform=terraform,
        )
    return result


def review_fact(properties: dict[str, Any], path: str) -> Any:
    value = properties.get(path)
    if path == "tagCount":
        from .network_evidence import bounded_count

        return bounded_count(value, 50)
    if path == "dashboardSummary":
        return summary_fact(value)
    return typed_reference(
        value,
        MG_KIND if path == "managementParentId" else "microsoft.compute/capacityreservationgroups",
    )


def replay_properties(kind: str, values: dict[str, Any]) -> dict[str, Any]:
    kind = kind.lower()
    paths = ({"tagCount"} if kind in TAG_KINDS else set()) | {
        VM_KIND: {"capacityReservationGroupId"},
        MG_KIND: {"managementParentId"},
        DASHBOARD_KIND: {"dashboardSummary"},
    }.get(kind, set())
    return {path: review_fact(values, path) for path in sorted(paths) if path in values}


def hierarchy_context(bundle: dict[str, Any]) -> dict[str, Any]:
    """Reuse saved Collector parent edges; never infer ancestry from labels or bare scopes."""
    metadata = bundle.get("metadata") or {}
    entries = metadata.get("relationships")
    result: dict[str, Any] = {
        "relationships": [],
        "unknown": "saved_management_hierarchy_not_supplied",
        "warning": "Original-time positive parent edges only; no identity designation, "
        "complete hierarchy, inherited policy result, billing access or regional DC usage.",
    }
    selected = bundle.get("scope")
    if (
        not isinstance(selected, str)
        or identity_type(selected) != MG_KIND
        or not isinstance(entries, list)
    ):
        return result
    if len(entries) > 100:
        return {**result, "unknown": "saved_management_hierarchy_over_100"}
    selected = scope_id(selected)
    parents: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            return {**result, "unknown": "saved_management_hierarchy_malformed"}
        # Collector also supplies explicit subscription selections without a parent edge.
        if "parent" not in entry:
            if entry.get("relationship") == "explicit_or_verified_descendant":
                continue
            return {**result, "unknown": "saved_management_hierarchy_parent_missing"}
        try:
            child, parent = scope_id(entry["id"]), scope_id(entry["parent"])
        except (InputError, KeyError, TypeError):
            return {**result, "unknown": "saved_management_hierarchy_identity_invalid"}
        if (
            identity_type(child) not in {MG_KIND, "microsoft.resources/subscriptions"}
            or identity_type(parent) != MG_KIND
            or child in parents
            or child in {parent, selected}
        ):
            return {**result, "unknown": "saved_management_hierarchy_ambiguous_or_wrong_type"}
        parents[child] = parent
    edges = []
    for child, parent in sorted(parents.items()):
        visited = {child}
        ancestor = parent
        while ancestor != selected and ancestor in parents and ancestor not in visited:
            visited.add(ancestor)
            ancestor = parents[ancestor]
        if ancestor != selected:
            return {**result, "unknown": "saved_management_hierarchy_unbound_or_cyclic"}
        edges.append({"id": canonical_id(child), "parent": parent})
    completeness = metadata.get("completeness")
    return {
        "relationships": edges[:100],
        "matching_relationships": len(edges),
        "truncated": len(edges) > 100,
        "complete": isinstance(completeness, dict) and completeness.get("relationships") is True,
        "warning": result["warning"],
    }
