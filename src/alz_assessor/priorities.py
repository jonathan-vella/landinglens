"""Source-backed priority metadata and nonbinding archetype suggestions."""

import copy
import json
from datetime import timedelta
from importlib.resources import files
from typing import Any

from .contracts import digest, require, scope_id, timestamp, validate
from .terraform import InputError

SEVERITIES = ("High", "Medium", "Low", "Unknown")
ARCHETYPE_SUGGESTIONS: dict[str, list[str]] = {
    "root": ["ALZ-223ace8c-b123-408c-a501-7f154e3ab369"],
    "platform": ["ALZ-2df27ee4-12e7-4f98-9f63-04722dd69c5b"],
    "landing_zones": ["ALZ-b03ed428-4617-4067-a787-85468b9ccf3f"],
    "corp": ["ALZ-e8bbac75-7155-49ab-a153-e8908ae28c84"],
    "online": ["ALZ-373f482f-3e39-4d39-8aa4-7e566f6082b6"],
    "sandbox": ["ALZ-667313b4-f566-44b5-b984-a859c773e7d2"],
    "security": ["ALZ-b86ad884-08e3-4727-94b8-75ba18f20459"],
    "management": ["ALZ-67e7a8ed-4b30-4e38-a3f2-9812b2363cef"],
    "connectivity": ["ALZ-7bc1c396-2461-4698-b57f-30ca69525252"],
    "identity": ["ALZ-348ef254-c27d-442e-abba-c7571559ab91"],
}


def sort_key(row: dict[str, Any]) -> tuple[Any, ...]:
    severity = row.get("severity", "Unknown")
    return (
        SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES),
        row.get("design_area", ""),
        row.get("control_id", ""),
        row.get("logical_id", ""),
    )


def load_priorities() -> dict[str, Any]:
    root = files("alz_assessor").joinpath("data")
    return json.loads(root.joinpath("catalog-priorities.json").read_text("utf-8"))


def prioritised_catalog(base: dict[str, Any], metadata: dict[str, Any]) -> dict[str, Any]:
    if (
        base["catalog_version"] != metadata["base_catalog_version"]
        or digest(base) != metadata["base_catalog_sha256"]
    ):
        raise InputError("Priority review requires the exact frozen base catalog")
    catalog = copy.deepcopy(base)
    if {c["upstream_guid"] for c in catalog["controls"]} != set(metadata["severities"]):
        raise InputError("Priority metadata differs from catalog GUID membership")
    for control in catalog["controls"]:
        severity = metadata["severities"][control["upstream_guid"]]
        if severity not in SEVERITIES:
            raise InputError("Unreviewed severity value")
        control["severity"] = severity
    catalog.update(
        catalog_version=metadata["catalog_version"],
        batch_catalog_version=base["catalog_version"],
        priority_manifest_sha256=digest(metadata),
    )
    return validate(catalog, "catalog")


def archetype_bindings(data: Any, evidence: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(data, dict) or set(data) != {"collected_at", "entries"}:
        raise InputError("Archetype bindings require only collected_at and entries")
    timestamp(require(data, "collected_at", str))
    entries = require(data, "entries", list)
    if not entries or len(entries) > 100:
        raise InputError("Supply 1-100 explicit management-group archetype bindings")
    architecture = load_priorities()["architecture"]
    seen = set()
    result = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"scope", "group_id"}:
            raise InputError("Archetype entry requires only scope and group_id")
        scope = scope_id(require(entry, "scope", str))
        boundary = evidence.get("scope")
        if (
            not isinstance(boundary, str)
            or scope != boundary.lower()
            or not scope.startswith("/providers/microsoft.management/managementgroups/")
        ):
            raise InputError("Archetype scope must equal the explicit evidence management group")
        group = require(entry, "group_id", str)
        if group not in architecture or scope in seen:
            raise InputError("Unknown architecture group or duplicate scope binding")
        seen.add(scope)
        result.append({"scope": scope, "group_id": group})
    return {"collected_at": data["collected_at"], "entries": result}


def suggestions(
    evidence: list[dict[str, Any]], at: str, max_age_hours: float = 24
) -> list[dict[str, Any]]:
    metadata = load_priorities()
    result = []
    for bundle in evidence:
        raw = (bundle.get("metadata") or {}).get("archetype_bindings")
        if raw is None:
            continue
        bindings = archetype_bindings(raw, bundle)
        current = (
            timedelta(minutes=-5)
            <= timestamp(at) - timestamp(bindings["collected_at"])
            <= timedelta(hours=max_age_hours)
        )
        for binding in bindings["entries"]:
            group = metadata["architecture"][binding["group_id"]]
            archetypes = group["archetypes"]
            mapped = [cid for arch in archetypes for cid in ARCHETYPE_SUGGESTIONS.get(arch, [])]
            relevant = bool(mapped)
            result.append(
                {
                    "mode": bundle["mode"],
                    "scope": binding["scope"],
                    "group_id": binding["group_id"],
                    "archetypes": archetypes,
                    "suggested_controls": mapped if relevant and current else [],
                    "reason": "reviewed_archetype_assignment"
                    if relevant and current
                    else (
                        "stale_archetype_binding"
                        if not current
                        else "archetype_mapping_not_reviewed"
                    ),
                    "collected_at": bindings["collected_at"],
                    "source_sha256": digest(metadata),
                    "requires_confirmation": True,
                }
            )
    return result
