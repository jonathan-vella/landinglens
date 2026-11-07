"""Explicit offline composition of modular normalized evidence bundles."""

from __future__ import annotations

import copy
from typing import Any

from .billing_evidence import minimized_evidence as minimized_budgets
from .contracts import (
    canonical_id,
    document,
    identity_type,
    scope_id,
    timestamp,
    validate,
)
from .governance_evidence import MG_KIND, hierarchy_context
from .key_lifecycle_evidence import minimized_evidence as minimized_keys
from .terraform import InputError

MAX_BUNDLES = 16
MAX_RESOURCES = 10_000


def _equivalent(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return (
        left["resource_type"].lower() == right["resource_type"].lower()
        and left["state"] == right["state"]
        and left["reason"] == right["reason"]
        and left.get("api_version") == right.get("api_version")
        and left["properties"] == right["properties"]
    )


def compose_evidence(bundles: list[dict[str, Any]], *, scope: str | None = None) -> dict[str, Any]:
    if not isinstance(bundles, list) or not 2 <= len(bundles) <= MAX_BUNDLES:
        raise InputError(f"Supply between 2 and {MAX_BUNDLES} normalized evidence bundles")
    validated = []
    for bundle in bundles:
        if isinstance(bundle, dict) and bundle.get("presentation_only"):
            raise InputError("Minimized presentations cannot be composed as evidence")
        validated.append(copy.deepcopy(validate(bundle, "evidence")))
    modes = {bundle["mode"] for bundle in validated}
    if len(modes) != 1:
        raise InputError("Composed evidence bundles must share the same mode (planned or observed)")
    mode = validated[0]["mode"]
    input_scopes = []
    for bundle in validated:
        bundle_scope = bundle.get("scope")
        if not isinstance(bundle_scope, str):
            raise InputError("Each composed bundle requires an explicit scope")
        input_scopes.append(scope_id(bundle_scope))
    if scope is not None:
        target_scope = scope_id(scope)
    elif len(set(input_scopes)) == 1:
        target_scope = input_scopes[0]
    else:
        raise InputError(
            "Supply an explicit --scope when composing evidence across multiple scopes"
        )
    relationships: list[dict[str, str]] = []
    seen_edges: set[tuple[str, str]] = set()
    for bundle in validated:
        raw_edges = (bundle.get("metadata") or {}).get("relationships")
        if isinstance(raw_edges, list):
            for edge in raw_edges:
                if (
                    isinstance(edge, dict)
                    and isinstance(edge.get("id"), str)
                    and isinstance(edge.get("parent"), str)
                ):
                    pair = (canonical_id(edge["id"]), scope_id(edge["parent"]))
                    if pair not in seen_edges:
                        seen_edges.add(pair)
                        relationships.append({"id": pair[0], "parent": pair[1]})
    connected_scopes: set[str] = {target_scope}
    if identity_type(target_scope) == MG_KIND and relationships:
        probe = document(
            "evidence",
            schema_version="1.1",
            mode=mode,
            source="saved",
            scope=target_scope,
            collected_at=validated[0]["collected_at"],
            inventory_complete=False,
            artifact_hashes={"probe": "0" * 64},
            diagnostics=[],
            resources=[],
            metadata={"relationships": relationships},
        )
        hierarchy = hierarchy_context(probe)
        if "unknown" in hierarchy:
            raise InputError("Composed management-group hierarchy is invalid, cyclic or unbound")
        connected_scopes.update(edge["id"] for edge in hierarchy["relationships"])
    for item_scope in input_scopes:
        if not any(
            item_scope == allowed or item_scope.startswith(allowed + "/")
            for allowed in connected_scopes
        ):
            raise InputError(
                f"Input bundle scope {item_scope} is outside target scope {target_scope}"
            )
    all_scopes: list[str] = []
    for item_scope in input_scopes:
        if item_scope not in all_scopes:
            all_scopes.append(item_scope)
    for bundle in validated:
        for extra in (bundle.get("metadata") or {}).get("scopes") or []:
            if isinstance(extra, str):
                normalized_extra = scope_id(extra)
                if normalized_extra not in all_scopes:
                    all_scopes.append(normalized_extra)
    artifact_hashes: dict[str, str] = {}
    diagnostics: list[dict[str, Any]] = []
    resources: list[dict[str, Any]] = []
    by_arm_id: dict[str, int] = {}
    conflicted_ids: set[str] = set()
    has_conflict = False
    for index, bundle in enumerate(validated, 1):
        prefix = f"bundle-{index}"
        for key, sha in bundle["artifact_hashes"].items():
            artifact_hashes[f"{prefix}:{key}"] = sha
        for diag in bundle.get("diagnostics") or []:
            diagnostics.append(copy.deepcopy(diag))
        for resource in bundle["resources"]:
            entry = copy.deepcopy(resource)
            entry["logical_id"] = f"{prefix}:{resource['logical_id']}"
            raw_id = entry.get("arm_id")
            if raw_id is None:
                resources.append(entry)
            else:
                identity = canonical_id(raw_id)
                entry["arm_id"] = identity
                if identity in conflicted_ids:
                    has_conflict = True
                    diagnostics.append(
                        {
                            "reason": "duplicate_resource",
                            "source_location": entry["source_location"],
                        }
                    )
                    continue
                if identity in by_arm_id:
                    prior_index = by_arm_id[identity]
                    prior = resources[prior_index]
                    diagnostics.append(
                        {
                            "reason": "duplicate_resource",
                            "source_location": entry["source_location"],
                        }
                    )
                    if _equivalent(prior, entry):
                        continue
                    has_conflict = True
                    conflicted_ids.add(identity)
                    del by_arm_id[identity]
                    resources[prior_index] = {
                        "logical_id": prior["logical_id"],
                        "arm_id": None,
                        "resource_type": prior["resource_type"],
                        "state": "unknown",
                        "reason": "duplicate_resource",
                        "source_location": prior["source_location"],
                        "properties": {},
                    }
                    continue
                by_arm_id[identity] = len(resources)
                resources.append(entry)
            if len(resources) > MAX_RESOURCES:
                raise InputError("Composed evidence exceeds the 10,000 resource limit")
    oldest = min(validated, key=lambda item: timestamp(item["collected_at"]))["collected_at"]
    sources = {bundle["source"] for bundle in validated}
    source_kind = validated[0]["source"] if len(sources) == 1 else "saved"
    metadata: dict[str, Any] = {
        "scopes": all_scopes,
        "warning": (
            "Composed multi-bundle evidence; completeness requires every input bundle to be "
            "complete and conflict-free."
        ),
    }
    if relationships:
        metadata["relationships"] = relationships
    providers = {
        (bundle.get("metadata") or {}).get("provider_version")
        for bundle in validated
        if (bundle.get("metadata") or {}).get("provider_version")
    }
    if len(providers) == 1:
        metadata["provider_version"] = next(iter(providers))
    composed = document(
        "evidence",
        schema_version="1.1",
        mode=mode,
        source=source_kind,
        scope=target_scope,
        collected_at=oldest,
        inventory_complete=all(b["inventory_complete"] for b in validated) and not has_conflict,
        artifact_hashes=artifact_hashes,
        diagnostics=diagnostics,
        resources=resources,
        metadata=metadata,
    )
    return minimized_keys(minimized_budgets(validate(composed, "evidence")))
