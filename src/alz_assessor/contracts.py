"""Versioned JSON contracts and identity invariants shared by all workflows."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from math import isfinite
from pathlib import Path
from typing import Any
from uuid import UUID

from .terraform import InputError

VERSION = "1.0"
SUPPORTED_VERSIONS = {"1.0", "1.1"}
OUTCOMES = {"pass", "fail", "unknown", "error", "manual", "not_applicable"}
STATES = {"known", "unknown", "inaccessible", "error", "absent"}
ARM_ID = re.compile(
    r"^/(?:subscriptions/[0-9a-f-]{36}(?:/resourceGroups/[^/]+)?|"
    r"providers/Microsoft.Management/managementGroups/[^/]+)"
    r"(?:/providers/[^/]+(?:/[^/]+/[^/]+)+)?$",
    re.IGNORECASE,
)


def now() -> str:
    return datetime.now(UTC).isoformat()


def timestamp(value: str) -> datetime:
    if not isinstance(value, str):
        raise InputError("Expected an ISO-8601 timestamp with timezone")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("timezone required")
        return parsed
    except (ValueError, TypeError) as exc:
        raise InputError("Expected an ISO-8601 timestamp with timezone") from exc


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(),
    ).hexdigest()


def control_digest(control: dict[str, Any]) -> str:
    """Bind review meaning, not polling timestamps or presentation metadata."""
    return digest(
        {
            key: control.get(key)
            for key in (
                "control_id",
                "upstream_id",
                "recommendation",
                "applicability",
                "method",
                "rule",
                "lifecycle",
                "evidence_requirements",
                "baseline",
                "automation",
                "design_area",
                "references",
                "rationale",
                "flags",
            )
            + (("review_resource_types",) if "review_resource_types" in control else ())
            + (("review_fact_paths",) if "review_fact_paths" in control else ())
        }
    )


def canonical_id(value: str) -> str:
    if not isinstance(value, str) or not ARM_ID.fullmatch(value):
        raise InputError("Identity must be a complete scope-bound ARM ID, not a resource name")
    if any(c in value for c in ("?", "#", "\\", "%")) or ".." in value.split("/"):
        raise InputError("Invalid ARM identity")
    if value.lower().startswith("/subscriptions/"):
        component = value.split("/")[2]
        try:
            if str(UUID(component)) != component.lower():
                raise ValueError("Noncanonical subscription ID")
        except ValueError as exc:
            raise InputError("Subscription identity must contain a UUID") from exc
    return value.lower()


def scope_id(value: str) -> str:
    result = canonical_id(value)
    if not re.fullmatch(
        r"/(?:subscriptions/[^/]+(?:/resourcegroups/[^/]+)?|"
        r"providers/microsoft.management/managementgroups/[^/]+)",
        result,
    ):
        raise InputError(
            "Assessment scope must be a subscription, resource group or management group"
        )
    return result


def identity_type(identity: str) -> str:
    value = canonical_id(identity)
    if "/providers/" in value:
        parts = value.rsplit("/providers/", 1)[-1].split("/")
        return "/".join([parts[0], *parts[1::2]])
    return (
        "microsoft.resources/resourcegroups"
        if "/resourcegroups/" in value
        else "microsoft.resources/subscriptions"
    )


def derive_id(scope: str | None, resource_type: Any, name: Any) -> str | None:
    if (
        not scope
        or not isinstance(resource_type, str)
        or not isinstance(name, str)
        or not name
        or not resource_type.startswith("Microsoft.")
    ):
        return None
    scope = scope_id(scope)
    if resource_type.lower() == "microsoft.management/managementgroups":
        return None
    if resource_type.lower() == "microsoft.resources/resourcegroups":
        return (
            canonical_id("/".join(scope.split("/")[:3]) + "/resourceGroups/" + name)
            if scope.startswith("/subscriptions/") and "/" not in name
            else None
        )
    if (
        resource_type.lower()
        in {
            "microsoft.storage/storageaccounts",
            "microsoft.network/firewallpolicies",
            "microsoft.network/virtualnetworks",
            "microsoft.operationalinsights/workspaces",
        }
        and "/resourcegroups/" not in scope
    ):
        return None
    parts, names = resource_type.split("/"), name.split("/")
    if len(parts) != len(names) + 1 or any(not item for item in names):
        return None
    suffix = "/".join(piece for pair in zip(parts[1:], names, strict=True) for piece in pair)
    return canonical_id(f"{scope}/providers/{parts[0]}/{suffix}")


def document(kind: str, **fields: Any) -> dict[str, Any]:
    return {"schema_version": VERSION, "kind": kind, **fields}


def require(data: Any, key: str, expected: type, *, allow_blank: bool = False) -> Any:
    if not isinstance(data, dict):
        raise InputError("Contract entries must be objects")
    value = data.get(key)
    if not isinstance(value, expected) or (expected is int and isinstance(value, bool)):
        raise InputError(f"{key} must be {expected.__name__}")
    if isinstance(value, str) and not allow_blank and not value.strip():
        raise InputError(f"{key} must not be blank")
    return value


def hashes(value: Any) -> None:
    if not isinstance(value, dict) or not value:
        raise InputError("Nonempty artifact hashes are required")
    for key, sha in value.items():
        if (
            not isinstance(key, str)
            or not isinstance(sha, str)
            or not re.fullmatch("[0-9a-f]{64}", sha)
        ):
            raise InputError("Artifact hashes must be SHA-256 hexadecimal strings")


def validate(data: Any, kind: str | None = None) -> dict[str, Any]:
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("schema_version"), str)
        or data["schema_version"] not in SUPPORTED_VERSIONS
    ):
        raise InputError("Unsupported or missing schema_version; expected 1.0 or 1.1")
    actual = data.get("kind")
    if not isinstance(actual, str):
        raise InputError("Document kind must be a string")
    if kind and actual != kind:
        raise InputError(f"Expected {kind} document")
    if actual == "evidence":
        if data.get("mode") not in ("planned", "observed"):
            raise InputError("Evidence mode must be planned or observed")
        if not isinstance(data.get("source"), str) or data.get("source") not in {
            "terraform",
            "terraform-plan",
            "arm",
            "bicep",
            "azure",
            "saved",
        }:
            raise InputError("Unsupported evidence source")
        timestamp(require(data, "collected_at", str))
        hashes(data.get("artifact_hashes"))
        require(data, "inventory_complete", bool)
        for diagnostic in require(data, "diagnostics", list):
            require(diagnostic, "reason", str)
        if data.get("metadata") is not None:
            require(data, "metadata", dict)
        if data.get("scope") is not None:
            scope_id(data["scope"])
        logical, identities = set(), set()
        for resource in require(data, "resources", list):
            if not isinstance(resource, dict):
                raise InputError("Resource must be an object")
            address = require(resource, "logical_id", str)
            require(resource, "resource_type", str)
            require(resource, "properties", dict)
            require(resource, "source_location", str)
            if not address or address in logical:
                raise InputError("Duplicate or empty logical resource identity")
            logical.add(address)
            if not isinstance(resource.get("state"), str) or resource.get("state") not in STATES:
                raise InputError("Invalid resource state")
            if resource["state"] != "known" and not resource.get("reason"):
                raise InputError("Non-known resources require an explicit reason")
            require(resource, "reason", str, allow_blank=resource["state"] == "known")
            identity = resource.get("arm_id")
            if identity is not None:
                identity = canonical_id(identity)
                resource_type = resource["resource_type"].lower()
                if (
                    resource_type.startswith("microsoft.")
                    and identity_type(identity) != resource_type
                ):
                    raise InputError("Resource type does not match its ARM identity")
                if identity in identities:
                    raise InputError("Duplicate or ambiguous ARM resource identity")
                identities.add(identity)
            if resource["state"] == "absent" and (not identity or not data["inventory_complete"]):
                raise InputError("Absence requires established identity and complete inventory")
    elif actual == "identity-map":
        hashes(data.get("artifact_hashes"))
        addresses, identities = set(), set()
        for entry in require(data, "entries", list):
            address = require(entry, "logical_id", str)
            identity = canonical_id(require(entry, "arm_id", str))
            scope = scope_id(require(entry, "scope", str))
            if identity != scope and not identity.startswith(scope + "/"):
                raise InputError("Identity map scope does not contain its resource")
            if address in addresses or identity in identities:
                raise InputError("Duplicate or ambiguous identity-map entries")
            addresses.add(address)
            identities.add(identity)
    elif actual in {"manual", "exceptions"}:
        if data.get("is_template"):
            raise InputError("Unasserted review templates cannot be ingested as completed records")
        entries = require(data, "entries", list)
        seen = set()
        for entry in entries:
            key = (require(entry, "control_id", str), scope_id(require(entry, "scope", str)))
            if key in seen:
                raise InputError("Duplicate manual/exception disposition")
            seen.add(key)
            require(entry, "rationale", str)
            if data["schema_version"] == "1.1":
                require(entry, "reviewer", str)
                require(entry, "evidence", str)
                hashes({"control": require(entry, "control_sha256", str)})
            start = timestamp(require(entry, "valid_from", str))
            end = timestamp(require(entry, "valid_until", str))
            if end <= start:
                raise InputError("Disposition validity must have a positive interval")
            if actual == "manual":
                if (
                    not isinstance(entry.get("outcome"), str)
                    or entry.get("outcome") not in OUTCOMES
                ):
                    raise InputError("Invalid manual outcome")
                require(entry, "evidence", str)
            elif entry.get("disposition") not in ("accepted", "rejected", "pending"):
                raise InputError("Invalid exception disposition")
    elif actual == "catalog":
        require(data, "catalog_version", str)
        areas = require(data, "design_areas", list)
        if any(not isinstance(area, str) or not area.strip() for area in areas):
            raise InputError("Design areas must be nonblank strings")
        seen = set()
        for control in require(data, "controls", list):
            identity = require(control, "control_id", str)
            if identity in seen:
                raise InputError("Duplicate control ID")
            seen.add(identity)
            if require(control, "design_area", str) not in areas:
                raise InputError("Unrecognized design area")
            if control.get("automation") not in ("automated", "assisted", "manual", "unmapped"):
                raise InputError("Invalid automation disposition")
            applicability = require(control, "applicability", list)
            if not applicability or any(
                value not in ("platform", "application") for value in applicability
            ):
                raise InputError("Invalid applicability")
            for field in ("upstream_id", "recommendation", "method", "rationale", "lifecycle"):
                require(control, field, str)
            if data["schema_version"] == "1.1":
                if control["lifecycle"] not in {"active", "retired"}:
                    raise InputError("Lifecycle must be active or retired")
                if control["lifecycle"] == "retired":
                    timestamp(require(control, "retired_at", str))
                    require(control, "retirement_reason", str)
                replacement = control.get("superseded_by")
                if replacement is not None and (
                    not isinstance(replacement, str) or replacement == identity
                ):
                    raise InputError("Invalid supersession")
            require(control, "flags", list)
            require(control, "references", list)
            require(control, "evidence_requirements", list)
            if "review_resource_types" in control:
                kinds = require(control, "review_resource_types", list)
                if (
                    not kinds
                    or len(kinds) > 10
                    or any(not isinstance(kind, str) or not kind.strip() for kind in kinds)
                ):
                    raise InputError("Review resource preparation requires 1-10 explicit types")
            if "review_fact_paths" in control:
                paths = require(control, "review_fact_paths", list)
                if (
                    not paths
                    or len(paths) > 4
                    or any(
                        not isinstance(path, str)
                        or path
                        not in {
                            "enableRbacAuthorization",
                            "publicNetworkAccess",
                            "networkAcls.defaultAction",
                            "minimumTlsVersion",
                        }
                        for path in paths
                    )
                ):
                    raise InputError("Review fact preparation requires reviewed scalar paths")
            if control["automation"] == "automated":
                rule = require(control, "rule", dict)
                for field in ("resource_type", "property"):
                    require(rule, field, str)
                operation = rule.get("operation", "boolean")
                if operation == "boolean":
                    require(rule, "expected", bool)
                    if "applicable_skus" in rule:
                        raise InputError("Boolean rules cannot contain SKU applicability")
                elif operation == "vault-deletion-protection" and data["schema_version"] == "1.1":
                    if (
                        rule["resource_type"] != "Microsoft.KeyVault/vaults"
                        or rule["property"] != "enableSoftDelete"
                        or rule.get("expected") is not True
                        or "applicable_skus" in rule
                    ):
                        raise InputError("Invalid reviewed vault deletion-protection conjunction")
                elif operation == "enum-equals" and data["schema_version"] == "1.1":
                    if require(rule, "expected", str) not in {"Alert", "Deny", "Off"}:
                        raise InputError("Unsupported firewall mode enum")
                    skus = require(rule, "applicable_skus", list)
                    if (
                        not skus
                        or any(not isinstance(sku, str) for sku in skus)
                        or len(set(skus)) != len(skus)
                        or set(skus) - {"Basic", "Standard", "Premium"}
                        or rule["resource_type"] != "Microsoft.Network/firewallPolicies"
                        or rule["property"] not in {"threatIntelMode", "intrusionDetection.mode"}
                    ):
                        raise InputError("Invalid reviewed enum/SKU applicability")
                else:
                    raise InputError("Unsupported rule operation or contract version")
            elif control.get("rule") is not None:
                raise InputError("Human-evidence controls cannot contain automated rules")
            if control.get("baseline") != "microsoft-recommendation":
                raise InputError("Tenant policy/org extensions cannot overwrite this baseline")
        for control in data["controls"]:
            if control.get("superseded_by") and control["superseded_by"] not in seen:
                raise InputError("Supersession references an unknown control")
        replacements = {c["control_id"]: c.get("superseded_by") for c in data["controls"]}
        for identity in replacements:
            visited = set()
            target = identity
            while target is not None:
                if target in visited:
                    raise InputError("Cyclic control supersession")
                visited.add(target)
                target = replacements.get(target)
    elif actual == "assessment":
        require(data, "catalog_version", str)
        require(data, "coverage", dict)
        freshness = data.get("freshness_policy_hours", 24)
        if (
            type(freshness) not in (int, float)
            or not isfinite(freshness)
            or not 0 < freshness <= 876_000
        ):
            raise InputError("Invalid assessment freshness policy")
        if not require(data, "evidence", list):
            raise InputError("Assessment requires evidence provenance")
        timestamp(require(data, "generated_at", str))
        for bundle in data["evidence"]:
            require(bundle, "inventory_complete", bool)
            timestamp(require(bundle, "collected_at", str))
            hashes(bundle.get("artifact_hashes"))
            for diagnostic in require(bundle, "diagnostics", list):
                require(diagnostic, "reason", str)
            if bundle.get("mode") not in ("planned", "observed"):
                raise InputError("Invalid assessment evidence mode")
            if bundle.get("scope") is not None:
                scope_id(bundle["scope"])
            if bundle.get("metadata") is not None:
                metadata = require(bundle, "metadata", dict)
                if "scopes" in metadata:
                    for scope in require(metadata, "scopes", list):
                        scope_id(scope)
        seen_results = set()
        for result in require(data, "results", list):
            require(result, "control_id", str)
            require(result, "upstream_id", str)
            require(result, "logical_id", str)
            require(result, "design_area", str)
            require(result, "applicability", list)
            require(result, "recommendation", str)
            if result.get("arm_id") is not None:
                canonical_id(result["arm_id"])
            for mode in ("planned", "observed"):
                item = result.get(mode)
                if item is not None:
                    if (
                        not isinstance(item, dict)
                        or not isinstance(item.get("outcome"), str)
                        or item.get("outcome") not in OUTCOMES
                    ):
                        raise InputError("Invalid assessment outcome")
                    require(item, "reason", str)
                    require(item, "evidence_links", list)
                    if item.get("freshness") not in ("current", "stale"):
                        raise InputError("Invalid assessment freshness")
                    if result.get("logical_id") is not None:
                        result_key = (
                            mode,
                            result["control_id"],
                            result.get("arm_id") or result["logical_id"],
                        )
                        if result_key in seen_results:
                            raise InputError("Duplicate or ambiguous assessment target")
                        seen_results.add(result_key)
            if result.get("comparison") not in (None, "match", "drift", "absent", "not_comparable"):
                raise InputError("Invalid comparison outcome")
            for hash_key in ("control_sha256", "rule_sha256"):
                if hash_key in result or data["schema_version"] == "1.1":
                    hashes({hash_key: result.get(hash_key)})
        if "retired_controls" in data:
            retired_ids = set()
            active_ids = {row["control_id"] for row in data["results"]}
            for item in require(data, "retired_controls", list):
                identity = require(item, "control_id", str)
                if identity in retired_ids or identity in active_ids:
                    raise InputError("Duplicate or active retired control")
                retired_ids.add(identity)
                require(item, "upstream_id", str)
                require(item, "recommendation", str)
                require(item, "retirement_reason", str)
                timestamp(require(item, "retired_at", str))
    else:
        raise InputError("Unsupported document kind")
    return data


def read_document(path: Path, max_bytes: int = 8_000_000) -> Any:
    with path.open("rb") as stream:
        content = stream.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise InputError("JSON document exceeds byte limit")
    return parse_document(content.decode("utf-8"))


def parse_document(content: str) -> Any:

    def pairs(entries: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in entries:
            if key in result:
                raise InputError("Duplicate JSON object key")
            result[key] = value
        return result

    def constant(value: str) -> Any:
        raise InputError("Nonfinite JSON numbers are not supported")

    try:
        return json.loads(
            content,
            object_pairs_hook=pairs,
            parse_constant=constant,
        )
    except (ValueError, RecursionError) as exc:
        raise InputError("JSON document could not be decoded safely") from exc


def apply_identity_map(bundle: dict[str, Any], mapping: dict[str, Any]) -> dict[str, Any]:
    validate(bundle, "evidence")
    validate(mapping, "identity-map")
    if mapping["artifact_hashes"] != bundle["artifact_hashes"]:
        raise InputError("Identity map artifact hashes do not match the evidence inputs")
    result = json.loads(json.dumps(bundle))
    by_address = {r["logical_id"]: r for r in result["resources"]}
    for entry in mapping["entries"]:
        if entry["logical_id"] not in by_address:
            raise InputError("Identity map references an unknown logical address")
        resource = by_address[entry["logical_id"]]
        identity = canonical_id(entry["arm_id"])
        if resource["resource_type"].lower().startswith("microsoft."):
            mapped_type = identity_type(identity)
            if mapped_type != resource["resource_type"].lower():
                raise InputError("Identity map resource type does not match the evidence")
        if resource.get("arm_id") and canonical_id(resource["arm_id"]) != identity:
            raise InputError("Identity map conflicts with a derived identity")
        resource["arm_id"] = identity
    return validate(result, "evidence")
