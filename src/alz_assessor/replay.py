"""Explicit local replay of a bounded, privacy-projected normalized evidence bundle."""

from __future__ import annotations

import hashlib
import json
import stat
from importlib.resources import files
from itertools import islice
from pathlib import Path
from typing import Any

from .catalog import load_catalog
from .contracts import digest, document, hashes, parse_document, require, scope_id, validate
from .diagnostics import REASONS
from .engine import assess
from .governance_evidence import replay_properties as governance_properties
from .identity_evidence import replay_properties as identity_properties
from .logging_evidence import replay_properties as logging_properties
from .network_evidence import replay_properties
from .organization_evidence import replay_properties as organization_properties
from .platform_health_evidence import replay_properties as platform_health_properties
from .policy_strategy_evidence import replay_properties as policy_strategy_properties
from .security_evidence import replay_properties as security_properties
from .sources import boolean, enumeration, property_at
from .tenant_evidence import replay_properties as tenant_properties
from .terraform import InputError
from .topology_evidence import replay_properties as topology_properties

MEMBERS = {"catalog.json", "evidence.json", "reviews.json"}
MAX_BYTES = 8_000_000
WARNING = (
    "Local replay retains scoped resource identities and is not anonymized. "
    "Free text/paths are withheld; reviewer labels are pseudonymized by default. "
    "No source trees, credentials, environment or automatic upload are included."
)
KNOWN_REASONS = {reason for reasons in REASONS.values() for reason in reasons}


def label(value: Any) -> str:
    return "withheld-" + digest(value)


def known_catalog(catalog: dict[str, Any]) -> dict[str, Any]:
    validate(catalog, "catalog")
    current = load_catalog()
    historical = [
        json.loads(item.read_text("utf-8"))
        for item in files("alz_assessor").joinpath("data").iterdir()
        if item.name.startswith("catalog-") and item.name.endswith(".json")
    ]
    if not any(digest(catalog) == digest(item) for item in [current, *historical]):
        raise InputError("Historical catalog is unavailable or differs from a packaged artifact")
    return catalog


def semantic(report: dict[str, Any]) -> str:
    return digest(
        {
            "coverage": report["coverage"],
            **({"evidence_tiers": report["evidence_tiers"]} if "evidence_tiers" in report else {}),
            **(
                {"applicability_suggestions": report["applicability_suggestions"]}
                if "applicability_suggestions" in report
                else {}
            ),
            **({"policy_signals": report["policy_signals"]} if "policy_signals" in report else {}),
            **(
                {"scanner_signals": report["scanner_signals"]}
                if "scanner_signals" in report
                else {}
            ),
            **({"query_signals": report["query_signals"]} if "query_signals" in report else {}),
            "results": [
                {
                    **{key: row.get(key) for key in ("control_id", "logical_id", "arm_id")},
                    **{
                        mode: {
                            **{
                                key: row[mode].get(key)
                                for key in (
                                    "outcome",
                                    "fact",
                                    "freshness",
                                    "exception_disposition",
                                    "disposition_validity",
                                )
                            },
                            **(
                                {"component_facts": row[mode]["component_facts"]}
                                if "component_facts" in row[mode]
                                else {}
                            ),
                        }
                        if row.get(mode)
                        else None
                        for mode in ("planned", "observed")
                    },
                }
                for row in report["results"]
            ],
        }
    )


def sanitize_evidence(bundle: dict[str, Any]) -> dict[str, Any]:
    if bundle.get("presentation_only"):
        raise InputError("Minimized presentations are not replayable")
    validate(bundle, "evidence")
    if len(bundle["resources"]) > 10_000:
        raise InputError("Replay resource limit exceeded")
    resources = []
    for resource in bundle["resources"]:
        values = resource["properties"]
        resources.append(
            {
                **{
                    key: resource.get(key)
                    for key in (
                        "logical_id",
                        "arm_id",
                        "resource_type",
                        "state",
                    )
                },
                **(
                    {
                        "api_version": "2020-05-01"
                        if resource.get("api_version") == "2020-05-01"
                        else None
                    }
                    if resource["resource_type"].lower()
                    == "microsoft.management/managementgroups/settings"
                    else {}
                ),
                "reason": resource["reason"]
                if resource["reason"] in KNOWN_REASONS
                else label(resource["reason"])
                if resource["reason"]
                else "",
                "source_location": "artifact://" + digest(resource["source_location"]),
                "properties": {
                    "enableSoftDelete": boolean(property_at(values, "enableSoftDelete")),
                    "enablePurgeProtection": boolean(property_at(values, "enablePurgeProtection")),
                    "enableRbacAuthorization": boolean(
                        property_at(values, "enableRbacAuthorization")
                    ),
                    "publicNetworkAccess": enumeration(
                        property_at(values, "publicNetworkAccess"),
                        ("Enabled", "Disabled"),
                    ),
                    "networkAcls": {
                        "defaultAction": enumeration(
                            property_at(values, "networkAcls.defaultAction"), ("Allow", "Deny")
                        )
                    },
                    "minimumTlsVersion": enumeration(
                        property_at(values, "minimumTlsVersion"), ("TLS1_0", "TLS1_1", "TLS1_2")
                    ),
                    "containerDeleteRetentionPolicy": {
                        "enabled": boolean(
                            property_at(values, "containerDeleteRetentionPolicy.enabled")
                        )
                    },
                    "supportsHttpsTrafficOnly": boolean(
                        property_at(values, "supportsHttpsTrafficOnly")
                    ),
                    "dnsSettings": {
                        "enableProxy": boolean(property_at(values, "dnsSettings.enableProxy"))
                    },
                    "sku": {
                        "tier": enumeration(
                            property_at(values, "sku.tier"), ("Basic", "Standard", "Premium")
                        )
                    },
                    "threatIntelMode": enumeration(
                        property_at(values, "threatIntelMode"), ("Alert", "Deny", "Off")
                    ),
                    "intrusionDetection": {
                        "mode": enumeration(
                            property_at(values, "intrusionDetection.mode"),
                            ("Alert", "Deny", "Off"),
                        )
                    },
                    **replay_properties(resource["resource_type"], values),
                    **identity_properties(resource["resource_type"], values),
                    **security_properties(resource["resource_type"], values),
                    **governance_properties(resource["resource_type"], values),
                    **organization_properties(resource["resource_type"], values),
                    **policy_strategy_properties(resource["resource_type"], values),
                    **topology_properties(resource["resource_type"], values),
                    **tenant_properties(resource["resource_type"], values),
                    **logging_properties(resource["resource_type"], values),
                    **platform_health_properties(resource["resource_type"], values),
                },
            }
        )
    metadata: dict[str, Any] = {"replay_sanitized": True}
    original = bundle.get("metadata") or {}
    if "relationships" in original and (bundle.get("scope") or "").lower().startswith(
        "/providers/microsoft.management/managementgroups/"
    ):
        from .governance_evidence import hierarchy_context

        hierarchy = hierarchy_context(bundle)
        if "unknown" in hierarchy:
            raise InputError("Cannot replay malformed, ambiguous or over-bound saved hierarchy")
        metadata["relationships"] = hierarchy["relationships"]
    if "query_evidence" in original:
        from .query_signals import validate_query_evidence

        validate_query_evidence(original["query_evidence"])
        metadata["query_evidence"] = original["query_evidence"]
    if "scanner_evidence" in original:
        from .scanner_evidence import validate_scanner

        validate_scanner(original["scanner_evidence"])
        metadata["scanner_evidence"] = original["scanner_evidence"]
    if any(
        key in original for key in ("policy_assignments", "policy_compliance", "policy_exemptions")
    ):
        from .policy_evidence import project_policy_metadata

        metadata.update(project_policy_metadata(original))
    if "archetype_bindings" in original:
        from .priorities import archetype_bindings

        metadata["archetype_bindings"] = archetype_bindings(original["archetype_bindings"], bundle)
    if "scopes" in original:
        metadata["scopes"] = [scope_id(value) for value in require(original, "scopes", list)]
    if isinstance(original.get("completeness"), dict):
        metadata["completeness"] = {
            key: value
            for key, value in original["completeness"].items()
            if key
            in {
                "inventory",
                "configuration",
                "relationships",
                "assignments",
                "exemptions",
                "compliance",
                "definitions",
            }
            and type(value) is bool
        }
    return validate(
        document(
            "evidence",
            schema_version=bundle["schema_version"],
            mode=bundle["mode"],
            source=bundle["source"],
            scope=bundle.get("scope"),
            collected_at=bundle["collected_at"],
            inventory_complete=bundle["inventory_complete"],
            artifact_hashes={label(key): value for key, value in bundle["artifact_hashes"].items()},
            resources=resources,
            metadata=metadata,
            diagnostics=[
                {
                    "reason": item["reason"]
                    if item["reason"] in KNOWN_REASONS
                    else label(item["reason"])
                }
                for item in bundle["diagnostics"]
            ],
        )
    )


def sanitize_reviews(
    records: dict[str, Any] | None,
    kind: str,
    retain_attribution: bool,
) -> dict[str, Any] | None:
    if records is None:
        return None
    validate(records, kind)
    if len(records["entries"]) > 1000:
        raise InputError("Replay review-entry limit exceeded")
    entries = []
    for original in records["entries"]:
        entry = {
            key: original[key]
            for key in (
                "control_id",
                "scope",
                "valid_from",
                "valid_until",
                "control_sha256",
                "outcome" if kind == "manual" else "disposition",
            )
            if key in original
        }
        entry["rationale"] = label(original["rationale"])
        if "evidence" in original:
            entry["evidence"] = "review://" + label(original["evidence"])
        if "reviewer" in original:
            entry["reviewer"] = (
                original["reviewer"]
                if retain_attribution
                else "reviewer-" + digest(original["reviewer"])
            )
        entries.append(entry)
    return validate(document(kind, schema_version=records["schema_version"], entries=entries))


def export_bundle(
    destination: Path,
    evidence: dict[str, Any],
    catalog: dict[str, Any],
    *,
    at: str,
    landing_zone: str = "platform",
    max_age_hours: float = 24,
    manual: dict[str, Any] | None = None,
    exceptions: dict[str, Any] | None = None,
    retain_attribution: bool = False,
    evidence_tiers: bool = False,
) -> dict[str, Any]:
    catalog = known_catalog(catalog)
    sanitized = sanitize_evidence(evidence)
    invocation = {"at": at, "landing_zone": landing_zone, "max_age_hours": max_age_hours}
    if evidence_tiers:
        invocation["evidence_tiers"] = True
    original = assess(
        evidence,
        catalog,
        manual=manual,
        exceptions=exceptions,
        at=at,
        landing_zone=landing_zone,
        max_age_hours=max_age_hours,
        evidence_tiers=evidence_tiers,
    )
    reviews = {
        "manual": sanitize_reviews(manual, "manual", retain_attribution),
        "exceptions": sanitize_reviews(exceptions, "exceptions", retain_attribution),
    }
    replayed = assess(
        sanitized,
        catalog,
        manual=reviews["manual"],
        exceptions=reviews["exceptions"],
        at=at,
        landing_zone=landing_zone,
        max_age_hours=max_age_hours,
        evidence_tiers=evidence_tiers,
    )
    if semantic(original) != semantic(replayed):
        raise InputError("Privacy projection cannot preserve this assessment's semantics")
    documents = {"catalog.json": catalog, "evidence.json": sanitized, "reviews.json": reviews}
    encoded = {
        name: (json.dumps(value, indent=2, allow_nan=False) + "\n").encode("utf-8")
        for name, value in documents.items()
    }
    manifest = {
        "schema_version": "1.1" if evidence_tiers else "1.0",
        "kind": "landinglens-replay",
        "files": {
            name: {"sha256": hashlib.sha256(value).hexdigest(), "size": len(value)}
            for name, value in encoded.items()
        },
        "invocation": invocation,
        "semantic_sha256": semantic(replayed),
        "warning": WARNING,
        "attribution_retained": retain_attribution,
    }
    encoded["manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    if (
        any(len(value) > MAX_BYTES for value in encoded.values())
        or sum(map(len, encoded.values())) > 16_000_000
    ):
        raise InputError("Replay bundle exceeds byte limits")
    # A new flat directory is the entire write boundary; no manifest path is used for writing.
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, value in encoded.items():
        with (destination / name).open("xb") as stream:
            stream.write(value)
    return {"warning": WARNING, "files": sorted(encoded), "semantic_sha256": semantic(replayed)}


def replay_bundle(source: Path) -> dict[str, Any]:
    if source.is_symlink() or source.is_junction() or not source.is_dir():
        raise InputError("Replay requires a regular local bundle directory, not a link/archive")
    names = {path.name for path in islice(source.iterdir(), 5)}
    if names != MEMBERS | {"manifest.json"}:
        raise InputError("Replay requires exactly the four fixed member paths")
    blobs = {}
    for name in sorted(names):
        path = source / name
        info = path.lstat()
        if (
            path.is_symlink()
            or path.is_junction()
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
        ):
            raise InputError("Replay members must be regular files without links")
        with path.open("rb") as stream:
            value = stream.read(MAX_BYTES + 1)
        if len(value) > MAX_BYTES:
            raise InputError("Replay member exceeds byte limit")
        blobs[name] = value
    if sum(map(len, blobs.values())) > 16_000_000:
        raise InputError("Replay bundle exceeds total byte limit")
    manifest = parse_document(blobs["manifest.json"].decode("utf-8"))
    if (
        not isinstance(manifest, dict)
        or set(manifest)
        != {
            "schema_version",
            "kind",
            "files",
            "invocation",
            "semantic_sha256",
            "warning",
            "attribution_retained",
        }
        or manifest["schema_version"] not in ("1.0", "1.1")
        or manifest["kind"] != "landinglens-replay"
        or manifest["warning"] != WARNING
        or type(manifest["attribution_retained"]) is not bool
    ):
        raise InputError("Unsupported replay manifest")
    members = require(manifest, "files", dict)
    if set(members) != MEMBERS:
        raise InputError("Replay manifest contains invalid or conflicting paths")
    for name in MEMBERS:
        entry = members[name]
        hashes({"file": require(entry, "sha256", str)})
        if (
            require(entry, "size", int) != len(blobs[name])
            or entry["sha256"] != hashlib.sha256(blobs[name]).hexdigest()
        ):
            raise InputError("Replay member hash or size mismatch")
    invocation = require(manifest, "invocation", dict)
    expected_options = {"at", "landing_zone", "max_age_hours"} | (
        {"evidence_tiers"} if manifest["schema_version"] == "1.1" else set()
    )
    if set(invocation) != expected_options:
        raise InputError("Replay invocation contains unsupported options")
    if manifest["schema_version"] == "1.1" and invocation["evidence_tiers"] is not True:
        raise InputError("Tiered replay requires explicit evidence_tiers=true")
    require(invocation, "at", str)
    require(invocation, "landing_zone", str)
    if type(invocation["max_age_hours"]) not in (int, float):
        raise InputError("Replay freshness must be numeric")
    catalog = known_catalog(parse_document(blobs["catalog.json"].decode("utf-8")))
    evidence = validate(parse_document(blobs["evidence.json"].decode("utf-8")), "evidence")
    reviews = parse_document(blobs["reviews.json"].decode("utf-8"))
    if not isinstance(reviews, dict) or set(reviews) != {"manual", "exceptions"}:
        raise InputError("Replay requires explicit manual/exception review slots")
    result = assess(evidence, catalog, **reviews, **invocation)
    hashes({"semantics": require(manifest, "semantic_sha256", str)})
    if semantic(result) != manifest["semantic_sha256"]:
        raise InputError("Replay semantic outcomes or coverage differ from the recorded result")
    return result
