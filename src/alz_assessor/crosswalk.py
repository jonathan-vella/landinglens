"""Reviewed evidence associations, never evaluator rules or executable queries."""

import json
import re
from importlib.resources import files
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from .contracts import digest, hashes, read_document, require, timestamp, validate
from .terraform import InputError

KINDS = {
    "alz-policy-assignment",
    "alz-policy-definition",
    "azure-policy-definition",
    "psrule",
    "arg-query",
}
STRENGTHS = {"equivalent", "partial", "related"}
WARNING = (
    "Crosswalk associations are not outcomes. Machine evidence requires review; "
    "no query or scanner is executed."
)


def public_url(value: Any) -> str:
    if not isinstance(value, str):
        raise InputError("Crosswalk provenance URL must be a string")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.netloc not in {"github.com", "raw.githubusercontent.com"}
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or "\\" in value
        or "%" in value
        or ".." in parsed.path.split("/")
    ):
        raise InputError("Crosswalk provenance requires a public immutable GitHub source")
    return value


def validate_crosswalk(data: Any, catalog: dict[str, Any]) -> dict[str, Any]:
    validate(catalog, "catalog")
    if (
        not isinstance(data, dict)
        or data.get("schema_version") != "1.0"
        or data.get("kind") != "crosswalk"
        or data.get("review_state") != "reviewed"
    ):
        raise InputError("Unsupported or unreviewed crosswalk contract")
    if set(data) != {
        "schema_version",
        "kind",
        "crosswalk_version",
        "catalog_sha256",
        "review_state",
        "reviewed_at",
        "reviewer",
        "sources",
        "entries",
    }:
        raise InputError("Unexpected crosswalk fields; raw evidence is not crosswalk metadata")
    require(data, "crosswalk_version", str)
    if data.get("catalog_sha256") != digest(catalog):
        raise InputError("Crosswalk catalog binding differs; use the exact reviewed catalog")
    timestamp(require(data, "reviewed_at", str))
    require(data, "reviewer", str)
    sources = require(data, "sources", list)
    if not sources or len(sources) > 100:
        raise InputError("Crosswalk requires 1-100 reviewed sources")
    source_by_id = {}
    for source in sources:
        if not isinstance(source, dict) or set(source) != {
            "id",
            "url",
            "revision",
            "sha256",
            "retrieved_at",
            "release",
            "license",
            "license_url",
            "license_revision",
            "license_sha256",
            "finding",
        }:
            raise InputError("Unexpected crosswalk source fields")
        identity = require(source, "id", str)
        if identity in source_by_id:
            raise InputError("Duplicate crosswalk source identity")
        revision = require(source, "revision", str)
        if not re.fullmatch("[0-9a-f]{40}", revision):
            raise InputError("Crosswalk source requires an immutable commit")
        license_revision = require(source, "license_revision", str)
        if not re.fullmatch("[0-9a-f]{40}", license_revision):
            raise InputError("Crosswalk licence requires an immutable commit")
        for field, commit in (("url", revision), ("license_url", license_revision)):
            url = public_url(source.get(field))
            if commit not in urlsplit(url).path.split("/"):
                raise InputError("Crosswalk source and licence URLs must pin their commit")
        hashes({field: source.get(field) for field in ("sha256", "license_sha256")})
        timestamp(require(source, "retrieved_at", str))
        require(source, "license", str)
        require(source, "finding", str)
        source_by_id[identity] = source
    controls = {control["upstream_guid"]: control for control in catalog["controls"]}
    entries = require(data, "entries", list)
    if len(entries) != len(controls):
        raise InputError("Crosswalk must retain every catalog GUID exactly once")
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"guid", "control_id", "targets"}:
            raise InputError("Unexpected crosswalk entry fields")
        guid = require(entry, "guid", str)
        try:
            valid_guid = str(UUID(guid)) == guid
        except ValueError:
            valid_guid = False
        if not valid_guid or guid not in controls or guid in seen:
            raise InputError("Unknown, invalid or duplicate crosswalk GUID")
        seen.add(guid)
        if entry.get("control_id") != controls[guid]["control_id"]:
            raise InputError("Crosswalk control identity does not match its GUID")
        targets = require(entry, "targets", list)
        if len(targets) > 100:
            raise InputError("Crosswalk target bound exceeded")
        unique = set()
        for target in targets:
            if not isinstance(target, dict) or set(target) != {
                "kind",
                "id",
                "strength",
                "rationale",
                "source_ids",
            }:
                raise InputError("Unexpected crosswalk target fields")
            kind, identity = require(target, "kind", str), require(target, "id", str)
            strength = require(target, "strength", str)
            if kind not in KINDS or strength not in STRENGTHS:
                raise InputError("Unknown crosswalk target kind or mapping strength")
            key = (kind, identity.casefold())
            if key in unique:
                raise InputError("Duplicate or conflicting crosswalk target")
            unique.add(key)
            require(target, "rationale", str)
            source_ids = require(target, "source_ids", list)
            if (
                not source_ids
                or len(source_ids) > 10
                or any(not isinstance(item, str) or item not in source_by_id for item in source_ids)
                or len(set(source_ids)) != len(source_ids)
            ):
                raise InputError("Crosswalk target requires unique known source references")
            if kind == "arg-query":
                hashes({"query": identity})
            elif kind == "azure-policy-definition":
                if not re.fullmatch(
                    r"/providers/Microsoft.Authorization/policyDefinitions/[0-9a-f-]{36}", identity
                ):
                    raise InputError("Built-in policy target requires its definition ID")
                try:
                    if str(UUID(identity.rsplit("/", 1)[-1])) != identity.rsplit("/", 1)[-1]:
                        raise ValueError("Noncanonical UUID")
                except ValueError as exc:
                    raise InputError("Invalid built-in policy definition UUID") from exc
            elif kind.startswith("alz-"):
                if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,255}", identity):
                    raise InputError("ALZ policy target requires a simple exact library name")
                if not any(
                    isinstance(source_by_id[item].get("release"), str)
                    and source_by_id[item]["release"].startswith("platform/alz/")
                    for item in source_ids
                ):
                    raise InputError("ALZ target requires a pinned platform/alz release")
            elif not re.fullmatch(r"(?:AZR-[0-9]{6}|Azure\.[A-Za-z0-9_.-]+)", identity):
                raise InputError("PSRule target requires a reviewed rule name or reference")
    return data


def load_crosswalk(catalog: dict[str, Any], path: Path | None = None) -> dict[str, Any]:
    if path:
        return validate_crosswalk(read_document(path), catalog)
    root = files("alz_assessor").joinpath("data")
    content = json.loads(root.joinpath("crosswalk.json").read_text("utf-8"))
    binding = json.loads(root.joinpath("crosswalk-binding.json").read_text("utf-8"))
    if binding.get("crosswalk_sha256") != digest(content):
        raise InputError("Packaged crosswalk provenance binding mismatch")
    return validate_crosswalk(content, catalog)


def inspect_crosswalk(
    data: dict[str, Any], catalog: dict[str, Any], selection: str | None = None
) -> dict[str, Any]:
    validate_crosswalk(data, catalog)
    entries = data["entries"]
    if selection is not None:
        matches = [
            control
            for control in catalog["controls"]
            if selection
            in {control["control_id"], control["upstream_guid"], control["upstream_id"]}
        ]
        if len(matches) != 1:
            raise InputError("Missing or ambiguous selection; use the canonical GUID or control ID")
        entries = [entry for entry in entries if entry["guid"] == matches[0]["upstream_guid"]]
    return {
        "crosswalk_version": data["crosswalk_version"],
        "catalog_version": catalog["catalog_version"],
        "controls": len(data["entries"]),
        "mapped_controls": sum(bool(entry["targets"]) for entry in data["entries"]),
        "targets": sum(len(entry["targets"]) for entry in data["entries"]),
        "entries": entries,
        "sources": data["sources"],
        "warning": WARNING,
    }
