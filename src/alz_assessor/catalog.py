"""Load the pinned, packaged catalog; never refresh references implicitly."""

import hashlib
import json
from importlib.resources import files
from typing import Any

from .contracts import control_digest, digest, read_document, require, timestamp, validate
from .terraform import InputError


def load_catalog(path: str | None = None) -> dict[str, Any]:
    if path:
        from pathlib import Path

        data = read_document(Path(path))
    else:
        root = files("alz_assessor").joinpath("data")
        data = json.loads(root.joinpath("catalog.json").read_text("utf-8"))
        if hashlib.sha256(
            root.joinpath("control-sources.json").read_bytes()
        ).hexdigest() != data.get(
            "control_source_manifest_sha256",
        ):
            raise InputError("Packaged control-source provenance hash mismatch")
        if data.get("wave_source_manifest_sha256"):
            if hashlib.sha256(
                root.joinpath("wave-control-sources.json").read_bytes()
            ).hexdigest() != data["wave_source_manifest_sha256"] or digest(
                json.loads(root.joinpath("accepted-matrix.json").read_text("utf-8"))
            ) != (
                data.get("first_wave_matrix_sha256")
                if data.get("batch_source_manifest_sha256")
                else data.get("accepted_matrix_sha256")
            ):
                raise InputError("Packaged first-wave source or accepted-matrix hash mismatch")
        if data.get("batch_source_manifest_sha256"):
            version = data.get("batch_catalog_version", data["catalog_version"])
            suffix = "" if version == "2026-11-05.1" else "-" + version
            if hashlib.sha256(
                root.joinpath(f"batch-control-sources{suffix}.json").read_bytes()
            ).hexdigest() != data["batch_source_manifest_sha256"] or digest(
                json.loads(root.joinpath(f"batch-matrix{suffix}.json").read_text("utf-8"))
            ) != data.get("accepted_matrix_sha256"):
                raise InputError("Packaged batch source or accepted-matrix hash mismatch")
        if data.get("priority_manifest_sha256"):
            from .priorities import load_priorities

            priorities = load_priorities()
            if (
                digest(priorities) != data["priority_manifest_sha256"]
                or {c["upstream_guid"]: c.get("severity") for c in data["controls"]}
                != priorities["severities"]
            ):
                raise InputError("Packaged severity source binding mismatch")
    if str(data.get("review_state", "")).startswith("candidate"):
        raise InputError("Source candidates cannot be loaded as accepted assessment catalogs")
    return validate(data, "catalog")


def catalog_lag(version: str, index: dict[str, Any]) -> dict[str, Any]:
    import re

    from .contracts import hashes

    if (
        not isinstance(index, dict)
        or set(index) != {"schema_version", "kind", "catalogs"}
        or (index["schema_version"] != "1.0" or index["kind"] != "accepted-catalog-index")
    ):
        raise InputError("Expected accepted-catalog-index contract 1.0")
    versions = []
    for entry in require(index, "catalogs", list):
        if not isinstance(entry, dict) or set(entry) != {"version", "sha256"}:
            raise InputError("Catalog index requires exact version and SHA-256")
        value = require(entry, "version", str)
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}\.\d+", value) or value in versions:
            raise InputError("Catalog index version is invalid or duplicated")
        hashes({"catalog": entry["sha256"]})
        versions.append(value)
    if not versions or len(versions) > 1000:
        raise InputError("Catalog index requires 1-1000 known accepted versions")

    def order(value: str) -> tuple[str, int]:
        day, sequence = value.rsplit(".", 1)
        return day, int(sequence)

    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}\.\d+", version):
        raise InputError("Catalog lag requires a comparable reviewed version")
    behind = sum(order(item) > order(version) for item in versions)
    return {
        "known_latest": max(versions, key=order),
        "versions_behind": behind,
        "warning": f"Catalog is {behind} versions behind the explicitly supplied local index. "
        "Index acceptance is a producer assertion; no network refresh or replacement.",
    }


def reviewed_refresh(candidate: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    validate(current, "catalog")
    validate(candidate, "catalog")
    if candidate.get("review_state") != "reviewed":
        raise InputError("Refresh accepts only an explicitly reviewed local catalog")
    timestamp(candidate.get("reviewed_at", ""))
    if candidate["catalog_version"] == current["catalog_version"]:
        raise InputError("Refresh requires a new catalog version; frozen versions are immutable")
    before = {item["control_id"]: item for item in current["controls"]}
    after = {item["control_id"]: item for item in candidate["controls"]}
    if before.keys() - after.keys():
        raise InputError("Refresh cannot silently remove imported checklist items")
    for key, control in before.items():
        if (control["automation"] == "automated" or after[key]["automation"] == "automated") and (
            after[key]["automation"] != control["automation"]
            or after[key].get("rule") != control.get("rule")
            or after[key]["lifecycle"] != control["lifecycle"]
        ):
            review = candidate.get("change_review")
            if (
                candidate["schema_version"] != "1.1"
                or not isinstance(review, dict)
                or review.get("base_sha256") != digest(current)
                or candidate.get("accepted_matrix_sha256") != review.get("matrix_sha256")
            ):
                raise InputError(
                    "Accepted automation matrix cannot be downgraded by reference refresh"
                )
            from .contracts import hashes

            hashes({"matrix": candidate.get("accepted_matrix_sha256")})
            timestamp(require(review, "reviewed_at", str))
            require(review, "reviewer", str)
            changes = require(review, "changes", list)
            for item in changes:
                require(item, "control_id", str)
            matches = [item for item in changes if item["control_id"] == key]
            if (
                len(matches) != 1
                or matches[0].get("before_sha256") != control_digest(control)
                or matches[0].get("after_sha256") != control_digest(after[key])
            ):
                raise InputError("Predicate change requires exact reviewed before/after hashes")
            require(matches[0], "rationale", str)
    return {
        "from": current["catalog_version"],
        "to": candidate["catalog_version"],
        "added": sorted(after.keys() - before.keys()),
        "changed": sorted(key for key in before if digest(before[key]) != digest(after[key])),
        "retired": sorted(key for key in after if after[key]["lifecycle"] == "retired"),
        "candidate_sha256": digest(candidate),
    }
