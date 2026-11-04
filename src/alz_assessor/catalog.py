"""Load the pinned, packaged catalog; never refresh references implicitly."""

import hashlib
import json
from importlib.resources import files
from typing import Any

from .contracts import digest, read_document, timestamp, validate
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
    return validate(data, "catalog")


def reviewed_refresh(candidate: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
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
        if control["automation"] == "automated" and (
            after[key]["automation"] != "automated" or after[key]["rule"] != control["rule"]
        ):
            raise InputError("Accepted automation matrix cannot be downgraded by reference refresh")
    return {
        "from": current["catalog_version"],
        "to": candidate["catalog_version"],
        "added": sorted(after.keys() - before.keys()),
        "changed": sorted(key for key in before if digest(before[key]) != digest(after[key])),
        "candidate_sha256": digest(candidate),
    }
