"""Maintainer-only source diffs; nothing is promoted or queried by this module."""

import hashlib
import re
import urllib.request
from collections import defaultdict
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from .azure import NoRedirect
from .contracts import digest
from .terraform import InputError


def public_fetch(url: str) -> bytes:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.netloc not in {"api.github.com", "raw.githubusercontent.com"}
        or parsed.username
        or parsed.fragment
    ):
        raise InputError("Source acquisition requires an approved public GitHub HTTPS origin")
    request = urllib.request.Request(url, headers={"User-Agent": "LandingLens-source-monitor/0.1"})
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
        content = response.read(8_000_001)
    if len(content) > 8_000_000:
        raise InputError("Public source exceeds acquisition byte limit")
    return content


def indexed_items(checklist: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(checklist, dict) or not isinstance(checklist.get("items"), list):
        raise InputError("Checklist schema requires an items array")
    result = {}
    for item in checklist["items"]:
        if not isinstance(item, dict):
            raise InputError("Checklist item must be an object")
        for key in ("guid", "id", "category", "text"):
            if not isinstance(item.get(key), str) or not item[key].strip():
                raise InputError("Checklist item has missing or changed required field types")
        try:
            identity = str(UUID(item["guid"]))
        except ValueError as exc:
            raise InputError("Invalid upstream GUID") from exc
        if identity in result:
            raise InputError("Conflicting upstream GUIDs")
        result[identity] = item
    return result


def source_schema(checklist: dict[str, Any]) -> dict[str, Any]:
    return {
        "top": {key: type(value).__name__ for key, value in sorted(checklist.items())},
        "items": sorted(
            {
                (key, type(value).__name__)
                for item in checklist["items"]
                for key, value in item.items()
            }
        ),
    }


def taxonomy(text: str) -> list[tuple[str, str]]:
    return sorted(set(re.findall(r"\[([^\]]+)\]\(\./design-area/([^)]+)\)", text)))


def semantic_diff(
    before: dict[str, Any],
    after: dict[str, Any],
    before_taxonomy: str,
    after_taxonomy: str,
    before_licenses: dict[str, str],
    after_licenses: dict[str, str],
) -> dict[str, Any]:
    old, new = indexed_items(before), indexed_items(after)
    displays: dict[str, list[str]] = defaultdict(list)
    for identity, item in new.items():
        displays[item["id"]].append(identity)
    changed = []
    for identity in sorted(old.keys() & new.keys()):
        fields = [
            key
            for key in sorted(old[identity].keys() | new[identity].keys())
            if digest(old[identity].get(key)) != digest(new[identity].get(key))
        ]
        if fields:
            changed.append(
                {
                    "guid": identity,
                    "fields": fields,
                    "review_bindings_require_review": True,
                    "before_sha256": digest(old[identity]),
                    "after_sha256": digest(new[identity]),
                }
            )
    return {
        "added_guids": sorted(new.keys() - old.keys()),
        "removed_guids_require_retirement": sorted(old.keys() - new.keys()),
        "changed": changed,
        "display_id_collisions": {
            key: sorted(values) for key, values in sorted(displays.items()) if len(values) > 1
        },
        "schema_changed": source_schema(before) != source_schema(after),
        "metadata_changed": digest(before.get("metadata")) != digest(after.get("metadata")),
        "top_level_changes": [
            key
            for key in sorted(before.keys() | after.keys())
            if key != "items" and digest(before.get(key)) != digest(after.get(key))
        ],
        "taxonomy_changed": taxonomy(before_taxonomy) != taxonomy(after_taxonomy),
        "license_changes": sorted(
            key
            for key in before_licenses.keys() | after_licenses.keys()
            if before_licenses.get(key) != after_licenses.get(key)
        ),
        "promotion": (
            "Not reviewed. Retain removed GUIDs as 1.1 retired records; resolve schema/taxonomy/"
            "ID conflicts and review changed bindings. Promotion requires a reviewed PR and "
            "exact matrix change evidence; no catalog bytes are replaced by monitoring."
        ),
    }


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()
