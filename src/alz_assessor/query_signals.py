"""Exact allowlisted scoped ARG observations, never recommendation predicates."""

import copy
import hashlib
import json
from datetime import timedelta
from importlib.resources import files
from typing import Any

from .contracts import (
    canonical_id,
    digest,
    document,
    hashes,
    identity_type,
    now,
    require,
    scope_id,
    timestamp,
    validate,
)
from .terraform import InputError

WARNING = (
    "ARG observations are Signals only. Empty rows and exhausted pages do not establish "
    "compliance or authorisation coverage."
)


def load_allowlist() -> dict[str, Any]:
    root = files("alz_assessor").joinpath("data")
    data = json.loads(root.joinpath("query-allowlist.json").read_text("utf-8"))
    binding = json.loads(root.joinpath("query-allowlist-binding.json").read_text("utf-8"))
    if binding.get("sha256") != digest(data) or data.get("schema_version") != "1.0":
        raise InputError("Packaged query allowlist binding/version mismatch")
    if len(data.get("queries", [])) != 49:
        raise InputError("Query review must account for all 49 audited GUIDs")
    for entry in data["queries"]:
        if entry["allowed"]:
            if hashlib.sha256(entry["query"].encode()).hexdigest() != entry["query_sha256"]:
                raise InputError("Allowlisted query text/hash mismatch")
    return data


def selected_query(guid: str, query: str | None = None) -> dict[str, Any]:
    matches = [
        entry for entry in load_allowlist()["queries"] if entry["guid"] == guid and entry["allowed"]
    ]
    if len(matches) != 1 or (query is not None and query != matches[0]["query"]):
        raise InputError("Query is not exact-hash allowlisted; no transport request is permitted")
    return matches[0]


def approved_text(query: Any) -> bool:
    return isinstance(query, str) and any(
        entry["allowed"] and entry["query"] == query for entry in load_allowlist()["queries"]
    )


def execute_query(
    transport: Any, guid: str, subscriptions: list[str], *, at: str | None = None, sleep: Any = None
) -> dict[str, Any]:
    from .azure import ARG_URL, Collector

    entry = selected_query(guid)
    if not isinstance(subscriptions, list) or not subscriptions or len(subscriptions) > 100:
        raise InputError("Query Signals require 1-100 explicit subscription scopes")
    scopes = []
    for subscription in subscriptions:
        if not isinstance(subscription, str):
            raise InputError("Query subscription identifiers must be strings")
        scope = scope_id("/subscriptions/" + subscription)
        if scope in scopes:
            raise InputError("Duplicate explicit query subscription scope")
        scopes.append(scope)
    collected = at or now()
    timestamp(collected)
    collector = Collector(transport, sleep=sleep) if sleep is not None else Collector(transport)
    token = None
    tokens = set()
    records: dict[str, dict[str, Any]] = {}
    pages = 0
    for _ in range(100):
        options: dict[str, Any] = {"$top": 1000, "resultFormat": "objectArray"}
        if token is not None:
            options["$skipToken"] = token
        response = collector.request(
            "POST",
            ARG_URL,
            "inventory",
            {
                "subscriptions": [scope.split("/")[2] for scope in scopes],
                "query": entry["query"],
                "options": options,
            },
        )
        if response is None:
            break
        pages += 1
        rows = response.get("data")
        total, count, truncated = (
            response.get("totalRecords"),
            response.get("count"),
            response.get("resultTruncated"),
        )
        if (
            not isinstance(rows, list)
            or len(rows) > 1000
            or type(count) is not int
            or count != len(rows)
            or type(total) is not int
            or total < count
            or not (
                type(truncated) is bool
                or isinstance(truncated, str)
                and truncated in ("true", "false")
            )
        ):
            raise InputError("ARG Signal response requires bounded object-array counts/truncation")
        for row in rows:
            if not isinstance(row, dict):
                raise InputError("ARG Signal row must be an object")
            identity = canonical_id(require(row, "id", str))
            if not any(identity.startswith(scope + "/") for scope in scopes):
                raise InputError("ARG Signal target escaped explicit subscription scope")
            if identity_type(identity) != entry["resource_type"]:
                raise InputError("ARG Signal target type differs from reviewed query")
            value = row.get("compliant")
            record = {
                "resource_id": identity,
                "reported_compliant": value if type(value) is bool else None,
                "conflicted": False,
            }
            if identity in records and records[identity] != record:
                record["conflicted"] = True
                record["reported_compliant"] = None
            if identity in records and records[identity]["conflicted"]:
                record["conflicted"] = True
                record["reported_compliant"] = None
            records[identity] = record
            if len(records) > 10_000:
                raise InputError("ARG Signal population exceeds 10,000")
        token = response.get("$skipToken")
        if not token:
            if truncated in (True, "true") or total > len(records):
                collector.gap("inventory", "truncated_without_continuation", ARG_URL)
            break
        if not isinstance(token, str) or not 0 < len(token) <= 64_000 or token in tokens:
            collector.gap("inventory", "invalid_or_repeated_continuation", ARG_URL)
            break
        tokens.add(token)
    else:
        collector.gap("inventory", "page_limit", ARG_URL)
    facts = {
        "guid": guid,
        "query_sha256": entry["query_sha256"],
        "collected_at": collected,
        "scopes": scopes,
        "pages": pages,
        "partial": not collector.facets["inventory"],
        "records": list(records.values()),
        "warning": WARNING,
    }
    return validate(
        document(
            "evidence",
            schema_version="1.1",
            mode="observed",
            source="azure",
            scope=scopes[0] if len(scopes) == 1 else None,
            collected_at=collected,
            inventory_complete=False,
            resources=[],
            diagnostics=collector.diagnostics,
            artifact_hashes=collector.artifacts
            or {"query-invocation": digest({"guid": guid, "scopes": scopes, "at": collected})},
            metadata={"scopes": scopes, "query_evidence": facts},
        ),
        "evidence",
    )


def validate_query_evidence(data: Any, *, minimized: bool = False) -> None:
    if (
        not isinstance(data, dict)
        or set(data)
        != {
            "guid",
            "query_sha256",
            "collected_at",
            "scopes",
            "pages",
            "partial",
            "records",
            "warning",
        }
        or data.get("warning") != WARNING
    ):
        raise InputError("Unexpected normalised query evidence fields")
    entry = selected_query(require(data, "guid", str))
    if data["query_sha256"] != entry["query_sha256"]:
        raise InputError("Saved query evidence hash differs from allowlist")
    hashes({"query": data["query_sha256"]})
    timestamp(require(data, "collected_at", str))
    require(data, "partial", bool)
    pages = require(data, "pages", int)
    if not 0 <= pages <= 100:
        raise InputError("Invalid query page count")
    scopes = require(data, "scopes", list)
    if (
        (not scopes and not minimized)
        or len(scopes) > 100
        or any(
            not isinstance(scope, str)
            or scope_id(scope) != scope
            or "/resourcegroups/" in scope
            or not scope.startswith("/subscriptions/")
            for scope in scopes
        )
    ):
        raise InputError("Query evidence requires exact subscription scopes")
    records = require(data, "records", list)
    if len(records) > 10_000:
        raise InputError("Query evidence record bound exceeded")
    seen = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {
            "resource_id",
            "reported_compliant",
            "conflicted",
        }:
            raise InputError("Unexpected query evidence record fields")
        if minimized:
            if record["resource_id"] is not None:
                raise InputError("Minimised query Signals must withhold identity")
            identity = None
        else:
            identity = canonical_id(require(record, "resource_id", str))
        if identity is not None and (
            identity in seen
            or identity_type(identity) != entry["resource_type"]
            or not any(identity.startswith(scope + "/") for scope in scopes)
        ):
            raise InputError("Duplicate, foreign or wrong-type query evidence identity")
        seen.add(identity)
        require(record, "conflicted", bool)
        if (
            record["reported_compliant"] is not None
            and type(record["reported_compliant"]) is not bool
        ):
            raise InputError("Query observation must be explicit boolean or unknown")


def query_signals(bundle: dict[str, Any], at: str, max_age_hours: float) -> dict[str, Any] | None:
    raw = (bundle.get("metadata") or {}).get("query_evidence")
    if raw is None:
        return None
    validate_query_evidence(raw)
    if bundle["mode"] != "observed" or raw["collected_at"] != bundle["collected_at"]:
        raise InputError("Saved query evidence mode/time differs from its original bundle")
    boundary_scopes = (bundle.get("metadata") or {}).get("scopes")
    if boundary_scopes != raw["scopes"]:
        raise InputError("Saved query subscription binding differs from bundle scopes")
    current = (
        timedelta(minutes=-5)
        <= timestamp(at) - timestamp(raw["collected_at"])
        <= timedelta(hours=max_age_hours)
    )
    result = copy.deepcopy(raw)
    for record in result["records"]:
        record["usable"] = (
            current
            and not raw["partial"]
            and not record["conflicted"]
            and type(record["reported_compliant"]) is bool
        )
    return result
