"""Compare established identities and facts, never names or incomplete absence."""

from datetime import timedelta
from typing import Any

from .contracts import canonical_id, document, now, timestamp, validate
from .engine import coverage
from .terraform import InputError


def compare(
    planned: dict[str, Any], observed: dict[str, Any], at: str | None = None
) -> dict[str, Any]:
    validate(planned, "assessment")
    validate(observed, "assessment")
    if planned.get("presentation_only") or observed.get("presentation_only"):
        raise InputError("Minimized presentations cannot be used for identity comparison")
    if planned["catalog_version"] != observed["catalog_version"]:
        raise InputError("Comparison requires the same reviewed catalog version")
    if planned["schema_version"] != observed["schema_version"]:
        raise InputError("Comparison requires matching contract versions")
    if not all(row.get("planned") is not None for row in planned["results"]):
        raise InputError("First assessment must contain planned results")
    if not all(row.get("observed") is not None for row in observed["results"]):
        raise InputError("Second assessment must contain observed results")
    instant = timestamp(at or now())

    def current(assessment: dict[str, Any]) -> bool:
        return all(
            timedelta(minutes=-5)
            <= instant - timestamp(bundle["collected_at"])
            <= timedelta(hours=assessment.get("freshness_policy_hours", 24))
            for bundle in assessment["evidence"]
        )

    planned_current, observed_current = current(planned), current(observed)

    def refreshed(row: dict[str, Any], mode: str, fresh: bool) -> dict[str, Any]:
        if fresh:
            return {**row}
        return {
            **row,
            mode: {
                **row[mode],
                "outcome": "unknown",
                "freshness": "stale",
                "fact": None,
                "reason": "stale_at_comparison",
            },
        }

    planned_rows = [refreshed(row, "planned", planned_current) for row in planned["results"]]
    observed_rows = [refreshed(row, "observed", observed_current) for row in observed["results"]]
    index: dict[tuple[str, str | None], dict[str, Any]] = {
        (row["control_id"], canonical_id(row["arm_id"])): row
        for row in observed_rows
        if row.get("arm_id")
    }
    scope_rows = {row["control_id"]: row for row in observed_rows if row["logical_id"] == "scope"}
    used = set()
    rows = []

    def same_meaning(left: dict[str, Any], right: dict[str, Any]) -> bool:
        return all(left.get(key) == right.get(key) for key in ("control_sha256", "rule_sha256"))

    for row in planned_rows:
        identity = canonical_id(row["arm_id"]) if row.get("arm_id") else None
        key = (row["control_id"], identity)
        other = (
            index.get(key)
            if identity
            else scope_rows.get(row["control_id"])
            if row["logical_id"] == "scope"
            else None
        )
        result = {
            **row,
            "comparison": "not_comparable",
            "comparison_reason": "identity_or_fact_unresolved",
        }
        if other:
            used.add(id(other))
            result["observed"] = other["observed"]
            if not same_meaning(row, other):
                result["comparison_reason"] = "incompatible_control_or_rule"
            if (
                identity
                and same_meaning(row, other)
                and row["planned"]["outcome"] in {"pass", "fail"}
                and other["observed"]["outcome"] in {"pass", "fail"}
                and type(row["planned"].get("fact")) is bool
                and type(other["observed"].get("fact")) is bool
            ):
                result["comparison"] = (
                    "match" if row["planned"]["fact"] == other["observed"]["fact"] else "drift"
                )
                result["comparison_reason"] = "canonical_identity_and_explicit_fact"
        elif identity:
            for bundle in observed["evidence"]:
                scope = bundle.get("scope")
                if (
                    bundle["mode"] == "observed"
                    and bundle["inventory_complete"]
                    and observed_current
                    and planned_current
                    and any(
                        item["control_id"] == row["control_id"] and same_meaning(row, item)
                        for item in observed_rows
                    )
                    and (
                        (scope and identity.startswith(scope.lower() + "/"))
                        or any(
                            identity.startswith(item.lower() + "/")
                            for item in (bundle.get("metadata") or {}).get("scopes", [])
                        )
                    )
                    and all(
                        item["arm_id"] or item["logical_id"] == "scope"
                        for item in observed_rows
                        if item["control_id"] == row["control_id"]
                    )
                    and all(
                        item["observed"]["freshness"] == "current"
                        for item in observed["results"]
                        if item.get("observed")
                    )
                ):
                    result["comparison"] = "absent"
                    result["comparison_reason"] = "known_identity_complete_current_inventory"
        rows.append(result)
    for row in observed_rows:
        if id(row) not in used:
            rows.append(
                {
                    **row,
                    "comparison": "not_comparable",
                    "comparison_reason": "unmatched_observed_resource_is_not_drift",
                }
            )
    complete = (
        planned["coverage"]["inventory_complete"] and observed["coverage"]["inventory_complete"]
    )
    return validate(
        document(
            "assessment",
            schema_version=planned["schema_version"],
            catalog_version=planned["catalog_version"],
            generated_at=instant.isoformat(),
            results=rows,
            evidence=planned["evidence"] + observed["evidence"],
            retired_controls=planned.get("retired_controls", []),
            coverage={
                **coverage(rows, complete),
                "retired_controls": len(planned.get("retired_controls", [])),
                "automated_controls": len(
                    {row["control_id"] for row in rows if row.get("automation") == "automated"}
                ),
            },
        )
    )
