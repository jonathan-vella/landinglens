"""Prepare local review records without asserting outcomes or reviewer identity."""

from typing import Any

from .contracts import control_digest, document, now, scope_id, timestamp, validate
from .diagnostics import guidance
from .terraform import InputError


def prepare_reviews(
    assessment: dict[str, Any],
    catalog: dict[str, Any],
    selected: list[str],
    scope: str,
    kind: str = "manual",
) -> dict[str, Any]:
    validate(assessment, "assessment")
    validate(catalog, "catalog")
    scope = scope_id(scope)
    if kind not in {"manual", "exceptions"} or not selected:
        raise InputError("Select manual/exceptions and at least one explicit control")
    if assessment.get("presentation_only"):
        raise InputError("Presentation-only reports cannot prepare identity-bound reviews")
    if assessment["catalog_version"] != catalog["catalog_version"]:
        raise InputError("Review preparation requires the assessment's exact catalog version")
    if not any(scope == (e.get("scope") or "").lower() for e in assessment["evidence"]):
        raise InputError("Review scope must match an explicit assessment evidence scope")
    entries = {}
    for selection in selected:
        controls = [
            c
            for c in catalog["controls"]
            if selection in {c["control_id"], c["upstream_id"]} and c["lifecycle"] == "active"
        ]
        if len(controls) != 1:
            raise InputError(
                "Control selection is missing or ambiguous; use its canonical control ID"
            )
        control = controls[0]
        binding = control_digest(control)
        rows = [r for r in assessment["results"] if r["control_id"] == control["control_id"]]
        if not rows or any(r.get("control_sha256") != binding for r in rows):
            raise InputError("Assessment control binding is unavailable or changed; reassess first")
        unresolved = [
            r[mode]
            for r in rows
            for mode in ("planned", "observed")
            if r.get(mode) and r[mode]["outcome"] in {"manual", "unknown", "error", "fail"}
        ]
        if not unresolved:
            raise InputError("Select an explicitly unresolved or failed control")
        entries[control["control_id"]] = {
            "control_id": control["control_id"],
            "control_sha256": binding,
            "scope": scope,
            "reviewer": None,
            "evidence": None,
            "rationale": None,
            "valid_from": None,
            "valid_until": None,
            "outcome" if kind == "manual" else "disposition": None,
            "preparation": {
                "reasons": sorted({r["reason"] for r in unresolved}),
                "guidance": [
                    guidance(reason) for reason in sorted({r["reason"] for r in unresolved})
                ],
            },
        }
    return document(
        kind,
        schema_version="1.1",
        is_template=True,
        entries=[entries[key] for key in sorted(entries)],
        warning="Unasserted: complete required fields and remove is_template before import.",
    )


def validate_reviews(
    reviews: dict[str, Any],
    catalog: dict[str, Any],
    scope: str,
    at: str | None = None,
) -> dict[str, Any]:
    validate(reviews)
    if reviews["kind"] not in {"manual", "exceptions"}:
        raise InputError("Expected completed manual or exception records")
    validate(catalog, "catalog")
    scope = scope_id(scope)
    instant = timestamp(at or now())
    controls = {c["control_id"]: c for c in catalog["controls"]}
    records = []
    for entry in reviews["entries"]:
        control = controls.get(entry["control_id"])
        if control is None or scope_id(entry["scope"]) != scope:
            raise InputError("Review references an unknown control or a different explicit scope")
        binding = (
            "legacy_unbound"
            if reviews["schema_version"] == "1.0"
            else "bound"
            if entry["control_sha256"] == control_digest(control)
            else "changed_control"
        )
        active = timestamp(entry["valid_from"]) <= instant < timestamp(entry["valid_until"])
        records.append(
            {
                "control_id": entry["control_id"],
                "binding": binding,
                "active": active,
                "reviewer": entry.get("reviewer") if binding == "bound" else None,
                "requires_review": binding != "bound"
                or not active
                or control["lifecycle"] != "active",
            }
        )
    return {
        "schema_version": "1.1",
        "kind": "review-validation",
        "records": records,
        "ready_to_apply": bool(records) and all(not r["requires_review"] for r in records),
        "warning": "Reviewer attribution is producer-supplied, not authenticated identity proof.",
    }
