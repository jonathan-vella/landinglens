"""One advisory evaluator for all normalized source modes."""

from __future__ import annotations

from datetime import timedelta
from math import isfinite
from typing import Any

from .contracts import control_digest, digest, document, now, timestamp, validate
from .sources import property_at
from .terraform import InputError


def coverage(results: list[dict[str, Any]], complete: bool) -> dict[str, Any]:
    counts: dict[str, dict[str, int]] = {mode: {} for mode in ("planned", "observed")}
    for mode in counts:
        for result in results:
            if result.get(mode):
                outcome = result[mode]["outcome"]
                counts[mode][outcome] = counts[mode].get(outcome, 0) + 1
    metrics = {}
    for mode, totals in counts.items():
        assessed = totals.get("pass", 0) + totals.get("fail", 0)
        denominator = sum(v for k, v in totals.items() if k != "not_applicable")
        metrics[mode] = {
            "outcomes": totals,
            "assessed": assessed,
            "known_applicable": denominator,
            "subset_pass_rate": totals.get("pass", 0) / assessed if assessed else None,
            "completion": assessed / denominator if denominator else None,
        }
    return {
        "controls": len({row["control_id"] for row in results}),
        "result_instances": len(results),
        "resource_instances": len(
            {
                row.get("arm_id") or row["logical_id"]
                for row in results
                if row["logical_id"] != "scope"
            }
        ),
        "inventory_complete": complete,
        "modes": metrics,
        "warning": "Subset metrics are not estate-wide compliance.",
    }


def assess(
    bundle: dict[str, Any],
    catalog: dict[str, Any],
    *,
    landing_zone: str = "platform",
    at: str | None = None,
    max_age_hours: float = 24,
    manual: dict[str, Any] | None = None,
    exceptions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    validate(bundle, "evidence")
    validate(catalog, "catalog")
    if max_age_hours <= 0 or not isfinite(max_age_hours) or max_age_hours > 876_000:
        raise InputError("Evidence freshness limit must be positive and finite")
    if landing_zone not in {"platform", "application"}:
        raise InputError("Select platform or application landing-zone scope")
    instant = timestamp(at or now())
    stale = instant - timestamp(bundle["collected_at"]) > timedelta(
        hours=max_age_hours
    ) or timestamp(bundle["collected_at"]) > instant + timedelta(minutes=5)
    for supplied, kind in ((manual, "manual"), (exceptions, "exceptions")):
        if supplied is not None:
            validate(supplied, kind)
            known_controls = {control["control_id"] for control in catalog["controls"]}
            if any(entry["control_id"] not in known_controls for entry in supplied["entries"]):
                raise InputError("Manual/exception entry references an unknown catalog control")
    results = []
    retired = []
    for control in catalog["controls"]:
        if control["lifecycle"] == "retired":
            retired.append(
                {
                    key: control.get(key)
                    for key in (
                        "control_id",
                        "upstream_id",
                        "recommendation",
                        "retired_at",
                        "retirement_reason",
                        "superseded_by",
                    )
                }
            )
            continue
        rule = control.get("rule")
        targets = [
            resource
            for resource in bundle["resources"]
            if rule and resource["resource_type"].lower() == rule["resource_type"].lower()
        ] or [None]
        for resource in targets:
            reason, fact, links = "human_evidence_required", None, []
            outcome = "manual"
            if landing_zone not in control["applicability"]:
                outcome, reason = "not_applicable", "landing_zone_not_applicable"
            elif rule:
                if resource is None:
                    outcome = "not_applicable" if bundle["inventory_complete"] else "unknown"
                    reason = (
                        "no_applicable_resources"
                        if outcome == "not_applicable"
                        else "incomplete_graph"
                    )
                elif stale:
                    outcome, reason = "unknown", "stale_evidence"
                elif resource["state"] != "known":
                    outcome = "error" if resource["state"] == "error" else "unknown"
                    reason = resource["reason"]
                else:
                    fact = property_at(resource["properties"], rule["property"])
                    enum = rule.get("operation") == "enum-equals"
                    sku = property_at(resource["properties"], "sku.tier") if enum else None
                    if enum and (
                        not isinstance(sku, str)
                        or sku
                        not in {
                            "Basic",
                            "Standard",
                            "Premium",
                        }
                    ):
                        outcome, reason, fact = "unknown", "sku_unresolved_or_wrong_type", None
                    elif enum and sku not in rule["applicable_skus"]:
                        outcome, reason, fact = (
                            "not_applicable",
                            "explicit_sku_capability_not_applicable",
                            None,
                        )
                    elif (enum and isinstance(fact, str) and fact in {"Alert", "Deny", "Off"}) or (
                        not enum and type(fact) is bool
                    ):
                        outcome = "pass" if fact == rule["expected"] else "fail"
                        reason = (
                            "explicit_property_matches"
                            if outcome == "pass"
                            else "explicit_property_differs"
                        )
                    else:
                        outcome, reason, fact = "unknown", "property_unresolved_or_wrong_type", None
                    links = [resource["source_location"] + "#" + rule["property"]]
                    if enum:
                        links.append(resource["source_location"] + "#sku.tier")
            disposition = None
            validity: dict[str, str | None] = {"manual": None, "exceptions": None}
            reviews = []
            for record_set, manual_set in ((manual, True), (exceptions, False)):
                if record_set is None:
                    continue
                for entry in record_set["entries"]:
                    if entry["control_id"] == control["control_id"]:
                        scope_matches = bool(
                            bundle.get("scope")
                            and entry["scope"].lower() == bundle["scope"].lower()
                        )
                        active = (
                            timestamp(entry["valid_from"])
                            <= instant
                            < timestamp(entry["valid_until"])
                        )
                        bound = record_set["schema_version"] == "1.1" and entry[
                            "control_sha256"
                        ] == control_digest(control)
                        legacy = record_set["schema_version"] == "1.0"
                        applicable_review = scope_matches and (
                            bound or (legacy and catalog["schema_version"] == "1.0")
                        )
                        reviews.append(
                            {
                                "kind": "manual" if manual_set else "exceptions",
                                "binding": "scope_mismatch"
                                if not scope_matches
                                else "bound"
                                if bound
                                else "legacy_unbound"
                                if legacy
                                else "changed_control",
                                "reviewer": entry.get("reviewer") if bound else None,
                                "requires_review": not bound or not active or not scope_matches,
                            }
                        )
                        validity["manual" if manual_set else "exceptions"] = (
                            "active" if active else "expired_or_not_yet_valid"
                        )
                        if (
                            manual_set
                            and not rule
                            and not stale
                            and active
                            and applicable_review
                            and landing_zone in control["applicability"]
                        ):
                            outcome, reason = entry["outcome"], "manual_attestation"
                            links = [entry["evidence"]]
                        elif not manual_set and applicable_review:
                            disposition = entry["disposition"]
            body = {
                "outcome": outcome,
                "reason": reason,
                "fact": fact,
                "evidence_links": links,
                "freshness": "stale" if stale else "current",
                "inventory_complete": bundle["inventory_complete"],
                "exception_disposition": disposition,
                "disposition_validity": validity,
                "reviews": reviews,
                "method": control["method"],
                "confidence": "explicit-configuration-only"
                if rule and outcome in {"pass", "fail"}
                else "human-attestation"
                if reason == "manual_attestation"
                else "insufficient-evidence",
            }
            results.append(
                {
                    "control_id": control["control_id"],
                    "upstream_id": control["upstream_id"],
                    "design_area": control["design_area"],
                    "recommendation": control["recommendation"],
                    "applicability": control["applicability"],
                    "automation": control["automation"],
                    "references": control["references"],
                    "flags": control["flags"],
                    "evidence_requirements": control["evidence_requirements"],
                    "rationale": control["rationale"],
                    "control_sha256": control_digest(control),
                    "rule_sha256": digest(rule),
                    "logical_id": resource["logical_id"] if resource else "scope",
                    "arm_id": resource.get("arm_id") if resource else None,
                    "planned": body if bundle["mode"] == "planned" else None,
                    "observed": body if bundle["mode"] == "observed" else None,
                    "comparison": None,
                }
            )
    return validate(
        document(
            "assessment",
            schema_version=catalog["schema_version"],
            catalog_version=catalog["catalog_version"],
            generated_at=instant.isoformat(),
            results=results,
            retired_controls=retired,
            evidence=[bundle],
            coverage={
                **coverage(results, bundle["inventory_complete"]),
                "retired_controls": len(retired),
                "automated_controls": sum(
                    c["automation"] == "automated" and c["lifecycle"] == "active"
                    for c in catalog["controls"]
                ),
            },
            source_versions={
                "catalog": catalog["catalog_version"],
                "contracts": catalog["schema_version"],
            },
            freshness_policy_hours=max_age_hours,
        )
    )
