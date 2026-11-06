"""Prepare local review records without asserting outcomes or reviewer identity."""

from typing import Any

from .contracts import control_digest, document, now, scope_id, timestamp, validate
from .diagnostics import guidance
from .engine import local_subchecks
from .network_evidence import REVIEW_PATHS, review_fact
from .sources import boolean, enumeration, property_at
from .terraform import InputError


def prepared_resource(
    resource: dict[str, Any],
    control: dict[str, Any],
    by_id: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    facts: dict[str, Any] = {}
    for path in control.get("review_fact_paths", []):
        if resource["state"] != "known":
            facts[path] = {"unknown": "resource_not_known"}
        elif path in REVIEW_PATHS:
            facts[path] = review_fact(resource["properties"], path)
        elif path == "enableRbacAuthorization":
            facts[path] = boolean(property_at(resource["properties"], path))
        else:
            facts[path] = enumeration(
                property_at(resource["properties"], path),
                {
                    "publicNetworkAccess": ("Enabled", "Disabled"),
                    "networkAcls.defaultAction": ("Allow", "Deny"),
                    "minimumTlsVersion": ("TLS1_0", "TLS1_1", "TLS1_2"),
                }[path],
            )
    prepared: dict[str, Any] = {
        **{key: resource.get(key) for key in ("logical_id", "arm_id", "resource_type", "state")},
        "facts": facts,
        "subchecks": local_subchecks(facts),
    }
    if "networkSecurityGroup.id" in facts:
        identity = facts["networkSecurityGroup.id"]
        candidates = by_id.get(identity, []) if isinstance(identity, str) else []
        linked: dict[str, Any] = {
            "arm_id": identity if isinstance(identity, str) else None,
            "unknown": "referenced_nsg_not_unique_known",
        }
        if (
            len(candidates) == 1
            and candidates[0]["resource_type"].lower() == "microsoft.network/networksecuritygroups"
            and candidates[0]["state"] == "known"
        ):
            linked = {
                "arm_id": identity,
                "securityRuleCount": review_fact(candidates[0]["properties"], "securityRuleCount"),
                "securityRuleSummary": review_fact(
                    candidates[0]["properties"], "securityRuleSummary"
                ),
                "defaultRuleSummary": review_fact(
                    candidates[0]["properties"], "defaultRuleSummary"
                ),
                "inboundRuleSummary": review_fact(
                    candidates[0]["properties"], "inboundRuleSummary"
                ),
            }
        prepared["linked_network_security_group"] = linked
    refs = facts.get("subnetReferences")
    if refs is None and "subnet.id" in facts:
        refs = [facts["subnet.id"]]
    if isinstance(refs, list):
        links: list[dict[str, Any]] = []
        for identity in refs[:20]:
            candidates = by_id.get(identity, []) if isinstance(identity, str) else []
            if (
                len(candidates) != 1
                or candidates[0]["resource_type"].lower()
                != ("microsoft.network/virtualnetworks/subnets")
                or candidates[0]["state"] != "known"
            ):
                links.append(
                    {
                        "arm_id": identity if isinstance(identity, str) else None,
                        "unknown": "referenced_subnet_not_unique_known",
                    }
                )
                continue
            child = candidates[0]
            prefixes = review_fact(child["properties"], "addressPrefixes")
            parent_id = identity.rsplit("/subnets/", 1)[0]
            parents = by_id.get(parent_id, [])
            parent: dict[str, Any] = {
                "arm_id": parent_id,
                "unknown": "referenced_vnet_not_unique_known",
            }
            if (
                len(parents) == 1
                and parents[0]["resource_type"].lower() == "microsoft.network/virtualnetworks"
                and parents[0]["state"] == "known"
            ):
                parent = {
                    "arm_id": parent_id,
                    "enableDdosProtection": review_fact(
                        parents[0]["properties"], "enableDdosProtection"
                    ),
                    "ddosProtectionPlan.id": review_fact(
                        parents[0]["properties"], "ddosProtectionPlan.id"
                    ),
                }
            links.append(
                {
                    "arm_id": identity,
                    "addressPrefixes": prefixes,
                    "subchecks": local_subchecks({"addressPrefixes": prefixes}),
                    "routeTable.id": review_fact(child["properties"], "routeTable.id"),
                    "networkSecurityGroup.id": review_fact(
                        child["properties"], "networkSecurityGroup.id"
                    ),
                    "virtualNetwork": parent,
                }
            )
        prepared["linked_subnets"] = links
        prepared["links_truncated"] = len(refs) > 20
    return prepared


def review_context(control: dict[str, Any], bundle: dict[str, Any]) -> dict[str, Any]:
    available = "resources" in bundle
    if available:
        validate(bundle, "evidence")
    kinds = control.get("review_resource_types", [])
    if control.get("rule"):
        kinds = [control["rule"]["resource_type"]]
    allowed = {kind.lower() for kind in kinds}
    by_id: dict[str, list[dict[str, Any]]] = {}
    for resource in bundle.get("resources", []):
        if resource.get("arm_id"):
            by_id.setdefault(resource["arm_id"].lower(), []).append(resource)
    matches = [
        resource
        for resource in bundle.get("resources", [])
        if resource["resource_type"].lower() in allowed
    ]
    context = {
        "mode": bundle["mode"],
        "collected_at": bundle["collected_at"],
        "inventory_complete": bundle["inventory_complete"],
        "normalized_resources_available": available,
        "resources": [prepared_resource(resource, control, by_id) for resource in matches[:100]],
        "matching_resources": len(matches) if available else None,
        "truncated": len(matches) > 100,
        "warning": (
            "Informational original-time inventory/subchecks only; positive references are not "
            "complete relationships. No whole-recommendation outcome or current freshness inferred."
        ),
    }
    if control["upstream_guid"] == "3c5a808d-c695-4c14-a63c-c7ab7a510e41" and available:
        from .policy_evidence import project_policy_metadata

        metadata = project_policy_metadata(bundle.get("metadata") or {})
        definition = (
            "/providers/microsoft.authorization/policydefinitions/"
            "83a86a26-fd1f-447c-b59d-e51f44264114"
        )
        assignments = metadata.get("policy_assignments")
        selected = (
            [
                entry
                for entry in assignments
                if isinstance(entry, dict)
                and entry.get("definition_id") == definition
                and isinstance(entry.get("id"), str)
            ]
            if isinstance(assignments, list)
            else []
        )
        exemptions = metadata.get("policy_exemptions")
        ids = {entry["id"] for entry in selected}
        context["saved_nic_policy_context"] = {
            "assignments": selected[:100],
            "exemptions": [
                entry
                for entry in exemptions
                if isinstance(entry, dict)
                and isinstance(entry.get("id"), str)
                and entry.get("assignment_id") in ids
            ][:100]
            if isinstance(exemptions, list)
            else None,
            "assignments_available": isinstance(assignments, list),
            "exemptions_available": isinstance(exemptions, list),
            "truncated": len(selected) > 100,
            "warning": "Original-time minimized references only; actual version, effect, "
            "enforcement, inherited scope, selectors/overrides and approved exceptions need "
            "separate evidence. Empty/unavailable is not enforcement or absence.",
        }
    return context


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
                **(
                    {"query_signals": assessment["query_signals"]}
                    if "query_signals" in assessment
                    and "ALZ-" + assessment["query_signals"]["guid"] == control["control_id"]
                    else {}
                ),
                **(
                    {
                        "scanner_signals": [
                            record
                            for run in (
                                [assessment["scanner_signals"]]
                                if "scanner_signals" in assessment
                                else assessment.get("scanner_signal_runs", [])
                            )
                            for record in run["records"]
                            if record["control_id"] == control["control_id"]
                        ]
                    }
                    if "scanner_signals" in assessment or "scanner_signal_runs" in assessment
                    else {}
                ),
                **(
                    {
                        "policy_signals": [
                            item
                            for item in assessment["policy_signals"]["records"]
                            if item["control_id"] == control["control_id"]
                        ]
                    }
                    if "policy_signals" in assessment
                    else {}
                ),
                **(
                    {
                        "evidence_tier": next(
                            item["tier"]
                            for item in assessment["evidence_tiers"]["controls"]
                            if item["control_id"] == control["control_id"]
                        )
                    }
                    if assessment["schema_version"] == "1.2"
                    else {}
                ),
                "available_evidence": [
                    review_context(control, bundle) for bundle in assessment["evidence"]
                ],
                "evidence_requirements": control["evidence_requirements"],
                "limitations": control["rationale"],
                "references": control["references"],
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
