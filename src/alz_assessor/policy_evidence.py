"""Bounded original-time policy evidence, never recommendation outcomes."""

import copy
import re
from collections import Counter
from datetime import timedelta
from typing import Any
from uuid import UUID

from .catalog import load_catalog
from .contracts import canonical_id, digest, hashes, identity_type, require, scope_id, timestamp
from .crosswalk import load_crosswalk
from .terraform import InputError

WARNING = (
    "Policy evaluations are Signals, never checklist passes. "
    "Assignment effects and exemptions need review."
)


def reference(value: Any) -> str | None:
    try:
        return canonical_id(value)
    except InputError:
        return None


def sha(value: Any, original: Any) -> str:
    return (
        value
        if isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value)
        else digest(original)
    )


def definition_reference(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    builtin = re.fullmatch(
        r"/providers/microsoft.authorization/(?:policydefinitions|policysetdefinitions)/([0-9a-f-]{36})",
        value.lower(),
    )
    if builtin:
        try:
            return value.lower() if str(UUID(builtin[1])) == builtin[1] else None
        except ValueError:
            return None
    identity = reference(value)
    return (
        identity
        if identity
        and identity_type(identity)
        in {
            "microsoft.authorization/policydefinitions",
            "microsoft.authorization/policysetdefinitions",
        }
        else None
    )


def project_policy_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name in ("policy_assignments", "policy_compliance", "policy_exemptions"):
        if name not in metadata:
            continue
        entries = metadata[name]
        if not isinstance(entries, list):
            result[name] = None
            continue
        if len(entries) > 10_000:
            raise InputError("Policy evidence population exceeds 10,000")
        projected: list[Any] = []
        for entry in entries:
            if not isinstance(entry, dict):
                projected.append(None)
                continue
            if name == "policy_compliance":
                evaluation: Any = entry.get("timestamp")
                try:
                    timestamp(evaluation)
                except InputError:
                    evaluation = None
                projected.append(
                    {
                        "resourceId": reference(entry.get("resourceId")),
                        "policyAssignmentId": reference(entry.get("policyAssignmentId")),
                        "policyDefinitionId": definition_reference(entry.get("policyDefinitionId")),
                        "complianceState": entry.get("complianceState")
                        if entry.get("complianceState") in ("Compliant", "NonCompliant")
                        else "Unknown",
                        "timestamp": evaluation,
                        "member_reference_sha256": sha(
                            entry.get("member_reference_sha256"),
                            entry.get("policyDefinitionReferenceId"),
                        ),
                        "content_sha256": sha(entry.get("content_sha256"), entry),
                    }
                )
            elif name == "policy_assignments":
                exclusions = entry.get("not_scopes")
                projected.append(
                    {
                        "id": reference(entry.get("id")),
                        "definition_id": definition_reference(entry.get("definition_id")),
                        "not_scopes": [reference(item) for item in exclusions]
                        if isinstance(exclusions, list) and len(exclusions) <= 100
                        else None,
                        "conflict": entry.get("conflict") is True,
                        "context_sha256": sha(entry.get("context_sha256"), entry),
                    }
                )
            else:
                expiry: Any = entry.get("expires_on")
                if expiry is not None:
                    try:
                        timestamp(expiry)
                    except InputError:
                        expiry = None
                projected.append(
                    {
                        "id": reference(entry.get("id")),
                        "assignment_id": reference(entry.get("assignment_id")),
                        "expires_on": expiry,
                    }
                )
        result[name] = projected
    if "policy_import" in metadata:
        imported = require(metadata, "policy_import", dict)
        timestamp(require(imported, "collected_at", str))
        result["policy_import"] = {
            "collected_at": imported["collected_at"],
            "content_sha256": sha(imported.get("content_sha256"), imported),
        }
    return result


def within(identity: str, bundle: dict[str, Any]) -> bool:
    scopes = [bundle.get("scope"), *((bundle.get("metadata") or {}).get("scopes") or [])]
    return any(
        isinstance(scope, str)
        and (identity == scope.lower() or identity.startswith(scope.lower() + "/"))
        for scope in scopes
    )


def import_policy_export(bundle: dict[str, Any], export: Any) -> dict[str, Any]:
    if bundle["mode"] != "observed":
        raise InputError("Policy exports are observed evidence; assess planned inputs separately")
    if (
        not isinstance(export, dict)
        or set(export)
        != {
            "schema_version",
            "kind",
            "scope",
            "collected_at",
            "assignments",
            "states",
            "exemptions",
        }
        or export.get("schema_version") != "1.0"
        or export.get("kind") != "policy-export"
    ):
        raise InputError("Expected bounded policy-export contract 1.0")
    boundary = scope_id(require(export, "scope", str))
    if not isinstance(bundle.get("scope"), str) or boundary != bundle["scope"].lower():
        raise InputError("Policy export must match the exact explicit evidence scope")
    timestamp(require(export, "collected_at", str))
    for key in ("assignments", "states", "exemptions"):
        entries = require(export, key, list)
        if len(entries) > 10_000 or any(not isinstance(item, dict) for item in entries):
            raise InputError("Policy exports require object arrays bounded to 10,000")
    result = copy.deepcopy(bundle)
    metadata = result.setdefault("metadata", {})
    if any(
        key in metadata for key in ("policy_assignments", "policy_compliance", "policy_exemptions")
    ):
        raise InputError("Saved policy evidence cannot be silently replaced")
    assignments = []
    for entry in export["assignments"]:
        identity = canonical_id(require(entry, "id", str))
        properties = require(entry, "properties", dict)
        if identity_type(identity) != "microsoft.authorization/policyassignments":
            raise InputError("Policy assignment ID has the wrong resource type")
        assignments.append(
            {
                "id": identity,
                "scope": properties.get("scope"),
                "definition_id": properties.get("policyDefinitionId"),
                "not_scopes": properties.get("notScopes"),
                "enforcement_mode": properties.get("enforcementMode"),
                "context_sha256": digest(properties),
            }
        )
    states = []
    for entry in export["states"]:
        identity = canonical_id(require(entry, "resourceId", str))
        if not within(identity, bundle):
            raise InputError("Policy state resource is outside the explicit supplied scope")
        states.append(
            {
                key: entry.get(key)
                for key in (
                    "resourceId",
                    "policyAssignmentId",
                    "policyDefinitionId",
                    "policyDefinitionReferenceId",
                    "complianceState",
                    "timestamp",
                )
            }
        )
    exemptions = []
    for entry in export["exemptions"]:
        identity = canonical_id(require(entry, "id", str))
        properties = require(entry, "properties", dict)
        if identity_type(identity) != "microsoft.authorization/policyexemptions":
            raise InputError("Policy exemption ID has the wrong resource type")
        expiry = properties.get("expiresOn")
        if expiry is not None:
            timestamp(expiry)
        exemptions.append(
            {
                "id": identity,
                "assignment_id": properties.get("policyAssignmentId"),
                "expires_on": expiry,
            }
        )
    metadata.update(
        policy_assignments=assignments,
        policy_compliance=states,
        policy_exemptions=exemptions,
        policy_import={"collected_at": export["collected_at"], "content_sha256": digest(export)},
    )
    metadata.update(project_policy_metadata(metadata))
    result["artifact_hashes"]["policy-export-content"] = digest(export)
    return result


def policy_signals(
    bundle: dict[str, Any], catalog: dict[str, Any], at: str, max_age_hours: float = 24
) -> dict[str, Any]:
    metadata = project_policy_metadata(bundle.get("metadata") or {})
    gaps: Counter[str] = Counter()
    result: dict[str, Any] = {
        "records": [],
        "gaps": [],
        "crosswalk_sha256": None,
        "warning": WARNING,
    }
    if not any(key in metadata for key in ("policy_assignments", "policy_compliance")):
        return result
    if bundle["mode"] != "observed":
        result["gaps"] = [{"reason": "policy_evidence_not_observed", "count": 1}]
        return result
    if digest(catalog) != digest(load_catalog()):
        result["gaps"] = [{"reason": "policy_crosswalk_catalog_unavailable", "count": 1}]
        return result
    crosswalk = load_crosswalk(catalog)
    result["crosswalk_sha256"] = digest(crosswalk)
    mapped: dict[str, list[tuple[str, str]]] = {}
    controls = {c["control_id"]: c for c in catalog["controls"]}
    for entry in crosswalk["entries"]:
        for target in entry["targets"]:
            if target["kind"] == "azure-policy-definition":
                mapped.setdefault(target["id"].lower(), []).append(
                    (entry["control_id"], target["strength"])
                )
    populations = {}
    for name in ("policy_assignments", "policy_compliance", "policy_exemptions"):
        entries = metadata.get(name)
        if not isinstance(entries, list):
            gaps[name + "_unavailable"] += 1
            entries = []
        if len(entries) > 10_000:
            raise InputError("Policy evidence population exceeds 10,000")
        populations[name] = entries
    assignments: dict[str, dict[str, Any] | None] = {}
    for entry in populations["policy_assignments"]:
        identity = reference(entry.get("id")) if isinstance(entry, dict) else None
        if not identity or identity_type(identity) != "microsoft.authorization/policyassignments":
            gaps["policy_assignment_identity_unresolved"] += 1
            continue
        if entry.get("conflict") or (identity in assignments and assignments[identity] != entry):
            assignments[identity] = None
            gaps["conflicting_policy_assignment"] += 1
        elif identity not in assignments:
            assignments[identity] = entry
    seen: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    conflicted = set()
    for entry in populations["policy_compliance"]:
        if not isinstance(entry, dict):
            gaps["policy_state_invalid"] += 1
            continue
        resource, assignment = (
            reference(entry.get("resourceId")),
            reference(entry.get("policyAssignmentId")),
        )
        definition = entry.get("policyDefinitionId")
        if (
            not resource
            or not assignment
            or not isinstance(definition, str)
            or identity_type(assignment) != "microsoft.authorization/policyassignments"
        ):
            gaps["policy_state_identity_unresolved"] += 1
            continue
        if not within(resource, bundle):
            gaps["policy_state_outside_explicit_scope"] += 1
            continue
        key = (
            resource,
            assignment,
            definition.lower(),
            sha(entry.get("member_reference_sha256"), entry.get("policyDefinitionReferenceId")),
        )
        if key in seen and seen[key] != entry:
            conflicted.add(key)
        seen[key] = entry
    collected = (metadata.get("policy_import") or {}).get("collected_at", bundle["collected_at"])
    timestamp(collected)
    for key, entry in seen.items():
        resource, assignment, definition, member_hash = key
        if definition not in mapped:
            gaps["policy_definition_not_mapped"] += 1
            continue
        context = assignments.get(assignment)
        flags = [
            "effect_and_exemption_interpretation_required",
            "policy_population_not_proven_complete",
        ]
        usable = True
        if key in conflicted:
            flags.append("conflicting_policy_evaluations")
            usable = False
        if context is None:
            flags.append("assignment_context_missing_or_conflicted")
            usable = False
        elif (
            not isinstance(context.get("definition_id"), str)
            or context["definition_id"].lower() != definition
        ):
            flags.append("initiative_or_definition_relationship_unresolved")
            usable = False
        if context:
            excluded = context.get("not_scopes")
            if not isinstance(excluded, list) or any(
                not isinstance(item, str) or reference(item) is None for item in excluded
            ):
                flags.append("assignment_exclusions_unresolved")
                usable = False
            elif any(
                resource == item.lower() or resource.startswith(item.lower() + "/")
                for item in excluded
            ):
                flags.append("resource_excluded_by_assignment")
                usable = False
        evaluation: Any = entry.get("timestamp")
        try:
            evaluated = timestamp(evaluation)
            fresh = (
                timedelta(minutes=-5) <= timestamp(at) - evaluated <= timedelta(hours=max_age_hours)
                and timedelta(minutes=-5)
                <= timestamp(at) - timestamp(collected)
                <= timedelta(hours=max_age_hours)
                and evaluated <= timestamp(collected) + timedelta(minutes=5)
            )
        except InputError:
            fresh, evaluation = False, None
        if not fresh:
            flags.append("policy_evaluation_stale_or_unresolved")
            usable = False
        state = entry.get("complianceState")
        if state not in ("Compliant", "NonCompliant"):
            flags.append("policy_state_not_supported")
            state, usable = "Unknown", False
        for control_id, strength in mapped[definition]:
            rule = controls[control_id].get("rule")
            expected = rule.get("resource_type") if isinstance(rule, dict) else None
            population_matches = (
                isinstance(expected, str) and identity_type(resource) == expected.lower()
            )
            result["records"].append(
                {
                    "control_id": control_id,
                    "resource_id": resource,
                    "assignment_id": assignment,
                    "definition_id": definition,
                    "member_reference_sha256": member_hash,
                    "compliance_state": state,
                    "evaluated_at": evaluation,
                    "collected_at": collected,
                    "usable": usable and population_matches,
                    "mapping_strength": strength,
                    "flags": flags
                    + ([] if population_matches else ["policy_resource_type_unreviewed"]),
                    "source_sha256": sha(entry.get("content_sha256"), entry),
                    "assignment_sha256": sha(context.get("context_sha256"), context)
                    if context
                    else digest(None),
                }
            )
    result["gaps"] = [{"reason": code, "count": count} for code, count in sorted(gaps.items())]
    return result


def refresh_signals(signals: dict[str, Any], at: str, max_age_hours: float) -> dict[str, Any]:
    result = copy.deepcopy(signals)
    for record in result["records"]:
        evaluation = record["evaluated_at"]
        if record["usable"] and (
            evaluation is None
            or not timedelta(minutes=-5)
            <= timestamp(at) - timestamp(evaluation)
            <= timedelta(hours=max_age_hours)
        ):
            record["usable"] = False
            if "policy_evaluation_stale_or_unresolved" not in record["flags"]:
                record["flags"].append("policy_evaluation_stale_or_unresolved")
    return result


def validate_signals(data: Any, *, minimized: bool = False) -> None:
    if not isinstance(data, dict) or set(data) != {
        "records",
        "gaps",
        "crosswalk_sha256",
        "warning",
    }:
        raise InputError("Unexpected policy Signal fields")
    if data["warning"] != WARNING:
        raise InputError("Unexpected policy Signal warning")
    records, gaps = require(data, "records", list), require(data, "gaps", list)
    if len(records) > 10_000 or len(gaps) > 100:
        raise InputError("Policy Signal bound exceeded")
    if data["crosswalk_sha256"] is not None:
        hashes({"crosswalk": data["crosswalk_sha256"]})
    for record in records:
        if not isinstance(record, dict) or set(record) != {
            "control_id",
            "resource_id",
            "assignment_id",
            "definition_id",
            "member_reference_sha256",
            "compliance_state",
            "evaluated_at",
            "collected_at",
            "usable",
            "mapping_strength",
            "flags",
            "source_sha256",
            "assignment_sha256",
        }:
            raise InputError("Unexpected policy Signal record fields")
        require(record, "usable", bool)
        if record["compliance_state"] not in ("Compliant", "NonCompliant", "Unknown"):
            raise InputError("Unsupported policy Signal state")
        if record["mapping_strength"] not in ("equivalent", "partial", "related"):
            raise InputError("Unsupported policy mapping strength")
        for field in ("resource_id", "assignment_id"):
            if record[field] is not None:
                canonical_id(record[field])
            elif not minimized:
                raise InputError("Full policy Signals require canonical identities")
        if (record["definition_id"] is None and not minimized) or definition_reference(
            record["definition_id"]
        ) != record["definition_id"]:
            raise InputError("Invalid policy Signal definition identity")
        if not re.fullmatch(r"ALZ-[0-9a-f-]{36}", require(record, "control_id", str)):
            raise InputError("Invalid policy Signal control identity")
        timestamp(require(record, "collected_at", str))
        if record["evaluated_at"] is not None:
            timestamp(record["evaluated_at"])
        hashes(
            {
                key: record[key]
                for key in ("member_reference_sha256", "source_sha256", "assignment_sha256")
            }
        )
        flags = require(record, "flags", list)
        if any(
            flag
            not in (
                "effect_and_exemption_interpretation_required",
                "policy_population_not_proven_complete",
                "conflicting_policy_evaluations",
                "assignment_context_missing_or_conflicted",
                "initiative_or_definition_relationship_unresolved",
                "assignment_exclusions_unresolved",
                "resource_excluded_by_assignment",
                "policy_evaluation_stale_or_unresolved",
                "policy_state_not_supported",
                "policy_resource_type_unreviewed",
            )
            for flag in flags
        ):
            raise InputError("Unknown policy Signal flag")
    for gap in gaps:
        if not isinstance(gap, dict) or set(gap) != {"reason", "count"}:
            raise InputError("Unexpected policy Signal gap fields")
        if require(gap, "count", int) <= 0 or require(gap, "reason", str) not in (
            "policy_evidence_not_observed",
            "policy_crosswalk_catalog_unavailable",
            "policy_assignments_unavailable",
            "policy_compliance_unavailable",
            "policy_exemptions_unavailable",
            "policy_assignment_identity_unresolved",
            "conflicting_policy_assignment",
            "policy_state_invalid",
            "policy_state_identity_unresolved",
            "policy_state_outside_explicit_scope",
            "policy_definition_not_mapped",
        ):
            raise InputError("Invalid policy Signal gap")
