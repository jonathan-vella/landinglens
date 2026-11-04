"""Bounded evidence guidance; explanations never execute their suggested actions."""

import re
from typing import Any

GUIDANCE = {
    "snapshot": (
        "A required local module snapshot is unavailable.",
        "An explicitly supplied, hash-verified module snapshot and its authorized local path.",
        "Supply a separately prepared and reviewed local snapshot manifest; no fetch is run.",
    ),
    "identity": (
        "A canonical identity or scope binding has not been established.",
        "Explicit scope and full resource identity, or an exact artifact-bound identity map.",
        "Review the identity bindings; names alone cannot establish identity or drift.",
    ),
    "stale": (
        "Evidence is outside the evaluation time's freshness policy.",
        "Evidence with original timestamps within the selected freshness policy.",
        "Supply current evidence, or replay historically without claiming currency.",
    ),
    "visibility": (
        "The relevant inventory or authorization coverage is incomplete.",
        "Complete relevant inventory plus independently established authorization coverage.",
        "Inspect scope and completeness; successful requests alone do not prove coverage.",
    ),
    "denied": (
        "A required read could not obtain the requested evidence.",
        "A successful, separately authorized read for the same explicit scope and operation.",
        "Have the owner review access separately; no login or permission change is run.",
    ),
    "expression": (
        "The bounded interpreter cannot establish this expression or property's exact typed value.",
        "Supported typed values or separately reviewed normalized evidence with provenance.",
        "Inspect the unsupported construct; do not infer defaults or execute IaC to fill the gap.",
    ),
    "limit": (
        "A safety bound prevented complete interpretation or collection.",
        "A smaller explicitly scoped input or complete evidence prepared outside this workflow.",
        "Reduce scope and inspect partial results; omitted items are not established absences.",
    ),
    "review": (
        "This recommendation needs attributable human evidence.",
        "A justified, scoped, content-bound review with supporting evidence and finite validity.",
        "Have a reviewer complete a review template; no passing outcome is prefilled.",
    ),
    "verified": (
        "The recorded result applies only to its stated evidence and method.",
        "The report's linked evidence, applicability and original timestamps.",
        "Review the narrow result; it is not estate-wide certification or operational proof.",
    ),
    "preflight": (
        "An input prerequisite is missing or unsupported.",
        "An existing permitted input, reviewed mapping, or already installed standalone compiler.",
        "Correct prerequisites separately; preflight never installs, compiles, fetches or logs in.",
    ),
}

REASONS = {
    "snapshot": (
        "required module snapshot missing",
        "required module snapshot absent",
        "local module directory missing",
        "missing module",
        "module source unresolved",
        "snapshot_hash_mismatch",
    ),
    "identity": (
        "identity_unresolved",
        "arm_identity_unresolved",
        "nested_deployment_scope_unresolved",
        "identity_or_fact_unresolved",
        "unmatched_observed_resource_is_not_drift",
        "incompatible_control_or_rule",
        "resource_outside_requested_scope",
    ),
    "stale": ("stale_evidence", "stale_at_comparison"),
    "visibility": (
        "incomplete_graph",
        "authorization_coverage_not_attested",
        "plan_declares_incomplete_or_errored",
        "invalid_or_repeated_continuation",
        "duplicate_resource",
        "truncated_without_continuation",
    ),
    "denied": ("transport_unavailable", "resource_configuration_unavailable"),
    "expression": (
        "property_unresolved_or_wrong_type",
        "property_not_supplied",
        "boolean_missing_unresolved_or_invalid",
        "unverified_provider_version",
        "required_parameter",
        "parameter_missing",
        "variable_missing",
        "arm_property_missing",
        "arm_index_unresolved",
        "arm_argument_unresolved",
        "arm_condition_unresolved",
        "arm_condition_unknown",
        "arm_variable_cycle",
        "unsupported_arm_expression",
        "unsupported_arm_node",
        "invalid_arm_accessor",
        "invalid_not",
        "secure_parameter_withheld",
        "keyvault_parameter_not_retrieved",
        "nested_parameter_missing",
        "nested_template_expression_scope_unverified",
        "unavailable_or_conditional_linked_template",
        "nested_child_resources_require_explicit_full_declarations",
        "symbolic or invalid count",
        "symbolic or invalid for_each (map or string set required)",
        "required variable",
        "unresolved attribute/index",
        "unknown/non-boolean condition",
        "unknown or invalid unary operand",
        "unresolved binary operand",
        "unsupported or invalid binary operands",
        "floating-point equality outside verified numeric subset",
        "unverified nested equality",
        "invalid template interpolation",
        "unknown or non-string object key",
        "unknown key",
        "division by zero",
        "signed remainder outside verified numeric subset",
        "nonintegral division outside supported numeric subset",
        "unverified collection membership",
        "count and for_each are mutually exclusive",
        "module has no instance",
        "output has no value",
        "sensitive/ephemeral input withheld by spike",
        "sensitive/ephemeral output withheld by spike",
        "JSON dynamic blocks unsupported in prerequisite spike",
    ),
    "limit": (
        "item_limit",
        "page_limit",
        "resource_limit",
        "arm_resource_limit",
        "arm_deployment_depth_limit",
        "arm_copy_unknown_or_expansion_limit",
        "arm_expression_limit",
        "numeric_size_limit",
        "string_limit",
        "instance expansion limit exceeded",
        "module recursion/depth limit exceeded",
        "reference depth limit exceeded",
        "expression limit exceeded",
        "numeric size limit",
        "collection size limit",
        "nested block depth limit exceeded",
    ),
    "review": ("human_evidence_required",),
    "preflight": (
        "input_unavailable",
        "input_invalid",
        "compiler_unavailable",
        "compiler_probe_failed",
        "scope_required",
        "compiler_not_probed",
        "compilation_not_run",
        "input_path_not_authorized",
    ),
    "verified": (
        "explicit_property_matches",
        "explicit_property_differs",
        "manual_attestation",
        "landing_zone_not_applicable",
        "no_applicable_resources",
        "prerequisite_checked",
        "canonical_identity_and_explicit_fact",
        "known_identity_complete_current_inventory",
    ),
}
REASON_GROUP = {reason: group for group, reasons in REASONS.items() for reason in reasons}
EXPRESSION_PREFIXES = (
    "unsupported_arm_function:",
    "unsupported function:",
    "unsupported expression:",
    "unresolved function argument:",
    "missing attribute:",
    "cyclic reference:",
)


def guidance(reason: str) -> dict[str, Any]:
    group = REASON_GROUP.get(reason)
    if re.fullmatch(r"http_[1-5][0-9]{2}", reason):
        group = "denied"
    if reason.startswith(EXPRESSION_PREFIXES):
        group = "expression"
    if group is None:
        return {
            "supported": False,
            "explanation": "Unsupported explanation: this reason code is not recognized.",
            "required_evidence": "Producer documentation for this exact reason code.",
            "next_action": "Retain the code and inspect its producer; no verdict is inferred.",
        }
    description, evidence, action = GUIDANCE[group]
    return {
        "supported": True,
        "explanation": description,
        "required_evidence": evidence,
        "next_action": action,
    }


def explain(reason: str) -> dict[str, Any]:
    return {"reason": reason, **guidance(reason)}
