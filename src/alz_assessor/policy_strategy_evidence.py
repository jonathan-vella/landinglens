"""Bounded Policy configuration, not an Azure Policy interpreter or compliance verdict."""

import re
from typing import Any

from .contracts import canonical_id, digest, identity_type, parse_document, scope_id
from .governance_evidence import MG_KIND, hierarchy_context, resource_in_scope
from .policy_evidence import definition_reference
from .sources import enumeration, property_at, unknown
from .terraform import InputError

DEFINITION = "microsoft.authorization/policydefinitions"
INITIATIVE = "microsoft.authorization/policysetdefinitions"
ASSIGNMENT = "microsoft.authorization/policyassignments"
ROLE = "microsoft.authorization/roleassignments"
KINDS = {DEFINITION, INITIATIVE, ASSIGNMENT}
PATHS = {"policyDefinitionSummary", "policyInitiativeSummary", "policyAssignmentSummary"}
GUIDS = {
    "5c986cb2-9131-456a-8247-6e49f541acdc",
    "d8a2adb1-17d6-4326-af62-5ca44e5695f2",
    "223ace8c-b123-408c-a501-7f154e3ab369",
    "3829e7e3-1618-4368-9a04-77a209945bda",
    "43334f24-9116-4341-a2ba-527526944008",
    "be7d7e48-4327-46d8-adc0-55bcf619e8a1",
    "3f988795-25d6-4268-a6d7-0ba6c97be995",
    "19048384-5c98-46cb-8913-156a12476e49",
}
RPC = "36243c78-bf99-498c-9df9-86d9f8d28608"
EFFECTS = (
    "addToNetworkGroup",
    "append",
    "audit",
    "auditIfNotExists",
    "deny",
    "denyAction",
    "deployIfNotExists",
    "disabled",
    "manual",
    "modify",
    "mutate",
)
WARNING = (
    "Supplied original-time configuration only, not effective Policy evaluation, inheritance, "
    "legal compliance, approved services, appropriate scope, built-in suitability or delegation. "
    "No tenant/intermediate root inferred, numeric root-assignment cap or referenced fetch."
)
TF_SCOPES = {
    "azurerm_management_group_policy_assignment": ("management_group_id", MG_KIND),
    "azurerm_subscription_policy_assignment": (
        "subscription_id",
        "microsoft.resources/subscriptions",
    ),
    "azurerm_resource_group_policy_assignment": (
        "resource_group_id",
        "microsoft.resources/resourcegroups",
    ),
}


def version(value: Any) -> Any:
    return (
        value
        if isinstance(value, str) and re.fullmatch(r"[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}", value)
        else unknown("exact_definition_version_missing_unresolved_or_unsupported")
    )


def count(value: Any, maximum: int) -> Any:
    return (
        len(value)
        if isinstance(value, list)
        and len(value) <= maximum
        and all(isinstance(row, dict) and "unknown" not in row for row in value)
        else unknown("policy_object_array_missing_invalid_or_over_bound")
    )


def definition_id(value: Any) -> Any:
    return definition_reference(value) or unknown("policy_definition_reference_invalid_or_missing")


def exclusions(value: Any) -> Any:
    if not isinstance(value, list) or len(value) > 100:
        return unknown("policy_not_scopes_missing_invalid_or_over_100")
    try:
        entries = [canonical_id(item) for item in value]
    except InputError:
        return unknown("policy_not_scope_invalid")
    if len(set(entries)) != len(entries):
        return unknown("policy_not_scopes_ambiguous")
    return entries


def members(value: Any, *, normalized: bool = False) -> Any:
    if not isinstance(value, list) or not 1 <= len(value) <= 100:
        return unknown("initiative_members_missing_invalid_or_over_100")
    result, seen = [], set()
    for row in value:
        if not isinstance(row, dict) or "unknown" in row:
            return unknown("initiative_member_not_explicit")
        ref = definition_id(row.get("definitionId" if normalized else "policyDefinitionId"))
        member = row.get("referenceSha256" if normalized else "policyDefinitionReferenceId")
        if not isinstance(ref, str) or not isinstance(member, str):
            return unknown("initiative_member_reference_missing_or_invalid")
        if normalized:
            if not re.fullmatch("[0-9a-f]{64}", member):
                return unknown("initiative_member_fingerprint_invalid")
        elif not member.strip() or len(member) > 256:
            return unknown("initiative_member_reference_missing_or_invalid")
        fingerprint = member if normalized else digest(member)
        if fingerprint in seen:
            return unknown("initiative_member_reference_ambiguous")
        seen.add(fingerprint)
        result.append(
            {
                "definitionId": ref,
                "referenceSha256": fingerprint,
                "definitionVersion": version(row.get("definitionVersion")),
            }
        )
    return result


def json_object(value: Any) -> Any:
    if not isinstance(value, str) or len(value.encode("utf-8")) > 100_000:
        return unknown("policy_json_missing_unresolved_or_over_bound")
    try:
        parsed = parse_document(value)
    except InputError:
        return unknown("policy_json_malformed_or_duplicate")
    return parsed if isinstance(parsed, dict) else unknown("policy_json_not_object")


def projected_properties(
    kind: str, values: dict[str, Any], *, terraform: bool = False
) -> dict[str, Any]:
    kind = kind.lower()
    if kind not in KINDS:
        return {}
    if kind == DEFINITION:
        rule = json_object(values.get("policy_rule")) if terraform else values.get("policyRule")
        return {
            "policyDefinitionSummary": {
                "policyType": enumeration(
                    values.get("policy_type" if terraform else "policyType"),
                    ("BuiltIn", "Custom", "Static", "NotSpecified"),
                ),
                "mode": enumeration(
                    values.get("mode"),
                    (
                        "All",
                        "Indexed",
                        "Microsoft.KeyVault.Data",
                        "Microsoft.Kubernetes.Data",
                        "Microsoft.Network.Data",
                    ),
                ),
                "literalEffect": enumeration(property_at(rule, "then.effect"), EFFECTS),
                "version": version(values.get("version") if not terraform else None),
            }
        }
    if kind == INITIATIVE:
        raw = values.get("policyDefinitions")
        if terraform:
            raw = values.get("policy_definition_reference")
            if isinstance(raw, list) and len(raw) <= 100:
                raw = [
                    {
                        "policyDefinitionId": row.get("policy_definition_id"),
                        "policyDefinitionReferenceId": row.get("reference_id"),
                        "definitionVersion": row.get("version"),
                    }
                    if isinstance(row, dict) and "unknown" not in row
                    else None
                    for row in raw
                ]
        return {
            "policyInitiativeSummary": {
                "policyType": enumeration(
                    values.get("policy_type" if terraform else "policyType"),
                    ("BuiltIn", "Custom", "Static", "NotSpecified"),
                ),
                "version": version(values.get("version") if not terraform else None),
                "members": members(raw),
                "groupCount": count(
                    values.get(
                        "policy_definition_group" if terraform else "policyDefinitionGroups"
                    ),
                    100,
                ),
            }
        }
    enforce = values.get("enforce")
    enforcement = (
        (
            ("Default" if enforce else "DoNotEnforce")
            if type(enforce) is bool
            else unknown("policy_enforcement_not_explicit")
        )
        if terraform
        else enumeration(values.get("enforcementMode"), ("Default", "DoNotEnforce"))
    )
    return {
        "policyAssignmentSummary": {
            "definitionId": definition_id(
                values.get("policy_definition_id" if terraform else "policyDefinitionId")
            ),
            "definitionVersion": version(
                values.get("definitionVersion") if not terraform else None
            ),
            "enforcementMode": enforcement,
            "notScopes": exclusions(values.get("not_scopes" if terraform else "notScopes")),
            "selectorCount": count(
                values.get("resource_selectors" if terraform else "resourceSelectors"), 10
            ),
            "overrideCount": count(values.get("overrides"), 10),
        }
    }


def review_fact(properties: dict[str, Any], path: str) -> Any:
    value = properties.get(path)
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("policy_summary_not_explicit")
    if path == "policyAssignmentSummary":
        return {
            "definitionId": definition_id(value.get("definitionId")),
            "definitionVersion": version(value.get("definitionVersion")),
            "enforcementMode": enumeration(
                value.get("enforcementMode"), ("Default", "DoNotEnforce")
            ),
            "notScopes": exclusions(value.get("notScopes")),
            **{
                key: value[key]
                if type(value.get(key)) is int and 0 <= value[key] <= 10
                else unknown("policy_count_missing_invalid_or_over_bound")
                for key in ("selectorCount", "overrideCount")
            },
        }
    result = {
        "policyType": enumeration(
            value.get("policyType"), ("BuiltIn", "Custom", "Static", "NotSpecified")
        ),
        "version": version(value.get("version")),
    }
    if path == "policyDefinitionSummary":
        result.update(
            mode=enumeration(
                value.get("mode"),
                (
                    "All",
                    "Indexed",
                    "Microsoft.KeyVault.Data",
                    "Microsoft.Kubernetes.Data",
                    "Microsoft.Network.Data",
                ),
            ),
            literalEffect=enumeration(value.get("literalEffect"), EFFECTS),
        )
    else:
        result.update(
            members=members(value.get("members"), normalized=True),
            groupCount=value["groupCount"]
            if type(value.get("groupCount")) is int and 0 <= value["groupCount"] <= 100
            else unknown("policy_group_count_missing_invalid_or_over_bound"),
        )
    return result


def replay_properties(kind: str, values: dict[str, Any]) -> dict[str, Any]:
    path = {
        DEFINITION: "policyDefinitionSummary",
        INITIATIVE: "policyInitiativeSummary",
        ASSIGNMENT: "policyAssignmentSummary",
    }.get(kind.lower())
    return {path: review_fact(values, path)} if path and path in values else {}


def location(identity: Any, kind: str) -> str | None:
    try:
        ref = canonical_id(identity)
        if identity_type(ref) != kind:
            return None
        parent, name = ref.rsplit("/providers/" + kind + "/", 1)
        return parent if name and "/" not in name else None
    except (InputError, ValueError):
        return None


def ancestry(parent: str, child: str, bundle: dict[str, Any]) -> Any:
    if child == parent or child.startswith(parent + "/"):
        return True
    if identity_type(parent) != MG_KIND:
        return unknown("policy_scope_ancestry_not_proven")
    hierarchy = hierarchy_context(bundle)
    if "unknown" in hierarchy:
        return unknown("policy_scope_ancestry_not_proven")
    parents = {edge["id"]: edge["parent"] for edge in hierarchy["relationships"]}
    cursor = (
        "/".join(child.split("/")[:3])
        if child.startswith("/subscriptions/")
        else "/".join(child.split("/")[:5])
    )
    visited: set[str] = set()
    while cursor not in visited:
        if cursor == parent:
            return True
        visited.add(cursor)
        if cursor not in parents:
            break
        cursor = parents[cursor]
    return unknown("policy_scope_ancestry_not_proven")


def unique_known(
    resource: dict[str, Any],
    bundle: dict[str, Any],
    by_id: dict[str, list[dict[str, Any]]],
) -> bool:
    identity = resource.get("arm_id")
    kind = resource["resource_type"].lower()
    parent = location(identity, kind)
    return (
        isinstance(identity, str)
        and by_id.get(identity.lower()) == [resource]
        and resource.get("state") == "known"
        and identity_type(identity) == kind
        and (
            kind not in {DEFINITION, INITIATIVE}
            or (
                parent is not None
                and identity_type(parent) in {MG_KIND, "microsoft.resources/subscriptions"}
            )
        )
        and resource_in_scope(resource, bundle)
    )


def joined_definition(
    ref: Any,
    requested: Any,
    target: str,
    bundle: dict[str, Any],
    by_id: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    ref = definition_id(ref)
    if not isinstance(ref, str):
        return unknown("referenced_definition_invalid")
    if ref.startswith("/providers/microsoft.authorization/"):
        return {"definitionId": ref, "unknown": "global_builtin_reference_not_fetched_or_bound"}
    candidates = by_id.get(ref, [])
    if len(candidates) != 1:
        return unknown("referenced_definition_missing_denied_ambiguous_or_out_of_scope")
    row = candidates[0]
    parent = location(ref, row["resource_type"].lower())
    if not parent or identity_type(parent) not in {MG_KIND, "microsoft.resources/subscriptions"}:
        return unknown("definition_location_not_management_group_or_subscription")
    if not unique_known(row, bundle, by_id):
        return unknown("referenced_definition_missing_denied_ambiguous_or_out_of_scope")
    if ancestry(parent, target, bundle) is not True:
        return unknown("definition_assignment_ancestry_not_proven")
    path = (
        "policyDefinitionSummary"
        if row["resource_type"].lower() == DEFINITION
        else "policyInitiativeSummary"
    )
    facts = review_fact(row["properties"], path)
    if not isinstance(facts, dict) or facts.get("policyType") != "Custom":
        return unknown("scoped_definition_not_explicit_custom")
    if not isinstance(requested, str) or not isinstance(facts.get("version"), str):
        return unknown("definition_join_requires_exact_supplied_versions")
    if requested != facts["version"]:
        return unknown("definition_version_mismatch")
    return {
        "definitionId": ref,
        "definitionLocation": parent,
        "facts": facts,
        "ancestry": "positive_supplied_path",
        "warning": WARNING,
    }


def configuration_context(
    resource: dict[str, Any],
    bundle: dict[str, Any],
    by_id: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    if sum(row["resource_type"].lower() in KINDS | {ROLE} for row in bundle["resources"]) > 100:
        return unknown("policy_configuration_population_over_100")
    if not unique_known(resource, bundle, by_id):
        return unknown("policy_resource_not_unique_known_in_selected_scope")
    kind, identity = resource["resource_type"].lower(), resource["arm_id"]
    parent = location(identity, kind)
    if not parent:
        return unknown("policy_resource_location_not_bound")
    result: dict[str, Any] = {"configuredScope": parent, "warning": WARNING}
    if kind == ASSIGNMENT:
        facts = review_fact(resource["properties"], "policyAssignmentSummary")
        result["definition"] = joined_definition(
            facts.get("definitionId"), facts.get("definitionVersion"), parent, bundle, by_id
        )
        excluded = facts.get("notScopes")
        result["exclusions"] = (
            [
                {"scope": item, "withinAssignmentScope": ancestry(parent, item, bundle)}
                for item in excluded
            ]
            if isinstance(excluded, list)
            else unknown("policy_exclusions_not_explicit")
        )
        from .policy_evidence import project_policy_metadata

        metadata = bundle.get("metadata") or {}
        saved = project_policy_metadata(
            {"policy_exemptions": metadata["policy_exemptions"]}
            if "policy_exemptions" in metadata
            else {}
        )
        exemptions = saved.get("policy_exemptions")
        result["savedExemptions"] = (
            [
                {"exemptionId": item["id"], "expires_on": item["expires_on"]}
                for item in exemptions
                if isinstance(item, dict) and item.get("assignment_id") == identity
            ][:100]
            if isinstance(exemptions, list) and len(exemptions) <= 100
            else unknown("saved_policy_exemptions_missing_or_over_100")
        )
        result["exemptionCoverage"] = unknown(
            "saved_references_not_validated_exemption_scope_members_selectors_or_effect"
        )
    elif kind == INITIATIVE:
        rows = review_fact(resource["properties"], "policyInitiativeSummary").get("members")
        result["members"] = (
            [
                joined_definition(
                    row["definitionId"], row["definitionVersion"], parent, bundle, by_id
                )
                for row in rows
            ]
            if isinstance(rows, list)
            else unknown("initiative_members_not_explicit")
        )
    elif kind == ROLE:
        from .identity_evidence import role_reference

        ref = role_reference(resource["properties"].get("roleDefinitionId"))
        result["resourcePolicyContributorReference"] = (
            ref.rsplit("/", 1)[-1] == RPC
            if isinstance(ref, str) and location(ref, "microsoft.authorization/roledefinitions")
            else unknown("scoped_role_definition_reference_not_explicit")
        )
        result["delegation"] = unknown(
            "role_reference_not_principal_membership_pim_conditions_deny_or_effective_authority"
        )
    return result


def tf_resource_id(scope: str | None, kind: str, values: dict[str, Any]) -> str | None:
    from .contracts import derive_id

    if not scope:
        return None
    boundary = scope_id(scope)
    if kind in {"azurerm_policy_definition", "azurerm_policy_set_definition"}:
        if kind == "azurerm_policy_set_definition" and "management_group_id" in values:
            return None
        target = values.get("management_group_id") if kind == "azurerm_policy_definition" else None
        if target is None:
            target = (
                "/".join(boundary.split("/")[:3])
                if boundary.startswith("/subscriptions/")
                else None
            )
        arm_type = DEFINITION if kind == "azurerm_policy_definition" else INITIATIVE
        expected = {MG_KIND, "microsoft.resources/subscriptions"}
    else:
        key, expected_kind = TF_SCOPES[kind]
        target, expected, arm_type = values.get(key), {expected_kind}, ASSIGNMENT
    if not isinstance(target, str):
        return None
    try:
        target = scope_id(target)
    except InputError:
        return None
    if identity_type(target) not in expected or not (
        target == boundary or target.startswith(boundary + "/")
    ):
        return None
    return derive_id(
        target, "Microsoft.Authorization/" + arm_type.rsplit("/", 1)[-1], values.get("name")
    )


def population_context(
    bundle: dict[str, Any], by_id: dict[str, list[dict[str, Any]]]
) -> dict[str, Any]:
    assignments = [row for row in bundle["resources"] if row["resource_type"].lower() == ASSIGNMENT]
    if len(assignments) > 100:
        return unknown("policy_assignment_population_over_100")
    scopes: dict[str, dict[str, Any]] = {}
    unresolved = 0
    for row in assignments:
        parent = location(row.get("arm_id"), ASSIGNMENT)
        if not parent or not unique_known(row, bundle, by_id):
            unresolved += 1
            continue
        summary = scopes.setdefault(
            parent, {"scope": parent, "assignmentCount": 0, "explicitExcludedScopeCount": 0}
        )
        summary["assignmentCount"] += 1
        excluded = review_fact(row["properties"], "policyAssignmentSummary").get("notScopes")
        previous = summary["explicitExcludedScopeCount"]
        summary["explicitExcludedScopeCount"] = (
            previous + len(excluded)
            if type(previous) is int and isinstance(excluded, list)
            else unknown("some_assignment_exclusions_not_explicit")
        )
    return {
        "suppliedAssignmentCount": len(assignments),
        "unresolvedAssignmentCount": unresolved,
        "byConfiguredScope": [scopes[key] for key in sorted(scopes)],
        "coverage": unknown(
            "supplied_subset_not_complete_tenant_root_or_effective_assignment_inventory"
        ),
        "warning": WARNING,
    }
