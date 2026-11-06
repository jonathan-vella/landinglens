"""Scoped resource configuration, not tenant strategy, delegated authority or billing proof."""

import re
from typing import Any, TypeGuard

from .contracts import canonical_id, scope_id
from .governance_evidence import resource_in_scope
from .sources import enumeration, unknown
from .terraform import InputError

DEFINITION = "microsoft.managedservices/registrationdefinitions"
ASSIGNMENT = "microsoft.managedservices/registrationassignments"
VIEW = "microsoft.costmanagement/views"
PATHS = {"lighthouseAuthorizationSummary", "registrationDefinitionId", "costViewSummary"}
GUIDS = {
    "70c15989-c726-42c7-b0d3-24b7375b9201",
    "6309957b-821a-43d1-b9d9-7fcf1802b747",
    "78e11934-499a-45ed-8ef7-aae5578f0ecf",
    "5d82e6df-6f61-42f2-82e2-3132d293be3d",
    "a24d0de3-d4b9-4dfb-8ddd-bbfaf123fa01",
    "32952499-58c8-4e6f-ada5-972e67893d55",
    "685cb4f2-ac9c-4b19-9167-993ed0b32415",
    "12cd499f-96e2-4e41-a243-231fb3245a1c",
}
UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", re.I)
WARNING = (
    "Supplied scoped configuration only. Authorization counts count syntactically valid "
    "principal/role pairs, not supported roles, distinct people, tenant inventory, effective "
    "access, same-identity use, partner status, automation adoption or business suitability."
)


def uuid_literal(value: Any) -> TypeGuard[str]:
    return isinstance(value, str) and UUID.fullmatch(value) is not None


def resource_parent(identity: Any, kind: str) -> str | None:
    if not isinstance(identity, str):
        return None
    try:
        identity = canonical_id(identity)
        parent, name = identity.rsplit("/providers/" + kind + "/", 1)
        if "/" in name or not name or (kind != VIEW and not uuid_literal(name)):
            return None
        parent = scope_id(parent)
        if not parent.startswith("/subscriptions/") or (
            kind == DEFINITION and parent.count("/") != 2
        ):
            return None
        return parent
    except (InputError, ValueError):
        return None


def definition_reference(value: Any) -> Any:
    return (
        canonical_id(value)
        if resource_parent(value, DEFINITION) is not None
        else unknown("subscription_registration_definition_reference_required")
    )


def authorization_count(value: Any, *, terraform: bool, required: bool) -> Any:
    if not isinstance(value, list) or not (1 if required else 0) <= len(value) <= 100:
        return unknown("authorization_list_missing_malformed_or_over_100")
    pairs = set()
    for row in value:
        if not isinstance(row, dict) or "unknown" in row:
            return unknown("authorization_pair_not_explicit")
        principal = row.get("principal_id" if terraform else "principalId")
        role = row.get("role_definition_id" if terraform else "roleDefinitionId")
        if not uuid_literal(principal) or not uuid_literal(role):
            return unknown("authorization_pair_not_literal_uuids")
        pair = (principal.lower(), role.lower())
        if pair in pairs:
            return unknown("authorization_pair_ambiguous")
        pairs.add(pair)
    return len(pairs)


def authorization_fact(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("authorization_summary_not_explicit")
    result = {}
    for key, minimum in (("authorizationPairCount", 1), ("eligiblePairCount", 0)):
        count = value.get(key)
        result[key] = (
            count
            if type(count) is int and minimum <= count <= 100
            else unknown("authorization_count_missing_malformed_or_over_100")
        )
    return result


def cost_scope(value: Any) -> Any:
    if isinstance(value, str):
        try:
            result = scope_id(value if value.startswith("/") else "/" + value)
            if result.startswith("/subscriptions/"):
                return result
        except InputError:
            pass
    return unknown("cost_view_subscription_or_resource_group_scope_required")


def view_fact(value: Any) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("cost_view_summary_not_explicit")
    return {
        "scope": cost_scope(value.get("scope")),
        "chart": enumeration(
            value.get("chart"), ("Area", "GroupedColumn", "Line", "StackedColumn", "Table")
        ),
        "metric": enumeration(value.get("metric"), ("ActualCost", "AHUB", "AmortizedCost")),
    }


def projected_properties(
    kind: str, values: dict[str, Any], *, terraform: bool = False
) -> dict[str, Any]:
    kind = kind.lower()
    if kind == DEFINITION:
        return {
            "lighthouseAuthorizationSummary": {
                "authorizationPairCount": authorization_count(
                    values.get("authorization" if terraform else "authorizations"),
                    terraform=terraform,
                    required=True,
                ),
                "eligiblePairCount": authorization_count(
                    values.get("eligible_authorization" if terraform else "eligibleAuthorizations"),
                    terraform=terraform,
                    required=False,
                ),
            }
        }
    if kind == ASSIGNMENT:
        return {
            "registrationDefinitionId": definition_reference(
                values.get("lighthouse_definition_id" if terraform else "registrationDefinitionId")
            )
        }
    if kind == VIEW and not terraform:
        return {"costViewSummary": view_fact(values)}
    return {}


def review_fact(properties: dict[str, Any], path: str) -> Any:
    value = properties.get(path)
    if path == "lighthouseAuthorizationSummary":
        return authorization_fact(value)
    if path == "registrationDefinitionId":
        return definition_reference(value)
    return view_fact(value)


def replay_properties(kind: str, values: dict[str, Any]) -> dict[str, Any]:
    path = {
        DEFINITION: "lighthouseAuthorizationSummary",
        ASSIGNMENT: "registrationDefinitionId",
        VIEW: "costViewSummary",
    }.get(kind.lower())
    return {path: review_fact(values, path)} if path and path in values else {}


def known_resource(
    identity: Any, kind: str, by_id: dict[str, list[dict[str, Any]]], bundle: dict[str, Any]
) -> dict[str, Any] | None:
    if resource_parent(identity, kind) is None:
        return None
    identity = canonical_id(identity)
    candidates = by_id.get(identity, [])
    if (
        len(candidates) != 1
        or candidates[0].get("state") != "known"
        or candidates[0].get("resource_type", "").lower() != kind
        or not isinstance(candidates[0].get("arm_id"), str)
        or canonical_id(candidates[0]["arm_id"]) != identity
        or not resource_in_scope(candidates[0], bundle)
    ):
        return None
    return candidates[0]


def resource_context(
    resource: dict[str, Any], by_id: dict[str, list[dict[str, Any]]], bundle: dict[str, Any]
) -> dict[str, Any]:
    kind = resource["resource_type"].lower()
    if known_resource(resource.get("arm_id"), kind, by_id, bundle) is not resource:
        return unknown("tenant_configuration_not_unique_known_supported_scoped")
    if kind == ASSIGNMENT:
        ref = review_fact(resource["properties"], "registrationDefinitionId")
        definition = known_resource(ref, DEFINITION, by_id, bundle)
        parent = resource_parent(resource["arm_id"], ASSIGNMENT)
        if definition is None or resource_parent(ref, DEFINITION) != "/".join(
            (parent or "").split("/")[:3]
        ):
            return unknown("registration_definition_not_unique_known_in_selected_subscription")
        return {
            "definition_id": ref,
            "lighthouseAuthorizationSummary": review_fact(
                definition["properties"], "lighthouseAuthorizationSummary"
            ),
            "warning": WARNING,
        }
    if kind == VIEW:
        fact = review_fact(resource["properties"], "costViewSummary")
        if fact.get("scope") != resource_parent(resource["arm_id"], VIEW):
            return unknown("cost_view_scope_not_bound_to_resource_parent")
        return {
            "costViewSummary": fact,
            "warning": "Saved chart/metric metadata only, not a query result, reporting "
            "outcome, current cost data, invoice access or agreement/billing hierarchy.",
        }
    if kind == DEFINITION:
        return {
            "lighthouseAuthorizationSummary": review_fact(
                resource["properties"], "lighthouseAuthorizationSummary"
            ),
            "warning": WARNING,
        }
    return unknown("tenant_configuration_resource_type_unsupported")


def prepared_signal(
    resource: dict[str, Any], by_id: dict[str, list[dict[str, Any]]], bundle: dict[str, Any]
) -> bool:
    from .tiers import has_fact

    context = resource_context(resource, by_id, bundle)
    if "costViewSummary" in context:
        return any(has_fact(context["costViewSummary"].get(key)) for key in ("chart", "metric"))
    return "unknown" not in context and any(
        has_fact(value) for key, value in context.items() if key not in {"warning", "definition_id"}
    )
