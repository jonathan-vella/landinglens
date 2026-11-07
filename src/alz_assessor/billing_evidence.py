"""Minimized budget configuration, never billing authority or financial assurance."""

import json
from typing import Any

from .contracts import canonical_id, identity_type, scope_id
from .governance_evidence import resource_in_scope
from .sources import boolean, enumeration, unknown
from .terraform import InputError

BUDGET = "microsoft.consumption/budgets"
PATHS = {"budgetConfiguration"}
TF_KINDS = {
    "azurerm_consumption_budget_subscription": "subscription_id",
    "azurerm_consumption_budget_resource_group": "resource_group_id",
}
GUIDS = {
    "54f0d8b1-22a3-4c0d-8ce2-58b9e086c93a",
    "ca0fe401-12ad-46fc-8a7e-86293866a9f6",
    "5cf9f485-2784-49b3-9824-75d9b8bdb57b",
    "6ad5c3dd-e5ea-4ff1-81a4-7886ff87845c",
    "90e87802-602f-4dfb-acea-67c60689f1d7",
    "e81a73f0-84c4-4641-b406-14db3b4d1f50",
    "ae757485-92a4-482a-8bc9-eefe6f5b5ec3",
}
GRAINS = ("Monthly", "Quarterly", "Annually", "BillingMonth", "BillingQuarter", "BillingAnnual")
OPERATORS = ("EqualTo", "GreaterThan", "GreaterThanOrEqualTo")
WARNING = (
    "Supplied subscription/RG configuration only, not EA department/account allocation, "
    "MCA profile/section organization, effective billing visibility, offer qualification, "
    "required recipients, group-mailbox suitability, notification delivery or audit operation. "
    "Amounts, currencies, spend, filters, dates, thresholds and contacts are withheld; "
    "active period, currency compatibility and notification suitability are not evaluated. "
    "Budgets do not stop consumption or enforce spending."
)


def budget_parent(identity: Any) -> str | None:
    if not isinstance(identity, str):
        return None
    try:
        parent, name = canonical_id(identity).rsplit("/providers/" + BUDGET + "/", 1)
        if not name or "/" in name:
            return None
        parent = scope_id(parent)
        return (
            parent
            if identity_type(parent)
            in {"microsoft.resources/subscriptions", "microsoft.resources/resourcegroups"}
            else None
        )
    except (InputError, ValueError):
        return None


def terraform_identity(scope: str | None, kind: str, values: dict[str, Any]) -> str | None:
    target, name = values.get(TF_KINDS[kind]), values.get("name")
    if not isinstance(target, str) or not isinstance(name, str) or not name or "/" in name:
        return None
    try:
        target = scope_id(target)
        selected = scope_id(scope) if scope else None
        expected = (
            "microsoft.resources/subscriptions"
            if kind.endswith("_subscription")
            else "microsoft.resources/resourcegroups"
        )
        identity = canonical_id(target + "/providers/" + BUDGET + "/" + name)
        if (
            selected
            and identity_type(target) == expected
            and budget_parent(identity) == target
            and (target == selected or target.startswith(selected + "/"))
        ):
            return identity
    except InputError:
        return None
    return None


def notifications(value: Any, *, terraform: bool = False, normalized: bool = False) -> Any:
    if not terraform and not normalized:
        if not isinstance(value, dict) or "unknown" in value or len(value) > 5:
            return unknown("budget_notifications_missing_malformed_or_over_five")
        # Dictionary keys can encode financial thresholds; do not retain them or their order.
        value = list(value.values())
    if not isinstance(value, list) or len(value) > 5:
        return unknown("budget_notifications_missing_malformed_or_over_five")
    result = []
    for row in value:
        if not isinstance(row, dict) or "unknown" in row:
            return unknown("budget_notification_not_explicit")
        result.append(
            {
                "enabled": boolean(row.get("enabled")),
                "operator": enumeration(row.get("operator"), OPERATORS),
                "thresholdType": enumeration(
                    row.get("threshold_type" if terraform else "thresholdType"),
                    ("Actual", "Forecasted"),
                ),
            }
        )
    return sorted(result, key=lambda row: json.dumps(row, sort_keys=True))


def configuration(value: Any, *, terraform: bool = False, normalized: bool = False) -> Any:
    if not isinstance(value, dict) or "unknown" in value:
        return unknown("budget_configuration_not_explicit")
    result = {
        "category": enumeration(value.get("category") if not terraform else None, ("Cost",)),
        "timeGrain": enumeration(value.get("time_grain" if terraform else "timeGrain"), GRAINS),
        "notifications": notifications(
            value.get("notification" if terraform else "notifications"),
            terraform=terraform,
            normalized=normalized,
        ),
    }
    return result


def projected_properties(
    kind: str, values: dict[str, Any], *, terraform: bool = False
) -> dict[str, Any]:
    if kind.lower() != BUDGET:
        return {}
    return {"budgetConfiguration": configuration(values, terraform=terraform)}


def review_fact(properties: dict[str, Any], path: str) -> Any:
    return configuration(properties.get(path), normalized=True)


def replay_properties(kind: str, values: dict[str, Any]) -> dict[str, Any]:
    return (
        {"budgetConfiguration": review_fact(values, "budgetConfiguration")}
        if kind.lower() == BUDGET and "budgetConfiguration" in values
        else {}
    )


def minimized_evidence(bundle: dict[str, Any]) -> dict[str, Any]:
    """Keep saved/injected budget payloads out of local-session persistence."""
    return {
        **bundle,
        "resources": [
            {
                **resource,
                "properties": replay_properties(BUDGET, resource["properties"]),
            }
            if resource["resource_type"].lower() == BUDGET
            else resource
            for resource in bundle["resources"]
        ],
    }


def resource_context(
    resource: dict[str, Any], by_id: dict[str, list[dict[str, Any]]], bundle: dict[str, Any]
) -> dict[str, Any]:
    identity = resource.get("arm_id")
    candidates = by_id.get(identity.lower(), []) if isinstance(identity, str) else []
    if (
        budget_parent(identity) is None
        or len(candidates) != 1
        or candidates[0] is not resource
        or resource.get("resource_type", "").lower() != BUDGET
        or resource.get("state") != "known"
        or not resource_in_scope(resource, bundle)
    ):
        return unknown("budget_not_unique_known_subscription_or_rg_in_selected_scope")
    return {
        "facts": {
            "budgetConfiguration": review_fact(resource["properties"], "budgetConfiguration")
        },
        "warning": WARNING,
    }


def prepared_signal(
    resource: dict[str, Any], by_id: dict[str, list[dict[str, Any]]], bundle: dict[str, Any]
) -> bool:
    from .tiers import has_fact

    return has_fact(resource_context(resource, by_id, bundle).get("facts", {}))
