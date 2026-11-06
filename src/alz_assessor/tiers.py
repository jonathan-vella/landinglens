"""Evidence routing is separate from technical outcomes and human decisions."""

from math import isfinite
from typing import Any

from .terraform import InputError

TIERS = ("verified", "signal", "needs_decision", "manual")
LABELS = {
    "verified": "Verified",
    "signal": "Signal",
    "needs_decision": "Needs decision",
    "manual": "Manual",
}


def has_fact(value: Any) -> bool:
    if isinstance(value, dict):
        return "unknown" not in value and any(has_fact(item) for item in value.values())
    if isinstance(value, list):
        return bool(value) and any(has_fact(item) for item in value)
    return type(value) in (str, bool, int) or (type(value) is float and isfinite(value))


def prepared_signal(control: dict[str, Any], bundle: dict[str, Any]) -> bool:
    from .governance_evidence import GUIDS as GOVERNANCE_GUIDS
    from .governance_evidence import resource_in_scope
    from .identity_evidence import HYBRID_GUIDS, RESILIENCE_GUIDS, hybrid_context
    from .logging_evidence import GUIDS as LOGGING_GUIDS
    from .logging_evidence import resource_paths, scoped_identity
    from .network_evidence import REVIEW_PATHS, review_fact
    from .network_policy_evidence import GUIDS as NETWORK_POLICY_GUIDS
    from .policy_strategy_evidence import GUIDS as POLICY_STRATEGY_GUIDS
    from .policy_strategy_evidence import unique_known as policy_unique_known
    from .sources import boolean, enumeration, property_at
    from .sovereign_evidence import GUIDS as SOVEREIGN_GUIDS
    from .sovereign_evidence import configuration_context as sovereign_context
    from .tenant_evidence import GUIDS as TENANT_GUIDS
    from .tenant_evidence import prepared_signal as tenant_signal
    from .virtual_wan_evidence import GUIDS as VWAN_GUIDS
    from .virtual_wan_evidence import known_resource

    kinds = {kind.lower() for kind in control.get("review_resource_types", [])}
    if not kinds or not control.get("review_fact_paths"):
        return False
    vwan = control["upstream_guid"] in VWAN_GUIDS
    logging = control["upstream_guid"] in LOGGING_GUIDS
    by_id: dict[str, list[dict[str, Any]]] = {}
    policy = control["upstream_guid"] in POLICY_STRATEGY_GUIDS
    if (
        vwan
        or policy
        or logging
        or control["upstream_guid"] in TENANT_GUIDS | HYBRID_GUIDS | SOVEREIGN_GUIDS
    ):
        for resource in bundle["resources"]:
            by_id.setdefault((resource.get("arm_id") or "").lower(), []).append(resource)
    for resource in bundle["resources"]:
        if resource["state"] != "known" or resource["resource_type"].lower() not in kinds:
            continue
        if control["upstream_guid"] in SOVEREIGN_GUIDS:
            context = sovereign_context(resource, by_id, bundle, control["review_fact_paths"])
            if has_fact(context.get("facts", {})):
                return True
            continue
        if control["upstream_guid"] in HYBRID_GUIDS:
            context = hybrid_context(resource, by_id, bundle)
            if has_fact(context.get("facts", {})):
                return True
            continue
        if policy and not policy_unique_known(resource, bundle, by_id):
            continue
        if control["upstream_guid"] in TENANT_GUIDS:
            if tenant_signal(resource, by_id, bundle):
                return True
            continue
        if control[
            "upstream_guid"
        ] in GOVERNANCE_GUIDS | RESILIENCE_GUIDS | NETWORK_POLICY_GUIDS and not resource_in_scope(
            resource, bundle
        ):
            continue
        if logging:
            identity = scoped_identity(resource, bundle.get("scope"))
            if not identity or len(by_id.get(identity, [])) != 1:
                continue
        if (
            vwan
            and known_resource(
                resource.get("arm_id"),
                resource["resource_type"].lower(),
                by_id,
                bundle.get("scope"),
            )
            is not resource
        ):
            continue
        for path in control.get("review_fact_paths", []):
            if logging and path not in resource_paths(resource["resource_type"]):
                continue
            properties = resource["properties"]
            if path in REVIEW_PATHS:
                fact = review_fact(properties, path)
            elif path == "enableRbacAuthorization":
                fact = boolean(property_at(properties, path))
            else:
                fact = enumeration(
                    property_at(properties, path),
                    {
                        "publicNetworkAccess": ("Enabled", "Disabled"),
                        "networkAcls.defaultAction": ("Allow", "Deny"),
                        "minimumTlsVersion": ("TLS1_0", "TLS1_1", "TLS1_2"),
                    }[path],
                )
            if has_fact(fact):
                return True
    return False


def body_tier(automation: str, body: dict[str, Any]) -> str:
    if automation == "manual":
        return "manual"
    if (
        automation == "automated"
        and body["freshness"] == "current"
        and body["outcome"] in {"pass", "fail"}
        and body.get("confidence") == "explicit-configuration-only"
    ):
        return "verified"
    if body["freshness"] == "current" and body.get("machine_evidence") is True:
        return "signal"
    return "needs_decision"


def summary(results: list[dict[str, Any]], retired: list[dict[str, Any]]) -> dict[str, Any]:
    groups: dict[str, list[str]] = {}
    for row in results:
        automation = row.get("automation")
        if automation not in {"automated", "assisted", "manual", "unmapped"}:
            raise InputError("Tiered results require an explicit automation disposition")
        values = groups.setdefault(row["control_id"], [])
        for mode in ("planned", "observed"):
            if row.get(mode):
                values.append(body_tier(automation, row[mode]))
    controls = []
    for identity, values in sorted(groups.items()):
        # A partial mixed target/mode population is never wholly Verified.
        tier = (
            "manual"
            if values and all(value == "manual" for value in values)
            else "verified"
            if values and all(value == "verified" for value in values)
            else "signal"
            if any(value in {"verified", "signal"} for value in values)
            else "needs_decision"
        )
        controls.append({"control_id": identity, "tier": tier})
    for item in retired:
        if item["control_id"] in groups:
            raise InputError("Retired tier identity conflicts with an active control")
        controls.append({"control_id": item["control_id"], "tier": "needs_decision"})
    controls.sort(key=lambda item: item["control_id"])
    return {
        "counts": {tier: sum(item["tier"] == tier for item in controls) for tier in TIERS},
        "controls": controls,
    }


def attach(assessment: dict[str, Any]) -> dict[str, Any]:
    assessment["schema_version"] = "1.2"
    if "source_versions" in assessment:
        assessment["source_versions"]["catalog_contract"] = assessment["source_versions"][
            "contracts"
        ]
        assessment["source_versions"]["contracts"] = "1.2"
    for row in assessment["results"]:
        for mode in ("planned", "observed"):
            if row.get(mode):
                row[mode]["evidence_tier"] = body_tier(row["automation"], row[mode])
    assessment["evidence_tiers"] = summary(
        assessment["results"], assessment.get("retired_controls", [])
    )
    if any(
        (bundle.get("metadata") or {}).get("archetype_bindings") is not None
        for bundle in assessment["evidence"]
    ):
        from .priorities import suggestions

        assessment["applicability_suggestions"] = suggestions(
            assessment["evidence"],
            assessment["generated_at"],
            assessment.get("freshness_policy_hours", 24),
        )
    return assessment
