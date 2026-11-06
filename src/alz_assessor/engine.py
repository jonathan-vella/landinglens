"""One advisory evaluator for all normalized source modes."""

from __future__ import annotations

from datetime import timedelta
from ipaddress import ip_address, ip_network
from math import isfinite
from typing import Any

from .contracts import control_digest, digest, document, now, timestamp, validate
from .network_evidence import address_list, bounded_count, nat_collections
from .policy_evidence import policy_signals
from .query_signals import query_signals
from .scanner_evidence import scanner_signals
from .sources import BLOB_SERVICE_TYPE, complete_blob_services, property_at, unknown
from .terraform import InputError
from .tiers import attach, prepared_signal


def restricted_direct_sources(addresses: list[str]) -> bool:
    intervals = []
    for value in addresses:
        if value in {"*", "any"}:
            return False
        if "/" in value:
            prefix = ip_network(value)
            intervals.append((int(prefix.network_address), int(prefix.broadcast_address)))
        elif "-" in value:
            first_text, last_text = value.split("-")
            intervals.append((int(ip_address(first_text)), int(ip_address(last_text))))
        else:
            single = int(ip_address(value))
            intervals.append((single, single))
    covered_until = 0
    for first, last in sorted(intervals):
        if first > covered_until:
            return True
        covered_until = max(covered_until, last + 1)
    return covered_until < 2**32


def local_subchecks(properties: dict[str, Any]) -> dict[str, Any]:
    """Original-time partial facts, never whole-recommendation outcomes."""
    result: dict[str, Any] = {}
    from .expressroute_evidence import fastpath_subchecks

    result.update(fastpath_subchecks(properties))
    if "virtualNetworkPrefixes" in properties:
        from .routing_evidence import address_subchecks

        result.update(address_subchecks(properties["virtualNetworkPrefixes"]))
    if "addressPrefixes" in properties:
        prefixes = address_list(properties["addressPrefixes"], prefix_only=True)
        known = (
            isinstance(prefixes, list)
            and bool(prefixes)
            and all(isinstance(value, str) and "/" in value for value in prefixes)
        )
        result["supplied_ipv4_prefixes_have_minimum_26_capacity"] = (
            all(ip_network(value).prefixlen <= 26 for value in prefixes)
            if known
            else unknown("explicit_ipv4_prefixes_required")
        )
        result["supplied_ipv4_prefixes_have_minimum_27_capacity"] = (
            all(ip_network(value).prefixlen <= 27 for value in prefixes)
            if known
            else unknown("explicit_ipv4_prefixes_required")
        )
    if "natRuleCollections" in properties:
        collections = nat_collections(properties["natRuleCollections"])
        restrictions = []
        complete = isinstance(collections, list) and bool(collections)
        for collection in collections if isinstance(collections, list) else []:
            body = collection["properties"]
            if body["action"]["type"] != "Dnat":
                complete = False
                continue
            for rule in body["rules"]:
                addresses = rule.get("sourceAddresses")
                if (
                    not isinstance(addresses, list)
                    or not addresses
                    or any(not isinstance(value, str) for value in addresses)
                ):
                    complete = False
                else:
                    restrictions.append(restricted_direct_sources(addresses))
        result["supplied_direct_dnat_addresses_restricted"] = (
            all(restrictions)
            if complete and restrictions
            else unknown("direct_dnat_source_addresses_not_complete")
        )
    return result


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
    evidence_tiers: bool = False,
) -> dict[str, Any]:
    validate(bundle, "evidence")
    validate(catalog, "catalog")
    if str(catalog.get("review_state", "")).startswith("candidate"):
        raise InputError("Source candidates are not accepted evaluator catalogs")
    if type(evidence_tiers) is not bool:
        raise InputError("Evidence tier selection must be an explicit boolean")
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
    queried = query_signals(bundle, instant.isoformat(), max_age_hours) if evidence_tiers else None
    queried_controls = (
        {"ALZ-" + queried["guid"]}
        if queried and any(row["usable"] for row in queried["records"])
        else set()
    )
    scanned = (
        scanner_signals(bundle, instant.isoformat(), max_age_hours) if evidence_tiers else None
    )
    scanned_controls = (
        {item["control_id"] for item in scanned["records"] if item["usable"]} if scanned else set()
    )
    supplemental = (
        policy_signals(bundle, catalog, instant.isoformat(), max_age_hours)
        if evidence_tiers
        else None
    )
    signal_controls = (
        {item["control_id"] for item in supplemental["records"] if item["usable"]}
        if supplemental
        else set()
    )
    resources = list(bundle["resources"])
    if any(
        c.get("rule") and c["rule"]["resource_type"].lower() == BLOB_SERVICE_TYPE.lower()
        for c in catalog["controls"]
        if c["lifecycle"] == "active"
    ):
        complete_blob_services(
            resources,
            256
            if bundle["mode"] == "planned"
            and bundle["source"] in {"terraform", "terraform-plan", "arm", "bicep"}
            else 10_000,
        )
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
        prepared = evidence_tiers and not stale and prepared_signal(control, bundle)
        review_signal = (
            evidence_tiers
            and not stale
            and landing_zone in control["applicability"]
            and (
                prepared
                or control["control_id"] in signal_controls
                or control["control_id"] in scanned_controls
                or control["control_id"] in queried_controls
            )
        )
        targets = [
            resource
            for resource in resources
            if rule and resource["resource_type"].lower() == rule["resource_type"].lower()
        ] or [None]
        for resource in targets:
            reason, fact, links = "human_evidence_required", None, []
            component_facts = None
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
                elif (
                    resource["resource_type"].lower() == BLOB_SERVICE_TYPE.lower()
                    and resource.get("arm_id")
                    and not resource["arm_id"].lower().endswith("/blobservices/default")
                ):
                    outcome, reason = "unknown", "blob_service_identity_not_default"
                else:
                    fact = property_at(resource["properties"], rule["property"])
                    vault = rule.get("operation") == "vault-deletion-protection"
                    if vault:
                        purge = property_at(resource["properties"], "enablePurgeProtection")
                        if type(fact) is bool and type(purge) is bool:
                            component_facts = {
                                "enableSoftDelete": fact,
                                "enablePurgeProtection": purge,
                            }
                        fact = (
                            fact and purge if type(fact) is bool and type(purge) is bool else None
                        )
                    enum = rule.get("operation") == "enum-equals"
                    premium = rule.get("operation") == "firewall-premium-sku"
                    capacity = rule.get("operation") in {"nsg-rule-capacity", "route-capacity"}
                    route_capacity = rule.get("operation") == "route-capacity"
                    sku = property_at(resource["properties"], "sku.tier") if enum else None
                    if capacity and bundle["mode"] != "observed":
                        outcome, reason, fact = (
                            "unknown",
                            "complete_observed_route_count_required"
                            if route_capacity
                            else "complete_observed_rule_count_required",
                            None,
                        )
                    elif (
                        capacity
                        and type(bounded_count(fact, 1000 if route_capacity else 2000)) is int
                    ):
                        outcome = "pass" if fact <= rule["expected"] else "fail"
                        reason = (
                            (
                                "within_checklist_route_target"
                                if outcome == "pass"
                                else "exceeds_checklist_route_target"
                            )
                            if route_capacity
                            else (
                                "within_checklist_rule_target"
                                if outcome == "pass"
                                else "exceeds_checklist_rule_target"
                            )
                        )
                    elif (
                        premium
                        and isinstance(fact, str)
                        and fact in {"Basic", "Standard", "Premium"}
                    ):
                        outcome = "pass" if fact == "Premium" else "fail"
                        reason = (
                            "explicit_property_matches"
                            if outcome == "pass"
                            else "explicit_property_differs"
                        )
                    elif enum and (
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
                        not enum and not premium and not capacity and type(fact) is bool
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
                    if vault:
                        links.append(resource["source_location"] + "#enablePurgeProtection")
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
                **({"component_facts": component_facts} if component_facts is not None else {}),
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
            if evidence_tiers:
                body["policy_signal_only"] = (
                    control["control_id"] in signal_controls
                    and not prepared
                    and outcome not in {"pass", "fail"}
                )
                body["supplemental_signal_only"] = (
                    control["control_id"] in signal_controls | scanned_controls | queried_controls
                    and not prepared
                    and outcome not in {"pass", "fail"}
                )
                body["machine_evidence"] = (
                    not stale
                    and landing_zone in control["applicability"]
                    and ((bool(rule) and outcome in {"pass", "fail"}) or review_signal)
                )
            results.append(
                {
                    "control_id": control["control_id"],
                    "upstream_id": control["upstream_id"],
                    "design_area": control["design_area"],
                    "recommendation": control["recommendation"],
                    "applicability": control["applicability"],
                    "automation": control["automation"],
                    **({"severity": control["severity"]} if "severity" in control else {}),
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
    result = document(
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
    if supplemental and (supplemental["records"] or supplemental["gaps"]):
        result["policy_signals"] = supplemental
    if scanned is not None:
        result["scanner_signals"] = scanned
    if queried is not None:
        result["query_signals"] = queried
    return validate(attach(result) if evidence_tiers else result)
