"""Prepare local review records without asserting outcomes or reviewer identity."""

from typing import Any

from .contracts import control_digest, document, now, scope_id, timestamp, validate
from .diagnostics import guidance
from .engine import local_subchecks
from .network_evidence import REVIEW_PATHS, review_fact
from .sources import boolean, enumeration, property_at
from .terraform import InputError


def direct_port_context(identity: Any, by_id: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    from .expressroute_evidence import PORT_KIND

    matches = by_id.get(identity, []) if isinstance(identity, str) else []
    if (
        len(matches) != 1
        or matches[0]["state"] != "known"
        or matches[0]["resource_type"].lower() != PORT_KIND
    ):
        return {
            "arm_id": identity if isinstance(identity, str) else None,
            "unknown": "referenced_direct_port_not_unique_known",
        }
    facts = {
        path: review_fact(matches[0]["properties"], path)
        for path in (
            "directPortBandwidthGbps",
            "directPortBillingType",
            "directPortEncapsulation",
            "peeringLocationConfigured",
        )
    }
    bandwidth = facts["directPortBandwidthGbps"]
    return {
        "arm_id": identity,
        "facts": facts,
        "published_fastpath_port_ip_limit": {10: 100000, 100: 200000, 400: 200000}.get(
            bandwidth, {"unknown": "reviewed_direct_port_capacity_required"}
        )
        if type(bandwidth) is int
        else {"unknown": "reviewed_direct_port_capacity_required"},
        "warning": "Published cumulative per-port IP limit only; no actual route population, "
        "enrollment, region availability, capacity headroom or achieved FastPath performance.",
    }


def prepared_resource(
    resource: dict[str, Any],
    control: dict[str, Any],
    by_id: dict[str, list[dict[str, Any]]],
    scope: str | None = None,
    bundle: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from .logging_evidence import GUIDS as LOGGING_GUIDS
    from .logging_evidence import linked_context, resource_paths
    from .operations_evidence import GUIDS as OPERATIONS_GUIDS
    from .operations_evidence import configuration_context as operations_context
    from .operations_evidence import resource_paths as operations_paths
    from .operations_evidence import unique_known as operations_unique
    from .platform_health_evidence import GUIDS as PLATFORM_HEALTH_GUIDS
    from .platform_health_evidence import linked_context as platform_context
    from .platform_health_evidence import resource_paths as platform_paths
    from .topology_evidence import GUIDS as TOPOLOGY_GUIDS
    from .topology_evidence import configuration_context as topology_context
    from .topology_evidence import resource_paths as topology_paths
    from .topology_evidence import unique_known as topology_unique_known

    facts: dict[str, Any] = {}
    for path in control.get("review_fact_paths", []):
        if resource["state"] != "known":
            facts[path] = {"unknown": "resource_not_known"}
        elif (
            bundle is not None
            and control["upstream_guid"] in OPERATIONS_GUIDS
            and not operations_unique(resource, bundle, by_id)
        ):
            facts[path] = {"unknown": "operations_resource_not_unique_known_in_scope"}
        elif control["upstream_guid"] in OPERATIONS_GUIDS and path not in operations_paths(
            resource["resource_type"]
        ):
            facts[path] = {"unknown": "fact_not_applicable_to_resource_type"}
        elif (
            bundle is not None
            and control["upstream_guid"] in TOPOLOGY_GUIDS
            and not topology_unique_known(resource, bundle, by_id)
        ):
            facts[path] = {"unknown": "topology_resource_not_unique_known_in_scope"}
        elif control["upstream_guid"] in TOPOLOGY_GUIDS and path not in topology_paths(
            resource["resource_type"]
        ):
            facts[path] = {"unknown": "fact_not_applicable_to_resource_type"}
        elif control["upstream_guid"] in LOGGING_GUIDS and path not in resource_paths(
            resource["resource_type"]
        ):
            facts[path] = {"unknown": "fact_not_applicable_to_resource_type"}
        elif control["upstream_guid"] in PLATFORM_HEALTH_GUIDS and path not in platform_paths(
            resource["resource_type"]
        ):
            facts[path] = {"unknown": "fact_not_applicable_to_resource_type"}
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
    if control["upstream_guid"] in LOGGING_GUIDS:
        prepared["logging_context"] = linked_context(resource, by_id, scope)
    if control["upstream_guid"] in PLATFORM_HEALTH_GUIDS and control["upstream_guid"] != (
        "aa45be6a-8f2d-4896-b0e3-775e6e94e610"
    ):
        prepared["platform_health_context"] = platform_context(resource, by_id, scope)
        if resource["resource_type"].lower() in {
            "microsoft.operationalinsights/workspaces",
            "microsoft.insights/scheduledqueryrules",
        }:
            prepared["logging_context"] = linked_context(resource, by_id, scope)
    if bundle is not None and control["upstream_guid"] in TOPOLOGY_GUIDS:
        prepared["topology_configuration"] = topology_context(resource, bundle, by_id)
    if bundle is not None and control["upstream_guid"] in OPERATIONS_GUIDS:
        prepared["operations_configuration"] = operations_context(resource, bundle, by_id)
    if bundle is not None:
        from .policy_strategy_evidence import GUIDS as POLICY_STRATEGY_GUIDS
        from .policy_strategy_evidence import configuration_context

        if control["upstream_guid"] in POLICY_STRATEGY_GUIDS | {
            "aa45be6a-8f2d-4896-b0e3-775e6e94e610"
        } and control.get("review_fact_paths"):
            prepared["policy_configuration"] = configuration_context(resource, bundle, by_id)
        from .network_policy_evidence import (
            FIREWALL,
            GATEWAY,
            PARTNER,
            gateway_context,
            partner_context,
            policy_context,
        )

        if "basePolicy.id" in facts and resource["resource_type"].lower() == FIREWALL:
            prepared["configured_policy_chain"] = policy_context(resource, bundle, by_id)
        if "gatewayDiagnosticSummary" in facts and resource["resource_type"].lower() == GATEWAY:
            prepared["configured_gateway_monitoring"] = gateway_context(resource, bundle, by_id)
        if "partnerConfiguration" in facts and resource["resource_type"].lower() == PARTNER:
            prepared["configured_partner_hub"] = partner_context(resource, bundle, by_id)
    from .virtual_wan_evidence import PATHS as VWAN_PATHS
    from .virtual_wan_evidence import WAN, hub_context, wan_hub_population

    if VWAN_PATHS.intersection(facts) and control["upstream_guid"] not in TOPOLOGY_GUIDS:
        prepared["virtual_wan_context"] = (
            wan_hub_population(resource, by_id, scope)
            if resource["resource_type"].lower() == WAN
            else hub_context(resource, by_id, scope)
        )
    if (
        "disableBgpRoutePropagation" in control.get("review_fact_paths", [])
        and resource["resource_type"].lower() == "microsoft.network/virtualnetworkgateways"
    ):
        from .routing_evidence import gateway_route_subchecks

        prepared["gateway_route_subchecks"] = gateway_route_subchecks(resource, by_id)
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
    if control["upstream_guid"] in TOPOLOGY_GUIDS:
        refs = None
    replica = facts.get("replicaConfiguration")
    if isinstance(replica, dict) and "unknown" not in replica:
        refs = [entry["subnetId"] for entry in replica["replicas"]]
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
            if any(path in facts for path in ("resolverIpConfigurations", "bastionSku")):
                links[-1]["dnsResolverDelegation"] = review_fact(
                    child["properties"], "dnsResolverDelegation"
                )
                if "resolverIpConfigurations" in facts:
                    links[-1]["subchecks"].update(
                        local_subchecks(
                            {
                                "addressPrefixes": prefixes,
                                "dnsResolverDelegation": links[-1]["dnsResolverDelegation"],
                            }
                        )
                    )
        prepared["linked_subnets"] = links
        prepared["links_truncated"] = len(refs) > 20
    for path, target_kind, paths, maximum in (
        (
            "availabilitySetId",
            "microsoft.compute/availabilitysets",
            ("platformFaultDomainCount", "platformUpdateDomainCount", "resourceLocation"),
            1,
        ),
        (
            "roleDefinitionId",
            "microsoft.authorization/roledefinitions",
            ("azureRoleType", "assignableScopeCount"),
            1,
        ),
        (
            "bastionVirtualNetworkId",
            "microsoft.network/virtualnetworks",
            ("dnsServerSummary", "resourceLocation"),
            1,
        ),
        (
            "dnsVirtualNetworkId",
            "microsoft.network/virtualnetworks",
            (
                "dnsServerSummary",
                "vnetEncryptionEnabled",
                "vnetEncryptionEnforcement",
                "resourceLocation",
            ),
            1,
        ),
        (
            "bastionPublicIpIds",
            "microsoft.network/publicipaddresses",
            (
                "publicIpSku",
                "publicIpTier",
                "publicIpAllocationMethod",
                "publicIpVersion",
                "configuredZones",
                "resourceLocation",
            ),
            20,
        ),
        (
            "resolverOutboundEndpointIds",
            "microsoft.network/dnsresolvers/outboundendpoints",
            ("subnetReferences", "resourceLocation"),
            2,
        ),
    ):
        if path not in facts:
            continue
        identities = [facts[path]] if maximum == 1 else facts[path]
        if not isinstance(identities, list):
            prepared["linked_" + path] = {"unknown": "relationships_missing_or_invalid"}
            continue
        linked_resources = []
        for identity in identities[:maximum]:
            candidates = by_id.get(identity, []) if isinstance(identity, str) else []
            if (
                len(candidates) == 1
                and candidates[0]["state"] == "known"
                and candidates[0]["resource_type"].lower() == target_kind
            ):
                linked_resources.append(
                    {
                        "arm_id": identity,
                        "facts": {p: review_fact(candidates[0]["properties"], p) for p in paths},
                    }
                )
            else:
                linked_resources.append(
                    {
                        "arm_id": identity if isinstance(identity, str) else None,
                        "unknown": "referenced_configuration_not_unique_known",
                    }
                )
        prepared["linked_" + path] = linked_resources
    if "virtualNetworkGateway1.id" in facts:
        identity = facts["virtualNetworkGateway1.id"]
        candidates = by_id.get(identity, []) if isinstance(identity, str) else []
        gateway: dict[str, Any] = {
            "arm_id": identity if isinstance(identity, str) else None,
            "unknown": "referenced_gateway_not_unique_known",
        }
        if (
            len(candidates) == 1
            and candidates[0]["resource_type"].lower() == "microsoft.network/virtualnetworkgateways"
            and candidates[0]["state"] == "known"
        ):
            child = candidates[0]
            gateway_facts = {
                path: review_fact(child["properties"], path)
                for path in (
                    "gatewayType",
                    "gatewaySku",
                    "activeActive",
                    "gatewayScaleBounds",
                    "gatewayPublicIpReferences",
                )
            }
            gateway = {
                "arm_id": identity,
                "facts": gateway_facts,
                "subchecks": local_subchecks(gateway_facts),
            }
            public_refs = gateway_facts["gatewayPublicIpReferences"]
            public_ips = []
            for public_id in public_refs if isinstance(public_refs, list) else []:
                matches = by_id.get(public_id, []) if isinstance(public_id, str) else []
                entry: dict[str, Any] = {
                    "arm_id": public_id if isinstance(public_id, str) else None,
                    "unknown": "referenced_public_ip_not_unique_known",
                }
                if (
                    len(matches) == 1
                    and matches[0]["resource_type"].lower() == "microsoft.network/publicipaddresses"
                    and matches[0]["state"] == "known"
                ):
                    entry = {
                        "arm_id": public_id,
                        "publicIpSku": review_fact(matches[0]["properties"], "publicIpSku"),
                        "configuredZones": review_fact(matches[0]["properties"], "configuredZones"),
                    }
                public_ips.append(entry)
            gateway["public_ips"] = public_ips if isinstance(public_refs, list) else public_refs
        prepared["linked_gateway"] = gateway
    if "expressRoutePort.id" in facts:
        prepared["linked_direct_port"] = direct_port_context(facts["expressRoutePort.id"], by_id)
    if "expressRouteCircuitId" in facts:
        identity = facts["expressRouteCircuitId"]
        matches = by_id.get(identity, []) if isinstance(identity, str) else []
        circuit: dict[str, Any] = {
            "arm_id": identity if isinstance(identity, str) else None,
            "unknown": "referenced_circuit_not_unique_known",
        }
        if (
            len(matches) == 1
            and matches[0]["state"] == "known"
            and matches[0]["resource_type"].lower() == "microsoft.network/expressroutecircuits"
        ):
            circuit_facts = {
                path: review_fact(matches[0]["properties"], path)
                for path in (
                    "circuitSku.tier",
                    "circuitSku.family",
                    "providerCircuitBandwidthMbps",
                    "directCircuitBandwidthGbps",
                    "expressRoutePort.id",
                )
            }
            circuit = {
                "arm_id": identity,
                "facts": circuit_facts,
                "linked_direct_port": direct_port_context(
                    circuit_facts["expressRoutePort.id"], by_id
                ),
            }
        prepared["linked_circuit"] = circuit
    return prepared


def review_context(control: dict[str, Any], bundle: dict[str, Any]) -> dict[str, Any]:
    from .billing_evidence import GUIDS as BILLING_GUIDS
    from .billing_evidence import resource_context as billing_context

    available = "resources" in bundle
    if available:
        validate(bundle, "evidence")
    kinds = control.get("review_resource_types", [])
    if control.get("rule"):
        kinds = [control["rule"]["resource_type"]]
    allowed = {kind.lower() for kind in kinds}
    by_id: dict[str, list[dict[str, Any]]] = {}
    for resource in bundle.get("resources", []):
        by_id.setdefault((resource.get("arm_id") or "").lower(), []).append(resource)
    matches = [
        resource
        for resource in bundle.get("resources", [])
        if resource["resource_type"].lower() in allowed
    ]
    from .governance_evidence import GUIDS as GOVERNANCE_GUIDS
    from .governance_evidence import resource_in_scope
    from .identity_evidence import HYBRID_GUIDS, RESILIENCE_GUIDS, hybrid_context
    from .logging_evidence import GUIDS as LOGGING_GUIDS
    from .logging_evidence import scoped_identity
    from .network_policy_evidence import GUIDS as NETWORK_POLICY_GUIDS
    from .operations_evidence import GUIDS as OPERATIONS_GUIDS
    from .platform_health_evidence import GUIDS as PLATFORM_HEALTH_GUIDS
    from .policy_strategy_evidence import GUIDS as POLICY_STRATEGY_GUIDS
    from .sovereign_evidence import GUIDS as SOVEREIGN_GUIDS
    from .sovereign_evidence import configuration_context as sovereign_context
    from .tenant_evidence import GUIDS as TENANT_GUIDS
    from .topology_evidence import GUIDS as TOPOLOGY_GUIDS

    unbound = 0
    sovereign_prepared = control["upstream_guid"] in SOVEREIGN_GUIDS and bool(
        control.get("review_fact_paths")
    )
    policy_prepared = control["upstream_guid"] in POLICY_STRATEGY_GUIDS | {
        "aa45be6a-8f2d-4896-b0e3-775e6e94e610"
    } and bool(control.get("review_fact_paths"))
    scoped_guids = (
        GOVERNANCE_GUIDS
        | RESILIENCE_GUIDS
        | HYBRID_GUIDS
        | NETWORK_POLICY_GUIDS
        | TENANT_GUIDS
        | BILLING_GUIDS
        | TOPOLOGY_GUIDS
        | OPERATIONS_GUIDS
    )
    if policy_prepared:
        scoped_guids |= POLICY_STRATEGY_GUIDS | {"aa45be6a-8f2d-4896-b0e3-775e6e94e610"}
    if sovereign_prepared:
        scoped_guids |= SOVEREIGN_GUIDS
    if control["upstream_guid"] in LOGGING_GUIDS | PLATFORM_HEALTH_GUIDS and not policy_prepared:
        scoped = [
            resource for resource in matches if scoped_identity(resource, bundle.get("scope"))
        ]
        unbound, matches = len(matches) - len(scoped), scoped
    elif control["upstream_guid"] in scoped_guids:
        scoped = [resource for resource in matches if resource_in_scope(resource, bundle)]
        unbound, matches = len(matches) - len(scoped), scoped
        by_id = {
            identity: candidates
            for identity, candidates in by_id.items()
            if all(resource_in_scope(resource, bundle) for resource in candidates)
        }
    context = {
        "mode": bundle["mode"],
        "collected_at": bundle["collected_at"],
        "inventory_complete": bundle["inventory_complete"],
        "normalized_resources_available": available,
        "resources": [
            prepared_resource(resource, control, by_id, bundle.get("scope"), bundle)
            for resource in matches[:100]
        ],
        "matching_resources": len(matches) if available else None,
        "truncated": len(matches) > 100,
        "warning": (
            "Informational original-time inventory/subchecks only; positive references are not "
            "complete relationships. No whole-recommendation outcome or current freshness inferred."
        ),
    }
    if control["upstream_guid"] in scoped_guids | LOGGING_GUIDS | PLATFORM_HEALTH_GUIDS:
        context["unbound_resources"] = unbound
    if control["upstream_guid"] in HYBRID_GUIDS:
        for prepared, resource in zip(context["resources"], matches[:100], strict=True):
            configuration = hybrid_context(resource, by_id, bundle)
            prepared["hybrid_configuration"] = configuration
            prepared["facts"] = configuration.get("facts", configuration)
            prepared["subchecks"] = {}
    if sovereign_prepared:
        for prepared, resource in zip(context["resources"], matches[:100], strict=True):
            configuration = sovereign_context(resource, by_id, bundle, control["review_fact_paths"])
            prepared["sovereign_configuration"] = configuration
            prepared["facts"] = configuration.get("facts", configuration)
            prepared["subchecks"] = {}
    if policy_prepared and available:
        from .policy_strategy_evidence import population_context

        context["supplied_policy_assignments"] = population_context(bundle, by_id)
    if control["upstream_guid"] in TENANT_GUIDS:
        from .tenant_evidence import resource_context

        for prepared, resource in zip(context["resources"], matches[:100], strict=True):
            prepared["tenant_configuration"] = resource_context(resource, by_id, bundle)
    if control["upstream_guid"] in BILLING_GUIDS:
        for prepared, resource in zip(context["resources"], matches[:100], strict=True):
            configuration = billing_context(resource, by_id, bundle)
            prepared["billing_configuration"] = configuration
            prepared["facts"] = configuration.get("facts", configuration)
            prepared["subchecks"] = {}
    if (
        policy_prepared
        or (sovereign_prepared and "managementParentId" in control["review_fact_paths"])
        or control["upstream_guid"] == "3a923c34-74d0-4001-aac6-a9e01e6a83de"
    ) and available:
        from .governance_evidence import hierarchy_context

        context["saved_management_hierarchy"] = hierarchy_context(bundle)
    if "expressRouteCircuitId" in control.get("review_fact_paths", []) and available:
        from .expressroute_evidence import (
            CIRCUIT_KIND,
            circuit_location_subchecks,
            gateway_circuit_subchecks,
        )

        if control["upstream_guid"] == "e0d5973c-d4cd-421b-8881-37f5e6c4cfd3":
            context["circuit_location_subchecks"] = circuit_location_subchecks(
                [
                    resource
                    for resource in bundle["resources"]
                    if resource["resource_type"].lower() == CIRCUIT_KIND
                ],
                by_id,
            )
        if control["upstream_guid"] == "669b215a-ce43-4371-8f6f-11047f6490f1":
            gateways = [
                resource
                for resource in bundle["resources"]
                if resource["resource_type"].lower() == "microsoft.network/virtualnetworkgateways"
            ]
            context["gateway_circuit_subchecks"] = [
                {
                    "arm_id": resource.get("arm_id"),
                    "subchecks": gateway_circuit_subchecks(resource, bundle["resources"], by_id),
                }
                for resource in gateways[:100]
            ]
            context["gateways_truncated"] = len(gateways) > 100
    if control["upstream_guid"] == "f348ef25-4c27-4d42-b8bb-ac7571559ab9":
        from .routing_evidence import address_subchecks

        prefixes: Any = []
        if not available or not matches or len(matches) > 100:
            prefixes = None
        else:
            for resource in matches:
                values = review_fact(resource["properties"], "virtualNetworkPrefixes")
                if (
                    resource["state"] != "known"
                    or not isinstance(values, list)
                    or not values
                    or any(not isinstance(value, str) for value in values)
                    or len(prefixes) + len(values) > 100
                ):
                    prefixes = None
                    break
                prefixes.extend(values)
        context["supplied_vnet_population_subchecks"] = {
            "subchecks": address_subchecks(prefixes),
            "warning": "Only the supplied bounded VNet population, not complete production/DR "
            "roles, estate inventory or approved subnet-move exceptions.",
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
