"""Declarative evidence-domain registry for review facts, paths, and replay projections."""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from functools import cache
from typing import Any


@dataclass(frozen=True)
class EvidenceDomain:
    name: str
    module: str
    has_paths: bool = True
    has_review_fact: bool = True
    has_replay_properties: bool = False
    static_paths: frozenset[str] | None = None

    def load_module(self) -> Any:
        return importlib.import_module(f".{self.module}", __package__ or "alz_assessor")

    def paths(self) -> set[str]:
        if self.static_paths is not None:
            return set(self.static_paths)
        if not self.has_paths:
            return set()
        return set(getattr(self.load_module(), "PATHS", ()))

    def review_fact(self, properties: dict[str, Any], path: str) -> Any:
        fn = self.load_module().review_fact
        return fn(properties, path)

    def replay_properties(self, resource_type: str, values: dict[str, Any]) -> dict[str, Any]:
        if not self.has_replay_properties:
            return {}
        fn = self.load_module().replay_properties
        result: dict[str, Any] = fn(resource_type, values)
        return result


DOMAINS: tuple[EvidenceDomain, ...] = (
    EvidenceDomain(
        name="key_lifecycle",
        module="key_lifecycle_evidence",
        has_replay_properties=True,
    ),
    EvidenceDomain(
        name="billing",
        module="billing_evidence",
        has_replay_properties=True,
    ),
    EvidenceDomain(
        name="organization",
        module="organization_evidence",
        has_replay_properties=True,
    ),
    EvidenceDomain(
        name="recovery",
        module="recovery_evidence",
        has_replay_properties=True,
    ),
    EvidenceDomain(
        name="operations",
        module="operations_evidence",
        has_replay_properties=True,
    ),
    EvidenceDomain(
        name="platform_health",
        module="platform_health_evidence",
        has_replay_properties=True,
    ),
    EvidenceDomain(
        name="topology",
        module="topology_evidence",
        has_replay_properties=True,
    ),
    EvidenceDomain(
        name="policy_strategy",
        module="policy_strategy_evidence",
        has_replay_properties=True,
    ),
    EvidenceDomain(
        name="tenant",
        module="tenant_evidence",
        has_replay_properties=True,
    ),
    EvidenceDomain(
        name="logging",
        module="logging_evidence",
        has_replay_properties=True,
    ),
    EvidenceDomain(
        name="network_policy",
        module="network_policy_evidence",
        has_replay_properties=False,
    ),
    EvidenceDomain(
        name="virtual_wan",
        module="virtual_wan_evidence",
        has_replay_properties=False,
    ),
    EvidenceDomain(
        name="governance",
        module="governance_evidence",
        has_replay_properties=True,
    ),
    EvidenceDomain(
        name="monitoring",
        module="monitoring_evidence",
        has_replay_properties=False,
        static_paths=frozenset({"connectionMonitorSummary", "expressRouteAlertSummary"}),
    ),
    EvidenceDomain(
        name="dns",
        module="dns_evidence",
        has_replay_properties=False,
    ),
    EvidenceDomain(
        name="expressroute",
        module="expressroute_evidence",
        has_replay_properties=False,
    ),
    EvidenceDomain(
        name="security",
        module="security_evidence",
        has_replay_properties=True,
    ),
    EvidenceDomain(
        name="protection",
        module="protection_evidence",
        has_replay_properties=False,
    ),
    EvidenceDomain(
        name="identity",
        module="identity_evidence",
        has_replay_properties=True,
    ),
    EvidenceDomain(
        name="routing",
        module="routing_evidence",
        has_replay_properties=False,
    ),
)

BASE_NETWORK_REVIEW_PATHS: frozenset[str] = frozenset(
    {
        "sku.tier",
        "sku.name",
        "subnetReferences",
        "firewallPolicy.id",
        "addressPrefixes",
        "routeTable.id",
        "natGateway.id",
        "targetResourceId",
        "workspaceId",
        "logAnalyticsDestinationType",
        "natRuleCollections",
        "ipAddresses",
        "configuredZones",
        "applicationRules",
        "enableDdosProtection",
        "ddosProtectionPlan.id",
        "privateConnections",
        "subnet.id",
        "networkSecurityGroup.id",
        "serviceEndpointCount",
        "serviceEndpointNetworkIdentifiers",
        "privateEndpointNetworkPolicies",
        "gatewayType",
        "securityRuleCount",
        "securityRuleSummary",
        "defaultRuleSummary",
        "egressRules",
        "enabled",
        "storageId",
        "trafficAnalytics.enabled",
        "trafficAnalytics.workspaceResourceId",
        "filteringConfigured",
    }
)

BASE_CATALOG_ONLY_PATHS: frozenset[str] = frozenset(
    {
        "enableRbacAuthorization",
        "publicNetworkAccess",
        "networkAcls.defaultAction",
        "minimumTlsVersion",
    }
)


@cache
def network_review_paths() -> frozenset[str]:
    paths = set(BASE_NETWORK_REVIEW_PATHS)
    for domain in DOMAINS:
        paths |= domain.paths()
    return frozenset(paths)


@cache
def catalog_review_fact_paths() -> frozenset[str]:
    return network_review_paths() | BASE_CATALOG_ONLY_PATHS


@cache
def network_replay_paths() -> frozenset[str]:
    excluded = {
        "security",
        "governance",
        "organization",
        "logging",
        "platform_health",
        "recovery",
        "tenant",
        "billing",
        "policy_strategy",
        "topology",
    }
    paths = set(network_review_paths())
    for domain in DOMAINS:
        if domain.name in excluded:
            paths -= domain.paths()
    return frozenset(paths)


def dispatch_domain_review_fact(properties: dict[str, Any], path: str) -> tuple[bool, Any]:
    for domain in DOMAINS:
        if path in domain.paths():
            return True, domain.review_fact(properties, path)
    return False, None


def collect_domain_replay_properties(resource_type: str, values: dict[str, Any]) -> dict[str, Any]:
    from .network_evidence import replay_properties as network_replay_properties

    merged: dict[str, Any] = dict(network_replay_properties(resource_type, values))
    for domain in DOMAINS:
        if domain.has_replay_properties:
            merged.update(domain.replay_properties(resource_type, values))
    return merged
