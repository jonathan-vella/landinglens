"""Explicit maintainer capture of batch sources already inspected for intent and semantics."""

import argparse
import hashlib
import json
import re
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROVIDER = "211156b6c9c3c4721a2a4631998a6bd08433a9ee"
LEARN = "https://learn.microsoft.com/en-us/"
RAW = f"https://raw.githubusercontent.com/hashicorp/terraform-provider-azurerm/{PROVIDER}/"
SPEC_REVISION = "5531fa823aafa40895d51db03315fa749fcb9cf0"
SPEC_RAW = f"https://raw.githubusercontent.com/Azure/azure-rest-api-specs/{SPEC_REVISION}/"
SOURCES = [
    (
        "vault-overview",
        LEARN + "azure/key-vault/general/overview",
        ["secrets", "application"],
        "Vault storage capability and application integration are distinct; "
        "existence is not adoption.",
    ),
    (
        "vault-throttling",
        LEARN + "azure/key-vault/general/overview-throttling",
        ["throttling", "regions"],
        "Vault partitioning depends on application security/availability "
        "domains and transaction demand.",
    ),
    (
        "vault-security",
        LEARN + "azure/key-vault/general/best-practices",
        ["soft delete", "purge protection", "Privileged Identity Management", "Private Endpoints"],
        "The linked page redirects to secure-key-vault. Separately enable soft delete "
        "and purge protection; PIM, access boundaries, network alternatives and audit "
        "integration require distinct evidence.",
    ),
    (
        "vault-monitor",
        LEARN + "azure/key-vault/general/monitor-key-vault",
        ["diagnostic setting", "Resource Logs"],
        "Resource logs require diagnostic routing; automatic metrics do not prove "
        "audit logging or a central destination.",
    ),
    (
        "vault-arm",
        LEARN + "azure/templates/microsoft.keyvault/2024-11-01/vaults",
        ["enableSoftDelete", "enablePurgeProtection"],
        "2024-11-01 exposes two separate boolean properties. Omitted documented "
        "creation defaults are not inferred.",
    ),
    (
        "vault-rest",
        LEARN + "rest/api/keyvault/keyvault/vaults/get?view=rest-keyvault-keyvault-2024-11-01",
        ["2024-11-01", "enableSoftDelete", "enablePurgeProtection"],
        "Scoped ARM GET retrieves one vault. The initially attempted 2023-07-01 "
        "Learn REST view falls back to 2024-11-01; only the actually reviewed "
        "2024-11-01 API is accepted.",
    ),
    (
        "container-guidance",
        LEARN + "azure/storage/blobs/soft-delete-container-overview",
        ["container", "365"],
        "Container protection differs from blob and account deletion protection. "
        "The supported retention range is 1-365; adequacy is workload-specific.",
    ),
    (
        "storage-data-protection",
        LEARN + "azure/storage/blobs/data-protection-overview",
        ["container soft delete", "basic data protection"],
        "Actual checklist-linked overview recommends enabling container and blob "
        "soft delete separately. Its link on G04.03 is insufficient policy-specific "
        "mapping; supplement it with TLS policy guidance.",
    ),
    (
        "blob-arm",
        LEARN + "azure/templates/microsoft.storage/2023-05-01/storageaccounts/blobservices",
        ["containerDeleteRetentionPolicy", "enabled", "365"],
        "The explicit container retention enabled boolean belongs to the default "
        "blob-service child, not the storage-account or blob-retention flag.",
    ),
    (
        "blob-rest",
        LEARN
        + "rest/api/storagerp/blob-services/get-service-properties?view=rest-storagerp-2023-05-01",
        ["2023-05-01", "containerDeleteRetentionPolicy", "blobServices/default"],
        "Scoped management.azure.com GET retrieves the exact default child. "
        "It is not a storage data-plane call and its omission of container "
        "retention remains unknown.",
    ),
    (
        "storage-tls",
        LEARN + "azure/storage/common/transport-layer-security-configure-minimum-version",
        ["minimumTlsVersion", "Azure Policy"],
        "Local minimum TLS configuration differs from definition/assignment/"
        "effect/parameter/exemption-backed policy enforcement.",
    ),
    (
        "storage-arm",
        LEARN + "azure/templates/microsoft.storage/2023-05-01/storageaccounts",
        ["minimumTlsVersion", "TLS1_0", "TLS1_1", "TLS1_2"],
        "2023-05-01 declares minimum TLS enum values, including TLS1_3 while its "
        "description says 1.3 minimum is unsupported. Only explicit TLS1_0/1/2 "
        "are projected; TLS1_3 stays unknown. Local TLS is not policy enforcement.",
    ),
    (
        "terraform-vault",
        RAW + "website/docs/r/key_vault.html.markdown",
        ["purge_protection_enabled", "soft_delete_retention_days"],
        "AzureRM 4.50.0 exposes purge protection and retention days but no "
        "independent soft-delete enabled attribute.",
    ),
    (
        "terraform-vault-implementation",
        RAW + "internal/services/keyvault/key_vault_resource.go",
        ["EnableSoftDelete: pointer.To(true)", "resourceKeyVaultCreate"],
        "The provider explicitly sets soft delete during creation. That creation-only "
        "fact does not prove imported/updated vault configuration from raw or planned values.",
    ),
    (
        "terraform-storage",
        RAW + "website/docs/r/storage_account.html.markdown",
        ["container_delete_retention_policy", "365"],
        "An explicit single container retention block with valid explicit days "
        "configures container retention; omitted default days are not inferred.",
    ),
    (
        "terraform-storage-implementation",
        RAW + "internal/services/storage/storage_account_resource.go",
        ["container_delete_retention_policy", "ContainerDeleteRetentionPolicy"],
        "Provider expandAccountBlobContainerDeleteRetentionPolicy at lines 2962-2975 "
        "sets Enabled=true and Days for a present block. Only explicit valid "
        "days are projected; omitted defaults are not inferred.",
    ),
]


SOURCES_17 = [
    (
        "subnet-arm",
        LEARN + "azure/templates/microsoft.network/2024-05-01/virtualnetworks/subnets",
        ["addressPrefix", "natGateway", "routeTable"],
        "Explicit IPv4 prefixes and typed "
        "route-table/NAT references are preparable. IPAM allocation, missing/mixed prefix "
        "forms and unavailable joins do not establish capacity or effective routes.",
    ),
    (
        "ipgroup-arm",
        LEARN + "azure/templates/microsoft.network/2024-05-01/ipgroups",
        ["ipAddresses", "string[]"],
        "IP group membership is a string array; only reviewed "
        "IPv4 address/prefix/range values are projected, with bounded lists.",
    ),
    (
        "terraform-ipgroup",
        RAW + "website/docs/r/ip_group.html.markdown",
        ["cidrs", "ip_group_cidr"],
        "4.50.0 cidrs is an optional membership list; absent "
        "cidrs can mean separately managed membership and is not an empty group.",
    ),
    (
        "firewall-premium",
        LEARN + "azure/firewall/premium-features",
        ["Premium", "IDPS", "TLS"],
        "Premium is a deployed SKU capability, not proof "
        "that TLS inspection, IDPS, categories or traffic inspection are enabled.",
    ),
    (
        "firewall-routing",
        LEARN + "azure/virtual-network/virtual-networks-udr-overview",
        ["0.0.0.0/0", "Virtual appliance"],
        "Configured UDRs, association, route selection "
        "and actual next-hop inspection are distinct. Dynamic/effective paths require evidence.",
    ),
    (
        "firewall-logging",
        LEARN + "azure/firewall/firewall-structured-logs",
        ["diagnostic", "resource-specific"],
        "The checklist link redirects to Monitor Azure "
        "Firewall; diagnostic routing and resource-specific destination "
        "are not proof of ingestion.",
    ),
    (
        "firewall-migration",
        LEARN + "azure/firewall-manager/migrate-to-policy",
        ["RuleCollectionGroup", "NatRuleCollections"],
        "Migration converts collections and "
        "associates policy. A policy reference does not prove rule equivalence "
        "or completed migration.",
    ),
    (
        "firewall-subnet",
        LEARN + "azure/firewall/firewall-faq",
        ["/26", "scaling"],
        "FAQ explains /26 scaling capacity; pinned provider guidance "
        "permits /26 or larger and documents a /24 example. Names alone do not identify use.",
    ),
    (
        "firewall-hierarchy",
        LEARN + "azure/firewall-manager/rule-hierarchy",
        ["base policy", "priority"],
        "Inherited collection priority and ownership are relevant; "
        "collection presence does not establish frequency-based organization.",
    ),
    (
        "firewall-ipgroups",
        LEARN + "azure/firewall/ip-groups",
        ["DNAT", "skipped"],
        "Groups support addresses, prefixes and ranges. Empty groups skip "
        "referencing rules; group presence is not utilization, reduction or source restriction.",
    ),
    (
        "firewall-dnat",
        LEARN + "azure/firewall/tutorial-firewall-dnat",
        ["specific source", "wildcards"],
        "Guidance explicitly avoids wildcard DNAT sources "
        "and distinguishes classic configuration from preferred Firewall Policy.",
    ),
    (
        "firewall-snat",
        LEARN + "azure/firewall/integrate-with-nat-gateway",
        ["SNAT", "AzureFirewallSubnet"],
        "NAT association, demand, port allocation, workload "
        "routes and failover evidence are separate. No arbitrary exhaustion threshold is inferred.",
    ),
    (
        "firewall-arm",
        LEARN + "azure/templates/microsoft.network/2024-05-01/azurefirewalls",
        ["managementIpConfiguration", "sourceIpGroups", "Premium"],
        "Versioned SKU tier/name, explicit subnet/policy references and classic NAT structures "
        "are reviewed. Missing values and unexpanded IP Groups are not safe-source evidence.",
    ),
    (
        "terraform-firewall",
        RAW + "website/docs/r/firewall.html.markdown",
        ["sku_tier", "management_ip_configuration", "/26"],
        "4.50.0 declares Basic/Standard/"
        "Premium, exactly one data subnet reference and optional management configuration. "
        "Both subnet kinds need minimum /26 capacity; defaults are not inferred.",
    ),
    (
        "terraform-subnet",
        RAW + "website/docs/r/subnet.html.markdown",
        ["address_prefixes", "ip_address_pool"],
        "4.50.0 supports explicit prefixes or IPAM pool, "
        "not both. IPAM allocation does not establish actual prefixes. Inline/standalone "
        "subnet mixing is unsupported by the provider.",
    ),
    (
        "terraform-nat",
        RAW + "website/docs/r/firewall_nat_rule_collection.html.markdown",
        ["source_addresses", "source_ip_groups", "natRuleCollections"],
        "4.50.0 classic NAT "
        "collections have actual child identities, Dnat/Snat actions and address/group source "
        "alternatives; absent direct addresses do not mean no sources.",
    ),
    (
        "terraform-diagnostics",
        RAW + "website/docs/r/monitor_diagnostic_setting.html.markdown",
        ["Dedicated", "target_resource_id", "enabled_log"],
        "Dedicated is meaningful only with "
        "a workspace; enabled_log and metric blocks differ. Terraform's imported pipe ID "
        "is not an ARM identity and must not be copied as one.",
    ),
]


SOURCES_18 = [
    (
        "premium-inspection-categories",
        LEARN + "azure/firewall/premium-features",
        ["TLS inspection must be enabled at the application rule level", "Web categories"],
        "TLS inspection requires application rules and CA/client trust, not Premium SKU alone. "
        "Current Learn guidance says categories also exist on Standard; the pinned provider's "
        "Premium restriction cannot establish universal SKU applicability.",
    ),
    (
        "gateway-before-firewall",
        LEARN
        + "azure/architecture/example-scenario/gateway/application-gateway-before-azure-firewall",
        ["Host header", "443", "root CA"],
        "Gateway-to-firewall inspection needs matching Host/DNS, port 443, trusted CA and an "
        "actual routed flow. Co-located resources or enabled TLS fields do not prove this chain.",
    ),
    (
        "firewall-backup-operations",
        LEARN + "azure/well-architected/service-guides/azure-firewall",
        ["backup and versioning", "doesn", "Virtual WAN"],
        "Maintain versioned policy/rule backups or a companion backup mechanism. Current "
        "assessment/replay exports are minimized facts, not complete restorable rule backups. "
        "The guidance also excludes Virtual WAN from hub-VNet DDoS-plan recommendations.",
    ),
    (
        "firewall-managed-zone-redundancy",
        LEARN + "azure/firewall/deploy-availability-zone-powershell",
        ["Zone-redundant-by-default", "backward compatibility", "ARM"],
        "The 2026-11-04 revision says omit explicit zones in compatible regions. Backend "
        "migration is not necessarily reflected in ARM/JSON/ARG. Empty or single configured "
        "zone lists cannot establish backend nonredundancy; explicit zone counts are facts only.",
    ),
    (
        "ddos-overview",
        "https://learn.microsoft.com/en-gb/azure/ddos-protection/ddos-protection-overview",
        ["DDoS Network Protection", "DDoS IP Protection", "virtual network"],
        "Network-plan protection and per-IP protection differ. A supplied VNet flag/plan is "
        "configuration evidence, not proof of firewall applicability or mitigation effectiveness.",
    ),
    (
        "injected-service-networking",
        LEARN + "azure/virtual-network/vnet-integration-for-azure-services",
        ["restrictions", "network security groups", "per guidance provided by the service"],
        "Injected services have service-specific subnet, route and NSG requirements. Generic "
        "default-route or NSG presence cannot prove control-plane reachability or breakage.",
    ),
    (
        "private-link-overview",
        LEARN + "azure/private-link/private-link-overview",
        ["ExpressRoute private peering", "Microsoft peering", "availability"],
        "Private Link supports on-premises private-peering access. Service availability, "
        "subresources, DNS and actual routes still require specific evidence; no packet test.",
    ),
    (
        "private-endpoint-overview",
        LEARN + "azure/private-link/private-endpoint-overview",
        ["Approved", "Pending", "DNS configuration", "public network access"],
        "Only approved connections can carry traffic, but approval alone does not establish "
        "DNS, private routing or disabled public access. A Terraform private IP can exist even "
        "for rejected requests; manual=false is not approval evidence.",
    ),
    (
        "vnet-arm",
        LEARN + "azure/templates/microsoft.network/2024-05-01/virtualnetworks",
        ["enableDdosProtection", "ddosProtectionPlan"],
        "Versioned VNet DDoS flag and canonical plan reference are separate typed fields; "
        "missing flags and absent plan data are unknown, not disabled or nonexistent.",
    ),
    (
        "private-endpoint-arm",
        LEARN + "azure/templates/microsoft.network/2024-05-01/privateendpoints",
        ["manualPrivateLinkServiceConnections", "privateLinkServiceConnectionState", "subnet"],
        "Versioned automatic/manual connection arrays contain target IDs and explicit states; "
        "retain only reviewed typed fields, not messages, DNS names, aliases or addresses.",
    ),
    (
        "application-rules-arm",
        LEARN
        + "azure/templates/microsoft.network/2024-05-01/firewallpolicies/rulecollectiongroups",
        ["ApplicationRule", "terminateTLS", "webCategories", "FirewallPolicyFilterRuleCollection"],
        "Application rule TLS booleans and supplied category counts are partial facts only. "
        "Do not retain rule descriptions, headers, destinations or category labels, or infer "
        "policy inheritance, effective ordering or traffic coverage.",
    ),
    (
        "terraform-vnet",
        RAW + "website/docs/r/virtual_network.html.markdown",
        ["ddos_protection_plan", "`enable`", "`id`"],
        "Pinned 4.50.0 explicit DDoS block has required ID and boolean enable. Omitted blocks "
        "do not establish a default. Inline/standalone subnet mixing remains unsupported.",
    ),
    (
        "terraform-private-endpoint",
        RAW + "website/docs/r/private_endpoint.html.markdown",
        ["private_connection_resource_alias", "is_manual_connection", "Rejected"],
        "Pinned 4.50.0 has one explicit service-connection block and target ID or alias. "
        "It does not export approval state; neither manual=false nor private IP proves approval. "
        "Aliases remain unresolved rather than being converted to ARM IDs.",
    ),
    (
        "terraform-application-rules",
        RAW + "website/docs/r/firewall_policy_rule_collection_group.html.markdown",
        ["terminate_tls", "web_categories", "firewall_policy_id"],
        "Pinned 4.50.0 collection action and rule TLS/categories are explicit fields. It "
        "documents Premium requirements that differ from current general feature guidance; "
        "no effective category/SKU or inherited-policy verdict is inferred.",
    ),
    *[
        source
        for source in SOURCES_17
        if source[0] in {"firewall-arm", "terraform-firewall", "subnet-arm", "terraform-subnet"}
    ],
]


SOURCES_19 = [
    (
        "service-endpoint-intent",
        LEARN + "azure/virtual-network/virtual-network-service-endpoints-overview",
        ["subnets independently", "public IP addresses", "network virtual appliance"],
        "Service endpoints are deliberately configured per subnet/service and may bypass an "
        "inspection route. Presence/absence does not establish intent, access restriction or "
        "exfiltration prevention. Current standard-service-endpoint preview is not inferred "
        "from pinned classic provider fields.",
    ),
    (
        "private-endpoint-egress-inspection",
        LEARN + "azure/private-link/inspect-traffic-with-azure-firewall",
        ["flow symmetry", "SNAT", "network policy support"],
        "The checklist relative guidance is resolved to the actual Learn page. FQDN/application "
        "rules, routing, subnet endpoint policies and SNAT symmetry must be reconciled; local "
        "FQDN counts or a private endpoint do not establish an inspected exclusive path.",
    ),
    (
        "gateway-subnet-capacity",
        LEARN + "azure/expressroute/expressroute-howto-add-gateway-resource-manager",
        ["/27 or larger", "16 ExpressRoute circuits", "/26 or larger"],
        "Minimum /27 means capacity at least /27, not exact prefix equality. Sixteen "
        "ExpressRoute circuits require /26 or larger; actual gateway references and workload "
        "requirements matter. No gateway deployment or circuit enumeration is executed.",
    ),
    (
        "virtualnetwork-tag-scope",
        LEARN + "azure/virtual-network/service-tags-overview",
        ["VirtualNetwork", "on-premises address spaces", "default routes"],
        "VirtualNetwork includes connected on-premises, peering, gateway and route prefixes "
        "and can contain default routes. A tag/default allow rule is not an isolation boundary "
        "or proof of effective segmentation.",
    ),
    (
        "landing-zone-segmentation",
        LEARN + "azure/cloud-adoption-framework/ready/azure-best-practices/"
        "plan-for-landing-zone-network-segmentation",
        ["Delegate subnet creation", "deny-only policies", "Virtual WAN"],
        "Subnet ownership is organizational evidence, distinct from PaaS subnet delegations. "
        "NSG/ASG protection needs exact traffic/association/priority context. Virtual WAN "
        "firewall guidance is conditional, not a blanket prohibition of central appliances.",
    ),
    (
        "nsg-effective-processing",
        LEARN + "azure/virtual-network/network-security-group-how-it-works",
        ["Inbound traffic", "Outbound traffic", "Intra-subnet traffic"],
        "Subnet and NIC NSGs interact in direction-specific order, including intra-subnet "
        "traffic. Configured rules/associations do not prove an effective allowed/denied path.",
    ),
    (
        "asg-membership",
        LEARN + "azure/virtual-network/application-security-groups",
        ["same virtual network", "isn't a member", "priority"],
        "ASG rule presence is not membership or enforcement. Source/destination memberships "
        "must be in the applicable same VNet; higher-priority rules and other NSGs matter.",
    ),
    (
        "vnet-flow-log-coverage",
        LEARN + "azure/network-watcher/vnet-flow-logs-overview",
        ["Incompatible services", "FastPath", "same region"],
        "VNet flow-log enabled configuration is not ingestion, supported-workload coverage "
        "or analytics usefulness. Storage/region/unsupported-service and ExpressRoute "
        "FastPath limitations remain human evidence questions; no flow data is read.",
    ),
    (
        "traffic-analytics-pipeline",
        LEARN + "azure/network-watcher/traffic-analytics",
        ["Log Analytics workspace", "raw flow logs", "Availability"],
        "Analytics needs flow data, a compatible workspace/region and actual processing, "
        "not just enabled=true. No workspace logs, permissions or billing are queried.",
    ),
    (
        "network-service-limits",
        LEARN + "azure/azure-resource-manager/management/azure-subscription-service-limits",
        ["Networking limits - Azure Resource Manager", "NSG rules per NSG", "2,000"],
        "Current ARM networking table lists 2,000 NSG rules, whereas the frozen checklist's "
        "900 recommendation cites a 1,000 limit. Keep the explicit checklist target distinct "
        "from current quota and from the separate classic-deployment table.",
    ),
    (
        "nsg-arm",
        LEARN + "azure/templates/microsoft.network/2024-05-01/networksecuritygroups",
        ["securityRules", "SecurityRulePropertiesFormat", "priority"],
        "Explicit declared custom rules are distinct from defaults, child declarations and "
        "complete observed configuration. Required rule fields are protocol/access/priority/"
        "direction. Rule previews must not expose names, descriptions, ports or addresses.",
    ),
    (
        "nsg-get-learn-fallback",
        LEARN
        + "rest/api/virtualnetwork/network-security-groups/get?view=rest-virtualnetwork-2024-05-01",
        ["2026-01-01", "defaultSecurityRules", "securityRules"],
        "The requested 2024-05-01 Learn REST view falls back to 2026-01-01. It is not evidence "
        "for the accepted 2024 GET; the separately pinned actual 2024 swagger supplies that.",
    ),
    (
        "nsg-rest-2024",
        SPEC_RAW + "specification/network/resource-manager/Microsoft.Network/Network/"
        "stable/2024-05-01/networkSecurityGroup.json",
        ["NetworkSecurityGroups_Get", "2024-05-01", "defaultSecurityRules", "securityRules"],
        "The exact 2024 GET returns NetworkSecurityGroup with separate custom/default arrays. "
        "This is not a paginated list. Whole-rule capacity requires a successful original-time "
        "complete custom-rule array, not inline Terraform or declared parent-only lists.",
    ),
    (
        "rest-spec-reuse",
        SPEC_RAW + "LICENSE",
        ["MIT License", "Copyright (c) 2017 Microsoft"],
        "Reviewed MIT reuse terms for the pinned Microsoft REST specification. Retain metadata "
        "and own factual findings only; no substantial upstream schema is redistributed.",
    ),
    (
        "gateway-arm",
        LEARN + "azure/templates/microsoft.network/2024-05-01/virtualnetworkgateways",
        ["gatewayType", "ipConfigurations", "subnet"],
        "Explicit gateway type and IP-configuration subnet IDs identify positive capacity "
        "review links. No resource-name inference, certificate or RADIUS material is retained.",
    ),
    (
        "flow-log-arm",
        LEARN + "azure/templates/microsoft.network/2024-05-01/networkwatchers/flowlogs",
        [
            "targetResourceId",
            "enabledFilteringCriteria",
            "networkWatcherFlowAnalyticsConfiguration",
        ],
        "Versioned fields expose enabled, target/storage/workspace IDs and analytics settings. "
        "The target description says NSG while the same page's VNet example uses a VNet: "
        "validate canonical target type rather than assume VNet coverage. Filters are not "
        "copied and enabled configuration never establishes ingestion.",
    ),
    (
        "terraform-nsg",
        RAW + "website/docs/r/network_security_group.html.markdown",
        ["empty slice", "overwrite rules", "security_rule"],
        "Pinned 4.50.0 allows inline and separately managed rules but warns not to mix them. "
        "Omission does not establish empty configuration. Whole counts remain unknown for "
        "raw/plan rather than assuming all rule resources are represented by one parent.",
    ),
    (
        "terraform-nsg-rule",
        RAW + "website/docs/r/network_security_rule.html.markdown",
        ["network_security_group_name", "source_application_security_group_ids", "priority"],
        "Pinned standalone rule has explicit parent name/group and typed rule/ASG references; "
        "its presence does not establish complete parent rules or effective segmentation.",
    ),
    (
        "terraform-gateway",
        RAW + "website/docs/r/virtual_network_gateway.html.markdown",
        ["subnet_id", "ExpressRoute", "up to 3"],
        "Pinned gateway configuration supports up to three explicit subnet-bearing IP configs. "
        "Keep typed gateway kind/IDs only, never VPN certificates, RADIUS secrets or addresses.",
    ),
    (
        "terraform-flow-log",
        RAW + "website/docs/r/network_watcher_flow_log.html.markdown",
        ["target_resource_id", "workspace_resource_id", "July 30, 2025"],
        "Pinned flow-log fields have explicit target/storage IDs, enabled bool and optional "
        "analytics block. Its NSG example is stale for new deployments after July 2025; "
        "do not recommend creating NSG flow logs or execute provider lifecycle side effects.",
    ),
    *[source for source in SOURCES_17 if source[0] in {"subnet-arm", "terraform-subnet"}],
    *[
        source
        for source in SOURCES_18
        if source[0] in {"terraform-application-rules", "application-rules-arm"}
    ],
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--append-new-sources", action="store_true")
    parser.add_argument("--batch", choices=["01", "17", "18", "19"], default="01")
    args = parser.parse_args()
    target = ROOT / "references" / "recommendation-batches" / f"batch-{args.batch}-sources.json"
    if target.exists() and not args.append_new_sources:
        raise ValueError("Frozen source review exists; do not silently recollect or redate it")
    sources = json.loads(target.read_text("utf-8"))["sources"] if target.exists() else []
    existing = {source["id"]: source for source in sources}
    for identity, url, markers, finding in {
        "01": SOURCES,
        "17": SOURCES_17,
        "18": SOURCES_18,
        "19": SOURCES_19,
    }[args.batch]:
        if identity in existing:
            if existing[identity]["url"] != url:
                raise ValueError("A captured source URL changed; use a new reviewed identity")
            continue
        request = urllib.request.Request(
            url, headers={"User-Agent": "LandingLens-source-review/0.1"}
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            content = response.read(8_000_001)
            resolved = response.url
        if len(content) > 8_000_000:
            raise ValueError("Source acquisition bound exceeded")
        text = content.decode("utf-8")
        if any(marker.lower() not in text.lower() for marker in markers):
            raise ValueError(f"Reviewed marker missing from {identity}; inspect actual source")
        match = re.search(r'<meta name="git_commit_id" content="([^"]+)"', text)
        sources.append(
            {
                "id": identity,
                "url": url,
                "resolved_url": resolved,
                "sha256": hashlib.sha256(content).hexdigest(),
                "retrieved_at": datetime.now(UTC).isoformat(),
                "revision": PROVIDER
                if url.startswith(RAW)
                else SPEC_REVISION
                if url.startswith(SPEC_RAW)
                else match.group(1)
                if match
                else "retrieved-page",
                "finding": finding,
                "reuse": "MPL-2.0 provider: metadata and own factual findings only"
                if url.startswith(RAW)
                else "MIT Microsoft REST specification: metadata and own factual findings only"
                if url.startswith(SPEC_RAW)
                else (
                    "Microsoft Learn attribution: source metadata and own factual findings only; "
                    "no page content redistributed"
                ),
            }
        )
        print(identity, sources[-1]["revision"], sources[-1]["sha256"])
    target.write_text(
        json.dumps({"batch": args.batch, "review_state": "reviewed", "sources": sources}, indent=2)
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
