"""Explicit maintainer capture of batch sources already inspected for intent and semantics."""

import argparse
import hashlib
import json
import re
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

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


SOURCES_11 = [
    (
        "peering-access",
        LEARN + "azure/virtual-network/virtual-network-manage-peering",
        ["allow-vnet-access", "forwarded traffic", "VirtualNetwork"],
        "Explicit allowVirtualNetworkAccess is a per-direction configuration setting, "
        "not reciprocal connectivity, NSG isolation, gateway transit or forwarding proof.",
    ),
    (
        "load-balancer-reliability",
        LEARN + "azure/reliability/reliability-load-balancer",
        ["front-end IP configuration", "back-end instances", "independently"],
        "Zone redundancy belongs to each frontend or its public IP, independently of "
        "backend placement and health. Standard SKU or two supplied backend entries "
        "does not establish operational or regional resilience.",
    ),
    (
        "expressroute-macsec",
        LEARN + "azure/expressroute/expressroute-howto-macsec",
        ["two physical ports", "GcmAesXpn256", "private endpoint"],
        "ExpressRoute Direct has two links. Configured cipher/SCI fields are not negotiated "
        "encryption; key availability, identities, port applicability and both ends require "
        "separate evidence. Never retain CAK/CKN values or secret identifiers.",
    ),
    (
        "vpn-private-peering",
        LEARN + "azure/vpn-gateway/site-to-site-vpn-private-peering",
        ["standard-IP", "same prefixes", "without VPN protection"],
        "Private-IP VPN connections need a functioning private circuit and preferred "
        "encrypted routes in both directions. Equal prefixes can prefer unencrypted "
        "ExpressRoute; a connection or IPsec policy is not encrypted-path proof.",
    ),
    (
        "ip-address-planning",
        LEARN + "azure/cloud-adoption-framework/ready/azure-best-practices/plan-for-ip-addressing",
        ["RFC 1918", "five IP addresses", "overlapping", "IPv6"],
        "Review the complete Azure/on-premises allocation and approved growth requirements. "
        "Local RFC1918 and pairwise IPv4 overlap subchecks do not prove global nonoverlap "
        "or appropriate sizing; IPv6 and NAT remain explicit unsupported context.",
    ),
    (
        "route-rest-2024",
        SPEC_RAW + "specification/network/resource-manager/Microsoft.Network/Network/"
        "stable/2024-05-01/routeTable.json",
        ["RouteTables_Get", "RouteTablePropertiesFormat", "nextHopType"],
        "The pinned GET returns the route table's custom routes separately from effective "
        "BGP/system routing. Only a successful explicit complete observed array can support "
        "the checklist 400 target; child declarations and service tags need no expansion.",
    ),
    (
        "route-arm",
        LEARN + "azure/templates/microsoft.network/2024-05-01/routetables",
        ["routes", "nextHopType", "addressPrefix"],
        "Declared custom routes do not establish completeness when child routes are managed "
        "separately. Next-hop types and count context are retained, not next-hop IPs.",
    ),
    (
        "peering-arm",
        LEARN
        + "azure/templates/microsoft.network/2024-05-01/virtualnetworks/virtualnetworkpeerings",
        ["allowVirtualNetworkAccess", "remoteVirtualNetwork", "allowForwardedTraffic"],
        "Explicit boolean access is distinct from forwarding/transit and remote topology. "
        "Missing boolean is unknown; no portal/provider default is inferred.",
    ),
    (
        "lb-arm",
        LEARN + "azure/templates/microsoft.network/2024-05-01/loadbalancers",
        ["frontendIPConfigurations", "backendAddressPools", "publicIPAddress", "zones"],
        "Frontend zone/public-IP references and bounded supplied backend counts are partial "
        "facts. Unknown memberships, VMSS expansion, probes and public-IP zones need review.",
    ),
    (
        "port-arm",
        LEARN + "azure/templates/microsoft.network/2024-05-01/expressrouteports",
        ["macSecConfig", "cipher", "sciState"],
        "Project bounded per-link cipher/SCI enums only; keys, secret identifiers, router "
        "labels and physical port details are withheld. Configuration is not link encryption.",
    ),
    (
        "connection-arm",
        LEARN + "azure/templates/microsoft.network/2024-05-01/connections",
        ["connectionType", "useLocalAzureIpAddress", "virtualNetworkGateway1"],
        "Connection type/private-IP boolean and canonical gateway IDs support review only; "
        "shared/authorization keys, IKE details and tunnel addresses are not exported.",
    ),
    *[
        (
            "terraform-" + identity,
            RAW + "website/docs/r/" + filename + ".html.markdown",
            markers,
            finding,
        )
        for identity, filename, markers, finding in (
            (
                "route-table",
                "route_table",
                ["route", "route resources", "address_prefix"],
                "Inline and separately managed routes cannot prove a complete custom population.",
            ),
            (
                "peering",
                "virtual_network_peering",
                ["allow_virtual_network_access", "remote_virtual_network_id"],
                "Only explicit per-direction booleans are evaluated.",
            ),
            (
                "load-balancer",
                "lb",
                ["frontend_ip_configuration", "sku", "zones"],
                "Standard SKU and explicit frontend context do not prove "
                "zone or backend resilience.",
            ),
            (
                "backend-pool",
                "lb_backend_address_pool",
                ["loadbalancer_id", "backend_address"],
                "Pool declarations alone cannot count distinct healthy backend instances.",
            ),
            (
                "expressroute-port",
                "express_route_port",
                ["link1", "link2", "macsec_cipher"],
                "Pinned provider supports two link blocks; no cipher default or key is retained.",
            ),
            (
                "gateway-connection",
                "virtual_network_gateway_connection",
                ["local_azure_ip_address_enabled", "virtual_network_gateway_id", "IPsec"],
                "Private-IP intent is not a preferred, working encrypted private-peering path.",
            ),
        )
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


SOURCES_11 += [
    source for source in SOURCES_19 if source[0] in {"network-service-limits", "rest-spec-reuse"}
]
SOURCES_11 += [source for source in SOURCES_18 if source[0] in {"vnet-arm", "terraform-vnet"}]


SOURCES_04 = [
    (
        "rbac-operating-model",
        LEARN + "azure/role-based-access-control/overview",
        ["role definition, and scope", "additive", "deny assignments"],
        "RBAC combines principal, role and scope with inheritance, additive grants, deny "
        "assignments and conditions. An assignment alone cannot establish operating-model "
        "alignment or effective least privilege; no principal identity/membership is inferred.",
    ),
    (
        "managed-identity-adoption",
        LEARN + "entra/identity/managed-identities-azure-resources/overview",
        ["special type", "Service code", "system-assigned", "user-assigned"],
        "Managed identities are special service principals. Attached identity configuration "
        "does not prove application credential use or absence of other service principals. "
        "Retain only explicit type/count context, never principal/tenant IDs or credentials.",
    ),
    (
        "administrative-account-provenance",
        "https://learn.microsoft.com/azure/active-directory/roles/security-planning",
        ["Microsoft accounts", "work or school", "emergency access"],
        "The legacy Azure AD URL redirects to Entra administrator security planning. "
        "Directory userType or an email suffix cannot authenticate an account's original "
        "identity source. Emergency-access exceptions require explicit evidence and decisions.",
    ),
    (
        "group-based-access",
        LEARN + "entra/fundamentals/how-to-manage-groups",
        ["permissions", "nested", "membership"],
        "Group assignment, actual membership/transitivity, role-assignable group constraints "
        "and hybrid source of authority are separate. No group creation, membership expansion "
        "or synchronization is performed; Group principal type is only configuration context.",
    ),
    (
        "conditional-access-enforcement",
        "https://learn.microsoft.com/azure/active-directory/conditional-access/overview",
        ["report-only", "after first-factor", "multifactor authentication"],
        "The legacy URL redirects to Entra. Enabled/report-only, included/excluded users/apps, "
        "grant logic and actual policy evaluation must be reconciled; policy presence or "
        "a successful sign-in alone never proves every Azure user's enforcement.",
    ),
    (
        "mfa-enforcement",
        "https://learn.microsoft.com/azure/active-directory/authentication/concept-mfa-howitworks",
        ["registered", "Conditional Access", "security defaults"],
        "The legacy URL redirects to Entra. Method registration, MFA requirement/enforcement, "
        "authentication strength, prior claims and emergency exceptions differ. Never equate "
        "a registered method, tenant default or one challenge with population coverage.",
    ),
    (
        "central-delegated-responsibilities",
        "https://learn.microsoft.com/azure/cloud-adoption-framework/manage/centralize-operations",
        ["Central (platform)", "Workload", "Assign responsibility"],
        "The legacy page redirects to ready-cloud-operations and separates central/platform "
        "and workload ownership. Role scope alone cannot attest an agreed operating model, "
        "delegation, escalation responsibility or acceptance by accountable owners.",
    ),
    (
        "privilege-eligibility-and-activation",
        "https://learn.microsoft.com/azure/active-directory/privileged-identity-management/pim-configure",
        ["permanent active", "eligible", "time-bound", "activation"],
        "The legacy URL redirects to Entra governance. Eligible and active, permanent and "
        "time-bound grants, approvals/MFA and Azure-versus-directory roles are distinct. "
        "PIM presence is not zero standing access; no grant/activation or directory read occurs.",
    ),
    (
        "role-assignment-arm",
        LEARN + "azure/templates/microsoft.authorization/2022-04-01/roleassignments",
        ["principalType", "roleDefinitionId", "Group", "conditionVersion"],
        "Project explicit principal-type enum and canonical role-definition ID only. No "
        "principal ID, name, account type, role permissions or condition text is retained. "
        "This is local assignment context, not an effective access computation.",
    ),
    (
        "storage-identity-arm",
        LEARN + "azure/templates/microsoft.storage/2023-05-01/storageaccounts",
        ["userAssignedIdentities", "SystemAssigned", "identity"],
        "Storage identity configuration exposes explicit type and user-assigned bindings; "
        "count/type alone cannot establish the consuming workload's authentication. IDs "
        "and arbitrary root identity properties are not exported.",
    ),
    (
        "terraform-role-assignment",
        RAW + "website/docs/r/role_assignment.html.markdown",
        ["principal_type", "role_definition_id", "scope"],
        "Pinned 4.50.0 explicit principal type/definition ID/scope are configuration only. "
        "Role names are not silently resolved and principal IDs or conditions are withheld.",
    ),
    (
        "terraform-storage-identity",
        RAW + "website/docs/r/storage_account.html.markdown",
        ["identity_ids", "SystemAssigned", "UserAssigned"],
        "Pinned storage identity block is optional; missing/symbolic/invalid values do not "
        "become defaults. Count validated supplied user-assigned references without retaining IDs.",
    ),
    *[source for source in SOURCES_11 if source[0] == "terraform-expressroute-port"],
    *[source for source in SOURCES_11 if source[0] == "port-arm"],
]

ALZ_REVISION = "4eae565287844360a61545f9799400431adb6d0a"
POLICY_REVISION = "f096d8de10fb25e71dd7f82b78ded110ec711d73"
ALZ_RAW = f"https://raw.githubusercontent.com/Azure/Azure-Landing-Zones-Library/{ALZ_REVISION}/"
POLICY_RAW = f"https://raw.githubusercontent.com/Azure/azure-policy/{POLICY_REVISION}/"
SOURCES_13 = [
    (
        "frontdoor-waf",
        "https://learn.microsoft.com/azure/web-application-firewall/afds/afds-overview",
        ["Prevention", "Standard", "precedence"],
        "Front Door is global; Standard supports custom rules only. Detection, Prevention, "
        "rule actions, exclusions and profile/domain/route precedence differ. Reviewed "
        "2024 schemas do not expose all newer attachment scopes; no global coverage inferred.",
    ),
    (
        "application-gateway-waf",
        "https://learn.microsoft.com/azure/web-application-firewall/ag/ag-overview",
        ["WAF_v2", "listeners", "path-based"],
        "Gateway/listener/path policies have distinct scope. WAF_v2 supports policy "
        "associations; SKU or a policy reference alone does not establish inspection.",
    ),
    (
        "origin-security",
        LEARN + "azure/frontdoor/origin-security",
        ["AzureFrontDoor.Backend", "X-Azure-FDID", "alone"],
        "Public origins require both Front Door backend address filtering and validation "
        "of the exact profile header. Service tag presence or any header rule alone is "
        "insufficient. Private Link also requires disallowing alternate public paths.",
    ),
    (
        "ddos-architectures",
        "https://learn.microsoft.com/azure/ddos-protection/ddos-protection-reference-architectures",
        ["Unsupported", "NAT Gateway", "Virtual WAN"],
        "Network and per-IP protection differ; reconcile supported endpoints and every "
        "positive association. NAT Gateway and Virtual WAN are unsupported in this source. "
        "Configured protection never establishes mitigation readiness or estate coverage.",
    ),
    (
        "default-outbound-current",
        "https://learn.microsoft.com/azure/virtual-network/ip-services/default-outbound-access",
        ["March 31, 2026", "earlier API", "deallocated", "delegated"],
        "Revision e8c3f408 says APIs released after March 31, 2026 default new VNets to "
        "private subnets; earlier APIs and existing VNets retain prior behavior. This is "
        "not the frozen September 30, 2025 blanket retirement statement. Existing VM "
        "stop/deallocation, managed/delegated-subnet limits and Internet UDR exceptions "
        "need migration planning, never execution. Preserve historical wording.",
    ),
    (
        "default-outbound-announcement",
        "https://azure.microsoft.com/updates/default-outbound-access-for-vms-in-azure-will-be-retired-transition-to-a-new-method-of-internet-access/",
        ["Azure Updates"],
        "The announcement link resolves to the dynamic Azure Updates shell. Captured HTML "
        "does not expose its item timeline, so no independent date verification is claimed; "
        "current scope/date findings are bound to the inspected Learn revision instead.",
    ),
    (
        "ddos-logging-redirect",
        LEARN + "azure/ddos-protection/diagnostic-logging",
        ["diagnostic setting", "categories"],
        "Legacy DDoS logging redirects to a general Azure Monitor resource-log tutorial. "
        "Diagnostic routing and actual ingestion are distinct; use actual IP log reference.",
    ),
    (
        "ddos-log-categories",
        LEARN
        + "azure/azure-monitor/reference/supported-logs/microsoft-network-publicipaddresses-logs",
        ["DDoSMitigationFlowLogs", "DDoSMitigationReports", "DDoSProtectionNotifications"],
        "The public-IP reference lists three exact DDoS categories. Project only their "
        "explicit enabled flags and bounded destination references, never raw log records.",
    ),
    (
        "alz-policy-wiki",
        "https://github.com/Azure/Enterprise-Scale/wiki/ALZ-Policies",
        ["Azure-Landing-Zones", "policy"],
        "The exact checklist wiki is a migration notice, not a current corp policy list. "
        "Follow the central policy site and inspect pinned actual library assignment.",
    ),
    (
        "alz-policy-site",
        "https://azure.github.io/Azure-Landing-Zones/policy/",
        ["preview", "custom", "built-in"],
        "ALZ includes custom and built-in definitions and sometimes preview defaults. "
        "Library presence is not an actual assignment or an enforcement outcome.",
    ),
    (
        "alz-corp",
        ALZ_RAW + "platform/alz/archetype_definitions/corp.alz_archetype_definition.json",
        ["Deny-Public-IP-On-NIC"],
        "Pinned corp explicitly includes Deny-Public-IP-On-NIC, not the separate deny-all "
        "public-IP assignment. Archetype templates are not deployed governance evidence.",
    ),
    (
        "alz-nic-assignment",
        ALZ_RAW
        + "platform/alz/policy_assignments/Deny-Public-IP-On-NIC.alz_policy_assignment.json",
        ["83a86a26-fd1f-447c-b59d-e51f44264114", "Default", "1.*.*"],
        "Actual library assignment binds built-in 83a86a26 version 1.*.* with Default "
        "enforcement, placeholder MG scope and explicit empty notScopes. Validate actual "
        "scope/inheritance/version, overrides/selectors/exemptions independently.",
    ),
    (
        "alz-deny-public-ip",
        ALZ_RAW + "platform/alz/policy_assignments/Deny-Public-IP.alz_policy_assignment.json",
        ["6c112d4e", "listOfResourceTypesNotAllowed", "Deny"],
        "The separate deny resource-types assignment forbids public-IP creation; this is "
        "not equivalent to denying NIC attachments, and is not included in pinned corp.",
    ),
    (
        "builtin-nic-public-ip",
        POLICY_RAW + "built-in-policies/policyDefinitions/Network/NetworkPublicIPNic_Deny.json",
        ["83a86a26", "ipconfigurations[*].publicIpAddress.id", "deny", "1.0.0"],
        "Built-in 83a86a26 version 1.0.0 has Indexed NIC-array alias logic and fixed deny, "
        "no effect parameter. It covers NICs, not just VMs. Saved assignment/exception "
        "context is preparation only; no alias evaluation, trigger or remediation occurs.",
    ),
    (
        "builtin-ddos-logging",
        POLICY_RAW
        + "built-in-policies/policyDefinitions/Monitoring/PublicIpDdosLogging_Audit.json",
        ["752154a7", "DDoSMitigationReports", "AuditIfNotExists"],
        "Built-in 752154a7 version 1.0.1 supports AuditIfNotExists/DeployIfNotExists/Disabled "
        "and has parameter-dependent log/workspace existence logic. Its assignment or "
        "compliance cannot prove whole-population DDoS logging or actual ingestion.",
    ),
    (
        "connectivity-to-azure",
        "https://learn.microsoft.com/azure/cloud-adoption-framework/ready/azure-best-practices/connectivity-to-azure",
        ["primary", "backup", "different peering locations"],
        "CAF recommends primary ExpressRoute, backup VPN and independent circuit "
        "locations, but workload suitability and maintained backup need separate evidence.",
    ),
    (
        "expressroute-backup",
        LEARN + "azure/expressroute/use-s2s-vpn-as-backup-for-expressroute-privatepeering",
        ["not recommended", "active-passive", "more specific"],
        "S2S backup is not recommended for latency-sensitive/mission-critical/bandwidth-"
        "intensive workloads. Equal-prefix preference, more-specific VPN routes, both "
        "directions and active maintenance matter. Presence never establishes failover.",
    ),
    (
        "expressroute-routing",
        "https://learn.microsoft.com/azure/expressroute/expressroute-routing",
        ["private AS", "BGP", "community"],
        "Reconcile private/Microsoft peering, both BGP sessions, prefix limits and route "
        "attributes. Microsoft removes private ASNs on Microsoft peering and does not "
        "honor arbitrary received communities. Never infer preference from BGP enabled.",
    ),
    (
        "expressroute-optimization",
        LEARN + "azure/expressroute/expressroute-optimize-routing",
        ["Local Preference", "AS PATH", "weight"],
        "Customer local preference, AS PATH prepending and Azure connection weight have "
        "different directions/scope. Weight is considered before AS-path length for "
        "Azure outbound; a numeric value alone never establishes the selected route.",
    ),
    (
        "expressroute-sizing",
        "https://learn.microsoft.com/azure/expressroute/expressroute-about-virtual-network-gateways?source=recommendations#gwsku",
        ["ErGwScale", "estimates", "maintenance"],
        "Current ExpressRoute guidance includes scalable SKU and maintenance/private-"
        "endpoint performance limits. Pinned provider lacks ErGwScale; configuration "
        "is not bandwidth demand, effective throughput or regional SKU availability.",
    ),
    (
        "vpn-sizing",
        LEARN + "azure/vpn-gateway/about-gateway-skus",
        ["benchmarks", "Generation2", "migration"],
        "VPN throughput is benchmarked, not guaranteed; generation, algorithm, tunnel/"
        "P2S mix and non-AZ migration matter. No demand or measured performance inferred.",
    ),
    (
        "frontdoor-policy-arm",
        LEARN
        + "azure/templates/microsoft.network/2024-02-01/frontdoorwebapplicationfirewallpolicies",
        ["policySettings", "managedRuleSets", "enabledState"],
        "Reviewed 2024-02-01 exposes mode/enabledState and supplied custom/managed arrays. "
        "Attempted Network 2024-05-01 URL returned 404; it is not an accepted API.",
    ),
    (
        "frontdoor-security-arm",
        LEARN + "azure/templates/microsoft.cdn/2024-02-01/profiles/securitypolicies",
        ["wafPolicy", "associations", "patternsToMatch"],
        "Project typed WAF ID, exact domain/endpoint IDs and explicit all-paths marker "
        "within each supplied association; bounded subset is not profile/route coverage.",
    ),
    (
        "application-gateway-arm",
        LEARN + "azure/templates/microsoft.network/2024-05-01/applicationgateways",
        ["gatewayIPConfigurations", "firewallPolicy", "backendAddresses"],
        "Project explicit gateway subnets, WAF references and bounded configured backend "
        "counts, withholding hostnames/certificates. Placement and exclusivity need review.",
    ),
    (
        "gateway-waf-arm",
        LEARN + "azure/templates/microsoft.network/2024-05-01/"
        "applicationgatewaywebapplicationfirewallpolicies",
        ["negationConditon", "RequestHeaders", "policySettings"],
        "Gateway custom conditions use the actual misspelled negationConditon API key. "
        "Retain header-shape/count/action/priority only, never FDID or other match values.",
    ),
    (
        "public-ip-arm",
        LEARN + "azure/templates/microsoft.network/2024-05-01/publicipaddresses",
        ["ddosSettings", "protectionMode", "ddosProtectionPlan"],
        "IP protection mode and plan binding are distinct. Inherited mode needs actual "
        "supported VNet attachment. Addresses/DNS labels are withheld.",
    ),
    (
        "nic-arm",
        LEARN + "azure/templates/microsoft.network/2024-05-01/networkinterfaces",
        ["publicIPAddress", "virtualMachine", "ipConfigurations"],
        "Supplied IP-configuration/subnet/public-IP and VM references are bounded positive "
        "links only. Missing references are not absence or effective policy enforcement.",
    ),
    (
        "diagnostics-arm",
        LEARN + "azure/templates/microsoft.insights/2021-05-01-preview/diagnosticsettings",
        ["categoryGroup", "logs", "storageAccountId"],
        "Explicit log category flags and typed workspace/storage destination IDs are "
        "configuration only. Extension target comes from actual scope/ID, not resource name.",
    ),
    (
        "connection-weight-implementation",
        RAW + "internal/services/network/virtual_network_gateway_connection_resource.go",
        ["routing_weight", "IntBetween(0, 32000)", "Sensitive"],
        "Actual pinned provider validates connection weight 0..32000 and exposes computed "
        "fields; preserve explicit values only, with shared/authorization keys withheld.",
    ),
    *[
        (
            identity,
            RAW + "website/docs/r/" + resource + ".html.markdown",
            markers,
            finding,
        )
        for identity, resource, markers, finding in [
            (
                "terraform-frontdoor-security",
                "cdn_frontdoor_security_policy",
                ["patterns_to_match", "cdn_frontdoor_domain_id"],
                "Pinned single firewall association nests in security_policies/firewall; "
                "domain active is computed, not defaulted. Profile parent ID is explicit.",
            ),
            (
                "terraform-frontdoor-policy",
                "cdn_frontdoor_firewall_policy",
                ["sku_name", "mode", "managed_rule"],
                "Pinned provider supports Standard/Premium and explicit enabled/mode; missing "
                "custom/managed arrays do not become zero. Rule counts are not blocking efficacy.",
            ),
            (
                "terraform-application-gateway",
                "application_gateway",
                ["gateway_ip_configuration", "firewall_policy_id", "fqdns"],
                "Project explicit subnet/WAF links and supplied address/FQDN counts only; "
                "withhold actual hosts, private addresses, certificates and rule paths.",
            ),
            (
                "terraform-gateway-waf",
                "web_application_firewall_policy",
                ["match_variables", "RequestHeaders", "negation_condition"],
                "Pinned gateway policy supports explicit policy_settings/custom_rules; "
                "header configuration is only a candidate, not verified exact-profile filtering.",
            ),
            (
                "terraform-public-ip",
                "public_ip",
                ["ddos_protection_mode", "ddos_protection_plan_id"],
                "Pinned IP mode defaults are not inferred; explicit mode/plan only. Historical "
                "provider zone prose differs from current guidance, so no resilience verdict.",
            ),
            (
                "terraform-nic",
                "network_interface",
                ["virtual_machine_id", "public_ip_address_id"],
                "Project explicit subnet/public-IP and computed VM links only; raw missing "
                "VM binding remains unknown rather than assuming an unattached interface.",
            ),
        ]
    ],
    *[
        source
        for source in SOURCES_17
        if source[0] in {"subnet-arm", "terraform-subnet", "terraform-diagnostics"}
    ],
    *[source for source in SOURCES_19 if source[0] in {"gateway-arm", "terraform-gateway"}],
    *[
        source
        for source in SOURCES_11
        if source[0] in {"connection-arm", "terraform-gateway-connection"}
    ],
]


SOURCES_12 = [
    (
        "site-recovery-addresses",
        "https://learn.microsoft.com/azure/site-recovery/concepts-on-premises-to-azure-networking#retain-ip-addresses",
        ["Retain IP addresses", "entire subnet", "address overlap"],
        "IP retention is possible but overlapping simultaneously connected sites cannot use "
        "VPN/ExpressRoute. Whole-subnet failover, route changes and DNS updates need an "
        "approved original-time plan; local prefix comparisons are not a complete DR inventory.",
    ),
    (
        "public-ip-zones",
        "https://learn.microsoft.com/azure/virtual-network/ip-services/public-ip-addresses#availability-zone",
        ["formerly", "no zones", "Standard v2"],
        "Current guidance makes formerly non-zonal Standard IPs zone-redundant in supported "
        "regions; empty zones alone cannot fail. Standard v2 is currently NAT Gateway v2 only "
        "and absent from the reviewed 2024 ARM/provider enum. Region, API and actual service "
        "compatibility require review; IP zone configuration is not backend resilience.",
    ),
    (
        "private-dns-quickstart",
        "https://learn.microsoft.com/azure/dns/private-dns-getstarted-portal",
        ["global resource", "autoregistration", "virtual network link"],
        "Zone/link configuration prepares Azure-only design review, not delegation or actual "
        "resolution. Global zones can link multiple regions; custom DNS and Resolver paths differ.",
    ),
    (
        "resolver-overview",
        "https://learn.microsoft.com/azure/dns/dns-private-resolver-overview",
        ["1000", "/28", "/24", "encryption", "6"],
        "Resolver/VNet must share region; endpoints require separate exclusively delegated "
        "IPv4 subnets /24 through /28. No encrypted VNet, IPv6, FastPath or cross-tenant "
        "ruleset linking. Current limits: 5 endpoints each direction, 2 outbound endpoints "
        "per ruleset, 1000 rules, 500 links and 6 target DNS servers per rule.",
    ),
    (
        "workload-dns",
        "https://learn.microsoft.com/azure/virtual-network/virtual-networks-name-resolution-for-vms-and-role-instances",
        ["DNS suffix", "Customer-managed", "App Service"],
        "Workload/service-specific DNS choice, suffixes and authoritative zones remain manual. "
        "Azure-provided DNS is VNet scoped; custom DNS bypasses the default resolution path.",
    ),
    (
        "autoregistration",
        "https://learn.microsoft.com/azure/dns/private-dns-autoregistration",
        ["primary", "only one", "PTR"],
        "Auto-registration applies only to VM primary NIC A records, one registration zone "
        "per VNet, not private endpoints, load balancers or PTR records. An enabled link is "
        "a literal partial fact, not correct lifecycle or universally required configuration.",
    ),
    (
        "multi-region-dns",
        "https://learn.microsoft.com/azure/cloud-adoption-framework/ready/azure-best-practices/private-link-and-dns-integration-at-scale#private-link-and-dns-integration-in-hub-and-spoke-network-architectures",
        ["multiple regions", "manual maintenance", "lifecycle"],
        "Regional private endpoints and service-specific failover DNS need explicit record "
        "lifecycle/ownership and original-time tests. Global zone or multiple links alone "
        "is not an approved multi-region failover strategy.",
    ),
    (
        "windows-65330",
        "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/"
        "unmasking-dns-timeouts-the-hidden-culprit-in-azure-virtual-networks/4250444",
        ["65330", "Source", "Disclaimer", "65530"],
        "Article concerns reserved ephemeral UDP SOURCE port 65330 on Windows hosts/containers, "
        "not DNS destination port 53. Intro also says 65530 and its probability arithmetic "
        "is not adopted. Unsupported AS-IS sample commands are not executed or redistributed. "
        "IaC DNS/NSG configuration does not establish guest exclusions or full host coverage.",
    ),
    (
        "bastion-overview",
        "https://learn.microsoft.com/azure/bastion/bastion-overview",
        ["Developer", "Premium", "private-only"],
        "Developer is shared dev/test infrastructure; dedicated Basic/Standard/Premium use "
        "AzureBastionSubnet, while Premium private-only has no public IP. Configuration "
        "cannot prove effective secure access, permitted identity or blocked bypass.",
    ),
    (
        "bastion-faq",
        "https://learn.microsoft.com/azure/bastion/bastion-faq#subnet",
        ["November 2, 2021", "UDR", "national clouds", "force-tunneling"],
        "New dedicated deployments require /26 or larger; pre-2021-11-02 /27 is grandfathered. "
        "UDRs/default-route force tunneling, exact internal DNS zone collisions, national "
        "cloud DNS and cross-tenant peering need separate review. FAQ IPv4-only wording "
        "differs from newer configuration preview; do not silently accept dual-stack.",
    ),
    (
        "bastion-settings",
        LEARN + "azure/bastion/configuration-settings",
        ["Private-only", "Static", "IPv6 dual stack", "preview"],
        "Developer/private-only are public-IP exceptions; dedicated subnet requirements "
        "remain. Premium recording and Standard-or-higher connection features are explicit "
        "flags only. Newer dual-stack preview and zone preview vary from FAQ/old schemas.",
    ),
    (
        "resolver-endpoints",
        LEARN + "azure/dns/private-resolver-endpoints-rulesets",
        ["loop", "168.63.129.16", "500", "same region"],
        "Ruleset links are regional, need no peering, and outbound endpoints must share "
        "a resolver. Longest-suffix/ordered-target processing, public wildcard resolution, "
        "inbound-loop avoidance and linked authoritative zones need separate evidence. "
        "Azure-provided DNS cannot be a forwarding target; dynamic inbound IP can change "
        "on reprovisioning. No domain names or raw target addresses are retained.",
    ),
    (
        "vnet-reserved-port",
        LEARN + "azure/virtual-network/virtual-networks-faq",
        ["65330", "UDP"],
        "VNet FAQ independently identifies reserved UDP port 65330. This is advisory "
        "source evidence, not permission for a guest probe or OS exclusion change.",
    ),
    *[
        (identity, LEARN + "azure/templates/microsoft.network/" + path, markers, finding)
        for identity, path, markers, finding in [
            (
                "private-zone-arm",
                "2024-06-01/privatednszones",
                ["PrivateZoneProperties"],
                "Reviewed zone schema has no configurable record inventory or delegation verdict.",
            ),
            (
                "private-link-arm",
                "2024-06-01/privatednszones/virtualnetworklinks",
                ["registrationEnabled", "resolutionPolicy", "NxDomainRedirect"],
                "Explicit typed VNet link, registration boolean and resolution policy. Public "
                "fallback applies only to Private Link zone A/AAAA/CNAME NXDOMAIN; "
                "not resolution proof.",
            ),
            (
                "resolver-arm",
                "2022-07-01/dnsresolvers",
                ["virtualNetwork", "SubResource"],
                "Immutable typed VNet reference and root region, not effective hybrid resolution.",
            ),
            (
                "inbound-arm",
                "2022-07-01/dnsresolvers/inboundendpoints",
                ["privateIpAllocationMethod", "ipConfigurations"],
                "Bounded configured subnet/allocation summaries only; "
                "private endpoint IP withheld.",
            ),
            (
                "outbound-arm",
                "2022-07-01/dnsresolvers/outboundendpoints",
                ["subnet"],
                "Explicit endpoint subnet reference; outbound endpoint has no inbound VIP.",
            ),
            (
                "ruleset-arm",
                "2022-07-01/dnsforwardingrulesets",
                ["dnsResolverOutboundEndpoints"],
                "Typed positive outbound endpoint relationships, not exhaustive rules or links.",
            ),
            (
                "forwarding-rule-arm",
                "2022-07-01/dnsforwardingrulesets/forwardingrules",
                ["forwardingRuleState", "domainName", "targetDnsServers"],
                "Literal state and minimized domain/target shape; no records/raw destinations "
                "or inference of precedence, loop freedom or destination responsiveness.",
            ),
            (
                "ruleset-link-arm",
                "2022-07-01/dnsforwardingrulesets/virtualnetworklinks",
                ["virtualNetwork", "metadata"],
                "Typed VNet relationship only; arbitrary metadata is withheld.",
            ),
            (
                "bastion-arm",
                "2024-05-01/bastionhosts",
                ["enablePrivateOnlyBastion", "Developer", "scaleUnits"],
                "Explicit SKU/private-only/connection/recording flags and typed subnet/public-IP "
                "links, 2..50 scale units. FQDN/ACL raw addresses withheld; no access verdict.",
            ),
        ]
    ],
    *[
        (identity, RAW + "website/docs/r/" + resource + ".html.markdown", markers, finding)
        for identity, resource, markers, finding in [
            (
                "terraform-private-zone",
                "private_dns_zone",
                ["soa_record"],
                "Zone resource does not establish delegation, DNS records or service suitability.",
            ),
            (
                "terraform-private-link",
                "private_dns_zone_virtual_network_link",
                ["registration_enabled", "resolution_policy", "2024-06-01"],
                "Explicit booleans/policy only; omitted registration false default "
                "is not inferred.",
            ),
            (
                "terraform-resolver",
                "private_dns_resolver",
                ["virtual_network_id", "2022-07-01"],
                "Typed VNet and literal location, no provider creation or runtime execution.",
            ),
            (
                "terraform-inbound",
                "private_dns_resolver_inbound_endpoint",
                ["ip_configurations", "private_ip_allocation_method"],
                "Provider has one configuration block. Missing Dynamic default is not inferred; "
                "private_ip_address withheld.",
            ),
            (
                "terraform-outbound",
                "private_dns_resolver_outbound_endpoint",
                ["subnet_id"],
                "Typed parent/subnet references; exclusive subnet population remains unverified.",
            ),
            (
                "terraform-ruleset",
                "private_dns_resolver_dns_forwarding_ruleset",
                ["private_dns_resolver_outbound_endpoint_ids"],
                "Up to two explicitly typed endpoint references; no automatic "
                "inventory completeness.",
            ),
            (
                "terraform-forwarding-rule",
                "private_dns_resolver_forwarding_rule",
                ["domain_name", "enabled", "target_dns_servers"],
                "Explicit enabled value only, not default true. Target ports/IPv4 shape minimized; "
                "namespace and IPs withheld.",
            ),
            (
                "terraform-ruleset-link",
                "private_dns_resolver_virtual_network_link",
                ["dns_forwarding_ruleset_id", "virtual_network_id"],
                "Typed parent and VNet links; supplied metadata withheld.",
            ),
            (
                "terraform-bastion",
                "bastion_host",
                ["Developer", "Premium", "session_recording_enabled", "2024-01-01"],
                "Provider 4.50 supports four SKUs but lacks private-only input. Its /27 example "
                "differs from /26 notes/current requirements. Do not infer Basic, false flags, "
                "2 scale units or public-only defaults. Readable dns_name withheld.",
            ),
        ]
    ],
    *[source for source in SOURCES_13 if source[0] in {"public-ip-arm", "terraform-public-ip"}],
    *[source for source in SOURCES_17 if source[0] in {"subnet-arm", "terraform-subnet"}],
    (
        "learn-terms",
        LEARN + "legal/termsofuse",
        ["Documents", "AS IS"],
        "Keep attribution, links, exact hashes and own factual findings, not copied Learn pages.",
    ),
    (
        "microsoft-terms",
        "https://www.microsoft.com/en-us/legal/terms-of-use",
        ["Non-Commercial", "Documents", "copyright"],
        "TechCommunity remains linked advisory evidence; no article, comments or unsupported "
        "sample scripts redistributed. Site terms are not a software execution authorization.",
    ),
    (
        "provider-license",
        RAW + "LICENSE",
        ["Mozilla Public License Version 2.0"],
        "Pinned provider is MPL-2.0; use metadata/own schema findings, not copied source code.",
    ),
    (
        "vnet-dns-arm",
        LEARN + "azure/templates/microsoft.network/2024-05-01/virtualnetworks",
        ["dnsServers", "encryption", "enabled"],
        "Explicit DNS server list count and encryption boolean, with no server IPs retained. "
        "Missing DNS list cannot establish use of default DNS.",
    ),
    (
        "terraform-rule-implementation",
        RAW
        + "internal/services/privatednsresolver/private_dns_resolver_forwarding_rule_resource.go",
        ["expandTargetDnsServerModel", "Default:  true", "Port:"],
        "Provider stores explicit enabled/target list; port has no reviewed default 53. "
        "Omitted/zero/invalid port remains unknown, never silently rewritten.",
    ),
    (
        "terraform-bastion-implementation",
        RAW + "internal/services/network/bastion_host_resource.go",
        ["MaxItems: 1", "IntBetween(2, 50)", "DisableCopyPaste", "Developer"],
        "One IP block, 2..50 units, copy-paste boolean inversion and SKU-conditioned features "
        "are verified. No private-only schema field; never infer false from its absence.",
    ),
    (
        "private-zone-links",
        LEARN + "azure/dns/private-dns-virtual-network-links",
        ["Completed", "one registration zone", "classic"],
        "Only one link per zone/VNet; link completion is distinct from provisioning and "
        "actual resolution. Missing/transient statuses remain unverified.",
    ),
    (
        "terraform-vnet-dns",
        RAW + "website/docs/r/virtual_network.html.markdown",
        ["dns_servers", "enforcement", "virtual_network_dns_servers"],
        "Explicit supplied DNS count only; separately managed DNS-server resources remain "
        "unknown. Encryption block exposes enforcement, not an independent enabled boolean.",
    ),
]


SOURCES_14 = [
    (
        "scalable-gateway",
        LEARN + "azure/expressroute/scalable-gateway",
        ["maximum scale unit", "40", "fixed scaling", "West Europe"],
        "ErGwScale bounds are 1-40; min=1 requires fixed max=1 and autoscale min starts at 2. "
        "Private Link workloads should use fixed scaling; IPsec over ExpressRoute is unsupported. "
        "The current source lists region exclusions including West Europe, "
        "not blanket availability. Configured minimum>=10 is a FastPath prerequisite subcheck, "
        "not actual scale or performance.",
    ),
    (
        "expressroute-cost",
        "https://learn.microsoft.com/azure/expressroute/plan-manage-cost",
        ["Unlimited data plan", "monthly port fee", "Global Reach"],
        "Local includes unlimited data; Standard/Premium offer different plans. Circuit, "
        "gateway, Direct port, outbound transfer, Global Reach and provider charges must be "
        "reconciled with actual demand and prices. No universal break-even threshold exists.",
    ),
    (
        "expressroute-local",
        "https://learn.microsoft.com/azure/expressroute/expressroute-faqs#expressroute-local",
        ["What is ExpressRoute Local", "peering location", "unlimited"],
        "Local reach is tied to the actual peering location's supported nearby Azure regions, "
        "not the circuit resource location or a Local SKU alone. FAQ Direct bandwidth text "
        "lags the dedicated Direct page's conditional 400-Gbps offering.",
    ),
    (
        "expressroute-gateway",
        "https://learn.microsoft.com/azure/expressroute/expressroute-about-virtual-network-gateways",
        ["ErGwScale", "minimum 10 scale units", "auto-assigned"],
        "Gateway performance values are estimates, not measured demand or throughput. "
        "ErGwScale FastPath requires at least ten scale units; new auto-assigned public-IP "
        "behavior differs from existing zonal deployments. SKU text cannot prove resilience.",
    ),
    (
        "hybrid-demand-and-isolation",
        "https://learn.microsoft.com/azure/cloud-adoption-framework/ready/azure-best-practices/connectivity-to-azure",
        ["higher than 10 Gbps", "routing domain", "share the bandwidth"],
        "The checklist's >10-Gbps/latency/dedicated-port triggers require actual requirements. "
        "VNets sharing a circuit share routing domain/bandwidth; different circuit declarations "
        "alone cannot establish effective isolation or absence of shared port contention.",
    ),
    (
        "fastpath",
        "https://learn.microsoft.com/azure/expressroute/about-fastpath",
        ["minimum of 10 scale units", "limited general availability", "25,000"],
        "Provider circuits support IPv4 hub FastPath; Direct adds conditional peering, UDR, "
        "IPv6 and enrolled limited-GA Private Link scenarios. Same-region/topology/service and "
        "port-cumulative IP limits apply; exhaustion/fallback routes through the gateway. "
        "Virtual WAN Direct defaults require five scale units and are a distinct resource model.",
    ),
    (
        "zone-gateway-creation",
        "https://learn.microsoft.com/azure/vpn-gateway/create-zone-redundant-vnet-gateway",
        ["For zonal gateways", "All gateway instances", "Standard"],
        "AZ SKU permits zonal as well as zone-redundant deployments. Public-IP configuration, "
        "deployment history and actual supported region are required, not a substring test. "
        "No creation, migration, public-IP fetch or regional API read is performed.",
    ),
    (
        "onprem-vpn-redundancy",
        "https://learn.microsoft.com/azure/vpn-gateway/vpn-gateway-highlyavailable",
        ["Multiple on-premises VPN devices", "BGP is required", "ECMP"],
        "Azure active-active is not on-premises appliance redundancy. Multiple-device designs "
        "require distinct device/connection bindings and appropriate BGP/ECMP/failover evidence; "
        "two local gateway records or tunnels cannot count real independent appliances.",
    ),
    (
        "expressroute-direct",
        "https://learn.microsoft.com/azure/expressroute/expressroute-erdirect-about",
        ["400-Gbps", "limited ExpressRoute peering locations", "QinQ", "billing type"],
        "Direct now documents dual 10/100/400-Gbps ports; 400 Gbps is location/enrollment "
        "conditional. Local/Standard/Premium, port billing and VLAN encapsulation remain "
        "distinct. QinQ/Dot1Q configuration is not tested routing isolation or cost suitability.",
    ),
    (
        "expressroute-architecture",
        "https://learn.microsoft.com/azure/architecture/framework/services/networking/expressroute/reliability",
        ["ExpressRoute", "service providers", "reliability testing"],
        "The legacy reliability URL redirects to the current Well-Architected service guide. "
        "Reconcile circuit, path, provider, peering-site and gateway failure domains and "
        "business requirements; configuration/SKU/association evidence alone is not resilience.",
    ),
    (
        "gateway-reliability",
        LEARN + "azure/reliability/reliability-virtual-network-gateway",
        ["might not be zone redundant", "ErGwScale", "Public IP addresses"],
        "New supported gateways can be automatically zone redundant while existing resources "
        "might not be. ExpressRoute ErGwScale is AZ-capable despite lacking AZ in its name. "
        "VPN public IPs must be Standard and zone redundant; "
        "operational topology remains separate.",
    ),
    (
        "expressroute-locations",
        LEARN + "azure/expressroute/expressroute-locations-providers",
        ["two distinct", "East US", "Seattle", "Local"],
        "Circuit resource region and physical peering location are different. The reviewed "
        "public table is not live inventory, admission or regional availability evidence; "
        "review exact Local target-region mapping and Direct port availability separately.",
    ),
    (
        "circuit-arm",
        LEARN + "azure/templates/microsoft.network/2024-05-01/expressroutecircuits",
        ["bandwidthInGbps", "bandwidthInMbps", "expressRoutePort", "family"],
        "Pinned ARM exposes explicit tier/family, provider Mbps versus Direct Gbps, port "
        "reference and rate-limit flag. The generated page labels circuit Gbps int while "
        "the exact REST schema says number; retain finite numeric facts "
        "without claiming eligibility.",
    ),
    (
        "circuit-rest-2024",
        SPEC_RAW + "specification/network/resource-manager/Microsoft.Network/Network/"
        "stable/2024-05-01/expressRouteCircuit.json",
        ['"type": "number"', "ExpressRouteCircuitSku", "enableDirectPortRateLimit"],
        "Exact GET/schema distinguishes circuit bandwidth number, provider integer Mbps, "
        "SKU enums and port reference. Secret/service keys, addresses, stats "
        "and notes are excluded.",
    ),
    (
        "port-rest-2024",
        SPEC_RAW + "specification/network/resource-manager/Microsoft.Network/Network/"
        "stable/2024-05-01/expressRoutePort.json",
        ["billingType", "bandwidthInGbps", "QinQ"],
        "Port bandwidth is integer; billing and encapsulation are independent enums. "
        "No arbitrary service keys, link identities, rack/interface values or secret references "
        "are included in the cost/capacity facts.",
    ),
    (
        "gateway-rest-2024",
        SPEC_RAW + "specification/network/resource-manager/Microsoft.Network/Network/"
        "stable/2024-05-01/virtualNetworkGateway.json",
        ["expressRouteGatewayBypass", "enablePrivateLinkFastPath", "autoScaleConfiguration"],
        "Pinned gateway/connection schema supports explicit bypass/Private Link booleans "
        "and autoscale bounds. Omitted defaults, current scale, deployed zone population and "
        "working routes are not inferred. Reuse merged predecessor gateway/connection helpers.",
    ),
    *[
        source
        for source in SOURCES_11
        if source[0]
        in {
            "port-arm",
            "connection-arm",
            "terraform-expressroute-port",
            "terraform-gateway-connection",
        }
    ],
    (
        "terraform-circuit",
        RAW + "website/docs/r/express_route_circuit.html.markdown",
        ["bandwidth_in_gbps", "bandwidth_in_mbps", "conflict", "rate_limiting_enabled"],
        "AzureRM 4.50.0 distinguishes mutually exclusive provider and Direct fields. Explicit "
        "single SKU block is required; Basic is an enum, not a justified regional/cost option. "
        "No migration, provider execution or service-key retention occurs.",
    ),
    (
        "terraform-gateway",
        RAW + "website/docs/r/virtual_network_gateway.html.markdown",
        ["active_active", "ErGw3AZ", "public_ip_address_id"],
        "Pinned provider documents active-active and IP-config references but no ErGwScale "
        "or autoscale field. Do not infer support from the newer ARM schema or invent a "
        "Terraform scale block. Missing defaults remain unknown; reuse predecessor helpers.",
    ),
    (
        "gateway-arm",
        LEARN + "azure/templates/microsoft.network/2024-05-01/virtualnetworkgateways",
        ["autoScaleConfiguration", "ErGwScale", "publicIPAddress"],
        "ARM supports explicit autoscale min/max and gateway SKU/public-IP/subnet references. "
        "Configured bounds do not measure actual scale or verify zone-redundant placement. "
        "Pinned Terraform documentation does not expose the same autoscale capability.",
    ),
    (
        "rest-spec-reuse",
        SPEC_RAW + "LICENSE",
        ["MIT", "Microsoft"],
        "Pinned Microsoft REST schemas are MIT licensed; retain metadata and own factual findings.",
    ),
    (
        "provider-reuse",
        RAW + "LICENSE",
        ["Mozilla Public License Version 2.0", "HashiCorp"],
        "Pinned provider is MPL-2.0. No provider source, page content or licensed implementation "
        "is redistributed in the preparation; retain attribution, hashes and own factual findings.",
    ),
    (
        "learn-reuse",
        LEARN + "legal/termsofuse",
        ["Notice Specific to Documents", "explicit license terms", "informational"],
        "Learn's general document reuse terms are constrained and explicit document licenses "
        "can govern separately. Retain URL/revision/hash attribution and own factual findings "
        "only; no Microsoft page text, graphics, layouts or assets are redistributed.",
    ),
]


SOURCES_22 = [
    (
        "sovereign-external-keys",
        LEARN
        + "industry/sovereign-cloud/sovereign-public-cloud/capabilities/external-key-management",
        ["external", "proxy", "availability"],
        "Legacy sovereign guidance redirects to Azure sovereign clouds. Managed HSM keys "
        "and external customer-operated HSM KEK custody differ; EKM requires a hard "
        "physical-custody mandate and introduces proxy/HSM availability responsibilities.",
    ),
    (
        "hsm-overview",
        LEARN + "azure/key-vault/managed-hsm/overview",
        ["cryptographic keys", "single-tenant", "external key"],
        "Managed HSM is a cryptographic-key service. Its presence or public-network "
        "configuration cannot prove key use, external custody or sovereign suitability.",
    ),
    (
        "hsm-object-types",
        LEARN + "azure/key-vault/general/about-keys-secrets-certificates",
        ["Secrets", "Not supported", "Managed HSM"],
        "Managed HSM supports HSM-protected keys, not secrets, certificates or storage "
        "account keys. Frozen G02.13 secrets/credentials wording is not current capability.",
    ),
    (
        "hsm-ekm-architecture",
        LEARN + "azure/key-vault/managed-hsm/external-key-management-overview",
        ["generally available", "preview", "No end-to-end", "KEK"],
        "EKM is GA; Private Link integration is preview. External KEK never leaves the "
        "external HSM; unwrap returns the DEK to the service. Compatible CMK services, "
        "mTLS, proxy operations, costs and end-to-end SLA exclusions require human review.",
    ),
    (
        "entra-audit-reporting",
        "https://learn.microsoft.com/azure/active-directory/reports-monitoring/overview-reports",
        ["Audit logs", "Sign-in logs", "Provisioning logs"],
        "Legacy AAD link redirects to Entra monitoring and health. Directory audit, "
        "sign-in and provisioning logs answer different questions; Azure activity "
        "diagnostics or role assignments do not prove an access-control audit report.",
    ),
    (
        "activity-export",
        "https://learn.microsoft.com/azure/azure-monitor/logs/logs-data-export?tabs=portal",
        ["new data", "12 hours", "discarded"],
        "Workspace export covers selected tables' new arrivals, not historical data. "
        "Unavailable destinations can cause discarded records after retries; configuration "
        "does not prove successful ingestion/export, completeness, retention or low cost.",
    ),
    (
        "activity-log",
        LEARN + "azure/azure-monitor/essentials/activity-log",
        ["90 days", "control plane", "diagnostic setting"],
        "Activity log retains management events for 90 days by default; resource/data-plane "
        "and Entra audit records differ. Subscription diagnostics and destinations are "
        "partial routing facts, not delivered retention or complete subscription coverage.",
    ),
    (
        "log-retention",
        LEARN + "azure/azure-monitor/logs/data-retention-configure",
        ["12 years", "total retention", "particular table"],
        "Current total table retention supports up to 12 years; analytics and total "
        "retention differ. Per-table overrides, privacy obligations, search/recovery "
        "and storage lifecycle/immutability require review, not an invented minimum.",
    ),
    (
        "defender-cspm",
        "https://learn.microsoft.com/azure/defender-for-cloud/concept-cloud-security-posture-management",
        ["Foundational CSPM", "Defender CSPM", "billable"],
        "Foundational and paid Defender CSPM differ; billable types are not the whole "
        "protection population. Feature components, connectors, exclusions and regional "
        "support require evidence beyond a CloudPosture Standard pricing record.",
    ),
    (
        "defender-servers",
        "https://learn.microsoft.com/azure/defender-for-cloud/plan-defender-for-servers-select-plan",
        ["Plan 1", "Plan 2", "resource level"],
        "Servers P1/P2 differ. Subscription recommendation has resource-level opt-outs "
        "and P1 overrides; plan configuration is not every server's protection or health.",
    ),
    (
        "defender-workloads",
        "https://learn.microsoft.com/azure/defender-for-cloud/connect-azure-subscription",
        ["workload protection", "coverage workbook", "paid plans"],
        "Workload plans and their required monitoring components differ. Review actual "
        "subscription/resource coverage and workload suitability, not the count of "
        "pricing records, a trial, or an Enable all description as runtime proof.",
    ),
    (
        "endpoint-protection",
        "https://learn.microsoft.com/mem/configmgr/protect/deploy-use/endpoint-protection",
        ["Configuration Manager", "antimalware", "monitor compliance"],
        "Legacy MEM URL redirects to Intune Configuration Manager. Installed antivirus, "
        "antimalware policy assignment, MDE onboarding, EDR and actual enforced endpoint "
        "health are distinct. Plan/agent presence is not enforcement.",
    ),
    (
        "legacy-security-center",
        "https://learn.microsoft.com/azure/security-center/",
        ["Defender for Cloud", "Workload protection"],
        "Legacy Security Center URL redirects to the Defender documentation landing page, "
        "not a patch-drift predicate. Supplement with current Update Manager guidance.",
    ),
    (
        "patch-assessment",
        LEARN + "azure/defender-for-cloud/enable-periodic-system-updates",
        ["Azure Update Manager", "deprecated", "Plan 2"],
        "Defender update recommendations use Update Manager; old MMA collection is "
        "deprecated. Explicit periodic-assessment mode is not successful assessment, "
        "missing-update compliance, alert routing or an approved patch-drift tolerance.",
    ),
    (
        "pricing-arm",
        LEARN + "azure/templates/microsoft.security/2024-01-01/pricings",
        ["pricingTier", "subPlan", "enforce", "isEnabled"],
        "2024-01-01 has scope-local tier/subplan and string True/False extension/enforce "
        "fields. Do not coerce booleans or infer an omitted subplan, coverage or cost.",
    ),
    (
        "pricing-rest",
        SPEC_RAW + "specification/security/resource-manager/Microsoft.Security/Security/"
        "stable/2024-01-01/pricings.json",
        ["resourcesCoverageStatus", "misalignment", "additionalExtensionProperties"],
        "Pinned REST explicitly distinguishes subscription plan status from resource "
        "coverage. Retain allowlisted configuration only; exclude arbitrary extension "
        "properties, exclusion tags, operation messages and protection-health claims.",
    ),
    (
        "hsm-arm",
        LEARN + "azure/templates/microsoft.keyvault/2024-11-01/managedhsms",
        ["publicNetworkAccess", "enablePurgeProtection", "initialAdminObjectIds"],
        "Project explicit public-network/purge settings only; admin/tenant identities, "
        "security domains, credentials and key URIs are withheld. No activation is performed.",
    ),
    (
        "diagnostic-arm",
        LEARN + "azure/templates/microsoft.insights/2021-05-01-preview/diagnosticsettings",
        ["categoryGroup", "enabled", "workspaceId", "storageAccountId"],
        "Explicit category/group plus boolean enabled and typed destinations are routing "
        "configuration. Metrics, empty/invalid arrays or storage retentionPolicy cannot "
        "establish activity export, delivered ingestion or retention adequacy.",
    ),
    (
        "vm-patch-rest",
        SPEC_RAW + "specification/compute/resource-manager/Microsoft.Compute/Compute/"
        "stable/2024-07-01/computeRPCommon.json",
        ["LinuxPatchSettings", "assessmentMode", "AutomaticByPlatform", "Manual"],
        "Linux and Windows patch-mode enums differ. Only one explicit OS configuration "
        "and its assessment/patch enums and agent boolean are projected; osProfile "
        "credentials, custom data, SSH material and OS compliance records are withheld.",
    ),
    (
        "terraform-pricing",
        RAW + "website/docs/r/security_center_subscription_pricing.html.markdown",
        ["CloudPosture", "subplan", "extension", "2023-01-01"],
        "Pinned AzureRM 4.50.0 uses pricing API 2023-01-01, explicit tier/resource_type/"
        "subplan and extension blocks; do not infer its default VirtualMachines target.",
    ),
    (
        "terraform-pricing-implementation",
        RAW + "internal/services/securitycenter/security_center_subscription_pricing_resource.go",
        ["extensionStatuses[input", "IsEnabledTrue", "only keep enabled extensions"],
        "Pinned expand sets supplied named extensions True; read flattens enabled ones "
        "only. No absent extension becomes disabled, no omitted defaults are projected, "
        "and arbitrary additional properties remain withheld.",
    ),
    (
        "terraform-hsm",
        RAW + "website/docs/r/key_vault_managed_hardware_security_module.html.markdown",
        ["public_network_access_enabled", "security_domain_encrypted_data", "2023-07-01"],
        "4.50.0 HSM uses 2023-07-01. Explicit public-network/purge booleans are preparable, "
        "not secrets storage, activation or EKM. Security-domain data and IDs are excluded.",
    ),
    (
        "terraform-diagnostics",
        RAW + "website/docs/r/monitor_diagnostic_setting.html.markdown",
        ["enabled_log", "Exactly one", "storage_account_id"],
        "4.50.0 enabled_log presence configures enabled logs; category and category_group "
        "are mutually exclusive. Missing/malformed values remain unknown; metrics do "
        "not imply logs, and no diagnostic category/data-plane read is performed.",
    ),
    *[
        (
            f"terraform-{os}-patch",
            RAW + f"website/docs/r/{os}_virtual_machine.html.markdown",
            ["patch_assessment_mode", "patch_mode", "provision_vm_agent"],
            f"Pinned {os} VM documentation supports explicit OS-specific patch and "
            "assessment enums with an agent boolean, not patch success/compliance. "
            "Default values, administrator data, custom data and secrets are not retained.",
        )
        for os in ("linux", "windows")
    ],
]


SOURCES_08 = [
    (
        "learn-reuse-terms",
        LEARN + "legal/termsofuse",
        ["Personal and Non-Commercial", "Microsoft Learn"],
        "Reviewed Learn Terms of Use; preserve attribution and URLs/hashes/revisions "
        "with independently authored factual findings only. No upstream page text, "
        "images, samples or dashboard contents are redistributed.",
    ),
    (
        "provider-reuse-terms",
        RAW + "LICENSE",
        ["Mozilla Public License Version 2.0", "Covered Software"],
        "Pinned provider license is MPL-2.0. No provider implementation is copied; "
        "retain metadata, attribution and independently authored mapping findings only.",
    ),
    (
        "owner-access-reviews",
        "https://learn.microsoft.com/entra/id-governance/access-reviews-overview",
        ["resource owners", "regularly", "role assignments"],
        "Access reviews require recurring resource-owner engagement and explicit access "
        "decisions. An Azure role assignment cannot prove awareness, responsibility, budget "
        "or policy review, remediation, or the organization's operating process.",
    ),
    (
        "subscription-limits",
        "https://learn.microsoft.com/azure/azure-resource-manager/management/"
        "azure-subscription-service-limits",
        ["regional level", "adjustable limits", "Free Azure trial"],
        "Service-specific adjustable and fixed limits differ; regional quota increases do "
        "not propagate to other regions. Public limits are not a subscription's actual "
        "quota, available capacity, provisioning success or owner awareness.",
    ),
    (
        "reservation-discounts",
        "https://learn.microsoft.com/azure/cost-management-billing/reservations/"
        "save-compute-costs-reservations",
        ["billing discount", "consistent", "scope"],
        "Reservations discount matching usage based on SKU, applicable region and scope; "
        "suitability needs attributable baseline demand and financial comparison. They "
        "do not change resource runtime state or establish available compute capacity.",
    ),
    (
        "capacity-not-quota-or-discount",
        LEARN + "azure/virtual-machines/capacity-reservation-overview",
        ["Quota and capacity are separate", "don't guarantee capacity", "SLA"],
        "On-demand capacity reservation is distinct from Reserved Instance billing discounts. "
        "Creation needs both quota and available capacity; matching VM association and "
        "applicable SKU/region/zone/SLA conditions matter. A configured group reference alone "
        "is neither accepted capacity nor cost suitability. No purchase or capacity read.",
    ),
    (
        "portal-dashboards",
        "https://learn.microsoft.com/azure/azure-portal/azure-portal-dashboards",
        ["private", "Metrics chart", "configuration"],
        "Shared dashboards are subscription resources while private dashboards need not be "
        "in resource inventory. Tile presence is not configured CPU/memory/free-disk coverage, "
        "correct target/time window, working telemetry, operational health or actual use.",
    ),
    (
        "dashboard-structure",
        LEARN + "azure/azure-portal/azure-portal-dashboards-structure",
        ["lenses", "MetricsChartPart", "MarkdownPart", "Disk Read Operations"],
        "Reviewed lenses/parts and exact MetricsChartPart/MarkdownPart type strings support "
        "only minimized structural counts. Disk I/O is not free disk space. Inputs, queries, "
        "titles, markdown, metric values and arbitrary tile payloads are never retained.",
    ),
    (
        "cost-operating-plan",
        "https://learn.microsoft.com/azure/cloud-adoption-framework/get-started/manage-costs",
        ["cost", "responsibilities", "business"],
        "The original manage-costs link now redirects to manage/administer. Its broader "
        "operating guidance does not establish a detailed cost plan; reviewer must reconcile "
        "accountability, budget/forecast, allocation, review cadence and corrective actions.",
    ),
    (
        "cost-plan-current",
        LEARN + "azure/cloud-adoption-framework/ready/azure-setup-guide/manage-costs",
        ["cost", "budget"],
        "Current cost optimization guidance supplements the redirected checklist link. "
        "A documented and operating process, agreed requirements and attributable reviews "
        "remain manual; no fixed budget, utilization threshold or responsibility is invented.",
    ),
    (
        "management-hierarchy",
        "https://learn.microsoft.com/azure/governance/management-groups/overview",
        ["only one parent", "root management group", "Microsoft Customer Agreement"],
        "MGs provide policy/access inheritance, not resource-tag inheritance or unrestricted "
        "billing visibility. Each MG/subscription has one parent; MCA cost-management support "
        "differs. Names/display names never designate an approved identity role.",
    ),
    (
        "identity-placement",
        LEARN + "azure/cloud-adoption-framework/ready/landing-zone/design-area/"
        "resource-org-management-groups",
        ["Identity", "dedicated subscription", "platform"],
        "The reference Identity MG contains a dedicated identity subscription under Platform. "
        "That conditional architecture is not proved by an identity-like name, VM location, "
        "parent ID or subscription membership; application identity requirements need review.",
    ),
    (
        "regional-domain-controllers",
        LEARN + "azure/cloud-adoption-framework/ready/landing-zone/design-area/"
        "identity-access-active-directory-hybrid-identity",
        ["site design", "same Azure region", "Identity subscription"],
        "Current hybrid identity guidance places domain controllers in an isolated Identity "
        "platform subscription. AD DS sites/subnets and locator behavior support regional "
        "use; same-region VMs, DNS settings or labels alone do not prove DC role or usage. "
        "Entra ID, managed Domain Services and self-managed AD DS remain distinct.",
    ),
    (
        "billing-tags",
        "https://learn.microsoft.com/azure/cloud-adoption-framework/ready/"
        "azure-best-practices/track-costs",
        ["tagging strategy", "billing", "Scope"],
        "Example business/cost tags are organization-dependent, not a required key set. "
        "Billing agreement, supported scope, authorized visibility and allocation semantics "
        "must be reviewed independently of tag presence or role assignment.",
    ),
    (
        "tag-rules",
        LEARN + "azure/azure-resource-manager/management/tag-resources",
        ["not to management groups", "don't inherit", "plain text", "50"],
        "Resources/RGs/subscriptions support tags subject to provider limits; MGs do not. "
        "Keys are case-insensitive, values case-sensitive. Resource tags do not automatically "
        "inherit. Retain only validated explicit pair count, never keys/values or defaults.",
    ),
    (
        "cost-tag-inheritance",
        LEARN + "azure/cost-management-billing/costs/enable-tag-inheritance",
        ["usage records", "not the resources", "current month", "24 hours"],
        "Cost Management inheritance is opt-in and agreement/scope/permission dependent "
        "(EA/MCA/MPA Azure plan). It changes usage records, not resources, within the current "
        "month after processing; conflict precedence is configurable. Resource-tag counts "
        "do not attest billing allocation, actual inheritance setting or historical coverage.",
    ),
    (
        "dashboard-arm",
        LEARN + "azure/templates/microsoft.portal/2020-09-01-preview/dashboards",
        ["DashboardLens", "DashboardParts", "lenses", "tags"],
        "Pinned planned-only 2020-09-01-preview exposes lens/part arrays and opaque metadata. "
        "Only structural counts and reviewed exact type classifications are projected. "
        "Unsupported shapes and malformed/over-bound content remain explicit unknowns.",
    ),
    (
        "management-arm",
        LEARN + "azure/templates/microsoft.management/2020-05-01/managementgroups",
        ["details", "parent", "tenant"],
        "Pinned 2020-05-01 exposes explicit details.parent.id. Omitted parent is not guessed "
        "as root; tenant-scope creation is outside this assessor's scope model. Existing "
        "saved descendant relationships are context only, not a role-designation predicate.",
    ),
    (
        "vm-capacity-arm",
        LEARN + "azure/templates/microsoft.compute/2024-07-01/virtualmachines",
        ["capacityReservationGroup", "capacityReservation", "id"],
        "Project only an explicit typed capacityReservation.capacityReservationGroup.id "
        "reference. Exclude credentials/OS data, reservation prices, consumption and "
        "capacity claims; resource-group/region/SKU matching requires separate review.",
    ),
    (
        "terraform-dashboard",
        RAW + "website/docs/r/portal_dashboard.html.markdown",
        ["dashboard_properties", "lenses", "parts", "hidden-title"],
        "Pinned 4.50.0 dashboard_properties is JSON with object-keyed lenses/parts in its "
        "example, unlike the ARM array shape. Bounded literal JSON is normalized separately; "
        "symbolic/malformed/duplicate-key input is unknown. Titles, tags and content withheld.",
    ),
    (
        "terraform-management",
        RAW + "website/docs/r/management_group.html.markdown",
        ["parent_management_group_id", "subscription_ids", "2020-05-01"],
        "Pinned 4.50.0 supports an explicit parent MG ID and subscription UUID list; "
        "membership conflicts with standalone associations. Omitted/computed parents, "
        "subscription purpose, inherited policy and regional DC use are not inferred.",
    ),
    (
        "terraform-dashboard-implementation",
        RAW + "internal/services/portal/portal_dashboard_resource.go",
        ["2019-01-01-preview", "json.Unmarshal", "dashboard_properties"],
        "The pinned provider uses 2019-01-01-preview and parses literal dashboard JSON. "
        "Do not claim its object-keyed schema is the ARM 2020 array schema; both bounded "
        "representations are separately tested. No provider or Terraform is executed.",
    ),
    *[
        (
            f"terraform-{os}-capacity",
            RAW + f"website/docs/r/{os}_virtual_machine.html.markdown",
            ["capacity_reservation_group_id", "tags"],
            f"Pinned {os} VM supports explicit capacity_reservation_group_id and tags. "
            "Only typed group reference and validated tag pair count are preparable, "
            "not a Reserved Instance discount, financial suitability or available capacity.",
        )
        for os in ("linux", "windows")
    ],
]


SOURCES_15 = [
    (
        "expressroute-gateway-propagation",
        LEARN + "azure/expressroute/expressroute-about-virtual-network-gateways",
        ["route propagation", "won't function", "same peering location"],
        "ExpressRoute-specific guidance also requires GatewaySubnet BGP propagation. "
        "Explicit joined flag is a configuration subclaim, not learned routes or uptime. "
        "SKU/location circuit maxima and subnet size are separate from two-site resilience.",
    ),
    (
        "expressroute-monitoring",
        "https://learn.microsoft.com/azure/expressroute/expressroute-monitoring-metrics-alerts",
        ["ArpAvailability", "BgpAvailability", "BitsInPerSecond"],
        "Actual checklist link redirects to monitoring data reference. Automatic platform "
        "metrics and diagnostic export support do not establish Insights use or ingestion.",
    ),
    (
        "expressroute-insights",
        LEARN + "azure/expressroute/expressroute-network-insights",
        ["extra setup", "primary and secondary", "maintenance"],
        "Insights needs no extra setup. Review original-time availability/utilization for "
        "both links, peering and gateway; maintenance can lower reported BGP availability "
        "while the customer-edge session remains up. No enablement boolean is invented.",
    ),
    (
        "connection-monitor-linked",
        "https://learn.microsoft.com/azure/expressroute/how-to-configure-connection-monitor",
        ["Log Analytics agent", "test groups", "thresholds"],
        "Checklist-linked page still instructs installing Log Analytics/MMA agents. "
        "This conflicts with current Network Watcher guidance; do not implement or endorse "
        "legacy agent installation. Test configuration is not successful probing.",
    ),
    (
        "connection-monitor-current",
        LEARN + "azure/network-watcher/connection-monitor-overview",
        ["Log Analytics agent is no longer supported", "Arc", "destination"],
        "Current guidance requires Arc-enabled on-premises source hosts and Azure Monitor "
        "Agent; Azure VM/VMSS sources require Network Watcher extension. Destination "
        "requirements differ. ARM/provider legacy endpoint enums are not current support.",
    ),
    (
        "expressroute-disaster-recovery",
        "https://learn.microsoft.com/azure/expressroute/"
        "designing-for-disaster-recovery-with-expressroute-privatepeering",
        ["different peering locations", "same metro", "180 seconds", "Connection Weight"],
        "Different peering locations can share a metro/failure domain. Different metros, "
        "provider/customer diversity, supported geopolitical/Premium reach and both-direction "
        "routing need review. Up to 180 seconds under some failures is not a promised SLO.",
    ),
    (
        "expressroute-coexistence",
        "https://learn.microsoft.com/azure/expressroute/expressroute-howto-coexist-resource-manager",
        ["route-based", "Basic", "longest prefix", "private peering"],
        "S2S coexistence requires route-based non-Basic VPN and supported GatewaySubnet; "
        "backup applies to private, not Microsoft, peering. Equal-prefix preference and "
        "longest-prefix selection differ; configuration does not demonstrate failover.",
    ),
    (
        "gateway-subnet-propagation",
        "https://learn.microsoft.com/azure/vpn-gateway/vpn-gateway-about-vpn-gateway-settings#gwsub",
        ["GatewaySubnet", "route propagation", "won't function"],
        "VPN-specific page requires BGP propagation on GatewaySubnet. Explicit "
        "disableBgpRoutePropagation=false must be joined to the actual known gateway subnet "
        "and table, not any table flag. NSG/UDR restrictions and availability are separate.",
    ),
    (
        "expressroute-high-availability",
        "https://learn.microsoft.com/azure/expressroute/"
        "designing-for-high-availability-with-expressroute#active-active-connections",
        ["same Customer Premises Equipment", "active-passive", "stateless"],
        "Both links need distinct customer edge devices and end-to-end failure domains. "
        "Active-active is recommended, active-passive supported with maintained routes; "
        "stateful/NAT effects and maintenance draining need operational evidence.",
    ),
    (
        "expressroute-bfd",
        "https://learn.microsoft.com/azure/expressroute/expressroute-bfd",
        ["Microsoft peering", "November 2025", "echo mode", "both your primary and secondary"],
        "Current BFD supports private and Microsoft peering. MSEE defaults depend on "
        "creation/reset and IPv4/IPv6 dates (IPv6 November 2025); customer/provider must "
        "configure interface and BGP linkage on both devices. Disable echo as advised. "
        "MSEE defaults/timer examples never prove edge configuration or failover SLO.",
    ),
    (
        "connection-monitor-arm",
        LEARN + "azure/templates/microsoft.network/2024-05-01/networkwatchers/connectionmonitors",
        ["testConfigurations", "testGroups", "disable", "workspaceResourceId"],
        "2024-05-01 supplies endpoint/configuration/group/output structures. Validate "
        "exact unique group references before minimizing names/addresses. Explicit "
        "disable=false and configured frequency/thresholds are not executing health tests.",
    ),
    (
        "metric-alert-arm",
        LEARN + "azure/templates/microsoft.insights/2018-03-01/metricalerts",
        ["enabled", "scopes", "metricNamespace", "actionGroupId"],
        "2018-03-01 metric alerts expose explicit scopes, enabled and criteria/actions. "
        "Only supplied ExpressRoute static criterion names and typed circuit scopes are "
        "prepared; dynamic/web-test/multiple-resource forms stay visibly unsupported.",
    ),
    (
        "terraform-connection-monitor",
        RAW + "website/docs/r/network_connection_monitor.html.markdown",
        ["test_configuration_names", "output_workspace_resource_ids", "2024-05-01"],
        "4.50.0 supports v2 only and explicit group endpoint/config references. Missing "
        "enabled/frequency defaults are not inferred; legacy endpoint enums do not "
        "establish supported Arc migration. Withhold addresses, headers, paths and notes.",
    ),
    (
        "terraform-connection-monitor-implementation",
        RAW + "internal/services/network/network_connection_monitor_resource.go",
        ["test_frequency_in_seconds", "test_group", "ChecksFailedPercent"],
        "Pinned implementation expands supplied groups/configurations/outputs into "
        "2024-05-01 structures. Provider creation defaults do not establish raw/import "
        "configuration and connection monitor creation is not an execution result.",
    ),
    *[
        source
        for source in SOURCES_11
        if source[0]
        in {"route-arm", "terraform-route-table", "connection-arm", "terraform-gateway-connection"}
    ],
    *[source for source in SOURCES_17 if source[0] in {"subnet-arm", "terraform-subnet"}],
    *[source for source in SOURCES_19 if source[0] in {"gateway-arm", "terraform-gateway"}],
    *[source for source in SOURCES_13 if source[0] == "expressroute-backup"],
    (
        "route-table-provider-implementation",
        RAW + "internal/services/network/route_table_resource.go",
        ["bgp_route_propagation_enabled", "DisableBgpRoutePropagation"],
        "Provider inverts explicit bgp_route_propagation_enabled into the ARM disable "
        "flag. Missing values remain unknown; subnet association must be known separately.",
    ),
    (
        "terraform-subnet-route-association",
        RAW + "website/docs/r/subnet_route_table_association.html.markdown",
        ["subnet_id", "route_table_id"],
        "Association is separately managed. Raw subnet/table presence cannot establish "
        "a join; reuse explicit supplied normalized subnet routeTable.id rather than "
        "defaulting missing associations or guessing names.",
    ),
    (
        "rest-spec-reuse",
        SPEC_RAW + "LICENSE",
        ["MIT License"],
        "Pinned REST specification reuse is MIT; retain metadata and own findings only.",
    ),
    *[
        (
            "rest-" + name,
            SPEC_RAW + "specification/network/resource-manager/Microsoft.Network/Network/"
            "stable/2024-05-01/" + filename,
            markers,
            finding,
        )
        for name, filename, markers, finding in [
            (
                "monitor",
                "networkWatcher.json",
                ["ConnectionMonitorTestGroup", "testFrequencySec"],
                "Pinned schema defines explicit groups, endpoint enums and configuration, "
                "including obsolete endpoint forms. Schema presence is not current support.",
            ),
            (
                "route",
                "routeTable.json",
                ["disableBgpRoutePropagation", "boolean"],
                "Pinned schema declares disableBgpRoutePropagation boolean. Omission is unknown.",
            ),
            (
                "subnet",
                "virtualNetwork.json",
                ["routeTable", "SubnetPropertiesFormat"],
                "Actual subnet properties carry route-table references; bind explicit identities.",
            ),
            (
                "gateway",
                "virtualNetworkGateway.json",
                ["peer", "virtualNetworkGateway1"],
                "Actual connection peer.id binds an ExpressRoute circuit; reuse cohort13's "
                "typed circuit/gateway facts and future merged cohort14 circuit metadata.",
            ),
        ]
    ],
]


SOURCES_15 += [
    source
    for source in SOURCES_14
    if source[0]
    in {
        "circuit-arm",
        "circuit-rest-2024",
        "port-arm",
        "port-rest-2024",
        "terraform-circuit",
        "terraform-expressroute-port",
        "connection-arm",
        "gateway-rest-2024",
        "provider-reuse",
        "learn-reuse",
    }
]


SOURCES_02 = [
    (
        "tenant-strategy",
        LEARN + "azure/cloud-adoption-framework/ready/landing-zone/design-area/"
        "multi-tenant/considerations-recommendations",
        ["single tenant", "regulatory", "Microsoft Customer Agreement"],
        "Prefer one corporate tenant unless documented requirements cannot be met there. "
        "ALZ is deployed separately in each tenant; subscription counts, names and Lighthouse "
        "registrations establish neither complete tenant inventory nor business justification.",
    ),
    (
        "tenant-automation",
        LEARN
        + "azure/cloud-adoption-framework/ready/landing-zone/design-area/multi-tenant/automation",
        ["Complete isolation", "Shared application registration", "managed identities"],
        "Two example platform automation models depend on required isolation; they are not "
        "mandatory workload patterns. Current guidance qualifies the older managed-identity "
        "limitation with user-assigned identity federation to a multitenant application. "
        "Lighthouse cannot supply all ALZ deployment permissions or prove automation adoption.",
    ),
    (
        "alz-lighthouse",
        LEARN
        + "azure/cloud-adoption-framework/ready/landing-zone/design-area/multi-tenant/lighthouse",
        ["not management groups or tenants", "clouds", "P2"],
        "Lighthouse delegates subscriptions/resource groups, not tenants or MGs, and cannot "
        "cross Azure clouds. Generic template scope lists do not override service limits. "
        "Eligible authorizations require managing-tenant P2; configuration is not actual use.",
    ),
    (
        "lighthouse-overview",
        LEARN + "azure/lighthouse/overview",
        ["subscriptions and resource groups", "national cloud", "partner"],
        "Enterprises as well as partners can use delegated resource management. Registration "
        "does not establish partner/CSP status, directory authority or actual same-identity use.",
    ),
    (
        "lighthouse-architecture",
        LEARN + "azure/lighthouse/concepts/architecture",
        ["subscription level", "registration assignment", "registration definition"],
        "A subscription-level definition and an assignment at the delegated subscription/RG "
        "form the configuration relationship. Only unique known scoped supplied joins are "
        "prepared; effective authorization, identity use and partner approval remain separate.",
    ),
    (
        "lighthouse-role-limits",
        LEARN + "azure/lighthouse/concepts/tenants-users-roles",
        ["custom roles", "DataActions", "User Access Administrator"],
        "Owner/custom/DataActions and listed authorization actions are unsupported. UAA has "
        "only a constrained managed-identity role-assignment use with explicit delegated roles; "
        "the automation article's blanket UAA wording is qualified here. Syntactically valid "
        "role-reference counts are not current built-in-role support or effective authority.",
    ),
    (
        "lighthouse-csp",
        LEARN + "azure/lighthouse/concepts/cloud-solution-provider",
        ["AOBO", "private plans", "whether or not"],
        "Lighthouse can complement CSP AOBO with granular resource permissions. CSP preview "
        "customer listing is independent of onboarding; reseller CSP private marketplace "
        "plans are unsupported. No registration implies a reseller or support relationship.",
    ),
    (
        "csp-guidance",
        LEARN + "azure/cloud-adoption-framework/ready/landing-zone/design-area/"
        "azure-billing-cloud-solution-provider#design-recommendations",
        ["escalation", "GDAP", "MPA"],
        "Partner manages MPA and is the first support contact; agree case creation/escalation "
        "and use granular resource delegation and GDAP appropriately. GDAP directory authority "
        "and Lighthouse resource delegation are distinct; actual support process stays manual.",
    ),
    (
        "mca-guidance",
        LEARN + "azure/cloud-adoption-framework/ready/landing-zone/design-area/"
        "azure-billing-microsoft-customer-agreement#design-recommendations",
        ["invoice sections", "outside of standard Azure RBAC", "group mailbox"],
        "MCA uses billing account/profile/invoice-section hierarchy, not EA departments/accounts. "
        "Billing roles are distinct from Azure RBAC and cannot be assigned at MG/RG. Reports, "
        "mailbox suitability and approved organizational mapping need separate evidence.",
    ),
    (
        "ea-guidance",
        LEARN + "azure/cloud-adoption-framework/ready/landing-zone/design-area/"
        "azure-billing-enterprise-agreement#design-considerations",
        ["departments", "February 15, 2024", "Notification Contact"],
        "EA departments/accounts/subscriptions differ from resource MG hierarchy and MCA. "
        "EA portal retired in February 2024; department quota is reporting, not enforcement. "
        "Actual agreement, owners and suitable billing separation cannot be inferred.",
    ),
    (
        "ea-notification",
        LEARN + "azure/cost-management-billing/manage/"
        "direct-ea-administration#manage-notification-contacts",
        ["Manage notification contacts", "Bill to contact", "November 16, 2026"],
        "EA notification contacts receive selected usage/user/lifecycle notifications without "
        "billing access; invoices go separately to Bill to contact. Group mailbox ownership, "
        "coverage and delivery require manual evidence. Upcoming 2026-11-16 WSA-only new billing "
        "role assignments are dated guidance, not a retroactive claim about existing roles.",
    ),
    (
        "cost-scopes",
        LEARN + "azure/cost-management-billing/costs/understand-work-scopes",
        ["Management groups", "Microsoft Customer Agreement", "Billing scopes"],
        "Azure RBAC/resource scopes and agreement billing scopes differ. MCA Cost Management "
        "does not currently support MGs; cost-details MG support is absent for EA and MCA. "
        "View configuration grants no billing/invoice visibility or completeness.",
    ),
    (
        "cost-views",
        LEARN + "azure/cost-management-billing/costs/save-share-views",
        ["Underlying data", "private views", "100 shared views"],
        "Saved views store configuration, not underlying cost data; scope/access, private/shared "
        "visibility and pinned dashboard snapshots differ. A chart/metric enum and exact scoped "
        "view binding cannot prove actual reporting, data freshness or financial suitability.",
    ),
    (
        "cost-csp",
        LEARN + "azure/cost-management-billing/costs/get-started-partners",
        ["Azure plan", "retail rates", "cost visibility policy"],
        "CSP customer cost access depends on Azure Plan/MCA, provider visibility policy and "
        "customer RBAC; retail customer views differ from partner invoice prices. Historical "
        "costs do not move to a new partner billing relationship. No prices or usage retained.",
    ),
    (
        "lighthouse-definition-arm",
        LEARN + "azure/templates/microsoft.managedservices/2022-10-01/registrationdefinitions",
        ["authorizations", "eligibleAuthorizations", "delegatedRoleDefinitionIds"],
        "Pinned 2022-10-01 definition includes authorization and optional eligible lists. "
        "Project bounded validated pair counts only; discard tenant/principal identifiers, "
        "display names, offer metadata, JIT approvers and private partner information.",
    ),
    (
        "lighthouse-assignment-arm",
        LEARN + "azure/templates/microsoft.managedservices/2022-10-01/registrationassignments",
        ["registrationDefinitionId", "fully qualified"],
        "Pinned 2022-10-01 assignment explicitly references a definition. Service-specific "
        "subscription definition and subscription/RG assignment limits supersede generic "
        "template-generated tenant/MG scope options.",
    ),
    (
        "cost-view-arm",
        LEARN + "azure/templates/microsoft.costmanagement/2019-11-01/views",
        ["ActualCost", "AmortizedCost", "scope", "chart"],
        "Pinned 2019-11-01 chart/metric enums and explicit view scope support minimized "
        "metadata only. Accept subscription/RG scopes only, require exact resource-parent "
        "binding; billing/MG/private provider-root views are not projected as supported.",
    ),
    (
        "terraform-lighthouse-definition",
        RAW + "website/docs/r/lighthouse_definition.html.markdown",
        ["lighthouse_definition_id", "authorization", "2022-10-01"],
        "AzureRM 4.50.0 definition UUID is lighthouse_definition_id; name is only display text. "
        "Do not derive an ARM identity from display name or fabricate an omitted generated UUID.",
    ),
    (
        "terraform-lighthouse-definition-implementation",
        RAW + "internal/services/lighthouse/lighthouse_definition_resource.go",
        [
            "commonids.ValidateSubscriptionID",
            "ManagedByTenantId",
            "NewScopedRegistrationDefinitionID",
        ],
        "Provider definition scope validates a subscription and uses explicit/generated UUID "
        "for resource identity. Authorization sets map directly; missing optional eligible "
        "list remains unknown rather than inventing zero or JIT/MFA defaults.",
    ),
    (
        "terraform-lighthouse-assignment",
        RAW + "website/docs/r/lighthouse_assignment.html.markdown",
        ["resource group", "lighthouse_definition_id", "2022-10-01"],
        "AzureRM assignment scope is subscription/RG; explicit optional name is a UUID and "
        "definition ID is fully qualified. Omitted name cannot establish a raw-source identity.",
    ),
    (
        "terraform-lighthouse-assignment-implementation",
        RAW + "internal/services/lighthouse/lighthouse_assignment_resource.go",
        ["ValidateResourceGroupID", "ExpandRegistrationDefinition", "RegistrationDefinitionId"],
        "Provider assignment uses literal scope/UUID and explicit definition reference; "
        "expanded embedded definition is not implicitly trusted or treated as a joined record.",
    ),
    (
        "subscription-resource-reference",
        LEARN + "azure/azure-resource-manager/templates/"
        "template-functions-resource#subscriptionresourceid",
        ["subscriptionResourceId", "current subscription", "resourceName1"],
        "The implicit-subscription literal overload constructs an ID at the current "
        "subscription, not RG. Only this bounded overload is interpreted for actual compiled "
        "Lighthouse references; explicit foreign-subscription and unresolved overloads stay "
        "unknown. ID construction does not expand the selected assessment/read boundary.",
    ),
    (
        "learn-terms",
        LEARN + "legal/termsofuse",
        ["Documentation", "explicit license terms"],
        "Retain attributed links, revision/hash/redirect metadata and independently authored "
        "findings only. Do not redistribute articles, samples, provider implementation or "
        "private tenant, billing, partner and contact data.",
    ),
    (
        "provider-license",
        RAW + "LICENSE",
        ["Mozilla Public License", "2.0"],
        "Pinned provider is MPL-2.0; only metadata and independently authored findings are "
        "redistributed, with no upstream implementation copied.",
    ),
]

SOURCES_05 = [
    (
        "landing-zone-roles",
        "https://learn.microsoft.com/azure/cloud-adoption-framework/ready/landing-zone/"
        "design-area/identity-access-landing-zones#microsoft-entra-id-recommendations",
        ["fewest permissions", "only create custom roles when necessary", "Global Administrator"],
        "Current guidance distinguishes Entra directory authority from Azure resource RBAC, "
        "prefers built-in roles when sufficient and limits Global Administrator to emergencies "
        "where existing roles cannot suffice. No universal custom-role requirement.",
    ),
    (
        "ad-ds-availability",
        "https://learn.microsoft.com/azure/architecture/reference-architectures/identity/"
        "adds-extend-domain#vm-recommendations",
        ["at least two VMs", "availability set", "Active Directory site"],
        "Legacy architecture URL redirects to example-scenario. At least two actual AD DS "
        "DC VMs in different zones, or an availability set where zones are unavailable; "
        "VM type/name/tags never establish DC role, complete population or regional support.",
    ),
    (
        "identity-regions",
        "https://learn.microsoft.com/azure/cloud-adoption-framework/ready/considerations/"
        "regions#identity",
        ["Identity", "new Azure region", "availability zones"],
        "Expand applicable self-managed AD DS or managed Domain Services into required "
        "regions. Resource metadata locations and globally scoped roles are not service "
        "placement, AD sites, local DC selection or geographical recovery evidence.",
    ),
    (
        "identity-team-boundaries",
        "https://learn.microsoft.com/azure/cloud-adoption-framework/ready/landing-zone/"
        "design-area/identity-access#prerequisites-for-a-landing-zone---design-recommendations",
        ["identity team", "application administrator", "separation of duties"],
        "Current overview delegates centralized directory services to platform identity "
        "teams and application access to workload administrators. Actual organizational "
        "responsibilities and least privilege need independently approved evidence.",
    ),
    (
        "domain-services-overview",
        "https://learn.microsoft.com/entra/identity/domain-services/overview",
        ["synchronization", "managed domain", "LDAP"],
        "Managed Domain Services is a stand-alone managed domain, not an extension of "
        "on-premises AD DS. Synchronization and LDAP write limitations require workload "
        "compatibility review; ARM existence or SKU proves no compatibility.",
    ),
    (
        "domain-services-replicas",
        LEARN + "entra/identity/domain-services/concepts-replica-sets",
        ["same Active Directory site", "five", "Enterprise", "same subscription"],
        "Up to five replica sets in the same subscription; additional replicas require "
        "Enterprise/Premium and fully meshed replica VNet connectivity. They share one "
        "AD site; separate sites/replication settings cannot be defined. Workloads must "
        "also reside in recovery regions. Configured sets do not prove replication health.",
    ),
    (
        "entra-log-integration",
        "https://learn.microsoft.com/azure/active-directory/reports-monitoring/"
        "concept-activity-logs-azure-monitor",
        ["Diagnostic settings", "sign-in", "Azure Monitor logs"],
        "Legacy Azure AD URL redirects to Entra integration options. Directory audit/sign-in "
        "logs differ from Azure activity/resource logs. Routing alone proves no ingestion, "
        "coverage, retention, central ownership or successful alerts.",
    ),
    (
        "entra-log-prerequisites",
        LEARN + "entra/identity/monitoring-health/"
        "howto-integrate-activity-logs-with-azure-monitor-logs",
        ["Security Administrator", "Log Analytics workspace", "log categories"],
        "Directory Security Administrator and separately authorized workspace/data access "
        "are prerequisites. A workspace in the selected subscription does not demonstrate "
        "tenant log export or directory permission. No new directory or log read.",
    ),
    (
        "emergency-access",
        "https://learn.microsoft.com/azure/active-directory/roles/security-emergency-access",
        ["two or more", "Report-only", "permanent", "90 days", "phishing-resistant"],
        "Legacy URL redirects to current Entra guidance: two or more cloud-only emergency "
        "accounts, phishing-resistant authentication independent of normal admin methods, "
        "permanent-active emergency GA, safe separate custody, monitoring and validation "
        "at least every 90 days. Blocking/restricting CA exclusions differ from report-only. "
        "Shared versus individual emergency account alternatives need an explicit decision.",
    ),
    (
        "mandatory-mfa-current",
        LEARN + "entra/identity/authentication/concept-mandatory-multifactor-authentication",
        ["October 1, 2025", "Read operations", "Workload identities", "emergency"],
        "Frozen October 2024 wording is not current universal enforcement. Phase 1 portal "
        "CRUD and phase 2 gradually from October 1 2025 CLI/PowerShell/IaC/control-plane "
        "create/update/delete differ; phase 2 reads excluded. Emergency accounts require "
        "MFA; workload identities are unaffected. No tenant rollout state is inferred.",
    ),
    (
        "vm-placement-arm",
        LEARN + "azure/templates/microsoft.compute/2024-07-01/virtualmachines",
        ["availabilitySet", "zones", "location"],
        "Pinned planned VM schema exposes top-level zones/location and availabilitySet.id. "
        "Explicit empty zones are only supplied nonzonal configuration, not unavailable "
        "regional zones. No guest/OS/credential/extension or inferred DC information.",
    ),
    (
        "availability-set-arm",
        LEARN + "azure/templates/microsoft.compute/2024-07-01/availabilitysets",
        ["platformFaultDomainCount", "platformUpdateDomainCount", "Resource groups"],
        "Pinned RG-scoped availability-set schema exposes configured fault/update counts. "
        "Known typed VM reference joins are context, never independent healthy DC proof.",
    ),
    (
        "role-definition-arm",
        LEARN + "azure/templates/microsoft.authorization/2022-04-01/roledefinitions",
        ["assignableScopes", "CustomRole", "roleName"],
        "Pinned scoped Azure role definition type and explicit assignable-scope count only. "
        "Do not retain role names, descriptions, principals or action contents, or equate "
        "resource RBAC to directory authority or team responsibilities.",
    ),
    (
        "domain-services-arm",
        LEARN + "azure/templates/microsoft.aad/2022-12-01/domainservices",
        ["replicaSets", "subnetId", "Resource groups"],
        "Actual resource is RG-scoped Microsoft.AAD/domainServices, with embedded replicaSets "
        "location/subnetId. No invented Graph or ARM replica child resources. Minimize to "
        "bounded configured replica/subnet/location context, not health or directory records.",
    ),
    (
        "entra-diagnostics-tenant-schema",
        LEARN + "azure/templates/microsoft.aadiam/2017-04-01/diagnosticsettings",
        ["Tenant", "AuditLogs", "SignInLogs", "workspaceId"],
        "Actual microsoft.aadiam/diagnosticSettings is tenant-only, not subscription-scoped "
        "Microsoft.Insights/diagnosticSettings. It remains unsupported within existing "
        "assessment scope; do not broaden scope or synthesize records to create a Signal.",
    ),
    *[
        (
            f"terraform-{os}-placement",
            RAW + f"website/docs/r/{os}_virtual_machine.html.markdown",
            ["availability_set_id", "zone", "location"],
            f"Pinned {os} VM has one zone, location and availability_set_id. Only explicit "
            "values are preparable; no null/default/absence inference or guest/DC role claim.",
        )
        for os in ("linux", "windows")
    ],
    (
        "terraform-availability-set",
        RAW + "website/docs/r/availability_set.html.markdown",
        ["platform_fault_domain_count", "platform_update_domain_count", "2024-03-01"],
        "Pinned provider uses 2024-03-01 for availability sets. Project only explicit "
        "counts, not defaults or guarantees of physically independent healthy controllers.",
    ),
    (
        "terraform-role-definition",
        RAW + "website/docs/r/role_definition.html.markdown",
        ["role_definition_resource_id", "{roleDefinitionId}|{scope}", "2022-05-01-preview"],
        "Pinned role-definition resource uses 2022-05-01-preview and Terraform composite "
        "id, not display name, for identity. Require explicit ARM role resource ID or "
        "UUID plus scope; missing/generated IDs remain unbound. No raw action contents.",
    ),
    (
        "terraform-domain-services",
        RAW + "website/docs/r/active_directory_domain_service.html.markdown",
        ["initial_replica_set", "inherits the same location", "2021-05-01"],
        "Pinned provider uses 2021-05-01 and requires initial_replica_set. Project only that "
        "supplied initial subnet/location, never complete managed-domain replica population. "
        "Provider import uses an initialReplicaSetId suffix, not a real ARM child.",
    ),
    (
        "terraform-domain-services-implementation",
        RAW + "internal/services/domainservices/active_directory_domain_service_resource.go",
        ["initialReplicaSetId", 'd.Set("resource_id", model.Id)', "2021-05-01"],
        "Actual provider uses a composite initialReplicaSetId import/state identity and "
        "separately exports resource_id for the ARM domain resource. Plans require that "
        "typed ARM binding and a matching composite ID, never a fake replica child.",
    ),
    (
        "terraform-role-definition-implementation",
        RAW + "internal/services/authorization/role_definition_resource.go",
        ["CustomRole", "RoleDefinitionResourceId", "2022-05-01-preview"],
        "Actual provider creates CustomRole and exports separate ARM resource ID while "
        "using a composite state identity. Supplied plans must bind both correctly; "
        "raw generated UUIDs and names never become an inferred ARM role identity.",
    ),
    (
        "terraform-replica-resource",
        RAW + "website/docs/r/active_directory_domain_service_replica_set.html.markdown",
        ["domain_service_id", "subnet_id", "service_status"],
        "Separate provider replica resource modifies its parent domain service; it is not "
        "a documented ARM replica child type. It stays explicitly unsupported rather than "
        "inventing resource identity, complete replica inventory or runtime status.",
    ),
    *[source for source in SOURCES_15 if source[0] in {"provider-reuse", "learn-reuse"}],
]


SOURCES_20 = [
    (
        "vwan-any-to-any",
        "https://learn.microsoft.com/azure/virtual-wan/scenario-any-to-any",
        ["Standard", "Default route table", "branch-to-branch"],
        "The actual scenario is unfiltered any-to-any with common association/propagation. "
        "Standard inter-hub defaults are not evidence of business suitability or reachability.",
    ),
    (
        "vwan-regional-design",
        "https://learn.microsoft.com/azure/cloud-adoption-framework/ready/azure-best-practices/"
        "virtual-wan-network-topology#virtual-wan-network-design-recommendationst",
        ["one or more", "same region", "connectivity subscription"],
        "Current CAF permits multiple hubs per region for scale; not exactly one. The "
        "original fragment is obsolete. Regions, complete workloads and limits need review.",
    ),
    (
        "vwan-firewall",
        "https://learn.microsoft.com/azure/virtual-wan/howto-firewall",
        ["secured hub", "Availability Zones", "doesn't permit"],
        "The linked portal conversion does not configure Firewall zones. Hub association "
        "and AZFW_Hub SKU are configuration, not filtering, availability or policy enforcement.",
    ),
    (
        "vwan-migration",
        "https://learn.microsoft.com/azure/virtual-wan/migrate-from-hub-spoke-topology",
        ["Standard SKU", "shared services", "migration"],
        "The illustrated staged migration is scenario-specific. Shared services stay in "
        "spokes; intended traffic, cutover, old routes and rollback need attributable review.",
    ),
    (
        "vwan-insights",
        "https://learn.microsoft.com/azure/virtual-wan/azure-monitor-insights",
        ["pre-packaged", "preview", "Dependency"],
        "The linked page labels the portal Insights view preview and describes a prepackaged "
        "workbook; no enablement boolean. Saved resource facts do not prove workbook use, "
        "health, metric arrivals or complete topology coverage.",
    ),
    (
        "vwan-faq",
        "https://learn.microsoft.com/azure/virtual-wan/virtual-wan-faq",
        ["enabled by default", "/23", "/22", "IPv6 isn't supported"],
        "WAN branch traffic defaults enabled in guidance, but missing flags remain unknown. "
        "Minimum hub /24, recommended /23 or larger; Firewall maximum scaling requires /22. "
        "Address space is immutable, IPv6 unsupported. Regions are an external eligibility "
        "review, not a guessed list. ER transit/Global Reach and routing intent differ.",
    ),
    (
        "vwan-routing-preference",
        "https://learn.microsoft.com/azure/virtual-wan/about-virtual-hub-routing-preference",
        ["Longest Prefix Match", "default setting", "selected last"],
        "ExpressRoute default, VPN and AS Path are explicit configurations. LPM/static "
        "precedence and remote ER/private-intent exceptions prevent a shortest-path assurance.",
    ),
    (
        "vwan-labels",
        "https://learn.microsoft.com/azure/virtual-wan/about-virtual-hub-routing#labels",
        ["Default", "If no label", "dynamic routing"],
        "Default label spans hubs; omitted VNet propagation labels default to Default in "
        "guidance but are not inferred from absent inputs. Dynamic, static and default-route "
        "propagation differ; nonempty labels do not prove correct inter-hub connectivity.",
    ),
    (
        "vwan-hub-capacity",
        LEARN + "azure/virtual-wan/hub-settings",
        ["routing infrastructure", "25 minutes", "/22", "10,000 routes"],
        "RIUs differ from gateway scale units: 2 RIUs support 3 Gbps/2000 VMs; autoscaling "
        "is not instant and does not prove headroom. Reviewed table 2..50 is an advisory "
        "envelope, not API quota or guaranteed performance. /22 Firewall condition remains.",
    ),
    (
        "vwan-routing-intent",
        LEARN + "azure/virtual-wan/how-to-routing-policies",
        ["21 Vianet", "custom route tables", "Internet"],
        "Internet intent requires local security next hop; default routes do not cross hubs. "
        "Custom routing configurations conflict with intent constructs; 21Vianet unsupported "
        "and Government NVA/SaaS availability conditional. Exact local firewall join is only "
        "configured intent, not actual inspection, filtering or route selection.",
    ),
    (
        "vwan-rest",
        SPEC_RAW + "specification/network/resource-manager/Microsoft.Network/Network/"
        "stable/2024-05-01/virtualWan.json",
        ["HubRoutingPreference", "ASPath", "routingPolicies", "allowBranchToBranchTraffic"],
        "Pinned 2024-05-01 defines WAN and hub branch flags separately; hub ASPath/"
        "ExpressRoute/VpnGateway, hubRouteTables labels and connection routing configuration. "
        "Hub route tables are not Microsoft.Network/routeTables. Internet/PrivateTraffic "
        "are a reviewed subset of free-form destination strings; others remain unsupported.",
    ),
    *[
        (
            f"terraform-{name}",
            RAW + f"website/docs/r/{name}.html.markdown",
            markers,
            finding,
        )
        for name, markers, finding in [
            (
                "virtual_wan",
                ["allow_branch_to_branch_traffic", "Standard", "2024-05-01"],
                "4.50.0 WAN defaults branch=true/type=Standard. Raw missing defaults are "
                "unknown; no hub flag substituted for the WAN-wide flag.",
            ),
            (
                "virtual_hub",
                ["branch_to_branch_traffic_enabled", "ASPath", "2024-05-01"],
                "4.50.0 hub branch default=false differs from WAN default=true. Retain both "
                "explicit booleans independently. Hub preference defaults ER, RIU minimum=2. "
                "Address prefix changes recreate hub; no default or growth inference.",
            ),
            (
                "virtual_hub_connection",
                ["propagated_route_table", "labels", "internet_security_enabled"],
                "Explicit routing/propagation blocks and child identity are preparable. "
                "Computed or absent labels/IDs stay unknown; static next-hop addresses withheld.",
            ),
            (
                "virtual_hub_route_table",
                ["labels", "hubRouteTables", "alternatively"],
                "Explicit labels support minimized equality only. Separately managed routes "
                "mean inline count cannot prove complete route population; all routes withheld.",
            ),
            (
                "virtual_hub_routing_intent",
                ["Internet", "PrivateTraffic", "next_hop"],
                "One or two unique named destination policies with exact typed firewall "
                "references prepare local intent; NVA/SaaS forms remain unsupported/unknown.",
            ),
        ]
    ],
    (
        "terraform-hub-implementation",
        RAW + "internal/services/network/virtual_hub_resource.go",
        ["AllowBranchToBranchTraffic", "Default:  false", "HubRoutingPreference"],
        "Pinned implementation writes the hub-specific flag independently of the WAN. "
        "Read pointer defaults cannot establish absent saved inputs; project explicit only.",
    ),
    (
        "terraform-connection-implementation",
        RAW + "internal/services/network/virtual_hub_connection_resource.go",
        ["Computed: true", "PropagatedRouteTables", "EnableInternetSecurity"],
        "Pinned routing and labels can be computed; expand maps supplied blocks to ARM "
        "fields. Neither inferred labels nor internet-security flag proves effective routes.",
    ),
    *[s for s in SOURCES_17 if s[0] in {"firewall-arm", "terraform-firewall"}],
    *[s for s in SOURCES_14 if s[0] in {"provider-reuse", "learn-reuse", "rest-spec-reuse"}],
]


def microsoft_site_terms(url: str) -> bool:
    parsed = urlsplit(url)
    return parsed.scheme == "https" and (
        parsed.netloc == "techcommunity.microsoft.com"
        or (parsed.netloc == "www.microsoft.com" and parsed.path.startswith("/en-us/legal/"))
    )


DOCS_REVISION = "c9d8b26db3b48d8d3e1d91f4cef575623ff12f83"
DOCS_RAW = f"https://raw.githubusercontent.com/github/docs/{DOCS_REVISION}/"
SOURCES_30 = [
    (
        "caf-iac-linked",
        "https://learn.microsoft.com/azure/cloud-adoption-framework/ready/considerations/"
        "infrastructure-as-code",
        ["implementation options", "version control", "Bicep"],
        "The actual checklist IaC link redirects to platform implementation options. AVM/"
        "accelerator capability does not establish platform or workload adoption.",
    ),
    (
        "caf-lifecycle-linked",
        "https://learn.microsoft.com/azure/cloud-adoption-framework/ready/considerations/"
        "development-strategy-development-lifecycle",
        ["Repository strategy", "Branch strategy", "pull request", "squash"],
        "CAF recommends Git, private landing-zone repositories, trunk-based development, "
        "branch permissions/policies, separate PR review and squash merges. No fixed reviewer "
        "count or branch lifetime is an organization-specific requirement.",
    ),
    (
        "caf-management-linked",
        "https://learn.microsoft.com/azure/cloud-adoption-framework/ready/landing-zone/"
        "design-area/management-platform",
        ["Inventory", "visibility", "monitoring"],
        "The original H02.04 link now concerns inventory and visibility, not emergency-fix "
        "backlog reconciliation. Preserve the original link and use current CAF automation "
        "guidance for the actual quick-fix process.",
    ),
    (
        "caf-security-linked",
        "https://learn.microsoft.com/azure/cloud-adoption-framework/ready/considerations/"
        "landing-zone-security#secure",
        ["DevSecOps", "Secure the design", "Secure operations"],
        "Security integration covers people and design/code/pipeline/operations throughout "
        "the lifecycle. A passing scan or enabled workflow cannot attest integration, "
        "risk ownership, remediation or operational feedback.",
    ),
    (
        "azure-residency-linked",
        "https://azure.microsoft.com/en-us/explore/global-infrastructure/data-residency",
        ["Geo", "Preview", "authorization"],
        "Azure's general Geo commitments have explicit service and preview exceptions. "
        "Region, geography, storage and processing are distinct; these commitments cannot "
        "be generalized to GitHub, Azure DevOps or every upstream package/image service.",
    ),
    (
        "caf-iac-updates",
        LEARN
        + "azure/cloud-adoption-framework/ready/considerations/infrastructure-as-code-updates",
        ["declarative", "state management", "emergency", "human approval"],
        "Declarative desired state differs from imperative scripts. Existing non-IaC "
        "resources need explicit state alignment; platform/workload maintenance, drift, "
        "reviewed changes and emergency reconciliation need attributable process evidence. "
        "Neither an IaC file nor compilation proves lifecycle management.",
    ),
    (
        "caf-automation",
        LEARN + "azure/cloud-adoption-framework/ready/considerations/automation",
        ["quick fixes", "backlog", "technical debt", "4-eyes"],
        "CAF explicitly requires registering quick fixes in the backlog and later reworking "
        "them to limit technical debt; emergency portal fixes must return to code. "
        "A ticket or hotfix branch alone cannot prove this process was followed.",
    ),
    (
        "azure-repos-branching",
        LEARN + "azure/devops/repos/git/git-branching-guidance?view=azure-devops",
        ["feature branches", "pull requests", "release branch"],
        "Simple feature/main/PR discipline and release fix porting are supported strategies. "
        "The article's suggested two reviewers is not a mandatory universal threshold; "
        "actual protected branches, bypasses and review practices require scoped evidence.",
    ),
    (
        "devops-residency",
        LEARN + "azure/devops/organizations/security/data-location?view=azure-devops",
        ["Token data", "Brazil", "macOS", "United States"],
        "Azure DevOps Services customer data uses a selected geography with exceptions: "
        "token data is US; profile/support/preview data have separate boundaries; "
        "macOS jobs transfer data to GitHub's US datacenter; Brazil replicates to South "
        "Central US. These are not Azure DevOps Server or exact-region guarantees.",
    ),
    (
        "devops-hosted-agents",
        LEARN + "azure/devops/pipelines/agents/hosted?view=azure-devops",
        ["any of the regions", "Brazil South", "fallback", "macOS"],
        "Windows/Linux agents can use any region in the organization's geography, not "
        "necessarily its exact region. EU organizations stay within the EU boundary; "
        "Brazil South has US capacity fallback; macOS agents always run in the US. "
        "An OS/pool label is not evidence of an actual assessed job's location.",
    ),
    (
        "acr-geo-replication",
        LEARN + "azure/container-registry/container-registry-geo-replication",
        ["all geo-replicas", "eventual consistency", "global endpoint", "Premium"],
        "Premium ACR replicates content and metadata to all selected replicas with eventual "
        "consistency. Global endpoints use network/health routing, not a residency promise. "
        "Regional serving does not remove other stored copies or upstream dependencies.",
    ),
    (
        "acr-data-endpoints",
        LEARN + "azure/container-registry/container-registry-dedicated-data-endpoints",
        ["307", "downloads", "same region", "Premium"],
        "Dedicated data endpoints serve layer downloads, not uploads. The 307 layer redirect "
        "stays in the serving replica's region; global replica selection and all stored "
        "replicas still need review. No host-name-derived sovereignty pass is justified.",
    ),
    (
        "acr-tasks",
        LEARN + "azure/container-registry/container-registry-tasks-overview",
        ["source code context", "base image", "diagnostic tracing"],
        "Tasks can send source context to Azure and consume local, Git, remote tarball or "
        "OCI contexts and public base images. Task/image presence does not prove execution "
        "or upstream residency. Command-line/URI secrets can enter diagnostic tracing; "
        "retain redacted references only, never context payloads, tokens or credentials.",
    ),
    (
        "acr-task-agent-pools",
        LEARN + "azure/container-registry/tasks-agent-pools",
        ["preview", "Linux", "Windows", "precached"],
        "Premium dedicated task pools are preview, Linux-only and limited to the published "
        "regions, including listed public-cloud and USGov regions. The VNet/pool does not "
        "bound all dependencies: service endpoints, diagnostics, package restores, external "
        "registries and changing precached base images still require review. No preview "
        "eligibility or actual pool residency is inferred from a registry location.",
    ),
    (
        "github-flow",
        DOCS_RAW + "content/get-started/using-github/github-flow.md",
        ["lightweight", "branch", "review"],
        "GitHub Flow is a lightweight branch-based strategy, not a mandated strategy for "
        "every release model. Review, checks and protected-branch requirements are separate "
        "from a local branch or PR's presence.",
    ),
    (
        "github-residency",
        DOCS_RAW + "content/admin/data-residency/"
        "about-github-enterprise-cloud-with-data-residency.md",
        ["USA", "GHE.com", "data residency"],
        "GitHub.com defaults to US storage. Enterprise Cloud residency is a distinct "
        "GHE.com deployment; current documented regions are EU including EFTA Norway/"
        "Switzerland, Australia, US and Japan. This EU boundary differs from Azure "
        "DevOps' EU-only hosted-agent boundary and is not country-level sovereignty.",
    ),
    (
        "github-residency-storage",
        DOCS_RAW + "content/admin/data-residency/about-storage-of-your-data-with-data-residency.md",
        ["outside your region", "Copilot", "prodname_secret_scanning"],
        "GHE.com stores customer content and identifiable Actions/BCDR data in-region, "
        "with exceptions for pseudonymous telemetry, billing, support, optional secret "
        "validity checks and Copilot. Current compliant-model policy changes Copilot's "
        "boundary; do not infer enrollment or settings. External actions, caches, package "
        "registries and upstream base images need independently attributable review.",
    ),
    (
        "github-residency-rendered",
        "https://docs.github.com/en/enterprise-cloud@latest/admin/data-residency/"
        "about-github-enterprise-cloud-with-data-residency",
        ["Norway", "Switzerland", "Japan", "GHE.com"],
        "Rendered official page includes reused region content absent from the pinned "
        "article file. Hash this actually reviewed EU/EFTA/Australia/US/Japan boundary; "
        "retrieved-page means no published commit identity, not a fabricated revision.",
    ),
    (
        "github-storage-rendered",
        "https://docs.github.com/en/enterprise-cloud@latest/admin/data-residency/"
        "about-storage-of-your-data-with-data-residency",
        ["outside your region", "Copilot", "Secret scanning"],
        "Rendered official storage exceptions complement the pinned template source. "
        "Compliant Copilot inference is conditional on the specified policy; no actual "
        "enterprise configuration or human authorization is asserted.",
    ),
    (
        "github-docs-reuse",
        DOCS_RAW + "LICENSE",
        ["Attribution 4.0 International"],
        "Pinned GitHub documentation uses CC-BY-4.0. Retain attribution, exact revision/"
        "hash and original factual findings only; no page content or assets redistributed.",
    ),
    (
        "learn-reuse",
        LEARN + "legal/termsofuse",
        ["Notice Specific to Documents", "explicit license terms"],
        "Learn document terms are constrained; separately explicit licenses can govern. "
        "Keep source metadata and original factual findings only, not article copies.",
    ),
    (
        "microsoft-site-reuse",
        "https://www.microsoft.com/en-us/legal/terms-of-use",
        ["Documents", "Personal and Non-Commercial"],
        "Microsoft site terms do not grant unrestricted reuse of Azure marketing pages. "
        "Keep linked metadata, checksum and original factual findings, not page text/assets.",
    ),
]


SOURCES_23 = [
    (
        "central-workspace-linked",
        "https://learn.microsoft.com/azure/azure-monitor/logs/design-logs-deployment",
        ["fewest number of workspaces", "Microsoft Entra tenants", "Data retention"],
        "Legacy link redirects to workspace-design. Start with one workspace, then use "
        "the fewest meeting tenant, region/residency, ownership, access, retention, cost "
        "and resilience requirements; central does not mean one universal workspace.",
    ),
    (
        "correlated-threats-linked",
        "https://learn.microsoft.com/azure/well-architected/security/monitor-threats"
        "#centralized-threat-detection-with-correlated-logs",
        ["correlated and normalized", "accurate timekeeping", "validation of logging"],
        "SIEM consolidation needs actual normalized/correlated data, synchronized time, "
        "detections and SecOps response. Onboarding/routing configuration proves none. "
        "Defender alerting alone may lack data aggregation. No query or threat test is run.",
    ),
    (
        "azure-lockbox-linked",
        "https://learn.microsoft.com/en-gb/azure/security/fundamentals/customer-lockbox-overview",
        ["Developer", "Global Administrator", "management groups", "Exclusions"],
        "Azure enablement is tenant administration, not subscription feature registration. "
        "Minimum Developer support, actual supported service/cloud population, subscription "
        "versus tenant approvers/logs, unsupported MG role scope and break-glass/incidental/"
        "legal-demand exclusions must be reviewed. Azure pending requests expire in four days.",
    ),
    (
        "m365-lockbox",
        LEARN + "purview/customer-lockbox-requests",
        ["Windows 365", "12 hours", "E5", "G5"],
        "M365 is separate tenant enablement/licensing: E5/G5 or qualifying add-on and "
        "supported Exchange/SharePoint/OneDrive/Teams/Windows365; Copilot interactions "
        "are covered through Exchange. Approver/admin and audit setup differ; requests "
        "expire after 12 hours without approval. No Azure resource establishes this.",
    ),
    (
        "event-grid-alerts-linked",
        "https://learn.microsoft.com/azure/event-grid/set-alerts",
        ["metrics and activity log operations", "dead-lettered", "Metrics"],
        "Actual link describes Event Grid service metric/activity alerts, not general log "
        "queries or proof of a log-oriented real-time solution. System topics use Metrics. "
        "The sample dead-letter threshold of ten is not a universal control requirement.",
    ),
    (
        "alert-types",
        LEARN + "azure/azure-monitor/alerts/alerts-types",
        ["Log search alert", "more latent", "Simple log search"],
        "Metric, activity-log, scheduled log-query and simple log alerts are distinct. "
        "Regular log evaluation and ingestion introduce latency; a configured frequency "
        "is not end-to-end real-time delivery. New preview metric types are not supported.",
    ),
    (
        "separate-accounts-linked",
        "https://learn.microsoft.com/azure/active-directory/roles/security-planning",
        ["dedicated accounts", "non-administrative", "emergency access"],
        "Legacy AAD link redirects to Entra security-planning. Separate everyday versus "
        "privileged use, individual accountability, emergency/automation exceptions, "
        "protection and actual operating evidence require manual review; counts of "
        "assignments/principals cannot establish separate-account use.",
    ),
    (
        "service-enablement-linked",
        "https://learn.microsoft.com/azure/cloud-adoption-framework/ready/landing-zone/"
        "design-area/service-enablement-framework",
        ["Segregation of duties", "Service availability", "Service-level agreements"],
        "CAF provides service-readiness questions spanning network/data, identity, "
        "governance, operations, compliance, SKUs/availability and SLAs. G06.01 needs "
        "an approved new-service design/onboarding plan; distinct G06.02 needs request "
        "intake, authorization, fulfillment, validation/escalation and accountable "
        "service-specific criteria. The source supplies no universal approval or SLA.",
    ),
    (
        "diagnostic-settings",
        LEARN + "azure/azure-monitor/essentials/diagnostic-settings",
        ["Aren't collected by default", "Azure Lighthouse", "latency"],
        "Resource logs require diagnostics; automatic metrics/activity logs differ. "
        "Cross-subscription or Lighthouse destinations require separate access/tenant "
        "evidence. Local joins intentionally require supplied in-bound typed workspaces "
        "and do not broaden tenant/scope to infer supported cross-boundary routing.",
    ),
    (
        "sentinel-onboarding",
        LEARN + "azure/sentinel/quickstart-onboard",
        ["paid service", "data connector", "Onboarding States"],
        "Onboarding, content/connectors and actual ingestion are separate. A workspace "
        "or default onboarding state does not establish correlation, active detections, "
        "all-service coverage, response, health or non-Sentinel SIEM adoption.",
    ),
    (
        "workspace-arm",
        LEARN + "azure/templates/microsoft.operationalinsights/2023-09-01/workspaces",
        ["retentionInDays", "publicNetworkAccessForIngestion", "PerGB2018"],
        "2023-09-01 has explicit SKU, default retention and network configuration. "
        "Only these bounded fields are retained; they are not table overrides, "
        "effective retention, ingest availability or completeness.",
    ),
    (
        "onboarding-arm",
        LEARN + "azure/templates/microsoft.securityinsights/2024-03-01/onboardingstates",
        ["customerManagedKey", "scope", "extension resource"],
        "2024-03-01 is a real workspace extension with customerManagedKey boolean. "
        "Only the exact default child joins a unique supplied workspace; no synthetic "
        "M365/Graph/Lockbox ARM types or universal SIEM predicate are added.",
    ),
    (
        "log-alert-arm",
        LEARN + "azure/templates/microsoft.insights/2023-12-01/scheduledqueryrules",
        ["LogAlert", "LogToMetric", "evaluationFrequency", "actionGroups"],
        "Only explicit LogAlert configuration with bounded supplied workspace IDs, "
        "enabled/frequency/window/condition count and typed action IDs is prepared. "
        "LogToMetric, nonworkspace scopes and new kinds stay unsupported. No KQL, "
        "dimensions, descriptions, rule bodies or action payloads are retained/executed.",
    ),
    (
        "topic-arm",
        LEARN + "azure/templates/microsoft.eventgrid/2022-06-15/topics",
        ["inputSchema", "CloudEventSchemaV1_0", "publicNetworkAccess"],
        "Only explicit input-schema and public-network enum context for custom topics. "
        "No endpoint, key, IP mask, identity, schema mapping or event payload retained.",
    ),
    (
        "topic-metrics",
        LEARN
        + "azure/azure-monitor/reference/supported-metrics/microsoft-eventgrid-topics-metrics",
        ["DeadLetteredCount", "DeliveryAttemptFailCount", "PublishFailCount"],
        "Prepared static Total topic criteria use these three actual REST metric names. "
        "Display names are not API names. Service metrics never become log-query proof.",
    ),
    (
        "metric-alert-arm",
        LEARN + "azure/templates/microsoft.insights/2018-03-01/metricalerts",
        ["SingleResourceMultipleMetricCriteria", "StaticThresholdCriterion", "actionGroupId"],
        "Reuse monitoring15's pinned metric API without altering its ExpressRoute semantics. "
        "Only single custom-topic static criteria are prepared; dynamic/multi-resource "
        "criteria remain unsupported, and action references are not delivery evidence.",
    ),
    (
        "diagnostic-arm",
        LEARN + "azure/templates/microsoft.insights/2021-05-01-preview/diagnosticsettings",
        ["workspaceId", "categoryGroup", "enabled"],
        "Reuse security22 diagnostic projection and typed destinations. Category groups "
        "and log selection are separate from metrics, default configuration coverage, "
        "actual category support, delivered ingestion, correlation and retention.",
    ),
    (
        "terraform-workspace",
        RAW + "website/docs/r/log_analytics_workspace.html.markdown",
        ["retention_in_days", "internet_ingestion_enabled", "2022-10-01"],
        "Pinned 4.50.0 explicit SKU, retention 30-730 and Internet flags normalize without "
        "inferring defaults; shared keys/customer IDs and arbitrary tags are withheld. "
        "Workspace retention is not every table's actual retention.",
    ),
    (
        "terraform-onboarding",
        RAW + "website/docs/r/sentinel_log_analytics_workspace_onboarding.html.markdown",
        ["workspace_id", "customer_managed_key_enabled", "2022-11-01"],
        "Pinned provider supports workspace-bound Sentinel onboarding; omitted CMK does "
        "not default false in evidence. Documentation import plural defaults is corrected "
        "by the actual implementation's literal default; no operational success inferred.",
    ),
    (
        "terraform-onboarding-implementation",
        RAW + "internal/services/sentinel/sentinel_log_analytics_workspace_onboarding_resource.go",
        ['"default"', "2022-11-01", "CustomerManagedKey"],
        "Actual 4.50.0 implementation constructs workspace extension onboardingStates/default "
        "using 2022-11-01. Strict parent IDs, not name heuristics, bind raw/plan evidence. "
        "No provider run, state polling, onboarding or default-value inference occurs.",
    ),
    (
        "learn-reuse",
        LEARN + "legal/termsofuse",
        ["Notice Specific to Documents", "explicit license terms"],
        "Retain attributed URL/revision/hash and original factual findings only, not "
        "article copies, screenshot assets, sample scripts or private request contents.",
    ),
    (
        "provider-license",
        RAW + "LICENSE",
        ["Mozilla Public License", "2.0"],
        "Pinned provider uses MPL-2.0. Only attributed metadata and original factual "
        "schema findings are retained; no implementation source is redistributed.",
    ),
]


SOURCES_16 = [
    (
        "gateway-diagnostics-linked",
        "https://learn.microsoft.com/azure/vpn-gateway/"
        "vpn-gateway-howto-setup-alerts-virtual-network-gateway-log",
        ["VPN Gateway", "GatewayDiagnosticLog", "TunnelDiagnosticLog"],
        "Actual D06.23 link redirects to VPN monitoring reference. Shared ARM resource type "
        "does not make IKE, P2S or tunnel categories applicable to ExpressRoute gateways.",
    ),
    (
        "expressroute-monitor-current",
        LEARN + "azure/expressroute/monitor-expressroute",
        ["diagnostic setting", "automatically", "gateway"],
        "Platform metrics are automatic; resource logs need diagnostic routing. Gateway "
        "metrics and actual ingestion/alert receipt must be reviewed separately from circuits.",
    ),
    (
        "gateway-logs",
        LEARN + "azure/azure-monitor/reference/supported-logs/"
        "microsoft-network-virtualnetworkgateways-logs",
        ["GatewayDiagnosticLog", "RouteDiagnosticLog", "IKEDiagnosticLog"],
        "Shared virtualNetworkGateways category index includes VPN-only logs. Prepare "
        "explicit categories/flags only, never infer ExpressRoute category support or health.",
    ),
    (
        "gateway-metrics",
        LEARN + "azure/azure-monitor/reference/supported-metrics/"
        "microsoft-network-virtualnetworkgateways-metrics",
        [
            "ExpressRouteGatewayCpuUtilization",
            "ExpressRouteGatewayBitsPerSecond",
            "ExpressRouteGatewayCountOfRoutesLearnedFromPeer",
        ],
        "ExpressRoute gateway metrics have gateway scope/namespace, not circuit scope. "
        "Dimension and export support differ. No default threshold or runtime result inferred.",
    ),
    (
        "vnet-expressroute-linked",
        "https://learn.microsoft.com/azure/expressroute/virtual-network-connectivity-guidance",
        ["peering", "disabled", "by default"],
        "Page recommends peering over gateway/MSEE paths but contains conflicting statements "
        "about default VNet connectivity. Retain discrepancy; project explicit flags only.",
    ),
    (
        "gateway-remote-traffic",
        LEARN + "azure/expressroute/expressroute-howto-add-gateway-portal-resource-manager",
        ["Allow traffic from remote virtual networks", "route maps", "always allowed"],
        "Current portal guidance says disabled by default; all applicable gateways need "
        "configuration. A route-map-upgraded vWAN known issue can allow vWAN routes regardless "
        "of flag. Explicit flags do not prove effective routing or absence of bypass.",
    ),
    (
        "azure-local-linked",
        "https://learn.microsoft.com/azure/cloud-adoption-framework/scenarios/"
        "azure-virtual-desktop/eslz-network-topology-and-connectivity",
        ["Azure Virtual Desktop", "reverse connect", "TLS"],
        "Original CAF workload link redirects to AVD connectivity, not a universal "
        "inspection mandate. Preserve workload-specific reverse-connect/TLS context.",
    ),
    (
        "interconnect-locations-linked",
        LEARN + "azure/expressroute/expressroute-locations-providers?tabs=america%2Ca-c%2Ca-k",
        ["two distinct", "peering locations", "geopolitical"],
        "Azure regions and ExpressRoute meet-me locations differ. Neither resource location "
        "nor equal/different peering labels proves physical transit or country/border crossing. "
        "D06.26 remains a factual question, not a prohibition.",
    ),
    (
        "peering-linked",
        LEARN + "azure/virtual-network/virtual-network-peering-overview",
        ["Global virtual network peering", "Microsoft backbone", "Service chaining"],
        "Local/global peering and service chaining are supported. Configured endpoint "
        "locations/access flags prove neither approved geography nor physical/transit paths.",
    ),
    (
        "firewall-linked",
        "https://learn.microsoft.com/azure/firewall/overview",
        ["east-west", "north-south", "Basic"],
        "Firewall capability/SKU is not actual outbound, non-HTTP/S inbound or conditional "
        "east-west inspection. Organization requirements and actual routes need evidence.",
    ),
    (
        "policy-linked",
        "https://learn.microsoft.com/azure/firewall-manager/policy-overview",
        ["same region", "NAT rule collections are not inherited", "DNS"],
        "Policies can bind globally while parent and child must share a region. Network/"
        "application rules inherit with parent priority; NAT does not. Names/associations "
        "do not designate organization-wide policy or prove complete coverage/delegation.",
    ),
    (
        "partner-linked",
        "https://learn.microsoft.com/azure/firewall-manager/deploy-trusted-security-partner",
        ["Zscaler", "VPN Gateway", "partner portal"],
        "Current deployment guidance lists Zscaler, VPN tunnels and partner-portal rule "
        "configuration. Binding/pending status is not a connected/filtering service. No "
        "signup, credential exchange, role assignment or deployment performed.",
    ),
    (
        "partner-current",
        LEARN + "azure/firewall-manager/trusted-security-partners",
        ["current supported security partner", "Zscaler", "Microsoft 365"],
        "Reviewed current support lists only Zscaler. Older schema enums are not current "
        "availability. No retirement date is established by these pages; other historical "
        "values remain unsupported/unknown rather than silently dropping the target. "
        "Microsoft 365 direct/local breakout has separate performance guidance.",
    ),
    (
        "manager-current",
        LEARN + "azure/firewall-manager/overview",
        ["only with secured virtual hub", "static or custom routes", "Routing Intent"],
        "Partner services/automatic routing require secured vWAN hubs, not hub VNets. "
        "Routing Intent governs inter-hub/branch filtering; Firewall Manager can overwrite "
        "custom/static routes. Existing binding is not topology or effective filtering.",
    ),
    (
        "fqdn-linked",
        "https://learn.microsoft.com/azure/firewall/fqdn-filtering-network-rules",
        ["DNS Proxy", "wildcards", "MSSQL"],
        "Prefer application FQDN rules for HTTP/S/MSSQL. Other TCP/UDP FQDN network rules "
        "require DNS proxy and do not support wildcards; resolution is IP-based, not SNI.",
    ),
    (
        "firewall-dns-current",
        LEARN + "azure/firewall/dns-settings",
        ["client virtual machines", "override", "Private DNS"],
        "Policy DNS overrides standalone settings; child can override inherited DNS. "
        "Clients must use the proxy for consistent resolution. Proxy flag proves neither "
        "client use nor successful resolution; Private DNS upstream behavior differs.",
    ),
    (
        "policy-provider",
        RAW + "website/docs/r/firewall_policy.html.markdown",
        ["base_policy_id", "proxy_enabled", "2024-05-01"],
        "Pinned 4.50.0 exposes explicit base policy and DNS flag. Omitted optional defaults "
        "do not prove root policy, disabled proxy or actual inherited configuration.",
    ),
    (
        "policy-rules-provider",
        RAW + "website/docs/r/firewall_policy_rule_collection_group.html.markdown",
        ["destination_fqdns", "protocols", "network_rule_collection"],
        "Bounded supplied rule counts/kinds/actions/protocols/FQDN counts can prepare "
        "review without retaining addresses, FQDNs, ports, descriptions or rule names.",
    ),
    *[
        (
            "network-policy-spec-" + name,
            SPEC_RAW + "specification/network/resource-manager/Microsoft.Network/Network/"
            "stable/2024-05-01/" + filename,
            markers,
            finding,
        )
        for name, filename, markers, finding in [
            (
                "policy",
                "firewallPolicy.json",
                ["basePolicy", "enableProxy", "targetFqdns"],
                "Pinned typed parent/DNS and rule collections; optional/read-only relationships "
                "are not complete inventory, root designation or effective filtering.",
            ),
            (
                "gateway",
                "virtualNetworkGateway.json",
                ["allowRemoteVnetTraffic", "allowVirtualWanTraffic"],
                "Two distinct explicit booleans. VNet flag excludes vWAN; unknown/missing is "
                "not a documented creation default or effective-route assertion.",
            ),
            (
                "partner",
                "securityPartnerProvider.json",
                ["ZScaler", "IBoss", "CheckPoint"],
                "Historical schema includes ZScaler/IBoss/CheckPoint; current reviewed Learn "
                "guidance lists only Zscaler. Old enum presence is not current support.",
            ),
        ]
    ],
    *[
        source
        for source in SOURCES_15
        if source[0]
        in {
            "metric-alert-arm",
            "connection-arm",
            "rest-spec-reuse",
            "provider-reuse",
            "learn-reuse",
        }
    ],
    *[
        source
        for source in SOURCES_17
        if source[0] in {"firewall-routing", "firewall-hierarchy", "subnet-arm"}
    ],
    (
        "gateway-traffic-provider",
        RAW + "website/docs/r/virtual_network_gateway.html.markdown",
        ["remote_vnet_traffic_enabled", "virtual_wan_traffic_enabled"],
        "Pinned 4.50.0 exposes two explicit distinct remote traffic flags. Documented "
        "optional defaults are not inferred for raw/imported/planned configuration.",
    ),
    *[source for source in SOURCES_22 if source[0] in {"diagnostic-arm", "terraform-diagnostics"}],
]
SOURCES_16 = list({source[0]: source for source in SOURCES_16}.values())
SOURCES_16_VWAN = [
    (
        "partner-vwan-vpn-rest",
        SPEC_RAW + "specification/network/resource-manager/Microsoft.Network/Network/"
        "stable/2024-05-01/virtualWan.json",
        ["VirtualHubProperties", "vpnGateway", "VpnGatewayProperties", "virtualHub"],
        "Actual pinned virtualWan.json, not nonexistent virtualHub.json/vpnGateway.json, "
        "defines hub.vpnGateway and VPN gateway.virtualHub references. This vWAN vpnGateways "
        "type differs from VNet virtualNetworkGateways. Configuration is not tunnel health.",
    ),
    (
        "partner-vwan-vpn-arm",
        LEARN + "azure/templates/microsoft.network/2024-05-01/vpngateways",
        ["virtualHub", "2024-05-01", "sharedKey"],
        "2024-05-01 vWAN VPN gateway has explicit virtualHub binding. Project only that "
        "typed ID; do not retain connections, addresses, keys, BGP or tunnel records.",
    ),
    (
        "partner-vwan-vpn-provider",
        RAW + "website/docs/r/vpn_gateway.html.markdown",
        ["virtual_hub_id", "2024-05-01", "Site-to-Site"],
        "Pinned 4.50.0 azurerm_vpn_gateway exposes required virtual_hub_id. A supplied "
        "positive reference is configuration only; hub's missing reciprocal reference "
        "cannot be inferred from provider defaults or a name.",
    ),
]


SOURCES_06 = [
    (
        "connect-staging-linked",
        "https://learn.microsoft.com/azure/active-directory/hybrid/"
        "how-to-connect-sync-staging-server",
        ["Active-Passive", "password writeback", "pending exports", "catch-up"],
        "Legacy link redirects to Connect Sync operations. Staging imports/synchronizes but "
        "does not normally export or run password sync/writeback; switching is an explicit "
        "active-passive procedure, never automatic active-active failover. Keep configuration "
        "aligned, verify pending exports/deletion protection and isolate the old active "
        "server before promotion. Password catch-up can take hours; do not restart during "
        "catch-up. This is not Cloud Sync equivalence or evidence of tested recovery.",
    ),
    (
        "synced-role-accounts-linked",
        "https://learn.microsoft.com/azure/active-directory/roles/best-practices",
        ["cloud native accounts", "on-premises synced accounts", "least privilege"],
        "Current redirected Entra guidance avoids synced accounts for directory roles "
        "because on-premises compromise can reach cloud authority. Any checklist exception "
        "requires separate justified, scoped, time-bound human evidence, not Azure role "
        "principalType, VM naming, managed identity or a fabricated synchronization flag.",
    ),
    (
        "app-proxy-current",
        LEARN + "entra/identity/app-proxy/overview-what-is-app-proxy",
        ["private network connector", "outbound", "internal users"],
        "The original application-proxy URL now redirects to a 404. Current overview "
        "describes Entra's cloud service and private network connectors for remote web "
        "application access, not an ARM proxy resource or general internal-user VPN. "
        "Central platform ownership, application onboarding and actual SSO remain decisions.",
    ),
    (
        "app-proxy-ha",
        LEARN + "entra/identity/app-proxy/application-proxy-high-availability-load-balancing",
        ["at least two connectors", "Three connectors", "different outbound connections"],
        "At least two connectors per group, preferably three, separate outbound failure "
        "domains and automatic updates are current HA guidance. Backend session persistence "
        "and connector/service operation need separate evidence. VM counts/names do not "
        "establish connector groups, configuration, platform ownership or availability.",
    ),
    (
        "identity-network-rbac-linked",
        "https://learn.microsoft.com/azure/cloud-adoption-framework/ready/landing-zone/"
        "design-area/identity-access-landing-zones",
        ["virtual network peered", "data plane", "regularly validate resource entitlements"],
        "Current reference architecture optionally deploys identity services in a dedicated "
        "subscription/VNet peered to the platform hub. Entra-native applications may need "
        "none. Secure identity boundaries and workload access separately. Data-plane RBAC "
        "is service-specific, not generic Owner authority. PIM review operation differs "
        "from configured assignments and the historical section anchors have changed.",
    ),
    (
        "pim-review-linked",
        "https://learn.microsoft.com/azure/active-directory/privileged-identity-management/"
        "pim-create-roles-and-resource-roles-review",
        ["snapshot", "eligible assignments", "Applied", "group"],
        "Current redirected PIM review guidance distinguishes Entra PRA from resource "
        "Owner/UAA prerequisites, licensing and active/eligible/all selection. Each instance "
        "captures a start-time snapshot; recurring configuration is not completion or "
        "applied revocation. Entra role-assignable groups are reviewed as groups; Azure "
        "group-member denial does not remove group membership and nested-group limits "
        "need review. Service-principal reviews have additional Workload ID Premium terms.",
    ),
    (
        "enrollment-owners-linked",
        "https://learn.microsoft.com/azure/cloud-adoption-framework/ready/landing-zone/"
        "design-area/azure-billing-enterprise-agreement",
        ["minimize the number of account owners", "February 15, 2024", "account owner"],
        "EA account owners can own subscriptions created under their account; other EA "
        "roles do not by themselves confer subscription/directory authority. Minimize "
        "actual enrollment account-owner authority, not a subscription Owner count. "
        "The EA portal retired in 2024; agreement applicability and exceptions need review.",
    ),
    (
        "ea-role-qualification",
        LEARN + "azure/cost-management-billing/manage/understand-ea-roles",
        ["November 16, 2026", "one account owner per account", "individual user accounts"],
        "EA billing roles differ from Azure RBAC and support individual users, not DG/SG "
        "assignment. One owner per account is a service constraint, not a universal "
        "enrollment-wide least-privilege threshold. Starting 2026-11-16 new billing role "
        "assignments require WSA; existing MSA assignments are not yet impacted.",
    ),
    (
        "sovereign-location-linked",
        LEARN + "industry/financial-services/architecture/location-based-access-content",
        ["GPS", "authentication context", "exports or downloads"],
        "This FSI example uses application-integrated authentication context and named "
        "GPS locations, with PIM access a possible use case. It does not define an "
        "organization's eligible administrator countries, nationality, legal sovereignty "
        "or blanket coverage for exported data. Those remain independently manual.",
    ),
    (
        "location-qualification",
        LEARN + "entra/identity/conditional-access/location-condition",
        ["Network", "unknown countries", "public IP address", "GPS"],
        "Location condition is now Network. Public-IP mapping or consented Authenticator "
        "GPS are access signals, not nationality or complete sovereignty assurance. "
        "Unknown locations, policy scope/exclusions and application integration need "
        "independent review. No employee location or sign-in data is collected.",
    ),
    (
        "vault-data-plane",
        LEARN + "azure/key-vault/general/rbac-guide",
        ["2026-02-01", "control plane", "data plane", "invalidates all access policies"],
        "Vault control/data planes are independent; Key Vault Contributor does not grant "
        "secret/key access. New API2026-02-01 defaults do not fill missing pinned2024-11-01 "
        "evidence. Explicit RBAC flag prepares only the configured vault model. HSM differs; "
        "changing model can cause outages without equivalent roles. No migration occurs.",
    ),
    (
        "storage-data-plane",
        LEARN + "azure/storage/blobs/authorize-access-azure-active-directory",
        ["data access", "Owner", "Contributor", "Reader"],
        "Blob data roles and token authorization differ from control-plane Owner/"
        "Contributor/Reader roles. Service support, effective permissions and actual "
        "authentication must be independently reviewed; account presence is insufficient.",
    ),
    (
        "sql-data-plane",
        LEARN + "azure/azure-sql/database/authentication-aad-overview",
        ["Create SQL principals", "Microsoft Entra administrator", "database"],
        "Azure SQL Entra authentication requires service-specific administrator and SQL "
        "principal/permission configuration. Do not equate generic Azure resource Owner "
        "or a Key Vault RBAC flag to SQL database authorization or every database service.",
    ),
    *[source for source in SOURCES_05 if source[0] == "identity-team-boundaries"],
    *[source for source in SOURCES if source[0] in {"vault-arm", "terraform-vault"}],
    *[source for source in SOURCES_11 if source[0] in {"peering-arm", "terraform-peering"}],
    *[source for source in SOURCES_02 if source[0] in {"learn-terms", "provider-license"}],
]


SOURCES_29 = [
    (
        "platform-automation-linked",
        "https://learn.microsoft.com/azure/cloud-adoption-framework/ready/landing-zone/"
        "design-area/platform-automation-devops",
        ["lifecycle", "DevOps teams topologies", "Test-driven development"],
        "Platform automation spans provisioning, management, evolution and operations. "
        "An accelerator or repository is not evidence that an assessed cross-functional "
        "team owns and operates that lifecycle.",
    ),
    (
        "team-topology-linked",
        "https://learn.microsoft.com/azure/cloud-adoption-framework/ready/considerations/"
        "devops-teams-topologies#design-recommendations",
        ["cross-functional", "business units", "Enabling teams", "policy-driven"],
        "Current topology separates platform lifecycle, workload lifecycle and time-bound "
        "enabling support. IT/security/compliance/business representation, explicit functions "
        "and policy-driven workload autonomy require operating evidence. The old "
        "design-recommendations fragment no longer identifies the current headings.",
    ),
    (
        "iac-linked",
        "https://learn.microsoft.com/azure/cloud-adoption-framework/ready/considerations/"
        "infrastructure-as-code",
        ["implementation options", "Bootstrap", "continuous"],
        "The original IaC link redirects to platform implementation options. Accelerator "
        "planning/prerequisite/bootstrap/run capabilities do not prove actual CI/CD use, "
        "deployment quality or application-team adoption.",
    ),
    (
        "lifecycle-linked",
        "https://learn.microsoft.com/azure/cloud-adoption-framework/ready/considerations/"
        "development-strategy-development-lifecycle#automated-builds",
        ["unit tests", "Key Vault", "predeployment", "Rollback"],
        "Lifecycle guidance distinguishes IaC/application build tests, limited service "
        "connections, secret variables, production-like delivery, change previews and rollback. "
        "A build file, green result or compiler cannot establish full operating discipline.",
    ),
    (
        "landing-zone-tdd",
        LEARN + "azure/cloud-adoption-framework/ready/considerations/"
        "development-strategy-test-driven-development",
        ["definition of done", "red/green", "not to create a suite of tests"],
        "TDD ties tests to agreed acceptance criteria and repeats red/green/refactoring and "
        "controlled test-environment validation. Test quantity, syntax checks and compiler "
        "success are not adequacy, application coverage or an agreed definition of done.",
    ),
    (
        "rbac-best-practices",
        LEARN + "azure/role-based-access-control/best-practices",
        ["least privilege", "conditions", "groups, not users", "wildcard"],
        "Use least privilege at narrow scopes, review privileged/conditional access and "
        "groups, and avoid broad wildcard custom permissions. Definitions/assignments alone "
        "do not establish effective workload autonomy or actual operating boundaries.",
    ),
    (
        "rbac-custom-roles",
        LEARN + "azure/role-based-access-control/custom-roles",
        ["built-in roles", "specific needs", "Test the custom role"],
        "Custom roles are conditional on built-in roles not meeting specific needs, not a "
        "universal requirement from frozen H01.03 shorthand. Test justified custom permissions "
        "and actual effective scope without collecting directory or raw role-action records.",
    ),
    (
        "secret-pipeline",
        LEARN + "azure/devops/pipelines/release/key-vault-in-own-project?view=azure-devops",
        ["service connection", "Managed Identity", "secrets"],
        "Key Vault pipeline integration requires authentication, access and connectivity. "
        "A sample tutorial or vault does not prove assessed code avoids literals or that "
        "runtime variables/logs/artifacts remain safe. No tutorial actions are executed.",
    ),
    (
        "secret-template-reference",
        LEARN + "azure/azure-resource-manager/templates/key-vault-parameter",
        ["enabledForTemplateDeployment", "deploy/action", "secretVersion"],
        "ARM parameter references retrieve a secret at deployment, including optional version "
        "selection and separate deployment access. Secure parameter type, reference or "
        "vault existence proves neither complete secret hygiene nor VM certificate behavior. "
        "No secret values, identifiers or deployment permissions are collected.",
    ),
    (
        "vending-linked",
        "https://learn.microsoft.com/azure/cloud-adoption-framework/ready/landing-zone/"
        "design-area/subscription-vending",
        ["CCoE", "IPAM", "commercial agreement", "aren't hard limits", "MPA"],
        "CCoE defines business logic/approval; platform teams create/configure/govern and hand "
        "off; workloads update budgets and operate. Intake, IPAM/networking, hierarchy, quotas, "
        "identities, offer eligibility and failure handling are separate. Budgets are not hard "
        "limits; DevTest is not available for MPA. An alias cannot prove this whole process.",
    ),
    (
        "vending-implementation",
        LEARN + "azure/architecture/landing-zones/subscription-vending",
        ["trackable request", "dedicated state file", "OpenID Connect", "Post-deployment"],
        "The request/source-control/deployment example is one approach, not a mandatory "
        "Gitflow policy. Validate approved input, one request per subscription, isolated "
        "Terraform state, least-privileged identity and result reporting/handoff. "
        "Creation/configuration ends automation, not workload operations.",
    ),
    (
        "vending-agreements",
        LEARN + "azure/cost-management-billing/manage/programmatically-create-subscription",
        [
            "Enterprise Agreement",
            "Microsoft Customer Agreement",
            "Microsoft Partner Agreement",
            "can't create support plans",
        ],
        "Programmatic creation covers EA/MCA/MPA with agreement/API-specific requirements. "
        "It does not create support plans or authorize a financial, subscription or access action.",
    ),
    (
        "vending-ea",
        LEARN + "azure/cost-management-billing/manage/"
        "programmatically-create-subscription-enterprise-agreement",
        ["Enterprise Administrator", "Enrollment Account", "2019-10-01-preview"],
        "EA creation requires Enterprise Administrator or Enrollment Account Owner authority; "
        "service principal delegation and API-version prerequisites differ. Subscription "
        "resource RBAC alone is not billing-plane creation authority.",
    ),
    (
        "vending-mca",
        LEARN + "azure/cost-management-billing/manage/"
        "programmatically-create-subscription-microsoft-customer-agreement",
        ["invoice section", "billing profile", "Azure subscription creator"],
        "MCA requires qualifying invoice-section/billing-profile/billing-account authority; "
        "legacy/latest API permissions can differ and cross-tenant creation has separate "
        "guidance. No actual agreement, billing scope or authority is inferred.",
    ),
    (
        "vending-mpa",
        LEARN + "azure/cost-management-billing/manage/"
        "programmatically-create-subscription-microsoft-partner-agreement",
        ["Admin Agent", "cloud solution provider", "REST APIs"],
        "MPA prerequisites name CSP Admin Agent. The text says REST examples and currently "
        "unsupported CLI/PowerShell although later tabs refer to CLI; this inconsistency "
        "does not establish an accepted executable client or actual customer eligibility.",
    ),
    (
        "learn-terms",
        LEARN + "legal/termsofuse",
        ["documentation", "explicit license terms", "third party"],
        "Retain attributed URLs, retrieved revisions/hashes and independently written factual "
        "findings only. Do not redistribute article text, comments, images or sample scripts; "
        "linked software and third-party material have separate terms.",
    ),
]


SOURCES_27 = [
    (
        "policy-overview",
        LEARN + "azure/governance/policy/overview",
        ["initiative", "Resource Policy Contributor", "audit"],
        "Actual E01.01/.03/.04/.05/.07/.08/.09 link. Initiatives group rules; definition "
        "placement and assignment scopes differ. Begin with audit and review as code. "
        "The current overview now discusses identity-aware policies; that is not an "
        "implemented interpreter, entitlement check or blanket replacement for RBAC.",
    ),
    (
        "approved-services",
        LEARN + "security/benchmark/azure/mcsb-asset-management#am-2-use-only-approved-services",
        ["AM-2", "approved", "Azure Policy"],
        "Actual E01.06 link requires organization-approved services and audit/restriction. "
        "It supplies no universal approved taxonomy or evidence that a referenced rule "
        "enforces one. ARG/Monitor suggestions are not additional execution authorization.",
    ),
    (
        "policy-scope",
        LEARN + "azure/governance/policy/concepts/scope",
        ["Definition location", "notScopes", "exempt/Action"],
        "Custom definitions live at management groups or subscriptions, not resource groups. "
        "Assignment must be at that location or a descendant. Exclusions omit evaluation/"
        "compliance counting; tracked exemptions are separate objects with extra permissions.",
    ),
    (
        "policy-assignment",
        LEARN + "azure/governance/policy/concepts/assignment-structure",
        ["DoNotEnforce", "definitionVersion", "resourceSelectors", "overrides"],
        "ID creation scope, excluded scopes, selectors, overrides, parameters, versions and "
        "enforcement mode are independent applicability/effect constraints. Missing/default/"
        "wildcard/effective versions are not exact supplied-version joins. DoNotEnforce "
        "does not disable evaluation; Default is not effective enforcement proof.",
    ),
    (
        "policy-exemption",
        LEARN + "azure/governance/policy/concepts/exemption-structure",
        ["expiresOn", "assignmentScopeValidation", "policyDefinitionReferenceId"],
        "Exemptions can select initiative members and resource/identity subsets, expire "
        "without object deletion and relax assignment-scope validation. Saved references "
        "alone cannot establish effective exemption, approval or complete coverage.",
    ),
    (
        "policy-effects",
        LEARN + "azure/governance/policy/concepts/effect-basics",
        ["disabled", "manual", "cumulative most restrictive"],
        "Explicit literal then.effect is a configuration fact only. Parameterized effects, "
        "conditions, effect-specific details, overrides, modes and independent cumulative "
        "assignments are not interpreted; existing resources and remediation differ.",
    ),
    (
        "policy-regulatory",
        LEARN + "azure/governance/policy/concepts/regulatory-compliance",
        ["Preview", "Customer", "Shared", "policyMetadata"],
        "Current page calls regulatory initiative grouping Preview. Groups/counts/reference "
        "metadata are not an arbitrary legal-control mapping, legal compliance verdict "
        "or customer/Microsoft/shared responsibility acceptance.",
    ),
    (
        "management-hierarchy",
        LEARN + "azure/governance/management-groups/overview",
        ["one parent", "tenant ID", "must have"],
        "Tenant root is directory-bound, not a name or the highest visible selected node. "
        "Use positive saved parent paths only; missing parents or incomplete trees prove "
        "no root identity or effective inherited policy/role outcome.",
    ),
    (
        "landing-zone-hierarchy",
        LEARN + "azure/cloud-adoption-framework/ready/landing-zone/design-area/"
        "resource-org-management-groups",
        ["Intermediate root", "Limit the number", "workload teams"],
        "Intermediate root is below tenant root with ALZ-wide parent purpose, requiring "
        "explicit designation. Root assignments should be limited but no numeric cap is "
        "specified. Workload RBAC is normally subscription/resource-group scoped, unlike "
        "platform-team MG access controlled through PIM. Initial management-group URL "
        "without resource-org prefix returned404; this actual page is the reviewed source.",
    ),
    (
        "resource-policy-contributor",
        LEARN + "azure/role-based-access-control/built-in-roles/management-and-governance"
        "#resource-policy-contributor",
        ["36243c78-bf99-498c-9df9-86d9f8d28608", "policyenrollments", "*/read"],
        "Role GUID36243c78-bf99-498c-9df9-86d9f8d28608 includes control-plane */read, "
        "Policy/PolicyInsights, deployments/support; current page also includes enrollments. "
        "It has no roleAssignments/write or dataActions. Reference/principalType alone "
        "does not prove application-team designation, active membership/PIM, absence of "
        "deny/conditions or effective least privilege/remediation-identity authority.",
    ),
    *[
        (
            "policy-spec-" + stem,
            SPEC_RAW + "specification/resources/resource-manager/Microsoft.Authorization/"
            "policy/stable/2023-04-01/" + stem + ".json",
            markers,
            finding,
        )
        for stem, markers, finding in [
            (
                "policyDefinitions",
                ["policyType", "policyRule", "version"],
                "Pinned2023-04-01 custom subscription/MG definitions versus global built-ins. "
                "Minimize type, explicit supported mode, exact version and literal effect; "
                "withhold rule/parameters/metadata and never fetch referenced definitions.",
            ),
            (
                "policySetDefinitions",
                ["PolicyDefinitionReference", "definitionVersion", "groupNames"],
                "Pinned2023-04-01 initiative references with per-member versions and unique "
                "reference IDs. Retain typed IDs, hashed member labels and bounded group counts "
                "only; no group names, regulatory mapping, parameter values "
                "or recursive evaluation.",
            ),
            (
                "policyAssignments",
                ["notScopes", "enforcementMode", "resourceSelectors"],
                "Pinned2023-04-01 assignment scope is ID prefix; scope property is readOnly. "
                "Minimized references/exclusions and counts preserve missing inputs as unknown. "
                "Selectors/overrides/parameters/identity bodies are not retained or interpreted.",
            ),
        ]
    ],
    *[
        (
            "policy-provider-" + stem,
            RAW + "website/docs/r/" + stem + ".html.markdown",
            markers,
            finding,
        )
        for stem, markers, finding in [
            (
                "policy_definition",
                ["management_group_id", "policy_rule", "policy_type"],
                "PinnedAzureRM4.50.0 explicit subscription/MG definitions; JSON-string rule "
                "is bounded/duplicate-checked before extracting literal effect only. "
                "Metadata version is not an effective or REST version; no join synthesized.",
            ),
            (
                "policy_set_definition",
                ["policy_definition_reference", "reference_id", "version"],
                "PinnedAzureRM4.50.0 subscription initiative references; member version optional, "
                "so absent/unresolved versions cannot make an exact supplied-version join. "
                "This resource has no management_group_id argument.",
            ),
            (
                "management_group_policy_assignment",
                ["management_group_id", "enforce", "not_scopes"],
                "PinnedAzureRM4.50.0 MG assignment with exact explicit target binding. "
                "Omitted enforce, exclusions, selectors or overrides are not inferred defaults.",
            ),
            (
                "subscription_policy_assignment",
                ["subscription_id", "enforce", "resource_selectors"],
                "PinnedAzureRM4.50.0 subscription assignment. Separate scope-specific provider "
                "resources share one minimized model; unsupported resource assignments "
                "stay unsupported.",
            ),
            (
                "resource_group_policy_assignment",
                ["resource_group_id", "enforce", "overrides"],
                "PinnedAzureRM4.50.0 RG assignment with explicit typed target; no subscription/"
                "MG promotion, service approval or automatic inheritance claim.",
            ),
        ]
    ],
    (
        "policy-role-arm",
        LEARN + "azure/templates/microsoft.authorization/2022-04-01/roleassignments",
        ["roleDefinitionId", "principalType", "conditionVersion"],
        "Existing versioned2022-04-01 role-assignment model is reused, without personal "
        "principals/condition bodies or new identity/role collection. Exact assignment "
        "scope and recognized role reference are not effective delegation.",
    ),
    (
        "learn-terms",
        LEARN + "legal/termsofuse",
        ["Personal and Non-Commercial", "DOCUMENTATION", "License"],
        "Reviewed Learn terms and documentation-specific terms; retain source metadata, "
        "URLs/revisions/hashes and own factual findings only, not articles/sample scripts.",
    ),
    (
        "policy-spec-license",
        SPEC_RAW + "LICENSE",
        ["MIT", "copyright"],
        "Pinned REST-spec MIT terms reviewed; only own findings and source metadata retained.",
    ),
    (
        "policy-provider-license",
        RAW + "LICENSE",
        ["Mozilla Public License", "2.0"],
        "Pinned provider MPL2.0 terms reviewed; no provider source code redistributed.",
    ),
]


SOURCES_25 = [
    (
        "service-health-linked",
        "https://learn.microsoft.com/azure/service-health/"
        "alerts-activity-log-service-notifications-portal",
        ["Resource Health", "Global", "public clouds"],
        "Service Health and Resource Health events are distinct. Current guidance limits "
        "Service Health alerts to public clouds/global and requires Global action groups. "
        "Subscription/tenant preview and event filters need separate coverage review.",
    ),
    (
        "action-groups-linked",
        "https://learn.microsoft.com/azure/azure-monitor/alerts/action-groups",
        ["five action groups", "Global", "one-time passcode"],
        "Enabled receiver configuration is not verified recipients, delivery or response. "
        "Global and regional processing differ; current email OTP enforcement requires "
        "operating evidence. No recipients, endpoints, secrets or contact tests are retained.",
    ),
    (
        "sentinel-linked",
        "https://learn.microsoft.com/azure/sentinel/quickstart-onboard",
        ["paid service", "data connector", "Log Analytics"],
        "This linked Sentinel onboarding page does not itself specify the checklist's "
        "no-raw-log-export principle. Onboarding/workspace configuration cannot establish "
        "all export paths or an on-premises boundary; require independent architecture review.",
    ),
    (
        "logs-reporting-linked",
        "https://learn.microsoft.com/azure/cloud-adoption-framework/ready/"
        "azure-setup-guide/monitoring-reporting?tabs=AzureMonitor",
        ["Visualization", "workbooks", "Logs"],
        "CAF describes collection, insights, visualization and response. Workspace existence "
        "does not establish ingestion, useful reports, use of Logs or report quality.",
    ),
    (
        "diagnostics-extension-linked",
        "https://learn.microsoft.com/azure/azure-monitor/agents/diagnostics-extension-overview",
        ["March 31, 2026", "no longer supported", "Don't use new deployments"],
        "WAD/LAD retired March 31, 2026; the current page explicitly forbids new deployments. "
        "Preserve immutable conditional wording but review legacy applicability, migration, "
        "shared-storage boundaries and alternatives, not an invented supported extension.",
    ),
    (
        "diagnostics-migration",
        LEARN + "azure/azure-monitor/agents/azure-monitor-agent-migration-wad-lad",
        ["Data Collection Rules", "Auxiliary", "September 1, 2026"],
        "AMA/DCR and destination-specific replacements require parity and cutover evidence. "
        "The ADX/Fabric preview destination also retired September 1, 2026. Do not copy "
        "stale deployment steps or infer migration from agent/storage presence.",
    ),
    (
        "operational-alerts-linked",
        "https://learn.microsoft.com/azure/azure-monitor/alerts/alerts-overview",
        ["Metric alerts", "Log search alerts", "Activity log alerts"],
        "Metric, scheduled log-query and activity alerts are distinct configuration types. "
        "Configured enabled criteria/actions do not prove actual firing, notification, "
        "acknowledgement, escalation or an approved operational response requirement.",
    ),
    (
        "monitoring-requirements-linked",
        "https://learn.microsoft.com/azure/architecture/best-practices/monitoring",
        ["Health monitoring", "Availability monitoring", "Performance monitoring"],
        "Requirements depend on business health, availability, performance, security and "
        "operating scenarios. No generic rule count, frequency or fabricated SLA answers "
        "the independently manual requirements assessment.",
    ),
    (
        "amba-linked",
        "https://learn.microsoft.com/azure/cloud-adoption-framework/ready/"
        "landing-zone/design-area/management-monitor",
        ["DeployIfNotExists", "Remediate", "service health alerts"],
        "CAF separates AMBA policy/initiative import, assignment, brownfield remediation "
        "and tests. Service Health needs direct action groups, not processing rules. "
        "Saved Policy references cannot prove AMBA origin/version or complete deployment.",
    ),
    (
        "redundancy-linked",
        "https://learn.microsoft.com/en-gb/azure/storage/common/redundancy-migration?tabs=portal",
        ["two-step", "data synchronization", "no SLA"],
        "Replication changes have account/service restrictions, conversion and synchronization "
        "requirements; configuration does not prove conversion completion or ready failover. "
        "No migration, support request, paid change or data-plane access is performed.",
    ),
    (
        "storage-redundancy",
        LEARN + "azure/storage/common/storage-redundancy",
        ["asynchronously", "ZRS", "data-modifying operations"],
        "ZRS protects primary zones; GRS protects a secondary region asynchronously, and "
        "GZRS combines them. Read-access is distinct. LRS is not zone/geo redundancy. "
        "SKU is not actual availability, RPO/RTO, backup, failover readiness or residency.",
    ),
    (
        "resource-health",
        LEARN + "azure/service-health/resource-health-alert-monitor-guide",
        ["distinct", "Unknown", "Platform initiated"],
        "Resource Health is individual-resource status/transition/reason monitoring; "
        "Service Health is broader service incidents. Do not substitute either population "
        "or a configured status filter for actual health or all-resource event coverage.",
    ),
    *[
        (
            identity,
            SPEC_RAW + "specification/monitor/resource-manager/Microsoft.Insights/Insights/" + path,
            markers,
            finding,
        )
        for identity, path, markers, finding in [
            (
                "activity-alert-spec",
                "stable/2020-10-01/activityLogAlerts_API.json",
                ["allOf", "containsAny", "actionGroupId", "scopes"],
                "Pinned 2020-10-01 defines allOf/anyOf/leaf criteria and explicit enabled, "
                "scope and action references. Only literal single category equality is "
                "classified; other condition payloads are withheld and remain incomplete.",
            ),
            (
                "action-group-spec",
                "stable/2023-01-01/actionGroups_API.json",
                ["emailReceivers", "enabled", "location"],
                "Pinned 2023-01-01 exposes receiver arrays, explicit enabled and location. "
                "Retain bounded per-type counts only, never receiver identities or secrets. "
                "Absent arrays/flags/location are unknown, not empty/enabled/global defaults.",
            ),
        ]
    ],
    *[
        (
            "terraform-" + name,
            RAW + f"website/docs/r/{name}.html.markdown",
            markers,
            finding,
        )
        for name, markers, finding in [
            (
                "monitor_activity_log_alert",
                ["ServiceHealth", "resource_health", "2020-10-01"],
                "4.50.0 explicit category, scopes, enabled and action references normalize "
                "without defaults. Only category equality is interpreted; filter block "
                "presence/count is not semantic matching or actual health assurance.",
            ),
            (
                "monitor_action_group",
                ["email_receiver", "location", "2023-01-01"],
                "4.50.0 receiver blocks normalize to bounded counts; enabled and location "
                "must be explicit. Default true/global is never evidence. No contacts retained.",
            ),
            (
                "monitor_metric_alert",
                ["dynamic_criteria", "criteria", "2018-03-01"],
                "4.50.0 static metric criteria counts are configuration context only; "
                "dynamic/web-test/multi-resource forms remain unsupported. No metric name, "
                "dimension, threshold payload or notification content is retained.",
            ),
            (
                "storage_account",
                ["account_tier", "account_replication_type", "RAGZRS"],
                "4.50.0 explicit tier plus replication type forms an exact reviewed SKU, "
                "never substring matching or a default. Unsupported Premium geo forms "
                "and omitted values remain unknown; kind is separately explicit context.",
            ),
        ]
    ],
    (
        "storage-arm",
        LEARN + "azure/templates/microsoft.storage/2023-05-01/storageaccounts",
        ["Standard_RAGZRS", "Premium_ZRS", "kind"],
        "Pinned 2023-05-01 root SKU and kind are separate from storage properties. "
        "Accept only its eight exact SKUs for configuration classification, not a "
        "guarantee that a kind/region/service combination is supported or operating.",
    ),
    *[
        source
        for source in SOURCES_23
        if source[0]
        in {
            "workspace-arm",
            "log-alert-arm",
            "metric-alert-arm",
            "terraform-workspace",
            "learn-reuse",
            "provider-license",
        }
    ],
    *[source for source in SOURCES_14 if source[0] == "rest-spec-reuse"],
    *[source for source in SOURCES_27 if source[0].startswith("policy-spec-")],
]


SOURCES_10 = [
    (
        "application-delivery",
        "https://learn.microsoft.com/azure/cloud-adoption-framework/ready/"
        "azure-best-practices/plan-for-app-delivery",
        ["spoke", "Front Door", "WAF"],
        "Application delivery is workload-owned; Application Gateway belongs with the "
        "application, not as a shared hub service. A documented standard, actual WAF "
        "operation and Front Door origin restriction remain human decisions.",
    ),
    (
        "network-design",
        "https://learn.microsoft.com/azure/cloud-adoption-framework/ready/"
        "enterprise-scale/network-topology-and-connectivity",
        ["Connectivity", "Corp", "Online"],
        "Redirects to landing-zone/design-area. Align networking with actual traffic "
        "and hybrid requirements; MG/resource names do not designate hub or spoke purpose.",
    ),
    (
        "landing-zone-regions",
        "https://learn.microsoft.com/azure/cloud-adoption-framework/ready/considerations/regions",
        ["multiple regions", "DNS zones are global", "Connectivity"],
        "Prepare platform connectivity for regional expansion and DR. Supplied locations "
        "are not independent failure domains, complete regional services or exercised DR. "
        "Private DNS zones are global, not another regional deployment.",
    ),
    (
        "traditional-topology",
        "https://learn.microsoft.com/azure/cloud-adoption-framework/ready/"
        "azure-best-practices/traditional-azure-networking-topology",
        ["aren't transitive", "minimal shared services", "partner vendor", "more than two"],
        "Traditional hub-spoke is scenario-dependent. Minimal gateways/firewall/NVAs and "
        "conditional DNS belong in a designated hub, not shared L7 ingress. Global peering "
        "is nontransitive; direct spoke paths can bypass inspection. More-than-two-region "
        "global transit has Virtual WAN/ExpressRoute alternatives, not a universal peering rule.",
    ),
    (
        "partner-nva",
        "https://learn.microsoft.com/azure/architecture/reference-architectures/dmz/nva-ha",
        ["vendor", "Convergence time", "Traffic symmetry"],
        "Redirects to networking/guide/network-virtual-appliance-high-availability. Vendor "
        "validation, actual version/topology/support, convergence, SNAT/symmetry and "
        "failover require partner evidence. Generic Azure patterns do not prove support.",
    ),
    (
        "coexisting-gateways",
        "https://learn.microsoft.com/azure/expressroute/"
        "expressroute-howto-coexist-resource-manager"
        "#to-enable-transit-routing-between-expressroute-and-azure-vpn",
        ["65515", "Basic", "/27", "Route Server"],
        "Conditional ER/S2S VPN coexistence needs route-based non-Basic VPN. GatewaySubnet "
        "/27-or-larger is not RouteServerSubnet sizing. Backup is private, not Microsoft, "
        "peering; equal-prefix preference differs from longest-prefix selection.",
    ),
    (
        "route-server-quickstart",
        "https://learn.microsoft.com/azure/route-server/"
        "quickstart-configure-route-server-portal#create-a-route-server-1",
        ["RouteServerSubnet", "minimum of /26 or larger", "Standard"],
        "Actual redirect quickstart-create-route-server-portal now requires /26 or larger. "
        "Immutable D01.08 and pinned AzureRM4.50.0 still say /27; preserve that discrepancy "
        "and qualify any sizing subcheck by this captured current source, not a whole verdict.",
    ),
    (
        "route-server-transit",
        LEARN + "azure/route-server/expressroute-vpn-support",
        ["active-active", "65515", "same virtual network", "isn't supported"],
        "Route exchange must be explicitly enabled; VPN active-active/ASN65515 are required, "
        "VPN BGP is not. All gateways must share the Route Server VNet. No ER-to-ER "
        "circuit transit or runtime route/health proof follows from configuration.",
    ),
    (
        "route-server-faq",
        LEARN + "azure/route-server/route-server-faq",
        ["S2S", "P2S", "4,000", "50,000", "10,000", "isn't an Azure Virtual WAN"],
        "VNet Route Server uses virtualHubs ARM identity but is not Virtual WAN. Transit "
        "excludes P2S. Current limits include16 BGP peers,4000 routes/peer,500 VNets,"
        "50000 VMs (capacity-dependent),10000 total prefixes; combined VNet/Route Server "
        "advertisements to ER remain1000. Updates count against peer limits; no estate "
        "count, entitlement or capacity is inferred from selected supplied records.",
    ),
    (
        "global-peering",
        "https://learn.microsoft.com/azure/virtual-network/virtual-networks-faq"
        "#can-i-create-a-peering-connection-to-a-vnet-in-a-different-region",
        ["Transitive peering is not supported", "different regions", "Connected"],
        "Global peering connects different regions; both directional links are required. "
        "Nontransitive and Basic Load Balancer/global-peering restrictions apply. Location "
        "inequality and reciprocal references do not establish hub designation or working paths.",
    ),
    (
        "network-insights",
        "https://learn.microsoft.com/azure/azure-monitor/insights/network-insights-overview",
        ["without requiring any configuration", "Connection monitor", "Diagnostic Toolkit"],
        "Redirects to Network Watcher Network Insights. Built-in topology/health/metrics "
        "need no configuration; monitor/flow/alert settings do not prove end-to-end "
        "operation, coverage, ingestion, owner response or executed diagnostic tests.",
    ),
    (
        "network-limits",
        "https://learn.microsoft.com/azure/azure-resource-manager/management/"
        "azure-subscription-service-limits?toc=/azure/virtual-network/toc.json"
        "#azure-resource-manager-virtual-networking-limits",
        ["650", "Route advertisement limits", "4,000", "10,000", "1,000"],
        "Actual current table lists650 peerings/VNet, not immutable historical500. "
        "Historical400 spokes is not a current universal threshold. ER private-peering "
        "Azure-to-onprem IPv4 gateway routes1000 (both SKUs), IPv6 100; incoming IPv4 "
        "onprem routes4000 Local/Standard or10000 Premium. Direction, family, SKU, "
        "Route Server limits, summarization and actual authorized quotas/complete counts "
        "require separate review; no live quota lookup or automatic headroom verdict.",
    ),
    (
        "route-server-arm",
        LEARN + "azure/templates/microsoft.network/2024-05-01/virtualhubs",
        ["allowBranchToBranchTraffic", "sku", "virtualWan"],
        "Shared virtualHubs type and SKU alone do not designate Route Server. Preserve "
        "explicit branch flag/preference separately from positively joined VNet attachment.",
    ),
    (
        "routing-ipconfiguration-arm",
        LEARN + "azure/templates/microsoft.network/2024-05-01/virtualhubs/ipconfigurations",
        ["subnet", "publicIPAddress"],
        "Separate virtualHubs/ipConfigurations child supplies typed subnet/public-IP "
        "relationships. Parent ipConfigurations is read-only references in the REST spec; "
        "do not invent embedded configuration bodies or retain private IPs.",
    ),
    (
        "route-server-provider",
        RAW + "website/docs/r/route_server.html.markdown",
        ["branch_to_branch_traffic_enabled", "subnet_id", "/27", "2024-05-01"],
        "AzureRM4.50.0 explicit azurerm_route_server maps to virtualHubs and separately "
        "creates its IP configuration. Omitted branch flag/preference defaults are not "
        "inferred; pinned /27 sizing guidance conflicts with current portal /26 guidance.",
    ),
    (
        "route-server-provider-implementation",
        RAW + "internal/services/network/route_server_resource.go",
        ["HubIPConfiguration", "AllowBranchToBranchTraffic", "VirtualHubIPConfiguration"],
        "Provider creates parent then separate ipConfig1 child with subnet/public-IP IDs. "
        "Explicit Terraform resource type prepares declared attachment without fabricating "
        "ARM kind=RouteServer or a child identity in normalized evidence.",
    ),
    (
        "routing-rest-spec",
        SPEC_RAW + "specification/network/resource-manager/Microsoft.Network/Network/"
        "stable/2024-05-01/virtualWan.json",
        ["HubIPConfigurationPropertiesFormat", "ipConfigurations", "allowBranchToBranchTraffic"],
        "Pinned REST defines separate HubIPConfiguration subnet/public-IP and parent "
        "read-only child references. No private IP/ASN/partner payloads are retained.",
    ),
    (
        "peering-rest-spec",
        SPEC_RAW + "specification/network/resource-manager/Microsoft.Network/Network/"
        "stable/2024-05-01/virtualNetwork.json",
        ["allowGatewayTransit", "useRemoteGateways", "peerCompleteVnets"],
        "Explicit peering flags have separate directional meanings. No missing defaults, "
        "effective transit, subnet-peering completeness or remote gateway inferred.",
    ),
    *[source for source in SOURCES_11 if source[0] in {"peering-arm", "terraform-peering"}],
    *[source for source in SOURCES_17 if source[0] in {"subnet-arm", "terraform-subnet"}],
    *[source for source in SOURCES_19 if source[0] in {"gateway-arm", "terraform-gateway"}],
    *[
        source
        for source in SOURCES_15
        if source[0]
        in {
            "connection-monitor-arm",
            "metric-alert-arm",
            "terraform-connection-monitor",
            "learn-reuse",
            "provider-reuse",
            "rest-spec-reuse",
        }
    ],
    (
        "learn-terms",
        LEARN + "legal/termsofuse",
        ["Notice Specific to Documents", "explicit license terms"],
        "Reviewed document terms; retain attributed metadata and own factual findings only, "
        "not article text, screenshots, samples or private comments.",
    ),
    (
        "provider-license",
        RAW + "LICENSE",
        ["Mozilla Public License", "2.0"],
        "Pinned provider MPL2.0; only own findings and source metadata retained.",
    ),
]


SOURCES_07 = [
    (
        "naming-standard",
        LEARN + "azure/cloud-adoption-framework/ready/azure-best-practices/resource-naming",
        ["tailored naming convention", "personal, sensitive, or confidential", "permanence"],
        "Naming must satisfy organization-specific requirements and per-type scope, character "
        "and length rules. Examples are not an approved enterprise standard; names are often "
        "immutable and must not contain confidential information. No raw names are retained.",
    ),
    (
        "management-design",
        LEARN + "azure/cloud-adoption-framework/ready/landing-zone/design-area/"
        "resource-org-management-groups",
        ["three to four", "Intermediate root", "sandbox", "connectivity subscription"],
        "CAF ideally recommends three to four levels, while separately documenting the six-level "
        "service bound excluding tenant root/subscriptions. The ALZ intermediate root is below "
        "tenant root. Sandbox purpose, platform placement, workload requirements and dedicated "
        "connectivity need explicit organizational designation; no naming/count predicate. "
        "Dedicated regional connectivity subscriptions can be justified by scale.",
    ),
    (
        "management-overview",
        LEARN + "azure/governance/management-groups/overview",
        ["six levels", "only one parent", "root level or the subscription level", "10,000"],
        "Single-parent hierarchy supports six MG levels below tenant root, "
        "excluding subscriptions. "
        "This is a service maximum, not CAF's ideal or a universal four-level counting convention. "
        "Partial positive parentage and selected scope cannot designate tenant root, establish "
        "complete estate depth, subscription absence, policy results or effective permissions.",
    ),
    (
        "hierarchy-protection",
        LEARN + "azure/governance/management-groups/how-to/protect-resource-hierarchy",
        [
            "defaultManagementGroup",
            "requireAuthorizationForGroupCreation",
            "Hierarchy Settings Administrator",
        ],
        "defaultManagementGroup governs new subscription placement, not existing membership or "
        "absence of root subscriptions. requireAuthorizationForGroupCreation requires root write "
        "permission for creation, not all effective privileged operations. Settings read/write "
        "permissions themselves grant no other hierarchy/resource access.",
    ),
    (
        "hierarchy-settings-arm",
        LEARN + "azure/templates/microsoft.management/2020-05-01/managementgroups/settings",
        ["Tenant", "'default'", "requireAuthorizationForGroupCreation", "defaultManagementGroup"],
        "Pinned tenant resource managementGroups/settings/default exposes independent explicit "
        "default MG reference and creation-authorization boolean. Supplied settings attach to "
        "a unique known selected anchor; that does not designate it as authoritative tenant root. "
        "No implicit defaults or ARM permission operations are executed.",
    ),
    (
        "management-arm",
        LEARN + "azure/templates/microsoft.management/2020-05-01/managementgroups",
        ["Tenant", "parent", "displayName"],
        "Pinned tenant MG resource has explicit resource key and details.parent.id. Resource "
        "keys are identities, never business-purpose or root designations. Display names, "
        "tenant/principal payloads and private metadata are not projected.",
    ),
    (
        "terraform-management",
        RAW + "website/docs/r/management_group.html.markdown",
        ["parent_management_group_id", "subscription_ids", "2020-05-01"],
        "Pinned AzureRM4.50 MG supplies explicit name key and optional parent ID. Omitted name "
        "is generated and cannot bind an identity. Optional subscription_ids and the separate "
        "association resource conflict if both managed; neither omission nor empty selected "
        "input proves complete actual root subscription absence. No settings resource is assumed.",
    ),
    (
        "terraform-management-association",
        RAW + "website/docs/r/management_group_subscription_association.html.markdown",
        ["management_group_id", "subscription_id", "2020-05-01"],
        "Separate AzureRM association binds a specific subscription to an MG, not a subscription "
        "purpose. It is not a new subscription object or settings resource; "
        "unsupported association "
        "inputs remain unknown rather than inventing complete inventory or deployment authority.",
    ),
    *[
        source
        for source in SOURCES_27
        if source[0] in {"policy-scope", "policy-assignment-structure", "management-hierarchy"}
    ],
    *[source for source in SOURCES_15 if source[0] in {"provider-reuse", "learn-reuse"}],
]


SOURCES_24 = [
    (
        "workspace-design-linked",
        LEARN + "azure/azure-monitor/logs/workspace-design#azure-regions",
        ["fewest number of workspaces", "Data retention", "Microsoft Entra tenants"],
        "Start with one and use the fewest workspaces meeting independent tenant, RBAC, "
        "ownership, geography, retention, resilience and cost requirements. Configuration "
        "does not establish approved centralization, complete ingestion or sovereignty.",
    ),
    (
        "regional-workspace-linked",
        LEARN + "azure/azure-monitor/logs/design-logs-deployment",
        ["workspace-design", "bandwidth", "diagnostic settings"],
        "Actual link redirects to workspace-design. Regional residency and VM bandwidth "
        "tradeoffs differ from resource diagnostic-setting egress; no universal regional "
        "workspace count or cost threshold is inferred.",
    ),
    (
        "retention-linked",
        LEARN + "azure/azure-monitor/logs/data-retention-archive?tabs=portal-1%2Cportal-2",
        ["4,383", "730", "30 days", "immediatePurgeDataOn30Days"],
        "Redirects to data-retention-configure. Analytics table retention 4-730 days, "
        "total up to4383 days/12 years. Basic queries use30 days, Auxiliary total retention; "
        "workspace defaults do not override explicit table settings. Thirty may retain31 "
        "unless the separate immediate-purge flag applies. CLI documented max2556 differs "
        "from REST/portal4383. No requirement adequacy or actual retained data inferred.",
    ),
    (
        "export-current",
        LEARN + "azure/azure-monitor/logs/logs-data-export",
        ["new data", "workspace's region", "immutability", "Unsupported tables"],
        "Continuous selected-table export covers new arriving data, not historical "
        "backfill or every supported/required table. Same-region destination, supported "
        "tables, transforms, delivery, storage access and immutable policy must be reviewed "
        "separately. No export or log operation is performed.",
    ),
    (
        "immutable-current",
        LEARN + "azure/storage/blobs/immutable-storage-overview",
        ["146,000", "Legal hold", "Locked", "Unlocked"],
        "Time-based retention spans1-146000 days; container and version WORM differ. "
        "Locked versus unlocked and legal hold are distinct. Configuration alone proves "
        "neither required data coverage, legal suitability nor effective protection.",
    ),
    (
        "machine-configuration-linked",
        LEARN + "azure/governance/machine-configuration/overview",
        ["November 2026", "50 guest assignments", "Audit", "ARM64"],
        "Redirects to overview/01-overview-concepts. Guest configurations differ from "
        "Policy definitions; assignments and Audit/Apply modes are not completed audits. "
        "Current OS/client/architecture and November2026 Linux PowerShell compatibility "
        "restrictions require human review. No guest/package/results payload is retained.",
    ),
    (
        "operational-compliance-linked",
        LEARN + "azure/cloud-adoption-framework/ready/landing-zone/design-area/"
        "management-operational-compliance#update-management-considerations",
        ["Azure Update Manager", "Windows and Linux", "business continuity"],
        "Shared linked guidance requires separate Azure and outside-Azure patch coverage, "
        "responsibility, schedules and business-continuity decisions; configured assessment "
        "or assignments do not prove installed patches or fleet compliance.",
    ),
    (
        "update-manager-current",
        LEARN + "azure/update-manager/overview",
        ["Azure Arc", "24 hours", "No dependency on Log Analytics"],
        "Current Update Manager supports Azure/Arc server patching without Log Analytics "
        "or Automation dependency; periodic24-hour assessment is not patch installation. "
        "Maintenance windows, scope, eligibility, results and exceptions remain human.",
    ),
    (
        "watcher-linked",
        LEARN + "azure/network-watcher/network-watcher-monitoring-overview",
        ["network-watcher-overview", "September 30, 2027", "no longer supports new"],
        "Actual link redirects to Network Watcher overview. Automatic regional enablement "
        "is not traffic analysis. NSG flow logs no longer support new creation and retire "
        "2027-09-30; VNet flow migration and actual storage/analytics operation need review.",
    ),
    (
        "locks-linked",
        LEARN + "azure/azure-resource-manager/management/lock-resources?tabs=json",
        ["control plane", "data plane", "management groups", "subscription cancellation"],
        "CanNotDelete and ReadOnly restrict control-plane operations, not data. Parent "
        "inheritance/most restrictive behavior and side effects need review; no management "
        "group locks or cancellation protection. Presence is not complete critical-resource "
        "protection or applicability; notes/owners are not retained.",
    ),
    (
        "deny-linked",
        LEARN + "azure/governance/policy/concepts/effect-deny",
        ["403", "existing resources", "non-compliant"],
        "Policy deny blocks matching create/update requests; existing resources can be "
        "noncompliant, not remediated. Exact definition/version/assignment/parameters/"
        "exemptions/enforcement/scope and role authority remain separate, not interpreted.",
    ),
    (
        "rbac-deny-distinction",
        LEARN + "azure/role-based-access-control/deny-assignments",
        ["private preview", "Azure creates and manages", "Exclude principals"],
        "RBAC deny assignments differ from Policy deny. Customer-managed denies are "
        "private preview; generated APIs do not imply general availability. No new "
        "deny-assignment transport, principal capture or effective-access assertion.",
    ),
    *[
        (
            identity,
            LEARN + "azure/templates/" + path,
            markers,
            finding,
        )
        for identity, path, markers, finding in [
            (
                "table-arm",
                "microsoft.operationalinsights/2023-09-01/workspaces/tables",
                ["4383", "730", "Setting this property to -1", "'Analytics'"],
                "2023-09-01 supports Analytics/Basic, explicit4-730 analytics and4-4383 "
                "total days. -1 is an inheritance sentinel, not negative retained days. "
                "Basic semantics differ from old provider docs; do not infer defaults.",
            ),
            (
                "export-arm",
                "microsoft.operationalinsights/2020-08-01/workspaces/dataexports",
                ["tableNames", "resourceId", "enable"],
                "2020-08-01 exposes explicit enable, selected tables and destination "
                "resource ID, not delivered export or implied historical coverage.",
            ),
            (
                "guest-arm",
                "microsoft.guestconfiguration/2024-04-05/guestconfigurationassignments",
                ["Audit", "configurationProtectedParameter", "latestAssignmentReport"],
                "2024-04-05 extension assignment retains only assignmentType/kind. "
                "Protected parameters, content URI/hash, reports and guest values excluded.",
            ),
            (
                "arc-arm",
                "microsoft.hybridcompute/2024-07-10/machines",
                ["assessmentMode", "patchMode", "osType"],
                "2024-07-10 has explicit OS and patch assessment/mode settings; these "
                "are not completed assessments, installed updates or Arc connectivity.",
            ),
            (
                "immutable-arm",
                "microsoft.storage/2023-05-01/storageaccounts/"
                "blobservices/containers/immutabilitypolicies",
                ["immutabilityPeriodSinceCreationInDays", "allowProtectedAppendWrites"],
                "2023-05-01 container policy day interval/append options are supplied "
                "configuration; template declaration does not prove a locked policy.",
            ),
            (
                "lock-arm",
                "microsoft.authorization/2020-05-01/locks",
                ["CanNotDelete", "ReadOnly", "NotSpecified"],
                "2020-05-01 lock level schema also lists NotSpecified, which provides "
                "no protection claim. Generated deployment scope list is not operational "
                "permission to use unsupported management-group locks.",
            ),
        ]
    ],
    *[
        (
            "operations-provider-" + name,
            RAW + "website/docs/r/" + name + ".html.markdown",
            markers,
            finding,
        )
        for name, markers, finding in [
            (
                "log_analytics_workspace_table",
                ["4383", "eight days", "2022-10-01"],
                "Pinned4.50.0 uses2022-10-01 and allows4-730 or discrete annual total "
                "values1095/1460/1826/2191/2556/2922/3288/3653/4018/4383. Basic eight-day "
                "wording differs from current30-day Learn; Basic analytics stays unknown.",
            ),
            (
                "log_analytics_data_export_rule",
                ["workspace_resource_id", "table_names"],
                "Pinned4.50.0 exports explicit tables/enable/destination using2020-08-01; "
                "no missing false default, historical export or delivery inferred.",
            ),
            (
                "policy_virtual_machine_configuration_assignment",
                ["assignment_type", "will not be executed", "content_uri"],
                "Pinned4.50.0 exposes VM extension assignment and configuration block; "
                "assignment alone is not executed without prerequisite extension. "
                "No guest/package/parameter values retained or fetched.",
            ),
            (
                "management_lock",
                ["lock_level", "2020-05-01"],
                "Pinned4.50.0 explicit scope/level become extension identity, not "
                "inferred criticality, complete inheritance or effective protection.",
            ),
            (
                "storage_container_immutability_policy",
                ["locked", "immutability_period_in_days", "2023-05-01"],
                "Pinned4.50.0 distinguishes explicit locked boolean/append settings/"
                "days from absent defaults. No legal sufficiency or effective WORM proof.",
            ),
            (
                "arc_machine",
                ["2024-07-10", "SystemAssigned"],
                "Pinned4.50.0 Arc resource exposes no patch assessment/mode fields. "
                "Terraform Arc patch configuration remains explicit unsupported unknown, "
                "not populated from invented arguments, identity or resource presence.",
            ),
        ]
    ],
    *[
        row
        for row in SOURCES_23 + SOURCES_22 + SOURCES_19 + SOURCES_27 + SOURCES_04
        if row[0]
        in {
            "workspace-arm",
            "terraform-workspace",
            "terraform-linux-patch",
            "terraform-windows-patch",
            "vm-patch-rest",
            "flow-log-arm",
            "terraform-flow-log",
            "vnet-flow-log-coverage",
            "traffic-analytics-pipeline",
            "policy-spec-policyDefinitions",
            "policy-spec-policyAssignments",
            "policy-provider-policy_definition",
            "policy-provider-subscription_policy_assignment",
            "role-assignment-arm",
            "terraform-role-assignment",
            "learn-terms",
            "policy-spec-license",
            "policy-provider-license",
        }
    ],
]


SOURCES_26 = [
    (
        "bcdr-linked",
        LEARN.removesuffix("en-us/") + "azure/cloud-adoption-framework/ready/landing-zone/"
        "design-area/management-business-continuity-disaster-recovery#design-recommendations",
        ["Site Recovery", "RPO", "PaaS"],
        "CAF separates Azure-to-Azure VM replication, native backup and service-specific PaaS DR. "
        "Configuration cannot establish complete protection, achieved recovery objectives "
        "or drills.",
    ),
    (
        "redundancy-linked",
        LEARN.removesuffix("en-us/") + "azure/storage/common/storage-redundancy",
        ["LRS", "ZRS", "GRS"],
        "Storage redundancy describes account replication, not a universal Azure Backup default "
        "or correct backup choice. Preserve immutable GRS wording with vault/workload "
        "qualifications.",
    ),
    (
        "recovery-vault-settings",
        LEARN + "azure/backup/backup-create-rs-vault",
        ["default", "geo-redundant", "snapshot", "vaulted"],
        "Redirects to backup-create-recovery-services-vault. Recovery Services documents default "
        "GRS and explicit LRS/ZRS choices before protection. Vault settings do not govern Azure "
        "Files snapshot backups, only vaulted backup; CRR has workload/region constraints and "
        "configuration does not prove a successful secondary restore or an achieved RPO.",
    ),
    (
        "backup-vault-settings",
        LEARN + "azure/backup/backup-vault-overview",
        ["storage redundancy", "business needs", "PostgreSQL"],
        "Data Protection Backup vaults require service-specific datastore/redundancy review; this "
        "page does not establish a universal GRS default. CRR support is workload-specific. "
        "No omitted setting is converted into observed configuration.",
    ),
    (
        "guest-linked",
        LEARN.removesuffix("en-us/") + "azure/governance/policy/concepts/guest-configuration",
        ["November 2026", "Arc", "50 guest assignments"],
        "Legacy Guest Configuration URL redirects to Machine Configuration. Assignments are "
        "distinct from Policy definitions; Audit, ApplyAndMonitor and ApplyAndAutoCorrect differ. "
        "November 2026 Linux PowerShell compatibility changes, OS/architecture and Arc/VMSS "
        "support require review; configured extension/assignment is not execution or compliance.",
    ),
    (
        "guest-assignments",
        LEARN + "azure/governance/machine-configuration/concepts/assignments",
        ["complianceStatus", "Null", "manually"],
        "Guest assignments can be created manually or by Policy. A temporary null assignment "
        "type is documented; neither assignment presence nor apply mode proves compliant settings "
        "or current drift monitoring. Package contents, URIs and reports are withheld.",
    ),
    (
        "guest-extension",
        LEARN + "azure/virtual-machines/extensions/guest-configuration",
        ["Microsoft.GuestConfiguration", "ConfigurationForLinux", "ConfigurationforWindows"],
        "Reviewed exact publisher/type pairs and AzurePolicyforLinux/Windows instance names. "
        "System identity, supported OS, network/content access and actual installation/reporting "
        "remain independent requirements. Never deploy or execute an extension.",
    ),
    (
        "drift-linked",
        LEARN.removesuffix("en-us/") + "azure/cloud-adoption-framework/ready/landing-zone/"
        "design-area/management-operational-compliance#monitoring-for-configuration-drift",
        ["configuration drift", "Machine Configuration", "Azure Policy"],
        "CAF recommends in-machine drift auditing through Policy and Machine Configuration. "
        "Reuse supplied Policy configuration/compliance Signals without interpreting rules or "
        "fetching built-ins; assignment references do not prove actual monitoring or remediation.",
    ),
    (
        "paas-linked",
        LEARN.removesuffix("en-us/")
        + "azure/architecture/framework/resiliency/backup-and-recovery",
        ["disaster recovery", "retention", "Regularly test restores"],
        "Legacy resiliency URL redirects to Well-Architected disaster recovery. No single tool "
        "covers every service; approve per-component RPO/RTO, retention, dependencies, failback "
        "and attributable drill results. A SQL failover group is not universal PaaS DR.",
    ),
    (
        "sql-recovery",
        LEARN + "azure/azure-sql/database/failover-group-sql-db",
        ["asynchronous", "customer managed", "test"],
        "SQL Database failover groups use asynchronous geo-replication; forced failover can lose "
        "data. Current customer-managed versus Microsoft-managed terminology differs from the "
        "pinned API Manual/Automatic enum. Configured policy is neither a drill nor achieved RPO.",
    ),
    (
        "backup-center-linked",
        LEARN.removesuffix("en-us/") + "azure/backup/backup-center-overview",
        ["legacy", "Resiliency", "no longer available"],
        "Backup Center is a legacy experience, no longer in portal search; current guidance "
        "points to Resiliency/Business Continuity Center. Console capability is not protected "
        "fleet coverage, third-party compatibility or successful backup/restore.",
    ),
    (
        "waf-diagnostics-linked",
        LEARN.removesuffix("en-us/") + "azure/web-application-firewall/afds/"
        "waf-front-door-best-practices#add-diagnostic-settings-to-save-your-wafs-logs",
        ["diagnostic settings", "false-positive", "Front Door Premium"],
        "Premium-qualified best practices separate configured log routing, regular attack review "
        "and false-positive tuning. No categories or WAF resource can prove actual log review.",
    ),
    (
        "waf-sentinel-linked",
        LEARN.removesuffix("en-us/") + "azure/web-application-firewall/afds/"
        "waf-front-door-best-practices#send-logs-to-microsoft-sentinel",
        ["Sentinel", "Azure WAF connector"],
        "WAF telemetry integration requires ingestion and analysis, not a shared workspace or "
        "Sentinel onboarding reference. No connectors, analytics, incidents or playbooks executed.",
    ),
    (
        "frontdoor-logs",
        LEARN + "azure/web-application-firewall/afds/waf-front-door-monitor",
        [
            "FrontDoorWebApplicationFirewallLog",
            "FrontdoorWebApplicationFirewallLog",
            "Logs aren",
            "enabled by default",
        ],
        "Authoritative service page distinguishes Standard/Premium "
        "FrontDoorWebApplicationFirewallLog from classic FrontdoorWebApplicationFirewallLog. "
        "Metrics/activity logs are not WAF logs; logging is not enabled by default. "
        "Only exact supplied categories are prepared; no payloads are retained.",
    ),
    (
        "appgateway-logs",
        LEARN + "azure/web-application-firewall/ag/web-application-firewall-logs",
        ["ApplicationGatewayFirewallLog", "detection", "prevention"],
        "ApplicationGatewayFirewallLog is distinct from access/performance/activity logs. "
        "Diagnostic destinations can be workspace, storage or Event Hubs; configured flags "
        "do not establish ingestion, attacks, false positives, retention or review.",
    ),
    (
        "waf-sentinel",
        LEARN + "azure/web-application-firewall/waf-sentinel",
        ["FrontDoorFirewallLog", "Content hub", "ingested WAF logs"],
        "Walkthrough currently says FrontDoorFirewallLog/FrontdoorFirewallLog, unlike the "
        "service-specific monitoring page's WebApplicationFirewallLog categories. Do not silently "
        "equate them. Actual connector/content/ingestion/analytics evidence remains a blank "
        "human decision, separate from category/destination/onboarding configuration.",
    ),
    *[
        (identity, LEARN + "azure/templates/" + path, markers, finding)
        for identity, path, markers, finding in [
            (
                "recovery-storage-arm",
                "microsoft.recoveryservices/2023-02-01/vaults/backupstorageconfig",
                ["storageModelType", "crossRegionRestoreFlag"],
                "Pinned child vaultstorageconfig exposes explicit storageModelType and CRR flag; "
                "do not read generic account SKU or unrelated vault properties as these settings.",
            ),
            (
                "backup-vault-arm",
                "microsoft.dataprotection/2024-04-01/backupvaults",
                ["datastoreType", "OperationalStore", "storageSettings"],
                "Pinned storageSettings pairs explicit datastore and redundancy. SnapshotStore is "
                "not in this ARM enum despite stale provider docs; unknown forms remain unknown. "
                "Soft-delete retention is not backup-policy/recovery-point retention.",
            ),
            (
                "backup-item-arm",
                "microsoft.recoveryservices/2024-01-01/vaults/backupfabrics/"
                "protectioncontainers/protecteditems",
                ["Microsoft.Compute/virtualMachines", "sourceResourceId", "policyId"],
                "Only exact Microsoft.Compute/virtualMachines item discriminator is normalized to "
                "typed source VM and backup-policy references; no job, payload or "
                "protection-health "
                "assertion, and no inferred identity from container names.",
            ),
            (
                "asr-arm",
                "microsoft.recoveryservices/2024-04-01/vaults/replicationfabrics/"
                "replicationprotectioncontainers/replicationprotecteditems",
                ["A2A", "fabricObjectId", "recoveryResourceGroupId"],
                "Only A2A providerSpecificDetails with explicit source VM, replication policy and "
                "recovery RG references is prepared. Other providers/migration kinds "
                "are unsupported. "
                "No replication health, recovery-point, RPO/RTO or failover outcome retained.",
            ),
            (
                "guest-arm",
                "microsoft.guestconfiguration/2024-04-05/guestconfigurationassignments",
                ["assignmentType", "ApplyAndMonitor", "Audit"],
                "Pinned extension resource retains exact assignment type only. Parameters, content "
                "URIs/hashes, reports and VMSS payloads are withheld; null is unknown, not Audit.",
            ),
            (
                "extension-arm",
                "microsoft.compute/2024-07-01/virtualmachines/extensions",
                ["publisher", "enableAutomaticUpgrade", "typeHandlerVersion"],
                "Retain only reviewed guest publisher/type and explicit upgrade booleans. "
                "No settings/protected settings/scripts/statuses or inferred installed version.",
            ),
            (
                "sql-arm",
                "microsoft.sql/2023-08-01/servers/failovergroups",
                ["Manual", "Automatic", "partnerServers", "databases"],
                "Pinned SQL Database group has typed database/partner-server references and "
                "read-write policy; full grace/data-loss/region/dependency/drill review "
                "remains human.",
            ),
            (
                "profile-arm",
                "microsoft.cdn/2024-02-01/profiles",
                ["Standard_AzureFrontDoor", "Premium_AzureFrontDoor"],
                "Root SKU qualifies a Standard/Premium Front Door profile. Classic and other CDN "
                "profiles stay unsupported; no security-policy or telemetry inference from SKU.",
            ),
            (
                "diagnostic-arm",
                "microsoft.insights/2021-05-01-preview/diagnosticsettings",
                ["categoryGroup", "enabled", "workspaceId", "storageAccountId"],
                "Retain only exact WAF categories/enabled values and typed workspace/storage "
                "references. Category groups are not expanded into individual categories; "
                "Event Hub "
                "keys/names/authorization payloads and private logs are withheld.",
            ),
        ]
    ],
    *[
        (
            "terraform-" + resource,
            RAW + "website/docs/r/" + resource + ".html.markdown",
            markers,
            finding,
        )
        for resource, markers, finding in [
            (
                "recovery_services_vault",
                ["storage_mode_type", "GeoRedundant"],
                "AzureRM 4.50.0 documents GRS default but only explicit storage_mode_type/CRR "
                "are projected. Generic vault ARM properties are not the storage-config child.",
            ),
            (
                "data_protection_backup_vault",
                ["datastore_type", "redundancy"],
                "4.50.0 requires explicit datastore/redundancy, not universal GRS. "
                "Stale SnapshotStore "
                "note is not silently accepted as the pinned ARM OperationalStore enum.",
            ),
            (
                "backup_protected_vm",
                ["source_vm_id", "backup_policy_id", "ProtectionStopped"],
                "4.50.0 source/policy can be omitted for retained/stopped protection; "
                "missing values "
                "stay unknown. Raw record identity needs explicit mapping; "
                "no guessed container ID.",
            ),
            (
                "site_recovery_replicated_vm",
                ["source_vm_id", "recovery_replication_policy_id"],
                "4.50.0 resource is Azure-to-Azure only. Explicit typed references "
                "are configuration, "
                "not replication success or tested failover.",
            ),
            (
                "policy_virtual_machine_configuration_assignment",
                ["assignment_type", "virtual_machine_id", "will not be executed"],
                "4.50.0 guest assignment can exist without extension execution. Only explicit "
                "assignment mode is retained; no package, parameter or reported "
                "compliance payloads.",
            ),
            (
                "virtual_machine_extension",
                ["publisher", "automatic_upgrade_enabled"],
                "4.50.0 explicit guest publisher/type/upgrade flags only; defaults, settings and "
                "protected settings are never retained or executed.",
            ),
            (
                "mssql_failover_group",
                ["server_id", "partner_server", "Automatic", "Manual"],
                "4.50.0 explicit SQL server/database references and failover mode "
                "normalize, without "
                "computed role, connection strings or default policy assumptions.",
            ),
            (
                "cdn_frontdoor_profile",
                ["sku_name", "Premium_AzureFrontDoor"],
                "4.50.0 exact Standard/Premium SKU qualifies Front Door categories, "
                "not WAF coverage.",
            ),
            (
                "monitor_diagnostic_setting",
                ["category_group", "log_analytics_workspace_id"],
                "4.50.0 enabled_log is explicit enabled-category configuration. "
                "Do not expand groups "
                "or confuse metrics/access logs with WAF logs; destination IDs "
                "are configuration only.",
            ),
        ]
    ],
    (
        "learn-terms",
        "https://learn.microsoft.com/legal/termsofuse",
        ["Terms of Use", "Microsoft"],
        "Reviewed Learn terms; preserve attributed metadata and own factual findings only, "
        "not article text, sample scripts, logs or third-party content.",
    ),
    (
        "provider-license",
        RAW + "LICENSE",
        ["Mozilla Public License", "2.0"],
        "Pinned provider MPL-2.0: retain source metadata and independently authored findings only.",
    ),
]
SOURCES_26 += [
    source
    for source in SOURCES_25
    if source[0]
    in {
        "workspace-arm",
        "terraform-workspace",
        "policy-spec-policyDefinitions",
        "policy-spec-policySetDefinitions",
        "policy-spec-policyAssignments",
        "policy-spec-license",
    }
]
SOURCES_26 += [
    source
    for source in SOURCES_23
    if source[0]
    in {"onboarding-arm", "terraform-onboarding", "terraform-onboarding-implementation"}
]


SOURCES_28 = [
    *[source for source in SOURCES_30 if source[0] == "microsoft-site-reuse"],
    (
        "sovereign-global-pinned-snapshot",
        POLICY_RAW + "built-in-policies/policySetDefinitions/Regulatory%20Compliance/"
        "MCfS_Sovereignty_Baseline_Global_Policies.json",
        ["c1cbff38-87c0-4b9f-9f70-035c7a3b5523", "1.2.0", "SO.5", "1.*.*"],
        "Explicitly reviewed public snapshot at the repository's existing Policy pin: "
        "global initiativec1cbff38-87c0-4b9f-9f70-035c7a3b5523 version1.2.0 has five members "
        "and SO.1 residency/SO.5 Trusted Launch groups, with wildcard member versions. "
        "This public-source review is not an implicit runtime definition fetch, observed "
        "assignment binding, exact resolved member versions or approved jurisdiction.",
    ),
    (
        "sovereign-confidential-pinned-snapshot",
        POLICY_RAW + "built-in-policies/policySetDefinitions/Regulatory%20Compliance/"
        "MCfS_Sovereignty_Baseline_Confidential_Policies.json",
        ["03de05a4-c324-4ccd-882f-a814ea8ab9ea", "1.2.0", "SO.4", "1.*.*-preview"],
        "Explicit public pinned snapshot: confidential initiative"
        "03de05a4-c324-4ccd-882f-a814ea8ab9ea version1.2.0 has22 members and SO.1/SO.3/SO.4 "
        "residency/CMK/confidential groups with wildcard and preview member versions. "
        "Those group numbers are not current design L1-L3 levels. No copied definitions "
        "are packaged, implicitly fetched or interpreted; no original-time deployed "
        "content/version, placement, in-use protection or complete compliance is inferred.",
    ),
    (
        "sovereign-policy-snapshot-license",
        POLICY_RAW + "LICENSE",
        ["MIT License", "Microsoft"],
        "MIT public Azure Policy repository at the exact reviewed pin; preserve attributed "
        "URL/revision/hash and own factual findings only, not copied policy bodies.",
    ),
    (
        "budget-alert-tutorial",
        LEARN + "azure/cost-management-billing/costs/tutorial-acm-create-budgets?"
        "bc=%2Fazure%2Fcloud-adoption-framework%2F_bread%2Ftoc.json"
        "&toc=%2Fazure%2Fcloud-adoption-framework%2Ftoc.json",
        ["Actual", "Forecasted", "0.01", "1000", "consumption isn't stopped"],
        "Actual E02.01 link: actual and forecasted alerts are separate configuration. "
        "Tutorial alert range is0.01%-1000%; cost evaluation is periodic, not real-time. "
        "Resources/consumption are not stopped. Scope/currency/filters, expiry, recipients "
        "and delivery need separate evidence and are not retained or tested here.",
    ),
    (
        "sovereign-release-history",
        "https://learn.microsoft.com/industry/release-plan/2023wave2/cloud-sovereignty/"
        "enable-data-sovereignty-policy-baseline",
        ["archived", "2023", "policy"],
        "Actual E03.01 redirects to retired previous-versions2023wave2 release history. "
        "The2023 GA promise is not a current definition/version, deployed assignment, "
        "complete sovereignty requirement or enforcement result.",
    ),
    (
        "sovereign-policy-design",
        LEARN + "industry/sovereign-cloud/sovereign-public-cloud/implementing-workloads/"
        "design-sovereign-policies#sovereign-policy-initiatives",
        ["Level", "audit", "management groups", "Confidential Policies"],
        "Actual E03.02 redirects to Azure Sovereign Clouds public design. Current L1 "
        "locality/transit, L2 at-rest/CMK and L3 in-use/confidential initiatives are "
        "service-specific, customized to requirements and applied to appropriate MGs "
        "including supporting services. Audit-first guidance is not enforced deny. "
        "Names/global references alone prove no content, version, placement or outcome.",
    ),
    (
        "sovereign-objectives-link",
        LEARN + "industry/sovereign-cloud/sovereign-public-cloud/sovereign-landing-zone/"
        "implement-controls-principles",
        ["implementation options", "architectural variant", "Bicep", "Terraform"],
        "Actual E03.03 now redirects to implementation-options, not an organization "
        "control-objective mapping. The article describes incremental SLZ variants "
        "and Terraform/Bicep paths. Preserve immutable wording and require an "
        "independent attributable redacted objectives-to-controls decision.",
    ),
    (
        "paired-regions",
        LEARN + "azure/reliability/regions-paired",
        ["nonpaired", "Brazil South", "asymmetrical", "doesn't automatically"],
        "Actual E03.04: pairing is optional/service-specific and can be asymmetric; "
        "Brazil South/South Central US is an explicit cross-geography exception. "
        "A pair gives no automatic HA/DR/failover or approved jurisdiction. No region "
        "table is turned into an organizational or physical-location allowlist.",
    ),
    (
        "service-data-residency",
        "https://azure.microsoft.com/en-us/explore/global-infrastructure/data-residency",
        ["subprocessors", "outside", "DataZone", "Preview", "Azure Databricks"],
        "Actual E03.05: regional deployment differs from data processing. Page lists "
        "operational copies, personnel remote operation and service-specific exceptions "
        "including Cloud Services, ADX traces, ML metadata, Databricks identities, "
        "Serial Console, Foundry Global/DataZone, Extended Zones and prerelease services. "
        "No resource region establishes all storage/backup/control/support locations, "
        "feature availability, contractual authorization or legal suitability.",
    ),
    (
        "vendor-access-linked-recommendations",
        LEARN + "azure/defender-for-cloud/recommendations-reference-identity-access",
        ["identity and access", "recommendations", "owner"],
        "Actual E03.06 is a Defender identity/access recommendations reference, not a "
        "vendor personnel jurisdiction/nationality register or contract. Account, role, "
        "external-domain or recommendation status cannot establish personnel location "
        "or vendor access eligibility. Keep that decision manual; collect no personnel.",
    ),
    (
        "confidential-computing-linked",
        LEARN + "azure/confidential-computing/",
        ["data", "processed", "attestation", "confidential"],
        "Actual E03.07 current portfolio covers VM/container/services and specialized "
        "enclaves; applicability and service/region/feature choices need workload-specific "
        "requirements, not a blanket confidential flag or at-rest CMK claim.",
    ),
    (
        "confidential-computing-in-use",
        LEARN + "azure/confidential-computing/overview",
        ["data in use", "attested", "properly configured"],
        "In-use protection uses a hardware-based attested TEE and depends on proper "
        "configuration. At-rest CMK, Trusted Launch, VM names and confidential labels "
        "are not equivalent. No workload content, attestation execution or actual "
        "operator-access assurance is collected or manufactured.",
    ),
    (
        "sovereign-global-current",
        LEARN + "azure/governance/policy/samples/mcfs-baseline-global",
        ["Global Policies", "partial view", "Allowed locations", "Trusted Launch"],
        "Current global baseline sample distinguishes residency and Trusted Launch. "
        "Its explicit partial-compliance caveat and changing associations prevent "
        "turning a name/initiative ID/Compliant Signal into legal compliance.",
    ),
    (
        "sovereign-confidential-current",
        LEARN + "azure/governance/policy/samples/mcfs-baseline-confidential",
        ["Confidential Policies", "partial view", "Customer-Managed Keys"],
        "Current confidential baseline includes service-specific residency/CMK controls "
        "and a partial-compliance caveat. Baseline identity/name is not versioned "
        "content, workload coverage, appropriate placement or in-use protection.",
    ),
    (
        "storage-regional-redundancy",
        LEARN + "azure/storage/common/storage-redundancy",
        ["ZRS", "GZRS", "asynchronously", "can't be changed", "archive tier"],
        "Storage-specific ZRS stays in primary-region zones; GRS/GZRS replicate "
        "asynchronously to a paired secondary selected from primary, with LRS there. "
        "GZRS needs zones and a pair; archive/unmanaged-disk constraints differ. "
        "Redundancy SKU is not actual secondary location, replication success, DR "
        "readiness, every service's behavior or approved jurisdiction.",
    ),
    (
        "foundry-processing-types",
        LEARN + "azure/ai-foundry/openai/how-to/deployment-types",
        ["Global", "Data Zone", "geography", "operational purposes"],
        "Current redirect is Foundry Models deployment-types. Global, Data Zone and "
        "geography-based processing differ from stored-at-rest geography; regional "
        "types can process between regions within that geography. Availability is "
        "model/type-specific and not inferred or probed from a resource location.",
    ),
    (
        "budget-arm-2024",
        LEARN + "azure/templates/microsoft.consumption/2024-08-01/budgets",
        ["Actual", "Forecasted", "five notifications", "1000"],
        "Versioned2024-08-01 reference exposes explicit enabled/operator/threshold/type, "
        "up to five notifications and decimal REST percent0..1000 prose versus tutorial "
        "minimum0.01. No omitted defaults, period validity, recipients or delivery inferred.",
    ),
    *[
        (
            "budget-rest-" + revision,
            SPEC_RAW + "specification/consumption/resource-manager/Microsoft.Consumption/"
            "Consumption/stable/" + revision + "/" + filename,
            ["Notification", "thresholdType", "Actual", "1000"]
            + (["Forecasted"] if revision == "2024-08-01" else []),
            "Pinned"
            + revision
            + ": "
            + (
                "thresholdType enum declares Actual only despite provider documentation "
                "advertising Forecasted on its2019-10-01 API; do not silently conflate contracts. "
                if revision == "2019-10-01"
                else "thresholdType explicitly declares Actual and Forecasted. "
            )
            + "Percent is numeric/decimal with0..1000 prose. Max-five notifications "
            "and all required source facts need separate validation; financial/contact "
            "payloads are never persisted. Initial unnested guessed paths returned404; "
            "public pinned directory inspection established this exact Consumption path.",
        )
        for revision, filename in [
            ("2019-10-01", "consumption.json"),
            ("2024-08-01", "openapi.json"),
        ]
    ],
    *[
        (
            "budget-provider-" + scope,
            RAW + "website/docs/r/consumption_budget_" + scope + ".html.markdown",
            ["Actual", "Forecasted", "1000", "2019-10-01"],
            "AzureRM4.50.0 explicit " + scope + " notification enabled/operator/type fields. "
            "Documented defaults are not observed facts. Docs allow Actual/Forecasted "
            "but identify2019-10-01 API whose pinned enum lists only Actual; keep source "
            "qualification. Percentage threshold is not amount/spend; do not retain "
            "amount/currency/billing/filter/contact payloads or infer delivery.",
        )
        for scope in ("subscription", "resource_group")
    ],
    *[
        source
        for source in SOURCES_27
        if source[0]
        in {
            "policy-overview",
            "policy-scope",
            "policy-assignment",
            "policy-exemption",
            "management-hierarchy",
            "landing-zone-hierarchy",
            "policy-spec-policyDefinitions",
            "policy-spec-policySetDefinitions",
            "policy-spec-policyAssignments",
            "policy-provider-policy_definition",
            "policy-provider-policy_set_definition",
            "policy-provider-management_group_policy_assignment",
            "policy-provider-subscription_policy_assignment",
            "policy-provider-resource_group_policy_assignment",
            "learn-terms",
            "policy-spec-license",
            "policy-provider-license",
        }
    ],
    *[
        source
        for source in SOURCES_04
        if source[0] in {"storage-identity-arm", "terraform-storage-identity"}
    ],
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--append-new-sources", action="store_true")
    parser.add_argument("--preparation-only", action="store_true")
    parser.add_argument("--vwan-supplement", action="store_true")
    parser.add_argument(
        "--batch",
        choices=[
            "01",
            "02",
            "04",
            "05",
            "06",
            "07",
            "08",
            "10",
            "11",
            "12",
            "13",
            "14",
            "15",
            "16",
            "17",
            "18",
            "19",
            "20",
            "22",
            "27",
            "28",
            "23",
            "24",
            "25",
            "26",
            "29",
            "30",
        ],
        default="01",
    )
    args = parser.parse_args()
    if args.vwan_supplement and (args.batch != "16" or not args.preparation_only):
        raise ValueError("The vWAN supplement is cohort16 preparation only")
    if (
        args.batch
        in {
            "02",
            "05",
            "06",
            "07",
            "10",
            "12",
            "16",
            "20",
            "23",
            "24",
            "25",
            "26",
            "27",
            "28",
            "29",
            "30",
        }
    ) != args.preparation_only:
        raise ValueError(
            "Cohorts 02/05/06/07/10/12/16/20/23/24/25/26/27/28/29/30 source capture require "
            "--preparation-only; no activation"
        )
    prefix = "preparation" if args.preparation_only else "batch"
    suffix = "-vwan" if args.vwan_supplement else ""
    target = (
        ROOT
        / "references"
        / "recommendation-batches"
        / f"{prefix}-{args.batch}{suffix}-sources.json"
    )
    if args.batch in {"02", "05", "06", "07"}:
        target = ROOT / "references" / "preparation" / f"batch-{args.batch}-sources.json"
    if target.exists() and not args.append_new_sources:
        raise ValueError("Frozen source review exists; do not silently recollect or redate it")
    sources = json.loads(target.read_text("utf-8"))["sources"] if target.exists() else []
    existing = {source["id"]: source for source in sources}
    selected_sources = {
        "01": SOURCES,
        "02": SOURCES_02,
        "04": SOURCES_04,
        "05": SOURCES_05,
        "06": SOURCES_06,
        "07": SOURCES_07,
        "08": SOURCES_08,
        "10": SOURCES_10,
        "11": SOURCES_11,
        "12": SOURCES_12,
        "13": SOURCES_13,
        "14": SOURCES_14,
        "15": SOURCES_15,
        "16": SOURCES_16,
        "17": SOURCES_17,
        "18": SOURCES_18,
        "19": SOURCES_19,
        "20": SOURCES_20,
        "22": SOURCES_22,
        "27": SOURCES_27,
        "28": SOURCES_28,
        "23": SOURCES_23,
        "24": SOURCES_24,
        "25": SOURCES_25,
        "26": SOURCES_26,
        "29": SOURCES_29,
        "30": SOURCES_30,
    }[args.batch]
    for identity, url, markers, finding in (
        SOURCES_16_VWAN if args.vwan_supplement else selected_sources
    ):
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
            missing = [marker for marker in markers if marker.lower() not in text.lower()]
            raise ValueError(f"Reviewed marker missing from {identity}: {missing}; inspect source")
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
                else ALZ_REVISION
                if url.startswith(ALZ_RAW)
                else POLICY_REVISION
                if url.startswith(POLICY_RAW)
                else DOCS_REVISION
                if url.startswith(DOCS_RAW)
                else match.group(1)
                if match
                else "retrieved-page",
                "finding": finding,
                "reuse": "MPL-2.0 provider: metadata and own factual findings only"
                if url.startswith(RAW)
                else "MIT Microsoft REST specification: metadata and own factual findings only"
                if url.startswith(SPEC_RAW)
                else "MIT Azure policy/library: metadata and own factual findings only"
                if url.startswith((ALZ_RAW, POLICY_RAW))
                else "CC-BY-4.0 GitHub Docs: attributed metadata and own findings only; "
                "no page content redistributed"
                if url.startswith(DOCS_RAW) or urlsplit(url).netloc == "docs.github.com"
                else "Microsoft site terms: linked metadata and own findings only; "
                "no article/comments/sample scripts redistributed"
                if microsoft_site_terms(url) or urlsplit(url).netloc == "azure.microsoft.com"
                else (
                    "Microsoft Learn attribution: source metadata and own factual findings only; "
                    "no page content redistributed"
                ),
            }
        )
        print(identity, sources[-1]["revision"], sources[-1]["sha256"])
    target.write_text(
        json.dumps(
            {
                "batch": args.batch,
                "review_state": "preparation-only-reviewed"
                if args.preparation_only
                else "reviewed",
                "sources": sources,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
