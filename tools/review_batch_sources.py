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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--append-new-sources", action="store_true")
    parser.add_argument(
        "--batch", choices=["01", "04", "11", "13", "15", "17", "18", "19", "22"], default="01"
    )
    args = parser.parse_args()
    target = ROOT / "references" / "recommendation-batches" / f"batch-{args.batch}-sources.json"
    if target.exists() and not args.append_new_sources:
        raise ValueError("Frozen source review exists; do not silently recollect or redate it")
    sources = json.loads(target.read_text("utf-8"))["sources"] if target.exists() else []
    existing = {source["id"]: source for source in sources}
    for identity, url, markers, finding in {
        "01": SOURCES,
        "04": SOURCES_04,
        "11": SOURCES_11,
        "13": SOURCES_13,
        "15": SOURCES_15,
        "17": SOURCES_17,
        "18": SOURCES_18,
        "19": SOURCES_19,
        "22": SOURCES_22,
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
                else ALZ_REVISION
                if url.startswith(ALZ_RAW)
                else POLICY_REVISION
                if url.startswith(POLICY_RAW)
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
