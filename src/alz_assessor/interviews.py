"""Shared narrative collection with explicit per-control bound human decisions."""

from typing import Any

from .contracts import control_digest, digest, document, require, scope_id, validate
from .reviews import prepare_reviews, validate_reviews
from .terraform import InputError

BANK_VERSION = "2026-11-06.19"
BANK = {
    "hybrid-identity-entitlements-sovereignty": {
        "question": "Decide all eight GUIDs independently using attributable redacted evidence "
        "and the control-specific requirements. For Connect Sync, distinguish maintained "
        "active/passive staging, pending-export checks and actual recovery, isolate the former "
        "active server and review password catch-up; do not assume Cloud Sync equivalence. "
        "Establish Entra role identity provenance and independently justify every required "
        "synced-account exception, not Azure RBAC or VM naming. Substantiate central Application "
        "Proxy ownership, workload handoffs, connector groups, independent outbound failure "
        "domains, updates and actual SSO/availability; the old link is unavailable and current "
        "reviewed replacements apply. Identify actual identity services and approved VNet/hub "
        "boundaries, then substantiate both-direction effective segmentation and authentication, "
        "not peering flags. Review resource-specific vault/storage/SQL data-plane permissions "
        "and actual use independently of control-plane Owner and newer API defaults. Establish "
        "PIM populations, licensing, active/eligible and group coverage, cadence and actual "
        "snapshot-bound completed/applied reviews, not recurrence configuration. Establish "
        "actual EA enrollment account owners and least privilege, not subscription Owner "
        "counts; distinguish one owner per account from an invented enrollment threshold and "
        "the upcoming WSA rule from existing MSA assignments. Separately establish organization-"
        "approved sovereign administrator eligibility, service/task/country boundaries, real "
        "enforcement and support/emergency exceptions; IP/GPS signals and the FSI example are "
        "not nationality or complete sovereignty assurance. Retain no principal/contact/secret/"
        "query/billing/employee-location payloads. Leave all eight outcomes independently blank "
        "until explicit scope/content/time/expiry-bound confirmation. B05.01 remains manual; "
        "Signals, exceptions and humanConfirmed never manufacture Verified.",
        "controls": [
            "ALZ-cd163e39-84a5-4b39-97b7-6973abd70d94",
            "ALZ-35037e68-9349-4c15-b371-228514f4cdff",
            "ALZ-d5d1e4e6-1465-48d3-958f-d77249b82111",
            "ALZ-9cf5418b-1520-4b7b-add7-88eb28f833e8",
            "ALZ-d4d1ad54-1abc-4919-b267-3f342d3b49e4",
            "ALZ-d505ebcb-79b1-4274-9c0d-a27c8bea489c",
            "ALZ-0ce74f19-9abb-47e4-ae95-6b057a1d2be9",
            "ALZ-1770a2ac-c194-4e5c-ade4-82939d38a510",
        ],
    },
    "platform-team-delivery-vending": {
        "question": "Reconcile actual cross-functional IT/security/compliance/business "
        "representation "
        "and ownership across platform design, build, maintenance and operations, then separately "
        "evidence assigned platform functions and interfaces rather than job titles or directory "
        "membership. Establish workload end-to-end application ownership, real self-service and "
        "escalation boundaries, policy guardrails and effective least-privileged RBAC including "
        "inherited/conditional permissions; adequate built-in roles are valid, custom roles need "
        "a specific justified gap and testing. Do not require centralized workload pipelines. "
        "Trace actual scoped IaC changes through CI triggers, builds, tests, previews, governed "
        "production-like deployment, release history, rollback and ongoing drift/failure response. "
        "Separately bind IaC AND application unit tests to agreed acceptance criteria/definition "
        "of done, relevant source revisions, failure handling and uncovered populations; "
        "syntax/compilation and test counts are not adequacy or a coverage threshold. Substantiate "
        "non-hardcoded secret handling via redacted references to approved secret variables/"
        "references, restricted deployment access, identity/network prerequisites, version/"
        "rotation/revocation and safe output handling. A vault, secure parameter, saved scan or "
        "no detected data proves no complete hygiene; never scan or fetch secrets. For vending, "
        "distinguish approved CCoE business logic and trackable validated intake from platform "
        "request/deployment automation, agreement/API-specific EA/MCA/MPA creation authority, "
        "configuration of existing subscriptions, offer/DevTest eligibility, IPAM/nonoverlap/"
        "networking, management-group policy placement, quotas/failure handling, least-privileged "
        "identities/RBAC, budgets/tags, reporting and actual workload handoff/operations. Budgets "
        "are not hard caps; DevTest is unavailable for MPA; the example Gitflow is not universal; "
        "Terraform per-subscription state and managed identity/OIDC are design considerations, "
        "not new execution authority. No alias, pipeline or configuration proves fulfilled vending "
        "governance. Use attributable redacted references only, not employee/team directory "
        "records, private code/pipeline content, secret literals/URIs, credentials or sensitive "
        "billing/request payloads. Supply seven separate outcomes, original-time scope/content "
        "binding, attribution and validity; exceptions remain independent and a shared narrative "
        "or humanConfirmed/Signal never manufactures Verified.",
        "controls": [
            "ALZ-e85f4226-bf06-4e35-8a8b-7aee4d2d633a",
            "ALZ-634146bf-7085-4419-a7b5-f96d2726f6da",
            "ALZ-a9e65070-c59e-4112-8bf6-c11364d4a2a5",
            "ALZ-165eb5e9-b434-448a-9e24-178632186212",
            "ALZ-0cadb8c7-8fa5-4fbf-8f39-d1fadb3b0460",
            "ALZ-108d5099-a11d-4445-bd8b-e12a5e95412e",
            "ALZ-a52e0c98-76b9-4a09-a1c9-6b2babf22ac4",
        ],
    },
    "policy-strategy-placement-delegation": {
        "question": "Supply eight separate decisions at the "
        "original evidence time. E01.01: "
        "identify approved governance "
        "objectives, initiative grouping and "
        "reviewed Policy-as-code "
        "rollout/maintenance; an initiative "
        "count or literal effect is not "
        "strategy or enforcement. E01.03: bind "
        "applicable regulatory obligations, "
        "customer/Microsoft/shared "
        "responsibilities and exact Policy/RBAC "
        "controls using attributable redacted "
        "evidence; built-in regulatory "
        "groupings, including current Preview "
        "status, are not a legal-compliance "
        "verdict. E01.04: explicitly designate "
        "the intermediate root below the actual "
        "tenant root and prove complete "
        "intended assignment ancestry; no name "
        "or missing parent establishes either "
        "root. Global built-ins are distinct "
        "from custom "
        "management-group/subscription "
        "definitions. E01.05: decide the "
        "highest appropriate scope for each "
        "control and justified lower-scope "
        "exclusions versus tracked exemptions; "
        "review conditions, mode, versions, "
        "overrides, resource/identity "
        "selectors, expiry and "
        "evaluation/remediation evidence "
        "separately. E01.06: provide the "
        "organization-approved services and "
        "exceptions and show the applicable "
        "audit/restriction controls; no generic "
        "allowed-service taxonomy is assumed. "
        "E01.07: compare actual built-in "
        "scope/cloud/version/parameter/effect "
        "suitability with custom alternatives "
        "and maintenance cost; a global GUID "
        "reference is not fetched content, "
        "existence or suitability. E01.08: "
        "identify the application team and "
        "least-privilege scope, actual active "
        "membership/PIM, conditions/deny "
        "assignments and remediation-identity "
        "grants; Resource Policy "
        "Contributor36243c78-bf99-498c-9df9-86d9f8d28608 "
        "includes control-plane read, "
        "PolicyInsights, deployments/support, "
        "not role-assignment write or "
        "dataActions. Workload RBAC is normally "
        "subscription/resource-group scoped; no "
        "reference/principal-type/count proves "
        "effective delegation. E01.09: "
        "explicitly establish tenant-root "
        "identity and review only must-have "
        "root assignments, exclusions and "
        "debugging/maintenance complexity "
        "against complete attributable "
        "inventory; no numeric assignment cap "
        "is prescribed and a selected tree is "
        "not complete. Use redacted supporting "
        "references, not rule bodies, principal "
        "records, service-list contents or "
        "fabricated organizational/legal "
        "decisions.",
        "controls": [
            "ALZ-5c986cb2-9131-456a-8247-6e49f541acdc",
            "ALZ-d8a2adb1-17d6-4326-af62-5ca44e5695f2",
            "ALZ-223ace8c-b123-408c-a501-7f154e3ab369",
            "ALZ-3829e7e3-1618-4368-9a04-77a209945bda",
            "ALZ-43334f24-9116-4341-a2ba-527526944008",
            "ALZ-be7d7e48-4327-46d8-adc0-55bcf619e8a1",
            "ALZ-3f988795-25d6-4268-a6d7-0ba6c97be995",
            "ALZ-19048384-5c98-46cb-8913-156a12476e49",
        ],
    },
    "tenant-lighthouse-billing-governance": {
        "question": "Decide all eight tenant/billing GUIDs independently using redacted "
        "attributable references. Justify a single corporate tenant or the specific regulatory/"
        "business requirements that cannot be met there, with authoritative inventory and "
        "service/B2B, licensing, audit and JML considerations, not resource counts. For "
        "applicable multitenant platform automation, explain approved complete isolation or "
        "shared-application/per-tenant-principal boundaries, current user-assigned managed-"
        "identity federation qualifications, targeting, privilege/credential lifecycle, "
        "actual authorized operation, monitoring and recovery. Substantiate actual same-"
        "identity Lighthouse use and effective least-privilege delegated tasks separately "
        "from registration pairs. Lighthouse delegates subscriptions/RGs, not tenants/MGs "
        "or across clouds; Owner/custom/DataActions and specified authorization actions are "
        "unsupported, and UAA's constrained managed-identity assignment exception is not "
        "general access administration or full ALZ deployment authority. Explicitly establish "
        "partner/CSP applicability, customer approval, scope, audit/removal and agreement "
        "conditions; Entra GDAP/DAP, AOBO and resource delegation are different. Separately "
        "evidence the approved CSP case-creation/support/escalation process and dated operation "
        "without contacts, tickets or invented SLAs. Demonstrate actual suitable Cost "
        "Management reports/views, audiences, allocation and current data/access: view "
        "configuration is not underlying data, shared access, reporting or a pinned dashboard. "
        "Review actual EA charge policies or CSP Azure Plan/MCA/provider visibility and retail-"
        "versus-invoice limitations; MCA MG and EA/MCA cost-details MG limitations apply. "
        "Separately establish appropriate maintained agreement-specific notification group "
        "mailbox ownership, categories/cadence, delivery/review/escalation and continuity; "
        "EA notification contacts are not Bill to invoice contacts and MCA differs. Map actual "
        "approved organizational structure to EA departments/accounts or MCA profiles/invoice "
        "sections, or applicable CSP partner-managed MPA/customer structures; Azure MG hierarchy "
        "does not prove billing separation or authority. Never infer commercial model, tenant "
        "inventory, effective access, automation adoption or business suitability from names "
        "or metadata. Do not retain tenant/principal/contact/email identifiers, private partner "
        "records, raw billing names/IDs, prices, usage, query bodies or credentials. All eight "
        "outcomes stay blank until separately confirmed with scope/content/time/expiry binding; "
        "support and mailbox suitability stay manual. Signals, humanConfirmed and exceptions "
        "never manufacture technical Verified or a whole-recommendation pass.",
        "controls": [
            "ALZ-70c15989-c726-42c7-b0d3-24b7375b9201",
            "ALZ-6309957b-821a-43d1-b9d9-7fcf1802b747",
            "ALZ-78e11934-499a-45ed-8ef7-aae5578f0ecf",
            "ALZ-5d82e6df-6f61-42f2-82e2-3132d293be3d",
            "ALZ-a24d0de3-d4b9-4dfb-8ddd-bbfaf123fa01",
            "ALZ-32952499-58c8-4e6f-ada5-972e67893d55",
            "ALZ-685cb4f2-ac9c-4b19-9167-993ed0b32415",
            "ALZ-12cd499f-96e2-4e41-a243-231fb3245a1c",
        ],
    },
    "central-logging-support-service-enablement": {
        "question": "Reconcile the approved central logging architecture with complete "
        "platform/application resource populations, diagnostic log categories and original-time "
        "arriving data. Centralization permits separate tenant, residency, access, ownership, "
        "retention and resilience boundaries; a local typed workspace join is only supplied "
        "configuration, not complete coverage. Separately substantiate actual SIEM connectors, "
        "normalization/time synchronization, cross-service correlation, maintained detections "
        "and SecOps triage/response using redacted attributable evidence; Sentinel onboarding "
        "alone proves none and other SIEMs remain valid. For sovereign applicability, review "
        "Azure and M365 Lockbox separately: Azure tenant enablement, Developer-or-higher "
        "support, supported service/cloud population, subscription versus tenant approvers/"
        "audit sources, no MG-scoped approval roles and emergency/incidental/legal-demand "
        "exclusions; M365 tenant enablement, E5/G5 or qualifying add-on, supported "
        "Exchange/SharePoint/OneDrive/Teams/Windows365 and Copilot-through-Exchange coverage, "
        "distinct approver and audit setup. Azure four-day and M365 twelve-hour pending expiry "
        "are not universal approvals. No feature registration, role assignment or resource "
        "flag establishes either tenant's effective coverage or actual support approval. "
        "The Event Grid checklist link covers service metrics/activity alerts, not general "
        "log-query alerting: explain the real log-to-event/detection/action architecture, "
        "supported log-query versus metric/activity semantics and original-time end-to-end "
        "latency/failure/response evidence; configured frequency or a metric alert proves "
        "neither real-time delivery nor log correlation. Separately evidence everyday versus "
        "privileged account use, protected accountable administration and emergency/automation "
        "exceptions without identities. Distinguish the approved new-service readiness/adoption "
        "plan (network/data protection, identity, segregation, privacy/residency, operations/"
        "recovery, capacity/SKU/region/GA/compliance/SLA and owners) from the approved "
        "service-request fulfillment plan (intake, authorization, catalog, accountable "
        "fulfillment, service-specific targets, validation, escalation, rollback and closure). "
        "Never invent policy, licensing, SLA, requests or approvals. Use redacted references, "
        "not logs/KQL/rule bodies, support/private request contents, personal identities, "
        "endpoints, webhook URLs or credentials. Decide all seven GUIDs independently; a shared "
        "narrative or Signal never manufactures Verified.",
        "controls": [
            "ALZ-e5f8d79f-2e87-4768-924c-516775c6ea95",
            "ALZ-a56888b2-7e83-4404-bd31-b886528502d1",
            "ALZ-d21a922d-5ca7-427a-82a6-35f7b21f1bfc",
            "ALZ-874a748b-662d-46d1-9051-2a66498f6dfe",
            "ALZ-6f704104-85c1-441f-96d3-c9819911645e",
            "ALZ-9a19bf39-c95d-444c-9c89-19ca1f6d5215",
            "ALZ-ae514b93-3d45-485e-8112-9bd7ba012f7b",
        ],
    },
    "network-monitoring-sovereignty-policy": {
        "question": "Reconcile the exact ExpressRoute gateway with applicable diagnostics, "
        "actual arriving logs, gateway-specific metrics, approved dimensions/thresholds/"
        "actions and alert receipt, not the linked VPN instructions or circuit alerts. "
        "Establish actual both-direction VNet/ExpressRoute and Azure-local inspection paths, "
        "workload context and required exceptions; explicit remote-VNet/vWAN flags are not "
        "effective routes and the route-map-upgraded vWAN exception needs review. Answer "
        "whether interconnects cross borders/countries from attributable redacted physical/"
        "provider evidence; this is a factual question, not a blanket prohibition. Supply "
        "organization-approved geography and review peering, transit and alternate paths "
        "without treating resource or meet-me locations as countries. Separately decide "
        "required outbound, non-HTTP/S inbound and conditional east-west inspection, designated "
        "global/base policy and complete estate associations, parent priority/NAT/DNS inheritance "
        "exceptions, region constraints and actual least-privilege team delegation. For optional "
        "partner services, current reviewed guidance lists only Zscaler in secured vWAN hubs "
        "with VPN tunnels and partner-managed rules; historical IBoss/CheckPoint enums are not "
        "present-day support, nor does the source establish a retirement date. Verify original-"
        "time support, regional/cloud/service suitability and actual routing/filtering; no "
        "signup or credential exchange. Known reciprocal hub/WAN/firewall/VPN and local "
        "connection/table/intent joins remain configuration, not partner default-route opt-in, "
        "actual tunnels or complete branch/VPN-connection coverage. Prefer application rules "
        "for HTTP/S/MSSQL and FQDN tags where supported; other TCP/UDP FQDN network rules require "
        "DNS proxy and consistent client/upstream resolution, without network-rule wildcards. "
        "Local flags/rule counts and inherited references prove none of these whole outcomes. "
        "Use redacted attributable references and supply nine separate decisions; never retain "
        "raw destinations, logs, contracts, principal records or credentials.",
        "controls": [
            "ALZ-3f79ed00-203b-4c95-9efd-691505f5a1f9",
            "ALZ-5234c93f-b651-41dd-80c1-234177b91ced",
            "ALZ-8ac6a9e0-1e6a-483d-b5de-32c199248160",
            "ALZ-4cc8ca4e-a503-4bac-9b1e-82283a711043",
            "ALZ-8b517d94-c9d0-42c4-9803-d93ed0a46bc0",
            "ALZ-e6c4cfd3-e504-4547-a244-7ec66138a720",
            "ALZ-5a4b1511-e43a-458a-ac22-99c4d7b57d0c",
            "ALZ-655562f2-b3e4-4563-a4d8-739748b662d6",
            "ALZ-14d99880-2f88-47e8-a134-62a7d85c94af",
        ],
    },
    "identity-resilience-roles-emergency-access": {
        "question": "Reconcile actual least-privileged Entra directory authority and justified "
        "Global Administrator use independently of Azure RBAC; distinguish the permanent-active "
        "emergency exception. Identify the complete actual AD DS controller population with "
        "redacted references, not VM names/tags/types. Review two actual controllers across "
        "supported available zones, or an appropriate availability set where zones are "
        "unavailable; configured placement is not health. Bind required workload/recovery "
        "regions to actual identity services and independently demonstrate AD DS sites/subnets "
        "and local DC locator/resolution/use. Managed Domain Services replicas instead share "
        "one AD site: review complete same-subscription replica population, Enterprise/Premium "
        "for additional sets, eligible regions, full-mesh connectivity, redundant workloads "
        "and actual replication/recovery. Terraform initial replicas are a subset, not absence "
        "of separately managed sets. Reconcile platform/network/security/subscription/application "
        "responsibilities and effective inherited/conditional permissions; prefer adequate "
        "built-in Azure roles and justify custom roles only where needed. Evaluate every "
        "applicable workload's LDAP write, Kerberos/NTLM, join, schema/privilege and trust "
        "dependencies, one-way sync, stand-alone domain and migration/rollback acceptance; "
        "compatibility stays manual. Cite independently authorized tenant AuditLogs/SignInLogs "
        "routing to the approved central workspace and actual arriving coverage/retention. "
        "Tenant-only microsoft.aadiam diagnostic settings remain unsupported in this scope; "
        "subscription diagnostics or workspace existence cannot prove tenant integration. "
        "Separately evidence emergency operating decisions: two or more cloud-only accounts, "
        "federation independence, permanent-active GA, approved shared/individual model, safe "
        "separate custody, secure workstations, alerts/post-use review and at-least-90-day "
        "validation. Separately evidence phishing-resistant passkey/FIDO2 or appropriate "
        "certificate-based MFA, independent dependencies, nonexpiry/cleanup and blocking CA "
        "exclusions versus report-only. Reconcile actual phased MFA applicability/rollout, "
        "not frozen universal October2024 enforcement: phase2 from October1 2025 excludes reads "
        "and workload identities are unaffected. Use redacted attributable references only, "
        "never principal/tenant/user/account names, raw directory/guest/log records, credential/"
        "passkey/certificate material or raw role actions. Decide all eight canonical GUIDs "
        "independently; one narrative, Signal, exception or humanConfirmed flag proves none.",
        "controls": [
            "ALZ-d98d954d-7d1c-4a07-92a7-cf3afe8dcbd2",
            "ALZ-1559ab91-53e8-4908-ae28-c84c33b6b780",
            "ALZ-e8aa1e41-870d-4968-94c6-77be14f510ac",
            "ALZ-f5664b5e-984a-4859-a773-e7d261623a76",
            "ALZ-8b9fe5c4-1049-4d40-9a92-3c3474d00018",
            "ALZ-0dd4e625-9c4b-4a56-b54a-4357bac12761",
            "ALZ-1cf0b8da-70bd-44d0-94af-8d99cfc89ae1",
            "ALZ-984a859c-773e-47d2-9162-3a765a917e1f",
        ],
    },
    "virtual-wan-topology-routing-capacity": {
        "question": "Bind the approved connectivity matrix to a documented Virtual WAN design "
        "and staged migration, actual workload/branch populations, shared services, cutover "
        "and rollback. Reconcile one or more eligible regional hubs in the intended common "
        "Standard WAN, actual limits and independent failure domains; supplied hub/region "
        "counts are not complete coverage or global reachability. Review each hub's local "
        "security solution, Internet/PrivateTraffic intent, actual routes/rules/filtering "
        "and arriving logs, custom-route conflicts, bypasses, cloud/region/NVA constraints "
        "and Firewall zones; default routes do not cross hubs. Demonstrate actual Insights "
        "dependency-map/workbook use and relevant original-time metrics/status/alerts, not "
        "a synthetic enablement flag. Decide branch-to-branch requirements and explicit "
        "blocking exceptions separately, retaining the WAN-versus-hub flag distinction and "
        "no inferred defaults. Review all intended VNet/VPN/ExpressRoute/P2S associations and "
        "dynamic label propagation, Default/None isolation, static routes and routing-intent "
        "limits; prepared VNet/table labels are only a subset. ASPath has a separate exact "
        "configuration predicate, not a selected-route or failover guarantee. Reconcile "
        "immutable nonoverlapping hub IPv4 space: /24 minimum, /23 general recommendation, "
        "/22 for Firewall maximum scale and NVA-specific allocations, actual usage and "
        "growth, quota and noninstant RIU-versus-gateway scaling. Use redacted attributable "
        "references, not raw addresses, custom labels, route/query/traffic payloads or "
        "invented runtime tests. Equality fingerprints are not anonymous or physical "
        "identity proof. Decide these eight human-evidence GUIDs independently; a shared "
        "narrative, configuration or technical Verified result does not confirm them.",
        "controls": [
            "ALZ-412e7f98-3f63-4047-82dd-69c5b5c2622f",
            "ALZ-54b69bad-33aa-4d5e-ac68-e1d76667313b",
            "ALZ-7d5d1e4e-6146-458d-9558-fd77249b8211",
            "ALZ-6667313b-4f56-464b-9e98-4a859c773e7d",
            "ALZ-261623a7-65a9-417e-8f34-8ef254c27d42",
            "ALZ-727c77e1-b9aa-4a37-a024-129d042422c1",
            "ALZ-2586b854-237e-47f1-84a1-d45d4cd2310d",
            "ALZ-9c75dfef-573c-461c-a698-68598595581a",
        ],
    },
    "development-lifecycle-sovereignty": {
        "question": "Reconcile the scoped platform AND application source/IaC populations with "
        "actual version-control use, repository visibility/access and change history; the "
        "chosen GitHub Flow/trunk/release branch model, consistent naming, protection and fix "
        "porting; separate PR review, updated-head approvals, checks, merge and bypass "
        "practices; emergency code fixes, backlog registration and later review/debt/drift "
        "reconciliation; and declarative desired-state adoption, existing-resource state "
        "alignment, change previews, deployment and rollback responsibilities. Describe "
        "security participation in design, code, pipeline and operations, risk/remediation "
        "ownership and feedback, not merely enabled scans. For sovereignty, bind approved "
        "geographic and storage/processing requirements to actual build agents, registries/"
        "replicas, base-image and package origins, redirects, caches, logs and backups. "
        "Reconcile Azure Geo exceptions; Azure DevOps Services geography versus exact region, "
        "US macOS/Brazil fallback/token exceptions; GitHub.com versus GHE.com EU/EFTA/Australia/"
        "US/Japan and storage/telemetry/Copilot/secret-check exceptions; ACR all-replica syncing/"
        "global routing versus regional layer endpoints; and preview Linux-only dedicated-pool "
        "regions with external dependencies. Use redacted attributable references, not private "
        "source/pipeline payloads, identities, hosts, location inventories, registry credentials "
        "or secret values. Supply each of seven outcomes separately; one narrative, a local "
        "checkout, compiler, workflow, scan or resource location proves none.",
        "controls": [
            "ALZ-cfe363b5-f579-4284-bc56-a42153e4c10b",
            "ALZ-c7245dd4-af8a-403a-8bb7-890c1a7cfa9d",
            "ALZ-12aeea20-9165-4b3e-bdf2-6795fcd3cdbe",
            "ALZ-2676ae46-65ca-444e-8695-fdddeace4cb1",
            "ALZ-2cdc9d99-dbcc-4ad4-97f5-e7d358bdfa73",
            "ALZ-cc87a3bc-c572-4ad2-92ed-8cabab66160f",
            "ALZ-047c91e2-6bb4-4a42-a0ef-ab06ad0062c9",
        ],
    },
    "resource-cost-governance": {
        "question": "Describe the scoped process that communicates owner responsibilities and "
        "demonstrates access, budget and policy reviews and remediation. Separately establish "
        "subscription-owner/core-team quota awareness and provisioning impact: quota is not "
        "available regional capacity. Reconcile financial suitability and matching-usage "
        "Reserved Instance discounts separately from accepted on-demand capacity reservation, "
        "VM/SKU/region/zone association and SLA conditions; discounts do not guarantee capacity. "
        "Demonstrate working dashboards or other visualizations covering appropriate CPU, "
        "guest-memory and free-disk capacity, targets and original-time telemetry; tile counts "
        "and disk I/O are not coverage or health. Cite the approved operating cost plan, "
        "accountability, forecast/budget, allocation, agreed reviews and corrective actions. "
        "If server-based identity is applicable, explicitly designate the dedicated identity "
        "subscription/MG and substantiate hosting/isolation and regional AD DS sites/subnets/"
        "locator use or managed Domain Services design; names and parent edges prove no role. "
        "Reconcile approved billing/cost taxonomy and attributable allocation with supported "
        "service/agreement/scope/access and actual tag-inheritance/conflict/time conditions. "
        "Resource tags do not automatically inherit; Cost Management inheritance changes "
        "usage records, not resources or all history. Use redacted references only, never "
        "personal owner/directory records, tag values, raw dashboard queries/content, "
        "billing amounts, usage histories or credentials. Decide all seven canonical GUIDs "
        "separately; configuration or a shared answer alone establishes none.",
        "controls": [
            "ALZ-49b82111-2df2-47ee-912e-7f983f630472",
            "ALZ-2dd69c5b-5c26-422f-94b6-9bad33aad5e8",
            "ALZ-c68e1d76-6673-413b-9f56-64b5e984a859",
            "ALZ-c773e7d2-6162-43a7-95a9-17e1f348ef25",
            "ALZ-ae28c84c-33b6-4b78-88b9-fe5c41049d40",
            "ALZ-3a923c34-74d0-4001-aac6-a9e01e6a83de",
            "ALZ-5de32c19-9248-4160-9d5d-1e4e614658d3",
        ],
    },
    "expressroute-monitoring-routing-failover": {
        "question": "Reconcile actual Insights availability/utilization for both links, peering "
        "and gateway with maintenance interpretation and arriving alerts/output; configured "
        "monitors are not health. Review supported Arc/AMA and Network Watcher agents rather "
        "than the linked retired MMA instructions, complete source/destination/redundant-path "
        "coverage and approved probe frequency/loss/latency requirements. Bind distinct "
        "circuits and exact gateways to actual independent peering/provider/customer failure "
        "domains; configured location-label fingerprints are neither canonical sites nor "
        "physical independence. For single-circuit private peering, reconcile maintained "
        "route-based non-Basic VPN suitability, Internet backup independence and both-direction "
        "preference/failover evidence. Review dynamic edge convergence/load sharing or maintained "
        "active-passive routing, NAT/stateful effects and maintenance draining. Bind both "
        "physical links to distinct real customer devices; verify interface and BGP-linked BFD "
        "on both customer/provider edges with private/Microsoft, IPv4/IPv6 creation/reset dates "
        "and vendor echo behavior. GatewaySubnet propagation has a separate strictly joined "
        "configuration predicate, not an availability/effective-route claim. Use attributable "
        "redacted references, never endpoint addresses, router credentials, raw probes or "
        "fabricated operational tests. Decide these eight human-evidence GUIDs separately; "
        "one answer or cloud-side default creates no whole-recommendation outcome.",
        "controls": [
            "ALZ-b30e38c3-f298-412b-8363-cefe179b599d",
            "ALZ-5bf68dc9-325e-4873-bf88-f8214ef2e5d2",
            "ALZ-e0d5973c-d4cd-421b-8881-37f5e6c4cfd3",
            "ALZ-cf3fe65c-fec0-495a-8edc-9675200f2add",
            "ALZ-d581a947-69a2-4783-942e-9df3664324c8",
            "ALZ-b258f058-b9f6-46cd-b28d-990106f0c3f8",
            "ALZ-fe2a1b53-6fbd-4c67-b58a-85d7c7a0afcb",
            "ALZ-669b215a-ce43-4371-8f6f-11047f6490f1",
        ],
    },
    "dr-dns-bastion": {
        "question": "Reconcile complete production/DR address populations and any Site Recovery "
        "IP-retention/subnet-move exception; actual public-IP SKU/region/API/zone and attached-"
        "service suitability; Azure-only zone ownership/delegation and default/custom DNS; "
        "both-direction hybrid Resolver endpoints, exclusive delegated subnets, rules, regional "
        "links and loop avoidance; workload-specific DNS; VM-primary-NIC-only registration and "
        "other record lifecycles; multi-region failover ownership/TTL/cache/update/rollback "
        "evidence; Windows/container UDP SOURCE port 65330 exclusion evidence; and Bastion "
        "SKU/private-only/legacy subnet/access/bypass/NSG/route/DNS exceptions. Use redacted "
        "evidence references, not DNS records, raw destinations, host inventories, credentials "
        "or recording URLs. Decide all ten GUIDs separately; configuration and one narrative "
        "do not establish outcomes.",
        "controls": [
            "ALZ-f348ef25-4c27-4d42-b8bb-ac7571559ab9",
            "ALZ-0c47f486-656d-4699-8c30-edef5b8a93c4",
            "ALZ-153e8908-ae28-4c84-a33b-6b7808b9fe5c",
            "ALZ-41049d40-3a92-43c3-974d-00018ac6a9e0",
            "ALZ-1e6a83de-5de3-42c1-a924-81607d5d1e4e",
            "ALZ-614658d3-558f-4d77-849b-821112df27ee",
            "ALZ-18c80eb0-582a-4198-bf5c-d8800b2d263b",
            "ALZ-baac3ecb-a94c-4ac4-8c79-cdf27c0d78df",
            "ALZ-ee1ac551-c4d5-46cf-b035-d0a3c50d87ad",
            "ALZ-6eab9eb6-762b-485e-8ea8-15aa5dba0bd0",
        ],
    },
    "expressroute-cost-resilience": {
        "question": "Describe the attributable actual outbound demand and full metered/unlimited/"
        "Direct-port/circuit/gateway/provider cost comparison, including Local reach and Global "
        "Reach restrictions. Reconcile physical peering location with every required workload/"
        "recovery region; resource location and public tables do not attest current availability. "
        "Distinguish AZ-capable SKU from deployed gateway/public-IP zone placement and Azure "
        "active-active from real independent on-premises appliances and failover. Supply actual "
        "throughput/latency and dedicated-port requirements rather than configured bandwidth. "
        "Review FastPath's exact connection/gateway/scale prerequisites, provider versus Direct "
        "IPv4/IPv6 and same-region topology, enrolled limited-GA Private Link services, published "
        "IP limits, fixed-scale guidance and fallback capacity. Reconcile Direct/Local billing "
        "choices and actual dedicated circuits, routing domains, VLAN/VRF/BGP paths and shared "
        "port contention against explicit isolation requirements. Use redacted attributable "
        "references, never addresses, keys or secret/private device identities. Decide each "
        "of the nine canonical GUIDs separately; configuration or one answer alone proves none.",
        "controls": [
            "ALZ-7025b442-f6e9-4af6-b11f-c9574916016f",
            "ALZ-f4e7926a-ec35-476e-a412-5dd17136bd62",
            "ALZ-2447ec66-138a-4720-8f1c-e16ed301d6e8",
            "ALZ-72e52e36-11cc-458b-9a4b-1511e43a58a9",
            "ALZ-c2299c4d-7b57-4d0c-9555-62f2b3e4563a",
            "ALZ-4d873974-8b66-42d6-b15f-512a65498f6d",
            "ALZ-45866df8-cf85-4ca9-bbe2-65ec1478919e",
            "ALZ-718cb437-b060-2589-8856-2e93a5c6633b",
            "ALZ-8042d88e-79d1-47b7-9b22-a5a67e7a8ed4",
        ],
    },
    "sovereign-audit-workload-protection": {
        "question": "Describe approved sovereign key-custody requirements and actual compatible "
        "CMK use: Managed HSM keys are not secrets/credentials, and external KEK custody adds "
        "customer-run HSM/proxy responsibilities. Identify actual redacted Entra access-audit "
        "reports separately from Azure activity logs. Reconcile all applicable subscriptions' "
        "activity categories, successful ingestion/export and table/storage retention with "
        "approved requirements; configuration and new-arrival export do not prove history. "
        "Distinguish paid CSPM, Servers P1/P2 and workload-specific plans/components, "
        "resource overrides, actual coverage and endpoint enforcement. Reconcile Update "
        "Manager assessment success and base-OS patch drift against the approved baseline "
        "rather than deprecated MMA or a guessed threshold. Use attributable redacted "
        "evidence references, never credentials, keys, security domains or private audit/"
        "endpoint records. Decide all eight canonical GUIDs separately; one answer, "
        "pricing record or diagnostic flag alone establishes no outcome.",
        "controls": [
            "ALZ-4ac6b67c-b3a4-4ff9-8e87-b07a7ce7bbdb",
            "ALZ-4e5695f2-223a-4ce8-ab12-308ca5017f15",
            "ALZ-4e3ab369-3829-4e7e-9161-83687a0477a2",
            "ALZ-09945bda-4333-44f2-9911-634182ba5275",
            "ALZ-36a72a48-fffe-4c40-9747-0ab5064355ba",
            "ALZ-77425f48-ecba-43a0-aeac-a3ac733ccc6a",
            "ALZ-24d96b30-61ee-4436-a1cc-d6ef08bc574b",
            "ALZ-15833ee7-ad6c-46d3-9331-65c7acbe44ab",
        ],
    },
    "inbound-outbound-hybrid": {
        "question": "Describe global Front Door policy/domain/route coverage and effective rules; "
        "both origin backend filtering and exact X-Azure-FDID rejection; workload-aligned proxy "
        "placement; every supported public IP's DDoS protection and arriving diagnostics; "
        "the approved explicit-outbound migration strategy with current API/existing-network "
        "scope (not the frozen retirement date); actual NIC-deny policy assignment/version/"
        "enforcement and independent exceptions; maintained primary ExpressRoute/backup VPN "
        "suitability; both-direction BGP preference; and measured demand supporting gateway "
        "SKU/generation. Reference redacted evidence, not header values, hosts, peer addresses "
        "or secrets. Decide all ten GUIDs separately, including both D05.08 meanings. "
        "Configuration or one shared answer alone establishes none of these outcomes.",
        "controls": [
            "ALZ-1d7aa9b6-4704-4489-a804-2d88e79d17b7",
            "ALZ-3b22a5a6-7e7a-48ed-9b30-e38c3f29812b",
            "ALZ-2363cefe-179b-4599-be0d-5973cd4cd21b",
            "ALZ-088137f5-e6c4-4cfd-9e50-4547c2447ec6",
            "ALZ-b034c01e-110b-463a-b36e-e3346e57f225",
            "ALZ-b1c82a3f-2320-4dfa-8972-7ae4823c8930",
            "ALZ-3c5a808d-c695-4c14-a63c-c7ab7a510e41",
            "ALZ-359c373e-7dd6-4162-9a36-4a907ecae48e",
            "ALZ-f29812b2-363c-4efe-879b-599de0d5973c",
            "ALZ-d4cd21b0-8813-47f5-b6c4-cfd3e504547c",
        ],
    },
    "access-operating-model": {
        "question": "Describe the approved RBAC scope/operating model and group source of "
        "authority; actual managed-identity use; administrator work/school account provenance; "
        "Conditional Access and MFA coverage, exclusions and evaluation evidence; and PIM "
        "eligible/active/permanent grants, activation limits and accepted responsibilities. "
        "Use redacted evidence references, not principal names, user records or credentials. "
        "Decide each canonical GUID separately, including the two distinct B03.02 entries. "
        "Configuration, one sign-in or an interview answer alone establishes no enforcement.",
        "controls": [
            "ALZ-348ef254-c27d-442e-abba-c7571559ab91",
            "ALZ-4348bf81-7573-4512-8f46-9061cc198fea",
            "ALZ-12e7f983-f630-4472-8dd6-9c5b5c2622f5",
            "ALZ-4b69bad3-3aad-45e8-a68e-1d76667313b4",
            "ALZ-53e8908a-e28c-484c-93b6-b7808b9fe5c4",
            "ALZ-1049d403-a923-4c34-94d0-0018ac6a9e01",
            "ALZ-e6a83de5-de32-4c19-a248-1607d5d1e4e6",
            "ALZ-14658d35-58fd-4772-99b8-21112df27ee4",
        ],
    },
    "vault-operating-model": {
        "question": "Describe how applications use, partition, access, privately reach and audit "
        "Key Vault. Give redacted evidence references and record a separate decision for each "
        "selected recommendation; neither a vault's existence nor a shared answer proves them.",
        "controls": [
            "ALZ-5017f154-e3ab-4369-9829-e7e316183687",
            "ALZ-a0477a20-9945-4bda-9333-4f2491163418",
            "ALZ-dc055bcf-619e-48a1-9f98-879525d62688",
            "ALZ-cdb3751a-b2ab-413a-ba6e-55d7d8a2adb1",
            "ALZ-17d6326a-f625-4ca4-9e56-95f2223ace8c",
        ],
    },
    "private-service-paths": {
        "question": "Describe shared PaaS private endpoints and the on-premises private-peering "
        "path, including subresource approval, DNS, routes, return path and public-access gaps. "
        "Reference redacted path evidence and decide each selected recommendation separately.",
        "controls": [
            "ALZ-e43a58a9-c229-49c4-b7b5-7d0c655562f2",
            "ALZ-b3e4563a-4d87-4397-98b6-62d6d15f512a",
        ],
    },
}
FIELDS = ("reviewer", "rationale", "evidence", "valid_from", "valid_until")


def question_bank(catalog: dict[str, Any]) -> dict[str, Any]:
    validate(catalog, "catalog")
    controls = {control["control_id"]: control for control in catalog["controls"]}
    questions = []
    for identity, item in BANK.items():
        if any(
            control not in controls or controls[control].get("rule") for control in item["controls"]
        ):
            raise InputError("Question bank requires its exact retained human-evidence controls")
        questions.append(
            {
                "id": identity,
                "question": item["question"],
                "controls": [
                    {
                        "control_id": control,
                        "recommendation": controls[control]["recommendation"],
                        "evidence_requirements": controls[control]["evidence_requirements"],
                        "limitations": controls[control]["rationale"],
                    }
                    for control in item["controls"]
                ],
            }
        )
    return {
        "schema_version": "1.0",
        "kind": "question-bank",
        "version": BANK_VERSION,
        "questions": questions,
        "warning": "Answers alone never establish an outcome.",
    }


def prepare_interview(
    assessment: dict[str, Any],
    catalog: dict[str, Any],
    question_id: str,
    scope: str,
    selected: list[str] | None = None,
) -> dict[str, Any]:
    question_bank(catalog)
    if question_id not in BANK:
        raise InputError("Unknown reviewed interview question")
    controls = selected if selected is not None else BANK[question_id]["controls"]
    if (
        not isinstance(controls, list)
        or not controls
        or any(not isinstance(control, str) for control in controls)
        or len(set(controls)) != len(controls)
        or any(control not in BANK[question_id]["controls"] for control in controls)
    ):
        raise InputError("Interview selection must be unique canonical controls from its question")
    prepared = prepare_reviews(assessment, catalog, controls, scope)
    return {
        "schema_version": "1.0",
        "kind": "interview-response",
        "bank_version": BANK_VERSION,
        "catalog_sha256": digest(catalog),
        "question_id": question_id,
        "scope": scope_id(scope),
        "answer": None,
        **{field: None for field in FIELDS},
        "decisions": [
            {
                "control_id": entry["control_id"],
                "control_sha256": entry["control_sha256"],
                "outcome": None,
            }
            for entry in prepared["entries"]
        ],
        "requirements_sha256": digest(
            {
                "scope": scope_id(scope),
                "controls": {
                    control: next(c for c in catalog["controls"] if c["control_id"] == control)[
                        "evidence_requirements"
                    ]
                    for control in controls
                },
            }
        ),
    }


def compile_interview(
    response: Any,
    catalog: dict[str, Any],
    *,
    at: str | None = None,
) -> dict[str, Any]:
    question_bank(catalog)
    if (
        not isinstance(response, dict)
        or set(response)
        != {
            "schema_version",
            "kind",
            "bank_version",
            "catalog_sha256",
            "question_id",
            "scope",
            "answer",
            *FIELDS,
            "decisions",
            "requirements_sha256",
        }
        or response.get("schema_version") != "1.0"
        or response.get("kind") != "interview-response"
    ):
        raise InputError("Expected interview-response contract 1.0 with exact fields")
    if response["bank_version"] != BANK_VERSION or response["catalog_sha256"] != digest(catalog):
        raise InputError("Interview bank/catalog changed; prepare a new response")
    question_id = require(response, "question_id", str)
    if question_id not in BANK:
        raise InputError("Unknown reviewed interview question")
    scope = scope_id(require(response, "scope", str))
    answer = require(response, "answer", str)
    if len(answer) > 4000:
        raise InputError("Interview answer exceeds 4,000 characters")
    for field in FIELDS:
        if len(require(response, field, str)) > (200 if field == "reviewer" else 4000):
            raise InputError("Interview review field exceeds bounds")
    if len(answer.strip() + "\n\n" + response["rationale"].strip()) > 4000:
        raise InputError("Combined interview answer and rationale exceed review field bounds")
    decisions = require(response, "decisions", list)
    if not decisions or len(decisions) > len(BANK[question_id]["controls"]):
        raise InputError("Interview requires bounded explicitly selected decisions")
    controls = {control["control_id"]: control for control in catalog["controls"]}
    seen = set()
    entries = []
    for decision in decisions:
        if not isinstance(decision, dict) or set(decision) != {
            "control_id",
            "control_sha256",
            "outcome",
        }:
            raise InputError("Supply exact per-control interview outcome and binding")
        identity = require(decision, "control_id", str)
        if identity not in BANK[question_id]["controls"] or identity in seen:
            raise InputError("Unknown or duplicate interview control")
        seen.add(identity)
        if decision["control_sha256"] != control_digest(controls[identity]):
            raise InputError("Interview control content changed")
        entries.append(
            {
                **decision,
                "scope": scope,
                **{field: response[field].strip() for field in FIELDS},
                "rationale": answer.strip() + "\n\n" + response["rationale"].strip(),
            }
        )
    if response["requirements_sha256"] != digest(
        {
            "scope": scope,
            "controls": {control: controls[control]["evidence_requirements"] for control in seen},
        }
    ):
        raise InputError("Interview requirements binding changed")
    record = document("manual", schema_version="1.1", entries=entries)
    if not validate_reviews(record, catalog, scope, at)["ready_to_apply"]:
        raise InputError("Every interview decision must be current and bound before applying")
    return record
