"""Shared narrative collection with explicit per-control bound human decisions."""

from typing import Any

from .contracts import control_digest, digest, document, require, scope_id, validate
from .reviews import prepare_reviews, validate_reviews
from .terraform import InputError

BANK_VERSION = "2026-11-06.27"
BANK = {
    "incident-zero-trust-key-lifecycle": {
        "question": (
            "Decide all eight recommendations independently, with separately attributable "
            "redacted evidence and exceptions, never one shared outcome. For G01.01, review "
            "service-specific pre-production incident plans, shared responsibilities, roles, "
            "escalation, prioritization, containment/recovery and original-time "
            "exercise/lessons evidence; legacy benchmark wording is qualified by current MCSB"
            " IR guidance. No incidents or personal contacts are retained and no exercise is "
            "run. For G01.02, substantiate verify-explicitly, least-privilege and assume-"
            "breach objectives across identities, endpoints, applications, infrastructure, "
            "networks and data, including workload and non-landing-zone responsibilities; a "
            "resource checklist is not Zero Trust maturity. For G02.05, distinguish "
            "integrated public-CA automation (currently DigiCert/GlobalSign), nonintegrated "
            "CA signing/merge workflows and self-signed regeneration. An imported "
            "certificate, expiration notification or vault is not automated public-CA "
            "renewal, deployment or successful adoption by consumers. For G02.06, separately "
            "review key generation/rotation, certificate renewal and consumer updates, "
            "ownership, lifetimes, service-specific refresh/old-version overlap and tested "
            "failure/recovery paths. Native key rotation is not import of externally "
            "generated HSM material; Managed HSM is key-only, not a certificate vault. For "
            "G02.09, distinguish vault instantiation/control-plane authority from data-plane "
            "access, actual team delegation/PIM/conditions/deny constraints and exact "
            "reviewed Policy definitions/versions/assignments/scopes/exclusions/exemptions "
            "plus timely compliance evidence. No referenced definition is fetched or rule "
            "interpreted. For G02.10, retain immutable MMK wording and current "
            "platform/service-managed terminology, default MMK versus requirement-driven CMK "
            "decisions per service/data set, dependencies, availability and recovery "
            "ownership. Storage keySource is only an explicit narrow setting; Blob/Files "
            "differs from Queue/Table Account versus Service key type, infrastructure "
            "encryption is separate and Terraform inline CMK presence/absence cannot "
            "reconcile separate CMK resources. Storage's versionless daily refresh is not key"
            " rotation or proof that consumers have updated. For G02.11, independently "
            "determine whether an accountable organizational sovereignty requirement mandates"
            " CMK; no geography, encryption setting or external-key-management preview "
            "establishes legal eligibility or sufficient sovereignty. For G02.12, review "
            "every required service/feature/SKU/cloud/region, Key Vault versus Managed HSM "
            "support, key origin/BYOK/algorithm/size/lifecycle and end-to-end "
            "availability/consumer integration against current service-specific references. A"
            " general support-table Yes or blank is not universal BYOK compatibility. All "
            "coverage, requirements, ownership, operation and exception decisions stay blank "
            "until explicitly supplied. No "
            "key/certificate/secret/URI/issuer/principal/incident/private payload retention, "
            "live probes, scans, queries, credential/key/renewal/rotation changes, contact or"
            " incident exercises."
        ),
        "controls": [
            "ALZ-b86ad884-08e3-4727-94b8-75ba18f20459",
            "ALZ-01365d38-e43f-49cc-ad86-8266abca264f",
            "ALZ-6d70ba6c-97be-4995-8904-83845c986cb2",
            "ALZ-913156a1-2476-4e49-b541-acdce979377b",
            "ALZ-b12308ca-5017-4f15-9e3a-b3693829e7e3",
            "ALZ-16183687-a047-47a2-8994-5bda43334f24",
            "ALZ-b48ade7f-50be-4d2e-9866-d57b17942fc2",
            "ALZ-25d62688-6d70-4ba6-a97b-e99519048384",
        ],
    },
    "agreement-budgets-visibility-billing-governance": {
        "question": (
            "Decide seven recommendations independently with dated attributable redacted evidence "
            "and separate exceptions. A03.03: establish actual EA department/account population, "
            "complete approved allocations and each budget/alert, including "
            "periods/filters/currency suitability, actual/forecasted semantics, "
            "authorized required recipients and demonstrated "
            "delivery/escalation; daily delayed budget evaluation does not stop consumption, and "
            "subscription/RG metadata proves no enrollment coverage. A03.04: independently "
            "substantiate every applicable EA DA/AO visibility policy plus appropriate scoped "
            "permissions and effective audience access; MCA Azure charges and "
            "partner cost policies "
            "differ, resource RBAC is not billing authority. A03.05: cite approved authoritative "
            "EA0148P qualification, Visual Studio rights and actual permitted development/testing "
            "adoption with current-terms reliability exceptions, not an assessor "
            "eligibility decision or saving claim. A04.01: independently establish "
            "MCA notification categories, maintained group-mailbox ownership/continuity, "
            "appropriate configuration and actual delivery/review/"
            "escalation; account contact, sold-to, bill-to, invoice email and sign-in destinations "
            "differ. A04.02: justify MCA profiles versus sections against organization "
            "and separate-invoice requirements, current complete mapping/roles and "
            "charge/reservation implications; "
            "qualify frozen same-profile movement wording with current product exceptions, never "
            "infer from MGs or cost views. A04.03: independently cite approved "
            "MCA0148G qualification, "
            "active Visual Studio subscriber conditions, permitted actual development/testing use "
            "and reliability exceptions; EA0148P and monthly credits are different. "
            "A04.04: document and demonstrate actual periodic billing-role audits "
            "covering direct/inherited/elevated authority, least privilege, cadence "
            "chosen by the organization, completed findings and "
            "verified remediation; written process or resource role assignments alone are "
            "insufficient. Keep each applicability/outcome blank until explicitly "
            "decided; no shared "
            "answer, Signals or humanConfirmed produces Verified. Do not retain amounts/currency/"
            "spend/billing identifiers/account or invoice content/contact/recipient/"
            "principal/secret "
            "payloads, and perform no live read, query, alert test, contact/permission change, "
            "eligibility decision, enrollment or purchase."
        ),
        "controls": [
            "ALZ-54f0d8b1-22a3-4c0d-8ce2-58b9e086c93a",
            "ALZ-ca0fe401-12ad-46fc-8a7e-86293866a9f6",
            "ALZ-5cf9f485-2784-49b3-9824-75d9b8bdb57b",
            "ALZ-6ad5c3dd-e5ea-4ff1-81a4-7886ff87845c",
            "ALZ-90e87802-602f-4dfb-acea-67c60689f1d7",
            "ALZ-e81a73f0-84c4-4641-b406-14db3b4d1f50",
            "ALZ-ae757485-92a4-482a-8bc9-eefe6f5b5ec3",
        ],
    },
    "naming-hierarchy-scoped-authorization": {
        "question": "Decide all eight GUIDs independently "
        "using attributable redacted evidence, "
        "explicit selected "
        "scope/content/time/expiry binding and "
        "separate exceptions. C01.01: cite the "
        "approved organization-specific naming "
        "standard, covered resource "
        "types/scopes, component order and "
        "immutable versus mutable metadata, "
        "actual adoption, ownership and "
        "exceptions; Azure "
        "syntax/examples/counts are not "
        "approval and no resource names or "
        "private tag values are retained. "
        "C02.01: declare the authoritative "
        "tenant root and ALZ intermediate root, "
        "exact level-counting convention, "
        "complete dated hierarchy and justified "
        "flatness/exceptions; immutable "
        "four-level wording must be reconciled "
        "with current CAF ideally three-to-four "
        "guidance, separately from the "
        "six-level service limit excluding "
        "tenant root/subscriptions. Supplied "
        "relative MG edges exclude the selected "
        "anchor and subscriptions and do not "
        "determine estate depth. C02.02: "
        "explicitly designate the sandbox and "
        "evidence experimentation, isolation "
        "from development/test/production, "
        "guardrails, access, cost/lifecycle and "
        "actual operating ownership; a label or "
        "group is insufficient. C02.03: "
        "designate the platform and intended "
        "tenant/intermediate parent, "
        "substantiate direct placement and "
        "common platform Policy/RBAC and "
        "accountable ownership; do not infer "
        "purpose/root from names or parentage. "
        "C02.04: designate the dedicated "
        "connectivity subscription and intended "
        "Connectivity MG, substantiate actual "
        "membership, required central "
        "networking/DNS/ER or justified "
        "alternatives and scale/regional "
        "exceptions; subscription or networking "
        "presence does not prove dedicated use. "
        "C02.05: separately establish "
        "authoritative tenant root, complete "
        "existing subscription placement and "
        "approved exceptions, and the explicit "
        "default group for future "
        "subscriptions; defaultManagementGroup "
        "does not relocate existing "
        "subscriptions or prove absence at "
        "root. C02.06: reconcile the explicit "
        "requireAuthorizationForGroupCreation "
        "setting attached to independently "
        "designated tenant root with separately "
        "evidenced effective least-privileged "
        "create/move/delete/settings/access "
        "operations, inheritance, PIM and "
        "emergency exceptions; the creation "
        "toggle and settings-read/write role do "
        "not prove all privileged operations. "
        "C02.07: bind each designated "
        "landing-zones child group to approved "
        "security/compliance/connectivity/feature "
        "requirements, actual placement and "
        "effective Policy/ownership; do not "
        "copy organizational charts or infer "
        "business purpose from graph shape. "
        "Missing/partial/ambiguous/stale/denied/unsupported/over-bound "
        "inputs remain unknown. No tenant "
        "reads, changes, queries or fabricated "
        "owner confirmation. Signals and "
        "humanConfirmed never manufacture "
        "Verified.",
        "controls": [
            "ALZ-cacf55bc-e4e4-46be-96bc-57a5f23a269a",
            "ALZ-2df27ee4-12e7-4f98-9f63-04722dd69c5b",
            "ALZ-667313b4-f566-44b5-b984-a859c773e7d2",
            "ALZ-61623a76-5a91-47e1-b348-ef254c27d42e",
            "ALZ-8bbac757-1559-4ab9-853e-8908ae28c84c",
            "ALZ-33b6b780-8b9f-4e5c-9104-9d403a923c34",
            "ALZ-74d00018-ac6a-49e0-8e6a-83de5de32c19",
            "ALZ-92481607-d5d1-4e4e-9146-58d3558fd772",
        ],
    },
    "recovery-guest-drift-waf-telemetry": {
        "question": (
            "Decide all eight recommendations independently using attributable redacted evidence, "
            "never one shared outcome. For Azure VM DR, reconcile complete eligible VM/application/"
            "dependency populations, Azure-to-Azure Site Recovery and native backup configuration "
            "with separately approved RPO/RTO, recovery points, retention, network/failback and "
            "actual drill/restore evidence. For redundancy, preserve the immutable GRS-default "
            "wording but qualify Recovery Services versus Data Protection Backup vaults, datastore/"
            "workload/region support and Azure Files snapshot versus vaulted backup; generic "
            "account SKU and omitted settings prove no default or suitable backup choice. For "
            "guest deployment, distinguish legacy Guest Configuration wording from current Machine "
            "Configuration, direct versus Policy-created assignments, Audit/apply/autocorrect "
            "modes, exact guest extension publisher/type/instance names, identity/network/content "
            "prerequisites and current OS/architecture/VMSS/Arc support, including November 2026 "
            "Linux PowerShell changes; assignments do not prove execution or compliance. For "
            "security drift monitoring, separately substantiate expected baselines, Policy "
            "definitions/versions/assignments/parameters/exclusions, timely compliance "
            "observations, "
            "responsible review and operating response. No built-in fetch or second rule "
            "interpreter. For PaaS DR, assess every actual service/SKU/region and "
            "component/workload "
            "failover/failback plan with original-time drills; a SQL Database failover group is "
            "narrow configuration, not universal support, successful failover or achieved RPO/RTO. "
            "For native/third-party backup, substantiate compatible workload/version coverage, "
            "retention/restore/security and ownership; legacy Backup Center now points to "
            "Resiliency/Business Continuity Center, whose presence is not protection. For WAF "
            "diagnostics, bind the actual delivery resource/service to explicit enabled firewall-"
            "log categories and destinations, then independently substantiate ingestion, "
            "retention, "
            "regular attack and false-positive review/tuning. Standard/Premium Front Door uses "
            "FrontDoorWebApplicationFirewallLog; classic capitalization differs and is unsupported "
            "by this preparatory target model. The Sentinel walkthrough's FrontDoorFirewallLog "
            "names conflict with the service-specific monitoring page: do not equate them. For "
            "WAF-to-Sentinel, separately prove connector/content configuration, arriving WAF data, "
            "analytics/detection coverage and accountable response; shared workspace/onboarding "
            "and categories do not prove integration. All requirements, coverage, testing, "
            "operating decisions and exceptions remain blank until explicitly supplied. No live "
            "probes, commands, backup/restore/failover, guest or compliance execution, "
            "WAF attacks, "
            "queries, traffic or telemetry retrieval; no logs, guest/package/report payloads, "
            "scripts, settings, secrets, private endpoints or personal data retained."
        ),
        "controls": [
            "ALZ-7ea02e1c-7166-45a3-bdf5-098891367fcb",
            "ALZ-eba8cf22-45c6-4dc1-9b57-2cceb3b97ce5",
            "ALZ-f541acdc-e979-4377-acdb-3751ab2ab13a",
            "ALZ-da6e55d7-d8a2-4adb-817d-6326af625ca4",
            "ALZ-b2ab13ad-a6e5-45d7-b8a2-adb117d6326a",
            "ALZ-f625ca44-e569-45f2-823a-ce8cb12308ca",
            "ALZ-89cc5e11-aa4d-4c3b-893d-feb99215266a",
            "ALZ-7f408960-c626-44cb-a018-347c8d790cdf",
        ],
    },
    "log-retention-machine-resource-guardrails": {
        "question": (
            "Provide nine independently attributable original-time decisions and exceptions, "
            "not a shared approval. F01.01: identify the approved central workspace and "
            "justify separate tenant, RBAC, ownership, sovereignty and per-resource same-"
            "table retention exceptions, with complete ingestion evidence. F01.02: approve "
            "single versus regional workspaces against required geography/resilience, VM "
            "bandwidth versus diagnostic-setting egress, access and cost; location "
            "labels/counts do not establish suitable design. F01.03: specify each required "
            "dataset's retention/recovery/privacy obligations and source-qualified analytics "
            "versus total day periods, acknowledging current4383-day/12-year total, ARM "
            "inheritance, Basic30 versus old provider8 and CLI2556 differences; if longer or "
            "tamper protection is required, show supported selected-table new-data export, "
            "historical coverage, actual same-region destination/container delivery and "
            "suitable locked/version/container WORM/legal hold interval, not settings-only "
            "legal assurance. F01.04: identify required Azure/Arc OS configuration drift "
            "audits, current OS/client/architecture and November2026 compatibility, "
            "prerequisite identity/extension and exact Policy/guest assignment scope/mode, "
            "then attributable completed audit/freshness/coverage evidence; assignments are "
            "not executed audits. F01.05: demonstrate actual Windows/Linux Azure VM Update "
            "Manager adoption, eligibility, extension/source health, maintenance and "
            "business-continuity schedules, complete patch results and exceptions; "
            "assessmentMode/patchMode are not installed updates. F01.06: separately "
            "demonstrate outside-Azure Arc server enrollment/support/connectivity, "
            "extension/source health, schedules, scope and actual patch results/exceptions; "
            "AzureRM4.50.0 Arc has no patch fields, and Log Analytics/Automation is not a "
            "prerequisite. F01.07: show required Network Watcher flow/traffic analytics "
            "operation, VNet migration from NSG flow logs (no new creation; "
            "retirement2027-09-30), actual supported targets, arriving storage/analytics, "
            "freshness/coverage and owned response; regional enablement or definitions are "
            "not executed traffic analysis. F01.08: independently designate critical shared "
            "services and review actual lock scope/level, full ancestor coverage, removal "
            "authority, control-plane/data-plane limits, side effects and exceptions; no "
            "management-group or subscription-cancellation protection inferred. F01.09: "
            "demonstrate appropriate Policy deny plus role-assignment guardrails with exact "
            "definitions/versions/conditions/parameters, assignment/enforcement, "
            "scope/inheritance/exemptions and actual permitted/blocked operations; "
            "distinguish RBAC deny assignments/private preview, no generic literal effect or "
            "role presence proves effective enforcement."
        ),
        "controls": [
            "ALZ-67e7a8ed-4b30-4e38-a3f2-9812b2363cef",
            "ALZ-7418ada9-4199-4c28-8286-d15e9433e8f3",
            "ALZ-5e6c4cfd-3e50-4454-9c24-47ec66138a72",
            "ALZ-e7d7e484-3276-4d8b-bc05-5bcf619e8a13",
            "ALZ-f9887952-5d62-4688-9d70-ba6c97be9951",
            "ALZ-c806c048-26b7-4ddf-b4c2-b4f0c476925d",
            "ALZ-90483845-c986-4cb2-a131-56a12476e49f",
            "ALZ-541acdce-9793-477b-adb3-751ab2ab13ad",
            "ALZ-a6e55d7d-8a2a-4db1-87d6-326af625ca44",
        ],
    },
    "sovereign-organization-regions-classification": {
        "question": "Decide all seven GUIDs independently with attributable redacted evidence "
        "and explicit scope/content/time/expiry binding. For C02.15 designate the authoritative "
        "landing-zones parent and both confidential organizational roles and substantiate each "
        "direct placement; names and positive parentage do not designate purposes. For C03.01 "
        "bind approved residency, latency, cost, reliability and dependency requirements to "
        "chosen regions and separately authorized access/quota/capacity references, not private "
        "workload/employee/location inventories or legal eligibility judgments. For C03.02 "
        "justify regional organization and actual independent failure domains, replication, "
        "recovery dependencies and tested failover/capacity; distinct labels and region pairs "
        "prove none, and current guidance does not mandate pairing or historical distance. "
        "For C03.03 reconcile every required service/SKU/feature/version/dependency in each "
        "primary/recovery region with dated evidence and independently review actual "
        "entitlement/access/quota/capacity; the public product page is informational and subject "
        "to change. For C04.01 explicitly reconcile immutable Public wording with the pinned "
        "four-zone Corp/Online and confidential architecture, approved customization, connectivity "
        "and confidential-computing policy controls; no Public-named MG is assumed. For C04.02 "
        "cite the organization's approved taxonomy, scope across processing/flows/backup/cache/"
        "preproduction, handling rules, unclassified/ambiguous decisions and ongoing maintenance; "
        "example labels are not a universal taxonomy and no actual private data is classified. "
        "For C04.03 substantiate approved non-sensitive sovereign metadata and actual consistent "
        "usage plus separate policy controls/enforcement; tags are plain text, not inherited or "
        "supported on MGs, and counts prove no classification/sovereignty. Preserve independent "
        "applicability, outcomes and exceptions; C03.01/C04.02 stay manual. No shared answer, "
        "name, Signals or humanConfirmed manufactures Verified.",
        "controls": [
            "ALZ-6cc0ea22-42bb-441e-a345-804ab0a09666",
            "ALZ-250d81ce-8bbe-4f85-9051-6a18a8221e50",
            "ALZ-19ca3f89-397d-44b1-b5b6-5e18661372ac",
            "ALZ-4c27d42e-8bba-4c75-9155-9ab9153e8908",
            "ALZ-914b8cb7-c2f6-40fa-ae18-81c049e0cb5a",
            "ALZ-51a1e9e9-a49a-40b2-87b9-ff753bc6de86",
            "ALZ-a89153d8-18b2-4caf-bc19-850fc8fba00f",
        ],
    },
    "platform-health-alerts-log-boundaries-redundancy": {
        "question": "Decide each of the nine monitoring recommendations independently "
        "from attributable "
        "redacted evidence. Reconcile separate Service Health service/region/event populations "
        "and Resource Health resource/status/transition/reason populations, including clouds, "
        "tenant preview versus subscription scope, original-time events and accountable response. "
        "Verify directly attached, enabled Global action groups for applicable Service Health "
        "alerts; receiver counts and configuration do not verify contacts, current email OTP, "
        "delivery, acknowledgement or escalation. Review every Azure-born raw-log export route "
        "and on-premises boundary, allowing critical-alert integration only as the immutable "
        "guidance describes; Sentinel onboarding and workspace location cannot prove no export. "
        "Demonstrate actual Azure Monitor Logs ingestion and useful insight/report usage, "
        "independently of metrics or workspace existence. F01.14 is conditional legacy wording: "
        "WAD/LAD retired March 31, 2026; record applicability, existing shared-storage "
        "boundaries, AMA/DCR destination-specific migration, parity and cutover without "
        "recommending new legacy deployments or treating boot diagnostics as the extension. "
        "Review operational metric, activity and log-query rule criteria, data arrival, enabled "
        "configuration, actions and actual end-to-end response separately. Supply the approved "
        "business monitoring requirements, owners, measurable "
        "health/availability/performance/security/retention/residency objectives and justified "
        "exceptions; never invent an SLA or threshold. For AMBA, bind the actual reviewed "
        "origin/version to complete intended platform populations, "
        "initiatives/assignments/parameters/exclusions, brownfield remediation and tests; generic "
        "Policy references prove none. For storage, assess exact SKU plus kind/service/region "
        "support, zone versus asynchronous geo protection, read access, "
        "conversions/synchronization, RPO/RTO, failover and residency with accountable "
        "requirements and exceptions. No probes, queries, deployments, contact tests, log/query "
        "contents, recipient addresses, phones, webhook URLs, keys, billing or personal identity "
        "payloads. Signals and human confirmations never manufacture Verified.",
        "controls": [
            "ALZ-e5695f22-23ac-4e8c-a123-08ca5017f154",
            "ALZ-d5f345bf-97ab-41a7-819c-6104baa7d48c",
            "ALZ-e3ab3693-829e-47e3-8618-3687a0477a20",
            "ALZ-6944008b-e7d7-4e48-9327-6d8bdc055bcf",
            "ALZ-619e8a13-f988-4795-85d6-26886d70ba6c",
            "ALZ-97be9951-9048-4384-9c98-6cb2913156a1",
            "ALZ-859c3900-4514-41eb-b010-475d695abd74",
            "ALZ-aa45be6a-8f2d-4896-b0e3-775e6e94e610",
            "ALZ-0d83fd81-952c-4d47-a6cb-3a930925ef2e",
        ],
    },
    "hub-spoke-route-server-monitoring": {
        "question": "Provide ten independently attributable original-time decisions and "
        "exceptions, "
        "not one shared approval. D01.01: identify the approved internal/external "
        "application-delivery standard, workload-owned spoke ingress, regional Application "
        "Gateway v2/WAF versus global Front Door/WAF and origin restriction, including justified "
        "protocol/partner alternatives. D01.02: explicitly designate hubs/spokes and justify "
        "traditional topology against flexibility, traffic/isolation/transit and managed "
        "alternatives; names and peering count do not prove purpose. D01.03: identify required "
        "regions and complete regional connectivity/DNS/identity/management readiness, physical "
        "failure domains and exercised DR; location labels are not readiness. D01.04: bind the "
        "designated hub to required shared ER/VPN/firewall or supported partner NVA and "
        "conditional DNS services, ownership and effective inspection; do not centralize shared "
        "L7 workload ingress. D01.06: if partner technology applies, identify exact "
        "vendor/version/supported design and evidence for HA, convergence, symmetry/SNAT, "
        "performance and Azure compatibility; generic Azure patterns are not vendor approval. "
        "D01.07: determine whether ER/S2S VPN transit is actually required, establish Route Server "
        "VNet attachment and explicit branch exchange, same-VNet gateways and active-active VPN "
        "ASN65515/route-based non-Basic requirements; VPN BGP is not required, P2S and ER-to-ER "
        "transit are excluded, effective routes/failover need separate evidence. D01.08: "
        "acknowledge immutable /27 wording versus current linked /26-or-larger quickstart and "
        "older provider /27 guidance; approve a dedicated RouteServerSubnet with current "
        "source-qualified capacity and NSG/UDR restrictions, not a name-only check. D01.09: "
        "designate actual regional hubs and approve both directional global peerings/alternative "
        "interregional design, nontransitivity, Basic Load Balancer restrictions and required "
        "inspection without unintended bypass; unequal regions do not prove global hub transit. "
        "D01.10: show actual Network Insights topology/health/metrics visibility, required "
        "connectivity/traffic/alerts, ingestion/freshness, ownership and response with redacted "
        "evidence; built-in views need no configuration and no test/probe is authorized here. "
        "D01.11: reconcile immutable400/500/1000 wording with current650 peerings/VNet and "
        "source-specific Route Server/ER direction/family/SKU limits; establish authorized current "
        "quotas and complete regional spokes/peerings/advertised-prefix populations, summarization "
        "and growth/exception plan, rather than counting selected records.",
        "controls": [
            "ALZ-373f482f-3e39-4d39-8aa4-7e566f6082b6",
            "ALZ-e8bbac75-7155-49ab-a153-e8908ae28c84",
            "ALZ-7bc1c396-2461-4698-b57f-30ca69525252",
            "ALZ-7dd61623-a364-4a90-9eca-e48ebd54cd7d",
            "ALZ-e2e8abac-3571-4559-ab91-53e89f89dc7b",
            "ALZ-ce463dbb-bc8a-4c2a-aebc-92a43da1dae2",
            "ALZ-91b9d7d5-91e1-4dcb-8f1f-fa7e465646cc",
            "ALZ-cc881471-607c-41cc-a0e6-14658dd558f9",
            "ALZ-4722d929-c1b1-4cd6-81f5-4b29bade39ad",
            "ALZ-0e7c28ec-9366-4572-83b0-f4664b1d944a",
        ],
    },
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
