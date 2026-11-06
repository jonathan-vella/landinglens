# Accepted release automation matrix

Local triage routes shared tier/severity evidence and explicit bound reviews,
not new predicates. Bulk/interview saves validate every selected outcome before
one immutable revision; unknown/pending decisions stay in the queue. Active
human confirmation does not rewrite automated technical evidence. Resume verifies
saved core hashes/invocation and rechecks freshness without recollection.

Summary-first HTML and text-only CSV/XLSX trackers share the sanitised assessment
model and add no predicates. Heat-map values are labelled outcome-instance counts,
not maturity scores. Tracker formula-like text is escaped; no spreadsheet
formulas/macros/external links are emitted. Source/version notes and minimisation
retain the evidence boundary without a new dependency or calculation engine.

Advisory SARIF and PR-summary outputs project the same outcomes/tiers/coverage;
they add no predicates. Unknown/manual Signals do not turn into passing scan
results. Source-file locations require an explicit base and real contained
paths; line numbers are never guessed. CI examples never gate on estate findings.

Source-update candidates do not change this accepted matrix. The extended
maintainer poll classifies only demonstrable HTTPS link/training edits as safe;
ambiguous wording/meaning/severity/query/external-target changes require review.
New items need decisions and removed items remain retired. Installed catalog
replacement and new predicate acceptance are never polling side effects.
Workflow PR/auto-merge operations remain subject to actual settings/checks/head
gates and retain artifacts/generated PR body when blocked.

Terraform assessment now recommends separately supplied plan JSON, with raw
source/snapshot analysis retained as the supported fallback. No predicate,
version, unknown handling or source/identity/sensitivity requirement changes.
The [ADR](planning/plan.md#adr-prefer-supplied-plan-json-freeze-interpreter-expansion)
limits interpreter expansion to bug fixes or explicit reviewed cohort needs.

## Evidence crosswalk foundation

Current successor `2026-11-06.8` retains all 255 entries: 10 automated, 202 assisted
and 43 manual. Crosswalk `2026-11-06.8` rebinds the unchanged 51-control,
53-association mapping to this exact catalog, without new external equivalence.
Exact predecessor `.6.7` is frozen; source-matrix acceptance alone is not delivery.
The history below remains version-specific.

### Cohort 12: DR addressing, DNS and Bastion

The [ten-GUID matrix](../references/recommendation-batches/batch-12.json) and
[43 source captures](../references/recommendation-batches/batch-12-sources.json)
precede `.6.8`. Eight useful assisted workflows and manual D03.08/D03.10 retain
their exact meanings. All earlier catalog/crosswalk bytes and own receipts remain
unchanged. Ten scope/content/expiry-bound decisions stay blank.

| Recommendation | Bounded preparation and necessary decision |
|---|---|
| D03.04 | Reused supplied IPv4/RFC1918/overlap summaries; complete production/DR populations and approved whole-subnet IP-retention exceptions need evidence |
| D03.05 | Standard/tier/allocation/version/region and reused zones; empty zones can now be redundant, but region/API/service and backend resilience need review |
| D03.06 | Zone identity, typed VNet links, completion/policy and minimized DNS-server count; delegation and actual default/custom resolution remain unverified |
| D03.07 | Resolver/VNet/endpoint/ruleset links, allocation, rule/target shape and delegated-subnet range subchecks; authority, regional limits, exclusivity and loop-free both-direction resolution need evidence |
| D03.08 | Manual workload/vendor DNS suitability, not workload inference from names or settings |
| D03.09 | Explicit VM-primary-NIC registration flag; one registration zone per VNet and independent non-VM/PTR lifecycles remain conditional |
| D03.10 | Manual service-specific multi-region/failover DNS plan, including ownership, updates, TTL/cache and rollback |
| D03.11 | Actual UDP SOURCE port 65330 advisory and specific Windows/container exclusion question; no guest probe, OS change or destination-port substitute |
| D05.01 | Bastion SKU/features/scaling and typed subnet/IP/Developer VNet links; approved access, bypass, NSG/route/DNS/audit evidence remains separate |
| D05.02 | Actual host/subnet binding and reused /26-capacity subcheck; Developer, private-only, pre-2021-11-02 /27 and exclusive occupancy need review |

Resolver endpoint subnets require IPv4 /24 through /28 and exclusive delegation;
ruleset links are regional, target order/suffix matching and inbound loops matter,
and Azure-provided DNS cannot be a forwarding target. Missing port is not default
53. New Bastion dual-stack preview wording differs from the IPv4-only FAQ/older
schemas. No DNS record/domain/target IP, ACL address or recording secret is retained.
Configured links, zones, registration or Bastion never establish effective
resolution, security, resilience or workload suitability.

### Cohort 14: ExpressRoute cost, FastPath and gateway resilience

The [nine-GUID matrix](../references/recommendation-batches/batch-14.json) and
[26 source captures](../references/recommendation-batches/batch-14-sources.json)
precede `.6.7`. Exact `.6.6` catalog/crosswalk bytes and every prior receipt are
preserved. All nine remain assisted; no setting can establish the whole recommendation.

| Recommendation | Bounded preparation and necessary decision |
|---|---|
| D06.04 | Circuit tier/family and provider Mbps versus Direct Gbps; actual outbound demand, negotiated prices and total costs justify unlimited billing |
| D06.05 | Positive circuit/connection/port bindings; actual peering location must support all required Local workload and recovery regions |
| D06.06 | Gateway SKU/type and explicit Standard public-IP/zone context; AZ-capable is not deployed zone-redundant placement |
| D06.07 | Direct port/circuit bandwidth and binding; actual throughput/latency or dedicated-port demand justifies Direct, not configured capacity |
| D06.08 | Separate bypass/Private Link flags, literal gateway-SKU/minimum-scale prerequisites and published Direct-port IP limit; actual topology, enrollment, supported traffic and fallback remain separate |
| D06.09 | VPN type/SKU, active-active and public-IP zone facts; actual supported regional zone-redundant placement needs evidence |
| D06.10 | IPsec/local-gateway bindings and BGP/active-active context; real independent on-premises appliances and failover cannot be counted from Azure declarations |
| D06.11 | Direct port billing is distinct from circuit family; review Local reach and full demand-dependent cost choices |
| D06.12 | Circuit/port/encapsulation/rate-limit facts; explicit isolation requirements and effective routing domains/shared contention remain human-reviewed |

Current Direct guidance includes conditional 400-Gbps offerings beyond older
10/100-Gbps summaries. FastPath provider circuits have narrower IPv4/hub support;
Direct peering/UDR/IPv6 and enrolled limited-GA Private Link have distinct limits.
ErGwScale requires configured minimum ten units for the FastPath subcheck,
supports bounds 1-40, and recommends fixed scaling for Private Link. Its current
source lists regional exclusions and does not support IPsec over ExpressRoute.
ARM supports these scale fields; pinned AzureRM 4.50.0 does not, and stays unknown.
Configured bounds, published port IP limits and bypass flags never prove actual
scale, route population, eligibility, latency or achieved throughput.

All adapters, partial subchecks, review contexts, tiers, reports, sessions and
packaged replay use the existing engine. Source-bound interviews leave nine
independent decisions blank. No prices, traffic, health, live regions, appliance
inventory, routing/packet probes, scanner/query execution or new permissions are used.

### Cohort 22: sovereign keys, auditing and workload protection

The [eight-GUID matrix](../references/recommendation-batches/batch-22.json) and
[25 source captures](../references/recommendation-batches/batch-22-sources.json)
precede `.6.6`. Exact `.6.5` catalog/crosswalk bytes are frozen; all eight remain
assisted. No whole recommendation follows from configuration alone.

| Recommendation | Bounded preparation and necessary decision |
|---|---|
| G02.13 | Explicit HSM network/purge settings; reconcile key versus secret capability, real CMK adoption, external KEK custody and sovereign requirements |
| G03.01 | Specific attributable Entra access-audit report, population, period and follow-up; Azure diagnostics are not a directory report |
| G03.02 | Explicit activity category/group enabled flags and typed destinations/target; verify actual ingestion/export and table/storage retention against approved requirements |
| G03.03 | CloudPosture tier/extension context; paid CSPM versus Foundational and actual resource/component coverage remain distinct |
| G03.04 | VirtualMachines tier/P1/P2 and scope context; reconcile server population, overrides, onboarding and effective protection |
| G03.05 | Distinct allowlisted workload plan/subplan/extension records; no record count establishes all-subscription protection |
| G03.06 | Specific endpoint enforcement/health review with optional server-plan context; installed agent/antivirus or pricing never proves enforcement |
| G03.07 | Explicit Linux/Windows assessment/patch mode and agent boolean; verify successful Update Manager assessments, baseline drift and accountable monitoring |

Current sovereign guidance distinguishes Managed HSM cryptographic keys from
secrets/credentials, which Managed HSM does not support. External-key management
is GA, while Private Link integration is preview; customer-operated HSM/proxy
availability and SLA responsibilities require explicit review. Legacy Entra and
Security Center URLs resolve to current monitoring/Defender guidance. Current
patch recommendations use Update Manager, not deprecated MMA collection.

All paths share the existing evaluator, context, tiers, reports, reviews and replay.
The new eight-GUID interview retains separate blank attributable decisions and
scope-bound requirements hashes. Existing interview meanings and all historical
controls remain unchanged. Additional pricing/HSM/VM ARM versions are planned-only,
not new Collector calls. Missing/denied/partial/stale/malformed/ambiguous/over-bound
evidence stays visible; no private audit records, credentials, key/security-domain
material, invented retention/cost/health threshold or live query is introduced.

### Cohort 13: inbound protection, outbound migration and hybrid connectivity

The [ten-GUID matrix](../references/recommendation-batches/batch-13.json) and
[42 actual source captures](../references/recommendation-batches/batch-13-sources.json)
precede `.6.5`. Exact delivered `.6.3` catalog/crosswalk bytes are frozen; `.6.4`
is not used. No new whole predicate is justified from the permitted inputs:
nine useful partial workflows remain assisted and D05.07 remains inherently manual.

| Recommendation | Preparation and explicit decision boundary |
|---|---|
| D05.03 | WAF enabled/mode/SKU and bounded custom/managed counts, typed policy/domain associations and explicit all-path marker; not global coverage or effective actions |
| D05.04 | Gateway/WAF/subnet links, minimized FDID condition shapes and source-tag/port summaries; require both backend filtering and exact-profile header rejection, including alternate paths |
| D05.05 | Gateway subnet and configured backend counts; require actual workload/VNet placement and accepted ownership, not hostnames or entry-count inference |
| D05.06 | Public-IP protection mode/plan and positive NIC links; inherited mode, service support and complete operational coverage remain separate |
| D05.07 | Explicit default-outbound flag and existing NAT/route links support an accountable migration plan; no configuration flag authenticates an approved strategy |
| D05.08 (`b1c82a3f...`) | Three exact DDoS category flags and typed workspace/storage destination/target; not all protected IPs or arriving/retained logs |
| D05.08 (`3c5a808d...`) | Exact NIC-deny source identity, existing minimized saved policy/exemption context and positive NIC/VM/IP links; not actual enforcement or approved exceptions |
| D06.01 | Gateway/circuit/local-gateway connection kinds/links; actual maintained primary/backup topology and workload suitability need evidence |
| D06.02 | Strict explicit connection weight 0..32000 and BGP context; direction, prefix specificity, local preference and actual selected routes stay distinct |
| D06.03 | Explicit supported gateway SKU/generation; require measured workload demand, performance and failure headroom rather than benchmark/SKU inference |

Current Learn revision `e8c3f40845eb970c6a231bf67fbdd8132fe63e79` describes
APIs released after March 31, 2026 defaulting **new VNets** to private subnets,
with earlier API and existing-VNet behavior unchanged. The frozen checklist's
September 30, 2025 wording is preserved, not asserted as current guidance.
The announcement link returned a dynamic shell without its timeline; it is not
independent date proof. Migration planning must reconcile deallocation,
dependencies, delegated/managed-subnet limits and Internet-next-hop exceptions;
no change is executed.

Pinned ALZ corp includes `Deny-Public-IP-On-NIC`, built-in `83a86a26` version
1.0.0 with fixed deny on the NIC public-IP alias. The separate deny-all-public-IP
assignment is not equivalent. Source query hashes and template assignments do not
create new crosswalk equivalence or actual enforcement claims.
S2S backup guidance excludes latency-sensitive/mission-critical/bandwidth-intensive
workloads; both-direction routing and maintained failover must be evidenced.
Current scalable ExpressRoute SKU is outside the pinned provider's SKU support.

All supported planned/raw/supplied-module/ARM/existing no-restore Bicep and
saved/injected details feed the same typed evaluator/review/tier/replay paths.
Actual diagnostic extension scopes are resolved within the selected boundary;
missing/wrong-type/version/sensitive/over-bound values stay unknown.
Header values, hosts, private/backend/peer addresses, certificates and keys are
withheld. The ten-GUID interview keeps decisions blank and binds requirements
to the explicit scope as well as catalog/content/time. No traffic/health/DNS/
encryption/log query, policy trigger, IaC execution or new access is performed.

### Cohort 19: service endpoints, subnet capacity and segmentation

The [source-backed matrix](../references/recommendation-batches/batch-19.json)
and [24 source captures](../references/recommendation-batches/batch-19-sources.json)
identify each canonical GUID. Reinspection on 2026-11-06 confirmed the same
reviewed revisions; dynamic Learn HTML hashes can differ without a source revision
change. The original captured hashes/times remain intact.

| Recommendation | Accepted scope |
|---|---|
| D08.04 | Assisted explicit endpoint count, network-identifier references and subnet policy enum; not approved endpoint intent or service-side access |
| D08.05 | Assisted minimized rule kinds/actions/FQDN and IPv4 counts; the relative guidance URL was resolved; no DNS, traffic or exfiltration verdict |
| D09.01 | Assisted exact gateway/subnet link and minimum-/27 IPv4-capacity subcheck; conditional /26 ExpressRoute capacity stays human-reviewed |
| D09.02 | Assisted separate custom/default priorities and VirtualNetwork indicators; a tag or default allow rule is not isolation |
| D09.03 | Assisted subnet guardrail/ownership questions; PaaS subnet delegation is not organizational responsibility |
| D09.04 | Assisted unique known subnet-to-NSG links and bounded rules; no effective segmentation claim |
| D09.05 | Assisted canonical typed ASG references; no NIC membership or enforcement claim |
| D09.06 | Assisted explicit flow-log/analytics configuration; no ingestion, supported-population or operational-use claim |
| D09.07 | Automated observed-only complete custom NSG rule count, pass <=900 and fail >900; defaults excluded and no service-quota/headroom claim |

Supported raw/supplied-module Terraform and optional plans use pinned AzureRM
4.50.0; declared ARM/existing no-restore Bicep use reviewed 2024-05-01 APIs.
Those declared/planned modes cannot prove complete NSG rule populations. Saved
observed and injected scoped-detail evidence exercise the count; all missing,
wrong-type, duplicate, transient, partial, denied, stale and over-bound cases
remain explicit. Replay retains original times. Old catalog meanings and the
fixed 251-GUID membership are unchanged. #90 passed normal exact-head CI/compiler
gates and merged; `deliveries.19` records each of its nine GUIDs' actual acceptance.

### Cohort 11: routing, peering and transport resilience

The [ten-GUID matrix](../references/recommendation-batches/batch-11.json)
and [21 actual source captures](../references/recommendation-batches/batch-11-sources.json)
precede `2026-11-06.2`. D01.12 evaluates only a complete successful observed
custom-route array against the literal <=400 checklist target, not effective
BGP/system routing or today's quota options. Declared/raw/planned child populations
stay unknown. D01.13 evaluates explicit per-direction `allowVirtualNetworkAccess`
only; no provider/portal default, reciprocal peering, transit or reachability is
inferred. All earlier predicates and exact delivered catalog bytes are unchanged.

Seven specific assisted workflows prepare frontend-zone/public-IP and supplied
backend-entry context, per-link MACsec cipher/SCI fields, IPsec private-IP intent
and gateway IDs, and explicit IPv4 address-space subchecks. D02.01 remains manual:
no setting establishes an approved business/security encryption requirement.
Backend entries are not distinct healthy instances; a Standard SKU or frontend
is not an SLA or backend/region resilience. MACsec config is not negotiated
edge-to-MSEE encryption or end-to-end privacy; a private-IP IPsec connection is
not proof that either direction prefers the encrypted path. Keys, secret
identifiers, tunnel addresses and raw destinations are withheld.

RFC1918 subchecks use exactly 10/8, 172.16/12 and 192.168/16, not the broader
`is_private` classification. Local pairwise prefix checks do not prove global
Azure/on-premises nonoverlap or appropriate capacity. IPv6/mixed, unresolved and
over-bound lists remain unknown; workload/IPAM/growth evidence stays explicit.
No traffic, encryption, key, health, DNS, on-premises or external IPAM query occurs.

### Cohort 04: access, managed identity and Entra controls

The [eight-GUID matrix](../references/recommendation-batches/batch-04.json) and
[14 actual sources](../references/recommendation-batches/batch-04-sources.json)
resolve legacy Azure AD/operations redirects to current Entra/CAF guidance.
Both B03.02 GUIDs remain distinct: managed-identity adoption and work/school
account provenance are different recommendations. All eight remain assisted;
no directory-policy enforcement predicate is invented.

Supported storage and ExpressRoute Direct port identity blocks expose only
explicit identity type and validated user-assigned binding count. IDs, tenant/
principal identifiers, keys and credentials are withheld. Attached configuration
is not actual application credential usage; managed identities themselves use
special service principals. Role assignments expose only explicit principal-type
enums and canonical role-definition IDs. Assignment presence/type/scope is not
membership, inherited/additive/deny/conditional effective access or agreed ownership.

The source-specific access-operating-model interview collects one redacted
narrative with eight separate explicit scope/content/expiry-bound decisions.
It distinguishes account origin from email/userType, group source of authority
from membership, CA report-only/exclusions from enforcement, MFA registration
from requirements/coverage, platform/workload responsibilities from assignment
scope, and PIM eligible/active/permanent grants from zero standing access.
Emergency-access exceptions remain explicit. Answers alone never pass a control,
and no human attestation becomes Verified machine evidence. No directory,
Graph, sign-in/audit-log, policy evaluation, PIM activation or authentication
operation occurs.

Crosswalk `2026-11-05.1` binds catalog `2026-11-05.3` without changing its
7 automated / 205 assisted / 43 manual dispositions or the fixed 251-target
ledger. All 255 GUIDs are represented: 51 have 53 associations; 204 are explicitly
unmapped. Forty-nine associations are related static query hashes, not an
execution allowlist or new predicates.

Actual reviewed sources are in
[`references/crosswalk/sources.json`](../references/crosswalk/sources.json).
ALZ Library `platform/alz/2026.10.0` pins `4eae565287844360a61545f9799400431adb6d0a`.
Its `Deny-Storage-http` assignment points to built-in
`404c3081-a854-4457-ae30-26a93ef643f9`, version `2.*.*`, with Deny effect.
The actual built-in source at `f096d8de10fb25e71dd7f82b78ded110ec711d73`
and PSRule `Azure.Storage.SecureTransfer` at tag `v1.48.0-B0228`
use API-dependent missing-property defaults. Their G04.01 mappings are **partial**,
not equivalent to LandingLens's explicit boolean predicate.

PSRule `Azure.Storage.ContainerSoftDelete` has additional days and population/
child-selection conditions; its G04.02 mapping is partial too. All four
nonquery associations require human interpretation of supported scope and
actual evidence. No assignment, scanner result or query hash changes a technical
outcome. Seven source captures retain immutable revisions, actual hashes,
retrieval times, reuse metadata and findings. The source builder is offline
unless its explicit maintainer capture flag is supplied.

The crosswalk CLI and strict contract are documented in
[contracts](contracts.md#evidence-crosswalk-version-10). This is LL-27's
foundation, not delivery of tiers, policy/scanner ingestion or query execution.

## Explicit evidence tier projection

LL-28 adds opt-in assessment 1.2 without promoting a control or changing any
frozen catalog. Verified means current sufficient accepted-predicate evidence,
including fail; Signal is machine evidence awaiting explicit confirmation; Needs
decision has no usable machine evidence; manual is separate. Mixed unresolved
targets never count as wholly Verified. Counts are control-level across modes,
not resource counts, and sum to the complete 255-GUID inventory.

Existing reviewed typed preparation can establish a Signal without establishing
the whole recommendation. Stale/denied/unsupported facts, arbitrary source
metadata, assignments, empty scanner/query outputs and accepted exceptions never
establish a pass. Review outcome, technical result and evidence tier are separate.
The [1.2 contract](contracts.md#assessment-version-12-evidence-tiers) defines
validation, historical compatibility, comparison and replay. No new Azure
operation, ingestion adapter or owner decision is added by tier projection.

## Source-backed priority and applicability suggestions

Metadata-only catalog `2026-11-05.5` carries 71 High / 158 Medium / 26 Low values
from the exact reviewed checklist. No automation classifications or original
predicate hashes change. The `.3` catalog is frozen byte-for-byte; current
crosswalk `.2` binds `.5` with the same 51/53 association coverage.

Actual pinned ALZ Library architecture and `landing_zones` archetype captures
are recorded in packaged `catalog-priorities.json`, including hashes, retrieval
times and MIT reuse metadata. Only the exact `landing_zones` ->
`Deny-Storage-http` -> G04.01 association supports a suggestion. The library's
template IDs are not discovered tenant identities. A saved explicit binding must
match the assessment's exact management group; it is a producer assertion, not
proof that the deployed topology equals the template.

Suggestions always require reviewer confirmation. Other archetype mappings are
unreviewed, and no parent inheritance or absence-based exclusion is inferred.
Stale/missing/foreign/conflicting bindings cannot set applicability or outcomes.
This is offline/saved evidence preparation, not new Azure reads or deployment.

## Policy evaluation Signals

The reviewed direct built-in storage mapping can prepare original-time Compliant/
NonCompliant policy observations as **Signals only** under explicit assessment
1.2. It never replaces G04.01's accepted explicit configuration predicate or
changes any automation count. Raw saved exports and the existing scoped
collector's normalised policy arrays share one bounded projection.

Canonical in-scope resource/assignment identities, a unique direct definition
match, explicit exclusions and current original evaluation/collection times are
required for a usable Signal. Conflicts, missing contexts, stale/future/unresolved
times, unsupported states and indirect initiatives remain visible but unusable.
Assignment-only/empty results cannot pass a recommendation. Parameters/effects/
exemption applicability and population completeness remain human review.
Comparison expires policy-only evidence at evaluation age; review/replay/privacy
retain the same boundary. See [contract](contracts.md#policy-export-and-signals).

## Saved scanner Signals

Saved detailed PSRule JSON and SARIF 2.1.0 are projected through the reviewed
crosswalk, never imported as predicates. The seed supports the two reviewed
storage PSRule rules with partial mappings. Generic SARIF from other namespaces
is accepted as explicitly unmapped evidence; matching text does not grant PSRule
provenance or whole-checklist equivalence. Exact caller-supplied result-index/
ARM-ID bindings are required for usable Signals.

Known Pass/Fail results with supported producer, current original time and explicit
complete-run context can supply Signals, not outcomes. Missing/unknown/error/
skipped/suppressed/partial/conflicted records remain visible. Empty output
establishes no coverage. Source metadata, supported shapes and exclusions are
documented in the [scanner contract](contracts.md#saved-scanner-evidence).
No scanner execution, external artifact fetch, new dependency or Azure call occurs.

## Reviewed upstream-query Signal allowlist

The 49-query audit remains static source evidence. Its two direct local
D07.06/D07.07 `id, compliant` observations are now allowlisted for explicit scoped
ARG execution under D5. Their original query bytes and hashes remain unchanged;
all 47 other entries have exact visible exclusion rationales. This does not
promote any audited candidate or bypass SKU, inheritance, missing-value or
configuration requirements in the accepted evaluator.

Only exact allowlisted text and explicit subscription request bodies are accepted.
Typed booleans are reported observations, not checklist outcomes. Null, malformed,
partial, conflicting, stale, denied and empty populations stay unresolved.
No live runtime is claimed; injected paging/retry/scope/error/privacy/replay
and installed saved-evidence workflows are the acceptance evidence.

The owner explicitly delegated LL-04 acceptance to Autopilot in the attached
execution authorization. This replaces the original human-interruption gate,
not the coverage safeguards. The accepted baseline is two explicit property
checks below, plus visibility and disposition for **all 255** reviewed checklist
items across the eight verified CAF design areas. The baseline cannot silently
shrink when adapters or catalog versions change.

The actual control-source review, retrieved bytes' checksums, timestamps, exact
AzureRM revision and reuse notes are frozen in
`references/2026-11-04-controls/manifest.json`. The reviewed checklist remains
`references/2026-11-04` (version 2026-11-04.1). Local IDs are `ALZ-` plus the original GUID; display IDs
are labels, not unique keys.

| Checklist item / GUID | Area and applicability | Automated evidence | Required positive / negative / unknown fixtures |
|---|---|---|---|
| G04.01 / b03ed428-4617-4067-a787-85468b9ccf3f | Security; platform and application storage accounts | Explicit `properties.supportsHttpsTrafficOnly`; raw AzureRM **4.50.0** `https_traffic_only_enabled`; compiled Bicep/direct ARM **2023-05-01**; saved/collected configuration | Explicit true / false in each mode; omitted or unresolved setting unknown; missing supplied security module unknown; secure parameter withheld |
| D07.18 / 94f3eede-9aa3-4088-92a3-bb9a56509fad | Network topology and connectivity; platform and application firewall policies | Explicit `properties.dnsSettings.enableProxy`; raw AzureRM **4.50.0** `dns.proxy_enabled`; compiled Bicep/direct ARM **2024-05-01**; saved/collected configuration | Explicit true / false in each mode; absent DNS configuration and unresolved inheritance unknown |

These are configuration checks, **not** Microsoft certification, runtime tests,
or proof that client DNS traffic actually traverses a firewall. Classic
standalone firewall DNS settings, parent-policy effective DNS resolution, Azure
Files SMB/NFS encryption and omitted provider/API defaults are outside these
automated predicates. Unsupported versions remain unknown. The storage REST
setting does not establish Azure Files encryption effectiveness.

## Explicitly accepted uncovered design areas

| Design area | Accepted release disposition and reason |
|---|---|
| Azure billing and Active Directory tenant | Assisted/manual: billing/tenant relationships and authorization need separately scoped evidence, not resource-name inference. The checklist's newer billing/Entra label remains recorded separately. |
| Identity and access management | Assisted/manual: no Microsoft Graph collection or identity-effectiveness inference is authorized or implemented by the baseline. |
| Resource organization | Assisted/manual: organization intent and hierarchy suitability need reviewer judgment; a management-group resource alone is not proof. |
| Management | Assisted/manual: workspace existence does not prove operational monitoring, retention intent or incident processes. |
| Governance | Assisted/manual: assignment existence is not compliance; organization intent, exemptions and evaluation results stay separate. |
| Platform automation and DevOps | Assisted/manual: bounded IaC analysis does not prove delivery-process or repository governance effectiveness. |

Every nonautomated item retains its original recommendation, guidance reference,
GUID, display ID, provenance, taxonomy mapping, uncertainty flags and explicit
human-evidence rationale. Applicability labels are conservative review routing,
not verified tenant-specific applicability. No candidate Graph query becomes an
automated rule by import.

## Acceptance evidence and sequencing

LL-04 exercises the storage slice through the common versioned contracts:
module-based raw Terraform with supplied ALZ and security snapshots, pass/fail,
missing modules, current saved observed match/drift, missing-scope
`not_comparable`, complete-only absence, and the same JSON/Markdown/HTML model.
`tests/test_assessment.py` is the slice regression baseline.

`tests/fixtures/slice/controls.bicep` is parameterized for both accepted controls;
`tests/test_matrix.py` exercises explicit true/false fixtures for Bicep, direct
ARM, raw Terraform and observed evidence. `tests/test_workflows.py` adds installed
CLI rendering/comparison, input-binding and partial-evidence cases;
`tests/test_collection.py` uses injected transports only. Actual installed Bicep
compilation is exercised locally without restore; environments without that
tool report explicit skips. These are fixture-based checks only. Live Azure
collection and deployment are neither performed nor claimed.

`test_installed_cli_accepted_matrix_in_each_source_mode` invokes the installed
package outside the checkout for both controls' positive/negative Terraform,
ARM and saved-observed inputs, plus Bicep when an existing compiler is configured.
Each case checks both exact outcomes, all 255 controls, eight design areas and
consistent JSON/Markdown/HTML rendering. Each planned source mode also compares
both canonical identities with saved observed evidence in all three formats.

## Accepted successor matrix: bounded first wave

The original two-control release acceptance above is preserved. Under the
owner's delegated acceptance authority, LL-19 accepts **D07.06 and D07.07 only**
for LL-20 promotion after LL-21 collection evidence. LL-21 is delivered in
PR #36. The packaged successor catalog `2026-11-04.2` implements these predicates
through contract 1.1 and the existing evaluator, with exact reviewed before/after
control hashes. Acceptance and fixture verification are not live verification,
nor evidence that upstream KQL is safe to execute.

[`candidate-audit.json`](../references/2026-11-04-wave1/candidate-audit.json)
classifies every one of the **49** pinned query-bearing GUIDs, records its query
hash, statically inferred output/identity, permission profile, population and
missing-value defects, plus the nonquery G02.03/G04.02/F01.08 candidates.
[`manifest.json`](../references/2026-11-04-wave1/manifest.json) records actual
retrieved Microsoft/API/provider source hashes, revisions, timestamps and reuse
notes. The audit is reproducible with `tools/audit_candidates.py`; only explicit
`--capture-sources` acquires metadata for a new review. No upstream query was
executed or imported as an evaluator.

| Item / GUID | Exact local predicate | Reviewed applicability | Committed modes |
|---|---|---|---|
| D07.06 / e9c8f584-6d5e-473b-8dc5-acc9fbaab4e3 | `threatIntelMode == "Deny"` | Explicit `sku.tier` Standard/Premium; Basic is capability-not-applicable | Raw AzureRM 4.50.0; compiled no-restore Bicep/direct ARM 2024-05-01; optional plan; saved/collected observed |
| D07.07 / b9d0dff5-bdd4-4cd8-88ed-5811610b2b2c | `intrusionDetection.mode == "Deny"` | Explicit Premium; Basic/Standard are capability-not-applicable | Same five modes and exact versions |

AzureRM mappings are explicit `sku`, `threat_intelligence_mode` and exactly one
`intrusion_detection` block's `mode`; optional plan maps the same reviewed
properties with unknown/sensitive masks honored. API enums are exactly
`Alert`, `Deny`, `Off`; SKU enums are exactly `Basic`, `Standard`, `Premium`.
Missing/wrong-type/unsupported values are unknown, never inferred from provider
defaults, a parent policy, firewall names or query coercion.

Positive fixtures require an explicit applicable tier plus Deny; negative
fixtures use Alert and Off. Unknown cases include missing/malformed/unresolved
fields, unsupported versions, stale evidence, inaccessible details and missing
targets under partial inventory. Known properties remain individually assessable
under partial inventory, with incomplete coverage still visible. Normalized
resource errors remain errors. Only explicit unsupported capability tiers, or
a genuinely complete inventory with no targets, establish not-applicability.
Installed CLI cases must cover these outcomes, exact identity match/drift,
and shared JSON/Markdown/HTML rendering in every committed mode.

These are **local configuration** predicates. A child's effective threat-intel/
IDPS mode may inherit a stricter parent; local Alert/Off failure is not proof of
an insecure effective inherited mode. Omitted/inherited-only local values remain
unknown. A Deny flag does not establish firewall attachment, allowlist/bypass or
signature behavior, traffic routing, operational protection or certification.
The first wave does not resolve inheritance or expand to classic firewall fields.

All 255 recommendations and both original predicates remain. No other audited
candidate is committed: arbitrary thresholds, inferred hub/DC names, absent joins
and violation-only query output are not passing evidence. G02.03 needs a compound
vault-state review, G04.02 needs the blob-service child configuration, and F01.08
needs explicit criticality intent plus ancestor locks; separate reviewed tasks/
matrices are required before implementing them.

### Promotion and historical compatibility

The package retains the original catalog as `data/catalog-2026-11-04.1.json`
with its unchanged 1.0 meaning and two predicates; explicit `--catalog FILE`
can select a supplied historical artifact. `tools/build_catalog.py` reconstructs
that frozen artifact and refuses a changed historical meaning. That increment's
catalog has all 255 entries, four automated controls and 251 human-evidence
items. Legacy unbound reviews do not assert outcomes under the new 1.1 catalog;
complete content-bound reviews instead. Different catalog/contract meanings
cannot produce comparison drift.

`tests/test_matrix.py` explicitly retains the historical cross-mode baseline.
`tests/test_control_wave.py` verifies successor typed outcomes, explicit SKU
applicability, missing/stale/partial/error evidence, unsupported mappings,
canonical identity comparison and installed raw Terraform, ARM, optional plan,
saved-observed and actual existing no-restore Bicep workflows. All report formats
retain the same outcomes and narrow local-configuration caveats. Source and
matrix artifacts are packaged and hash-checked. No live-control outcome is
claimed from these tests.

## Fixed-target batch 01: vault and storage protection

The owner delegated source-backed batch acceptance for the fixed 251 starting
GUIDs. The [matrix](../references/recommendation-batches/batch-01.json) records
each exact GUID, intent, classification, source IDs, evidence modes, semantics,
limitations and uncertainty tests. The
[source manifest](../references/recommendation-batches/batch-01-sources.json)
contains actual retrieved hashes/revisions and original factual findings, not
redistributed pages or executed upstream queries.

| Recommendation | Accepted explicit predicate | Modes and material limits |
|---|---|---|
| G02.03 / 2ba52752-6944-4008-ae7d-7e4843276d8b | Same vault's `enableSoftDelete` **and** `enablePurgeProtection` are explicitly true | ARM/existing no-restore Bicep API **2024-11-01**, saved observed and injected scoped ARM GET. Both booleans known: conjunction passes/fails; missing/wrong-type/stale/inaccessible stays unknown. Raw AzureRM **4.50.0** and optional plan expose purge state but not soft-delete state after import/update: unknown, not an assumed creation default. Recovery effectiveness is not tested. |
| G04.02 / 159aac9f-863f-4f48-82cf-00c28fa97a0e | Exact default blob-service child's `containerDeleteRetentionPolicy.enabled` is explicitly true | ARM/existing Bicep and scoped ARM GET API **2023-05-01**, saved observed; AzureRM **4.50.0** raw/optional plan with one explicit retention block and integer days **1-365**. Missing/invalid/default days remain unknown. Blob deletion protection does not substitute for container protection. A known account missing child configuration produces unknown, not N/A. No owner-specific retention threshold or recovery claim. |

G02.01, G02.04, G02.07, G02.08 and G04.03 remain assisted; G02.02 is explicitly
manual because application/environment/regional partitioning and capacity need
intent. All six now have specific redacted evidence requests, human decision
questions, limitations and bounded inventory preparation in templates/editor.
Reviewed local RBAC, public-network/default-ACL and minimum-TLS scalars are
prepared for G02.04, G02.07 and G04.03 respectively, without promoting
least privilege, actual private connectivity or effective policy enforcement.
No secret enumeration, PIM access, DNS/network probe, log query, policy
enforcement interpretation or human approval is inferred. G04.03's supplied
checklist link is a storage protection overview, not sufficient TLS-policy
semantics; the actually inspected TLS-policy guidance supplements it.

Working catalog `2026-11-05.1` has **6 automated / 206 assisted / 43 manual**.
Both `.1` and `.2` historical catalogs and the original four hashes remain.
Compound comparison retains both explicit vault component facts, so two
different failing configurations are not incorrectly labelled a match.
Absent target populations require complete relevant inventory; independent known
facts remain usable during unrelated gaps. Pending delivery evidence is not
live verification or completion of the remaining 243 targets.

## Fixed-target cohort 17: firewall deployment and operations

The [nine-GUID matrix](../references/recommendation-batches/batch-17.json) and
[17 reviewed sources](../references/recommendation-batches/batch-17-sources.json)
support working successor `2026-11-05.2`: **7 automated / 205 assisted / 43 manual**.
The two D07.12 display IDs retain separate original GUIDs.
[#49](https://github.com/jonathan-vella/landinglens/pull/49) merged after all eight
CI checks passed and all four compiler artifacts reported exercised.

D07.05 checks the deployed `Microsoft.Network/azureFirewalls` **Premium** tier,
not a Firewall Policy. ARM/existing no-restore Bicep/saved observed/detail GET
use **2024-05-01**; raw Terraform and optional plan use explicit AzureRM
**4.50.0**. Premium passes, Basic/Standard fail, unsupported/missing/wrong types
remain unknown. Feature enablement, traffic inspection and capacity are not proven.

The other eight recommendations remain assisted with specific review questions
and typed original-time facts. Unique canonical firewall-to-subnet references
can expose supplied IPv4 prefix capacity: /24, /25 and /26 have at least /26
capacity; /27 does not. This deliberately does not fail a valid larger subnet
because the checklist says /26. Invalid, IPv6, empty, conflicting or IPAM-only
prefix evidence is unknown. This partial capacity result never clears D07.11.

Direct classic DNAT sources can be checked for `*`, `any`, `0.0.0.0/0` or the
full IPv4 range, including multiple supplied prefixes/ranges that together
cover all IPv4 addresses within one rule. This does not resolve IP Groups, inherited/effective policy,
application/network rules or coverage, and never clears D07.13. Typed diagnostic
target/workspace/destination fields do not establish categories or ingestion.
Association alone does not establish migration, effective routing, rule ownership,
deduplication, SNAT demand or failover. No additional live access, diagnostic
enumeration, log query, packet test, module acquisition or human decision occurs.

## Fixed-target cohort 18: resilience and private connectivity

The [nine-GUID matrix](../references/recommendation-batches/batch-18.json) and
[18 actual source captures](../references/recommendation-batches/batch-18-sources.json)
support working successor `2026-11-05.3`, still **7 automated / 205 assisted /
43 manual**. All nine remain assisted. [#51](https://github.com/jonathan-vella/landinglens/pull/51)
merged after all eight checks passed and all four compiler artifacts reported
exercised; per-GUID receipts retain fixture/injected and installed-CLI scope.

D07.15-.17 prepare minimal application-rule action, explicit TLS boolean and
supplied category-label count with specific trust/coverage/gateway flow questions.
Labels, destinations, headers, secret/certificate material and connection messages
are withheld. Current Learn describes Standard/Premium category support whereas
pinned AzureRM 4.50.0 describes Premium requirements; neither statement establishes
universal applicability or effective categorization. D07.20 asks for attributable
versioned artifacts and restore-test evidence; minimized assessor replay is not
a restorable firewall backup.

D07.21 deliberately has **no configured-zone-count predicate**. Microsoft's
2026-11-04 guidance recommends omitting explicit zones for new eligible-region
deployments; migrated backend redundancy may not appear in ARM/JSON/ARG.
Empty, single or multiple configured zones cannot determine redundancy or an SLA.
The workflow requests attributable platform/region evidence without recommending
unnecessary redeployment or treating a region list as migration proof.

D07.22 prepares explicit VNet DDoS flag/plan references and unique positive
firewall-subnet-VNet joins, with a specific Virtual WAN applicability question.
D07.23 requests per-service injected PaaS control-plane requirements and exposes
supplied NSG/route-table references, not a generic default-route verdict.
D08.02-.03 prepare endpoint target/subnet/explicit ARM connection state and ask
about service subresources, DNS/public access, ExpressRoute private peering and
return routing. Terraform intent/IP cannot establish approval; Approved cannot
establish working private connectivity. Aliases and missing joins remain unknown.

All new mappings use ARM **2024-05-01** and AzureRM **4.50.0**; raw supplied-module
Terraform, optional plan, ARM/existing no-restore Bicep, saved observed and injected
detail transports share the bounded preparation vocabulary. No effective-policy
expansion, parent traversal, new live reads, connectivity test or human decision
is added. All 255 entries, the fixed 251 targets and exact historical catalog bytes
remain preserved.
