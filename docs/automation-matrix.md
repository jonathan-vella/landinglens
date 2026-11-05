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
