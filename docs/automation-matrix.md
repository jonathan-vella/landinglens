# Accepted release automation matrix

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
that frozen artifact and refuses a changed historical meaning. The current
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
