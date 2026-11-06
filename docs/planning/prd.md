# LandingLens product requirements

## Next increment: assessor efficiency

Owner-authorised on 2026-11-05, tracked in
[#53](https://github.com/jonathan-vella/landinglens/issues/53). Reduce assessor
effort by reusing attributable evidence and prioritising explicit human decisions,
not by counting Signals as passes. The
[execution plan](plan.md#assessor-efficiency-increment) defines acceptance,
dependencies and delivery gates.

Verified starting point: `main` at `ce59bce5953e4e9cdb7122072324a9a2cc0928cb`,
catalog `2026-11-05.3`, 255 entries: 7 automated, 205 assisted, 43 manual.
#51 is merged and #50 closed, contrary to the request's expected pending state.
The fixed ledger has 26 merged and 225 pending targets. Cohort 19 work for #52
is preserved in a named Git stash, not accepted or included in this increment's
planning PR. Its draft `.4` catalog is not the delivered baseline.

All independent efficiency implementation and reconciliation are merged through
#83. Catalog `.5` retains 255 GUIDs with 7 automated / 205 assisted / 43 manual
recommendations. Crosswalk `.2` has 51 mapped controls and 53 partial/related
associations. Evidence-specific authored integration tiers are 7 Verified /
8 Signal / 197 Needs decision / 43 manual, not live estate counts.

Latest local and exact installed-wheel suites ran 292 tests: 291 passed and one
Windows privilege case skipped. All eight final platform checks and four
downloaded compiler artifacts passed/exercised. Actual authored browser and native
workbook acceptance passed; no new live Azure/query compilation/scanner run is
claimed. The earlier Windows short-path CI defect and corrected rerun remain
recorded without weakening tests.

Source polling and accepted catalog/index/notice Release assets are demonstrated.
The owner's later approval enabled both repository settings and workflow-scoped
check dispatch. Actual source run `42047648713` used `GITHUB_TOKEN` to create,
label and merge authored safe-link bot #88 after exact-SHA dispatched run
`42047963456` and other checks passed. An ordinary unchanged poll created no PR.
The accepted catalog/ledger remain unchanged; #78 now has the required operational
evidence, with no remaining mandatory blocker for tracking #53. The
[delivery reconciliation](plan.md#assessor-efficiency-delivery-reconciliation-2026-11-05)
is the criterion-by-criterion source for PRs, merges, historical checks, limits and
minimum owner action.

### Requirements and acceptance

| Requirement | Scope and acceptance | Work |
|---|---|---|
| FR-23 | Versioned source-hashed crosswalk for every GUID, allowing empty mappings; verified ALZ Library, built-in Policy, PSRule and query identities with conservative strength/rationale; inspect/validate CLI and provenance tests. Mapping is not an outcome. | LL-27 |
| FR-24 | Explicit contract 1.2 evidence tiers, separate from automation disposition/outcome: Verified, Signal, Needs decision, with manual counted separately. Control counts sum to 255; old 1.0/1.1 meanings and render/replay remain unchanged. All formats share one model. | LL-28 |
| FR-25 | Preserve source-backed severity and deterministic priority. Suggest applicability only from explicit saved MG/archetype evidence and require reviewer confirmation; never infer exclusions from names. | LL-29 |
| FR-26 | Saved/scoped assignment and original-time compliance evidence maps to attributable Signals. Assignments, exemptions, evaluation time, freshness, gaps and technical results remain distinct. Injected/saved acceptance stays within #40's boundary. | LL-30 |
| FR-27 | Ingest supported saved PSRule and generic SARIF with scanner/version/baseline/hash provenance and redaction. Never run/install scanners; empty results, unknown rules or missing identities cannot pass controls. | LL-31 |
| FR-28 | Recommend separately supplied plan JSON, retaining raw Terraform fallback. Doctor hints explain both. Freeze interpreter scope to bug fixes unless an accepted cohort needs more; no Terraform execution. | LL-32 |
| FR-29 | Execute only exact reviewed hash-allowlisted upstream ARG queries with explicit scoped transport, typed output/identity validation and bounded paging/retries. Emit Signals only; exclude and explain all other audited queries. | LL-33 |
| FR-30 | Specific multi-GUID interviews produce only explicitly confirmed, content/scope-bound reviews with reviewer/rationale/evidence/validity. Reprioritise fixed cohorts by severity/crosswalk coverage without changing membership or receipts. | LL-34 |
| FR-31 | Extend source polling to checklist, ALZ Library, PSRule and built-ins. Produce classified candidate PRs; safe-only auto-merge is separately guarded. Preserve review/retirement/history; accepted catalog Release assets only, local lag notice, no runtime replacement. Blocked GitHub settings retain artifacts and generated PR body. | LL-35 |
| FR-32 | Three-pane local triage with keyboard navigation, tier/severity queue, evidence/decision panel, disclosed effort estimate, explicit bulk Signal review, interviews and verified resume. Retain capability/Host/origin/routes, immutable revisions and no remote assets. | LL-36 |
| FR-33 | Advisory SARIF and Markdown PR summaries share the sanitised assessment model; genuine safe locations only, no invented source lines. Provide a docs example without findings-based gates. | LL-37 |
| FR-34 | Summary-first HTML, separate completion/subset pass rate, severity risks, text-labelled area heat map and minimised CSV/XLSX trackers. Review dependencies first and test spreadsheet injection, workbook validity and all-format parity. | LL-38 |
| FR-35 | README quickstart, one linked limitations page, preserved planning/catalog history and checked links/examples. Never present planned behaviour as delivered. | LL-39 |
| FR-36 | Criterion-by-criterion merged delivery, actual checks/skips, tier totals/crosswalk coverage and live-versus-injected limits. Close tracking only when every mandatory item is closed; blockers remain visible. | LL-40 |

Contract design decision: retain `automation` and all six technical outcomes.
Tiers describe evidence available in a particular assessment, not permanent new
compliance dispositions. Verified means a current supported accepted predicate
has sufficient evidence, including a failure, not that it passed. Signal means
attributable machine evidence awaits confirmation. Needs decision means no usable
machine evidence. Explicit manual disposition remains its own count. Aggregate
once per GUID with conservative mixed-resource/mode handling, defined and tested
in LL-28; insufficient evidence cannot become Verified. No 1.0/1.1 document
acquires these meanings implicitly.

All changes preserve advisory exits 0/2, planned/observed separation, independent
exceptions, `not_comparable`, immutable historical bytes, original policy times,
review attribution/content/scope/expiry and privacy. No signal, assignment,
scanner, query or interview answer creates a pass without an accepted predicate
or explicit bound human decision. Every current GUID remains visible; retired
records remain traceable under explicit lifecycle semantics.

## Active increment: fixed recommendation expansion

The current delivered successor is `2026-11-06.1`: 255 retained GUIDs, 8 automated,
204 assisted and 43 manual. Cohorts 01, 17, 18 and 19 are merged (35 fixed targets);
216 remain pending. Cohort 19/#90 reconciled the saved draft against exact
delivered `.5` foundations and passed normal exact-head delivery gates.
Only complete successful observed custom NSG snapshots can evaluate
the explicit <=900 checklist target. Declared/raw/planned rule lists remain
unknown; the target is distinct from the current 2,000 ARM service quota.
Configured zones do
not establish backend redundancy; rule TLS/category fields and approved private
endpoints do not establish effective inspection or connectivity. This is not exhaustive
251-target acceptance; delivery/check evidence is tracked in the
[active plan](plan.md#recommendation-expansion-active).
Earlier catalog counts and runtime results below are historical.

**FR-22:** Address every GUID in the frozen 251-item starting set with reviewed
sources and the strongest defensible implementation: full explicit predicate,
useful partial/assisted support, specific inherently manual workflow, or exact
visible blocker. Classification alone is not delivery. Keep canonical membership,
source revisions, precise supported modes, prerequisites, tests, limitations
and merged acceptance per GUID. No unavailable/empty/filtered/inaccessible
evidence, resource name, accepted exception or narrow local flag can establish
the whole recommendation. Retain all 255 entries, original four meanings and
historical replay. Continue independent batches within the existing access
boundary; do not broaden permissions or invent owner decisions.

Status: advisory release baseline merged by the owner through
[PR #13](https://github.com/jonathan-vella/landinglens/pull/13) on 2026-11-04.
Acceptance hardening is merged through
[PR #15](https://github.com/jonathan-vella/landinglens/pull/15);
issues #1-#12 are closed with verified acceptance evidence.
All twelve backlog items have implementation evidence in the
[plan](plan.md#implemented-release-baseline-2026-11-04). The owner authorized
end-to-end work and delegated matrix acceptance to Autopilot. The subsequent
completion authorization permits additional scoped PRs, merges after passing
checks and acceptance-backed issue closure. Publication, deployment and live
Azure collection remain excluded.

Verified findings: [source review](../../references/2026-11-04/review.md) and
[prerequisite acceptance evidence](plan.md#prerequisite-results-2026-11-04).
The catalog contains 255 items with GUID-based provenance: two accepted
automated predicates, 211 assisted and 42 manual recommendations. The
[accepted matrix](../automation-matrix.md) identifies both verified property
mappings, required modes and uncovered areas. Duplicate display IDs and the
CAF/checklist billing-label conflict remain flagged. Full per-item semantic
mapping, Microsoft certification and live Azure verification are not claimed.

Feasibility is demonstrated for the tested bounded subset against synthetic,
versioned ALZ-shaped module snapshots and an unmodified, commit-pinned Microsoft
AVM workspace module 0.5.1, not the complete official AVM library.
Unsupported expressions and missing modules remain unknown. Actual Bicep
compilation was exercised with restoration disabled. Bounded ARM expressions,
safe inner-scope inline templates and native HCL dynamic blocks are implemented.
Runtime expressions, linked/child templates, JSON dynamic blocks and richer
interpreter semantics remain unknown/incomplete, not silently passed.

## Problem

Azure platform and workload teams need to assess what they intend to deploy or
have already deployed against Microsoft Azure Landing Zones guidance. Doing this
manually makes it difficult to maintain a current checklist, trace findings to
evidence, and distinguish an unverified recommendation from an actual violation.

LandingLens will provide an advisory checklist organized by verified Microsoft
landing-zone design areas. It will assess infrastructure as code (IaC) or
read-only Azure evidence without requiring both.

## Goals

- Make guidance, evidence and applicability traceable for each checklist item.
- Assess both platform and application landing zones.
- Support Bicep/ARM, raw Terraform source and deployed Azure in the first
  release; accept Terraform plan JSON as an optional additional input.
- Clearly separate planned and observed results, including unknown and manual
  outcomes.
- Produce consistent JSON, Markdown and HTML reports suitable for review.
- Provide useful automation without implying that every recommendation is
  machine-verifiable.

## Users

- **Platform engineers** assess shared landing-zone infrastructure and
  inherited governance.
- **Application teams** assess workload landing zones and identify dependencies
  on shared platform capabilities.
- **Reviewers and owners** inspect evidence, open questions, exceptions and
  assessment coverage.

## Product and delivery decisions

| Topic | Decision |
|---|---|
| Delivery | Standalone command-line tool in this repository |
| Landing-zone scope | Platform and application landing zones |
| IaC | Bicep/ARM and raw Terraform; a Terraform plan is not required |
| Deployed evidence | Explicitly scoped, read-only Azure collection |
| Reports | JSON, Markdown and self-contained HTML |
| Enforcement | Advisory; assessment findings do not block CI |
| Microsoft sources | Retrieve, verify and pin reviewed public references |
| Runtime | Python is recommended by the plan; dependency choices require validation |

The installed command is `alz-assessor`; publication naming remains unverified.
python-hcl2 8.1.4 is accepted for bounded AST parsing following the
[dependency review](../dependency-review.md); future dependencies need their own review.
The [implementation plan](plan.md) is the source of detailed execution
boundaries.

FR-28 now recommends separately supplied plan JSON as the first Terraform path,
retaining raw-source fallback. No plan is required or executed. The
[ADR](plan.md#adr-prefer-supplied-plan-json-freeze-interpreter-expansion) freezes
custom interpreter expansion to bug fixes unless accepted cohort requirements
justify a narrow extension.

## Non-goals for the first release

- Deploying, changing, remediating or deleting Azure resources or policies.
- Running Terraform `init`, `plan`, `apply`, backend access or provisioners
  implicitly; fetching remote modules automatically; or executing source code.
- Providing a complete Terraform, Bicep or ARM interpreter or inferring
  undocumented provider defaults.
- Automatically signing in, collecting an entire tenant, or assuming Microsoft
  Graph or billing permissions.
- Building a hosted service, database or blocking assessment-based CI gate.
  FR-21 permits a temporary loopback form; FR-32 extends that same local boundary
  into triage, not a hosted application.
- Claiming all Microsoft recommendations are automated or every landing zone is
  compliant.

## Functional requirements

### FR-01: Source verification and catalog

Before claiming Microsoft alignment, retrieve and review the
[Azure Landing Zones site](https://azure.github.io/Azure-Landing-Zones/),
[CAF design-area guidance](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/design-areas)
and [Microsoft ALZ checklist](https://github.com/Azure/review-checklists/blob/main/checklists/alz_checklist.en.json).
Verify their current structure, exact design-area names, checklist identifiers
and reuse terms. Record source URLs, revision or commit where available,
retrieval time, hashes and review state.

Maintain a versioned catalog with stable local IDs, upstream references,
guidance, design-area mapping, applicability, evidence needs and lifecycle
status. Keep Microsoft recommendations, effective tenant policy and
organization-specific extensions distinct. Source changes require review; they
must not silently rewrite past assessment results.

### FR-02: Complete inventory and explicit automation coverage

Every imported checklist item must remain visible with a documented disposition:
automated, assisted, manual, unmapped or not applicable to the assessed scope.
An unsupported item must not become a pass or disappear from the report.

After source verification and the vertical slice, an owner must accept a
concrete automation matrix naming the controls, design areas, evidence modes and
required positive/negative fixtures. It must include a nonempty automated set
across Bicep/ARM, raw Terraform and observed Azure evidence. Areas without
automated coverage must be explicitly identified and accepted. An entirely
manual or unmapped catalog does not satisfy release acceptance.

### FR-03: Terraform source evidence

Analyze `.tf` and `.tf.json` files without requiring a Terraform plan. Support
documented variable inputs, explicit defaults, locals, local modules and a
tested, bounded subset of expressions. Verify variable precedence against
upstream documentation.

Accept an explicit manifest mapping remote module references to user-supplied,
versioned local snapshots. Resolve nested dependencies only when their sources
are available and authorized. Record snapshot provenance; do not fetch remote
modules automatically.

Expand `count`, `for_each` and dynamic blocks only when their values are known
and valid. Bound recursion and expansion. Data sources, remote state, computed
attributes, unsupported expressions and unavailable modules remain unknown.
Evaluate independently resolvable portions and report incomplete graph coverage.

### FR-04: Optional Terraform plan evidence

Accept a user-supplied Terraform plan JSON as an additional planned-evidence
source. Preserve its provenance separately from source analysis. Do not assume a
plan corresponds to a source tree merely because both were supplied, and do not
silently replace contradictory source evidence.

### FR-05: Bicep and ARM evidence

Accept ARM template JSON and parameter inputs. Compile Bicep only with an
already installed compiler and implicit module restoration disabled. Record
compiler and input provenance. Missing tools or modules must produce actionable
diagnostics; unresolved runtime expressions remain unknown. No compilation
failure may produce invented resource evidence.

### FR-06: Read-only deployed Azure evidence

Require an explicit subscription or management-group scope and use existing
authorized credentials. Collect relevant inventory, relationships and effective
policy assignments, parameters, exclusions and exemptions. Collect actual
policy-compliance evidence separately, with its evaluation time.

Handle inherited assignments, pagination, throttling, permission failures,
stale results and partial inventories explicitly. Verify API operations and
least-privilege requirements before implementation. Tenant, billing or identity
controls requiring additional permissions remain manual or unknown unless
separately supported and authorized.

### FR-07: Evidence, identity and comparison

Evidence must retain its source mode, target identity, known or unknown state,
reason, time, scope and available source reference or hash. Planned and observed
facts remain separate.

Automatically compare planned and deployed resources only when a canonical ARM
resource ID can be established from resolved properties and explicit scope
bindings. A Terraform address is not an ARM ID, and a resource name alone is not
a match. Support an explicit, source-hash-bound identity map; reject duplicate
or ambiguous mappings.

Missing bindings, unresolved identities or unverified artifact relationships
yield `not_comparable`, not a drift verdict. Resource absence can be established
only when the identity is known and the relevant live inventory is complete.

### FR-08: Evaluation and manual evidence

Each applicable result is `pass`, `fail`, `unknown`, `error`, `manual` or
`not_applicable`, with a reason and evidence. Keep planned and observed results
independent. An assignment alone is not evidence that a resource is compliant;
a stale fact is not a current pass.

Allow manual evidence and exception dispositions with scope, rationale and
validity. An accepted exception does not change a technical failure into a
pass. Applicability decisions and missing evidence must remain visible.

### FR-09: Reports and coverage

Render JSON, Markdown and HTML from the same assessment model. Group results by
verified design area and show applicable platform/application scope, source
versions, evidence timestamps, manual and unknown outcomes, exceptions and
inventory completeness. HTML must be escaped and self-contained, without
external scripts or asset requests.

Report control counts separately from resource-instance counts. Show:

- Assessment completion: assessed instances divided by known applicable
  instances, including unknown and pending-manual instances in the denominator.
- Pass rate among assessed instances: passes divided by passes plus failures,
  labeled as a subset rather than overall estate compliance.
- Inventory completeness and unresolved applicability separately.

When a denominator is zero, report the rate as unavailable. An incomplete
inventory must not produce an estate-wide compliance claim.

### FR-10: CLI and offline use

Provide workflows to inspect reviewed catalog material, assess inputs, collect
explicitly scoped Azure evidence, compare compatible assessments and render
reports. Support offline assessment from pinned catalog and saved evidence
bundles.

A completed advisory assessment returns success even when it contains findings,
unknowns or pending manual items. Invalid invocation and unrecoverable
execution failures return a nonzero exit with a clear diagnostic. Partial
collection remains conspicuous in the report. An assessment never authorizes
deployment.

## Next increment requirements

Planning baseline: requested on 2026-11-04 before implementation. The
[delivery reconciliation](plan.md#next-increment-delivery-reconciliation-2026-11-04)
now records merged implementation and per-criterion evidence. The owner requested this
extension following the automation/source-maintenance/presentation research
and usability recommendations. Preserve the completed release and its accepted
two-control matrix; do not reinterpret the 49 upstream query-bearing entries
as verified automation. Full issue acceptance criteria are in the
[next-increment plan](plan.md#next-increment-trustworthy-automation-and-usable-reviews)
and [linked backlog](backlog.md#next-increment-work-items).

### FR-11: Controlled lifecycle and review compatibility (LL-13)

Support explicit contract-version evolution without silently reinterpreting
1.0 documents. Keep old source/catalog versions and historical replay.
Retired controls remain traceable but do not inflate current active
denominators; supersession and changed predicate/content require review.

Bind new attestations/exceptions to control content, scope, validity and an
explicitly supplied opaque reviewer label. Legacy unbound records remain
visible but cannot acquire verified attribution/content binding by default.
Treat attribution as a producer assertion, not authenticated identity proof.
Reject ambiguous/conflicting review records; exception disposition never
rewrites a technical result. Comparison must disclose incompatible
catalog/rule meanings instead of manufacturing drift.

### FR-12: Offline readiness and actionable unknowns (LL-14, LL-15)

Provide a preflight/doctor workflow for explicit input modes, checking paths,
snapshot hashes, mappings, scope/identity prerequisites and existing compiler
availability. Emit structured and human-readable readiness; success means
only that the checked prerequisites passed, not complete IaC or Azure support.

Preserve stable reason codes and add specific, sanitized explanations of
what evidence resolves each unknown/error. Unknown reason codes remain
visible with an explicit unsupported-explanation notice. Never fetch modules,
install/restore tooling, execute IaC, authenticate, query Azure or weaken
validation as a preflight/diagnostic side effect.

### FR-13: Review preparation (LL-16)

Generate deterministic templates for selected unresolved controls and scope.
Require supplied outcomes, rationale, reviewer and evidence before accepting
them as completed reviews; do not prefill a passing attestation. Validate
expiry, content/scope binding and duplicate/conflicting records. Present
review status/ownership independently of technical outcomes, without a
service, identity lookup or automatic issue/message creation.

### FR-14: Accessible static presentation (LL-17)

Improve the existing self-contained HTML, not a hosted web application.
Provide summary, area, finding, control-detail, review and provenance views
from one sanitized model. Filtering/sorting/expansion cannot reevaluate rules.
Keep useful no-JavaScript content, text statuses, keyboard access and print
styles; test representative offline/browser/print behavior.

Retain JSON/Markdown parity and distinguish automated coverage, completion,
assessed-subset pass rate, resource counts, visibility and freshness.
Safely serialize any embedded data, validate links and preserve minimized
presentation-only output. No raw evidence dump, credentials, CDN, telemetry,
external asset requests or PDF dependency by default.

### FR-15: Reviewed source maintenance (LL-18)

Use weekly/manual public-source detection with immutable candidate snapshots,
source/license hashes and semantic diffs. Display last successful polling,
last semantic review and pending changes separately. Detect GUID changes,
text/query/schema/taxonomy/license changes and display-ID conflicts.

Historical FR-15 baseline: failed detection retains the known catalog with an explicit warning; no
runtime refresh, automatic query execution or auto-merge. Default workflow
permissions are read-only and output is candidate/diff artifacts. A maintainer
opens a reviewed promotion PR. Bot write access/credentials require separate
approval. Apply FR-11 retirement and stale-review handling during promotion.
Ten-working-day triage is an operating proposal, not a delivery guarantee.
FR-31 supersedes the artifact-only/bot-write gate only for the newly approved
workflow; arbitrary query execution and runtime refresh remain excluded.

### FR-16: Evidence-backed automation expansion (LL-19, LL-20)

Audit all 49 pinned query-bearing entries and G02.03/G04.02/F01.08 by GUID.
Distinguish executable predicates from relational/contextual heuristics and
inventory-only evidence. Review D07.06/D07.07 as the bounded first-wave
candidates, including enum/SKU/API/provider/applicability semantics.

Record a successor matrix under the existing delegated acceptance authority
before implementation, naming controls, modes and all required outcomes.
Implement only accepted predicates in the existing evaluator/adapters; avoid
a general-purpose expression language, inferred defaults or duplicate engine.
Test installed cross-mode behavior, identity, missing/partial/stale evidence
and report parity. The original matrix/inventory remain intact.

If no candidate is viable, leave implementation/integrated acceptance blocked
pending an explicit coverage decision. A research conclusion does not satisfy
the promised new-control implementation. Later candidate waves need their own
reviewed matrix and scoped implementation tasks.

### FR-17: Scalable scoped evidence (LL-21)

Review exact ARG/ARM detail/child-resource/PolicyStates operations, API versions,
properties and least-privilege needs for the committed matrix. Require explicit
scope, validate returned identities/continuations and retain bounded paging,
retry, error, truncation and time metadata.

ARG is eventually consistent; completed pagination does not prove complete
authorization. Missing properties and partial visibility stay unresolved.
Policy configuration, exemptions and original-time compliance evaluations
remain distinct. Demonstrate behavior with injected transports, not live calls
or triggerEvaluation, and preserve offline use and data minimization.

### FR-18: Optional MCP feasibility (LL-22)

Evaluate source and metadata only: native versus proxied tools, exact schemas,
explicit scope, structured facts, paging, identity, freshness, privacy and
read-only/exact-tool allowlists. Missing remote scope/output evidence yields
a documented not-ready decision; mocks cannot verify remote behavior.

This study is optional and non-gating. It does not install/start/authenticate
tooling or deliver a production MCP adapter. A future adapter or live pilot
requires a separate scoped issue and any excluded-action authorization.

### FR-19: Portable replay with privacy boundaries (LL-23)

Offer an explicit, bounded local bundle of sanitized normalized evidence,
catalog/rule versions, safe invocation metadata, hashes and bound reviews.
Exclude credentials, source trees, raw variable files and ambient environment.
Sanitize all metadata/review text and pseudonymize reviewer labels by default;
retaining attribution requires opt-in. Disclose retained scoped resource IDs
and never upload/share automatically.

Replay from an installed wheel outside the checkout at the recorded evaluation
time must preserve semantic outcomes, identities, freshness and coverage.
Unavailable artifacts, tampered hashes, invalid schema, traversal, links and
size/count violations fail explicitly. Minimized exports stay presentation-only,
not replayable. Do not promise identical generation timestamps or HTML bytes.

### FR-20: Continuous verification and offline acceptance (LL-24, LL-25)

Add deterministic generated tests for unknown propagation, type safety,
redaction, expansion bounds and evidence loss without invented passes.
Automate clean-wheel build/install outside the checkout and verify import
location/dependency consistency. Retain Windows/Linux Python 3.12/3.13,
exact-byte fixture portability, lint/format/types and advisory exit behavior.

Report real-compiler exercised versus unavailable jobs and skip reasons;
claim compiler CI coverage only after an existing-compiler integration job
actually runs. No automatic compiler installation/restoration fallback.

Reconcile every mandatory issue against merged implementation and actual checks,
including an explicitly supplied licensed/redacted offline ALZ reference corpus.
No live Azure proof, deployment, package publication or automatic issue closure
is implied. LL-22 and a future authorized live pilot are not release dependencies.

### FR-21: One-step local review saving (LL-26)

The owner requested automation of the review workflow on 2026-11-05. A single
`review serve` invocation opens a loopback-only browser form over saved normalized
evidence. The assessor supplies the decision, reviewer, rationale, supporting
evidence and finite validity; Save automatically validates, persists and
regenerates JSON/Markdown/HTML and minimized HTML through the existing Python
contracts and evaluator. No manual JSON editing, download/import or render
sequence is required. Manual evidence and exceptions retain their distinct
meanings; excepted technical failures are not converted into passes.

Scope/control hashes come from the supplied exact evidence/catalog, not browser
fields. Minimized/rendered reports and unscoped inputs fail explicitly. Preserve
supplied review records, require explicit replacement confirmation, detect stale
browser revisions, retain immutable earlier revisions and expose validation/write
errors without losing the last saved output. Reevaluate at save time without
refreshing source evidence timestamps or weakening the chosen freshness policy.

The temporary standard-library loopback listener is the narrow exception to the
original no-web-application non-goal; no hosted portal, database, authentication
service, new dependency or Azure access is introduced. Use an ephemeral port,
random per-session capability, exact Host/origin checks, bounded JSON writes and
fixed routes. Do not serve raw normalized evidence in the editor or load remote
assets. Disclose private identities/output paths, stop behavior and the trusted
local-process boundary. Record HTTP/session/installed-wheel and actual browser
save/report-refresh acceptance under [#44](https://github.com/jonathan-vella/landinglens/issues/44).

### Next-increment delivery status

FR-11 through FR-19 and the FR-20 invariant/clean-wheel foundations are delivered
through PRs #31-#39, with actual supported CI passing before each merge.
The final FR-20 reconciliation adds an installed, licensed-corpus workflow and
the [criterion-by-criterion delivery record](plan.md#next-increment-delivery-reconciliation-2026-11-04);
Issue #28 is closed following [#41](https://github.com/jonathan-vella/landinglens/pull/41),
merge `fcb58a4a5f3706ad51e6ade69cbecb1e073d7644`, with all eight checks passing.
Earlier release results remain historical rather than being relabelled as
newer verification.

The pre-expansion catalog `2026-11-04.2` retains all 255 entries: four bounded automated
predicates, 209 assisted and 42 manual. Original `2026-11-04.1` meaning is packaged
unchanged. D07.06/D07.07 use exact explicit local mode/SKU evidence, not effective
inherited or runtime protection. Remaining audited candidates were not
silently promoted. Optional MCP is **not ready**, a completed study rather than
a delivered adapter. Replay is a bounded local directory retaining identities,
not an anonymized report or support for arbitrary unavailable historical rules.

The final local installed-wheel run exercised 145 tests (144 passed; one Windows
symlink-privilege skip), real existing no-restore Bicep and the licensed AVM/
authored ALZ corpus. Six symbolic controllers and incomplete visibility remain
explicit. The separate owner-authorized live pilot in #40 retains private
scope/raw evidence. Its installed collector found and, after merged #42, verified
an assignment-filter fix: 293 HTTP 200s with zero HTTP failures on the rerun.
Inventory authorization was not attested and ancestor custom-definition references
remained unread. This cannot substitute for full control or estate verification;
see the [sanitized pilot record](../collection.md#selected-boundary-live-pilot).
Publication, deployment/remediation and authentication/permission changes remain
outside this delivery.

## Non-functional requirements

- **Safety:** No implicit deployment, remediation, authentication, Terraform
  execution or module download.
- **Privacy:** Do not emit credentials or sensitive parameter values. Minimize
  and redact collected inventory as configured; do not commit raw evidence
  automatically.
- **Integrity:** Bind assessments to catalog and input provenance; retain
  unsupported or stale evidence as unresolved.
- **Reliability:** Bound parsing, recursion and expansion; report errors and
  partial collection instead of silently defaulting.
- **Reproducibility:** Support repeatable offline evaluation against pinned
  catalog and evidence snapshots.
- **Dependencies:** Assess licensing, maintenance, supported runtimes,
  approved feed availability and applicable package-age requirements before
  selecting or installing dependencies.
- **Accessibility:** Keep Markdown and HTML readable, with explicit text labels
  rather than conveying outcomes by color alone.

## Release acceptance

The first release is ready only when:

1. Microsoft sources, design-area taxonomy, checklist structure and reuse terms
   are verified and recorded; imported items have dispositions.
2. The representative module-based Terraform feasibility cases pass without a
   required plan or automatic remote-module retrieval.
3. The vertical slice demonstrates pass, fail, unknown, compatible comparison
   and non-comparable identities in all three report formats.
4. An owner accepts the concrete automation matrix, and every committed
   control/evidence-mode combination has passing positive and negative fixtures.
5. The installed CLI demonstrates source-only Terraform, Bicep/ARM, saved live
   evidence and identity-resolved comparison workflows.
6. Clean-environment installation, lint, type, schema, unit and integration
   checks pass without production Azure credentials.
7. Documentation describes supported coverage, incomplete evidence, permissions,
   snapshot preparation, source refresh, redaction and advisory exit behavior.

Real-tenant smoke tests require separately authorized scope and credentials.
Mocked or saved evidence must not be presented as live-tenant verification.

## Execution and open decisions

### Source-automation permission approval: 2026-11-05

After being asked about the three exact changes, the owner replied:
"I approve these changes. proceed." This authorises enabling repository
**Allow GitHub Actions to create and approve pull requests**, enabling
**Allow auto-merge**, and adding **`actions: write` to the source-update workflow
only** so it can dispatch existing `checks.yml` on the candidate branch.

Both settings are now verified true. Repository-wide default workflow permissions
remain `read`; branch protection and all other settings, secrets, credentials and
Azure permissions are unchanged. The source workflow never approves reviews or
bypasses checks. Its token creates the PR, dispatches the fixed check workflow,
waits for all four supported platform jobs and all other applicable checks, then
binds any safe-only merge request to the exact candidate SHA.

This narrowly supersedes the earlier prohibition for those two settings only.
Validation may use a clearly labelled authored safe-link fixture with the real
source poll retained separately; it must not claim Microsoft changed its source
or activate/publish a new accepted catalog. Actual workflow/PR/check/merge evidence
is required before resolving #78.

The [backlog](backlog.md) links each implementation task to a GitHub issue.
The source inventory, bounded parser choice, delegated automation-matrix
acceptance, two reviewed item/control mappings and scoped Azure API choices are
recorded in the linked evidence. No original implementation issue remains
after LL-12; new work is tracked separately in the next-increment backlog.
Additional automation and source/API versions require review; the existing
accepted limitations do not imply unverified coverage.

### Assessor-efficiency authorisation: 2026-11-05

The following owner approvals are recorded verbatim. They supersede the earlier
planning-only and artifact-only gates only within this increment.

- **D1** Planning update and issue creation: **APPROVED**
- **D2** Implementation of every work item below, through separate scoped PRs, merging
  each after all required checks pass, and closing issues that have verified, merged
  acceptance evidence: **APPROVED**
- **D3** The source-update workflow may open PRs using the workflow's own
  `GITHUB_TOKEN`, with `contents: write` and `pull-requests: write` scoped to that single
  workflow (no PATs, no stored bot secrets): **APPROVED**
- **D4** Auto-merge for the "safe" catalog-change class (wording, link or translation only,
  all checks green), with every other class requiring a human merge: **APPROVED**
- **D5** Executing reviewed, allowlisted, read-only upstream Azure Resource Graph queries
  as **Signals** (never passes) within an explicit, user-supplied scope: **APPROVED**. This
  replaces the rule "upstream queries are data, never executed" for allowlisted queries
  only. Non-allowlisted queries stay data.
- **D6** Adding new runtime or dev dependencies (for example, `openpyxl` for XLSX export)
  **is approved, provided each one passes the existing dependency-review process**
  (licence, maintenance, supported runtimes, approved feed, package age), recorded in
  `docs/dependency-review.md`. If a candidate fails review, choose an alternative or a
  standard-library approach. Do not stop.

Exclusions remain: no Azure deployment/remediation/deletion/policy mutation, wider
live reads than #40, automatic authentication or permission changes, repository
settings/protection/secrets changes, package publication, implicit modules or
unsupported Terraform/Bicep execution. Policy/D5 acceptance uses saved fixtures
and injected transports; unavailable authorised credentials mean live behaviour
is undemonstrated. Dependencies require review before installation. Accepted
catalogs may be published only as GitHub Release assets under FR-31, not packages.

Repository facts win on state; this authorisation wins on new scope. Choose the
smallest existing-contract design, use weaker crosswalk strengths where uncertain,
record unverifiable subsets and blockers, and continue independent work. Do not
reopen closed issues. No approval question is required for these routine choices.
The 2026-11-05 read-only settings inspection found auto-merge disabled and workflow
PR creation/approval disabled. Do not change either setting. LL-35 must retain
artifacts/generated PR body and record exact blocked operations in #53.
