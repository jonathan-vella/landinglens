# LandingLens product requirements

## Active increment: fixed recommendation expansion

The current working successor is `2026-11-05.2`: 255 retained GUIDs, 7 automated,
205 assisted and 43 manual. Batch 01 is merged; cohort 17 implementation and
its acceptance are tracked separately. This is not exhaustive
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

## Non-goals for the first release

- Deploying, changing, remediating or deleting Azure resources or policies.
- Running Terraform `init`, `plan`, `apply`, backend access or provisioners
  implicitly; fetching remote modules automatically; or executing source code.
- Providing a complete Terraform, Bicep or ARM interpreter or inferring
  undocumented provider defaults.
- Automatically signing in, collecting an entire tenant, or assuming Microsoft
  Graph or billing permissions.
- Building a web application, hosted service, database or blocking
  assessment-based CI gate. The later owner-authorized FR-21 follow-up permits
  only a temporary loopback form for local review saving.
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

Failed detection retains the known catalog with an explicit warning; no
runtime refresh, automatic query execution or auto-merge. Default workflow
permissions are read-only and output is candidate/diff artifacts. A maintainer
opens a reviewed promotion PR. Bot write access/credentials require separate
approval. Apply FR-11 retirement and stale-review handling during promotion.
Ten-working-day triage is an operating proposal, not a delivery guarantee.

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

The [backlog](backlog.md) links each implementation task to a GitHub issue.
The source inventory, bounded parser choice, delegated automation-matrix
acceptance, two reviewed item/control mappings and scoped Azure API choices are
recorded in the linked evidence. No original implementation issue remains
after LL-12; new work is tracked separately in the next-increment backlog.
Additional automation and source/API versions require review; the existing
accepted limitations do not imply unverified coverage.

The current request authorizes this planning update and issue creation, not
implementation of the next increment or excluded actions. Live Azure access,
authentication/permissions, bot write credentials, deployment, policy scans,
tool/module installation and package publication remain separately gated.
If candidate verification fails, obtain an explicit coverage decision rather
than silently dropping the expansion requirement.
