# LandingLens implementation backlog

This backlog tracks the complete [implementation plan](plan.md) and
[product requirements](prd.md). Each work item links to its GitHub issue;
issue status is the source of truth. Dependencies describe implementation
order, not additional authorization to access Azure or publish a package.

## Assessor-efficiency work items

Owner-authorised 2026-11-05, tracking
[#53](https://github.com/jonathan-vella/landinglens/issues/53).
[FR-23-FR-36](prd.md#next-increment-assessor-efficiency) and the
[numbered plan](plan.md#assessor-efficiency-increment) govern delivery.
Verified baseline is merged `.3`, 7/205/43, not the paused draft `.4`.
All items below are open, not delivered by this planning update.

| ID / issue | Work item | Prerequisites | FR | Delivery status |
|---|---|---|---|---|
| [LL-27 / #58](https://github.com/jonathan-vella/landinglens/issues/58) | Verified evidence crosswalk | Planning PR | FR-23 | Merged #69; issue closed |
| [LL-28 / #59](https://github.com/jonathan-vella/landinglens/issues/59) | Explicit evidence tiers | LL-27 | FR-24 | Merged #70; issue closed |
| [LL-29 / #56](https://github.com/jonathan-vella/landinglens/issues/56) | Severity/applicability | LL-27, LL-28 | FR-25 | Merged #71; issue closed |
| [LL-30 / #55](https://github.com/jonathan-vella/landinglens/issues/55) | Saved/scoped policy Signals | LL-27, LL-28, LL-29 | FR-26 | Merged #72; issue closed |
| [LL-31 / #63](https://github.com/jonathan-vella/landinglens/issues/63) | Saved scanner ingestion | LL-27, LL-28, LL-29, LL-30 | FR-27 | Merged #73; issue closed |
| [LL-32 / #54](https://github.com/jonathan-vella/landinglens/issues/54) | Plan-first guidance | Existing adapters; execute after LL-33 | FR-28 | Local/exact installed checks pass; CI/merge pending |
| [LL-33 / #60](https://github.com/jonathan-vella/landinglens/issues/60) | Allowlisted query Signals | LL-27, LL-28, LL-29, LL-31 | FR-29 | Merged #74; issue closed |
| [LL-34 / #57](https://github.com/jonathan-vella/landinglens/issues/57) | Interviews/cohort priority | LL-28, LL-29, LL-32 | FR-30 | Pending |
| [LL-35 / #62](https://github.com/jonathan-vella/landinglens/issues/62) | Source-update PR pipeline | LL-27, LL-28, LL-29, LL-34 | FR-31 | Implementation pending; observed auto-merge/workflow PR settings block operational publication |
| [LL-36 / #61](https://github.com/jonathan-vella/landinglens/issues/61) | Local triage workspace | LL-28, LL-29, LL-30, LL-31, LL-33, LL-34, LL-38 | FR-32 | Pending |
| [LL-37 / #65](https://github.com/jonathan-vella/landinglens/issues/65) | SARIF/PR summaries | LL-28, LL-29; execute after LL-35 | FR-33 | Pending |
| [LL-38 / #64](https://github.com/jonathan-vella/landinglens/issues/64) | Summary/tracker exports | LL-28, LL-29, LL-37 | FR-34 | Pending dependency review |
| [LL-39 / #67](https://github.com/jonathan-vella/landinglens/issues/67) | Documentation restructure | LL-32, LL-35, LL-36, LL-37, LL-38 | FR-35 | Pending |
| [LL-40 / #66](https://github.com/jonathan-vella/landinglens/issues/66) | Reconcile delivery | LL-27-LL-39 merged or explicitly blocked | FR-36 | Pending; blockers do not satisfy criteria |

Planning merged in #68 and LL-27 in #69. Current dependency-ready item:
**LL-32 / #54**. Follow the
plan's explicit execution order; blocked GitHub publication does not prevent
offline evidence/triage work. Do not change repository settings. Keep candidate
artifacts/generated PR body when workflow PR creation or safe auto-merge is denied.
The tracking issue retains precise owner actions; no routine authorisation question
is needed. No issue is closed solely because a blocker or disposition is written.

## Active: fixed 251-recommendation expansion

The [active plan](plan.md#recommendation-expansion-active) and
[fixed ledger](../../references/recommendation-batches/ledger.json) govern this
owner-authorized increment. Baseline `2026-11-04.2` remains 4 automated /
209 assisted / 42 manual; the target set never changes with later promotions.

| Cohort | Scope | Dependencies | Acceptance/delivery |
|---|---|---|---|
| 01 / [#46](https://github.com/jonathan-vella/landinglens/issues/46) | G02.01-.04, G02.07-.08, G04.02-.03; fixed GUIDs in ledger | Delivered catalogs/contracts/local reviews; no new live access required | [#47](https://github.com/jonathan-vella/landinglens/pull/47) merged; all eight checks passed, exact installed suite and all four CI compiler integrations exercised; issue closed |
| 17 / [#48](https://github.com/jonathan-vella/landinglens/issues/48) | Nine firewall GUIDs; duplicate D07.12 entries remain distinct | Merged cohort 01, actual source review, reviewed network schemas | [#49](https://github.com/jonathan-vella/landinglens/pull/49) merged; all eight checks passed, exact installed suite and all four CI compiler integrations exercised; issue closed |
| 18 / [#50](https://github.com/jonathan-vella/landinglens/issues/50) | Nine TLS/resilience/private-connectivity GUIDs | Merged cohort 17; 18 actual source captures and reviewed versioned schemas | [#51](https://github.com/jonathan-vella/landinglens/pull/51) merged; all eight checks passed, exact installed suite and all four compiler integrations exercised; issue closed |
| 19 / [#52](https://github.com/jonathan-vella/landinglens/issues/52) | Nine service-endpoint/subnet/segmentation GUIDs | Merged cohort 18; re-evaluate after efficiency foundations | Paused unmerged draft preserved in named Git stash; no acceptance receipt |
| Other cohorts | Other 216 GUIDs in unchanged 5-10-item cohorts | Evidence foundations, then LL-34 severity/crosswalk priority with per-batch source requirements | Pending; partitioning/tiering is not delivery |

Working successor `2026-11-05.3`: 7 automated / 205 assisted / 43 manual, all 255 visible.
Twenty-six fixed targets are merged and 225 undelivered, including paused cohort 19; classification
alone is not delivery.
G02.02 is explicitly manual; unsupported Terraform vault soft-delete evidence
remains unknown. Create ready batch issues as implementation proceeds, not 251
bookkeeping issues. Continue after each merge; retain blockers and demonstrated
versus undemonstrated runtime labels. Prior completion statements below refer
only to their earlier increments.

## LL-26: automated local review session

[#44](https://github.com/jonathan-vella/landinglens/issues/44) tracks the
owner-directed 2026-11-05 follow-up. One `review serve` command opens a local
browser workflow; Save validates an explicit human decision, persists a new
revision and regenerates all reports automatically. No JSON editing or separate
import/render steps, new evaluator, dependency, hosted service or Azure operation.
Depends on the delivered LL-13/LL-16/LL-17 contracts/reviews/reporting. The prior
scope is complete. This increment is implemented and locally verified with 157
installed tests (156 passed, one Windows privilege skip), static/type/dependency
checks, real Bicep and an actual browser save, automatic report refresh, refused
unconfirmed replacement and listener stop. Browser validation used authored
fixtures, not new Azure reads or invented real approvals.

Acceptance: scoped normalized inputs, explicit bound decisions and retained
existing reviews, transactional outputs, guarded loopback access, installed/
HTTP/browser tests and synchronized documentation. Closure requires verified
implementation and merged delivery; see FR-21 and the plan's LL-26 section.

## Implementation evidence: 2026-11-04

LL-01 through LL-12 were delivered to `main` through
[PR #13](https://github.com/jonathan-vella/landinglens/pull/13), merged by the
owner on 2026-11-04. The subsequent completion authorization permits additional
scoped PRs, merges after passing checks and acceptance-backed issue closure.
Publication, deployment and live Azure collection were excluded at that stage.
The later selected-boundary read authorization is tracked separately in #40. GitHub is
the source of final issue state; closure requires verified, merged evidence.

Final reconciliation: issues **#1-#12 are closed as completed**, each with
criterion-specific evidence. The acceptance hardening was merged through
[PR #15](https://github.com/jonathan-vella/landinglens/pull/15), commit
`7c6c3390907c9916f264a645f6359d7fdb48897d`, after both four-job CI runs passed.

LL-01 produced reviewed snapshot **2026-11-04.1**, an eight-area taxonomy and
the complete 255-item provenance/disposition ledger. Three duplicated display
IDs, the billing-label conflict and unverified item/control mappings are explicit.
LL-02 produced an installable Python CLI spike and executable Terraform,
snapshot/scoping/precedence/bounds and no-restore Bicep checks. Its ALZ module
snapshots include authored ALZ wrappers plus an unmodified, pinned Microsoft AVM
workspace 0.5.1 module. Bounded operator/dynamic-block improvements now leave six
resource controllers symbolic. Full AVM compatibility is not claimed.
See [current evidence and limits](plan.md#implemented-release-baseline-2026-11-04).

The owner explicitly delegated LL-04 acceptance to Autopilot. The accepted
[two-control matrix](../automation-matrix.md) covers raw Terraform, Bicep/ARM and
observed fixtures with positive/negative cases; all 255 entries remain visible.
Six uncovered areas have explicit assisted/manual rationale.

**Original baseline:** no dependency-ready issue remains after LL-12.
The next increment below records separate work and its subsequent delivery.
The contract-validation and final acceptance follow-ups are merged. The
criterion-by-criterion
[acceptance evidence](plan.md#final-acceptance-reconciliation-2026-11-04) governs
issue closure; open checkboxes alone are not evidence of missing implementation.

## Next increment work items

Originally planned on 2026-11-04 following the research and requested plan review.
The [next-increment plan](plan.md#next-increment-trustworthy-automation-and-usable-reviews)
contains numbered acceptance criteria; [FR-11-FR-20](prd.md#next-increment-requirements)
defines corresponding product requirements. LL identifiers are not GitHub
issue numbers. All thirteen issues were originally created open. Current merged
evidence is in the
[delivery reconciliation](plan.md#next-increment-delivery-reconciliation-2026-11-04):
#17-#27 and #29 are closed; #28 awaits this final reconciliation's green merge.

| ID | Work item | Prerequisites | PRD | Delivery |
|---|---|---|---|---|
| [LL-13 (#18)](https://github.com/jonathan-vella/landinglens/issues/18) | Evolve catalog lifecycle and review bindings | Completed baseline | FR-11 | Mandatory |
| [LL-14 (#24)](https://github.com/jonathan-vella/landinglens/issues/24) | Add offline preflight | Completed baseline | FR-12 | Mandatory |
| [LL-15 (#23)](https://github.com/jonathan-vella/landinglens/issues/23) | Explain unresolved evidence | Completed baseline | FR-12 | Mandatory |
| [LL-16 (#21)](https://github.com/jonathan-vella/landinglens/issues/21) | Prepare attributable human reviews | LL-13, LL-15 | FR-13 | Mandatory |
| [LL-17 (#20)](https://github.com/jonathan-vella/landinglens/issues/20) | Improve self-contained HTML reports | LL-13 | FR-14 | Mandatory |
| [LL-18 (#17)](https://github.com/jonathan-vella/landinglens/issues/17) | Detect and review source changes | LL-13 | FR-15 | Mandatory |
| [LL-19 (#22)](https://github.com/jonathan-vella/landinglens/issues/22) | Audit automation candidates and define the successor matrix | Completed baseline | FR-16 | Mandatory |
| [LL-20 (#19)](https://github.com/jonathan-vella/landinglens/issues/19) | Implement the accepted first control wave | LL-13, LL-19, LL-21 | FR-16 | Mandatory; blocked if no accepted wave |
| [LL-21 (#25)](https://github.com/jonathan-vella/landinglens/issues/25) | Extend explicitly scoped observed collection | LL-13, LL-19 | FR-17 | Mandatory |
| [LL-22 (#29)](https://github.com/jonathan-vella/landinglens/issues/29) | Evaluate optional Azure MCP transport | LL-21 | FR-18 | Optional, non-gating study |
| [LL-23 (#27)](https://github.com/jonathan-vella/landinglens/issues/27) | Add opt-in sanitized replay bundles | LL-13, LL-16 | FR-19 | Mandatory |
| [LL-24 (#26)](https://github.com/jonathan-vella/landinglens/issues/26) | Strengthen invariants and installed-wheel CI | Completed baseline | FR-20 | Mandatory |
| [LL-25 (#28)](https://github.com/jonathan-vella/landinglens/issues/28) | Reconcile the next increment offline | LL-13-LL-21, LL-23, LL-24 | FR-20 | Mandatory |

Historical dependency-ready work was **LL-25 / #28 final reconciliation**. Its mandatory
implementation prerequisites are merged, including LL-21 in #36, the accepted
first wave in #37 and replay in #39. The optional MCP study concluded not ready
in #38 and does not block release acceptance.
That work is now merged and #28 closed; the current dependency-ready item is
LL-27 after the assessor-efficiency planning PR.

Dependencies are implementation prerequisites, not authorization. New source
monitoring defaults to read-only artifact generation, not bot PR write access.
LL-19 audits 49 upstream query entries plus G02.03/G04.02/F01.08; LL-20 implements
only the accepted D07.06/D07.07 first-wave matrix. A failed gate leaves LL-20
and LL-25 blocked pending an explicit coverage decision, not complete.

LL-22 ends with a justified ready/not-ready feasibility record, not a production
adapter or proof of remote scope behavior. An MCP adapter, new automation waves
or real-tenant pilot need separate scoped issues/decisions. The owner's later
private selected-boundary authorization is now tracked in #40, not inferred
from the original planning permission; no broader access is implied.

Close new issues only after their own acceptance criteria are satisfied and
implementation is merged. The original planning task did not execute those
issues; later authorized implementation is evidenced separately. Exclusions
and advisory/non-blocking behavior remain intact.

### Current delivery evidence

| Delivered work | PR / merge |
|---|---|
| LL-13 / #18 | [#31](https://github.com/jonathan-vella/landinglens/pull/31) / `001b344f17d4592df8129aa091d2bb4704951223` |
| LL-14-LL-15 / #24, #23 | [#32](https://github.com/jonathan-vella/landinglens/pull/32) / `1082abe2daf2b7b13b678bda4edfeadd10812338` |
| LL-16-LL-17 / #21, #20 | [#33](https://github.com/jonathan-vella/landinglens/pull/33) / `576f0e519dc90a4a86aaeb66d26073b62cb75a9a` |
| LL-18, LL-24 / #17, #26 | [#34](https://github.com/jonathan-vella/landinglens/pull/34) / `730837d489e7284e884b105b15584866087ab203` |
| LL-19 / #22 | [#35](https://github.com/jonathan-vella/landinglens/pull/35) / `601062bee928d0a7c1d41dabfa123875af501b59` |
| LL-21 / #25 | [#36](https://github.com/jonathan-vella/landinglens/pull/36) / `a44543f35c916d6021cae38bb390f4c1d1c23adf` |
| LL-20 / #19 | [#37](https://github.com/jonathan-vella/landinglens/pull/37) / `66f164c8c745bac0fb55513a08b0f1916775f2d6` |
| LL-22 / #29, study only | [#38](https://github.com/jonathan-vella/landinglens/pull/38) / `fc0e35c774414cf715aef3a877752df0781c9020` |
| LL-23 / #27 | [#39](https://github.com/jonathan-vella/landinglens/pull/39) / `c8fe279a317d2e6eec1f6078d37dee4ab8660343` |
| LL-25 / #28 | [#41](https://github.com/jonathan-vella/landinglens/pull/41) / `fcb58a4a5f3706ad51e6ade69cbecb1e073d7644` |

LL-25 adds the installed licensed-corpus/review/replay/retirement workflow.
The final local exact-wheel run passed 144 of 145 tests, with one Windows
symlink-privilege skip; real existing Bicep, static/type/dependency checks passed.
That increment's matrix has four automated predicates and all 255 entries. Six
corpus controllers remain symbolic; no complete AVM/ALZ compatibility or
live-control verification follows from these results. The reconciliation passed
all eight actual checks and merged; #28 is closed. #40 remains separately tracked:
its initial live run found an assignment-filter defect, now covered by a
regression fix merged in [#42](https://github.com/jonathan-vella/landinglens/pull/42)
as `6139ba1f20e2a6d2adca6e6f86e85e8ec1e5490c`. The exact installed rerun completed:
293 HTTP 200s, zero HTTP failures, 98 resources, original policy timestamps and
all report workflows. #40's acceptance record preserves the initial failure and
the verified fix, not a claim of full tenant/control visibility. Private
identities/evidence remain outside Git; authorization and ancestor-definition
gaps remain explicit. No mandatory backlog gate remains blocked.

## Original baseline work items

| ID | Work item | Prerequisites |
|---|---|---|
| [LL-01](https://github.com/jonathan-vella/landinglens/issues/1) | Verify Microsoft references and build the checklist inventory | None |
| [LL-02](https://github.com/jonathan-vella/landinglens/issues/2) | Bootstrap the standalone project and prove parser feasibility | None |
| [LL-03](https://github.com/jonathan-vella/landinglens/issues/3) | Define versioned assessment contracts and resource identity | LL-01, LL-02 |
| [LL-04](https://github.com/jonathan-vella/landinglens/issues/4) | Prove the vertical slice and agree the automation matrix | LL-01, LL-02, LL-03 |
| [LL-05](https://github.com/jonathan-vella/landinglens/issues/5) | Build the source-backed checklist catalog and control mappings | LL-04 |
| [LL-06](https://github.com/jonathan-vella/landinglens/issues/6) | Implement raw Terraform and optional plan evidence adapters | LL-04 |
| [LL-07](https://github.com/jonathan-vella/landinglens/issues/7) | Implement Bicep and ARM evidence adapters | LL-04 |
| [LL-08](https://github.com/jonathan-vella/landinglens/issues/8) | Implement read-only Azure evidence collection | LL-04 |
| [LL-09](https://github.com/jonathan-vella/landinglens/issues/9) | Implement evaluation and planned-versus-observed comparison | LL-03, LL-04, LL-05 |
| [LL-10](https://github.com/jonathan-vella/landinglens/issues/10) | Implement JSON, Markdown and HTML report renderers | LL-04 |
| [LL-11](https://github.com/jonathan-vella/landinglens/issues/11) | Integrate CLI workflows and end-to-end assessment | LL-06, LL-07, LL-08, LL-09, LL-10 |
| [LL-12](https://github.com/jonathan-vella/landinglens/issues/12) | Validate, document and prepare the advisory release | LL-11 |

## Execution sequence

### 1. Establish reference truth and technical feasibility

- **LL-01:** Verify the actual Microsoft design areas, checklist schema,
  licensing and provenance; retain every imported item's disposition.
- **LL-02:** Establish the package and prove source parsing against a
  representative module-based ALZ configuration, including explicit local
  module snapshots and honest missing-module outcomes.

These items can proceed independently. Their source inventory and bounded
feasibility evidence established the gate. The source-backed catalog is now
implemented; complete parser/interpreter coverage is not claimed.

### 2. Establish contracts and the vertical-slice gate

- **LL-03:** Define versioned catalog, evidence and result contracts, including
  explicit scope and cross-mode identity rules.
- **LL-04:** Demonstrate representative controls end to end using raw
  Terraform, saved observed evidence and all three report formats. Obtain
  acceptance of the initial automation matrix before full expansion, under
  the owner's explicit delegation to Autopilot.

The accepted matrix must identify actual source-backed controls, applicable
evidence modes and tests. It must include automated coverage across all three
input modes; areas without automation remain explicitly visible. An all-manual
catalog is not a completed release.

### 3. Expand coverage and evidence modes

- **LL-05:** Import the complete reviewed checklist inventory and implement the
  accepted control mappings.
- **LL-06:** Extend raw Terraform analysis and optional plan ingestion.
- **LL-07:** Add Bicep/ARM evidence.
- **LL-08:** Add explicitly scoped, read-only Azure collection.
- **LL-09:** Extend evaluation and identity-safe planned/observed comparison.
- **LL-10:** Extend the JSON, Markdown and HTML renderers.

LL-05, LL-06, LL-07, LL-08 and LL-10 can proceed independently after the
vertical-slice checkpoint. LL-09 also depends on the catalog and contracts.

### 4. Integrate and validate

- **LL-11:** Wire the installed CLI and demonstrate the agreed end-to-end
  scenarios and automation matrix.
- **LL-12:** Complete clean-environment checks, advisory CI and user-facing
  documentation; record any separately authorized live smoke-test results.

## Release gates

- Microsoft alignment is not claimed until the referenced sources and actual
  upstream checklist have been verified.
- Every imported item has provenance and a visible disposition; unsupported,
  manual or unknown items are not hidden.
- The accepted automation matrix has passing positive and negative fixtures
  for every committed control/evidence-mode combination.
- Planned and observed results remain separate; unresolved identities are not
  compared, and incomplete inventories do not establish absence.
- Reports agree on outcomes and coverage, disclose incomplete evidence, and
  do not expose credentials or sensitive parameter values.
- Tests run without production credentials. Live Azure access, deployment,
  package publication and other consequential actions require their own
  authorization.
