# LandingLens implementation backlog

This backlog tracks the complete [implementation plan](plan.md) and
[product requirements](prd.md). Each work item links to its GitHub issue;
issue status is the source of truth. Dependencies describe implementation
order, not additional authorization to access Azure or publish a package.

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

Current dependency-ready work: **LL-25 / #28 final reconciliation**. Its mandatory
implementation prerequisites are merged, including LL-21 in #36, the accepted
first wave in #37 and replay in #39. The optional MCP study concluded not ready
in #38 and does not block release acceptance.

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
The current matrix has four automated predicates and all 255 entries. Six
corpus controllers remain symbolic; no complete AVM/ALZ compatibility or
live-control verification follows from these results. The reconciliation passed
all eight actual checks and merged; #28 is closed. #40 remains separately tracked:
its initial live run found an assignment-filter defect, now covered by a
regression fix pending installed live reverification. Private identities/evidence
remain outside Git; authorization and ancestor-definition gaps remain explicit.

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
