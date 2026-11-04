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
Publication, deployment and live Azure collection remain excluded. GitHub is
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

**Next dependency-ready issue:** none after LL-12. The baseline is merged.
The contract-validation and final acceptance follow-ups are merged. The
criterion-by-criterion
[acceptance evidence](plan.md#final-acceptance-reconciliation-2026-11-04) governs
issue closure; open checkboxes alone are not evidence of missing implementation.

## Work items

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
