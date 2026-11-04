# Implementation plan: standalone Azure Landing Zones assessor

## Problem and approach

Create a standalone, advisory-only CLI that compares planned or deployed Azure infrastructure with Microsoft Azure Landing Zones guidance. Organize the checklist and reports by the verified Microsoft design areas.

Use a versioned, source-backed control catalog; normalize evidence from Bicep/ARM, raw Terraform source, optional Terraform plan JSON and read-only Azure collection; then evaluate and report through one shared engine. Preserve planned and observed results separately. Missing evidence, unresolved expressions and unsupported controls must never become passes.

This is the approved implementation plan. The initial LL-01/LL-02 increment
established the prerequisites below. The owner subsequently authorized
end-to-end implementation, feature-branch push and one ready PR, and delegated
LL-04 matrix acceptance to Autopilot. The subsequent completion authorization
permits additional scoped PRs, merges after passing checks and acceptance-backed
issue closure. Publication, deployment and live Azure collection remain excluded.

Original research basis: an earlier report retained in the planning session,
not included here. Implementation now uses the retrieved, pinned sources in
[`references/2026-11-04`](../../references/2026-11-04/review.md), not assumptions
from that report.

## Next increment: trustworthy automation and usable reviews

Status: planning update requested on 2026-11-04; the work below is **not
implemented**. It extends, rather than reopens, the completed LL-01-LL-12
baseline. The [PRD](prd.md#next-increment-requirements) and
[backlog](backlog.md#next-increment-work-items) track the same scope.
This request covers planning, review and issue creation, not execution of
these implementation tasks or authorization to access Azure.

The immediate priorities are offline preflight, actionable unknowns and
human-review preparation. Improve the existing static reports and source
maintenance in parallel; grow verified controls without adding a second
evaluator, hosted application, database or general-purpose rule language.

### Research decisions and evidence

- The pinned [Microsoft ALZ checklist](https://github.com/Azure/review-checklists/blob/f131b93418892102b00c247fd9cf685e3d356522/checklists/alz_checklist.en.json)
  contains 255 items and 49 nonempty `graph` fields, not 49 verified controls.
  B03.02 is an inventory query; B04.01 uses a hub-name heuristic and does not
  return canonical `id` plus boolean `compliant`. Audit queries before reuse.
- In that same snapshot, D07.06 explicitly compares `threatIntelMode` with
  `Deny` and D07.07 compares `intrusionDetection.mode` with `Deny`, making
  them plausible narrow candidates, not verified new controls.
  G02.03, G04.02 and F01.08 have no `graph` text in that reviewed JSON.
- Use one deterministic Python evaluator after normalization. Prefer explicit
  ARG/ARM/Policy evidence; keep assignments, exemptions and original-time
  PolicyStates separate. [ARG visibility](https://learn.microsoft.com/en-us/azure/governance/resource-graph/overview)
  can be partial without a warning; paging does not prove authorization.
- Azure MCP is optional. Its reviewed [registry](https://github.com/microsoft/mcp/blob/deb78ee37b1da6930668c51db397afaaad555861/servers/Azure.Mcp.Server/src/Resources/registry.json)
  proxies ARM to a remote service. The discovered `execute_query` schema had
  no explicit tenant/subscription/MG fields; public source and installed tool
  versions were not established as identical. No live behavior was verified.
- Borrow navigation, rule transparency and export organization from
  [the ALZ documenter](https://github.com/GetToThe-Cloud/documenter-azure-landingzone/tree/ee446fc90805b723f6ea0d40a85ea0052a6e6b5e).
  Do not import its count-based maturity scores as compliance predicates,
  split PowerShell/JavaScript evaluators or local authentication server.
  Retain MIT notices for substantial copied/adapted portions.
- Monitor upstream revisions and prepare candidate diffs; never replace the
  installed catalog at runtime. Start with weekly detection and manual
  dispatch; ten-working-day triage is a proposed operating target, not a
  claim of implemented monitoring or source currency.
- Improve self-contained HTML over the existing sanitized projection.
  Browser code may filter/sort, but cannot recalculate technical outcomes.
  No CDN, external fonts, browser credentials, live fetches or hosted service.

### Scope, sequencing and gates

Work IDs LL-13-LL-25 are distinct from GitHub issue numbers. The backlog
records their actual issue links and prerequisites. Unless marked optional,
the tasks below define this increment; no completion claim is made by this
planning update.

1. Establish controlled contract/catalog evolution (LL-13). In parallel,
   implement actionable diagnostics (LL-15), offline preflight (LL-14),
   review the automation queue (LL-19) and strengthen CI (LL-24).
2. Use the evolved contracts for human review (LL-16), reports (LL-17) and
   reviewed source maintenance (LL-18). Keep these small, independent CLI
   workflows rather than a new application.
3. Implement scoped collection (LL-21) against the reviewed matrix, then
   promote the first control wave end to end (LL-20). Prepare portable replay
   bundles (LL-23) once review bindings are available.
4. Run integrated offline acceptance (LL-25). Optional MCP feasibility
   (LL-22) must not block useful delivery; a justified not-ready decision
   completes the study, not a production adapter or live-verification claim.

No live Azure pilot, new authentication, role change, deployment, policy
evaluation trigger, remediation, module/tool installation or package/release
publication is authorized. A future live pilot needs explicit scope, existing
approved credentials and evidence-retention permission. It is not a mandatory
offline-release dependency and does not get a misleading executable issue.
Existing non-goals and advisory exit behavior remain in force.

### Bounded work and acceptance criteria

The numbered criteria below are the issue acceptance contract, not suggestions
to omit during implementation.

#### LL-13: Evolve catalog lifecycle and review bindings

1. Define explicit supported-version compatibility for existing 1.0 documents
   and new lifecycle/review fields. Retain old fixtures and historical replay;
   never synthesize missing reviewer, content or scope bindings as verified.
2. Retain removed upstream GUIDs as retired records with reviewed supersession
   where applicable. Active/current denominators exclude retired controls;
   historical catalogs remain immutable and reproducible.
3. Bind new manual/exception review records to control-content hash, scope,
   reviewer attribution, evidence reference and validity. Use an explicitly
   supplied opaque reviewer label, not a directory lookup or required email.
   Changed/unbound
   records remain visible and require review; attribution is not authenticated
   identity proof. Preserve technical outcomes independently of exceptions.
4. Provide a reviewed version/matrix change path for legitimate predicate
   changes without a generic downgrade override. Wire validation, refresh,
   evaluation, comparison and every report; mixed versions/rules cannot create
   spurious drift. Test retirement, changed wording, stale bindings and old data.

#### LL-14: Add offline preflight

1. Add a documented preflight/doctor CLI workflow for an explicitly selected
   input; check permitted paths, snapshot hashes, scope/identity prerequisites,
   supported provider mappings and existing compiler availability.
2. Emit machine-readable and human-readable readiness with actionable reasons,
   distinguishing missing requirements, unsupported capabilities and warnings.
3. Never install, restore, fetch modules, contact Azure or initiate login.
   Do not execute IaC; any compiler version probe is bounded and explicit.
4. Exercise installed CLI success/failure/partial cases on supported runtimes;
   no preflight success may imply complete interpretation or Azure readiness.

#### LL-15: Explain unresolved evidence

1. Map existing reason codes to bounded, specific explanations and required
   evidence, including missing snapshots, unresolved identity, stale facts,
   denied reads, partial inventory and unsupported expressions.
2. Preserve stable reason codes, technical outcomes and sanitized provenance
   across JSON/Markdown/HTML and CLI diagnostics; do not dump source values.
3. Explain safe next actions without executing them, weakening validation,
   granting permissions, suggesting implicit downloads or claiming certainty.
4. Test every documented reason and unknown/unrecognized codes; retain the
   code and an explicit unsupported-explanation notice rather than hiding it.

#### LL-16: Prepare attributable human reviews

1. Generate deterministic manual-evidence and exception templates for explicitly
   selected unresolved controls/scope, using LL-13 bindings and LL-15 guidance.
2. Leave outcome, rationale, reviewer and supporting evidence unasserted until
   supplied; generated templates cannot be ingested as completed attestations.
3. Validate completed records, conflict/duplicate handling, expiry and changed
   control content. Do not select an arbitrary last matching record.
4. Keep review ownership/status and exception disposition separate from technical
   evidence; test import and every report without a service, identity provider
   or automatic GitHub issue/message creation.

#### LL-17: Improve self-contained HTML reports

1. Build summary, design-area, findings, control detail, review and provenance
   views from the existing sanitized projection; retain all active dispositions
   and explicitly present retired/historical entries under LL-13 semantics.
2. Show control versus resource counts, completion, assessed-subset pass rate,
   automated coverage, inventory visibility and freshness separately.
3. Add accessible keyboard/filter/expand navigation and print CSS; useful content
   remains without JavaScript. No network assets, duplicate evaluator or raw
   evidence dump; validate links and safely embed any client-side data.
4. Test format/model parity, malicious strings, minimized presentation-only mode,
   no external requests and representative offline/browser/print behavior.
   Do not claim PDF byte reproducibility or introduce a PDF engine by default.

#### LL-18: Detect and review source changes

1. Reuse maintainer snapshot/build utilities for weekly/manual public-source
   detection, candidate acquisition and hashes/license retention, not runtime
   refresh. Separate last successful poll, semantic review and pending changes.
2. Diff GUID additions/removals, text, category, applicability, links, queries,
   schema, taxonomy and license. Flag display-ID collisions and same-GUID edits.
3. Use LL-13 retirement/review semantics; promotion requires reviewed PR/matrix
   evidence. Preserve prior source/catalog bytes and stale-attestation impact.
4. Test upstream failures, malformed/changed schema, GUID conflicts, removals and
   deterministic generation. Failed polling retains the known catalog and an
   explicit warning; the monitor never auto-merges or executes upstream queries.
5. Default to read-only GitHub permissions and downloadable candidate/diff
   artifacts. A maintainer opens the promotion PR; do not create credentials or
   grant bot write access. Automated PR writing is deferred pending separate
   approval. Treat upstream data as untrusted and pin workflow dependencies.

#### LL-19: Audit automation candidates and define the successor matrix

1. Classify all 49 pinned query-bearing entries by GUID as direct predicate,
   relational check, heuristic or evidence-only; validate output types/identity,
   applicability, missing-value behavior, permissions and population semantics.
2. Also review G02.03, G04.02 and F01.08, which lack upstream query text. Record
   compound/child-resource/inheritance/criticality limits, not invented passes.
3. Propose D07.06 and D07.07 as the bounded first wave, subject to verified
   enum/SKU/API/provider semantics. Name each committed control/mode, positive,
   negative, unknown/error/not-applicable cases and exact source/version evidence.
4. Accept and record a successor matrix under the existing delegated acceptance
   authority; preserve the two-control baseline if candidates fail review.
   A missing viable candidate is an explicit coverage gate, not authority to
   substitute heuristics or silently reduce promised modes. Future candidate
   implementation remains deferred until a separate reviewed matrix/task.

#### LL-20: Implement the accepted first control wave

1. Implement only LL-19's accepted first-wave predicates through the existing
   engine and reviewed adapter mappings; add only needed typed enum and
   applicability operations, not a general executable expression language.
2. Wire raw Terraform, Bicep/ARM, optional plan and observed modes precisely as
   committed in the matrix; do not infer provider defaults or capability/SKU.
3. Demonstrate true/false/unknown/error/not-applicable, missing/partial/stale
   evidence and identity-safe comparisons through the installed CLI.
4. Update the catalog/matrix/user docs and all report formats; preserve the
   original controls and entire inventory. LL-19/LL-21 evidence must precede
   promotion; no new mapping is live-verified by mocked tests.
5. If LL-19 accepts no viable first wave, leave this issue blocked with the
   precise gap and request an explicit coverage decision. Do not close it as
   implemented or mark LL-25 complete on the strength of a research decision.

#### LL-21: Extend explicitly scoped observed collection

1. Review and pin exact ARG, ARM detail/child-resource and existing PolicyStates
   operations/versions and required permissions for the committed matrix.
   Collect only approved properties and keep policy evidence categories distinct.
2. Require explicit scope; validate continuation destinations and returned
   identities. Preserve pages/truncation, bounded retry/errors and collection
   versus policy-evaluation times; ARG eventual consistency remains explicit.
3. Treat pagination completion separately from authorization coverage. Missing
   properties, partial visibility and incomplete child inventories remain
   unknown/inaccessible, not false, absent or automatically not applicable.
4. Use injected transports for multi-page, truncated-without-token, forbidden,
   partial, throttled and stale cases, and verify offline installed workflows.
   No live calls, triggerEvaluation, generic actions or authentication changes.

#### LL-22: Evaluate optional Azure MCP transport

1. Inspect pinned source and available metadata without Azure resource calls.
   Record native versus proxied tools, discovered schemas, credential/cache/
   telemetry boundaries and read-only plus exact-tool allowlist requirements.
2. Define contract tests for explicit scope, structured facts, identity,
   completeness/paging, errors, original-time freshness and schema drift.
   KQL filters are not proof of authorization or transport scope.
3. Produce an evidence-backed ready/not-ready decision. Missing scope/output
   evidence stays a documented blocker; mocks do not prove remote behavior.
4. Do not install/start/authenticate new tooling or implement a production
   adapter under this study. A later adapter/live pilot needs its own scoped
   issue and any excluded-action authorization; LL-25 does not depend on it.

#### LL-23: Add opt-in sanitized replay bundles

1. Define a bounded local bundle with catalog/rule versions, sanitized normalized
   evidence, safe invocation metadata, hashes and bound reviews/exceptions;
   no credentials, raw variable files, source trees or ambient environment.
   Sanitize all included metadata/review text and pseudonymize reviewer labels
   by default without exporting the mapping; require explicit opt-in to retain
   attribution. Disclose that replay retains scoped resource identities and is
   not an anonymized report; never upload or share the bundle automatically.
2. Demonstrate offline semantic replay at an explicit recorded evaluation time
   from the installed wheel outside the checkout. Preserve outcomes, identities,
   freshness and coverage; do not claim identical generated timestamps/HTML bytes.
3. Label minimized exports presentation-only, not replayable. Incomplete evidence
   remains incomplete; unavailable historical artifacts fail explicitly.
4. Validate manifest paths, entry/size limits, hashes and schema before import;
   reject traversal/links/conflicts and prevent overwrite outside the selected
   destination. Test tampering, malformed bundles and privacy sentinels.

#### LL-24: Strengthen invariants and installed-wheel CI

1. Add deterministic generated/invariant tests for unknown propagation, strict
   types, redaction, bounded expansion and loss of evidence without manufactured
   passes. Reuse unittest first; justify any additional dependency separately.
2. Automate building a wheel and installing that artifact in a clean environment
   outside the checkout; verify the imported package location and dependencies.
3. Distinguish real-Bicep exercised versus unavailable jobs and preserve skip
   reasons. Require at least one demonstrated existing-compiler integration job
   before claiming compiler coverage; never auto-install/restore Bicep.
4. Retain Windows/Linux Python 3.12/3.13, exact-byte fixture portability,
   formatting/lint/types and advisory findings exit behavior. Do not silently
   turn optional environment checks into a false green coverage claim.

#### LL-25: Reconcile the next increment offline

1. Reconcile each mandatory issue AC to merged code, tests, docs and actual CI;
   optional LL-22 and a separately authorized live pilot are not release gates.
2. Run an explicitly supplied, licensed/redacted ALZ reference corpus plus existing
   fixtures through installed workflows. Record supported versus unresolved
   behavior and review false-pass/unknown cases; never fetch modules implicitly.
3. Exercise preflight, diagnostics, review import/expiry, refresh/retirement,
   rich reports, replay and the accepted cross-mode matrix end to end.
4. Record clean-wheel/static/dependency checks, supported CI/compiler coverage
   and limitations. Close new issues only after their criteria and merged
   evidence justify it; no package publication or live-verification claim.

### Deferred work and completion boundary

Do not implement the documenter's maturity scoring, a hosted portal, Power BI,
deployed workbooks, PDF tooling, arbitrary KQL execution, all 255 automated
controls or exhaustive IaC interpretation. G02.03/G04.02/F01.08 enter reviewed
discovery in LL-19, not an unbounded implementation promise in LL-20.
An MCP adapter and real-tenant pilot require later explicit go/no-go work.

This increment is complete only when mandatory LL-13-LL-21 and LL-23-LL-25
have merged acceptance evidence, all active imported recommendations remain
visible, historical assessments remain reproducible and exclusions remain
truthfully labelled. Creating issues or merging this planning update does
not satisfy those implementation criteria. A failed LL-19 coverage gate leaves
LL-20/LL-25 blocked until an explicit revised scope/matrix decision; it does not
silently waive automated-control expansion.

### Planning review: 2026-11-04

The requested rubber-duck review challenged the draft before PRD/backlog
synchronization. Applied corrections: explicit failed-candidate blocking,
reviewer privacy throughout replay, artifact-only/read-only source monitoring
instead of unapproved bot write access, and source-backed candidate rationale.
The compiler-availability gate remains explicit: unavailable tooling cannot
be presented as exercised CI coverage, and no installation fallback is allowed.

The full research scope (automation, source maintenance, optional MCP and static
presentation) plus the subsequent usability recommendations is included because
the owner's planning request followed both discussions. This does not authorize
implementation or excluded actions. No owner decision is needed merely to file
the offline work; future live access, bot write permissions or a failed coverage
gate still requires an explicit decision rather than assumed consent.

## Implemented release baseline: 2026-11-04

The accepted [automation matrix](../automation-matrix.md) names **G04.01**
(storage secure-transfer flag) and **D07.18** (firewall-policy DNS-proxy flag).
Autopilot accepted this concrete baseline under the owner's explicit delegation,
including the documented reasons six design areas have no automated predicate.
All **255** original GUIDs remain visible: **2 automated, 211 assisted and
42 manual**. This supersedes candidate dispositions, not the original inventory.
The same evaluator and report model established by the LL-04 slice were extended;
there is no replacement engine or all-manual release.

| Issues | Implementation and executable evidence |
|---|---|
| LL-03 / #3 | Version-1.0 contracts, hash-bound identity maps, distinct evidence states, scope, freshness and disposition validity; `tests/test_contracts.py`. |
| LL-04 / #4 | Module-based Terraform slice, saved observed match/drift, missing-binding non-comparability, complete-only absence and three formats; `tests/test_assessment.py`. |
| LL-05 / #5 | Full packaged catalog with preserved provenance, uncertainty flags, explicit review-only refresh/diff and no silent matrix downgrade; `tests/test_workflows.py`. |
| LL-06 / #6 | Raw HCL AST evaluation, supplied snapshots, native dynamic blocks, precedence/scoping/bounds and optional separately hash-bound plan import; Terraform/AVM/workflow/matrix tests. |
| LL-07 / #7 | Existing-compiler no-restore Bicep, direct ARM/parameters, bounded expressions/copies and safe nested scope handling; Bicep/matrix/workflow tests. |
| LL-08 / #8 | Explicit-scope read-only collector, inherited assignments, exemption expiry, separate policy evaluations, bounded pagination/retries and visible partial authorization; injected transports in `tests/test_collection.py` only. |
| LL-09 / #9 | Six outcomes, independent manual/exception disposition, freshness rechecks and canonical identity/fact comparison; assessment/workflow tests. |
| LL-10 / #10 | JSON, Markdown and escaped self-contained HTML share counts, evidence and reasons; minimized reports are presentation-only. |
| LL-11 / #11 | Installed `catalog`, `assess`, `collect`, `compare`, `render` workflows and input guards; outside-checkout CLI workflow tests. |
| LL-12 / #12 | Pinned dependencies, clean-wheel validation, Windows/Linux Python 3.12/3.13 advisory CI and user-facing contracts/collection/limitations documentation. |

The full positive/negative matrix is in `tests/test_matrix.py`; real Bicep
compilation is local and explicitly skips where no existing compiler is
available. CI never installs/restores Bicep, deploys, publishes or collects Azure
data. Findings return success; software/input failures remain nonzero.

Local release verification used a wheel installed into a fresh environment,
not the editable checkout: **92 tests run, 91 passed, one Windows
symlink-privilege skip**. Both real-compiler positive/negative control cases and
outside-checkout installed workflows ran. Ruff lint/format, mypy and dependency
consistency passed. CI covers the declared Windows/Linux runtime matrix; its
actual run is linked from the delivery PR rather than assumed from local results.

The owner merged [PR #13](https://github.com/jonathan-vella/landinglens/pull/13)
on 2026-11-04; its four Windows/Linux Python 3.12/3.13 check jobs passed.
The subsequent contract-validation follow-up was committed locally as `4295773`.
Its installed-wheel verification ran
**95 tests, 94 passed, one Windows symlink-privilege skip**, with the existing
Bicep compiler; Ruff lint/format, mypy and dependency consistency also passed.
This supplements rather than replaces the historical release verification above.
The newer completion authorization supersedes the original one-PR allowance.

**Remaining capability limits:** the two predicates prove configuration flags,
not DNS routing, runtime encryption effectiveness or complete ALZ compliance.
The other 253 recommendations need human evidence. Six real-AVM controllers
remain symbolic; richer HCL semantics, JSON dynamic blocks, provider defaults
and complete AVM/ALZ graph support remain unproven. ARM runtime references,
linked templates, nested child declarations and inline deployments without
verified inner-expression semantics remain unknown/incomplete. Compiled bytes
bind resolved dependencies, but individual cached Bicep source hashes are not
available. Explicit plan IDs/maps are required for identity; source association
is a reviewed producer assertion, not proof Terraform generated the plan.
Live Azure behavior is unverified. Inventory completeness additionally requires
explicit producer authorization-coverage attestation; HTTP 200 is insufficient.

These are documented bounds of the approved advisory baseline, not fabricated
passes or removal of the all-mode requirements. All original acceptance
criteria below remain the reference. Issue closure requires the acceptance
reconciliation and merged evidence below; there is no remaining dependency-ready
implementation issue after LL-12 for that baseline; the next increment above
introduces separate work.

## Final acceptance reconciliation: 2026-11-04

The final audit read issues #1-#12 and their comments (none at audit time), the
PRD, backlog, implementation and executable fixtures. AC numbers below follow
each issue's acceptance-criteria order. The original LL-04 human-interruption
requirement was superseded by explicit owner delegation, not silently waived.
All evidence is offline, saved or mocked; live Azure verification is neither
required by these issues nor claimed.

| Issue | Acceptance criteria and concrete evidence |
|---|---|
| #1 | AC1: all 255 entries retain source revision/hash, retrieval time, item hash and disposition (`inventory.json`, `test_complete_inventory_and_per_item_provenance`). AC2-3: duplicate IDs, billing-label conflicts and unverified mappings are explicit; exact taxonomy points to retained source lines (`review.md`, `test_exact_taxonomy_is_traced_to_reviewed_excerpt`). AC4: reviewed HashiCorp precedence and Bicep no-restore semantics are documented and exercised. AC5-6: frozen manifest/ledger precede catalog consumption, with no certification claim; retained source/license hashes are checked by `test_source_and_license_hashes`. |
| #2 | AC1-2: literals, supplied variables, locals and isolated child defaults/inputs/outputs are checked in `test_terraform.py`. AC3-4: ALZ nested snapshots and the pinned AVM fixture resolve supported properties; missing snapshots remain unknown without execution/network. AC5: known/unknown count and map/set expansion, plus bounds, are tested. AC6: each precedence layer and interleaved overrides have executable checks. AC7: real existing Bicep success/unrestored failure and mocked missing-tool/timeout/invalid-output cases are in `test_bicep.py`. AC8: feasibility was demonstrated for the documented bounded subset; no stop decision or runtime substitution was needed. Dependency vetting is retained in `docs/dependencies.json`. |
| #3 | AC1: all six versioned document kinds have positive/negative fixtures (`test_all_contracts_positive_negative_version_and_required_fields`). AC2: distinct known/unknown/inaccessible/error/absent states and six result outcomes are tested. AC3-4: full scope/type/name/parent identities, module instances, same-name/different-scope targets, ARM-to-observed and unbound non-comparability are covered by contract, assessment and workflow tests. AC5-6: incomplete absence and duplicate/conflicting/hash-mismatched identity maps are rejected. `contracts.py` is shared by adapters, evaluator, comparison and rendering. |
| #4 | AC1: installed slice CLI checks consistent JSON/Markdown/HTML and advisory pass/fail behavior (`test_installed_cli_slice_advisory_exit_in_every_format`). AC2-4: the accepted matrix commits G04.01 and D07.18 across Terraform, Bicep/ARM and observed fixtures; all eight areas remain visible and six uncovered areas have explicitly accepted rationale. AC5-6: `docs/automation-matrix.md` records fixture-only evidence and delegated acceptance; `test_assessment.py` and `test_matrix.py` are the retained regression baseline, not a replacement engine. |
| #5 | AC1: GUID-set equality proves no imported item disappears. AC2: automated rules have reviewed references, explicit resource-type/applicability predicates and positive/negative tests. AC3-4: accepted IDs and all-mode outcomes are asserted; reviewed refresh rejects removal or silent rule downgrade. AC5: human-evidence entries stay in all-format reports. Evidence: `catalog.py`, packaged catalog, `test_inventory_guid_provenance_dispositions_and_no_matrix_downgrade`, matrix and report tests. |
| #6 | AC1: source-only module/snapshot fixtures exercise both accepted controls without a plan. AC2: outcome, derived identity, unresolved graph and distinct reviewed plan-binding tests are in matrix, assessment and workflow suites. AC3: README documents exact source/version/subdirectory/hash mappings and authorized roots. AC4: recursion, traversal and symlink-escape tests run; the symlink test can skip on Windows privilege denial and runs on Linux CI. AC5: analyzer has no subprocess/network execution path, and offline guards reject attempted execution during raw-source tests. |
| #7 | AC1-4: ARM parameters, literal/unknown/API-version/copy/nested-scope cases and actual no-restore Bicep positive/negative fixtures are exercised by matrix, Bicep and workflow tests; failed compilation never returns evidence. AC5: the compiler invokes only existing standalone `--version` and `build --no-restore --stdout`; no installer, restore, what-if or deployment path exists. Final hardening also rejects nested boolean/integer equality coercion and leaves unverified floating-point equality unknown. |
| #8 | AC1: injected-transport tests cover management-group inheritance, paging, retry limits, expired exemptions, denied configuration/inventory, stale evidence and partial descendants. AC2: assignment configuration and original-time policy-compliance records remain separate; assignment presence does not pass governance controls. AC3-4: explicit scope/token inputs only, no login/Graph/billing enumeration and no live test. AC5: exact operations/versions/actions are pinned in collection reference metadata and `docs/collection.md`; HTTP success alone does not establish authorization completeness. |
| #9 | AC1: repeated fixed-time assessment is deterministic. AC2: policy presence remains manual. AC3-5: comparison requires canonical identity and explicit facts; same-name/different-scope, stale, unbound and unmatched targets remain non-comparable across Terraform and ARM/Bicep-normalized modes. AC6: only current, complete, relevant, identity-resolved observed inventory establishes absence. AC7: active or expired exceptions retain technical failures. Evidence: `engine.py`, `comparison.py`, assessment and workflow tests. |
| #10 | AC1: all formats use one minimized result model and retain identical coverage/outcomes. AC2-3: malicious HTML is escaped, external assets are absent, raw properties/secure values are withheld and unknown metadata is filtered. AC4: incomplete inventory and zero denominators never claim estate-wide or 100% compliance. AC5: manual/unknown/inaccessible/stale reasons are retained. Evidence: `reports.py`, `test_formats_have_same_outcomes_and_escape_html`, cross-format/zero-denominator/redaction and staleness tests. |
| #11 | AC1-4: subprocess tests outside the checkout assess source-only Terraform, Bicep, saved observed evidence, render all three formats and compare canonical identities; ARM comparison has dedicated coverage. AC5: the final installed-source CLI matrix checks both controls' positive/negative outcomes for Terraform, ARM, saved observed and existing Bicep, retaining 255 controls/eight areas. AC6-7: offline execution guards, explicit collect credentials/scope, missing-tool and invalid-input failures, and completed-with-findings exit success are tested. Evidence: `cli.py`, matrix, CLI and workflow suites. |
| #12 | AC1-2: clean wheel installation, full offline tests, lint/format/types/dependency checks and actual Windows/Linux Python 3.12/3.13 CI verify the accepted matrix. AC3: CI runs a deliberately failing configuration assessment successfully; only software/input failures fail the job. AC4-6: inspected fixtures use synthetic scopes and injected transports, require no production credentials and do not publish/create repositories/deploy; README and collection docs explicitly distinguish mocked/saved evidence from live verification. New follow-up CI must pass before merge and issue closure. |

The audit found and fixed nested ARM equality type confusion and extended
installed-source CLI matrix coverage. The earlier contract-validation fix
rejects blank human attestations and malformed catalog/report inputs before
evaluation/rendering. Acceptance is limited to the reviewed two-control matrix,
not full ALZ compliance or complete Terraform/ARM interpretation.

Final local verification used an exact Git archive of `24e9c04`, built its wheel
without dependency changes and installed it with the reviewed development pins
into a new virtual environment through the approved feed. The imported package
was confirmed under that environment's `site-packages`, not an editable checkout.
**97 tests ran: 96 passed, one Windows symlink-privilege skip.** The actual
existing Bicep compiler exercised both controls and all-format source comparisons
with restoration disabled. Ruff lint/format, mypy, dependency consistency and
installed catalog validation passed. Wheel SHA-256:
`d3a573db14eb6b809fbf318b8ac3d5eba7b56763a439321e07f2feae4b297646`.

### Final delivery and issue state

[PR #15](https://github.com/jonathan-vella/landinglens/pull/15) merged at
2026-11-04T16:36:38Z as `7c6c3390907c9916f264a645f6359d7fdb48897d`.
Its [push checks](https://github.com/jonathan-vella/landinglens/actions/runs/41867916726)
and [PR checks](https://github.com/jonathan-vella/landinglens/actions/runs/41867991016)
each passed all four Windows/Linux Python 3.12/3.13 jobs before merge; there
were no outstanding reviews or review comments. Issues **#1-#12 were then
closed as completed**, with individual acceptance evidence, and their closed
states were verified through GitHub. No original implementation issue remains
open. Source snapshots, accepted coverage and historical verification results
remain unchanged.

Historical maintenance at acceptance: existing
[Dependabot PR #14](https://github.com/jonathan-vella/landinglens/pull/14)
tracks a setuptools build-backend update. GitHub reports two development-scope
advisories (medium and low) for the existing pin. They are not represented as
resolved by this acceptance delivery; dependency re-vetting/upgrades were not
silently folded into the original implementation scope.
Subsequently, PR #14 merged as `e9046fef649c8da49e9701a7a744f60afe9ba455`,
updating the build pin to setuptools 84.1.0. The current planning checkout
includes that change; this update does not claim a new vulnerability audit.

## Prerequisite results: 2026-11-04

The approved standalone location is this `landinglens` repository, separate
from APEX. Only issues [#1](https://github.com/jonathan-vella/landinglens/issues/1)
and [#2](https://github.com/jonathan-vella/landinglens/issues/2) were implemented in
the first increment. The following records that historical checkpoint;
downstream results and the delegated gate are recorded above. Issues remain open.

### LL-01 reference and inventory gate

- Snapshot **2026-11-04.1** contains immutable source revisions, actual retrieval
  timestamps, SHA-256 values, source licenses and reviewed provenance.
- CAF publishes eight design areas; the exact table labels and line citations
  are preserved. The ALZ technical site is implementation guidance, not a
  replacement design-area taxonomy.
- The complete checklist has **255 items and 255 unique GUIDs**. Display IDs
  `B03.02`, `D05.08` and `D07.12` are duplicated. The ledger uses upstream GUIDs
  and preserves IDs, JSON Pointers and item hashes; future identity stability
  must be reviewed rather than assumed.
- Every item has provenance and an explicit candidate disposition: **7 automated,
  206 assisted, 42 manual**. These are candidates, not an accepted automation
  matrix or implemented control coverage.
- Checklist billing terminology differs from the CAF taxonomy. That conflict,
  candidate category mappings, unverified per-item guidance mappings and
  unresolved platform/application applicability are explicit in the ledger.
- MIT/CC BY 4.0 retention and attribution requirements were reviewed and notices
  retained. Website assets and HashiCorp page prose are not redistributed.
- HashiCorp local variable precedence and Microsoft Bicep no-restore behavior
  were retrieved and reviewed, with sources and executable regression cases.

Artifacts: [review](../../references/2026-11-04/review.md),
[source manifest](../../references/2026-11-04/manifest.json),
[full disposition ledger](../../references/2026-11-04/inventory.json).
This establishes a reviewed source inventory, **not Microsoft certification,
complete recommendation mapping or live verification**.

### LL-02 project and feasibility gate

| Required case | Demonstrated outcome |
|---|---|
| Standalone Python package, tests, lint and type checking | Installable `src/alz_assessor` package, `alz-assessor` spike commands, standard-library unittest, Ruff and mypy configuration. Python 3.12.10 / Windows ARM64 exercised. |
| Dependency vetting | Exact runtime, build and development pins reviewed for licenses, compatibility, maintenance, configured feed availability and seven-day minimum artifact age; newer ineligible candidates rejected. See [dependency review](../dependency-review.md). |
| Raw Terraform literals, variables and locals | Parsed with python-hcl2's HCL2 AST; bounded allowlisted evaluation, forward locals, cycles and unresolved values tested. `.tf.json` is tested separately. |
| Local module inputs and outputs | Child defaults and caller inputs resolve in child scope; root locals, root tfvars and ambient environment do not leak into child modules. |
| Representative module-based ALZ input | Authored ALZ-shaped root resolves management group, shared Log Analytics, hub VNet and application resource-group properties using exact-version, hashed platform and nested management snapshots plus a local connectivity module. An additional fixture resolves workspace name/location/resource group/retention/SKU/local-auth properties from the unmodified Microsoft AVM workspace 0.5.1 snapshot, commit `b4ffa3ff87ac09ff6de3b7014c44b4d213aa302b`, through a versioned platform wrapper. |
| Missing modules and provenance | The same fixture without the nested mapping or snapshot yields explicit unknowns and incomplete coverage, while independent properties remain resolvable. No snapshots means no invented module resources. Hash/version mismatches and source/ref/subdirectory matching are tested. |
| `count` and `for_each` | Known integer count, string-set/map for_each and module instances expand; data-driven controls remain symbolic. File/byte, instance, expression and recursion bounds are explicit. |
| Variable precedence | Defaults < explicitly opted-in environment values < terraform.tfvars < terraform.tfvars.json < lexical auto files < ordered explicit var/file arguments. Ambient environment and HCP Terraform workspace variables are not read. |
| Bicep | Actual installed Bicep 0.47.16 compiled the local fixture with `--no-restore --stdout`. The unrestored registry module failed BCP190. Missing tooling, partial stdout on failure, invalid output and timeouts never yield resource evidence. |
| No implicit execution/fetch | Terraform spike has no command/network path; regression tests prohibit socket connections and subprocess invocation. Bicep uses only the existing standalone compiler with no-restore. No Terraform init/plan/apply, module fetch, restore, deployment or Azure collection was performed. |

Executable evidence lives in `tests/test_terraform.py`, `tests/test_bicep.py`,
`tests/test_avm_fixture.py`, `tests/test_references.py` and `tests/test_cli.py`; reproduction commands are in
the [README](../../README.md).

Local checks: 58 unittest cases run, 57 passed and one Windows symlink-creation
case skipped for missing platform privilege; the real Bicep integration case
ran. Ruff lint/format, mypy, dependency consistency and wheel build/installed-CLI
smoke checks passed. These checks use no production Azure credentials.

**Actual limitations, not scope reductions:** authored ALZ wrappers and synthetic
modules are complemented by one actual AVM resource-module snapshot, not the
complete ALZ pattern library. At this checkpoint ten AVM resource controllers
were symbolic; subsequent bounded operators and native dynamic blocks reduced
that to six and resolved the internet-access settings.
This proves supported properties, not full AVM compatibility. Unsupported
operators/functions, computed attributes, data sources and dynamic blocks remain
unknown at that checkpoint. Provider-schema-specific JSON nested-block normalization, Terraform
constraint/type validation and defaults, complete Bicep/parameter dependency
provenance remain limited; bounded ARM evaluation is now implemented. Windows symlink creation
can require privileges; that regression case explicitly skips when unavailable,
while traversal/authorized-root cases execute. Real Azure behavior is unverified.

The bounded prerequisite cases enabled LL-03, followed by LL-04 before broad
expansion. The owner subsequently delegated that gate; the accepted matrix and
downstream implementation are recorded above.

## Confirmed decisions

| Decision | Captured answer |
|---|---|
| Assessment scope | Both platform and application landing zones |
| Initial evidence support | Bicep/ARM, Terraform and deployed Azure |
| Terraform source support | Analyze raw Terraform source without requiring a plan |
| Delivery | Separate standalone project, not integrated into APEX |
| Enforcement | Advisory reports only |
| Interface | CLI with JSON, Markdown and HTML reports |
| Reference sourcing | Retrieve public Microsoft sources and pin reviewed snapshots |
| Implementation runtime | No user preference; recommendation below |

### Recommended implementation choices

- **Python**, packaged as an installable CLI. Raw Terraform parsing is an important requirement, so prove a maintained HCL2 parser and a bounded evaluator before broad implementation. `python-hcl2` is a candidate, not an approved or verified dependency.
- Working project/command name: `alz-assessor`; verify naming before publishing. No remote repository creation or package publication is authorized.
- No web application, database, hosted service, deployment engine or APEX runtime dependency.
- Use standard-library CLI facilities where sufficient; add only justified parsing, schema, Azure authentication/client and rendering dependencies.
- Validate licenses, maintenance, supported Python versions, approved feed availability and applicable seven-day package-age requirements before dependency pins or installation. Do not copy APEX version requirements automatically.
- Choose the new project location before implementation writes. It must remain separate from the current APEX checkout unless the user explicitly changes the delivery decision.

## Release-one scope and boundaries

### Included

- A catalog spanning all verified ALZ design areas, with explicit platform/application applicability.
- An inventory of imported checklist items and their automation/mapping disposition.
- First-class raw Terraform analysis, without requiring Terraform plan generation.
- Bicep compilation and direct ARM JSON ingestion.
- Optional supplied Terraform plan JSON as an additional planned-evidence source.
- Explicit management-group or subscription assessment scopes for read-only Azure collection.
- Manual-evidence intake and separately recorded exception dispositions.
- JSON, Markdown and self-contained HTML reports.
- A comparison mode for matching planned and observed evidence when identity and provenance are sufficient.
- Offline evaluation from previously collected evidence and pinned catalog snapshots.

### Not included

- Automatic remediation, deployment, Terraform apply, subscription vending or policy changes.
- Implicit Terraform init/plan/validate, backend access, provisioner execution or arbitrary source execution.
- Automatic retrieval of remote Terraform/Bicep modules.
- A complete Terraform, Bicep or ARM runtime interpreter.
- Exhaustive provider-default inference or claims that every Microsoft recommendation is automatable.
- Unapproved tenant-wide collection, Microsoft Graph permissions, billing permissions or interactive authentication.
- A web UI, assessment-driven CI blocking, remote repository creation or publication.

Every imported item remains visible even when manual, unsupported, unmapped or outside the current scope. Design-area alignment is not a promise of complete automation.

## Reference-verification gate

The original planning research was local-only. LL-01 has now retrieved and
reviewed the approved source inventory; see the frozen snapshot and limitations
above. Only the accepted matrix's two property mappings are verified; the other
recommendations retain their review requirements. The following gate remains
the procedure for future source versions.

During implementation:

1. Retrieve and review:
   - <https://azure.github.io/Azure-Landing-Zones/>
   - <https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/design-areas>
   - <https://github.com/Azure/review-checklists/blob/main/checklists/alz_checklist.en.json>
2. Verify exact design-area names, actual checklist fields and stable upstream identifiers.
3. Check source licenses and retention/reuse terms; retain only permitted material and necessary excerpts.
4. Record source URLs, revision/commit where available, retrieval time, checksums and review state.
5. Establish source precedence: documented guidance defines the recommendation; checklist items supply assessment inventory; effective tenant policy and organization-specific requirements remain separate mappings.
6. Verify upstream Terraform variable precedence/HCL semantics and Bicep compilation behavior before implementing them.
7. Freeze a reviewed catalog version. Future source updates produce an explicit diff and review, never a silent change to historical results.

Do not label draft mappings as Microsoft-aligned or substitute an ALZ policy baseline for the full design-area checklist.

## Implemented project structure

Paths are relative to this standalone root. Flat, purpose-specific modules avoid
unnecessary packages; executable contract validators replace an additional
schema dependency.

```text
pyproject.toml
README.md
references/
src/alz_assessor/
  cli.py
  contracts.py
  catalog.py
  terraform.py
  bicep.py
  sources.py
  arm.py
  plan.py
  azure.py
  engine.py
  comparison.py
  reports.py
  data/
tests/
  fixtures/
docs/
```

Keep modules small and purpose-driven. Introduce additional layers only when real implementation complexity requires them.

## Evidence and evaluation contracts

### Catalog control

Include a stable local ID, verified upstream references, primary design area, related areas if needed, platform/application applicability, recommendation, evaluation method, automation mode, evidence requirements and lifecycle state.

Maintain separate associations for Microsoft recommendations, effective tenant policies and organization extensions. Do not invent upstream item identifiers or treat every recommendation as mandatory policy.

### Evidence fact

Record source mode, logical/resource identity, resource type, property/value or relationship, known/unknown state, reason, collection time, scope, source location/query and available artifact hash.

Bind source, parameters, variables, module versions and compilation/plan artifacts where available. Hashes of different input sets must not be presented as matching provenance.

### Cross-mode resource identity

- Retain source identity separately from Azure identity. A Terraform module/resource/instance address is not an ARM resource ID.
- Use a canonical ARM resource ID for automatic planned-to-observed matching only when scope, resource type, name and any parent-resource identity are known. Apply documented ARM ID normalization while preserving the original ID.
- Planned evidence must carry explicit scope bindings where required: tenant, management group, subscription and/or resource group. Bindings supplied to `assess` or `compare` become part of the evidence provenance; never infer them from an ambient Azure CLI subscription.
- Derive planned Bicep/ARM IDs only from resolved resource declarations and bindings. Derive Terraform IDs only through tested, version-aware provider-resource mappings and resolved attributes, or an explicitly verified supplied ID.
- Allow an explicit identity-map artifact when derivation is insufficient. Bind its logical addresses, ARM IDs and scope to the source artifact hashes; validate duplicate, ambiguous and conflicting mappings.
- Do not match on resource name alone. Missing bindings, unknown names, unsupported mappings or unverified artifact relationships produce `not_comparable` with a reason, not a drift verdict.
- Evaluate an expected resource as absent only when its identity is established and the relevant live inventory is complete. Unmatched observed resources are not automatically violations.

### Assessment result

For each control and target, retain:

- Independent `planned` and `observed` outcomes.
- `pass`, `fail`, `unknown`, `error`, `manual` or `not_applicable`.
- Evidence links, evaluation method and reason codes.
- Freshness, target inventory completeness and confidence limitations.
- Exception disposition separately from the technical outcome.
- Drift only when the two evidence modes describe comparable identities and facts.

A stale fact is not a current pass. A policy assignment is not proof of resource compliance. A source-only finding is not proof of deployed behavior. An accepted exception does not convert a failure into a pass.

## Adapter requirements

### Raw Terraform source

Accept `.tf` and `.tf.json`, explicit variable files and supported conventional variable files. Parse using a maintained HCL2 parser, not regular expressions.

- Resolve literals, explicit defaults, supplied variables, locals, local-module inputs/outputs and a tested subset of pure expressions.
- Document variable precedence after checking upstream semantics. Do not read ambient environment values unless explicitly requested.
- Resolve local modules only within authorized roots; detect recursion, path traversal and symlink escapes.
- Expand `count`, `for_each` and dynamic blocks only when their controlling values are known and valid. Bound expansion and recursion to prevent runaway processing; exceeding a limit produces an explicit diagnostic.
- Preserve symbolic references and unknowns for data sources, remote state, computed attributes, unresolved module outputs and unsupported expressions.
- Do not fetch remote modules. An explicitly supplied local module snapshot can be analyzed with provenance recorded.
- Document a module-snapshot workflow for module-based ALZ inputs. An explicit manifest maps each module source, version/ref and subdirectory to an authorized local snapshot with a content hash; nested dependencies require their own resolved local sources or mappings.
- Without those snapshots, affected module resources remain unknown. Report unresolved module calls and the resulting coverage limitation; do not describe module-call metadata alone as meaningful resource-level assessment.
- Never infer omitted provider or module defaults without reviewed, version-specific evidence.
- Continue evaluating independently resolvable portions of the source; report incomplete graph coverage.
- Accept optional plan JSON without making it mandatory. Keep its provenance distinct; do not silently overwrite source findings or assume it matches the supplied source.

### Bicep and ARM

- Accept direct ARM template JSON with parameter inputs.
- Compile Bicep using an installed compiler, with implicit module restoration disabled.
- Missing compiler or unrestored modules produce an actionable input diagnostic. A failed compilation cannot produce invented resource evidence.
- Evaluate a documented bounded subset of ARM expressions; unresolved runtime references remain unknown.
- Record compiler version and source/parameter hashes. Do not install tools, restore modules, run what-if or deploy implicitly.

### Deployed Azure

- Require explicit subscription IDs or a management-group scope; do not assume entire-tenant access.
- Use existing authorized credentials without collecting tokens in chat or starting login automatically.
- Enumerate resources and scope relationships, applicable policy assignments/parameters/exclusions/exemptions, and relevant observed configuration.
- Collect policy-compliance results separately from policy definitions; retain evaluation times and per-resource evidence where needed.
- Handle pagination, inherited assignments, throttling, permission gaps and partial scope enumeration explicitly.
- Verify API operations, versions and least-privilege permissions during implementation.
- Keep tenant/billing/identity controls manual or unknown unless their required evidence and permissions are separately supported and authorized.
- Do not claim runtime effectiveness solely from configured resources.

## CLI and reporting behavior

Proposed command groups, subject to packaging verification:

- `catalog`: inspect, validate and explicitly refresh reviewed reference material.
- `assess`: assess an explicitly selected source or saved evidence bundle.
- `collect`: collect read-only Azure evidence for an explicitly selected scope.
- `compare`: compare compatible planned and observed assessment bundles.
- `render`: generate JSON, Markdown and HTML from the same assessment model.

Reports must:

- Group controls by verified design area, with platform/application applicability.
- Show planned and observed outcomes side by side where available.
- Include unmapped, manual, inaccessible, stale and unsupported items.
- Separate control counts from resource-instance counts.
- Show assessed-subset pass rate alongside assessment completion and inventory completeness.
- Never present an incomplete or unknown estate as compliant; an empty assessed denominator is not 100%.
- Include source/catalog versions, evidence timestamps and actionable explanations.
- Produce escaped, self-contained HTML with no external scripts or asset requests.
- Exclude credentials and sensitive parameter values; minimize and redact inventory as configured. Do not commit raw evidence automatically.

Advisory exit behavior:

- Completed assessments return success even when findings include failures, unknowns or pending manual items.
- Invalid invocation or an unrecoverable execution failure returns a nonzero exit with a clear diagnostic.
- Partial collection can produce a report, but must be conspicuous in run completeness and per-target results.
- No assessment outcome authorizes deployment.

## Implementation todos

Plan approval, the standalone repository location and all twelve implementation
work items have evidence above. The original task descriptions and acceptance
criteria below are retained for review. GitHub issue status is not changed
automatically by this document.

### 1. Verifying references and checklist inventory

Perform the reference-verification gate. Produce a reviewed source manifest, verified design-area taxonomy, inspected upstream item inventory and a mapping/disposition ledger.

Acceptance: every imported item has provenance and a disposition; source conflicts and unverified mappings are explicit. Use the actual inventory and automation feasibility to prepare the release coverage proposal, rather than assuming catalog size or per-area automation coverage in advance.

### 2. Establishing the standalone project and parser feasibility

Create the approved standalone package skeleton, supported-runtime policy, dependency manifest and test/lint configuration. Prove HCL2 parsing, bounded evaluation and local Bicep compilation before scaling control implementation.

Required feasibility cases:

- Literal Terraform attributes and supplied variables resolve as expected.
- Local-module input/output scope is correct.
- Unavailable remote modules remain unknown without network calls.
- A representative module-based ALZ root, including nested dependencies, resolves supported resource properties from explicitly supplied, versioned local module snapshots. Repeat without a required snapshot and verify explicit unknowns rather than fabricated passes.
- Known map/set `for_each` and integer `count` expand correctly; data-driven cases remain symbolic.
- Variable precedence is verified against documented behavior.
- Missing Bicep tooling/modules fails explicitly without fabricated output.

If a suitable parser or toolchain cannot meet these requirements, stop and return the actual constraint rather than switching runtime or reducing raw-source support silently.

### 3. Defining versioned assessment contracts

Implement catalog, evidence, assessment, manual-evidence and exception schemas/models. Implement the cross-mode identity contract, reason codes, freshness and scope-completeness rules.

Acceptance: positive/negative fixtures validate; unknown, absent, inaccessible and not-applicable states remain distinguishable. Identity fixtures cover scope-bound Bicep/ARM resources, Terraform local-module instances, explicit identity maps, missing bindings, duplicate mappings and same-name resources in different scopes.

### 4. Proving a narrow vertical slice and accepting the automation baseline

Before full catalog and adapter expansion, assess representative source-backed controls from one verified design area through a minimal end-to-end CLI path.

- Use raw Terraform with supplied ALZ module snapshots as the first adapter, because this is the principal source-analysis feasibility risk.
- Implement only the catalog entries, evaluator behavior and JSON/Markdown/HTML rendering needed for this slice. Later tasks extend these same components; do not create a disposable parallel engine.
- Demonstrate both satisfying and violating configurations, plus a missing-module unknown. Match a scope-bound planned resource to a saved observed-evidence fixture and demonstrate a real comparison and a non-comparable case.
- Record which behavior was established with fixtures; this checkpoint does not claim live-Azure verification.

At this checkpoint, obtain explicit acceptance of a concrete release automation matrix derived from the verified source inventory. The owner delegated this decision to Autopilot; the recorded matrix satisfies the original safeguards. List control IDs, design areas, applicable evidence modes, automated versus assisted/manual disposition, and required positive/negative fixtures.

Acceptance: the installed CLI produces consistent reports for the slice; the matrix names a nonempty automated control set with required coverage for Bicep/ARM, raw Terraform and observed Azure evidence. Any design area without automated coverage is explicitly identified and accepted, not silently omitted. An entirely manual/unmapped catalog cannot satisfy release acceptance.

If the verified catalog or feasibility results materially change expected coverage, return the actual limitation for a scope decision here. Do not silently relax the requirement for all three input modes, or reclassify committed automated controls as manual to ship.

### 5. Building the catalog and control mappings

Import the reviewed checklist inventory and implement control mappings incrementally across the design areas. Give every item an automation state: automated, assisted, manual, unmapped or not applicable to scope.

Acceptance: no imported item disappears; every active automated rule has a source reference, applicability predicate and tests. The implemented mappings satisfy the accepted release automation matrix; deviations remain visible and require an explicit coverage decision.

### 6. Implementing Terraform source and optional plan adapters

Extend the vertical-slice adapter to the raw-source contract above, including local modules, explicit module-snapshot mappings, variable resolution, symbolic unknown propagation and bounded expansion. Add a separate optional plan-JSON importer.

Acceptance: the agreed Terraform controls work against the representative module-based ALZ fixture without a plan or Terraform execution; expected rule outcomes, resolved resource identities, unresolved graph coverage and mismatched optional-plan provenance are tested. Document the snapshot preparation workflow and limits.

### 7. Implementing Bicep/ARM adapters

Implement source/parameter loading, explicit compiler invocation, ARM normalization and bounded expression handling.

Acceptance: literal/resolvable facts are assessed; compilation failures and runtime-only values cannot become passes.

### 8. Implementing read-only Azure collection

Implement explicit-scope inventory, resource relationships, effective-policy discovery and independent observed/compliance evidence collection.

Acceptance: management-group inheritance, pagination, expired exemptions, denied permissions, stale results and partial inventories behave correctly in mocked tests. Real-tenant smoke tests require separately authorized scope and credentials.

### 9. Implementing the evaluator and comparison engine

Extend the slice evaluator with applicability, evidence sufficiency, independent planned/observed evaluation, manual evidence, exception dispositions and comparison through the cross-mode identity contract.

Acceptance: deterministic fixture results; policy presence is never a compliance pass; source/live differences are not automatically contradictions. Tested identity matches enable comparisons across supported source modes; unresolved or ambiguous identities remain `not_comparable`, and incomplete inventories never establish resource absence.

### 10. Implementing consistent report renderers

Extend the slice's JSON, Markdown and HTML renderers to the complete common result contract.

Acceptance: all formats agree on outcomes/counts; HTML is escaped and self-contained; evidence redaction and incomplete-coverage warnings are tested.

### 11. Integrating the CLI end to end

Extend the slice CLI to all commands, adapters, evaluator behavior, evidence bundles and renderers. Document scope bindings, identity-map inputs, variable/parameter precedence, source-analysis limits, credential behavior and advisory exit codes.

Acceptance: the representative source-only Terraform scenario, a Bicep/ARM scenario, a saved live-evidence scenario and paired identity-resolved comparisons all produce the required reports from the installed package. The accepted automation matrix is exercised end to end, not just schema-validated.

### 12. Validating and documenting the release

Complete unit, schema, adapter, integration and report-consistency tests. Add an advisory CI workflow for this standalone project, usage examples, permission/retention guidance, supported-control matrix and source-refresh procedure.

Acceptance: package installation, lint/type checks and tests pass in a clean environment; every committed automated control/evidence-mode combination has passing positive/negative fixtures and meets the accepted automation matrix. No test requires production Azure credentials; authorized live smoke-test results are recorded when available.

Do not claim live-tenant verification if only mocked or saved evidence was tested. Do not publish a package, create a remote repository or deploy anything without separate authorization.

## Dependency graph

- Reference verification and project/parser feasibility can start independently.
- Contracts require verified reference structure and the project foundation.
- The narrow vertical slice requires contracts, verified candidate controls and the parser feasibility proof.
- Full catalog mappings, Terraform, Bicep/ARM, live collection and renderer expansion require the accepted vertical-slice checkpoint and release automation matrix.
- The evaluator requires catalog mappings and contracts.
- CLI integration requires all adapters, evaluator and renderers.
- Final release validation requires the integrated CLI.

Develop and test against normalized fixtures wherever possible so adapters and renderers can proceed independently without duplicated evaluation logic.

## Validation and release guardrails

Beyond feasibility tests, cover:

- Parse errors, invalid inputs, unsupported expressions, cyclic modules and resource-expansion limits.
- Representative ALZ module snapshots, nested module mappings, snapshot hash/version mismatches and missing snapshots.
- Cross-mode identity derivation, explicit scope binding, same-name resources across scopes, conflicting maps and non-comparable resources.
- Conditional applicability, pending manual evidence and expired exceptions.
- Unknown vs missing vs denied-permission evidence.
- Scope inheritance, complete pagination, throttling and unreadable subscriptions.
- Stale policy results and conflicting observations.
- Independent planned/observed results and unverified source-plan relationships.
- Zero assessed items and incomplete inventory metric denominators.
- Malicious strings in HTML, sensitive values in plans/parameters and output redaction.
- Reproducible offline evaluation against pinned catalog/evidence snapshots.
- Upstream checklist schema changes, retired items and source-update review.
- Regression against the accepted automated-control matrix; downgrading planned automation to manual/unmapped must not make release checks pass.

The plan is complete when these deliverables and boundaries are approved. Implementation is complete only after the standalone tool meets its acceptance criteria with its supported coverage and verification limits accurately documented.
