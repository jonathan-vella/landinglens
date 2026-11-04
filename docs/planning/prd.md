# LandingLens product requirements

Status: advisory release baseline merged by the owner through
[PR #13](https://github.com/jonathan-vella/landinglens/pull/13) on 2026-11-04.
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
  assessment-based CI gate.
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
recorded in the linked evidence. There is no remaining dependency-ready issue
after LL-12. Additional automation or source/API versions require new review;
the existing accepted limitations do not imply unverified coverage.
