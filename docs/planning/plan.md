# Implementation plan: standalone Azure Landing Zones assessor

## Problem and approach

Create a standalone, advisory-only CLI that compares planned or deployed Azure infrastructure with Microsoft Azure Landing Zones guidance. Organize the checklist and reports by the verified Microsoft design areas.

Use a versioned, source-backed control catalog; normalize evidence from Bicep/ARM, raw Terraform source, optional Terraform plan JSON and read-only Azure collection; then evaluate and report through one shared engine. Preserve planned and observed results separately. Missing evidence, unresolved expressions and unsupported controls must never become passes.

This is a plan only. No project, Azure resources, credentials, repository or deployment will be created during planning.

Research basis: an earlier research report retained in the original planning session; it is not included in this repository.

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

The research was local-only: the current Microsoft documentation and upstream checklist have not been verified. This is a prerequisite, not completed research.

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

## Proposed project structure

Paths below are relative to the future standalone project root.

```text
pyproject.toml
README.md
catalog/
schemas/
src/alz_assessor/
  cli.py
  references.py
  contracts.py
  evidence.py
  evaluators.py
  sources/
    terraform.py
    bicep_arm.py
    azure_live.py
  reports/
    json_report.py
    markdown_report.py
    html_report.py
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

All implementation tasks remain pending until plan approval and a standalone project location are established.

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

At this checkpoint, obtain explicit acceptance of a concrete release automation matrix derived from the verified source inventory. List control IDs, design areas, applicable evidence modes, automated versus assisted/manual disposition, and required positive/negative fixtures.

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
