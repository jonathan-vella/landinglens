# LandingLens user guide

LandingLens assesses **supplied** Azure Landing Zones configuration or saved
observations. Its reports are advisory: they are not a compliance determination,
an Azure deployment, or a test of effective security and operations. Start with
the [offline quickstart](../README.md#try-an-offline-assessment), then use this
guide with your own inputs.

## Understand the results

- **Planned** evidence describes supported declarations in Terraform, ARM or
  Bicep. It does not prove what was deployed or how it operates.
- **Observed** evidence describes collected facts within a stated scope and
  time. A partial, stale or inaccessible inventory is not proof of absence.
- **Unknown** is not a pass. Manual decisions and exceptions remain separate
  from technical results; an exception does not turn a failure into a pass.
- With `--evidence-tiers`, **Verified** means an accepted configuration
  predicate had sufficient current evidence; it includes both passes and
  failures. **Signal** is context for review, not a pass. **Needs decision**
  and **Manual** identify remaining review work.
- The packaged catalog has 255 checklist GUIDs. Reports may contain multiple
  result rows per recommendation and target. Completion and the pass rate
  among assessed results use different denominators.

For detailed boundaries and source-qualified caveats, see
[what LandingLens does and doesn't prove](what-landinglens-proves.md) and the
[automation matrix](automation-matrix.md).

## Install

Python 3.12 and 3.13 are supported. From the repository root, using your
approved package index:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install .
.venv\Scripts\alz-assessor catalog validate
```

The commands below assume the environment is activated or `alz-assessor` is on
your path. Windows examples use backslashes; on Linux use `.venv/bin/activate`
and forward slashes. Normal assessment and reporting need no Azure credentials.

## Prepare inputs and assess

Start with `doctor` to check the selected input and prerequisites. Its `ready`,
`partial` and `blocked` states describe input readiness, not Azure readiness.
Use the same scope and input options for assessment. Findings and partial
evidence do not themselves cause a nonzero exit; invalid input or an
unrecoverable error returns 2.

### Observed evidence

The offline fixture can be assessed at its recorded time:

```powershell
alz-assessor doctor tests\fixtures\slice\observed.json --input evidence
alz-assessor assess tests\fixtures\slice\observed.json --input evidence --at 2026-11-04T00:00:00Z --evidence-tiers --output observed.assessment.json
```

Selecting a historical evaluation time reproduces a historical example; it
does not make the evidence current. For your own evidence, omit `--at` to
evaluate freshness at the current time. Optional live `collect` is a separate
operation requiring an existing ARM token and **separate authorization for the
exact scope and operations**. See [collection boundaries](collection.md); the
historical pilot is not authorization for your environment. Do not put tokens
in commands, documents, reports or chat.

### Terraform, ARM and Bicep

For Terraform, prefer a separately created plan JSON. LandingLens reads it; it
does not run Terraform:

```powershell
alz-assessor doctor plan.json --input terraform-plan --provider-version 4.50.0 --scope /subscriptions/00000000-0000-0000-0000-000000000001
alz-assessor assess plan.json --input terraform-plan --provider-version 4.50.0 --scope /subscriptions/00000000-0000-0000-0000-000000000001 --evidence-tiers --evidence-output planned.evidence.json --output planned.assessment.json
```

For raw Terraform, use explicit local snapshots and authorized roots:

```powershell
alz-assessor doctor .\infra --input terraform --snapshots snapshots.json --authorize-root .\modules --provider-version 4.50.0 --scope /subscriptions/00000000-0000-0000-0000-000000000001
alz-assessor assess .\infra --input terraform --snapshots snapshots.json --authorize-root .\modules --provider-version 4.50.0 --scope /subscriptions/00000000-0000-0000-0000-000000000001 --evidence-tiers --output terraform.assessment.json
```

For ARM JSON, supply parameters when applicable:

```powershell
alz-assessor doctor template.json --input arm --parameters parameters.json --scope /subscriptions/00000000-0000-0000-0000-000000000001
alz-assessor assess template.json --input arm --parameters parameters.json --scope /subscriptions/00000000-0000-0000-0000-000000000001 --evidence-tiers --evidence-output arm.evidence.json --output arm.assessment.json
```

Bicep requires an already-installed standalone compiler and restored local
modules; replace the example compiler path with your own:

```powershell
alz-assessor doctor main.bicep --input bicep --compiler C:\path\to\bicep.exe --parameters parameters.json --scope /subscriptions/00000000-0000-0000-0000-000000000001
alz-assessor assess main.bicep --input bicep --compiler C:\path\to\bicep.exe --parameters parameters.json --scope /subscriptions/00000000-0000-0000-0000-000000000001 --evidence-tiers --output bicep.assessment.json
```

Compilation uses `--no-restore`. LandingLens does not install compilers,
restore modules, log in, run Terraform, or deploy. Identity maps and plan/source
associations must be explicitly bound to supplied inputs; names alone are not
identities. See the [technical reference](technical-reference.md#assessment-workflows).

The [multi-region Bicep example](examples/bicep-multiregion-alz/README.md)
provides fictional governance, logging, firewall and VPN declarations and
offline baseline, defect and remediation scenarios. Its results are planned,
not observed Azure evidence.

### Compose and enrich evidence

To combine compatible normalized evidence bundles in an explicitly selected
scope, use `compose` before assessment:

```powershell
alz-assessor compose logging.evidence.json hub.evidence.json --scope /subscriptions/00000000-0000-0000-0000-000000000001 --output estate.evidence.json
alz-assessor assess estate.evidence.json --input evidence --evidence-tiers --output estate.assessment.json
```

Composition requires compatible modes and scope relationships; unrelated
subscriptions are not automatically one estate. Conflicts and unsupported
relationships remain explicit. Preserve the normalized evidence files if you
need review, composition or replay; an assessment report is not a replacement.

Saved policy and scanner exports can provide Signals:

```powershell
alz-assessor assess observed.evidence.json --input evidence --evidence-tiers --policy-evidence policy-export.json --scanner-evidence scanner-export.json --output enriched.assessment.json
```

`scanner-export.json` must be the documented **scanner-export wrapper**, with
provenance, mode, scope and explicit result-to-resource bindings; raw SARIF or
PSRule output alone is not accepted. The policy export also has a specific
wrapper and scope. See the [scanner](contracts.md#saved-scanner-evidence) and
[policy](contracts.md#policy-export-and-signals) contracts. Scanner and Policy
Signals are not automated passes. Only explicitly allowlisted queries can be
collected separately; see [query evidence](contracts.md#allowlisted-query-evidence).

### Compare planned and observed

```powershell
alz-assessor compare planned.assessment.json observed.assessment.json --output comparison.assessment.json
```

Comparison requires compatible assessment contracts and uses explicit identity,
scope and freshness bindings. Missing or stale bindings can yield
`not_comparable`, not drift. Use `--at` only to reproduce a historical comparison.
Minimized presentations cannot be compared.

## Review decisions

The local review workspace starts from **normalized evidence**, not a rendered
assessment:

```powershell
alz-assessor review serve estate.evidence.json --directory private-reviews --evidence-tiers
alz-assessor review serve private-reviews\revision-0002 --resume --directory resumed-reviews
```

Inspect the queue and evidence, then explicitly provide the decision, reviewer,
rationale, supporting evidence and validity. Bulk review and guided interviews
still require separate explicit outcomes. Saves create immutable revisions;
resume verifies saved hashes and preserves original evidence times. Use a new
directory, keep the loopback capability URL and files private, and stop the
server with **Stop local review** or Ctrl+C.

For file-based review, `review prepare` creates a blank scoped template;
`review validate` checks the completed record, and `assess --manual` or
`--exceptions` imports it. `interview inspect`, `interview prepare` and
`interview apply` support multi-control questions. Review migration across
catalogs is available with `review migrate`. See
[review contracts](contracts.md#review-workspace-version-10) and the
[technical reference](technical-reference.md#identity-manual-evidence-and-optional-plans).

## Render and explore

Render a saved assessment in the format you need:

```powershell
alz-assessor render estate.assessment.json --format html --minimize --output report.html
alz-assessor render estate.assessment.json --format markdown --output report.md
alz-assessor render estate.assessment.json --format json --output report.json
alz-assessor render estate.assessment.json --format csv --minimize --output tracker.csv
alz-assessor render estate.assessment.json --format xlsx --minimize --output tracker.xlsx
```

XLSX requires a new output file. SARIF and `pr-summary` are also available for
advisory CI; the [example workflow](examples/advisory-pr-workflow.yml) does not
grant repository or code-scanning permissions.

### Portable report canvas

Build a read-only explorer from one to eight saved **non-minimized** planned,
observed or comparison assessments:

```powershell
python tools\build_report_canvas.py --report "Planned" planned.assessment.json --report "Observed" observed.assessment.json --output-directory report-preview
```

Open `report-preview\index.html` in a browser or Copilot's Browser canvas.
Filters and navigation change the view, not the results or decisions. The
preview includes minimized presentations and HTML reports. Resource-record
counts are unavailable when the saved report does not retain those arrays;
this is not a count of zero. Use a new output directory. Add `--fictional`
only for demonstration inputs.

### Native Copilot canvas

In the GitHub Copilot App, open the repository's **LandingLens ALZ Workspace**
canvas and ask Copilot to load a saved assessment by path. The canvas can
filter findings and select a control. Its `stage_decision` action creates a
**draft, not saved or approved**; use the review workspace or file-based
workflow to validate and persist actual decisions. Opening the canvas without
loading an assessment does not populate it.

## Privacy and troubleshooting

Full evidence and reviews may contain resource identities, paths, topology,
reviewer names and review text. Treat them and the local capability URL as
private. `--minimize` removes selected sensitive fields for presentation, but
is **not** a guarantee of anonymity; inspect output before sharing. A minimized
presentation cannot establish identity for comparison or replay, and cannot be
used as the portable canvas's source assessment. Replay bundles also retain
scoped identities and are not anonymous.

If `doctor` reports `partial`, inspect its diagnostics rather than assuming
complete coverage. Missing compiler modules, unsupported expressions, absent
identity bindings and stale evidence remain unknown. For a reason code, run
`alz-assessor explain REASON`; use `--format json` for machine-readable output.
If a preview or XLSX destination exists, choose a new path. For detailed
schemas, limits and failure handling, see [contracts](contracts.md),
[collection](collection.md) and the [technical reference](technical-reference.md).
