# LandingLens User Guide

This guide walks through the end-to-end workflow for assessing, reviewing, and documenting an Azure Landing Zone (ALZ) with LandingLens (`alz-assessor`).

For evidence boundaries and non-goals, read [What LandingLens does and doesn't prove](what-landinglens-proves.md). For JSON schema details, see [Contracts](contracts.md) and the [Automation matrix](automation-matrix.md).

---

## 1. Core Concepts

- **Complete Catalog Visibility**: Every assessment evaluates all **255 active ALZ checklist recommendations** across 8 design areas (`12` automated configuration predicates, `200` assisted recommendations with prepared machine context, and `43` manual recommendations).
- **Four Evidence Tiers (`--evidence-tiers`)**:
  - `Verified`: Deterministic configuration predicate evaluated against current, scoped machine evidence (`pass` or `fail`).
  - `Signal`: Machine context (prepared resource facts, Azure Policy states, PSRule/SARIF scanner runs, or allowlisted ARG queries) is present to assist human review, but never auto-passes a control.
  - `Needs decision`: Assisted control awaiting scoped evidence or human review.
  - `Manual`: Process, organizational, or operational recommendation requiring human attestation.
- **Explicit Scope & Content Binding**: Human decisions (`manual` and `exceptions`) are bound to an explicit Azure scope (`subscription`, `resourceGroup`, or `managementGroup`), a `control_sha256` content hash, and a validity window (`valid_from` to `valid_until`).

---

## 2. Installation & Setup

Use Python 3.12 or 3.13:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install .
.venv\Scripts\alz-assessor catalog validate
```

---

## 3. Step 1: Preflight & Normalize Inputs (`doctor` and `assess`)

Run `alz-assessor doctor` before assessing to verify paths, module snapshot hashes, provider versions, and parameter files offline without executing Terraform, Bicep, or Azure logins.

### Terraform Plan JSON (Recommended for Terraform)

Supports plans up to **32 MB** and **2,500 managed resources** (including default storage blob-service children):

```powershell
alz-assessor doctor plan.json --input terraform-plan --provider-version 4.50.0 --scope /subscriptions/00000000-0000-0000-0000-000000000001
alz-assessor assess plan.json --input terraform-plan --provider-version 4.50.0 --scope /subscriptions/00000000-0000-0000-0000-000000000001 --evidence-tiers --evidence-output planned.evidence.json --output planned.assessment.json
```

### Raw Terraform with Local Snapshots

```powershell
alz-assessor doctor .\infra --input terraform --snapshots snapshots.json --authorize-root .\modules --provider-version 4.50.0 --scope /subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-hub
alz-assessor assess .\infra --input terraform --snapshots snapshots.json --authorize-root .\modules --provider-version 4.50.0 --scope /subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-hub --evidence-tiers --output tf.assessment.json
```

### ARM Templates & Bicep (`--parameters` Placeholder Preflight)

When `--parameters` is supplied for `arm` or `bicep`, `doctor` inspects the JSON parameter file for unresolved ALZ Accelerator placeholders (`{{...}}`) and reports `accelerator_placeholder_unresolved` before compilation or evaluation:

```powershell
alz-assessor doctor template.json --input arm --parameters parameters.json --scope /subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-logging
alz-assessor assess template.json --input arm --parameters parameters.json --scope /subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-logging --evidence-tiers --evidence-output logging.evidence.json --output logging.assessment.json
```

### Saved Observed Evidence & Read-Only Collection

See [Collection boundaries](collection.md) for explicit-scope read-only collection (`alz-assessor collect`) using an existing bearer token environment variable.

---

## 4. Step 2: Compose Multi-Template Estates (`compose`)

Modular ALZ estates typically split management groups, logging, hub networking, and identity across separate templates or subscriptions. Use `alz-assessor compose` to merge `2–20` normalized evidence bundles of the same mode (`planned` or `observed`) into one estate-wide bundle:

```powershell
alz-assessor compose mg.evidence.json logging.evidence.json hub.evidence.json --scope /providers/Microsoft.Management/managementGroups/alz --output estate.evidence.json
alz-assessor assess estate.evidence.json --input evidence --evidence-tiers --output estate.assessment.json
```

- Template-local `logical_id` and `artifact_hashes` keys are automatically namespaced (`bundle-1:...`, `bundle-2:...`).
- Resources sharing the same canonical `arm_id` with identical normalized facts are deduplicated; conflicting declarations for the same `arm_id` emit a `conflicting_composed_resource` diagnostic and set `inventory_complete: false`.

---

## 5. Step 3: Enrich Assessments & Compare Drift (`assess`, `compare`)

### Management-Group Archetype Suggestions (`--archetypes`)

Attach an explicit management-group archetype binding file (`alz`, `platform`, `landingzones`, `corp`, `online`, `sandbox`, `security`, `management`, `connectivity`, `identity`) alongside `--evidence-tiers` to surface nonbinding `applicability_suggestions` (`requires_confirmation: true`):

```powershell
alz-assessor assess estate.evidence.json --input evidence --evidence-tiers --archetypes archetypes.json --output estate.assessment.json
```

### Policy, Scanner, and Query Signals

```powershell
alz-assessor assess estate.evidence.json --input evidence --evidence-tiers --policy-evidence policy-export.json --scanner-evidence psrule.sarif --output estate.assessment.json
```

### Planned vs. Observed Comparison (`compare`)

```powershell
alz-assessor compare planned.assessment.json observed.assessment.json --output comparison.assessment.json
```

---

## 6. Step 4: Triage & Record Human Decisions (`review`, `interview`)

### Interactive Local Review Workspace (`review serve`)

Launch the loopback-only review workspace from a saved normalized evidence bundle:

```powershell
alz-assessor review serve estate.evidence.json --directory private-reviews --evidence-tiers
```

Key workspace features:
- **Design-Area Progress Sidebar**: Click any design area to filter the queue; visual progress bars track `(total - remaining) / total` completion.
- **Interactive Queue Cards & Filters**: Filter by search text, design area, evidence tier (`Verified`, `Signal`, `Needs decision`, `Manual`), and severity (`High`, `Medium`, `Low`). Navigate with mouse clicks or `Alt+Up` / `Alt+Down`.
- **3-Tab Workflow Switcher**:
  1. **Single control**: Inspect structured prepared resource facts/subchecks, click **Insert prepared evidence summary** to cite machine context in `#evidence`, and save a `manual` or `exceptions` decision. Reviewer label and validity dates stay sticky when moving to the next unreviewed control.
  2. **Batch triage**: Record explicit per-control outcomes across up to **50** eligible `signal`, `needs_decision`, or `manual` controls in one atomic revision.
  3. **Guided interview**: Answer any of the **27** multi-control architecture questions (`question_bank`), review inline per-control evidence requirements, attach optional per-control `note` annotations (`<= 1,000` chars), and compile separate content-bound decisions.

Resume a previous session directory safely (verifying all saved file hashes):

```powershell
alz-assessor review serve private-reviews\revision-0003 --resume --directory resumed-reviews
```

### CLI Interview & Review Commands

```powershell
alz-assessor interview inspect
alz-assessor interview prepare estate.assessment.json --question private-service-paths --scope /subscriptions/00000000-0000-0000-0000-000000000001 --output interview.template.json
alz-assessor interview apply completed-interview.json --output manual.json
```

### Migrate Reviews Across Catalog Updates (`review migrate`)

When upgrading to a newer catalog version, carry forward unchanged bound reviews automatically and flag controls whose wording or requirements changed:

```powershell
alz-assessor review migrate manual.json --from-catalog old-catalog.json --to-catalog new-catalog.json --scope /subscriptions/00000000-0000-0000-0000-000000000001 --output migrated-manual.json
```

If a control's `control_sha256` changed between catalogs, inspect the field diff in `migrated-manual.json` (`migration.records`) and re-run with `--confirm-control <CONTROL_ID>` after verifying your decision still holds.

---

## 7. Step 5: Render Deliverables & Explore in Canvas

### Render Reports & Trackers (`render`)

```powershell
# Standalone HTML report (smart default collapse for non-failing controls, click-to-filter heatmap)
alz-assessor render estate.assessment.json --format html --output report.html

# Redacted public/shareable HTML report (strips scopes, resource IDs, reviewer names, and rationales)
alz-assessor render estate.assessment.json --format html --minimize --output report.minimized.html

# Markdown report (valid Markdown tables per design area + attributed review rationale)
alz-assessor render estate.assessment.json --format markdown --output report.md

# CSV and native Excel (.xlsx) trackers (includes Reviewer, Review rationale, and Review valid until columns)
alz-assessor render estate.assessment.json --format csv --output tracker.csv
alz-assessor render estate.assessment.json --format xlsx --output tracker.xlsx
```

### Portable Browser Report Canvas (`tools/build_report_canvas.py`)

Build a read-only multi-report explorer supporting `planned`, `observed`, and `comparison` assessments:

```powershell
python tools\build_report_canvas.py --report "Planned Hub" planned.assessment.json --report "Observed Hub" observed.assessment.json --report "Drift Comparison" comparison.assessment.json --output-directory report-preview
```

Open `report-preview\index.html` to filter by **Outcome**, **Design area**, **Severity**, **Evidence tier**, and **Comparison** (`drift`, `match`, `absent`, `not_comparable`), navigate with `ArrowUp`/`ArrowDown` and `/`, and inspect privacy-safe review status badges.

### Native GitHub Copilot App Canvas Extension (`.github/extensions/landinglens-canvas/`)

When working inside the GitHub Copilot App, the repository includes a project-scoped canvas extension (`landinglens` / **LandingLens ALZ Workspace**):
- Supports live agent actions: `load_assessment`, `filter_findings`, `select_control`, and `stage_decision` (non-committing draft staging labeled **Draft — not saved / not approved**).
- Uses a capability-token-gated loopback server with Server-Sent Events (`/events`), strict nonce-backed CSP, and Rampa theme tokens.
