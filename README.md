# LandingLens

Offline-first, advisory Azure Landing Zones CLI for assessing supplied IaC or
saved observed evidence. All 255 checklist GUIDs remain visible. The current
catalog has 12 accepted configuration predicates, 200 assisted recommendations
and 43 manual recommendations.

Virtual WAN adds an exact scoped ASPath configuration check and eight separate
blank decisions for scenario, topology, security, Insights, branch exceptions,
labels and capacity. These facts do not prove effective routing, filtering,
monitoring, complete regional coverage or free growth capacity; current Firewall
maximum scaling needs /22 hub space, not just the general /23 recommendation.

Resource/cost governance prepares scoped tag counts, dashboard structure,
capacity-group references and hierarchy context with seven separate blank
decisions. These do not establish cost attribution, monitoring health, identity
roles or available capacity; owner awareness and operating plans remain manual.

The NSG and route-count predicates are observed-only. Declared rules/routes do
not establish complete custom populations. Peering access is an explicit setting,
not proof of reachability; configured segmentation is not effective isolation.
The reviewed cohorts also prepare WAF/origin, DDoS/logging, explicit outbound and
hybrid-path evidence. Those facts are not protection, ingestion, enforcement,
failover or measured demand. Both D05.08 recommendations stay distinct.

DR addressing, DNS and Bastion review now includes minimized typed configuration
and ten separate blank decisions. Configured links, registration, zones or
Bastion presence do not prove resolution, record lifecycle, resilience or secure
access; workload DNS and multi-region strategies remain manual.

ExpressRoute monitoring/routing/failover adds eight separate blank decisions and
a strictly joined GatewaySubnet propagation configuration check. Missing flags,
unbound/ambiguous/out-of-scope tables and empty inventory cannot pass. Configured
monitors, alert routing and location labels do not prove health, ingestion,
physical independence, edge BFD or actual convergence/failover.

Read [what LandingLens does and doesn't prove](docs/what-landinglens-proves.md)
before interpreting results. [Detailed workflows](docs/usage.md),
[contracts](docs/contracts.md) and the [accepted matrix](docs/automation-matrix.md)
describe exact supported inputs and evidence requirements.

## Install

Use Python 3.12 or 3.13 and your approved package index. From this checkout:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install .
.venv\Scripts\alz-assessor catalog validate
```

Windows and Linux are supported. The examples below use Windows paths;
activate the installed environment or use its console-script path.

## Try an offline assessment

The supplied observed fixture is historical, so evaluate it at its recorded time:

```powershell
.venv\Scripts\alz-assessor doctor tests\fixtures\slice\observed.json --input evidence
.venv\Scripts\alz-assessor assess tests\fixtures\slice\observed.json --input evidence --at 2026-11-04T00:00:00Z --evidence-tiers --output assessment.json
.venv\Scripts\alz-assessor render assessment.json --format html --minimize --output report.html
.venv\Scripts\alz-assessor render assessment.json --format csv --minimize --output tracker.csv
.venv\Scripts\alz-assessor render assessment.json --format xlsx --minimize --output tracker.xlsx
```

XLSX requires a new output file. Findings, unknowns and manual work return exit 0;
invalid input or software failures return exit 2. Selecting a historical time
does not make the fixture current evidence.

## Use your own inputs

For Terraform, prefer a separately prepared plan JSON:

```powershell
alz-assessor doctor plan.json --input terraform-plan --provider-version 4.50.0 --scope /subscriptions/00000000-0000-0000-0000-000000000001
alz-assessor assess plan.json --input terraform-plan --provider-version 4.50.0 --scope /subscriptions/00000000-0000-0000-0000-000000000001 --evidence-tiers --output planned.json
```

LandingLens does not generate plans. Raw Terraform with explicit local module
snapshots remains the supported fallback. ARM JSON, an existing no-restore Bicep
compiler and saved observed evidence are also supported.
[Input preparation and identity binding](docs/usage.md#assessment-workflows)
explain the required flags; use your actual authorised scope.

## Triage and record decisions

Start from your current saved normalised evidence:

```powershell
alz-assessor review serve evidence.json --directory private-reviews --evidence-tiers
alz-assessor review serve private-reviews\revision-0002 --resume --directory resumed-reviews
```

The local workspace provides area progress, a tier/severity queue, evidence,
explicit bulk decisions and interviews. Supply reviewer, rationale, supporting
evidence and validity. Saves create immutable revisions and regenerate reports
and trackers. Resume verifies the saved hashes and preserves original evidence
times. Keep the local capability URL and identity-bearing files private.

## Evidence reuse and CI

Use `catalog crosswalk inspect --id G04.01` to inspect reviewed associations.
Attach saved Policy/PSRule/SARIF evidence with the documented wrapper contracts.
Only explicitly allowlisted queries can run through scoped collection. These
sources produce Signals, not automatic passes. See
[evidence reuse](docs/usage.md#assessment-workflows) and
[collection boundaries](docs/collection.md).

`--format sarif` and `--format pr-summary` support advisory CI.
The [example workflow](docs/examples/advisory-pr-workflow.yml) includes an
optional pinned SARIF uploader; repository permissions must already allow it.
Source polling retains candidates and a generated PR body when workflow PR
creation or safe auto-merge is blocked. Accepted catalogs are immutable
[Release assets](https://github.com/jonathan-vella/landinglens/releases),
never runtime auto-replacements.

## Development and history

[Development checks and parser details](docs/usage.md#install-and-check),
[dependency decisions](docs/dependency-review.md),
[delivery history](docs/planning/plan.md#catalog-delivery-history) and the
[current backlog](docs/planning/backlog.md#assessor-efficiency-work-items)
record supported behaviour, verification and outstanding blockers.
