# LandingLens workflows

For the short path, start with the [quickstart](../README.md).
[What LandingLens does and doesn't prove](what-landinglens-proves.md) defines
evidence guarantees and limits. [Catalog delivery history](planning/plan.md#catalog-delivery-history)
and the [accepted matrix](automation-matrix.md) retain version-specific decisions.
Commands below run from the repository root.

## Install and check

Supported release runtimes are Python 3.12 and 3.13; local execution uses
Python 3.12.10 / Windows ARM64. CI exercises Windows/Linux with both versions.
Newer Python versions are not yet a supported release target. Use your
approved package index; the dependency review used Microsoft's configured
package-feed proxy, with no public-index fallback.

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
.venv\Scripts\python -m unittest discover -s tests -v
.venv\Scripts\python -m ruff check .
.venv\Scripts\python -m ruff format --check .
.venv\Scripts\python -m mypy
.venv\Scripts\python -m pip check
```

For the real compiler integration test, set `BICEP_COMPILER` to an **already
installed** standalone compiler executable. Without one that integration case
is explicitly skipped; missing-tool and failed-build tests still run. Symlink
escape tests may be skipped when Windows denies symlink creation privileges.
The implementation never installs Bicep or invokes the Azure CLI wrapper.

CI builds an exact wheel, installs it into a fresh environment outside the
checkout, asserts the import location, checks dependencies, then runs the full
suite and advisory smoke workflow there. Each Windows/Linux Python 3.12/3.13
job retains `compiler-coverage.json`: only a successful real local-build and
missing-module `--no-restore` integration is marked exercised. An unavailable
compiler remains explicitly unavailable; mocks and a green job do not establish
compiler coverage. Generated invariants cover strict types, loss of evidence,
redaction and bounded expansion without adding a test dependency.

## Assessment workflows

Cohort21's [preparation matrix](../references/recommendation-batches/preparation-21.json)
and [reviewed sources](../references/recommendation-batches/preparation-21-sources.json)
are not accepted catalog or interview-bank activation. Four assisted and four
manual decisions separately cover incident planning, Zero Trust, public-CA
renewal, key/certificate rotation, vault delegation/Policy, MMK/CMK choice,
sovereignty requirements and complete service BYOK support. Existing vault and
Policy context and explicit storage keySource/infrastructure/Queue-Table settings
are configuration only. Terraform inline CMK presence/absence does not reconcile
separate CMK resources, so final key source remains unknown.

Integrated partner-CA renewal is not arbitrary issuer automation or self-signed
regeneration. Key rotation is not certificate renewal or confirmed consumer
updates; storage version refresh is separate. Managed HSM is key-only. No
configuration or general support table establishes effective privilege,
enforcement, complete coverage, rehearsed IR, Zero Trust maturity or sovereignty
eligibility. Every decision and exception stays independently blank. No new live
route, key/certificate/secret/URI/issuer/principal/incident payload, query, security
scan or operational change is introduced.

Use `--question naming-hierarchy-scoped-authorization` for cohort07's
[eight accepted workflows](../references/recommendation-batches/batch-07.json)
in `.25`. Its original [preparation](../references/preparation/batch-07.json)
remains separate; all eight accepted decisions and exceptions start independently
blank with attribution and scope/content/time/expiry binding.
Existing raw/local-module Terraform and supplied plans can prepare explicit MG
keys/parents; pinned ARM/Bicep2020-05-01 can additionally prepare
`managementGroups/settings/default`. Saved normalized settings must retain that
explicit `api_version`; no AzureRM settings resource or new live route is assumed.
Only unique known typed positively joined selected-scope graphs are usable.
Unsupported expressions, missing parent records, conflicting/cyclic ancestry and
over100 relevant records remain unknown. Neither root purpose nor complete estate
depth is inferred. All source-specific decisions and exceptions remain independent.

Cohort25's [accepted matrix](../references/recommendation-batches/batch-25.json)
and [captured source findings](../references/recommendation-batches/batch-25-sources.json)
define nine separate F01.10-F01.18 reviews and a registered blank interview in
catalog `2026-11-06.21`, following the explicit slot after checked06/10 delivery.
Original [preparation](../references/recommendation-batches/preparation-25.json)
is retained separately; source acceptance alone is not delivery. The
offline adapters prepare activity-alert category/scope/action metadata, action-group
enabled/global-processing/channel counts, static single-resource metric-alert
metadata and exact storage redundancy SKUs. Existing workspace/log-alert and
Policy configuration helpers are reused. Unknown flags, missing receiver arrays,
unsupported versions/forms and ambiguous/out-of-scope relationships stay explicit;
recipient identities, contacts, webhook URLs, query/log contents and secrets are
not retained.

Configuration never proves event emission, delivery/response, Logs ingestion or
report quality, absence of raw-log export, AMBA origin/version/remediation or
complete monitoring coverage. Exact redundancy SKU classification does not prove
kind/service/region support, actual availability, completed conversion, failover
or residency. F01.16 requirements remain manual. Current Microsoft guidance says
WAD/LAD retired March 31, 2026: F01.14 preserves its immutable conditional wording
but requires applicability and supported migration review, not new legacy
deployments. No live collection, alert/contact tests, query, deployment, compiler
acquisition or module restore is added.

For Terraform, prefer a separately prepared plan JSON with
`--input terraform-plan --provider-version 4.50.0 --scope ARM_SCOPE`.
LandingLens only reads the supplied JSON; it never runs Terraform to produce it.
Keep sensitive-value masks, explicit resource IDs and source/plan hash bindings.
If a plan is unavailable, raw Terraform with supplied local module snapshots
remains a supported bounded fallback, not an inferior compliance result.

Run `alz-assessor doctor SOURCE --input MODE` before assessment. It checks paths,
all explicitly supplied snapshot hashes, reviewed provider mappings and identity
prerequisites through the same bounded offline adapters. It emits JSON by default;
`--format text` explains each prerequisite. `ready` means checked prerequisites,
`partial` means supported inspection with unresolved capabilities, and `blocked`
means an invalid/missing requirement (exit 2). Partial readiness exits 0 but is
explicitly not complete interpretation or Azure readiness.

Bicep preflight checks an existing compiler only; `--probe-compiler` explicitly
permits a bounded `--version` call. It never builds, restores, installs, fetches
modules, queries Azure or logs in. Compilation remains an assessment operation.
Supply the same scope/provider/snapshot/identity-map flags used for assessment.

`alz-assessor explain REASON` gives bounded, offline evidence guidance without
executing any suggested action. `--format json` is machine-readable. Reports
carry the same explanations and required evidence alongside unchanged reason
codes and technical outcomes. Unknown producer codes remain visible with an
explicit unsupported-explanation notice.

The following examples use authored fixtures, not a live tenant. The Terraform
fixture combines the proven ALZ module graph with an explicitly supplied
security snapshot; it does not execute providers or need a plan.

```powershell
alz-assessor catalog validate
alz-assessor catalog inspect --id G04.01
alz-assessor catalog crosswalk validate
alz-assessor catalog crosswalk inspect --id G04.01
alz-assessor assess tests\fixtures\slice --input terraform --snapshots tests\fixtures\slice\snapshots.json --authorize-root tests\fixtures\alz --provider-version 4.50.0 --scope /subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-management --output planned.json
alz-assessor assess tests\fixtures\slice --input terraform --snapshots tests\fixtures\slice\snapshots.json --authorize-root tests\fixtures\alz --provider-version 4.50.0 --var secure=false --format markdown --output findings.md
alz-assessor assess tests\fixtures\slice\controls.bicep --input bicep --compiler C:\path\to\bicep.exe --scope /subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-management --format html --output bicep.html
alz-assessor assess template.json --input arm --parameters parameters.json --scope /subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-management --output arm.json
alz-assessor assess tests\fixtures\slice\observed.json --input evidence --at 2026-11-04T00:00:00Z --output observed.json
alz-assessor compare planned.json observed.json --output comparison.json
alz-assessor render comparison.json --format html --output comparison.html
```

Source maintenance now prepares classified candidate snapshots and a PR body with
actual checks. Its single workflow has approved `GITHUB_TOKEN` content/PR write
permissions and `actions: write` to dispatch only existing `checks.yml` on its
candidate branch. No PAT or stored bot secret is used. On 2026-11-05 the owner
approved enabling workflow PR creation/approval and repository auto-merge; both
settings are verified enabled and default workflow permissions remain read-only.
Operational validation passed with bot-created and bot-merged #88, recorded in
#78. Artifacts remain the fallback when a create/dispatch/check gate fails. Only safe-only
candidates with every supported platform check green and the exact checked head
may request auto-merge. Needs-review candidates require human merge; all accepted
promotion remains reviewed. Source candidates never replace the installed catalog
by polling. Dispatched jobs are verified directly on the exact-SHA Actions run,
because GitHub may omit that suite from the PR rollup. PR-associated checks are
verified separately.

The manual `validate_publication` dispatch uses an explicitly labelled authored
link-only fixture to exercise a real bot PR, dispatched platform checks and the
safe merge gate. It retains the independent live poll as `observed-*` artifacts,
does not claim an upstream source change and cannot be combined with accepted
catalog publication. Scheduled polls never enable this validation mode.

The workflow's explicit `publish_accepted` dispatch publishes only the installed
accepted catalog and version index as immutable GitHub Release assets, never a
package. Existing releases/assets are not overwritten. Supply a downloaded,
reviewed local index with `--catalog-index FILE` to assess/compare/render to show
known versions behind; runtime does not contact GitHub or replace its catalog.

The offline crosswalk links every GUID to zero or more reviewed evidence sources.
Its first version has **51 mapped controls / 53 associations**: four partial
storage policy/PSRule associations and 49 related upstream query hashes.
The other 204 entries have explicit empty mappings. A mapping is not a result,
query execution permission or an equivalent pass. Source revisions, release tags,
hashes, licence metadata and reviewer rationale are included in inspection.
Use a canonical GUID/control ID for duplicated display IDs. `--crosswalk FILE`
and `--source CATALOG` select an explicit matching pair; mismatched catalogs fail.
See the [crosswalk contract](contracts.md#evidence-crosswalk-version-10).

Add `--evidence-tiers` to `assess`, `review serve` or `replay export` for explicit
assessment contract 1.2. **Verified** means sufficient current accepted-predicate
evidence, including failures. **Signal** means usable machine evidence awaits
human confirmation. **Needs decision** has no usable machine evidence; manual
recommendations remain separately counted. Counts are once per GUID across
targets/modes and sum to 255 for the packaged catalog. A partly unresolved
predicate population is Signal, never wholly Verified.

Existing commands without the flag keep 1.0/1.1 output unchanged. Compare two
1.2 assessments to retain/recompute tiers; mixed contracts are not comparable.
`render` displays the saved version without upgrading it. Signals do not create
outcomes or reviews. Existing typed prepared facts can supply Signals. Scanner and query ingestion are
separate pending work, not inferred from arbitrary
metadata. See [tier semantics](contracts.md#assessment-version-12-evidence-tiers).

For saved policy exports, use `assess evidence.json --input evidence
--evidence-tiers --policy-evidence policy.json`. The separate `policy-export`
1.0 file carries explicit `scope`, original `collected_at`, and raw ARM
`assignments`, PolicyStates `states` and `exemptions` arrays. Its scope must equal
the observed evidence; it cannot replace existing saved policy records or attach
observations to planned input. See the [policy contract](contracts.md#policy-export-and-signals).

Existing scoped collector bundles also supply policy Signals when assessed with
`--evidence-tiers`, without a new collection operation. Compliant and NonCompliant
states are evidence for review, not checklist outcomes. Stale/conflicted/missing
contexts, indirect initiative relationships and unsupported states stay explicitly
unusable; assignment presence or empty evaluations never clear a control.
Original evaluation times, source hashes and gaps remain visible across reports,
review preparation, comparison and replay. No new live validation is claimed.

`assess evidence.json --input evidence --evidence-tiers --scanner-evidence scanner.json`
accepts a saved `scanner-export` 1.0 wrapper containing PSRule detailed JSON or
SARIF 2.1.0 plus explicit producer/version/baseline, original time, scope, mode,
input hashes and result-index-to-ARM-ID bindings. LandingLens never installs or
runs the scanner. Matching rule names from an unrelated producer, unbound target
names, empty findings, failed/partial runs and stale results cannot establish passes.
See the [scanner contract](contracts.md#saved-scanner-evidence).

For separately authorised use, `collect --subscription SUBSCRIPTION_UUID
--query-guid e9c8f584-6d5e-473b-8dc5-acc9fbaab4e3 --output query-evidence.json`
runs the exact reviewed upstream query using the existing ARM-token environment
selection. This is opt-in collection, not an assessment side effect. Only D07.06
and D07.07 query hashes are allowlisted; no arbitrary query text, ambient scope,
automatic login or management-group expansion is accepted in this path.
Assess the saved result with `--input evidence --evidence-tiers`.
Unknown/partial/stale/conflicted/empty query output never establishes a pass.
Use only the already authorised #40 boundary; this increment tested injected
transports and saved outputs, not a new live run.

Catalog `2026-11-05.5` adds source-backed priority metadata: 71 High, 158 Medium
and 26 Low recommendations. Reports and review queues sort severity first;
historical catalogs retain their original presentation. This is a metadata-only
successor, not new automated coverage. Draft `.4` remains paused cohort-19 work.

For evidence scoped to one explicit management group, `assess --evidence-tiers
--archetypes FILE` accepts a saved binding shaped as
`{"collected_at":"2026-11-05T00:00:00Z","entries":[{"scope":"/providers/Microsoft.Management/managementGroups/your-group","group_id":"landingzones"}]}`.
The scope must exactly match the evidence, not a guessed group name. The reviewed
ALZ Library architecture supplies suggestions only: `landing_zones` contains
`Deny-Storage-http`, associated with G04.01. Other archetypes are explicitly
unreviewed; no inheritance, exclusion or outcome is inferred. Every suggestion
requires reviewer confirmation. Saved evidence, review sessions and replay retain
the binding's original time; minimised reports withhold its private scope.

The frozen observed fixture is assessed at its recorded example time. Comparison
rechecks both inputs against its own time and the 24-hour default freshness
limit, so this example becomes non-comparable when the fixture ages.
`--at` can reproduce comparisons of saved historical inputs; choosing a past
time cannot prove that newly read source files existed then. Current collection
time never makes old policy evaluations current. Missing bindings yield
`not_comparable`, not drift.

`--format json|markdown|html|sarif|pr-summary|csv|xlsx` applies to assess, compare and render.
SARIF 2.1.0 retains stable rules, independent modes/outcomes, tier/freshness and
coverage. Azure-only evidence has no invented file location. Optional
`--sarif-base EXISTING_DIRECTORY` includes only real supplied source files beneath
that directory, without guessing line numbers. `--minimize` omits all locations.
`pr-summary` reports completion separately from assessed-subset pass rate and
lists up to ten priority failures. Both remain advisory exit 0.
The [example PR workflow](examples/advisory-pr-workflow.yml) writes a job
summary and offers an explicitly enabled, pinned SARIF uploader; repository code
scanning/fork-token permissions must already support it. No setting is changed.

HTML starts with an executive summary, priority failures and a text-labelled
design-area heat map; completion remains separate from pass rate among assessed.
`--format csv` and `--format xlsx --output tracker.xlsx` export the same
severity-ordered tracker values, one row per target/mode. XLSX requires a new
output file and preserves existing workbooks. Headers are frozen/filterable and
a Notes sheet records source/version and snapshot limits. Cells are text only;
formula-like prefixes are escaped and no formulas, external links or macros exist.
Use `--minimize` before sharing either tracker. This is a static assessment
snapshot, not a financial/calculation model.

Every format
shows all dispositions, independent planned/observed results, evidence reasons,
source/catalog versions, subset metrics and inventory completeness. Findings
return **0**, including failures, unknowns and manual work. Invalid invocation or
unrecoverable input/tool failure returns **2**. Zero denominators are unavailable,
not 100%. CI checks software behavior; it does not gate on estate findings.

Normal workflows export only reviewed boolean/enum properties, provenance and result
facts, not raw variable/parameter values. Marked sensitive Terraform values,
plan sensitivity markers and ARM secure parameters are withheld. An explicit
`--evidence-output FILE` saves the normalized evidence contract when needed for
later identity maps or plan associations. `--minimize` removes resource IDs,
source paths and topology from reports; minimized output is presentation-only
and cannot be used for comparison. HTML escapes all data and has no external
scripts, fonts or assets. Diagnostic spikes below are not assessment reports.

HTML reports provide summary/area navigation, separate control and resource
metrics, expandable findings, human-review status and provenance. Optional local
search/outcome/area filters only hide existing results; they never reevaluate
rules. All findings are present and expanded without JavaScript. Print styles
hide controls, restore all findings and expand details; no PDF engine is needed.
The report uses system fonts, light/dark theme variables and a no-network CSP.
Guidance links require HTTPS and only navigate when explicitly selected.

### Identity, manual evidence and optional plans

Use `--question log-retention-machine-resource-guardrails` for cohort24's nine
independent decisions. Review central/regional workspace exceptions, dataset
retention/recovery/privacy and actual export/container WORM separately. Preserve
source-qualified units and Basic30/provider8/CLI2556/REST4383 differences. Guest
assignments, Azure/Arc assessment/patch modes and flow definitions require actual
completed audit/patch/traffic evidence, not resource-presence approval. Explicitly
designate critical services and review actual lock scope/side effects and Policy
deny plus role authority, distinct from RBAC deny assignments. Every outcome and
exception remains independently blank and bound; no new live operation occurs.

Use `--question sovereign-organization-regions-classification` for cohort09's
seven distinct decisions. Explicitly designate organizational MG roles/root and
reconcile immutable Public wording with current SLZ's four-zone architecture.
Substantiate regional requirements, justified organization, actual required
service/feature availability and separate entitlement/quota/capacity references;
location strings, region pairs and public tables prove none. Separately reference
the approved classification taxonomy and non-sensitive sovereign tag usage.
No actual private data classification, legal/eligibility decision, sensitive tag
value, private workload/employee/location payload or new live availability/account
read is performed. Every outcome stays blank until explicit bound confirmation;
Signals and exceptions never manufacture Verified.

Use `--question central-logging-support-service-enablement` for cohort23's
seven distinct decisions. Review actual central logging/ingestion and SIEM
correlation separately; workspace routing or Sentinel onboarding does not prove
either. Azure and M365 Lockbox require separate tenant/service/license/approver/
audit evidence. The linked Event Grid metric/activity tutorial is not general
log-query alerting or measured real-time delivery. Separate privileged-account
use, new-service readiness and service-request fulfillment remain manual, not
inferred from resource presence. Supply redacted references, never log/query/rule
bodies, support/private request contents, identities, endpoints or credentials.

`interview inspect` lists versioned, specific multi-control questions and each
control's evidence requirements. `interview prepare assessment.json --question
private-service-paths --scope ARM_SCOPE --output response.json` prepares a blank
shared narrative with separate per-control decisions. After the assessor supplies
the answer, reviewer, rationale, evidence, validity and every selected outcome,
`interview apply response.json --output manual.json` validates all bindings
together and writes a normal manual-review document. Existing outputs are refused.
An answer alone never approves anything; a failed/expired/changed decision rejects
the whole output. Import the completed document with the usual `assess --manual`.
The local workspace integration is separately tracked, not delivered by this CLI.

Use `--question network-monitoring-sovereignty-policy` for cohort16's nine
separate diagnostic/routing/inspection/geography/global-policy/partner/DNS
decisions. Its technical context is configuration only; border crossing is a
factual question, not a blanket prohibition. Current partner support, actual
paths/tunnels/filtering, approved regions, role delegation and client DNS use
require separate attributable evidence. Every outcome starts blank.

Use `--question inbound-outbound-hybrid` for cohort 13's ten separate GUID
decisions, including DDoS logging and NIC public-IP policy as distinct D05.08
recommendations. Its migration question preserves the frozen date and current
API/existing-network scope distinction. Preparation leaves every decision blank.
The scope is included in the requirements hash; changed scope, bank, content or
validity requires fresh preparation, not editing a binding.

Use `--question expressroute-monitoring-routing-failover` for cohort15's eight
separate monitoring/topology/edge decisions. D06.17 has a separate strictly joined
GatewaySubnet propagation predicate; manual answers never override it. Review
location-label and monitoring configuration as partial Signals, not independent
physical sites, probe health, ingestion, edge BFD or failover evidence. All
questions start blank and require actual attributable evidence.

Use `--question sovereign-audit-workload-protection` for cohort22's eight distinct
key-custody, Entra audit, activity-retention, CSPM/Servers/workload, endpoint and
patch-drift decisions. Only references/redacted attestations are appropriate:
never enter key/credential/security-domain material or private audit records.
Configuration facts are review context, not proof of coverage or compliance.

Use `--question expressroute-cost-resilience` for cohort14's nine independent
cost, Local-region, gateway-placement, actual-demand, FastPath, on-premises VPN
and routing-isolation decisions. Supply redacted attributable requirements and
operational references, not keys, addresses or private appliance identities.
Configured bandwidth and published limits are not measured demand or headroom;
SKU/zone/bypass settings are not resilience, current availability or performance.
Preparation leaves all outcomes blank and retains scope/content/expiry guards.

Use `--question resource-cost-governance` for cohort08's seven separate ownership,
quota, reservation/capacity, dashboard, operating-plan, identity-placement and
billing-tag decisions. Provide redacted attributable references, not tag values,
raw dashboard queries/content, financial amounts, usage histories or personal
owner/directory records. A Reserved Instance discount is not a capacity guarantee;
resource tags do not automatically inherit, and Cost Management tag inheritance
changes usage records under distinct agreement/scope/time conditions. Explicit
resource identities or positive saved MG parent bindings are required for scoped
machine context; names and bare scope metadata never designate identity roles.

For the automated local workflow, start from saved **normalized evidence**, not
a rendered or minimized assessment:

```powershell
alz-assessor review serve evidence.json --directory private-reviews
```

The browser opens automatically. Choose a finding and review kind; supply the
decision, reviewer, justification, supporting evidence and expiry, then select
**Save review and update reports**. Python validates the bound review, writes a
new revision and refreshes the report automatically. No JSON editing or separate
validation/import/render commands are needed. An exception remains separate from
the technical result; an accepted exception never turns a failure into a pass.
Reviews apply to the displayed evidence scope/control, not just one resource.

The workspace has design-area progress, a severity/tier-filtered "Needs me" queue
and an evidence/decision panel. Use Alt+Up/Alt+Down or Previous/Next to navigate.
The effort estimate states its fixed per-tier assumptions; it is not measured
effort or a compliance score. Unknown/manual/pending decisions remain in the queue.

For bulk Signal review, select each control and its explicit outcome, then supply
shared reviewer, justification, evidence and validity. No decision is prefilled.
One transaction validates all selected records and creates one immutable revision;
any invalid/stale/unconfirmed replacement leaves the previous revision intact.
The interview panel reuses one narrative with separate per-GUID outcomes.
Human confirmation of an automated-control Signal does not replace its technical
predicate or turn unavailable configuration into a pass.

Supply `--manual FILE` / `--exceptions FILE` to retain existing records,
`--catalog FILE` for the exact nondefault version-1.1 catalog, and the original
`--landing-zone` / `--max-age-hours` selections when applicable. Existing records
are not silently replaced: confirm replacement explicitly; earlier revisions
remain intact. Changed/expired records stay visible as requiring review.

Each `revision-NNNN` directory contains the normalized evidence, exact catalog,
completed review files, full normalized assessment and JSON/Markdown/HTML plus
minimized HTML reports. `invocation.json` records applicability/freshness selections
and evaluation time for reopening. Validation/write failures leave the previous revision
intact and are shown in the page. Evidence timestamps are never refreshed;
evaluation/freshness is recomputed at save time. To reopen, start another session
with saved `evidence.json`, `catalog.json`, `manual.json` and `exceptions.json`
from the desired revision and a **new** output directory. Original inputs and
existing directories are never overwritten.

New revisions include CSV/XLSX trackers and a hash-bound core manifest. Resume with
`review serve PRIVATE_DIRECTORY\revision-0002 --resume --directory NEW_DIRECTORY`.
This verifies the saved evidence, catalog, reviews, assessment and invocation;
do not override their scope/catalog/freshness selections. Original evidence times
and prior revisions are preserved; freshness is reevaluated now. A changed hash,
link, schema or invocation fails explicitly. Legacy revisions without a manifest
still use the explicit saved-file workflow above rather than gaining new trust.

This is a private loopback-only listener, not a hosted application. Keep its
capability URL and output files private: full files retain scoped identities,
review text and attribution. Other local processes/users are trusted; this is
not an authentication boundary or an anonymized bundle. No Azure operations,
outbound requests, credentials or new dependencies are needed. Use **Stop local
review** or Ctrl+C to release the listener; simply closing a tab does not stop
it. `--no-browser` prints the address without launching a browser.

The original explicit file workflows remain available:

`alz-assessor review prepare assessment.json --control CONTROL_ID --scope ARM_SCOPE
--kind manual --output review.json` creates deterministic, content-bound templates
for explicitly selected unresolved/failed controls. Use `--kind exceptions` for a
separate exception record. Display IDs that are ambiguous require the canonical
control ID. Preparation never asserts a reviewer, outcome, rationale or evidence.
Complete those fields and the finite validity interval, then remove `is_template`.
`review validate review.json --scope ARM_SCOPE --at TIME` reports changed bindings,
expiry and review readiness; it neither authenticates the reviewer nor imports
an outcome automatically. Use `assess --manual`/`--exceptions` to import completed
records. Duplicate/conflicting records fail, and exceptions never rewrite facts.

### Opt-in local replay

Save normalized input with `assess --evidence-output evidence.json`, then create
a replay at an explicit evaluation time:

```powershell
alz-assessor replay export evidence.json --at 2026-11-04T00:00:00Z --destination replay-bundle
alz-assessor replay run replay-bundle --format html --output replay.html
```

Supply the original `--manual`, `--exceptions`, `--catalog`, `--landing-zone`
and `--max-age-hours` selections when applicable. Export evaluates and binds
that invocation; it does not reconstruct missing normalized facts from a
rendered report or prove the files existed at the selected historical time.
The installed package includes current `2026-11-06.3` and frozen
`2026-11-04.1`, `2026-11-04.2`, `2026-11-05.1`, `2026-11-05.2` and
`2026-11-05.3`, `2026-11-05.5`, `2026-11-06.1` and `2026-11-06.2` catalog meaning.
Altered/custom or unavailable historical
artifacts fail explicitly rather than substituting today's rules.

Replay is a new bounded four-file local directory, not an archive, service or
automatic upload. It retains scoped resource/logical identities and is **not
anonymized**. Only the reviewed property vocabulary is retained. Paths, arbitrary
metadata, unknown free-text reasons and review evidence/rationale are withheld
or replaced by hash aliases. Reviewer labels are pseudonymized without a mapping
export; only explicit `--retain-attribution` retains their original labels.
Treat hashes and retained identities as sensitive inventory. No source trees,
raw variables, environment or credentials are bundled.

Import rejects extra/traversal paths, links, duplicate JSON keys, unsupported
schema, size/hash mismatches and changed semantic outcomes. Each file is bounded
to 8 MB, total content to 16 MB, with 10,000 resources and 1,000 review entries.
Export refuses an existing destination; import does not extract files.
Outcomes, identities, freshness and coverage are checked at the recorded time;
free text, generated presentation bytes and source paths are not reproduced.
Partial inputs remain partial. Minimized presentations cannot be replayed.

`--identity-map FILE` accepts an exact input-hash-bound map, not name matching.
Entries require `logical_id`, full `arm_id` and `scope`; duplicates, conflicting
IDs and stale input hashes fail. Default-provider derivation is restricted to
reviewed AzureRM 4.50.0 mappings and explicit scope/name/group bindings. Provider
selectors, module provider remappings and inline subscription/tenant bindings
are conservatively not auto-derived; use a reviewed identity map.

`--manual FILE` and `--exceptions FILE` accept the separate version-1.0 contracts
in [contracts.md](contracts.md). Records require scoped control IDs,
rationale and `valid_from`/`valid_until`. Manual records additionally require an
outcome and evidence reference. Exception disposition never rewrites technical
failure; expiration is visible.

`assess plan.json --input terraform-plan --provider-version 4.50.0` assesses an
optional plan independently, without invoking Terraform or replacing raw-source
findings. To assert an association, supply `--source-evidence` and `--plan-binding`.
The latter requires `review_state: "reviewed"`, the exact `plan_sha256`, and
`source_artifact_hashes` identical to that evidence bundle. Mismatch fails.
Hashes prove artifact identity, not that Terraform generated the plan from a
particular tree; the reviewed association remains the producer's assertion.
Plan identity requires an explicit full planned ID within the selected scope
or a reviewed identity map; names alone do not establish provider scope.

For real collection permissions, explicit scopes, existing-token handling,
pagination, partial runs and inventory authorization attestation, see
[collection.md](collection.md). No credentials are needed for offline use.

## Reviewed source maintenance

Maintainers can run `python tools\monitor_sources.py --output NEW_DIRECTORY`.
This explicitly acquires commit-pinned public sources from the existing reviewed
registry, retains licensed bytes/hashes and produces GUID/field/schema/taxonomy/
licence diffs. The extended weekly/manual workflow prepares classified PRs only
when its existing permissions/settings/check gates allow it; otherwise it retains
artifacts and a generated PR body. Runtime assessment never polls or replaces its catalog.

`status.json` separates last successful polling, the recorded catalog semantic
review and pending changes. `--previous-status FILE` retains the last successful
poll across failed local attempts; without a prior status it remains unknown.
GitHub run artifacts retain per-run history for 14 days. Failed/invalid polling
warns and exits 2 without touching known snapshots. Changed license terms block
source retention pending review; license hashes and the required review remain
visible. Nonallowlisted upstream queries remain data; the separately approved
exact allowlist executes only through explicit scoped collection as Signals.

A maintainer must review the candidate, preserve removed GUIDs as retired 1.1
records, reconcile taxonomy/ID conflicts, inspect stale review bindings and open
a promotion PR. Use the exact reviewed matrix-change path and explicit
`catalog refresh`; detection does not grant predicate acceptance or permission
to bypass publication/check settings.

## Offline Terraform spike

```powershell
.venv\Scripts\alz-assessor spike-terraform tests\fixtures\alz --snapshots tests\fixtures\alz\snapshots.json
.venv\Scripts\alz-assessor spike-terraform tests\fixtures\alz
.venv\Scripts\alz-assessor spike-terraform tests\fixtures\alz --snapshots tests\fixtures\alz\snapshots.json --var 'location="australiasoutheast"'
```

The first command resolves four resource configurations through a root, a
versioned platform snapshot, a separately mapped nested management snapshot and
a nested local connectivity module. The second keeps the unavailable module
explicitly unknown, emits a coverage diagnostic and does not invent its resources.
Tests repeat the same fixture with just its nested snapshot absent.

These first fixtures are **synthetic, authored ALZ-shaped snapshots**. They represent
management-group organization, shared logging, hub networking and an application
resource group. No provider defaults, Azure IDs or compliance are inferred.

An additional fixture exercises the unmodified Microsoft AVM workspace module
0.5.1, commit `b4ffa3ff87ac09ff6de3b7014c44b4d213aa302b`, behind an authored platform
wrapper with a nested local connectivity dependency:

```powershell
.venv\Scripts\alz-assessor spike-terraform tests\fixtures\alz-avm --snapshots tests\fixtures\alz-avm\snapshots.json
```

Its per-file provenance and MIT notice are retained. The module snapshot was
retrieved explicitly during this prerequisite task; the CLI never fetches it.
Workspace name, location, resource group, retention, SKU, local-auth and both
internet-access settings resolve from the actual module. Empty identity/timeout
dynamic blocks resolve correctly. Six unsupported resource controllers remain
symbolic; full graph coverage is not claimed.
Telemetry resources have known zero count because the fixture passes
`enable_telemetry = false`; no provider or telemetry implementation executes.
The same root with the nested AVM snapshot absent produces an explicit missing
snapshot diagnostic and no fabricated workspace. This is measured partial
AVM support, **not complete AVM/ALZ compatibility or complete graph coverage**.

For your own already-supplied snapshot, create an explicit JSON manifest:

```json
{
  "modules": [{
    "source": "example.invalid/landinglens/alz/azurerm",
    "version": "1.0.0",
    "subdirectory": "",
    "path": "snapshots/platform",
    "sha256": "<reviewed content hash>"
  }]
}
```

The source/version/subdirectory must match exactly; version constraints are
not resolved to an arbitrary snapshot. `path` is relative to the manifest and
points to the already-selected module subdirectory. Nested remote dependencies
need separate mappings. `tree_hash()` hashes sorted relative file paths and
contents with length delimiters; the synthetic fixture hash utility demonstrates
the algorithm. Hashes are validated before analysis. Never regenerate hashes
just to accept an unexpected change.
Hashes include line endings. Normalize authored fixtures to the repository's LF
policy before freezing hashes; preserve upstream snapshot bytes unchanged.

Snapshot/local module paths must resolve within the root or an explicit
`--authorize-root PATH`. Merely naming a manifest does not authorize unrelated
filesystem roots. Traversal and symlink escapes are rejected; snapshot trees
containing links are rejected. There is no module download/cache fallback.

Supported now: literals, declared variable defaults, ordered explicit variables
and files, conventional tfvars, locals (including forward references and cycle
detection), local module inputs/outputs, nested snapshots, attribute/index access,
scalar templates, boolean conditionals, bounded integer arithmetic/comparisons,
logical operators, tested pure collection/string functions, `toset`, integer
`count`, map/string-set `for_each` and native HCL dynamic blocks with known
collections. `.tf` uses the real HCL2 parser; `.tf.json` has a
separate JSON mapping with single-interpolation type preservation.

Unknowns remain explicit for data sources, remote state, computed resource
attributes, missing modules, unsupported functions/operators and unknown/invalid
expansion controls. JSON-encoded dynamic blocks remain explicitly unsupported;
native HCL dynamic expansion is tested and bounded.
Provider-schema-specific JSON block normalization, constraints/type conversion,
validation checks, provider defaults, richer functions, splats, loops and full
HCL runtime semantics remain unproven. Signed remainder is outside the verified
numeric subset. Do not use this spike to validate Terraform.

Limits default to 256 total module/resource instances, 16 module levels,
10,000 expression steps, 256 files and 2 MB source bytes. Expression/reference
depth also has a 64-level bound. Exceeding a graph expansion limit records an
unknown/diagnostic; invalid inputs and file/byte limits fail explicitly.

Variable precedence (lowest to highest): defaults, explicitly supplied environment
values (Python API only; ambient environment is never read), `terraform.tfvars`,
`terraform.tfvars.json`, lexical `*.auto.tfvars[.json]`, then interleaved
`--var-file` / `--var NAME=JSON_VALUE` arguments. Child tfvars are not loaded.
Variable files must be inside an authorized root. HCP Terraform variables are
not supported. See the [reviewed source semantics](../references/2026-11-04/review.md).

Source files, effective supplied root bindings, the snapshot manifest and module
snapshot hashes are recorded. Marked sensitive/ephemeral variables and outputs
are withheld conservatively. Normal assessment never exports arbitrary resource
properties. Diagnostic CLI output also withholds raw outputs and unreviewed
properties; the internal parser API is not a redacted report API.

## Local Bicep compilation spike

```powershell
.venv\Scripts\alz-assessor spike-bicep tests\fixtures\bicep\local.bicep --compiler C:\path\to\bicep.exe
.venv\Scripts\alz-assessor spike-bicep tests\fixtures\bicep\unrestored.bicep --compiler C:\path\to\bicep.exe
```

Always invokes `build --no-restore --stdout` after recording `--version`.
Missing tooling, unrestored modules, timeouts, failed builds and invalid compiler
output fail explicitly without resource evidence. No automatic restore/install,
Azure authentication, what-if or deployment is attempted. Successful compilation
is **not** evaluation. Use `assess --input bicep` for the bounded ARM evaluator.
The compiler API keeps its template in memory; diagnostic CLI output withholds
that raw template. Assessment binds source, parameters, compiler version and
compiled-template hashes. Compiled bytes cover resolved dependencies, but
individual cached dependency-source hashes are not available.

ARM supports literals, parameters, variables, member/index access, concatenation,
boolean functions, explicit scope/resource IDs and bounded resource copies.
Equality preserves nested value types; floating-point equality remains unknown
rather than relying on Python numeric coercion.
Runtime references, unsupported functions/APIs, linked templates and nested child
resource declarations remain unknown/incomplete rather than guessed. Reviewed
API versions are intentionally narrow; omission of a setting never infers a
provider or service default.

Both spikes use exit 0 for successful bounded analysis/compilation, even when
Terraform values are unknown, and exit 2 for invalid inputs or execution failures.
They print JSON only on success and errors to stderr. They are intentionally
separate from the production `assess` interface.

## Reviewed references

[Snapshot review](../references/2026-11-04/review.md) documents exact taxonomy,
255-item inventory, duplicate IDs, unresolved mappings, precedence and reuse terms.
[Manifest](../references/2026-11-04/manifest.json) and
[disposition ledger](../references/2026-11-04/inventory.json) are versioned offline
inputs to the packaged catalog. The baseline is not tenant policy.
[Dependency review](dependency-review.md) records accepted/rejected candidates.

`tools/capture_references.py` is a deliberate network acquisition tool, not a CLI
dependency; it refuses to overwrite the frozen snapshot.
`tools/build_inventory.py` reproduces the reviewed derived inventory from pinned
bytes; it does not fetch or certify recommendation mappings.
`tools/capture_avm_fixture.py` explicitly captures the pinned AVM source fixture
and refuses to overwrite an existing snapshot. Its retained `.tf` files are
unmodified upstream material, not code to execute.
`tools/build_catalog.py` reproduces the packaged inventory from frozen reviewed
bytes. `tools/review_control_sources.py` and `tools/review_collection_sources.py`
are explicit maintainer source-review acquisitions, never runtime fallbacks.

To review a new local catalog without replacing the installed snapshot:

```powershell
alz-assessor catalog refresh --reviewed next-reviewed-catalog.json --accept-reviewed --output accepted-next-catalog.json
alz-assessor catalog inspect --source accepted-next-catalog.json
```

Refresh requires a new reviewed version, refuses to overwrite an existing
destination or drop imported items, prints an explicit diff/hash, and rejects
accepted-matrix downgrades. Assess it explicitly with `--catalog FILE`; historical
reports keep their own catalog version. New automated behavior requires code,
source review and matrix regression tests, not just importing a query.

No Terraform command, deployment, module download, package publication, automatic
authentication, repository creation or live collection is part of validation.
