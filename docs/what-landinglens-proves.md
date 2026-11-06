# What LandingLens does and doesn't prove

LandingLens is an advisory assessor, not Microsoft certification, an estate-wide
compliance score or an operational security test. It retains all checklist GUIDs,
their source-backed meanings and visible gaps. Version-specific decisions are in
the [accepted matrix](automation-matrix.md); delivery and historical verification
are in the [plan](planning/plan.md).

## Evidence and outcomes

| Evidence | What it establishes | What it does not establish |
|---|---|---|
| Accepted explicit configuration predicate | The stated typed property test for the supplied resource and time | Effective inheritance, runtime routing/protection, recovery success or estate completeness |
| Supplied Terraform plan, raw source or ARM/Bicep | Supported planned configuration with provenance and visible unknowns | Deployed behaviour, provider defaults, complete language/module compatibility or a valid Terraform deployment |
| Saved/scoped Azure inventory | Original-time observed facts within the explicit supplied boundary | Unrestricted authorisation or completeness from successful requests/pagination alone |
| Policy/scanner/query Signal | A mapped, attributable machine observation with its limits | A checklist pass from assignment presence, empty violations, scanner success or an external default |
| Bound human review | An explicit supplied scoped decision with attribution, evidence and finite validity | Authenticated identity proof or permission to replace automated technical facts |
| Accepted exception | A separate human disposition | Conversion of technical failure into pass |

Missing/null/unresolved/inaccessible/partial/stale evidence is never an invented
pass or absence. Not-applicable needs established applicability; not-comparable
is never drift. Planned and observed outcomes stay separate. Original evaluation
times are not refreshed by collection, rendering, review saving or resume.

## Tiers and counts

With explicit assessment 1.2, Verified means sufficient current evidence for an
accepted predicate, including a failure. Signal means usable machine evidence
awaits human confirmation. Needs decision has no usable machine evidence.
Manual disposition is counted separately. Control counts are once per GUID across
targets/modes; incomplete mixed populations are not wholly Verified.

Completion and pass rate among assessed instances use different denominators.
Unknown/manual work remains visible, and zero assessed results make pass rate
unavailable. The heat map shows labelled result-instance counts, not maturity.
The workspace effort estimate states fixed planning assumptions, not measured
effort or an audit commitment.

## Scope and execution

Normal assessment, reporting and replay are offline. Live collection requires
explicit separately authorised subscriptions or management groups and an existing
token. The only approved live boundary remains the private selection in #40.
No automatic login, consent, role change, broader Graph/billing/data-plane access,
policy evaluation trigger, deployment or remediation occurs.

LandingLens never runs Terraform init/plan/apply, backends or provisioners, fetches
IaC modules implicitly, installs Bicep or restores its modules. The existing
compiler is used only with restoration disabled. Scanner intake never installs or
runs scanners. Query text is not authority: only exact allowlisted queries can run,
with explicit subscription transport scope, as Signals.

## Privacy and saved records

Full evidence/review files retain resource identities, paths, topology and
reviewer text. Use minimised reports/trackers before sharing. Minimisation is
presentation-only, not identity evidence for comparison or replay; hashes can
still reveal sensitive inventory associations.

The temporary workspace is loopback-only with a random capability URL, exact
Host/origin checks and bounded fixed routes. Local processes/users are trusted;
this is not an authentication service. No remote assets, telemetry or automatic
uploads are loaded. Stop the listener when finished.

Saves and bulk/interview decisions require explicit outcomes and replacement
consent. Invalid records leave earlier revisions intact. Resume checks bounded
core-file hashes and invocation data, not authenticated authorship. Unknown or
pending human decisions remain work to resolve. Replay preserves available
packaged historical meaning and refuses missing/tampered artifacts; it cannot
invent an unavailable historical catalog.

## Catalog maintenance and verification

Source detection is separate from semantic acceptance. Candidates cannot be used
as accepted evaluator catalogs. Wording/meaning/severity/query/new/removed/
crosswalk-source changes require review; only demonstrable safe changes may request
auto-merge after actual platform checks and exact-head gates. The owner explicitly
approved workflow PR creation/approval, repository auto-merge and `actions: write`
for the source workflow on 2026-11-05. Both repository settings are enabled;
default workflow permissions remain read-only. Actual workflow-token creation,
four-job dispatch and safe merge passed with
[#88](https://github.com/jonathan-vella/landinglens/pull/88), recorded in
[#78](https://github.com/jonathan-vella/landinglens/issues/78). The link-only
fixture is explicitly authored; the independent real poll found no change.
Ordinary unchanged polling also created no PR. No branch-protection change,
bypass, PAT or stored bot secret is used.

Accepted catalog Release assets never replace the installed catalog at runtime.
A locally supplied version index is a producer assertion, not an online update.
Historical catalogs and original control meanings remain frozen.

Fixture/injected, installed CLI, actual browser/workbook and live evidence are
different verification labels. This efficiency increment has no new live Azure
run; the earlier narrowly scoped pilot is not proof of every control or a tenant.
See [collection](collection.md), [contracts](contracts.md) and
[detailed workflows](usage.md) for precise supported cases and bounds.

## Cohort 22 preparation, not delivered

The [eight-GUID preparation matrix](../references/recommendation-batches/batch-22-preparation.json)
and [25 captured sources](../references/recommendation-batches/batch-22-sources.json)
record source review and offline typed configuration support only. No successor
catalog, crosswalk, delivery receipt or new live Collector API is activated.
Terraform/supplied-plan and direct ARM-property helpers prepare allowlisted
Defender plan fields, activity-log routing, Managed HSM settings and VM patch
configuration. Current accepted controls retain their earlier meanings; the
specific questions/context remain candidate-only until serialized integration.

Managed HSM stores HSM-protected cryptographic keys, not secrets or credentials.
External KEK custody adds customer-operated HSM/proxy responsibilities and is not
inferred from HSM presence. Legacy Entra and Security Center links resolve to
current monitoring/Defender guidance. Patch recommendations now use Update Manager,
not deprecated MMA collection. Pricing, diagnostic destinations and periodic
assessment configuration prove neither fleet-wide protection nor successful
ingestion, retained data, endpoint enforcement, OS compliance or sovereign
suitability. Retention, costs and acceptable patch drift require explicit
requirements and attributable redacted operational evidence; no threshold,
private audit record or human decision is invented.
