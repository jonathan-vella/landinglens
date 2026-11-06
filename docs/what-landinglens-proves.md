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

Cohort 13 prepares WAF attachments/modes, origin-rule shapes, public-IP DDoS/log
configuration, explicit outbound flags, saved NIC-policy context and hybrid
gateway/connection facts. None establishes effective protection, exclusive origin
access, arriving diagnostics, enforcement, selected routes, failover or measured
demand. D05.07 remains manual and both D05.08 GUIDs remain distinct.
The frozen default-outbound retirement wording differs from the inspected current
Learn guidance for new VNets and later APIs; see the
[versioned findings](automation-matrix.md#cohort-13-inbound-protection-outbound-migration-and-hybrid-connectivity).

Cohort14 supplies typed ExpressRoute circuit/port billing and capacity, FastPath
flags, source-specific gateway scale/zone context and scoped positive relationships.
Nine explicit decisions distinguish actual requirements/costs, Local reach,
deployed resilience, real on-premises devices and effective routing isolation.
The published FastPath IP limit is not observed usage or available headroom.
No current regional/port availability, achieved throughput/latency, working
FastPath, operational redundancy or economic suitability follows from settings.
ARM scale support does not imply the pinned Terraform provider supports it.

## Cohort 08: resource and cost governance

The [seven-GUID accepted matrix](../references/recommendation-batches/batch-08.json)
and [24 preserved source captures](../references/recommendation-batches/batch-08-sources.json)
precede `2026-11-06.10`. Source/matrix activation alone does not change delivery
counts or establish merged acceptance.
The existing adapters prepare explicit tag-pair counts, bounded dashboard
structure, typed VM capacity-reservation-group references and MG parent IDs.
Existing saved Collector parent relationships can supply original-time scoped
context; no new Collector route, billing, quota or directory read is added.
Machine context requires explicit in-scope resource identities or positive saved
MG parent bindings, not names or bare scope metadata.

Reserved Instances provide matching-usage billing discounts, not guaranteed
capacity. On-demand capacity reservation is distinct and subject to actual
acceptance, quota, matching configuration and SLA conditions. Neither a reference
nor a public quota limit proves available regional capacity or cost suitability.
Dashboard counts do not prove CPU, guest memory or free-disk monitoring; disk I/O
is not free space, and tiles may be unconfigured or unavailable. No queries,
markdown, input payloads, metric readings, tag keys/values or financial records
are retained by these projections.

Resource tags do not automatically inherit. Cost Management inheritance changes
usage records, not resources, and depends on agreement, scope, access, conflict
settings and current-month processing. No required tag key set is invented.
MG names or parent edges do not designate identity subscriptions or establish
regional domain-controller use. Owner responsibility, quota awareness and the
cost-management operating plan remain three separate manual recommendations;
all seven preparation decisions remain blank.

Cohort15's GatewaySubnet propagation predicate is a strictly joined scoped
configuration check, not a gateway uptime or effective-route verdict. A table
flag alone, missing association/default or empty inventory cannot pass.
Monitoring/alert configuration and supplied location-label fingerprints remain
Signals awaiting eight separate decisions, never health, ingestion, verified
peering sites, physical edge independence, customer/provider BFD or actual
convergence/failover. Unsupported/ambiguous populations stay visible; linked
legacy-agent and current BFD date/peering conditions are not silently simplified.

Cohort12 prepares DR prefixes, public-IP configuration, private DNS links,
Resolver endpoint/rule shapes and Bastion settings. Public-IP empty zones cannot
alone establish nonredundancy; registration applies only to VM primary NICs.
Resolver subnets, regional links and loop avoidance need distinct evidence.
Bastion Developer/private-only and pre-2021-11-02 /27 exceptions remain explicit.
The port-65330 guidance concerns a Windows UDP source port, not DNS destination
port 53; no guest read or OS change occurs. Workload-specific DNS and multi-region
failover plans remain manual. No DNS record, raw destination or recording secret
is retained, and no configuration becomes a resolution/security/resilience pass.

## Tiers and counts

Cohort20's [Virtual WAN matrix](../references/recommendation-batches/batch-20.json)
adds one strict scoped ASPath configuration predicate and eight separate
assisted decisions. Explicit WAN/hub branch flags, Internet-intent/local-firewall
joins, supplied-table labels, prefix length and RIU minimum never prove complete
topology, effective propagation/filtering,
Insights use, regional eligibility, business suitability or available capacity.
Current Firewall maximum scaling needs /22 rather than the general /23
recommendation. Hub routing/RIUs are distinct from VNet GatewaySubnet propagation
and VNet-gateway scale. Exact-label equality fingerprints retain sensitive
associations and are not anonymous. Branch connection forms remain unsupported
in the label adapter; missing defaults/joins stay unknown and all eight human
decisions start blank. Source/schema/bank acceptance alone is not delivery.

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

## Cohort 22: security configuration and explicit review

The [eight-GUID matrix](../references/recommendation-batches/batch-22.json)
and [25 captured sources](../references/recommendation-batches/batch-22-sources.json)
record source review and offline typed configuration support. Successor `.6.6`
preserves the exact delivered `.6.5` catalog/crosswalk and all earlier receipts.
Catalog integration is not delivery; the ledger changes only after checked merge.
Terraform/supplied-plan and direct ARM-property helpers prepare allowlisted
Defender plan fields, activity-log routing, Managed HSM settings and VM patch
configuration. The source-specific interview prepares eight separate blank
scope/content/time-bound decisions through existing review, tier and replay paths.
The extra ARM versions are planned-only; live Collector routes are unchanged.

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
