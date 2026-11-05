# Versioned contracts

`alz_assessor.contracts.validate` is the executable validator for the JSON
contracts. Each document requires an explicit supported version (`"1.0"` or
`"1.1"`) and a `kind`. Existing producers/fixtures default to 1.0.
Unsupported versions fail rather than being interpreted as current data.
Assessment-only version 1.2 is an explicit opt-in described below; other document
kinds do not acquire a 1.2 interpretation.
The same contracts are used by adapters, evaluation, comparison and rendering.

## Evidence crosswalk version 1.0

The separate `crosswalk` document is validated by
`alz_assessor.crosswalk.validate_crosswalk`; it does not change catalog/evidence/
assessment contract 1.0 or 1.1. Every catalog GUID appears exactly once, including
explicit empty mappings. `catalog_sha256` binds the exact reviewed catalog;
future versions require a matching explicitly reviewed crosswalk.

Each target has an exact kind/ID, `equivalent`, `partial` or `related` strength,
reviewer rationale and unique source references. Supported kinds are ALZ policy
assignment/definition names, Microsoft built-in Policy definition IDs, PSRule rule
IDs/names and upstream ARG query SHA-256 values. ALZ associations require a pinned
`platform/alz` release. Source and licence URLs pin actual commits and retain
hashes, retrieval time, licence metadata and factual findings. An own audit's
underlying checklist licence is distinguished from a product licence grant.
No substantial upstream content is redistributed.

The packaged binding hashes the complete crosswalk, and offline generation
rechecks the actual frozen checklist/audit bytes and all 49 query hashes. Explicit
files are producer-supplied reviewed associations, not authenticated assertions.
Validation rejects changed catalog bindings, invalid/duplicate GUIDs, conflicting
targets, unknown source IDs, invalid target formats, missing hashes/rationale,
unreviewed versions and extra raw-data fields. Sources are bounded to 100,
targets to 100 per GUID and source references to 10 per target.

`catalog crosswalk inspect [--id ID]` returns mappings/provenance;
`catalog crosswalk validate` returns counts and validation status. Both are offline,
and ambiguous display IDs fail rather than choosing a GUID. Neither loads query
text, executes a scanner or changes assessment outcomes, review bindings, frozen
catalogs or the fixed-target ledger. Missing mappings do not imply N/A.

## Assessment version 1.2: evidence tiers

`assess --evidence-tiers`, `review serve --evidence-tiers` and
`replay export --evidence-tiers` explicitly select the new assessment contract.
Catalog/evidence/review contracts and bytes stay 1.0/1.1. Without the flag, output
retains its previous schema/meaning. `render` never upgrades a saved report.
`source_versions` distinguishes assessment contract from original catalog contract.

Per-mode `machine_evidence` is a strict boolean and `evidence_tier` is derived,
not an outcome. Verified requires an accepted automated predicate, current
freshness, explicit configuration confidence and pass/fail. It includes technical
failure; capability/scope N/A is not automatically Verified. Signal requires
current usable typed prepared evidence or a known subset of an otherwise
unresolved predicate population. Needs decision has no usable machine evidence.
Manual disposition is counted separately regardless of human review status.
A completed human attestation changes an allowed outcome, not the evidence tier.

`evidence_tiers` contains deterministic per-control identities/tiers and four
nonnegative integer counts. Each GUID is counted once across all resource
instances and planned/observed modes. Mixed Verified/unresolved targets are
Signal, not wholly Verified. Retired entries remain traceable as Needs decision
but stay outside active completion denominators. All 255 packaged GUIDs are
counted. No crosswalk, assignment presence, empty query, arbitrary scanner
metadata, resource presence or exception creates machine evidence or a pass.
The first tier producer uses existing reviewed typed preparation only; ingestion
adapters are separately scoped work.

Validation recomputes tiers/counts and rejects boolean/coerced counts, changed
identities and fields grafted onto 1.0/1.1 assessments. Comparison requires matching
contracts and recomputes tiers after refreshing evidence age. Review templates
retain the control tier with all decision fields blank. Local sessions persist
the explicit invocation selection without widening listener privileges.

Replay manifest 1.1 is selected only for tiered export and requires explicit
`evidence_tiers: true`; its semantic witness includes tiers. Replay manifest 1.0
keeps its exact three invocation fields and historical witness meaning. Original
evidence timestamps, reviewed facts, redaction and attribution rules remain.
JSON/Markdown/HTML share the same counts, with no browser-side tier evaluator.

## Catalog and evidence contracts

### Guided interview responses

The versioned `question-bank` 1.0 groups specific Key Vault operating-model and
private-service-path questions by exact retained human-evidence control IDs.
It exposes each control's own requirements/limitations; a shared question does
not claim the recommendations have identical meanings or outcomes.

`interview-response` 1.0 binds bank version, full catalog hash, question, explicit
scope, selected unique canonical control IDs, content hashes and a requirements
hash. Preparation leaves answer, reviewer, rationale, evidence, validity and every
per-control outcome null. Compilation requires every field and separate explicit
outcome, validates current scope/content/time through existing 1.1 reviews, and
produces only a standard `manual` document. No inferred answer-to-outcome mapping,
automated technical override, exception change or implicit reviewer exists.

All selected records validate before CLI output is opened exclusively; invalid/
expired/duplicate/conflicting bindings cannot leave a partial output or overwrite
existing records. Answer/field lengths and group sizes are bounded. The shared
narrative becomes attributable rationale, not machine evidence or a Verified tier.
Original single-control workflows and historical replay remain unchanged.

### Allowlisted query evidence

The separate packaged `query-allowlist` 1.0 accounts for all 49 frozen audited
GUIDs. Two exact unchanged local firewall Deny-mode queries are approved as
Signals; 47 exclusions retain their audited limitation and rationale. Query
bytes/SHA-256, canonical identity column, expected `id` and boolean-or-null
`compliant`, resource type and permission profile are pinned. The packaged
allowlist digest and every approved query hash are checked offline.
This is static review, not live service compilation proof or a new predicate.

`collect --query-guid GUID` requires 1-100 explicit unique subscription UUIDs and
the existing token environment. It rejects management-group/graph/inventory
flags and unallowlisted GUIDs before transport. The existing HTTP transport
accepts only fixed inventory or exact allowlisted query text at reviewed ARG
2022-10-01; it never accepts arbitrary caller KQL.

The executor uses existing bounded retries/response limits and at most
100 pages/10,000 retained identities with explicit skip tokens/object-array
counts/truncation. Foreign/wrong-type/malformed identities fail; missing or
wrong-type booleans remain unknown. Repeated tokens, denied/oversized/transient
failures, truncated-without-token responses and conflicting rows remain explicit.
Only identity and reported boolean are retained, never arbitrary returned tags,
names or fields. Pagination exhaustion cannot establish inventory authorisation;
the produced evidence always has `inventory_complete=false`.

Typed `query_evidence` keeps exact GUID/hash/scopes, original collection time,
pages/partial state and projected observations. Assessment 1.2 rechecks time and
bindings to produce query Signals, not configuration facts. Both boolean values
remain observations; empty output proves nothing. Partial/conflicted/unknown/
stale records cannot establish usable complete evidence or a passing outcome.
Reports, blank review preparation, comparison and replay preserve these semantics;
minimised output removes private resource/scope IDs. No query is run by assessment,
rendering or replay.

### Saved scanner evidence

`scanner-export` version 1.0 requires `format` (`psrule-json` or `sarif-2.1.0`),
`scanner` with plain bounded `name`, `version`, `baseline`, explicit `scope`,
`mode`, original `evaluated_at`, nonempty `artifact_hashes`, boolean `complete`,
`identities` and `output`. Mode/scope must match the supplied evidence exactly.
Each identity maps one result `index` to a canonical in-scope `arm_id`; target names,
paths and filenames never establish resource identity. Unbound results stay visible
but unusable. Raw output must be an explicit array for PSRule, or one SARIF run
with driver/results/invocations. No scanner is installed or executed.

Source review in [scanner-sources.json](../references/scanner-sources.json)
pins actual PSRule detailed output and SARIF example/schema/licence metadata.
The reviewed PSRule crosswalk maps SecureTransfer/AZR-000196 and
ContainerSoftDelete/AZR-000289 only. Rule-reference conflicts fail; other rules
and generic scanner namespaces remain explicit unmapped gaps rather than being
guessed equivalent to PSRule. SARIF driver/version and any ruleIndex/time binding
must agree with supplied provenance. Omitted SARIF kind has its specified fail
semantics, not a success inference. Suppressed/skipped/error states stay unusable.

Results and bindings are bounded to 10,000, structure depth to 32. External SARIF
properties, remote/absolute/traversal artifact paths, invalid versions/shapes,
duplicate bindings and replacement of existing normalised scanner records fail.
Messages, snippets, target names, raw object/detail/custom properties and input
path labels are withheld; input hashes retain neutral labels. Caller-supplied
producer/baseline/time/completeness are provenance assertions, not authenticated
scanner execution proof.

The supported PSRule for Azure module version is the actually reviewed
`1.48.0-B0228`. Detailed JSON declares that module/version in the wrapper.
SARIF from PSRule core must additionally identify the matching Azure module in
`tool.extensions`; core scanner name alone does not establish Azure rule provenance.

Assessment 1.2 retains typed `scanner_signals`, crosswalk/input/content hashes,
producer/version/baseline, mapped rule/status/target, flags and gaps. Pass/Fail
are Signals only; unknown/error/partial/failed/conflicted/stale/unbound/wrong-type
results remain visible and unusable. Existing outcomes never change. Separate
planned/observed scanner runs remain separate in comparison; their original times
are checked again. Review preparation leaves decisions blank. Replay retains the
projected metadata and semantic witness; minimisation removes private scope/IDs.

### Policy export and Signals

The explicit `policy-export` wrapper has schema version `1.0`, kind
`policy-export`, exact `scope`, original `collected_at`, `assignments`, `states`
and `exemptions`. Arrays contain saved ARM/PolicyStates objects and are bounded
to 10,000 each. All fields are required; unknown top-level fields, wrong shapes,
foreign targets/scopes, planned-mode attachment or replacement of existing saved
policy populations fail. `assess --policy-evidence FILE` requires `--evidence-tiers`.
The original resource evidence timestamp is not changed by import.

The importer projects assignment identity/definition/exclusions and context hash,
original evaluation identity/state/time/member hash, and exemption identity/
assignment/expiry. Raw parameters, descriptions, member labels and arbitrary
properties are withheld. Its `policy-export-content` binding hashes the explicit
parsed document; it is a semantic content hash, not a byte-for-byte export claim.
Existing normalised collector policy arrays use the same projector. Nothing
executes policy evaluations or follows definitions beyond the saved boundary.

Assessment 1.2's strict `policy_signals` envelope retains mapped records, exact
crosswalk hash, stable gap counts and an explicit non-outcome warning. The
verified seed supports direct built-in storage secure-transfer evaluations through
the partial crosswalk. Current Compliant/NonCompliant observations with canonical
in-scope targets, a unique matching assignment/definition and valid original times
can supply a Signal, never a pass or new resource fact. Collection time cannot
refresh evaluation time. Assignment alone or empty evaluations supplies no Signal.
No successful read proves policy/population completeness.

Missing/denied/partial contexts, conflicting records, exclusions, stale/future/
invalid times, unmapped definitions, unsupported states and indirect initiative
relationships stay visible and unusable. Initiative member interpretation and
other state values require further source-backed mappings; they are not silently
coerced to compliance. Effects, parameters/selectors/overrides and effective
exemption applicability always require review. The association does not establish
current enforcement or whole-control equivalence.

Technical outcomes remain independent. Per-mode `policy_signal_only` records when
policy evidence is the sole machine basis, so comparison can expire that Signal
at the original evaluation age even while resource collection is still current.
Review preparation leaves all decisions blank. Replay projects the same typed
metadata/provenance and preserves Signal semantics; minimised reports remove
resource/assignment/private definition identities. Stable policy guidance explains
gaps without triggering evaluation, changing access or recommending a wider scan.

Metadata-only successor `2026-11-05.5` carries the frozen checklist's optional
`severity`: High, Medium, Low or explicit Unknown. Its source-hashed priority
manifest binds all GUIDs, actual architecture/archetype captures and reviewed
limitations. `batch_catalog_version` identifies the unchanged `.3` matrix/source
bundle instead of copying it. The exact `.3` catalog and first crosswalk remain
frozen; crosswalk `.2` binds the new catalog without changing associations.
Severity is presentation metadata, not a predicate or an automatic applicability
decision; original four content hashes and all technical meanings are retained.
FR-31 must still classify future severity changes as needs-review and stale
affected reviews rather than treating priority changes as safe wording updates.

An optional explicit archetype file contains only `collected_at` and 1-100
`entries`, each with canonical MG `scope` and a reviewed architecture `group_id`.
The MG must equal the evidence scope. Unknown/duplicate/foreign bindings or raw
extra fields fail; no topology lookup, inheritance or default-name matching
occurs. `--archetypes` requires assessment 1.2 and cannot replace an existing saved
binding. The normalised metadata and hash preserve the supplied original time.

Only the verified `landing_zones` assignment association yields a positive G04.01
review suggestion. Missing/stale/unreviewed mappings yield no suggestion, not N/A
or a pass. Typed `applicability_suggestions` always require confirmation; they
cannot change `applicability` or outcomes. JSON/Markdown/HTML and review queue
ordering use one deterministic severity key; old catalogs without severity keep
their previous ordering. Replay retains bindings/suggestions and their witness;
minimisation removes the actual private scope.

Batch successor `2026-11-05.1` adds the narrowly typed 1.1 operation
`vault-deletion-protection`: only `Microsoft.KeyVault/vaults`,
`enableSoftDelete`, expected `true`, with the fixed second boolean
`enablePurgeProtection`. Both facts must be explicit booleans. Result `fact`
is the conjunction; `component_facts` retains both booleans for exact
configuration comparison and replay witnesses. This is not a general expression
engine. Existing boolean/firewall enum meanings are unchanged.

Successor `2026-11-05.2` adds `firewall-premium-sku`: only deployed
`Microsoft.Network/azureFirewalls`, property `sku.tier`, expected `Premium`.
Explicit Basic/Standard fail; unsupported, wrong-type or missing tiers stay
unknown. A Premium Firewall Policy is not a deployed firewall SKU or a feature
enablement/traffic-inspection claim. Both negative SKU facts remain available
for configuration comparison rather than collapsing every failure into a match.

Optional `review_resource_types` selects 1-10 explicit types for bounded
inventory preparation, not applicability or outcome evaluation. It participates
in the control content hash only when present, preserving historical hashes.
Templates/editor show up to 100 matching identities/types/states, original
collection time, inventory completeness, explicit truncation and whether
normalized resource evidence is available. Optional content-bound
`review_fact_paths` selects only the reviewed RBAC, network-access/default-action
and minimum-TLS scalar vocabulary, plus reviewed network SKU, canonical
relationship, IPv4 prefix/address and classic DNAT source facts.
Successor `2026-11-05.3` permits 1-8 reviewed paths, including top-level configured
firewall zones, explicit VNet DDoS flag/plan ID, subnet NSG references, private
endpoint target/state and minimal application-rule action/TLS/category-count
facts. No category labels, rule destinations, headers, descriptions, connection
messages, DNS names, private endpoint addresses or certificate material are retained.
Configured zones are limited to three distinct `"1"`/`"2"`/`"3"` identifiers;
empty and single-zone configurations never determine backend redundancy.
Application collections are bounded to 20 and their combined prepared rules to
100; category lists to 100 nonblank strings of at most 128 characters, retained
only as supplied-label counts (not validated category membership). Private
connections are bounded to 20 across both ARM connection arrays. Only explicit
ARM Approved/Pending/Rejected/Disconnected states are retained; Terraform
approval intent or an assigned IP cannot supply approval state. Aliases never
become ARM target IDs. Missing/invalid/defaulted facts stay unknown.
Network lists are limited to 100 entries; classic NAT collections to 20 with
100 rules each. Prefix capacity and direct-source subchecks run in the shared
evaluator, not browser code, and never establish whole-recommendation outcomes.
Only unique known subnet records can resolve explicit firewall/private-endpoint subnet IDs;
missing/ambiguous/inaccessible/wrong-type links are unknown, with at most
20 linked previews and explicit truncation. These typed local facts are informational
and may resolve the exact canonical subnet parent to one known VNet's DDoS facts,
never through names or new reads. Missing/denied parent evidence stays unknown.
They remain informational
subchecks, never a least-privilege, reachable private path or effective-policy
pass. Arbitrary raw properties and approvals are never copied. All original
review bindings/expiry apply.

| Kind | Required content and invariants |
|---|---|
| `catalog` | Version, canonical design areas, GUID-based local IDs, recommendation, related areas, applicability, method, automation disposition, evidence requirements, lifecycle and reviewed references. Tenant policy and organization extensions are separate mappings, not replacements for the recommendation baseline. |
| `evidence` | Planned/observed mode, source adapter, timestamp with timezone, explicit scope or null, nonempty SHA-256 artifact bindings, completeness, diagnostics and resource facts. Each resource has a logical address, type, optional canonical ARM ID, minimized properties, source location, state and non-known reason. |
| `assessment` | Catalog version, generation time, independent planned/observed results, reason codes, evidence links, freshness, method, completeness, exception disposition and coverage denominators. |
| `identity-map` | Exact evidence artifact hashes and unique logical-address/ARM-ID/scope entries. Hash mismatches, duplicates, unknown addresses, conflicting derived IDs and mismatched resource types are errors. |
| `manual` | Control ID, scope, outcome, rationale, supporting evidence reference and finite validity interval. Attestation does not overwrite automated technical evidence. |
| `exceptions` | Control ID, scope, accepted/rejected/pending disposition, rationale and finite validity interval. An accepted exception never converts a technical failure into a pass. |

Resource states are `known`, `unknown`, `inaccessible`, `error` and `absent`.
An absent resource requires an established ARM ID and complete relevant
inventory. Outcomes are independently `pass`, `fail`, `unknown`, `error`,
`manual` and `not_applicable`; absence and inventory completeness are not
synonyms for any one of these outcomes.

Identity requires explicit scope, type, name and complete parent names.
Names, Terraform addresses and ARM IDs are distinct. Same-name resources in
different groups do not match. Comparison requires canonical IDs and known,
current facts. Unsupported mappings and missing bindings are `not_comparable`.
Artifact hashes bind explicit scope/provider inputs as well as source files,
variable inputs and module manifests; no ambient subscription is used.

Versioned contracts allow additive metadata. Required fields and identity
invariants are validated, rather than silently defaulted. Evidence properties
outside the implemented control vocabulary are not exported. A report contains
only result facts, not raw source variables or provider configuration.

Required text must contain non-whitespace content, including manual evidence
references and manual/exception rationale. A known resource may have an empty
reason; other resource states require a reason. Catalog/result display IDs,
catalog flags and structured diagnostic lists are validated before evaluation
or rendering, so malformed saved documents produce explicit input errors.

## Version 1.1 lifecycle and reviews

Catalogs explicitly select `active` or `retired`. Retirement requires a timestamp
and rationale; records remain visible in every report but are excluded from
active denominators. Supersession references must exist and cannot form cycles.
Historical catalogs are not rewritten.

New manual/exception documents require an opaque, explicitly supplied reviewer,
supporting evidence, scope, validity and `control_sha256` from `control_digest`.
The hash covers recommendation/rule/applicability and review-relevant meaning,
not poll timestamps. Reviewer labels are assertions, not authenticated identity.
Duplicate dispositions fail instead of selecting the last record. Changed or
legacy-unbound records are visible as requiring review; 1.0 records retain their
old effect only against a 1.0 catalog. Exceptions never rewrite technical facts.

Assessment output adopts its catalog's contract version. Comparison rejects
mixed contract/catalog versions; incompatible content/rule hashes cannot create
matches, drift or absence. Historical 1.0 assessments remain readable.

Reviewed refresh retains every prior GUID. Changes to accepted predicates,
automation disposition or retirement require a 1.1 `change_review` with the exact
base catalog hash, accepted matrix hash, reviewer/time and unique before/after
control hashes with rationale. This is a review record, not a generic downgrade
switch; missing/malformed review evidence fails explicitly.

The successor catalog also uses a bounded `enum-equals` operation for the
reviewed firewall-policy mode fields only. Exact `Alert`/`Deny`/`Off` strings
and explicit `Basic`/`Standard`/`Premium` SKU applicability are typed separately;
booleans, coercions, omitted fields and unreviewed values cannot satisfy either.
Capability exclusions need an explicit recognized SKU. Stale/error evidence is
handled before applicability; incomplete inventory cannot prove no targets.
The original boolean operation and frozen 1.0 catalog meaning are unchanged.
Identity-safe comparison accepts exact enum facts under matching control/rule
hashes, never arbitrary strings or cross-type equality.
