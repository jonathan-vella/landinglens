# Versioned contracts

`alz_assessor.contracts.validate` is the executable validator for the JSON
contracts. Each document requires an explicit supported version (`"1.0"` or
`"1.1"`) and a `kind`. Existing producers/fixtures default to 1.0.
Unsupported versions fail rather than being interpreted as current data.
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

## Catalog and evidence contracts

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
