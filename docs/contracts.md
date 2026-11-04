# Versioned contracts

`alz_assessor.contracts.validate` is the executable validator for the JSON
contracts. Each document requires an explicit supported version (`"1.0"` or
`"1.1"`) and a `kind`. Existing producers/fixtures default to 1.0.
Unsupported versions fail rather than being interpreted as current data.
The same contracts are used by adapters, evaluation, comparison and rendering.

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
