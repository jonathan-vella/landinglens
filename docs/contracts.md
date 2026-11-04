# Version 1.0 contracts

`alz_assessor.contracts.validate` is the executable validator for the JSON
contracts. Each document requires `schema_version: "1.0"` and a `kind`.
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
