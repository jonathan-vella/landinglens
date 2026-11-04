# Reference review: 2026-11-04.1

Review scope: retrieve the three approved sources, inspect their actual text
and complete checklist inventory, review reuse terms, and verify input-tool
semantics. This is a source/inventory review by the implementation author, not
Microsoft certification, a legal opinion, or owner acceptance of automation.

`manifest.json` binds each source URL to its retrieval time and SHA-256. For
GitHub-backed sources it pins the reviewed repository commit and retains the
unmodified source bytes and license. The rendered public pages were retrieved
as well, but only their hashes/URLs are retained. The rendered page can lag the
repository: its hash is not claimed to be the hash of the Markdown snapshot.
No website images, logos, themes or page layouts are redistributed.

## Taxonomy and precedence

The CAF article's Environment and Compliance tables (`caf-design-areas.md`,
lines 24-27 and 41-44) publish eight design areas:

1. Azure billing and Active Directory tenant
2. Identity and access management
3. Resource organization
4. Network topology and connectivity
5. Security
6. Management
7. Governance
8. Platform automation and DevOps

The exact table rows and source line numbers are also in `inventory.json`.
Do not substitute newer terminology without reviewing the source.

The technical ALZ site points to Learn for concepts (`alz-site.md`, lines
15-17). It describes management groups, policy, RBAC, centralized logging and
networking as platform components (lines 33-46), not a competing taxonomy.
Its links to the ALZ Library are not permission to replace the full checklist
with a policy baseline.

Documented guidance defines recommendations; the checklist supplies the
assessment inventory. Effective tenant policy and organization-specific
requirements must have separate mappings, not overwrite the Microsoft baseline.
Individual linked recommendation pages have **not** all been reviewed. The
ledger therefore explicitly flags every item-to-guidance and applicability
mapping as unverified. It makes no platform/application applicability decisions.

## Actual checklist structure and identifiers

The pinned JSON has top-level `items`, `categories`, `waf`, `yesno`, `status`,
`severities` and `metadata`. Metadata says "Azure Landing Zone Review", state
"GA", and timestamp "February 25, 2026"; that timestamp is upstream metadata,
not this review's retrieval time or proof that each recommendation is current.

All 255 items contain `category`, `subcategory`, `text`, `waf`, `guid`, `id`,
`severity` and `link`. Optional fields are `service` (170), `training` (221),
`graph` (49), `ammp` (2) and `description` (4). These are observed fields and
frequencies, not an asserted upstream JSON Schema. Preserve optional fields.

There are 255 unique GUIDs. `id` is **not unique**: `B03.02`, `D05.08` and
`D07.12` each occur twice. The ledger keys by the actual upstream `guid`, retains
the display `id`, and points back to the full item using a JSON Pointer.
No upstream guarantee of identifier permanence across revisions was found:
GUID is the unique snapshot key, not an invented guarantee of eternal stability.
A future refresh must diff GUIDs, display IDs and content, not renumber silently.

Checklist categories have counts:

| Published category | Items |
|---|---:|
| Azure Billing and Microsoft Entra ID Tenants | 15 |
| Identity and Access Management | 24 |
| Resource Organization | 22 |
| Network Topology and Connectivity | 106 |
| Governance | 16 |
| Management | 26 |
| Security | 32 |
| Platform Automation and DevOps | 14 |

The billing category differs materially from CAF's published name. Case-only
differences also exist. Proposed category-to-area associations are retained as
**candidate, not verified**; the billing conflict is flagged on all 15 affected
items. Checklist letter prefixes are not CAF diagram legend letters (for
example networking is D in the checklist and E in CAF). Never map by prefix.

All 255 recommendation texts were inspected. The explicit per-item ledger has
7 candidate-automated, 206 candidate-assisted and 42 candidate-manual dispositions,
each with source revision/hash, retrieval time, item hash, pointer, rationale
and unresolved flags. Candidates are not committed automation coverage.
The seven configuration-property candidates are D07.06, D07.07, D07.18, F01.08,
G02.03, G04.01 and G04.02. Context, exceptions, full recommendation coverage and
provider-specific behavior still require mapping and positive/negative fixtures.
An upstream `graph` query is untrusted reference text, not an executable or
validated compliance test; none was run. No item was removed or declared
not-applicable without an assessment scope. Time-sensitive text (for example
D05.07's September 2025 retirement date) is preserved, not certified current.

## Reuse and retention

| Material | Reviewed terms | Retention decision |
|---|---|---|
| ALZ technical site's repository source | MIT, Microsoft copyright; `alz-site.LICENSE` | Retain unmodified Markdown and license; derived excerpts require the same notice. No implied endorsement or trademark rights. |
| ALZ review checklist | MIT, Microsoft copyright; `alz-checklist.LICENSE` | Retain full JSON and license; inventory is a derived index with explicit change indication here. |
| CAF article's repository source | CC BY 4.0; `caf-design-areas.LICENSE` | Retain Markdown with attribution to Microsoft and contributors, original immutable URL, license, and indication that the taxonomy/ledger are derived. |
| Bicep article's repository source | CC BY 4.0; `bicep-cli.LICENSE` | Same attribution/license/change-indication obligations. No claim that sample code licenses license the whole product. |
| Microsoft Learn website | `https://learn.microsoft.com/en-us/legal/termsofuse`, "Notice Specific to Documents" | Explicit document licenses control conflicts with general site restrictions. Retain the CC-licensed repository text above, not website assets. Terms URL and retrieved checksum are in the manifest. |
| HashiCorp variable documentation | Public documentation page; no blanket redistribution permission inferred | Retain factual semantics in our own words and source URL/checksum only; do not redistribute page HTML or full prose. |

The retained sources are unmodified. `inventory.json` and this review are
LandingLens-derived material, not documents published or approved by Microsoft.
License files are kept beside the snapshots and must accompany redistribution.
Check third-party linked material separately before importing it. This review
does not authorize copying every page linked from a checklist item.

## Verified Terraform variable semantics

Reviewed: <https://developer.hashicorp.com/terraform/language/values/variables>,
sections "Assign values to variables", "Variable definition files" and
"Undeclared variables". The site lists highest precedence first; the spike
applies the following order **lowest to highest**:

1. Declared defaults.
2. Explicitly opted-in environment values.
3. `terraform.tfvars`.
4. `terraform.tfvars.json`.
5. `*.auto.tfvars` and `*.auto.tfvars.json` together in lexical filename order.
6. Explicit variable and variable-file arguments in their supplied order;
   the last assignment wins.

Ambient `TF_VAR_*` is never read. Explicit file arguments in the CLI are
interleaved with `--var NAME=JSON_VALUE`; they are not grouped by option type.
JSON CLI values are an intentionally narrower input syntax than Terraform's
shell-dependent `-var` syntax. HCP Terraform workspace/set precedence is not
implemented: this is an offline local CLI, not an HCP Terraform execution.
Child modules receive only caller inputs and their own defaults, not root
tfvars, root locals, the caller's variables or ambient environment.

Also reviewed: <https://developer.hashicorp.com/terraform/language/syntax/json>,
"Expression Mapping" and "Block-type-specific Exceptions". JSON expression
strings use template semantics; a single interpolation preserves its value's
type. Native quoted templates stringify scalar interpolations. These paths
have separate executable fixtures. Provider-schema-specific JSON nested block
interpretation is not proven by this prerequisite spike.

## Verified Bicep semantics

`bicep-cli.md`, lines 90-119, says normal build automatically restores external
registry modules and `--no-restore` prevents that behavior. If an external
artifact is not cached, the build fails. The `restore` section (lines 604-610)
describes downloading artifacts to the local cache. Documentation's suggested
restore workaround is **not** executed by LandingLens.

The spike invokes only an already installed standalone executable:
`bicep --version`, then `bicep build FILE --no-restore --stdout`. It does not use
the Azure CLI wrapper, whose install/upgrade behavior is outside this spike.
No fallback installs tools, restores modules, logs in, runs what-if or deploys.

Actual compiler verification used Bicep CLI 0.47.16 (3f73e1a234). A local workspace
template compiled successfully; its location remained an ARM parameter expression,
not a resolved resource property. The unrestored unique `.invalid` registry module
failed with BCP190 and no resource evidence. Missing executable, timeout, invalid
output and failed-build-with-partial-stdout cases have executable tests.

## Freeze and downstream consumption

Snapshot version: **2026-11-04.1**. Manifest SHA-256 values bind retained
content/license bytes; `inventory_sha256` binds the derived ledger. Git attributes
prevent line-ending conversion from corrupting those checksums. Offline tests
verify exact coverage, taxonomy citations, hashes and duplicate-ID flags.

Later catalog work consumes this inventory and performs the still-unverified
item/control mappings, rather than re-inventing source taxonomy or dropping
items. A refresh must use a new version, review upstream changes/terms and retain
historical snapshots. Do not rerun acquisition over this reviewed directory.
