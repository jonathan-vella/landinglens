# LandingLens

Standalone, offline-first, advisory Azure Landing Zones CLI. All **255** reviewed
checklist items remain visible across eight CAF design areas. The
[accepted automation baseline](docs/automation-matrix.md) implements two explicit
configuration checks: storage secure transfer and firewall-policy DNS proxy.
The other 253 items require human evidence; they are not silently treated as
passes. **This is not Microsoft certification or estate-wide compliance.**

Raw Terraform, Bicep/ARM, optional plan JSON and saved observed evidence share
[versioned contracts](docs/contracts.md), one evaluator and JSON/Markdown/HTML
reports. Read-only Azure collection is implemented but has only been verified
with mocks; **no live tenant collection or deployment was performed**.

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

## Assessment workflows

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
alz-assessor assess tests\fixtures\slice --input terraform --snapshots tests\fixtures\slice\snapshots.json --authorize-root tests\fixtures\alz --provider-version 4.50.0 --scope /subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-management --output planned.json
alz-assessor assess tests\fixtures\slice --input terraform --snapshots tests\fixtures\slice\snapshots.json --authorize-root tests\fixtures\alz --provider-version 4.50.0 --var secure=false --format markdown --output findings.md
alz-assessor assess tests\fixtures\slice\controls.bicep --input bicep --compiler C:\path\to\bicep.exe --scope /subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-management --format html --output bicep.html
alz-assessor assess template.json --input arm --parameters parameters.json --scope /subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-management --output arm.json
alz-assessor assess tests\fixtures\slice\observed.json --input evidence --at 2026-11-04T00:00:00Z --output observed.json
alz-assessor compare planned.json observed.json --output comparison.json
alz-assessor render comparison.json --format html --output comparison.html
```

The frozen observed fixture is assessed at its recorded example time. Comparison
rechecks both inputs against its own time and the 24-hour default freshness
limit, so this example becomes non-comparable when the fixture ages.
`--at` can reproduce comparisons of saved historical inputs; choosing a past
time cannot prove that newly read source files existed then. Current collection
time never makes old policy evaluations current. Missing bindings yield
`not_comparable`, not drift.

`--format json|markdown|html` applies to assess, compare and render. Every format
shows all dispositions, independent planned/observed results, evidence reasons,
source/catalog versions, subset metrics and inventory completeness. Findings
return **0**, including failures, unknowns and manual work. Invalid invocation or
unrecoverable input/tool failure returns **2**. Zero denominators are unavailable,
not 100%. CI checks software behavior; it does not gate on estate findings.

Normal workflows export only reviewed boolean properties, provenance and result
facts, not raw variable/parameter values. Marked sensitive Terraform values,
plan sensitivity markers and ARM secure parameters are withheld. An explicit
`--evidence-output FILE` saves the normalized evidence contract when needed for
later identity maps or plan associations. `--minimize` removes resource IDs,
source paths and topology from reports; minimized output is presentation-only
and cannot be used for comparison. HTML escapes all data and has no external
scripts, fonts or assets. Diagnostic spikes below are not assessment reports.

### Identity, manual evidence and optional plans

`--identity-map FILE` accepts an exact input-hash-bound map, not name matching.
Entries require `logical_id`, full `arm_id` and `scope`; duplicates, conflicting
IDs and stale input hashes fail. Default-provider derivation is restricted to
reviewed AzureRM 4.50.0 mappings and explicit scope/name/group bindings. Provider
selectors, module provider remappings and inline subscription/tenant bindings
are conservatively not auto-derived; use a reviewed identity map.

`--manual FILE` and `--exceptions FILE` accept the separate version-1.0 contracts
in [contracts.md](docs/contracts.md). Records require scoped control IDs,
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
[collection.md](docs/collection.md). No credentials are needed for offline use.

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
not supported. See the [reviewed source semantics](references/2026-11-04/review.md).

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

[Snapshot review](references/2026-11-04/review.md) documents exact taxonomy,
255-item inventory, duplicate IDs, unresolved mappings, precedence and reuse terms.
[Manifest](references/2026-11-04/manifest.json) and
[disposition ledger](references/2026-11-04/inventory.json) are versioned offline
inputs to the packaged catalog. The baseline is not tenant policy.
[Dependency review](docs/dependency-review.md) records accepted/rejected candidates.

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
