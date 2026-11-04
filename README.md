# LandingLens

Standalone, advisory-only Azure Landing Zones CLI, currently at the LL-01/LL-02
prerequisite stage. **This is a bounded parser feasibility spike, not an ALZ
assessment engine or a Microsoft-certified compliance tool.**

The approved [plan](docs/planning/plan.md), [PRD](docs/planning/prd.md) and
[backlog](docs/planning/backlog.md) retain the full release scope. Contracts,
control evaluation, live Azure collection, comparison and reports are not yet
implemented.

## Install and check

Python 3.12 or newer; exercised on Python 3.12.10 / Windows ARM64. Use your
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
Workspace name, location, resource group, retention, SKU and local-auth setting
resolve from the actual module. Ten unsupported resource controllers remain
symbolic; its internet-access comparisons and dynamic blocks remain unknown.
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

Snapshot/local module paths must resolve within the root or an explicit
`--authorize-root PATH`. Merely naming a manifest does not authorize unrelated
filesystem roots. Traversal and symlink escapes are rejected; snapshot trees
containing links are rejected. There is no module download/cache fallback.

Supported now: literals, declared variable defaults, ordered explicit variables
and files, conventional tfvars, locals (including forward references and cycle
detection), local module inputs/outputs, nested snapshots, attribute/index access,
scalar templates, boolean conditionals, `toset` of known strings, integer `count`
and map/string-set `for_each`. `.tf` uses the real HCL2 parser; `.tf.json` has a
separate JSON mapping with single-interpolation type preservation.

Unknowns remain explicit for data sources, remote state, computed resource
attributes, missing modules, unsupported functions/operators and unknown/invalid
expansion controls. Dynamic blocks remain an explicit unsupported value in this
spike; their bounded expansion is still required by LL-06, not removed from scope.
Provider-schema-specific JSON block normalization, constraints/type conversion,
validation checks, provider defaults, richer functions, splats, loops and full
HCL runtime semantics remain unproven. Do not use this spike to validate Terraform.

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
are withheld conservatively, but literals can contain sensitive data: use only
approved inputs and treat spike stdout as potentially sensitive. Production
redaction and versioned evidence contracts belong to later issues.

## Local Bicep compilation spike

```powershell
.venv\Scripts\alz-assessor spike-bicep tests\fixtures\bicep\local.bicep --compiler C:\path\to\bicep.exe
.venv\Scripts\alz-assessor spike-bicep tests\fixtures\bicep\unrestored.bicep --compiler C:\path\to\bicep.exe
```

Always invokes `build --no-restore --stdout` after recording `--version`.
Missing tooling, unrestored modules, timeouts, failed builds and invalid compiler
output fail explicitly without resource evidence. No automatic restore/install,
Azure authentication, what-if or deployment is attempted. Successful compilation
is **not** ARM expression evaluation: unresolved expressions remain in the template.
The result records root-source and template hashes, not a complete transitive
Bicep/parameter provenance bundle; that remains LL-07 work.

Both spikes use exit 0 for successful bounded analysis/compilation, even when
Terraform values are unknown, and exit 2 for invalid inputs or execution failures.
They print JSON only on success and errors to stderr. They are intentionally
separate from the future `assess` interface.

## Reviewed references

[Snapshot review](references/2026-11-04/review.md) documents exact taxonomy,
255-item inventory, duplicate IDs, unresolved mappings, precedence and reuse terms.
[Manifest](references/2026-11-04/manifest.json) and
[disposition ledger](references/2026-11-04/inventory.json) are versioned offline
inputs for subsequent catalog work. The baseline is not tenant policy.
[Dependency review](docs/dependency-review.md) records accepted/rejected candidates.

`tools/capture_references.py` is a deliberate network acquisition tool, not a CLI
dependency; it refuses to overwrite the frozen snapshot.
`tools/build_inventory.py` reproduces the reviewed derived inventory from pinned
bytes; it does not fetch or certify recommendation mappings.
`tools/capture_avm_fixture.py` explicitly captures the pinned AVM source fixture
and refuses to overwrite an existing snapshot. Its retained `.tf` files are
unmodified upstream material, not code to execute.
No Terraform command, IaC execution, deployment, live Azure collection or implicit
module retrieval is part of these prerequisites.
