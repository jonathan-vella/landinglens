# Dependency review

## Tracker XLSX decision: 2026-11-05

LL-38 requires a static tracker snapshot, not spreadsheet calculation/editing.
Use standard-library `zipfile` and `xml.etree.ElementTree` for the seven-part
OOXML workbook with explicit inline text, styles, frozen headers, filter and
source notes. No runtime/dev dependency or installation is needed, so no new
package licence/feed/age/maintenance acceptance is implied. `openpyxl` was not
selected or installed: its additional editing/formula features are unnecessary
for this bounded output. Revisit the dependency review if scope later needs them.

All tracker cells are explicit text, with formula-like prefixes escaped in CSV
and XLSX; no formulas, macros, external links or hidden raw data exist. This is
a snapshot of the shared assessment model, not an editable calculation model.
No formula recalculation tool or Office process is required. Tests check ZIP/XML
parts/relationships, exact CSV/XLSX value parity, bounds, privacy and absence of
formula/error cells; native workbook inspection provides an additional
interoperability check without adding a project dependency.

Reviewed 2026-11-04 for LL-02. Exact metadata, upload timestamps, artifact hashes,
upstream project URLs, repository maintenance state and feed availability are
captured in `dependencies.json`. Every upstream repository was checked as
non-archived/non-disabled, with its last-push timestamp and metadata hash retained.
The configured approved index is
`https://packagefeedproxy.microsoft.io/pypi/simple/`; all nine exact versions
were present and an isolated Python 3.12.10 Windows ARM64 install succeeded
through that index. No public-index fallback was configured.

The seven-day minimum is measured against the newest artifact upload for each
selected release, not its first upload. Every selected version meets it.
This is a technical acceptance for the spike, not a claim of organizational
security/legal approval or a vulnerability audit.

| Dependency | Pin | License | Purpose and decision |
|---|---|---|---|
| python-hcl2 | 8.1.4 | MIT | Accepted HCL2 syntax parser; active upstream release 2026-09-08, repository not archived, pushed 2026-09-21 at review. Supports Python >=3.8. The spike uses its raw Lark AST rather than string regex parsing or arbitrary execution. |
| lark | 1.3.1 | MIT | Parser runtime required by python-hcl2; explicit transitive pin. Mature maintained parser; Python >=3.8. |
| regex | 2026.9.29 | Apache-2.0 AND CNRI-Python | Required by python-hcl2, not added as our IaC parser; explicit transitive pin. Recent maintained release; Python >=3.10. Preserve upstream license notices in distributions. |
| setuptools | 80.9.0 | MIT | Build backend only; deliberately mature version, not copied from APEX. No backend plugins. |
| ruff | 0.17.3 | MIT | Lint/format tooling; standalone tool, no Python runtime dependency chain. Uploaded 2026-10-27, over seven days old at review. |
| mypy | 1.18.2 | MIT | Type checker; mature pinned version with a small known dependency chain. Newer 2.4.1 uploaded 2026-10-28 is under seven full days at review and was not selected. |
| mypy-extensions | 1.1.0 | MIT | Required by mypy; accepted mature release. 1.2.0 uploaded 2026-11-03 is too new and rejected. |
| typing-extensions | 4.16.0 | PSF-2.0 | Required by mypy; compatible maintained release. |
| pathspec | 0.12.1 | MPL-2.0 | Required by mypy; development-only, unmodified library. Preserve MPL file-level notices/source obligations if redistributing it; no pathspec code is copied into this project. |

The release targets Python 3.12 and 3.13 (`>=3.12,<3.14`), with Windows/Linux
CI coverage and local Python 3.12.10 Windows ARM64 execution. Newer runtimes
remain unverified. Standard-library `argparse`, `unittest`, JSON, hashing,
HTTP transport and path handling remain sufficient for the full accepted
baseline. No dependencies were added for downstream implementation: no pytest,
Azure SDK, authentication package, template engine or CLI framework is needed.

python-hcl2 was a candidate, not predetermined: its maintenance and compatibility,
feed presence, MIT license, package age, `.tf` AST, `.tf.json` integration and
unknown-expression behavior were inspected and exercised before accepting it
for this spike. Version 8 preserves quotes and adds serialization metadata by
default; the raw AST avoids confusing literal strings with serialized expressions.
It is **not** an evaluator: the small allowlisted evaluator is our code.
No dependency evaluator or Python `eval` is invoked.

Metadata/license evidence comes from PyPI version metadata and the installed
distribution notices; metadata alone is not a license grant. Upstream project
URLs are retained per dependency for subsequent maintenance review. The dependency
installation preserves their bundled notices. The snapshot notices under
`references/` apply only to reference material, not a new project-wide license.
The owner has not chosen a product license or approved publication.

`tools/vet_dependencies.py` is an explicit maintainer network utility. Normal
CLI commands/tests do not contact PyPI or the package feed. Re-vetting must not
silently replace pins; edit the manifest and review the new metadata first.
