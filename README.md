# LandingLens

LandingLens is an offline-first, advisory assessor for Azure Landing Zones. It
assesses supplied infrastructure-as-code or saved observed evidence against the
packaged ALZ checklist, highlights configuration findings and unknowns, and
helps reviewers record decisions. It does not deploy infrastructure, certify
compliance, or prove that a configuration works in a live environment.

The catalog retains all 255 checklist GUIDs. Some recommendations have bounded
configuration checks; others need machine-assisted or manual review. A result
row can represent one resource target, so row counts are not counts of distinct
recommendations. See [what LandingLens does and doesn't prove](docs/what-landinglens-proves.md).

## Install

Use Python 3.12 or 3.13 and an approved package index. From a checkout on Windows:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install .
.venv\Scripts\alz-assessor catalog validate
```

On Linux, use `.venv/bin/python` and `.venv/bin/alz-assessor` instead. Run
commands from the repository root.

## Try an offline assessment

The supplied observed fixture is historical. The explicit time reproduces the
example; it does not make old evidence current.

```powershell
.venv\Scripts\alz-assessor doctor tests\fixtures\slice\observed.json --input evidence
.venv\Scripts\alz-assessor assess tests\fixtures\slice\observed.json --input evidence --at 2026-11-04T00:00:00Z --evidence-tiers --output assessment.json
.venv\Scripts\alz-assessor render assessment.json --format html --minimize --output report.html
.venv\Scripts\alz-assessor render assessment.json --format xlsx --minimize --output tracker.xlsx
.venv\Scripts\python tools\build_report_canvas.py --report "Example" assessment.json --fictional --output-directory report-preview
```

Open `report.html` or `report-preview\index.html` in a browser. Use new paths for
the XLSX file and preview directory; they are not overwritten. Findings,
unknowns and manual work do not make the command fail. Invalid input or an
unrecoverable error returns exit code 2.

Full evidence and review files can contain resource identities and reviewer
text. Minimized output is presentation-only, not a guarantee of anonymity, and
cannot be used for comparison or replay. Keep generated files private and
review them before sharing.

## Learn more

- [User guide](docs/user-guide.md): inputs, assessment, review, reports and canvases.
- [Multi-region example](docs/examples/bicep-multiregion-alz/README.md): fictional
  Bicep scenarios and reproducible offline reports.
- [Collection boundaries](docs/collection.md): explicit authorization and
  existing-token requirements for optional live collection.
- [Contracts](docs/contracts.md), [automation matrix](docs/automation-matrix.md)
  and [technical reference](docs/technical-reference.md): supported formats,
  limitations and maintenance.
