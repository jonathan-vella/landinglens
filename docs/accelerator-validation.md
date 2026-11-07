# Offline accelerator validation

You do not need a deployed ALZ to test LandingLens. Public Microsoft templates
provide representative **declared configuration**, not observed Azure evidence.
No Azure login, deployment, traffic test or live collection is part of this workflow.

## Multi-region scenario and report package

The reusable
[fictional two-region Bicep ALZ](examples/bicep-multiregion-alz/README.md)
adds governance, central logging, Sweden Central and Germany West Central hubs,
Premium Azure Firewalls, VPN declarations, and one spoke per region. Its
baseline, controlled-defect, and remediated assessments remain separate across
four explicit fictional scopes. Frozen compiler-produced ARM fixtures make the
assessment/report workflow reproducible without a compiler or network access.

The scenario demonstrates supported firewall-threat-intelligence and peering
configuration changes, while keeping VPN operation, unsupported
local-network-gateway properties, and owner-specific retention requirements
unknown or manual. The sample reports are planned configuration evidence only;
they do not prove deployed behavior or compliance.

## Reviewed inputs and results

The offline experiment used the MIT-licensed
[ALZ Bicep Accelerator](https://github.com/Azure/alz-bicep-accelerator/tree/88dcafa6afcd57e1b3ccd772a81c88bd29ae2ac2/templates),
revision `88dcafa6afcd57e1b3ccd772a81c88bd29ae2ac2`, with unchanged
`core/logging/main.bicep` and `networking/hubnetworking/main.bicep`.
The [provenance record](../references/accelerator-validation.json) identifies
the snapshot and all 14 acquired module versions/OCI manifests.
Keep Microsoft's LICENSE with any copied source.

An existing Bicep CLI 0.47.16 compiled both templates after **explicit**, separately
authorized public-module acquisition. The compiler cache was isolated and cloud
credential precedence was empty. Subsequent compilation and assessment used
`--no-restore`; the module-cache bytes did not change during assessment.
An initial empty-cache build failed with BCP190 as expected.

The initial experiment in #170 produced:

| Input | Normalized resource records | Records marked known / unknown | Automated recommendation outcomes |
|---|---:|---:|---|
| Logging | 16 | 5 / 11 | All 12 unknown |
| Two-region hub networking | 2 | 2 / 0 | All 12 unknown |

The compatibility follow-up uses the **same compiled bytes and fictional base
parameters**, without changing Microsoft sources:

| Input | Normalized resource records | Records marked known / unknown | Assessment |
|---|---:|---:|---|
| Logging | 8 | 8 / 0 | Workspace identity, PerGB2018 SKU, retention 30 and explicit ingestion/query flags recovered; all 12 automated outcomes still unknown |
| Two-region hub networking | 20 | 20 / 0 | Two scoped VNets, four subnets and two reciprocal peerings recovered; 263 assessment rows covering all 255 recommendations |

The hub's automated **resource rows**, not distinct recommendations, include two
passes for D01.13 (declared peering access), two failures for D07.06 (declared
firewall threat-intelligence mode), two not-applicable rows and 14 unknown rows.
This is not 255 automatic checks or observed operating assurance.

Controlled fictional inputs verify workspace retention 30 to 90, VNet prefix
changes, D01.13 pass to fail when both peering access flags are false, zero
peerings when both deployment flags are false, and absence of firewalls/policies
when their flags are false. Disabled Bastion, VPN/ExpressRoute, DDoS and private
DNS resources are not invented. All seven cases produce valid minimized
HTML/XLSX exports and semantically identical local replay.

The reader now handles bounded variable/property copies, named indices,
map/filter/reduce lambdas, null-safe access, positional string formatting,
explicit subscription/resource-group IDs and locally provable module outputs.
Nullable parameters retain null. Null supplied to a nonnullable parameter uses
only its declared default; a required parameter without a default stays unknown.
That distinction was independently checked with the existing Microsoft Bicep
local test engine, including a failing negative assertion, without restoration.
Secure or unresolved local type references remain withheld.

The unchanged hub template also redeclares VNets and reciprocal peerings in
multiple modules. Equal **projected** declarations share one inventory row with
both addresses recorded in diagnostics. Conflicting projected declarations
become unknown; there is no last-write-wins compliance assumption.
Duplicate identities within one template still fail validation.
Existing pointers remain outside created-resource inventory.

The [follow-up provenance](../references/accelerator-compatibility.json) records
six actually reviewed API pages and their content hashes/revisions. Support is
restricted to the reviewed projections, including workspace `2025-07-01`,
onboarding `2025-09-01`, peering `2024-01-01`, firewall/policy `2024-10-01`
and route table `2024-07-01`. Newer perimeter access states remain unknown under
the existing two-state workspace projection; they are not mapped to Enabled.
These API additions apply only to offline ARM/Bicep interpretation; observed
collector API allowlists and routes are unchanged.

These are **useful selected-template results, not full accelerator compatibility**.
A known record can still contain unknown properties. Inventory remains explicitly
incomplete when pointers/redeclarations or other diagnostics are present.
External resource references, runtime-assigned properties, linked templates,
output-copy forms, unsupported expression forms/APIs and deployment-time
`pickZones()` remain unknown. A local output is evaluated only from supplied
inline templates and parameters, not queried from Azure. No observed evidence
is generated from these declared configurations.

Limits remain 2 MB input, 256 copy/lambda elements, 256 total resource/deployment/
reference instances, 16 deployment levels, 64 expression depth and 10,000 steps
per expression context. Empty nested deployment fan-out is also globally bounded.
Do not rewrite Microsoft templates or substitute older APIs just to obtain passes.

The experiment exposed two ARM-reader defects, now covered by regressions:
expression-valued nested parameter wrappers (`if`/`createObject`/`empty`) and
symbolic `existing` resource references. Existing references are not created
resource inventory, and unsupported parameter wrappers remain unknown.
Object construction remains bounded; scalar bindings and ambiguous keys are rejected.

## Repeat the workflow

1. Acquire the exact public snapshot above and retain its LICENSE.
2. Copy the selected template trees into a working directory. Preserve the
   original `.bicep` bytes. In its `bicepconfig.json`, configure a dedicated
   `cacheRootDirectory` and `"cloud": {"credentialPrecedence": []}`.
3. With explicit approval for module acquisition, run the existing compiler's
   `restore` command on each selected entry point. Verify acquired versions and
   manifest/layer digests against the provenance record. Do not install a compiler
   or run the accelerator bootstrap/deployment scripts.
4. Use fictional parameter files, never tenant credentials or real owner decisions.
   The experiment used one logging workspace and two hub configurations in
   `westeurope`/`northeurope`; telemetry was disabled. Accelerator
   `{{...}}` placeholders must not be mistaken for resolved configuration.
5. Assess with the existing compiler and explicit scope/ARM parameter JSON:

```powershell
alz-assessor assess .\working\templates\core\logging\main.bicep --input bicep --compiler C:\path\to\bicep.exe --parameters .\logging.parameters.json --scope /subscriptions/00000000-0000-0000-0000-000000000001 --evidence-tiers --evidence-output .\logging.evidence.json --output .\logging.assessment.json
alz-assessor render .\logging.assessment.json --format html --minimize --output .\logging-report.html
alz-assessor render .\logging.assessment.json --format xlsx --minimize --output .\logging-tracker.xlsx
```

XLSX output must be a new file. Alternatively, compile with
`bicep build ENTRY --no-restore --outfile template.json` and assess
`--input arm`; keep the compiler/source/module provenance alongside that output.

## Reviews, controlled changes and replay

The experiment also verified blank review preparation, a clearly labelled
fictional manual decision, immutable save/resume, HTML/XLSX output and local
replay. Saving that fictional decision changed no technical outcome and
preserved the original evidence time. It is not a real incident-response review.

For selected file-based reviews, use an **assessment** as the preparation input:

```powershell
alz-assessor review prepare .\logging.assessment.json --scope /subscriptions/00000000-0000-0000-0000-000000000001 --kind manual --control ALZ-b86ad884-08e3-4727-94b8-75ba18f20459 --output .\review-template.json
```

For the local reviewer workspace, use saved **evidence** instead:

```powershell
alz-assessor review serve .\logging.evidence.json --directory .\private-reviews --evidence-tiers
```

Changing the fictional logging tag object from one key to no keys changed the
resolved resource-group tag count from 1 to 0 and changed the input binding hash.
Changing unsupported configuration must not manufacture a known result.
Never generate observed evidence from compiled templates.

```powershell
alz-assessor replay export .\logging.evidence.json --at ORIGINAL_EVIDENCE_TIME --evidence-tiers --destination .\logging-replay
alz-assessor replay run .\logging-replay --format html --output .\logging-replayed.html
```

Use the recorded `collected_at`, not a new timestamp to make old evidence current.
Replay retains scoped resource identities and is not anonymized. Keep review
files and local capability URLs private.

The historical compatibility experiment also produced a separate offline kit;
its `compatibility\acceptance.py` script is not included in this repository.
For a reproducible repository-contained workflow, use the
[multi-region example](examples/bicep-multiregion-alz/README.md) and its frozen
fixtures. The historical provenance record remains available above.

This validates local compilation, selected-template interpretation and the
review/export workflow. Other accelerator entry points and unsupported patterns
are not covered; deployed behaviour and estate completeness require separately
authorized observed evidence.
