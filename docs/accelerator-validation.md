# Offline accelerator validation

You do not need a deployed ALZ to test LandingLens. Public Microsoft templates
provide representative **declared configuration**, not observed Azure evidence.
No Azure login, deployment, traffic test or live collection is part of this workflow.

## Reviewed inputs and result

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

| Input | Normalized resource records | Records marked known / unknown | Automated recommendation outcomes |
|---|---:|---:|---|
| Logging | 16 | 5 / 11 | All 12 unknown |
| Two-region hub networking | 2 | 2 / 0 | All 12 unknown |

These are **partial results, not full accelerator compatibility**. A known
record can still contain unknown properties or lack a resolved identity.
The hub result contains only resource-group records with unresolved identities;
it is not a two-VNet inventory.

Remaining gaps include variable-copy arrays, named copy indices, lambdas,
module-output references, scope expressions and unreviewed newer AVM APIs
(for example, the workspace uses `2025-07-01`). Deployment-time `pickZones()`
cannot be resolved offline. Unsupported branches and resources remain visible
in diagnostics; they are not treated as absent, compliant or verified.
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

This validates local compilation, partial assessment and the review/export
workflow. Full real-template interpretation still needs the listed compatibility
work; deployed behaviour and estate completeness require separately authorized
observed evidence.
