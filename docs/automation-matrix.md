# Accepted release automation matrix

The owner explicitly delegated LL-04 acceptance to Autopilot in the attached
execution authorization. This replaces the original human-interruption gate,
not the coverage safeguards. The accepted baseline is two explicit property
checks below, plus visibility and disposition for **all 255** reviewed checklist
items across the eight verified CAF design areas. The baseline cannot silently
shrink when adapters or catalog versions change.

The actual control-source review, retrieved bytes' checksums, timestamps, exact
AzureRM revision and reuse notes are frozen in
`references/2026-11-04-controls/manifest.json`. The reviewed checklist remains
`references/2026-11-04` (version 2026-11-04.1). Local IDs are `ALZ-` plus the original GUID; display IDs
are labels, not unique keys.

| Checklist item / GUID | Area and applicability | Automated evidence | Required positive / negative / unknown fixtures |
|---|---|---|---|
| G04.01 / b03ed428-4617-4067-a787-85468b9ccf3f | Security; platform and application storage accounts | Explicit `properties.supportsHttpsTrafficOnly`; raw AzureRM **4.50.0** `https_traffic_only_enabled`; compiled Bicep/direct ARM **2023-05-01**; saved/collected configuration | Explicit true / false in each mode; omitted or unresolved setting unknown; missing supplied security module unknown; secure parameter withheld |
| D07.18 / 94f3eede-9aa3-4088-92a3-bb9a56509fad | Network topology and connectivity; platform and application firewall policies | Explicit `properties.dnsSettings.enableProxy`; raw AzureRM **4.50.0** `dns.proxy_enabled`; compiled Bicep/direct ARM **2024-05-01**; saved/collected configuration | Explicit true / false in each mode; absent DNS configuration and unresolved inheritance unknown |

These are configuration checks, **not** Microsoft certification, runtime tests,
or proof that client DNS traffic actually traverses a firewall. Classic
standalone firewall DNS settings, parent-policy effective DNS resolution, Azure
Files SMB/NFS encryption and omitted provider/API defaults are outside these
automated predicates. Unsupported versions remain unknown. The storage REST
setting does not establish Azure Files encryption effectiveness.

## Explicitly accepted uncovered design areas

| Design area | Accepted release disposition and reason |
|---|---|
| Azure billing and Active Directory tenant | Assisted/manual: billing/tenant relationships and authorization need separately scoped evidence, not resource-name inference. The checklist's newer billing/Entra label remains recorded separately. |
| Identity and access management | Assisted/manual: no Microsoft Graph collection or identity-effectiveness inference is authorized or implemented by the baseline. |
| Resource organization | Assisted/manual: organization intent and hierarchy suitability need reviewer judgment; a management-group resource alone is not proof. |
| Management | Assisted/manual: workspace existence does not prove operational monitoring, retention intent or incident processes. |
| Governance | Assisted/manual: assignment existence is not compliance; organization intent, exemptions and evaluation results stay separate. |
| Platform automation and DevOps | Assisted/manual: bounded IaC analysis does not prove delivery-process or repository governance effectiveness. |

Every nonautomated item retains its original recommendation, guidance reference,
GUID, display ID, provenance, taxonomy mapping, uncertainty flags and explicit
human-evidence rationale. Applicability labels are conservative review routing,
not verified tenant-specific applicability. No candidate Graph query becomes an
automated rule by import.

## Acceptance evidence and sequencing

LL-04 exercises the storage slice through the common versioned contracts:
module-based raw Terraform with supplied ALZ and security snapshots, pass/fail,
missing modules, current saved observed match/drift, missing-scope
`not_comparable`, complete-only absence, and the same JSON/Markdown/HTML model.
`tests/test_assessment.py` is the slice regression baseline.

`tests/fixtures/slice/controls.bicep` is parameterized for both accepted controls;
`tests/test_matrix.py` exercises explicit true/false fixtures for Bicep, direct
ARM, raw Terraform and observed evidence. `tests/test_workflows.py` adds installed
CLI rendering/comparison, input-binding and partial-evidence cases;
`tests/test_collection.py` uses injected transports only. Actual installed Bicep
compilation is exercised locally without restore; environments without that
tool report explicit skips. These are fixture-based checks only. Live Azure
collection and deployment are neither performed nor claimed.
