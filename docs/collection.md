# Explicit-scope read-only collection

The original release collector was verified with injected transports and saved
fixtures, not a live tenant. That historical baseline is unchanged. Subsequent
owner-authorized access probes are bounded access evidence, not full collector
or control verification. Normal assessment and tests need no Azure credentials.

## Next-increment scoped collection

The accepted first wave adds only explicit firewall-policy `sku.tier`,
`threatIntelMode` and `intrusionDetection.mode` to the existing approved detail
projection. It does not collect bypass lists, secrets or arbitrary properties.
Missing or wrong-type fields remain unknown. API/provider semantics and the
bounded local-configuration meaning are in the
[successor matrix](automation-matrix.md#accepted-successor-matrix-bounded-first-wave).

Optional `collect --resource-graph` replaces subscription resource enumeration
with the **fixed** `resources | project id, type` query. Scope is an explicit
subscription array in every POST body, derived only from supplied subscriptions
or validated management-group descendant chains. There is no arbitrary-query,
tenant-wide or partial-scope switch. ARG supplies inventory, not control
outcomes; approved per-resource ARM GETs supply configuration. Eventual
consistency and incomplete child-resource population remain explicit.

ARG object-array results, exact counts, truncation and continuation tokens are
validated independently of RBAC coverage. Missing tokens on truncated results,
repeated tokens, foreign resource identities, malformed counts and denied reads
cannot establish completeness. Existing `--inventory-authorized` remains a
separate caller attestation, never inferred from successful requests.

All validated child management groups receive scoped policy reads. Assignment
and exemption conflicts remain unusable/conflicted rather than selecting a
last record. Management-group exemptions explicitly use `atScope()` to retain
applicable and expired evidence without the service's unfiltered-list failure.
PolicyStates preserve original evaluation times; collection start time does not
re-date them or trigger evaluation.

Policy definitions and initiatives are listed at exact requested scopes.
Referenced definitions resolve only within that boundary or as Microsoft
built-ins; an ancestor/custom definition outside the approved boundary stays an
explicit gap, not permission to broaden reads. Definition/rule/parameter hashes,
initiative associations and inaccessible states are retained, not arbitrary
rule bodies or parameter values. These are configuration categories, never
recommendation-compliance results. Reference expansion is bounded to 16 levels,
1,000 definitions/initiatives and 10,000 member associations.
Initiative members must reference policy definitions, not nested initiatives.

The new pinned read-operation review is
[`collection-apis.json`](../references/2026-11-04-wave1/collection-apis.json).
It records actual ARG 2022-10-01 and definition/initiative 2023-04-01 source
hashes, revisions, operations and schema names. Only the recorded runtime
allowlist is used; reviewed OpenAPI metadata is not executable authorization.

`collect` requires explicit subscription IDs or one management-group name.
Management-group descendants are enumerated, including subscription/parent
relationships. Subscription assignment lists retain both inherited (`atScope()`)
and descendant assignments; IDs deduplicate the two lists. Original assignment
scope, definition ID, exclusions, selectors, overrides and enforcement mode are
retained. Parameter names and value hashes are retained, but parameter values
are withheld. Exemptions retain assignment/reference associations and expiration.
None of these records is interpreted as recommendation compliance.

Policy-state queries are separate, read-only **POST queryResults** operations,
not evaluation triggers. Their per-resource compliance state and original
evaluation timestamp remain separate from resource configuration and collection
time. Old policy evaluations are not made current by recollecting them. The
initial automated controls inspect explicit resource configuration only; all
governance judgments remain human-evidence work.

## Verified operations and least privilege

Public Microsoft REST references verified resource enumeration
(`2021-04-01`) and management-group descendants (`2020-05-01`). The exact pinned
policy OpenAPI operations, filter semantics, retrieval timestamps, hashes and
the Policy Insights query permission are recorded in
[`collection-apis.json`](../references/2026-11-04-controls/collection-apis.json).
Control-specific GET versions are recorded in the
[accepted matrix](automation-matrix.md) and its source manifest.
Supplementary operation and nested-template review metadata is retained in
[`collection-support.json`](../references/2026-11-04-controls/collection-support.json);
the previously frozen policy review was not overwritten.

| Read operation | API version | Required action at the selected scope |
|---|---|---|
| GET subscription resources | 2021-04-01 | `Microsoft.Resources/subscriptions/resources/read` |
| GET management-group descendants | 2020-05-01 | `Microsoft.Management/managementGroups/descendants/read` |
| GET storage-account configuration | 2023-05-01 | `Microsoft.Storage/storageAccounts/read` |
| GET firewall-policy configuration | 2024-05-01 | `Microsoft.Network/firewallPolicies/read` |
| POST fixed ARG inventory with explicit subscription body | 2022-10-01 | `Microsoft.ResourceGraph/resources/read` plus visibility of every relevant resource |
| GET scoped/referenced policy definitions | 2023-04-01 | `Microsoft.Authorization/policyDefinitions/read` |
| GET scoped/referenced initiatives | 2023-04-01 | `Microsoft.Authorization/policySetDefinitions/read` |
| GET policy assignments, unfiltered and `atScope()` | 2023-04-01 | `Microsoft.Authorization/policyAssignments/read` |
| GET policy exemptions, including expired entries | 2022-07-01-preview | `Microsoft.Authorization/policyExemptions/read` |
| POST latest policy-state query results | 2019-10-01 | `Microsoft.PolicyInsights/policyStates/queryResults/action` |

Reader's `*/read` covers the GET actions, but do not assume it grants the
separate Policy Insights query action. An owner may arrange an appropriately
scoped existing/custom read-only role outside LandingLens. The CLI never creates
roles, changes permissions, requests tenant-wide/Graph/billing access, or starts
login. Descendant resources must also be authorized.

HTTP 200 and exhausted pagination do **not** prove unrestricted RBAC visibility.
By default, authorization coverage is unverified and inventory is incomplete.
`--inventory-authorized` is the caller's explicit attestation that the requested
scope is fully visible; it neither grants nor independently verifies permission.
Only that attestation plus successful inventory and relationship enumeration can
make inventory complete. Permission gaps or truncated pages still invalidate it.
Do not use the flag for a partially accessible estate. Saved evidence's
`inventory_complete` is likewise a producer assertion, not a discovery of rights.

## Credentials and failure handling

Supply an **already authorized** ARM token through a selected environment
variable (`LANDINGLENS_ARM_TOKEN` by default), never an argument, a committed
file, a report or chat. Token acquisition is an external owner action.

```powershell
alz-assessor collect --subscription 00000000-0000-0000-0000-000000000001 --output observed.json
alz-assessor collect --management-group platform --output observed.json
```

These are real read-only collection commands for separately authorized use.
They were **not** executed during development. Do not copy raw tokens into this
documentation. Reports/evidence are local files only; nothing is uploaded.

Transport accepts only `https://management.azure.com`, rejects redirects and
cross-origin continuations, and limits continuation paths to the same operation.
There are at most 100 pages/10,000 list items and four bounded retry attempts
for throttling/transient status codes. Retry delays are capped at 30 seconds.
Each response is limited to 8 MB; an oversized response records an explicit
facet gap rather than discarding independently collected evidence.
Denied or exhausted requests produce facet-specific diagnostics. Independently
available resources remain assessable, but missing configuration is inaccessible,
not a pass. Inventory, configuration, relationships, assignments, exemptions and
compliance completeness remain visible separately; partial collection is explicit.

Only the original two flags and three successor-matrix enum/SKU fields are
exported from resource details.
Raw resource properties, tags, service error bodies, auth headers and policy
parameter values are not exported. Treat resource IDs and topology as sensitive
inventory; use report `--minimize` before sharing. A minimized presentation cannot
be used to establish identity for later comparison.

Assessment reports show policy record counts, not arbitrary policy payloads or
parameters. Keep the separately saved collection bundle for detailed manual
review of assignment scope, exclusions, exemption expiry and original policy
evaluation timestamps; those records never become automatic recommendation passes.

The scoped-extension verification ran 133 tests against an installed wheel
outside the checkout: 132 passed and one Windows symlink-privilege case skipped.
This included the existing no-restore Bicep compiler and injected collection to
saved-evidence assessment. It did not use live Azure credentials or calls.
