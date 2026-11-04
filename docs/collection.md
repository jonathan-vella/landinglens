# Explicit-scope read-only collection

The collector is implemented and tested with injected mock transports and saved
fixtures. **No live Azure collection or tenant verification was run.** Normal
source assessment and tests need no Azure credentials.

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
Denied or exhausted requests produce facet-specific diagnostics. Independently
available resources remain assessable, but missing configuration is inaccessible,
not a pass. Inventory, configuration, relationships, assignments, exemptions and
compliance completeness remain visible separately; partial collection is explicit.

Only the two reviewed control properties are exported from resource details.
Raw resource properties, tags, service error bodies, auth headers and policy
parameter values are not exported. Treat resource IDs and topology as sensitive
inventory; use report `--minimize` before sharing. A minimized presentation cannot
be used to establish identity for later comparison.

Assessment reports show policy record counts, not arbitrary policy payloads or
parameters. Keep the separately saved collection bundle for detailed manual
review of assignment scope, exclusions, exemption expiry and original policy
evaluation timestamps; those records never become automatic recommendation passes.
