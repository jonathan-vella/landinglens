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
Management-group assignments likewise use `atScope()`; every validated descendant
group is read separately, while subscription unfiltered lists retain child
resource-group/resource assignments. The owner-authorized pilot found four
unfiltered management-group assignment HTTP 400s, whereas the scoped reads
succeeded. Removing those failing calls does not lose descendant coverage.
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
The historical baseline did not execute them. The later owner-authorized pilot
used the installed Collector API under an additional exact-scope/operation egress
guard, then installed CLI assessment and rendering. Do not copy raw tokens into this
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

## Optional Azure MCP study: not ready

LL-22's decision is **not ready for a production LandingLens transport**. This
completes the optional feasibility study, not an adapter or live pilot.
On 2026-11-04, only the already available ARM/policy routers' `learn=true`
metadata was requested. No resource tool, new process, installation, login,
consent, permission change or tenant operation was executed. The owner's
"server 3" label does not establish a software version.

The reviewed Microsoft source is pinned to
[`deb78ee37b1da6930668c51db397afaaad555861`](https://github.com/microsoft/mcp/tree/deb78ee37b1da6930668c51db397afaaad555861):
the [registry](https://github.com/microsoft/mcp/blob/deb78ee37b1da6930668c51db397afaaad555861/servers/Azure.Mcp.Server/src/Resources/registry.json),
[authentication documentation](https://github.com/microsoft/mcp/blob/deb78ee37b1da6930668c51db397afaaad555861/docs/Authentication.md)
and [README](https://github.com/microsoft/mcp/blob/deb78ee37b1da6930668c51db397afaaad555861/servers/Azure.Mcp.Server/README.md)
were actually retrieved. They are public MIT-licensed repository references;
this study records findings rather than redistributing their documentation.
Pinning local source does not freeze remote tools or prove the installed build.

| Observed interface | Boundary and decision |
|---|---|
| ARM namespace | Registry-proxied to `https://mcp.management.azure.com`, not the same implementation boundary as a native local collector. The registry requests a distinct OAuth audience; an existing ARM token does not establish proxy consent/cache availability. |
| `execute_query` | Required `query`; optional `options` contains only `$top`, `$skipToken`, `resultFormat`. No explicit subscription, management-group or tenant transport field was exposed. Query text/KQL filtering is not authorization scope. Reject for the approved pilot. |
| `get_resource` | Required exact `resourceId`; optional `apiVersion` and `queryParameters`. An adapter would have to require the pinned API version, allowlist IDs/query keys, validate returned identity and block implicit latest-version selection. Tenant/credential selection remains unproved. |
| Policy namespace | Not an external entry in the reviewed registry. Discovered `policy_assignment_list` has optional `scope`, `subscription`, `tenant`, and no required fields. Its subscription description permits ambient CLI-profile/environment defaults. Native namespace discovery does not verify its credential implementation or output completeness. |
| Result schemas | Discovered inputs and prose/examples are not an enforced normalized output contract. No service output, authorization coverage, full paging or original evaluation-time behavior was demonstrated. |

The pinned authentication guide documents a local credential chain that can
reach interactive browser authentication; broker mode can also fall back to a
browser. It documents pinning `AZURE_TOKEN_CREDENTIALS=AzureCliCredential`, but
this does not prove the configured server/proxy uses that setting or the intended
tenant/cache. A future adapter must reject interactive acquisition and validate
the existing principal/tenant before the first scoped operation. Local SDK,
CLI, broker and proxy caches/consents are distinct unverified boundaries, not
interchangeable proof of access.

The pinned README documents read-only configuration (not enabled by default)
and telemetry enabled by default. A future deployment needs verified read-only
mode **and** an exact command/argument allowlist, not a whole-namespace grant.
Exclude generic CLI execution, deployment, scans, mutation and authentication
tools. Require `AZURE_MCP_COLLECT_TELEMETRY=false` and
`AZURE_MCP_COLLECT_TELEMETRY_MICROSOFT=false`, with actual configuration evidence;
these flags do not attest the remote service's logging/retention. None of the
running server's credential, cache, telemetry or read-only settings was changed
or claimed verified by this study.

### Required future transport contract tests

These are adapter acceptance requirements, **not executed remote tests**:

| Case | Required behavior before parity can be accepted |
|---|---|
| Scope and credentials | Exact tenant/principal and explicit subscription body or validated descendant boundary; reject omitted/ambient scope, foreign IDs and browser/broker/consent fallback. |
| Structured facts | Exact reviewed operation/API version, typed property projection and canonical resource ID; reject coercion, arbitrary payloads, prose-only responses and missing identity. |
| Paging and completeness | Preserve every bounded page, counts, truncation and tokens; repeated/missing tokens and partial/denied child inventories stay incomplete. Exhaustion never attests RBAC coverage. |
| Errors and retries | Bound throttling/transient retries; permission, service, transport and byte limits remain explicit facet gaps, never passing empty inventories. |
| Time | Preserve collection start and original PolicyStates evaluation timestamps separately; replay against an explicit time and reject stale facts. No triggerEvaluation. |
| Schema drift | Pin schema/operation fingerprints, reject incompatible output changes and rerun direct-transport parity fixtures before any reviewed promotion. |
| Safety and privacy | Verify exact read-only allowlist, no redirects/authentication/mutations, telemetry/retention boundaries and redaction before resource access; exercise privacy sentinels. |

A later adapter/pilot requires its own scoped issue and any missing owner
authorization. The direct injected transport is the parity baseline. This
not-ready decision does not block the mandatory offline increment or justify
broader Azure access.

## Selected-boundary live pilot

The separately authorized pilot in #40 used the existing cached identity, verified
its tenant/principal/audience claims and read one approved management-group
boundary: four groups including its root and three descendant subscriptions.
Exact identities, tokens, normalized evidence and reports remain private.

The initial installed-wheel run inventoried 98 resources and exercised JSON,
Markdown, HTML and minimized HTML workflows. There were 293 HTTP 200 responses
and four HTTP 400s, all from unfiltered management-group assignment requests.
Filtered assignment reads succeeded. Five automated result instances comprised
three passes, one failure and one explicit capability exclusion; these are local
configuration results, not a whole-estate security score or runtime proof.
These initial failures are retained as historical evidence, not relabelled as
successful calls.

The fix merged in [#42](https://github.com/jonathan-vella/landinglens/pull/42)
as `6139ba1f20e2a6d2adca6e6f86e85e8ec1e5490c` after all eight checks passed.
A second exact installed-wheel run, outside the checkout and under the same
guard, completed in 329 seconds: **293 HTTP 200 responses and no HTTP failures**.
It retained 98 resources and the same five automated result instances. All
ten assignment reads succeeded; assignment, exemption, configuration,
relationship and existing-compliance facets were complete within the collector's
bounds. All 1,726 retained PolicyStates records had their original timestamps.
JSON, Markdown, HTML and minimized HTML workflows succeeded. The minimized HTML
contained none of the private tenant/account/group/subscription allowlist values.
No applicable IDPS-mode positive/negative result or effective runtime protection
is established by the capability exclusion.

Inventory authorization was deliberately not attested. Four ancestor custom
definition references remained outside the approved boundary; those reads were
not attempted. Inventory and definition completeness therefore cannot be claimed.
PolicyStates retain original timestamps; no evaluation was triggered. No MCP
resource calls, login, permission changes, deployment or remediation occurred.
