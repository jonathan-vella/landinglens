# Explicit-scope read-only collection

The original release collector was verified with injected transports and saved
fixtures, not a live tenant. That historical baseline is unchanged. Subsequent
owner-authorized access probes are bounded access evidence, not full collector
or control verification. Normal assessment and tests need no Azure credentials.

## Policy evidence reuse

LL-30 consumes the existing scoped collector's separate assignments, exemptions
and original-time PolicyStates records as assessment 1.2 Signals. No new
management-plane operation, permission, scope expansion or evaluation trigger is
introduced. The existing #40 guard and API versions/actions below remain the
live boundary. Saved exports can be attached through an explicit
[`policy-export` wrapper](contracts.md#policy-export-and-signals); normalised
collector evidence needs no wrapper or new collection command.

Only direct source-verified crosswalk definitions are interpreted. The initial
storage mapping is partial: a Compliant state is not a checklist pass, effects/
exemptions need review, and missing/denied/conflicted/stale/indirect initiative
contexts remain unusable. Definition/initiative configuration does not substitute
for an actual original-time evaluation. Empty evaluations do not prove compliance
or absence; raw assignment parameters/descriptions are not exported.

Verification is saved/injected and installed CLI only. The injected existing
collector path demonstrates an independent fresh policy Signal while the
resource-detail GET is denied and its technical outcome remains unknown. No new
live tenant run, login, permission change, ancestor read, Graph/billing/data-plane
access or policy scan was attempted. Live behaviour for this increment remains
undemonstrated, not silently counted as exercised.

## Reviewed upstream-query Signals

Owner approval D5 permits exact hash-allowlisted read-only queries as Signals,
not arbitrary KQL or recommendation passes. The seed contains only the reviewed
D07.06/D07.07 local firewall-policy mode observations from the existing frozen
49-query audit; other candidates retain explicit exclusion reasons. This does
not change the evaluator's stricter SKU/missing/inheritance requirements.

The opt-in `collect --query-guid GUID --subscription UUID` path uses existing
`Microsoft.ResourceGraph/resources/read`, API 2022-10-01 and the same scoped
transport/retry/byte guards. It requires explicit subscriptions in every POST
body, never derives authority from query text or an ambient account, and does
not enumerate management-group descendants. The caller must stay within the
previously approved exact #40 boundary; no new live run is performed for acceptance.
The existing token environment is required; no login or permission change occurs.

At most 100 pages/10,000 identities are retained; missing/repeated tokens,
partial/denied/oversized responses and original-time freshness remain explicit.
No rows or exhausted pages prove compliance or authorisation completeness.
Saved output is assessed/replayed offline with Signals only. See the
[query contract](contracts.md#allowlisted-query-evidence) for schema/provenance
and unsupported cases. Tests use saved/injected transports and installed CLI;
live query compilation/behaviour remains undemonstrated.

## Batch-01 configuration reads

The batch successor adds only management-plane configuration GETs:
`Microsoft.KeyVault/vaults` **2024-11-01** (`enableSoftDelete` and
`enablePurgeProtection`, plus explicit RBAC/public-network/default-ACL flags
for assisted review) and each inventoried storage account's exact
`Microsoft.Storage/storageAccounts/blobServices/default` **2023-05-01**
(`containerDeleteRetentionPolicy.enabled`). These correspond to
`Microsoft.KeyVault/vaults/read` and
`Microsoft.Storage/storageAccounts/blobServices/read`; no permission is granted
or changed. The actual operation/schema sources are in the
[batch source manifest](../references/recommendation-batches/batch-01-sources.json).

Child identity must equal the requested canonical child. No blob/container,
secret, certificate, key, credential or access-key enumeration occurs. A denied
or absent child read remains unavailable, not disabled or N/A; other independent
known configuration remains usable. Missing child facts in saved/declared
evidence also remain unknown. Derived children count toward existing resource
bounds (256 planned, 10,000 collected/evaluated); overflow fails explicitly.
Raw response hashes bind the additional reads under the original collection
time/scope. Existing egress, paging, origin, authorization and privacy guards
remain; no new live verification is claimed by this offline/injected batch.
The existing storage-account detail projection also retains explicit
`minimumTlsVersion` for assisted TLS-policy review. It does not evaluate policy
enforcement. TLS1_3 appears in the 2023-05-01 template enum while the same
reference says minimum 1.3 is unsupported; this mapping stays unknown rather
than resolving the contradiction speculatively.

## Next-increment scoped collection

### Cohort-17 network projections

The reviewed detail allowlist now includes existing inventoried
`Microsoft.Network/azureFirewalls`, standalone
`Microsoft.Network/virtualNetworks/subnets` and `Microsoft.Network/ipGroups`
at **2024-05-01**. Only the reviewed SKU, positive references, IPv4 prefix/address
and classic DNAT source fields are retained. The generic collector's existing
approved per-resource GET path is used; there is no new diagnostic enumeration,
parent/ancestor traversal, route/packet/log query or data-plane access. Canonical
positive references do not establish complete relationships or missing-resource
absence. Mocked detail reads/denials and saved fixtures exercise these additions;
no new live tenant run is claimed.

### Cohort-18 network preparation

The existing per-inventoried-resource detail path additionally supports
`Microsoft.Network/virtualNetworks`, `Microsoft.Network/privateEndpoints` and
`Microsoft.Network/firewallPolicies/ruleCollectionGroups` at **2024-05-01**
(`read` on those exact resource types). Missing child/group inventory is not
silently expanded through parents. No permission is granted or scope broadened.
Firewall configured zones come from the resource root, not `properties.zones`.
Only typed VNet DDoS flag/plan, subnet NSG, endpoint target/explicit state and
bounded rule action/TLS/category-count facts are projected. Canonical subnet/VNet
links use already supplied unique known records, never additional reads.
Connection messages/aliases, category labels, rule destinations/headers, DNS
names, private endpoint addresses and certificate material are withheld.

These are informational configuration facts: backend zone migration can be
invisible to ARM/JSON/ARG, private connection intent is not approval, Approved
is not end-to-end DNS/routing, and TLS/category fields are not effective
inspection. The [18 actual reviewed sources](../references/recommendation-batches/batch-18-sources.json)
and [nine-GUID matrix](../references/recommendation-batches/batch-18.json)
retain these limitations. Verification uses saved fixtures and injected detail
reads/denials, not a new live tenant run, packet/DNS/log probe or approval action.

### Cohort-19 segmentation preparation

The existing per-inventoried-resource detail path additionally recognizes NSGs,
standalone NSG security rules, virtual network gateways and Network Watcher flow
logs at **2024-05-01**, using `read` on those exact resource types. Saved/injected
tests exercise these projections; no new live reads or permissions are authorized
or claimed. No rule-list expansion, NIC/ASG membership enumeration, effective-rule
query, packet/DNS test or workspace/storage data-plane request occurs.

Only a successful observed NSG GET can supply the complete custom-rule count for
the checklist's <=900 predicate. The reviewed pinned 2024 REST schema separates
custom and default rules; the Learn GET page requested with the 2024 view falls
back to 2026 and is not substituted as its schema. Transient, denied, malformed,
missing or over-bound populations remain unknown. Counts do not establish estate
completeness or rule effectiveness. Other projections are bounded informational
facts for the [nine-GUID matrix](../references/recommendation-batches/batch-19.json)
and [24 reviewed sources](../references/recommendation-batches/batch-19-sources.json).
Flow-log enablement is not ingestion, and the workflow does not recommend
creating new NSG flow logs after Microsoft's July 2025 cutoff.

### Cohort-11 routing and transport preparation

The existing per-inventoried-resource detail path additionally recognizes route
tables, VNet peerings, load balancers/backend pools, ExpressRoute Direct ports and
gateway connections at **2024-05-01**, with their exact management-plane `read`
operations. Verification is saved/injected only; no new live access is authorized
or claimed. Existing request/scope/origin/byte/identity guards still apply.

Only complete Succeeded route-table custom arrays can support the observed <=400
checklist predicate. Peering access is an explicit boolean, not traffic flow.
Other typed projections retain bounded frontend/backend context, per-link
MACsec cipher/SCI, connection type/private-IP intent, gateway IDs and VNet IPv4
prefixes. They never collect keys/secret identifiers, credentials, tunnel/next-hop
addresses, actual backend IPs or arbitrary raw properties. No effective-route,
backend-health, circuit/router-end, reciprocal-topology or IPAM expansion occurs.
The [matrix](../references/recommendation-batches/batch-11.json) distinguishes
local configuration, partial subchecks, manual requirements and runtime evidence.

### Cohort-04 access and identity context

Role assignments use reviewed **2022-04-01** management-plane detail schema
and `Microsoft.Authorization/roleAssignments/read` on already supplied/inventoried
resources only. No role, principal, directory, membership, inherited grant or
condition expansion occurs. This adds no live permission or read authorization.
Saved/injected transport tests exercise these projections and denial behavior.

Supported existing storage **2023-05-01** and Direct-port **2024-05-01** detail
projections additionally minimize explicit root identity blocks to type/count.
Principal/tenant IDs, user-assigned identity IDs, credentials and arbitrary
identity properties are withheld. These facts do not show application adoption
or absence of separately configured credentials.

The eight source-specific interviews require explicit accountable decisions;
there is no Entra/Graph/sign-in/audit-log read, policy/MFA/PIM activation,
authentication or permission change. Legacy source redirects and the precise
unsupported enforcement claims are retained in the
[matrix](../references/recommendation-batches/batch-04.json).

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
