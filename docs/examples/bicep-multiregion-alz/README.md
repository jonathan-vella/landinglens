# Offline multi-region Azure Landing Zone

This fictional example adapts Microsoft's Bicep IaC Accelerator at revision
`88dcafa6afcd57e1b3ccd772a81c88bd29ae2ac2` into a two-region hub-and-spoke
configuration for LandingLens assessment. It is an offline simulation: it does
not log in to Azure, deploy resources, collect live evidence, or contain real
tenant/subscription IDs, VPN endpoints, or shared keys.

## Architecture and scope

| Assessment | Fictional scope | Included configuration |
|---|---|---|
| Governance | `/providers/Microsoft.Management/managementGroups/fictional-alz` | Management-group hierarchy and representative ALZ policy definitions/assignments |
| Management | `/subscriptions/00000000-0000-0000-0000-000000000001` | Central Log Analytics workspace and monitoring resources |
| Connectivity | `/subscriptions/00000000-0000-0000-0000-000000000002` | Sweden Central and Germany West Central hubs, Premium Azure Firewalls, VPN gateways, local-network gateways, connections and reciprocal hub peerings |
| Workloads | `/subscriptions/00000000-0000-0000-0000-000000000005/resourceGroups/rg-alz-workloads` | One spoke per region, subnet NSGs, firewall-default route tables, hub peerings and remote-gateway settings |

The hubs use `10.10.0.0/16` and `10.20.0.0/16`; spokes use
`10.11.0.0/24` and `10.21.0.0/24`. Hub VPN declarations use fictional
TEST-NET endpoints and secure key parameters with no supplied values. Zone and
SKU availability is not verified. Routes, gateway transit and VPN connections
are declarations only; they do not prove effective routing, tunnel health,
firewall enforcement, failover, or log ingestion.

Assessments stay separate by scope. Do not compose these bundles across
subscriptions: this ARM/Bicep path does not emit the relationship metadata
required to establish hierarchy. Each report retains all 255 recommendations;
its result-instance and resource counts are not compliance percentages.

LandingLens currently does not project local-network-gateway properties. These
declared resources are explicitly retained as unknown with
`arm_resource_type_unsupported`; their existence is not a compliance pass or a
deliberate security defect. VPN behavior and owner-specific retention policy
remain unverified.

## Scenarios

Parameter files are under `scenarios\`. The `defective` case is an intentionally
controlled configuration variant, not a claim about a deployed environment:

| Setting | Baseline | Defective | Remediated |
|---|---|---|---|
| Firewall threat-intelligence mode | `Deny` | `Off` | `Deny` |
| Sweden hub/spoke peering access | Enabled | Disabled | Enabled |
| Workspace retention | 90 days | 30 days | 90 days |

The supported D07.06 firewall and D01.13 peering checks expose the first two
changes. LandingLens has no owner-defined retention threshold here, so the
30-day value remains a configuration fact and does not become an invented
failure or pass. No manual review is prefilled.

## Reproduce the assessments and reports

From the repository root, use a fresh output directory:

```powershell
python docs\examples\bicep-multiregion-alz\reproduce.py --output-directory .\alz-report-package
```

The runner assesses the frozen compiler-produced ARM fixtures against the
checked-in scenario parameters and packaged catalog. It writes four scope-bound
evidence/assessment pairs per scenario, scoped HTML/Markdown/JSON/XLSX exports,
one four-report explorer per scenario, a package index, and a summary. It
refuses to overwrite an existing output directory. XLSX trackers are static,
formula-free exports.

Run the unconditional fixture and scenario regressions with:

```powershell
python -m unittest tests.test_multiregion_alz_example tests.test_arm_compatibility
```

The frozen ARM fixture hashes and their source, parameter, compiler, upstream,
and module provenance are recorded in
`tests\fixtures\multiregion-alz\provenance.json`. Optional Bicep recompilation
requires the existing Bicep CLI 0.47.16 and the pinned public AVM modules in an
isolated module cache. Use `--no-restore`; do not use the user's default cache
or run Azure deployment/bootstrap commands. The compiled fixtures allow the
assessment and reporting workflow to run without Bicep or network access.

See [accelerator validation](../../accelerator-validation.md) for the broader
interpreter boundaries and reproduction notes.
