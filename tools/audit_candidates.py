"""Reproduce the GUID audit from pinned bytes; acquisition is an explicit maintainer flag."""

import argparse
import hashlib
import json
import re
from pathlib import Path

from review_control_sources import fetch

from alz_assessor.contracts import digest, now
from alz_assessor.maintenance import indexed_items
from alz_assessor.terraform import InputError

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "references" / "2026-11-04"
DEST = ROOT / "references" / "2026-11-04-wave1"
PROVIDER = "211156b6c9c3c4721a2a4631998a6bd08433a9ee"
CHECKLIST = "60b8d3a961651b7581808024f9a537d329a132d96217d8d77d7e5237ef40f62a"

# Classification describes the inspected query, not acceptance of its compliance claim.
AUDIT = {
    "B03.02": (
        "evidence-only",
        "resource rows",
        "id",
        "Selects existing managed identities, omits combined identity type and "
        "service-principal consumers; cannot establish replacement or tenant usage.",
    ),
    "B03.03": (
        "relational",
        "integer 0/1",
        "subscriptionId (subscription scope)",
        "Only exact subscription-scope role assignments join; no assignment ID, "
        "nested groups, inherited/RG roles or on-premises group management evidence.",
    ),
    "B03.09": (
        "heuristic",
        "integer 0/1",
        "name only",
        "DC role inferred from name/tags. Any zone or availability set does not prove "
        "two DCs across zones, supported locations or resiliency.",
    ),
    "B03.11": (
        "evidence-only",
        "constant integer 1",
        "roleName only",
        "Custom-role existence does not prove required business roles, permissions "
        "or team alignment; role definition ID is lost.",
    ),
    "B03.13": (
        "direct-predicate",
        "violation rows",
        "id",
        "Replica-array count subset only. Missing arrays can disappear; complete "
        "replica inventory and intended multi-region applicability are required.",
    ),
    "B04.01": (
        "heuristic",
        "integer 0/1",
        "name and remoteVnetId",
        "Hub classification is a name substring, not topology. Missing peerings or "
        "inaccessible remote networks cannot establish connectivity.",
    ),
    "B04.04": (
        "heuristic",
        "integer 0/1",
        "scope",
        "Arbitrary owner threshold >3; Azure RBAC Owner counts are not enrollment "
        "account ownership. Missing assignments do not prove zero owners.",
    ),
    "C02.01": (
        "relational",
        "boolean expression",
        "id",
        "Subscription ancestor-chain length only; root counting and complete visible "
        "hierarchy matter. Null/inaccessible chains cannot prove flatness.",
    ),
    "C02.05": (
        "relational",
        "boolean expression",
        "id",
        "Ancestor length >1 is a subscription-placement subset, not proof that all "
        "subscriptions are visible or root governance is appropriate.",
    ),
    "C02.14": (
        "heuristic",
        "boolean expression",
        "id",
        "Non-null tags can be empty or irrelevant; no billing keys/values or cost "
        "allocation intent is tested.",
    ),
    "D01.08": (
        "direct-predicate",
        "boolean expression",
        "parent VNet id",
        "Prefix split has no explicit numeric/CIDR validation; <=27 differs from "
        "exact /27. Distinct parent IDs lose multiple subnet identities.",
    ),
    "D01.11": (
        "heuristic",
        "boolean expression",
        "id",
        "450 peerings differs from 400 spokes and 500 peering limit; not regional "
        "hub identification or ExpressRoute prefix population. Empty arrays vanish.",
    ),
    "D01.12": (
        "heuristic",
        "boolean expression",
        "id",
        "<360 differs from recommendation limit 400. Expansion loses empty/omitted "
        "route tables; embedded routes must be complete.",
    ),
    "D01.13": (
        "direct-predicate",
        "boolean expression",
        "parent id and peeringName",
        "Explicit peering flag subset; child canonical ID is not projected. "
        "Capitalized True syntax and returned types are not service-executed.",
    ),
    "D01.14": (
        "relational",
        "violation rows",
        "load-balancer id",
        "Frontend/private zones and public-IP joins require complete child/remote "
        "inventory; excludes Basic instead of failing it; regional support unknown.",
    ),
    "D01.15": (
        "relational",
        "violation rows with integer counts",
        "load-balancer id",
        "Inline backend and NIC membership branches need complete inventories; "
        "unmatched/null NIC counts may disappear. Pool identity is not retained.",
    ),
    "D03.02": (
        "heuristic",
        "boolean expression",
        "id and cidr",
        "RFC1918-looking string prefix is not validated CIDR/network containment; "
        "multiple prefixes require distinct evidence instances.",
    ),
    "D03.03": (
        "heuristic",
        "boolean expression",
        "id and addressPrefix",
        "Mask >16 is not evidence that address space is appropriately allocated "
        "or not wasted; string/numeric conversion and intent are unverified.",
    ),
    "D03.05": (
        "direct-predicate",
        "violation rows",
        "id",
        "Regional IP zone-array subset; does not establish Standard SKU, zone "
        "capability or global-IP applicability. No rows is not a pass.",
    ),
    "D05.02": (
        "direct-predicate",
        "boolean expression",
        "parent VNet id",
        "Named Bastion subnet prefix subset; needs numeric CIDR validation, SKU "
        "applicability and canonical subnet IDs; missing subnets are not absent.",
    ),
    "D06.03": (
        "heuristic",
        "boolean expression",
        "id",
        "Excluding Basic/Standard is not bandwidth or performance sizing evidence; "
        "missing SKUs and workload requirements remain unknown.",
    ),
    "D06.04": (
        "heuristic",
        "boolean expression",
        "id",
        "Metered/local SKU is not a cost-justification test; actual bandwidth, "
        "contract and intended usage are missing.",
    ),
    "D06.05": (
        "relational",
        "boolean expression",
        "gateway id",
        "Connection/circuit join needs full canonical identities and region "
        "eligibility. Any Local circuit does not justify every circuit's cost.",
    ),
    "D06.06": (
        "heuristic",
        "boolean expression",
        "id",
        "AZ substring is not verified zone support; population also includes VPN "
        "although recommendation names ExpressRoute. Region applicability missing.",
    ),
    "D06.09": (
        "heuristic",
        "boolean expression",
        "id",
        "SKU-name AZ substring does not establish regional zone availability or "
        "current capability; no default/capability inference is accepted.",
    ),
    "D06.15": (
        "relational",
        "boolean expression",
        "gateway id",
        "Distinct circuit-location count requires complete connection/circuit joins; "
        "case-normalized IDs and missing locations need explicit validation.",
    ),
    "D06.17": (
        "relational",
        "boolean expression",
        "parent VNet id",
        "Left-join null disableBgpRoutePropagation is treated as compliant: an "
        "inaccessible/missing route table can manufacture a pass. Not accepted.",
    ),
    "D07.04": (
        "heuristic",
        "boolean expression",
        "id",
        "DNS proxy alone does not establish application rules, FQDN network rules "
        "or egress routing; compound recommendation cannot be reduced to this flag.",
    ),
    "D07.05": (
        "direct-predicate",
        "boolean expression",
        "id",
        "Explicit policy SKU only, not firewall association, runtime protection "
        "or whether Premium is required for this workload.",
    ),
    "D07.06": (
        "direct-predicate",
        "boolean expression",
        "id",
        "Reimplement typed local Deny flag with explicit Standard/Premium tier. "
        "Basic cannot deny. Missing enums/SKU are unknown, not provider defaults.",
    ),
    "D07.07": (
        "direct-predicate",
        "boolean expression",
        "id",
        "Reimplement typed local IDPS Deny flag on explicit Premium tier only; "
        "not effective inherited mode, bypass/signature coverage or runtime IDPS.",
    ),
    "D07.08": (
        "heuristic",
        "boolean expression",
        "VNet id and subnetId",
        "A route-table reference is not an Internet route to a firewall/NVA; "
        "Virtual WAN peering inferred from names. Missing joins are unsafe.",
    ),
    "D07.11": (
        "direct-predicate",
        "boolean expression",
        "parent VNet id",
        "Exact /26 subset needs numeric/CIDR validation and canonical subnet ID; "
        "omitted arrays and subnet applicability remain unknown.",
    ),
    "D07.18": (
        "direct-predicate",
        "boolean expression",
        "id",
        "Query filters to attached policies and compares a Boolean with string "
        "true. Existing accepted typed predicate is separate, not this query.",
    ),
    "D07.21": (
        "direct-predicate",
        "violation rows",
        "id",
        "Non-VWAN firewall zone-array subset; managed/regional zone support and "
        "SKU/availability applicability need review. No rows cannot prove resilience.",
    ),
    "D07.22": (
        "relational",
        "boolean expression",
        "firewall id (nullable on outer join)",
        "Firewall/VNet/DDoS plan joins need complete child IDs; orphan right rows "
        "can lack firewall identity. Association is not runtime mitigation.",
    ),
    "D08.04": (
        "direct-predicate",
        "boolean expression",
        "subnet id",
        "Null serviceEndpoints becomes compliant; missing details can manufacture "
        "a pass. Exceptions and full subnet inventory require review.",
    ),
    "D09.01": (
        "direct-predicate",
        "boolean expression",
        "parent VNet id",
        "Gateway subnet <=27 requires numeric/CIDR and canonical child checks; "
        "missing or inapplicable gateway subnets cannot be inferred absent.",
    ),
    "D09.02": (
        "heuristic",
        "boolean expression",
        "id",
        "Any blanket deny ignores priority, preceding allows, service-tag "
        "semantics and effective NSG rules; not an effective inbound-policy proof.",
    ),
    "D09.04": (
        "direct-predicate",
        "boolean expression",
        "parent id and subnetName",
        "NSG-reference presence subset only; requires canonical child identities, "
        "explicit special-subnet applicability and effective-policy caveats.",
    ),
    "D09.06": (
        "relational",
        "boolean expression",
        "lowercased VNet id",
        "Flow-log join tests existence but does not require the projected Traffic "
        "Analytics flag to be true. Inaccessible flow logs cannot prove absence.",
    ),
    "D09.07": (
        "direct-predicate",
        "boolean expression",
        "id",
        "<900 disagrees with no more than 900 at the boundary; complete custom "
        "rule arrays and separate system/effective rules require review.",
    ),
    "D10.03": (
        "direct-predicate",
        "boolean expression",
        "id",
        "Virtual-hub firewall reference subset; existence does not prove secured "
        "outbound routing or effective filtering.",
    ),
    "D10.06": (
        "direct-predicate",
        "boolean expression",
        "id",
        "Boolean property compared with string true; coercion is not accepted. "
        "Explicit approved branch-blocking intent can change applicability.",
    ),
    "D10.07": (
        "direct-predicate",
        "boolean expression",
        "id",
        "Explicit routing-preference enum subset; defaults, operational routing "
        "and regional/product applicability are not inferred.",
    ),
    "D10.09": (
        "heuristic",
        "boolean expression",
        "id",
        "Mask <23 incorrectly excludes /23 versus at least /23; subnet text "
        "parsing is not CIDR validation. No corrected automation is accepted here.",
    ),
    "F01.18": (
        "direct-predicate",
        "violation rows",
        "id",
        "LRS SKU matches only; missing/unsupported SKUs and resiliency intent "
        "cannot become passes from an empty violation list.",
    ),
    "G02.02": (
        "heuristic",
        "boolean expression",
        "subscriptionId and nullable vault id",
        "Vault count !=1 makes zero vaults compliant; does not distinguish apps, "
        "environments or regions. Not an acceptable segregation predicate.",
    ),
    "G03.09": (
        "relational",
        "boolean expression",
        "workspaceResourceId",
        "Inner-joined SecurityInsights solution existence excludes unmatched "
        "workspaces and does not prove SIEM ingestion, correlation or operations.",
    ),
}

SOURCES = [
    (
        "firewall-arm",
        "https://learn.microsoft.com/en-us/azure/templates/"
        "microsoft.network/2024-05-01/firewallpolicies",
        ["threatIntelMode", "intrusionDetection", "Deny", "Premium"],
        "2024-05-01 exposes explicit Alert/Deny/Off modes and Basic/Standard/Premium tiers; "
        "IDPS effective parent/child mode is the stricter mode.",
    ),
    (
        "firewall-sku",
        "https://learn.microsoft.com/en-us/azure/firewall/features-by-sku",
        ["Alert only", "Alert and Deny", "IDPS"],
        "Basic threat intelligence cannot deny; Standard/Premium can. IDPS is Premium-only.",
    ),
    (
        "firewall-inheritance",
        "https://learn.microsoft.com/en-us/azure/firewall-manager/policy-overview",
        ["stricter", "inherited"],
        "Parent threat intelligence is inherited; child can be stricter. Local flags do not "
        "prove attachment, effective inheritance, allowlists or traffic protection.",
    ),
    (
        "firewall-provider",
        f"https://raw.githubusercontent.com/hashicorp/"
        f"terraform-provider-azurerm/{PROVIDER}/website/docs/r/firewall_policy.html.markdown",
        ["threat_intelligence_mode", "intrusion_detection", "2024-05-01"],
        "AzureRM 4.50.0 explicit sku, threat_intelligence_mode and intrusion_detection.mode "
        "map to the reviewed ARM fields. Optional defaults must not be inferred.",
    ),
    (
        "vault-soft-delete",
        "https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview",
        ["purge protection", "soft-delete"],
        "G02.03 is compound soft-delete plus purge protection; creation defaults are not "
        "evidence of explicit configuration or older-vault state.",
    ),
    (
        "container-soft-delete",
        "https://learn.microsoft.com/en-us/azure/storage/blobs/soft-delete-container-overview",
        ["1 and 365", "storage account"],
        "G04.02 needs the blobServices/default child configuration and supported account "
        "capability, not the parent storage list or blob-level deletion alone.",
    ),
    (
        "resource-locks",
        "https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources",
        ["CanNotDelete", "inherit"],
        "F01.08 needs explicit critical-resource intent and ancestor lock coverage. "
        "Management locks do not protect data-plane content.",
    ),
]


def build_audit(checklist, source_manifest):
    indexed_items(checklist)
    if digest(checklist) != CHECKLIST:
        raise InputError("Pinned content changed; explicitly review every GUID before regeneration")
    queries = [item for item in checklist["items"] if item.get("graph")]
    if len(queries) != 49 or {item["id"] for item in queries} != AUDIT.keys():
        raise InputError("Pinned query population changed; every GUID requires explicit review")
    rows = []
    for item in sorted(queries, key=lambda value: value["guid"]):
        classification, output, identity, note = AUDIT[item["id"]]
        rows.append(
            {
                "guid": item["guid"],
                "display_id": item["id"],
                "query_sha256": hashlib.sha256(item["graph"].encode()).hexdigest(),
                "classification": classification,
                "statically_inferred_output": output,
                "projected_identity": identity,
                "permission_profile": "role-definitions"
                if item["id"] == "B03.11"
                else "role-assignments"
                if item["id"] in {"B03.03", "B04.04"}
                else "ancestry"
                if item["id"] in {"C02.01", "C02.05"}
                else "resources",
                "population_applicability_and_missing_value_review": note,
                "runtime_verified": False,
                "disposition": "accepted-typed-reimplementation"
                if item["id"] in {"D07.06", "D07.07"}
                else "existing-separate-predicate"
                if item["id"] == "D07.18"
                else "deferred",
            }
        )
    return {
        "version": "2026-11-04-wave1.1",
        "review_state": "reviewed-static-not-service-executed",
        "source_manifest_sha256": digest(source_manifest),
        "permission_profiles": {
            "resources": "Microsoft.ResourceGraph/resources/read plus read access to every "
            "selected resource/child/join population; not proof of authorization completeness.",
            "role-definitions": "ARG plus Microsoft.Authorization/roleDefinitions/read.",
            "role-assignments": "ARG plus Microsoft.Authorization/roleAssignments/read; "
            "no Entra/Graph group-membership proof.",
            "ancestry": "ARG subscription-container visibility and management-group ancestry "
            "read coverage; no tenant-wide population inference.",
        },
        "universal_limits": [
            "Queries were inspected as untrusted data, never executed or imported as rules.",
            "Declared output types are static review, not service compilation/runtime validation.",
            "Every projection/join needs complete canonical scope-bound identities before use.",
            "Null/coerced values, filtered-out rows and inaccessible joins cannot prove absence.",
            "Only explicit scoped transport populations are allowed; "
            "query text cannot scope access.",
        ],
        "query_audit": rows,
        "nonquery_candidates": [
            {
                "display_id": item["id"],
                "guid": item["guid"],
                "disposition": "deferred",
                "reason": {
                    "G02.03": "Compound soft-delete/purge protection; API/provider versions, "
                    "older-vault behavior and positive/negative mappings need a separate matrix.",
                    "G04.02": "Child blobServices/default configuration and retention/capability "
                    "semantics require detail reads; parent account presence is insufficient.",
                    "F01.08": "Criticality requires supplied intent and current review; ancestor "
                    "locks and complete lock visibility cannot be inferred from resource names.",
                }[item["id"]],
            }
            for item in checklist["items"]
            if item["id"] in {"G02.03", "G04.02", "F01.08"}
        ],
        "accepted_first_wave": {
            "D07.06": {
                "property": "threatIntelMode",
                "expected": "Deny",
                "applicable_tiers": ["Standard", "Premium"],
                "not_applicable": ["Basic"],
            },
            "D07.07": {
                "property": "intrusionDetection.mode",
                "expected": "Deny",
                "applicable_tiers": ["Premium"],
                "not_applicable": ["Basic", "Standard"],
            },
        },
        "mode_commitment": [
            "raw-terraform-4.50.0",
            "bicep-no-restore",
            "arm-2024-05-01",
            "optional-plan",
            "saved-and-collected-observed",
        ],
        "outcome_commitment": {
            "pass": "Explicit applicable SKU and exact local Deny mode.",
            "fail": "Explicit applicable SKU and exact local Alert or Off mode.",
            "unknown": "Missing/invalid/unresolved SKU or mode, unsupported mapping/version, "
            "stale facts, incomplete/unavailable evidence; never infer provider defaults.",
            "error": "A normalized error resource remains an error.",
            "not_applicable": "Only explicit reviewed unsupported capability SKU, or verified "
            "complete inventory with no target; partial/denied inventory never proves absence.",
        },
        "acceptance": "Accepted under delegated matrix authority for bounded explicit local "
        "configuration predicates, not effective inherited mode or runtime security. "
        "Original two-control baseline and all 255 entries remain unchanged until LL-20 "
        "promotion follows LL-21 collection evidence. No other candidate is committed.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-sources", action="store_true")
    args = parser.parse_args()
    DEST.mkdir(exist_ok=True)
    manifest_path = DEST / "manifest.json"
    if args.capture_sources:
        if manifest_path.exists():
            raise InputError("Source review is frozen; use a new reviewed version")
        records = []
        for name, url, markers, finding in SOURCES:
            content = fetch(url)
            if not all(marker.lower().encode() in content.lower() for marker in markers):
                raise InputError("Actual source did not contain reviewed markers: " + name)
            revision = re.search(
                rb'name="git_commit_id"\s+content="([0-9a-f]{40})"',
                content,
            )
            records.append(
                {
                    "id": name,
                    "url": url,
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "retrieved_at": now(),
                    "revision": PROVIDER
                    if name == "firewall-provider"
                    else revision.group(1).decode()
                    if revision
                    else "retrieved-page",
                    "finding": finding,
                    "reuse": "MPL-2.0 provider documentation; metadata and own facts only"
                    if name == "firewall-provider"
                    else "Microsoft Learn CC-BY-4.0 documentation; metadata and own facts only",
                }
            )
        manifest_path.write_text(
            json.dumps(
                {
                    "version": "2026-11-04-wave1.1",
                    "sources": records,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    audit = build_audit(
        json.loads((BASE / "alz-checklist.json").read_text("utf-8")),
        json.loads(manifest_path.read_text("utf-8")),
    )
    target = DEST / "candidate-audit.json"
    content = json.dumps(audit, indent=2) + "\n"
    if target.exists() and target.read_text("utf-8") != content:
        raise InputError("Audit changed; preserve this version and create a reviewed successor")
    target.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    main()
