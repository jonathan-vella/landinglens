"""Build the installed catalog from reviewed bytes; no network or new source decisions."""

import argparse
import hashlib
import json
from pathlib import Path

from alz_assessor.contracts import document, validate

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "references" / "2026-11-04"
RULES = {
    "G04.01": {
        "resource_type": "Microsoft.Storage/storageAccounts",
        "property": "supportsHttpsTrafficOnly",
        "expected": True,
        "guidance": "https://learn.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer",
        "coverage": "Storage-account secure-transfer flag; not SMB/NFS encryption effectiveness.",
        "api_versions": ["2023-05-01"],
    },
    "D07.18": {
        "resource_type": "Microsoft.Network/firewallPolicies",
        "property": "dnsSettings.enableProxy",
        "expected": True,
        "guidance": "https://learn.microsoft.com/en-us/azure/firewall/dns-settings",
        "coverage": (
            "Explicit firewall-policy DNS proxy flag, not client routing or runtime behavior."
        ),
        "api_versions": ["2024-05-01"],
    },
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--slice", action="store_true")
    args = parser.parse_args()
    inventory = json.loads((SOURCE / "inventory.json").read_text(encoding="utf-8"))
    upstream = json.loads((SOURCE / "alz-checklist.json").read_text(encoding="utf-8"))
    controls = []
    for item, row in zip(upstream["items"], inventory["items"], strict=True):
        if args.slice and item["id"] != "G04.01":
            continue
        rule = RULES.get(item["id"])
        automation = (
            "automated"
            if rule
            else "manual"
            if row["disposition"] == "candidate-manual"
            else "assisted"
        )
        controls.append(
            {
                "control_id": "ALZ-" + item["guid"],
                "upstream_id": item["id"],
                "upstream_guid": item["guid"],
                "design_area": row["proposed_design_area"],
                "related_areas": [],
                "upstream_category": item["category"],
                "applicability": ["platform"]
                if item["id"].startswith("A")
                else [
                    "platform",
                    "application",
                ],
                "applicability_note": "Review recommendation conditions within selected scope.",
                "recommendation": item["text"],
                "automation": automation,
                "method": "explicit-boolean" if rule else "human-review",
                "rule": rule,
                "lifecycle": "active",
                "baseline": "microsoft-recommendation",
                "rationale": rule["coverage"] if rule else row["reason"],
                "evidence_requirements": [rule["property"]]
                if rule
                else [
                    "Scoped human review of linked recommendation, applicability "
                    "and supporting evidence",
                ],
                "mapping_state": "verified-property-subset" if rule else "inventory-category-only",
                "flags": [] if rule else row["flags"],
                "inventory_flags": row["flags"],
                "references": [
                    {
                        "source_url": row["source_url"],
                        "source_sha256": row["source_sha256"],
                        "revision": row["source_revision"],
                        "retrieved_at": row["retrieved_at"],
                        "pointer": row["pointer"],
                        "item_sha256": row["item_sha256"],
                        "guidance": rule["guidance"] if rule else item["link"],
                    }
                ],
            }
        )
    catalog = document(
        "catalog",
        catalog_version="2026-11-04.1" + ("-slice" if args.slice else ""),
        design_areas=[area["name"] for area in inventory["taxonomy"]],
        controls=controls,
        separate_mappings={"effective_tenant_policy": [], "organization_extensions": []},
        review_state="reviewed",
        reviewed_at=json.loads(
            (ROOT / "references" / "2026-11-04-controls" / "manifest.json").read_text("utf-8"),
        )["sources"][0]["retrieved_at"],
        reference_manifest_sha256=hashlib.sha256(
            (SOURCE / "manifest.json").read_bytes()
        ).hexdigest(),
        control_source_manifest_sha256=hashlib.sha256(
            (ROOT / "references" / "2026-11-04-controls" / "manifest.json").read_bytes(),
        ).hexdigest(),
    )
    validate(catalog, "catalog")
    target = ROOT / "src" / "alz_assessor" / "data"
    target.mkdir(exist_ok=True)
    (target / "catalog.json").write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
    (target / "reference.LICENSE").write_bytes((SOURCE / "alz-checklist.LICENSE").read_bytes())
    (target / "control-sources.json").write_bytes(
        (ROOT / "references" / "2026-11-04-controls" / "manifest.json").read_bytes(),
    )


if __name__ == "__main__":
    main()
