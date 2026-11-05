"""Build the installed catalog from reviewed bytes; no network or new source decisions."""

import argparse
import copy
import hashlib
import json
from pathlib import Path

from alz_assessor.catalog import reviewed_refresh
from alz_assessor.contracts import control_digest, digest, document, validate

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
    if not args.slice:
        historical = target / "catalog-2026-11-04.1.json"
        if historical.exists() and digest(json.loads(historical.read_text("utf-8"))) != digest(
            catalog
        ):
            raise ValueError("Frozen historical catalog cannot be overwritten with changed meaning")
        historical.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
        previous = copy.deepcopy(catalog)
        wave = ROOT / "references" / "2026-11-04-wave1"
        audit = json.loads((wave / "candidate-audit.json").read_text("utf-8"))
        manifest = (wave / "manifest.json").read_bytes()
        matrix_sha = digest(audit)
        catalog.update(
            schema_version="1.1",
            catalog_version="2026-11-04.2",
            accepted_matrix_sha256=matrix_sha,
            wave_source_manifest_sha256=hashlib.sha256(manifest).hexdigest(),
        )
        changes = []
        for control in catalog["controls"]:
            if control["upstream_guid"] not in {
                "e9c8f584-6d5e-473b-8dc5-acc9fbaab4e3",
                "b9d0dff5-bdd4-4cd8-88ed-5811610b2b2c",
            }:
                continue
            before = control_digest(control)
            threat = control["upstream_id"] == "D07.06"
            field = "threatIntelMode" if threat else "intrusionDetection.mode"
            coverage = (
                "Explicit local firewall-policy mode on a verified capable SKU; not effective "
                "inherited mode, attachment, bypass/signature coverage or runtime protection."
            )
            rule = {
                "operation": "enum-equals",
                "resource_type": "Microsoft.Network/firewallPolicies",
                "property": field,
                "expected": "Deny",
                "applicable_skus": ["Standard", "Premium"] if threat else ["Premium"],
                "api_versions": ["2024-05-01"],
                "coverage": coverage,
            }
            control.update(
                automation="automated",
                method="explicit-enum-with-sku",
                rule=rule,
                evidence_requirements=["sku.tier", field],
                rationale=coverage,
                mapping_state="verified-local-configuration-subset",
                flags=[],
            )
            for source in json.loads(manifest)["sources"][:4]:
                control["references"].append(
                    {
                        "source_url": source["url"],
                        "source_sha256": source["sha256"],
                        "revision": source["revision"],
                        "retrieved_at": source["retrieved_at"],
                        "pointer": field,
                        "guidance": source["url"],
                    }
                )
            changes.append(
                {
                    "control_id": control["control_id"],
                    "before_sha256": before,
                    "after_sha256": control_digest(control),
                    "rationale": (
                        "LL-19 accepted exact local enum/SKU matrix; LL-21 collection verified."
                    ),
                }
            )
        if len(changes) != 2:
            raise ValueError("Reviewed wave GUIDs no longer match the pinned inventory")
        catalog["change_review"] = {
            "base_sha256": digest(previous),
            "matrix_sha256": matrix_sha,
            "reviewed_at": json.loads(manifest)["sources"][0]["retrieved_at"],
            "reviewer": "delegated-maintainer-matrix-review",
            "changes": changes,
        }
        reviewed_refresh(catalog, previous)
        (target / "wave-control-sources.json").write_bytes(manifest)
        (target / "accepted-matrix.json").write_bytes((wave / "candidate-audit.json").read_bytes())
    (target / "catalog.json").write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
    (target / "reference.LICENSE").write_bytes((SOURCE / "alz-checklist.LICENSE").read_bytes())
    (target / "control-sources.json").write_bytes(
        (ROOT / "references" / "2026-11-04-controls" / "manifest.json").read_bytes(),
    )
    if not args.slice:
        from build_batches import main as build_batches

        build_batches()


if __name__ == "__main__":
    main()
