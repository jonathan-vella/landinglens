"""Reproduce the reviewed inventory dispositions, not a control catalog."""

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "references" / "2026-11-04"
# Deliberate reviewed candidates only; none is an implemented or accepted release control.
AUTOMATED = {
    "D07.06",
    "D07.07",
    "D07.18",
    "F01.08",
    "G02.03",
    "G04.01",
    "G04.02",
}
MANUAL = {
    "A02.02",
    "A03.01",
    "A04.04",
    "B03.12",
    "B05.01",
    "C02.08",
    "C02.09",
    "C02.12",
    "C03.01",
    "C04.02",
    "D01.01",
    "D01.06",
    "D02.01",
    "D03.08",
    "D03.10",
    "D05.07",
    "D06.26",
    "E03.03",
    "E03.06",
    "E03.07",
    "F01.16",
    "G01.01",
    "G01.02",
    "G02.11",
    "G02.12",
    "G05.01",
    "G06.01",
    "G06.02",
}
AREAS = {
    "Azure Billing and Microsoft Entra ID Tenants": "Azure billing and Active Directory tenant",
    "Identity and Access Management": "Identity and access management",
    "Resource Organization": "Resource organization",
    "Network Topology and Connectivity": "Network topology and connectivity",
    "Security": "Security",
    "Management": "Management",
    "Governance": "Governance",
    "Platform Automation and DevOps": "Platform automation and DevOps",
}


def main() -> None:
    manifest = json.loads((SNAPSHOT / "manifest.json").read_text(encoding="utf-8"))
    checklist = json.loads((SNAPSHOT / "alz-checklist.json").read_text(encoding="utf-8"))
    items = checklist["items"]
    source = next(s for s in manifest["sources"] if s["id"] == "alz-checklist")
    ids = Counter(item["id"] for item in items)
    assert len({item["guid"] for item in items}) == len(items), "GUID collision requires review"
    caf_lines = (SNAPSHOT / "caf-design-areas.md").read_text(encoding="utf-8").splitlines()
    taxonomy = []
    for line_number, line in enumerate(caf_lines, 1):
        if line.startswith("| !["):
            matches = re.findall(r"\[([^\]]+)\]\(\./design-area/([^)]+)\)", line)
            for name, path in matches:
                taxonomy.append(
                    {
                        "name": name,
                        "source": "caf-design-areas",
                        "line": line_number,
                        "relative_link": "./design-area/" + path,
                    }
                )
    assert set(AREAS.values()) == {area["name"] for area in taxonomy}
    ledger = []
    for index, item in enumerate(items):
        disposition = "candidate-assisted"
        reason = (
            "Recommendation reviewed; applicability, complete inventory and guidance-level "
            "mapping require reviewer judgment. No implemented evaluator or validated query."
        )
        if item["id"] in AUTOMATED:
            disposition = "candidate-automated"
            reason = (
                "Explicit configuration property is a candidate for bounded evaluation; "
                "applicability, provider mapping and positive/negative fixtures remain unverified."
            )
        elif item["id"] in MANUAL or item["id"].startswith("H"):
            disposition = "candidate-manual"
            reason = "Requires organizational decision/process evidence outside IaC alone."
        flags = [
            "item-guidance-mapping-unverified",
            "platform-application-applicability-unverified",
        ]
        if ids[item["id"]] > 1:
            flags.append("duplicate-upstream-display-id")
        if item["category"].startswith("Azure Billing"):
            flags.append("billing-taxonomy-label-conflict")
        ledger.append(
            {
                "upstream_guid": item["guid"],
                "upstream_id": item["id"],
                "source": "alz-checklist",
                "source_url": source["content_url"],
                "source_revision": source["revision"],
                "source_sha256": source["sha256"],
                "retrieved_at": source["retrieved_at"],
                "pointer": f"/items/{index}",
                "item_sha256": hashlib.sha256(
                    json.dumps(item, sort_keys=True, separators=(",", ":")).encode(),
                ).hexdigest(),
                "upstream_category": item["category"],
                "proposed_design_area": AREAS[item["category"]],
                "mapping_state": "candidate-not-verified",
                "disposition": disposition,
                "reason": reason,
                "flags": flags,
            }
        )
    inventory = {
        "snapshot_version": manifest["snapshot_version"],
        "review_state": "reviewed-inventory-not-a-control-catalog",
        "taxonomy": taxonomy,
        "top_level_fields": list(checklist),
        "item_field_occurrences": dict(Counter(key for item in items for key in item)),
        "upstream_metadata": checklist["metadata"],
        "duplicate_display_ids": {key: n for key, n in ids.items() if n > 1},
        "disposition_counts": dict(Counter(row["disposition"] for row in ledger)),
        "items": ledger,
    }
    (SNAPSHOT / "inventory.json").write_text(
        json.dumps(inventory, indent=2) + "\n",
        encoding="utf-8",
    )
    for entry in manifest["sources"]:
        entry["review_state"] = "reviewed-see-review.md"
    manifest["review_notes"] = "review.md"
    manifest["inventory_sha256"] = hashlib.sha256(
        (SNAPSHOT / "inventory.json").read_bytes()
    ).hexdigest()
    (SNAPSHOT / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
