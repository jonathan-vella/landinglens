"""Capture reviewed priority sources explicitly; regenerate catalog metadata offline."""

import argparse
import hashlib
import json
from pathlib import Path

from alz_assessor.contracts import digest, now
from alz_assessor.maintenance import public_fetch
from alz_assessor.priorities import prioritised_catalog

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "src" / "alz_assessor" / "data"
REVISION = "4eae565287844360a61545f9799400431adb6d0a"
RAW = f"https://raw.githubusercontent.com/Azure/Azure-Landing-Zones-Library/{REVISION}/"


def capture() -> None:
    target = DATA / "catalog-priorities.json"
    if target.exists():
        raise ValueError("Frozen priority review exists; do not silently recollect")
    sources = []
    content_by_id = {}
    license_bytes = public_fetch(RAW + "LICENSE")
    if b"MIT License" not in license_bytes:
        raise ValueError("Library licence changed; inspect before retaining source")
    for identity, path in (
        (
            "architecture",
            "platform/alz/architecture_definitions/alz.alz_architecture_definition.json",
        ),
        (
            "landing-zones",
            "platform/alz/archetype_definitions/landing_zones.alz_archetype_definition.json",
        ),
    ):
        content = public_fetch(RAW + path)
        content_by_id[identity] = json.loads(content)
        sources.append(
            {
                "id": identity,
                "url": RAW + path,
                "revision": REVISION,
                "release": "platform/alz/2026.10.0",
                "sha256": hashlib.sha256(content).hexdigest(),
                "retrieved_at": now(),
                "license": "MIT",
                "license_url": RAW + "LICENSE",
                "license_sha256": hashlib.sha256(license_bytes).hexdigest(),
            }
        )
    checklist = ROOT / "references" / "2026-11-04" / "alz-checklist.json"
    raw_checklist = checklist.read_bytes()
    items = json.loads(raw_checklist)["items"]
    base_bytes = (DATA / "catalog.json").read_bytes()
    base = json.loads(base_bytes)
    if base["catalog_version"] != "2026-11-05.3":
        raise ValueError("Freeze priority metadata against delivered .3, not a draft catalog")
    (DATA / "catalog-2026-11-05.3.json").write_bytes(base_bytes)
    (DATA / "crosswalk-2026-11-05.1.json").write_bytes((DATA / "crosswalk.json").read_bytes())
    if "Deny-Storage-http" not in content_by_id["landing-zones"]["policy_assignments"]:
        raise ValueError("Reviewed storage assignment association changed")
    metadata = {
        "version": "2026-11-05.1",
        "catalog_version": "2026-11-05.5",
        "base_catalog_version": base["catalog_version"],
        "base_catalog_sha256": digest(base),
        "checklist_sha256": hashlib.sha256(raw_checklist).hexdigest(),
        "reviewed_at": now(),
        "reviewer": "owner-delegated-source-backed-review",
        "sources": sources,
        "severities": {item["guid"]: item.get("severity", "Unknown") for item in items},
        "architecture": {
            entry["id"]: {"archetypes": entry["archetypes"], "parent_id": entry["parent_id"]}
            for entry in content_by_id["architecture"]["management_groups"]
        },
        "limitations": "Bindings are explicit producer assertions, not discovered topology. "
        "Only landing_zones -> Deny-Storage-http -> G04.01 is reviewed here. "
        "No inherited archetype/population exclusion or automatic applicability outcome.",
    }
    target.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")


def build() -> None:
    metadata = json.loads((DATA / "catalog-priorities.json").read_text("utf-8"))
    base = json.loads(
        (DATA / f"catalog-{metadata['base_catalog_version']}.json").read_text("utf-8")
    )
    catalog = prioritised_catalog(base, metadata)
    path = DATA / "catalog.json"
    content = json.dumps(catalog, indent=2) + "\n"
    if path.read_text("utf-8") != content:
        path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-reviewed-sources", action="store_true")
    args = parser.parse_args()
    if args.capture_reviewed_sources:
        capture()
    build()
