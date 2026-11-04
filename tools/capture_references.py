"""Explicit maintainer-only acquisition; never imported by the offline CLI."""

import hashlib
import json
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "references" / "2026-11-04"
SOURCES = {
    "alz-site": (
        "Azure/Azure-Landing-Zones",
        "7ffa9b9c20ccc4bb3ebe2f36a5d31e5f3df79cc5",
        "docs/content/_index.md",
        "https://azure.github.io/Azure-Landing-Zones/",
        "MIT",
    ),
    "caf-design-areas": (
        "MicrosoftDocs/cloud-adoption-framework",
        "6535103c6b3b54175cf4b10bf8985f433ae9a514",
        "docs/ready/landing-zone/design-areas.md",
        "https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/landing-zone/design-areas",
        "CC-BY-4.0",
    ),
    "alz-checklist": (
        "Azure/review-checklists",
        "f131b93418892102b00c247fd9cf685e3d356522",
        "checklists/alz_checklist.en.json",
        "https://github.com/Azure/review-checklists/blob/main/checklists/alz_checklist.en.json",
        "MIT",
    ),
    "bicep-cli": (
        "MicrosoftDocs/azure-docs",
        "d38f1ab1475b19e08cc9a53a90c18656954a3ff4",
        "articles/azure-resource-manager/bicep/bicep-cli.md",
        "https://learn.microsoft.com/en-us/azure/azure-resource-manager/bicep/bicep-cli",
        "CC-BY-4.0",
    ),
}


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()


def capture() -> None:
    if DEST.exists():
        raise SystemExit("Snapshot already exists; use a new reviewed snapshot, never overwrite.")
    DEST.mkdir(parents=True)
    entries = []
    for name, (repo, revision, path, url, license_id) in SOURCES.items():
        raw_url = f"https://raw.githubusercontent.com/{repo}/{revision}/{path}"
        content = fetch(raw_url)
        filename = name + (".json" if path.endswith(".json") else ".md")
        (DEST / filename).write_bytes(content)
        license_bytes = fetch(f"https://raw.githubusercontent.com/{repo}/{revision}/LICENSE")
        license_file = name + ".LICENSE"
        (DEST / license_file).write_bytes(license_bytes)
        entries.append(
            {
                "id": name,
                "url": url,
                "content_url": raw_url,
                "revision": revision,
                "retrieved_at": datetime.now(UTC).isoformat(),
                "sha256": hashlib.sha256(content).hexdigest(),
                "file": filename,
                "license": license_id,
                "license_file": license_file,
                "license_sha256": hashlib.sha256(license_bytes).hexdigest(),
                "review_state": "retrieved-awaiting-review",
            }
        )
    # Hash the actual public pages too; retain repository-licensed text, not site assets.
    for name, url in [
        ("alz-site-rendered", "https://azure.github.io/Azure-Landing-Zones/"),
        ("caf-rendered", SOURCES["caf-design-areas"][3]),
        ("bicep-rendered", SOURCES["bicep-cli"][3]),
        ("learn-terms", "https://learn.microsoft.com/en-us/legal/termsofuse"),
        (
            "terraform-variables",
            "https://developer.hashicorp.com/terraform/language/values/variables",
        ),
    ]:
        content = fetch(url)
        entries.append(
            {
                "id": name,
                "url": url,
                "revision": None,
                "retrieved_at": datetime.now(UTC).isoformat(),
                "sha256": hashlib.sha256(content).hexdigest(),
                "retention": "URL, checksum and factual review notes only; no page redistribution",
                "review_state": "retrieved-awaiting-review",
            }
        )
    (DEST / "manifest.json").write_text(
        json.dumps({"snapshot_version": "2026-11-04.1", "sources": entries}, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    capture()
