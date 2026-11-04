"""Explicit acquisition of one reviewed AVM snapshot for the LL-02 proof only."""

import hashlib
import json
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from alz_assessor.terraform import tree_hash

REPOSITORY = "Azure/terraform-azurerm-avm-res-operationalinsights-workspace"
REVISION = "b4ffa3ff87ac09ff6de3b7014c44b4d213aa302b"
VERSION = "0.5.1"
FILES = (
    "LICENSE",
    "locals.tf",
    "main.data_export.tf",
    "main.indexes.tf",
    "main.linked_service.tf",
    "main.linked_storage_account.tf",
    "main.nsp.tf",
    "main.privateendpoint.tf",
    "main.privatelinkscope.tf",
    "main.tables.tf",
    "main.telemetry.tf",
    "main.tf",
    "outputs.tf",
    "terraform.tf",
    "variables.tf",
)


def main() -> None:
    root = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "alz-avm"
    snapshot = root / "snapshots" / "workspace"
    if snapshot.exists():
        raise SystemExit("AVM fixture snapshot exists; never overwrite a reviewed version.")
    snapshot.mkdir()
    files = []
    for name in FILES:
        url = f"https://raw.githubusercontent.com/{REPOSITORY}/{REVISION}/{name}"
        with urllib.request.urlopen(url, timeout=60) as response:
            content = response.read()
        (snapshot / name).write_bytes(content)
        files.append(
            {
                "file": name,
                "url": url,
                "sha256": hashlib.sha256(content).hexdigest(),
                "retrieved_at": datetime.now(UTC).isoformat(),
            }
        )
    provenance = {
        "repository": REPOSITORY,
        "revision": REVISION,
        "tag": "v" + VERSION,
        "license": "MIT",
        "retained": "All module-root .tf files and LICENSE, unmodified",
        "omitted": "Examples, tests, CI and documentation; no module-root IaC omitted",
        "review_state": "reviewed-source-fixture-not-complete-AVM-compatibility",
        "files": files,
    }
    (root / "provenance.json").write_text(
        json.dumps(provenance, indent=2) + "\n",
        encoding="utf-8",
    )
    modules = [
        {
            "source": "example.invalid/landinglens/avm-platform/azurerm",
            "version": "1.0.0",
            "subdirectory": "",
            "path": "snapshots/platform",
            "sha256": tree_hash(root / "snapshots" / "platform"),
            "origin": "LandingLens authored platform wrapper",
        },
        {
            "source": "Azure/avm-res-operationalinsights-workspace/azurerm",
            "version": VERSION,
            "subdirectory": "",
            "path": "snapshots/workspace",
            "sha256": tree_hash(snapshot),
            "origin": provenance["repository"],
            "revision": REVISION,
        },
    ]
    (root / "snapshots.json").write_text(
        json.dumps({"modules": modules}, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
