"""Publish only the installed accepted catalog as immutable GitHub Release assets."""

import argparse
import json
import subprocess
import tempfile
from importlib.resources import files
from pathlib import Path

from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import digest


def publish(repository: str, commit: str) -> dict:
    catalog = load_catalog()
    if catalog.get("review_state") != "reviewed":
        raise ValueError("Only an accepted installed catalog can be published")
    tag = "catalog-" + catalog["catalog_version"]
    existing = subprocess.run(
        ["gh", "release", "view", tag, "--repo", repository],
        capture_output=True,
        timeout=120,
        check=False,
    )
    if existing.returncode == 0:
        return {"published": False, "reason": "Release exists; immutable assets were not replaced."}
    # Distinguish a missing release from authentication/network failures before any write.
    checked = subprocess.run(
        ["gh", "api", f"repos/{repository}/releases", "--jq", ".[].tag_name"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if checked.returncode:
        raise ValueError("Release listing unavailable; no publication attempted")
    if tag in checked.stdout.splitlines():
        raise ValueError("Existing release state changed; do not overwrite")
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        path = root / (tag + ".json")
        path.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
        index = root / "accepted-catalogs.json"
        index.write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "kind": "accepted-catalog-index",
                    "catalogs": [
                        {"version": catalog["catalog_version"], "sha256": digest(catalog)}
                    ],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        notice = root / "reference.LICENSE"
        notice.write_bytes(files("alz_assessor").joinpath("data", "reference.LICENSE").read_bytes())
        result = subprocess.run(
            [
                "gh",
                "release",
                "create",
                tag,
                str(path),
                str(index),
                str(notice),
                "--repo",
                repository,
                "--target",
                commit,
                "--title",
                tag,
                "--notes",
                "Accepted catalog assets only. Runtime does not download or replace its catalog.",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if result.returncode:
            raise ValueError(
                "Accepted catalog release publication failed; no replacement attempted"
            )
        return {"published": True, "url": result.stdout.strip()}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    print(json.dumps(publish(args.repository, args.commit), indent=2))
