"""Freeze the synthetic fixture module snapshot hashes, not remote module retrieval."""

import json
from pathlib import Path

from alz_assessor.terraform import tree_hash

root = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "alz"
modules = []
for name in ("platform", "management"):
    path = root / "snapshots" / name
    source_name = "alz" if name == "platform" else name
    modules.append(
        {
            "source": f"example.invalid/landinglens/{source_name}/azurerm",
            "version": "1.0.0",
            "subdirectory": "",
            "path": f"snapshots/{name}",
            "sha256": tree_hash(path),
            "origin": "LandingLens synthetic authored fixture, not an official AVM/ALZ release",
        }
    )
(root / "snapshots.json").write_text(
    json.dumps({"modules": modules}, indent=2) + "\n",
    encoding="utf-8",
)
