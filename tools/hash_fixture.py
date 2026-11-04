"""Freeze the synthetic fixture module snapshot hashes, not remote module retrieval."""

import json
from pathlib import Path

from alz_assessor.contracts import derive_id, digest, document
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
slice_root = root.parent / "slice"
slice_modules = [{**entry, "path": "../alz/" + entry["path"]} for entry in modules]
slice_modules.append(
    {
        "source": "example/security/azurerm",
        "version": "1.0.0",
        "subdirectory": "",
        "path": "snapshots/security",
        "sha256": tree_hash(slice_root / "snapshots" / "security"),
        "origin": "LandingLens authored security slice, not an upstream module",
    }
)
(slice_root / "snapshots.json").write_text(
    json.dumps({"modules": slice_modules}, indent=2) + "\n",
    encoding="utf-8",
)
scope = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-management"
resources = [
    {
        "logical_id": "saved-storage",
        "resource_type": "Microsoft.Storage/storageAccounts",
        "arm_id": derive_id(scope, "Microsoft.Storage/storageAccounts", "landinglenslogs"),
        "state": "known",
        "reason": "",
        "properties": {"supportsHttpsTrafficOnly": True},
        "source_location": "authored://storage-fixture",
    }
]
(slice_root / "observed.json").write_text(
    json.dumps(
        document(
            "evidence",
            mode="observed",
            source="saved",
            scope=scope,
            collected_at="2026-11-04T00:00:00Z",
            inventory_complete=True,
            artifact_hashes={"authored-resource-records": digest(resources)},
            resources=resources,
            diagnostics=[],
        ),
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)
avm_root = root.parent / "alz-avm"
avm_manifest = avm_root / "snapshots.json"
avm = json.loads(avm_manifest.read_text(encoding="utf-8"))
for module in avm["modules"]:
    actual = tree_hash(avm_root / module["path"])
    if module["origin"].startswith("LandingLens authored"):
        module["sha256"] = actual
    elif actual != module["sha256"]:
        raise RuntimeError("Unmodified upstream snapshot changed; refusing to accept new bytes")
avm_manifest.write_text(json.dumps(avm, indent=2) + "\n", encoding="utf-8")
