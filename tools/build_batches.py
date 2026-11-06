"""Reproduce the fixed target ledger and reviewed batch successor without network access."""

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from alz_assessor.catalog import reviewed_refresh
from alz_assessor.contracts import control_digest, digest, validate

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "src" / "alz_assessor" / "data"
REVIEWS = ROOT / "references" / "recommendation-batches"
FIRST = ("G02.01", "G02.02", "G02.03", "G02.04", "G02.07", "G02.08", "G04.02", "G04.03")


def write(path: Path, value: Any) -> None:
    content = json.dumps(value, indent=2, ensure_ascii=True) + "\n"
    if not path.exists() or path.read_text("utf-8") != content:
        path.write_text(content, encoding="utf-8")


def baseline() -> dict[str, Any]:
    path = DATA / "catalog-2026-11-04.2.json"
    if not path.exists():
        content = (DATA / "catalog.json").read_bytes()
        original = json.loads(content)
        if original["catalog_version"] != "2026-11-04.2":
            raise ValueError("Restore the exact .2 baseline before initializing batch delivery")
        path.write_bytes(content)
    original = validate(json.loads(path.read_text("utf-8")), "catalog")
    counts = {
        disposition: sum(c["automation"] == disposition for c in original["controls"])
        for disposition in ("automated", "assisted", "manual")
    }
    if counts != {"automated": 4, "assisted": 209, "manual": 42}:
        raise ValueError("The fixed baseline requires explicit count reconciliation")
    return original


def target_set(original: dict[str, Any]) -> dict[str, Any]:
    controls = original["controls"]
    targets = [c for c in controls if c["automation"] != "automated"]
    first = [next(c for c in targets if c["upstream_id"] == key) for key in FIRST]
    groups = [first]
    for area in original["design_areas"]:
        remaining = [c for c in targets if c not in first and c["design_area"] == area]
        count = (len(remaining) + 9) // 10
        if not count:
            continue
        size, extra = divmod(len(remaining), count)
        offset = 0
        for index in range(count):
            stop = offset + size + (index < extra)
            groups.append(remaining[offset:stop])
            offset = stop
    records = [
        {
            "guid": c["upstream_guid"],
            "control_id": c["control_id"],
            "upstream_id": c["upstream_id"],
            "baseline_disposition": c["automation"],
            "baseline_control_sha256": control_digest(c),
            "design_area": c["design_area"],
            "batch": f"{index:02d}",
        }
        for index, group in enumerate(groups, 1)
        for c in group
    ]
    if len(records) != 251 or len({c["guid"] for c in records}) != 251:
        raise ValueError("Batch partition lost or duplicated a canonical target GUID")
    return {
        "baseline_version": original["catalog_version"],
        "baseline_sha256": digest(original),
        "baseline_file_sha256": hashlib.sha256(
            (DATA / "catalog-2026-11-04.2.json").read_bytes()
        ).hexdigest(),
        "preserved_automated": {
            c["control_id"]: control_digest(c) for c in controls if c["automation"] == "automated"
        },
        "targets": records,
    }


def apply_batch(
    previous: dict[str, Any],
    original: dict[str, Any],
    targets: dict[str, Any],
    batch: dict[str, Any],
    batches: list[dict[str, Any]],
    manifests: list[dict[str, Any]],
) -> dict[str, Any]:
    if batch.get("review_state") == "preparation-only-reviewed":
        raise ValueError("Preparation matrices cannot activate an accepted catalog successor")
    catalog = copy.deepcopy(previous)
    identity = batch["batch"]
    for version, expected_hash in batch.get("preserved_catalog_bytes", {}).items():
        if (
            hashlib.sha256((DATA / f"catalog-{version}.json").read_bytes()).hexdigest()
            != expected_hash
        ):
            raise ValueError("A delivered historical catalog's exact bytes changed")
    manifest_path = REVIEWS / f"batch-{identity}-sources.json"
    if not manifest_path.exists():
        raise ValueError("Capture and review actual batch sources before building a successor")
    manifest = json.loads(manifest_path.read_text("utf-8"))
    expected = {r["guid"] for r in targets["targets"] if r["batch"] == identity}
    if (
        len(batch["recommendations"]) != len(expected)
        or {r["guid"] for r in batch["recommendations"]} != expected
    ):
        raise ValueError("Reviewed batch does not match its fixed GUID membership")
    if set(batch.get("prerequisites", [])) - {b["batch"] for b in batches}:
        raise ValueError("A batch's accepted prerequisite matrix is unavailable")
    if manifest["batch"] != identity:
        raise ValueError("Source manifest belongs to a different batch")
    source_by_id = {source["id"]: source for source in manifest["sources"]}
    updates = {item["guid"]: item for item in batch["recommendations"]}
    changes = []
    for control in catalog["controls"]:
        update = updates.get(control["upstream_guid"])
        if update is None:
            continue
        before = control_digest(control)
        control.update(
            automation="manual" if update["classification"] == "manual" else "assisted",
            evidence_requirements=update["evidence_requirements"],
            rationale=update["limitations"],
            mapping_state=f"source-reviewed-batch-{identity}",
            flags=update["flags"],
        )
        if "review_resource_types" in update:
            control["review_resource_types"] = update["review_resource_types"]
        if "review_fact_paths" in update:
            control["review_fact_paths"] = update["review_fact_paths"]
        if update.get("rule"):
            control.update(automation="automated", method=update["method"], rule=update["rule"])
        for key in update["sources"]:
            source = source_by_id[key]
            control["references"].append(
                {
                    "source_url": source["url"],
                    "source_sha256": source["sha256"],
                    "revision": source["revision"],
                    "retrieved_at": source["retrieved_at"],
                    "pointer": control["upstream_guid"],
                    "guidance": source["url"],
                }
            )
        changes.append(
            {
                "control_id": control["control_id"],
                "before_sha256": before,
                "after_sha256": control_digest(control),
                "rationale": f"Owner-delegated source-backed batch {identity} acceptance: "
                + update["classification"],
            }
        )
    batches.append(batch)
    manifests.append(manifest)
    matrix = {"fixed_targets_sha256": digest(targets), "batches": batches, "sources": manifests}
    version = batch.get("catalog_version", "2026-11-05.1")
    suffix = "" if identity == "01" else "-" + version
    source_name = f"batch-control-sources{suffix}.json"
    if identity == "01":
        (DATA / source_name).write_bytes(manifest_path.read_bytes())
    else:
        write(DATA / source_name, {"batches": manifests})
    catalog.update(
        catalog_version=version,
        first_wave_matrix_sha256=original["accepted_matrix_sha256"],
        accepted_matrix_sha256=digest(matrix),
        batch_source_manifest_sha256=hashlib.sha256((DATA / source_name).read_bytes()).hexdigest(),
    )
    if "priority_manifest_sha256" in catalog:
        catalog["batch_catalog_version"] = version
    catalog["change_review"] = {
        "base_sha256": digest(previous),
        "matrix_sha256": digest(matrix),
        "reviewed_at": batch.get("accepted_at", manifest["sources"][0]["retrieved_at"]),
        "reviewer": "owner-delegated-source-backed-batch-review",
        "changes": changes,
    }
    for identity, expected_hash in targets["preserved_automated"].items():
        if control_digest(next(c for c in catalog["controls"] if c["control_id"] == identity)) != (
            expected_hash
        ):
            raise ValueError("An original automated control changed during batch expansion")
    reviewed_refresh(catalog, previous)
    write(DATA / f"batch-matrix{suffix}.json", matrix)
    return catalog


def catalog_order(batch: dict[str, Any]) -> tuple[str, int]:
    date, sequence = batch.get("catalog_version", "2026-11-05.1").rsplit(".", 1)
    return date, int(sequence)


def main() -> None:
    original = baseline()
    targets = target_set(original)
    fixed = REVIEWS / "targets.json"
    if fixed.exists() and json.loads(fixed.read_text("utf-8")) != targets:
        raise ValueError("The fixed target set cannot be changed by catalog refresh or delivery")
    write(fixed, targets)
    catalog = original
    batches: list[dict[str, Any]] = []
    manifests: list[dict[str, Any]] = []
    updates = {}
    issues = {}
    accepted = sorted(
        (json.loads(path.read_text("utf-8")) for path in REVIEWS.glob("batch-[0-9][0-9].json")),
        key=catalog_order,
    )
    priorities = (
        json.loads((DATA / "catalog-priorities.json").read_text("utf-8"))
        if (DATA / "catalog-priorities.json").exists()
        else None
    )
    for index, batch in enumerate(accepted):
        catalog = apply_batch(catalog, original, targets, batch, batches, manifests)
        if priorities and catalog["catalog_version"] == priorities["base_catalog_version"]:
            from alz_assessor.priorities import prioritised_catalog

            catalog = prioritised_catalog(catalog, priorities)
            if index < len(accepted) - 1:
                frozen = DATA / f"catalog-{catalog['catalog_version']}.json"
                if not frozen.exists() or json.loads(frozen.read_text("utf-8")) != catalog:
                    raise ValueError(
                        "Restore the exact delivered priority catalog before expansion"
                    )
        if index < len(accepted) - 1:
            frozen = DATA / f"catalog-{catalog['catalog_version']}.json"
            if frozen.exists() and json.loads(frozen.read_text("utf-8")) != catalog:
                raise ValueError("A delivered historical catalog's meaning changed")
            write(frozen, catalog)
        updates.update({item["guid"]: item for item in batch["recommendations"]})
        issues[batch["batch"]] = batch.get(
            "issue", "https://github.com/jonathan-vella/landinglens/issues/46"
        )
    write(DATA / "catalog.json", catalog)
    ledger = [
        {
            **item,
            "status": "implementation-in-progress" if item["guid"] in updates else "pending",
            "review": updates.get(item["guid"]),
            "issue": issues.get(item["batch"]),
            "pr": None,
            "merge_commit": None,
            "runtime_evidence": [],
        }
        for item in targets["targets"]
    ]
    ledger_path = REVIEWS / "ledger.json"
    if ledger_path.exists():
        existing = json.loads(ledger_path.read_text("utf-8"))
        if existing["fixed_targets_sha256"] != digest(targets) or {
            entry["guid"] for entry in existing["recommendations"]
        } != {item["guid"] for item in ledger}:
            raise ValueError("Delivery ledger differs from the fixed target set")
        for entry in existing["recommendations"]:
            if entry["status"] == "merged":
                receipt = existing.get("deliveries", {}).get(entry["batch"])
                if (
                    not receipt
                    or not receipt.get("pr")
                    or not receipt.get("merge_commit")
                    or entry.get("pr") != receipt["pr"]
                    or entry.get("merge_commit") != receipt["merge_commit"]
                ):
                    raise ValueError("Merged recommendation differs from its cohort receipt")
            elif entry.get("merge_commit") or (
                entry["status"] == "pending" and (entry.get("pr") or entry.get("runtime_evidence"))
            ):
                raise ValueError("Undelivered recommendation has stale acceptance references")
            if entry["guid"] in updates and entry["status"] != "merged":
                entry["review"] = updates[entry["guid"]]
                entry["issue"] = issues[entry["batch"]]
                if entry["status"] == "pending":
                    entry["status"] = "implementation-in-progress"
        write(ledger_path, existing)
    else:
        write(ledger_path, {"fixed_targets_sha256": digest(targets), "recommendations": ledger})


if __name__ == "__main__":
    main()
