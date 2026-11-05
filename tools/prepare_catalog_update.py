"""Maintainer extension: reviewed-source metadata, candidate diff and PR body artifacts."""

import copy
import json
import re
from pathlib import Path
from typing import Any

from alz_assessor.catalog import load_catalog
from alz_assessor.catalog_updates import candidate_catalog, pr_body
from alz_assessor.contracts import digest, read_document
from alz_assessor.maintenance import public_fetch, sha256
from alz_assessor.terraform import InputError

ROOT = Path(__file__).resolve().parents[1]


def extended_sources(destination: Path, fetch: Any = public_fetch) -> list[str]:
    baseline = read_document(ROOT / "references/crosswalk/sources.json")["sources"]
    selected = {
        "alz-storage-assignment": ("Azure/Azure-Landing-Zones-Library", "platform/alz/"),
        "psrule-storage-yaml": ("Azure/PSRule.Rules.Azure", "v"),
        "builtin-storage-transfer": ("Azure/azure-policy", None),
    }
    changes, records = [], []
    revisions: dict[str, tuple[str, str | None]] = {}
    for source in baseline:
        if source["id"] not in selected:
            continue
        repo, prefix = selected[source["id"]]
        if prefix:
            releases = json.loads(
                fetch(f"https://api.github.com/repos/{repo}/releases?per_page=100")
            )
            if not isinstance(releases, list):
                raise InputError("Release metadata must be an array")
            releases = [
                item
                for item in releases
                if isinstance(item, dict)
                and not item.get("draft")
                and isinstance(item.get("tag_name"), str)
                and item["tag_name"].startswith(prefix)
            ]
            if not releases:
                raise InputError("No verifiable source release in the bounded release page")
            tag = releases[0]["tag_name"]
            ref = json.loads(fetch(f"https://api.github.com/repos/{repo}/git/ref/tags/{tag}"))[
                "object"
            ]
            if ref.get("type") == "tag":
                ref = json.loads(
                    fetch(f"https://api.github.com/repos/{repo}/git/tags/{ref['sha']}")
                )["object"]
            revision = ref.get("sha")
        else:
            tag = None
            revision = json.loads(fetch(f"https://api.github.com/repos/{repo}/commits/HEAD")).get(
                "sha"
            )
        if not isinstance(revision, str) or not re.fullmatch("[0-9a-f]{40}", revision):
            raise InputError("Source release did not resolve to an immutable commit")
        revisions[repo] = (revision, tag)
        license_bytes = fetch(f"https://raw.githubusercontent.com/{repo}/{revision}/LICENSE")
        if sha256(license_bytes) != source["license_sha256"]:
            raise InputError("Source licence changed: " + source["id"] + "; content not retained")
        path = source["url"].split("/" + source["revision"] + "/", 1)[1]
        content = fetch(f"https://raw.githubusercontent.com/{repo}/{revision}/{path}")
        if source["id"] == "psrule-storage-yaml":
            text = content.decode("utf-8")
            if "kind: Rule" not in text or "Azure.Storage.SecureTransfer" not in text:
                raise InputError("PSRule source structure changed; mapping requires review")
        elif not isinstance(json.loads(content), dict):
            raise InputError("Source structure changed; review candidate manually")
        record = {
            "id": source["id"],
            "revision": revision,
            "release": tag,
            "sha256": sha256(content),
            "license_sha256": sha256(license_bytes),
        }
        if record["sha256"] != source["sha256"] or (
            tag is not None and tag != source.get("release")
        ):
            changes.append(source["id"])
        records.append(record)
        if source["id"] in {"psrule-storage-yaml", "alz-storage-assignment"}:
            tree_hashes = []
            prefix_path = (
                "src/PSRule.Rules.Azure/"
                if source["id"] == "psrule-storage-yaml"
                else "platform/alz/"
            )
            for commit in (source["revision"], revision):
                tree = json.loads(
                    fetch(f"https://api.github.com/repos/{repo}/git/trees/{commit}?recursive=1")
                )
                if tree.get("truncated") is not False or not isinstance(tree.get("tree"), list):
                    raise InputError("Library/baseline tree is incomplete")
                entries = [
                    {"path": item["path"], "sha": item["sha"]}
                    for item in tree["tree"]
                    if isinstance(item, dict)
                    and item.get("type") == "blob"
                    and str(item.get("path", "")).startswith(prefix_path)
                ]
                tree_hashes.append(digest(entries))
            if tree_hashes[0] != tree_hashes[1]:
                changes.append(source["id"] + "-library-tree")
            records.append(
                {
                    "id": source["id"] + "-library-tree",
                    "revision": revision,
                    "before_sha256": tree_hashes[0],
                    "sha256": tree_hashes[1],
                }
            )
    # Track definition blob identities without downloading or evaluating their rule bodies.
    revision, _ = revisions["Azure/azure-policy"]
    tree = json.loads(
        fetch(f"https://api.github.com/repos/Azure/azure-policy/git/trees/{revision}?recursive=1")
    )
    if tree.get("truncated") is not False or not isinstance(tree.get("tree"), list):
        raise InputError("Built-in policy source tree is incomplete")
    definitions = [
        {"path": item["path"], "sha": item["sha"]}
        for item in tree["tree"]
        if isinstance(item, dict)
        and item.get("type") == "blob"
        and str(item.get("path", "")).startswith("built-in-policies/")
    ]
    baseline_revision = next(
        source["revision"] for source in baseline if source["id"] == "builtin-storage-transfer"
    )
    old_tree = json.loads(
        fetch(
            f"https://api.github.com/repos/Azure/azure-policy/git/trees/{baseline_revision}?recursive=1"
        )
    )
    if old_tree.get("truncated") is not False or not isinstance(old_tree.get("tree"), list):
        raise InputError("Built-in policy baseline tree is incomplete")
    old_definitions = [
        {"path": item["path"], "sha": item["sha"]}
        for item in old_tree["tree"]
        if isinstance(item, dict)
        and item.get("type") == "blob"
        and str(item.get("path", "")).startswith("built-in-policies/")
    ]
    if digest(old_definitions) != digest(definitions):
        changes.append("builtin-definition-tree")
    records.append(
        {
            "id": "builtin-definition-tree",
            "revision": revision,
            "content_sha256": digest(definitions),
            "definitions": len(definitions),
        }
    )
    (destination / "extended-source-status.json").write_text(
        json.dumps(
            {
                "records": records,
                "changes": changes,
                "coverage": "Release identity and reviewed crosswalk targets; "
                "other target mappings require review.",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return changes


def prepare(
    destination: Path, baseline: Path, tests: str, *, fetch: Any = public_fetch
) -> dict[str, Any]:
    status = read_document(destination / "status.json")
    if status.get("warning"):
        raise InputError("Incomplete source poll cannot produce a promotable candidate")
    external = extended_sources(destination, fetch)
    update = candidate_catalog(
        load_catalog(),
        read_document(baseline / "alz-checklist.json"),
        read_document(destination / "alz-checklist.json"),
        at=status["poll_attempted_at"],
        external_changes=external,
    )
    for name, value in (
        ("candidate-catalog.json", update["candidate"]),
        ("catalog-update.json", update),
    ):
        (destination / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    (destination / "PR-BODY.md").write_text(pr_body(update, tests), encoding="utf-8")
    return update


def prepare_validation(destination: Path, baseline: Path, tests: str) -> dict[str, Any]:
    """Keep the live poll intact and isolate one explicitly authored link-only fixture."""
    for name in ("candidate-catalog.json", "catalog-update.json", "PR-BODY.md"):
        source = destination / name
        if not source.is_file():
            raise InputError("Validation requires an independently completed live source poll")
        (destination / ("observed-" + name)).write_bytes(source.read_bytes())
    before = read_document(baseline / "alz-checklist.json")
    after = copy.deepcopy(before)
    item = next(
        entry for entry in after["items"] if entry["guid"] == "b03ed428-4617-4067-a787-85468b9ccf3f"
    )
    expected = "https://learn.microsoft.com/azure/storage/common/storage-require-secure-transfer"
    if item.get("link") != expected:
        raise InputError("The reviewed link-validation fixture baseline changed")
    item["link"] = expected.replace("microsoft.com/azure/", "microsoft.com/en-us/azure/", 1)
    status = read_document(destination / "status.json")
    update = candidate_catalog(
        load_catalog(),
        before,
        after,
        at=status["poll_attempted_at"],
    )
    if update["classification"] != "safe":
        raise InputError("Authored validation must remain strictly link-only")
    update["validation_only"] = True
    update["validation_note"] = (
        "Authored locale-link fixture, not an upstream source-change claim. "
        "The independently observed poll is retained in observed-* artifacts. "
        "No catalog activation or accepted Release publication."
    )
    for name, value in (
        ("candidate-catalog.json", update["candidate"]),
        ("catalog-update.json", update),
    ):
        (destination / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    (destination / "PR-BODY.md").write_text(
        "## Validation only\n\n"
        + update["validation_note"]
        + "\n\nRelates to #78.\n\n"
        + pr_body(update, tests),
        encoding="utf-8",
    )
    return update
