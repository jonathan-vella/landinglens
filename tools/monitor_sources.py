"""Explicit maintainer acquisition using the reviewed source registry; artifact-only."""

import argparse
import json
import re
from collections.abc import Callable
from pathlib import Path

from capture_references import SOURCES

from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import now, read_document, timestamp
from alz_assessor.maintenance import public_fetch, semantic_diff, sha256
from alz_assessor.terraform import InputError


def monitor(
    baseline: Path,
    destination: Path,
    fetch: Callable[[str], bytes] = public_fetch,
    *,
    at: str | None = None,
    previous_status: dict | None = None,
) -> dict:
    instant = at or now()
    timestamp(instant)
    if destination.exists():
        raise InputError("Candidate destination exists; snapshots are never overwritten")
    destination.mkdir(parents=True)
    manifest = read_document(baseline / "manifest.json")
    previous_poll = (previous_status or {}).get("last_successful_poll")
    if previous_poll:
        timestamp(previous_poll)
    catalog = load_catalog()
    status = {
        "poll_attempted_at": instant,
        "last_successful_poll": previous_poll,
        "last_semantic_review": {
            "catalog_version": catalog["catalog_version"],
            "recorded_reviewed_at": catalog.get("reviewed_at"),
        },
        "pending_changes": None,
        "promotion_allowed": False,
        "warning": None,
    }
    records = []
    try:
        old_sources = {s["id"]: s for s in manifest["sources"] if "file" in s}
        if old_sources.keys() != SOURCES.keys():
            raise InputError("Baseline source registry differs from reviewed sources")
        for name, (repo, _, path, url, license_id) in SOURCES.items():
            old = old_sources[name]
            filename = name + (".json" if path.endswith(".json") else ".md")
            license_file = name + ".LICENSE"
            if old["file"] != filename or old["license_file"] != license_file:
                raise InputError("Baseline source paths differ from reviewed filenames")
            if (
                sha256((baseline / filename).read_bytes()) != old["sha256"]
                or sha256((baseline / license_file).read_bytes()) != old["license_sha256"]
            ):
                raise InputError("Baseline source/license hash mismatch")
            commit = json.loads(fetch(f"https://api.github.com/repos/{repo}/commits/HEAD"))
            if not isinstance(commit, dict):
                raise InputError("Upstream commit metadata must be an object")
            revision = commit.get("sha")
            if not isinstance(revision, str) or not re.fullmatch("[0-9a-f]{40}", revision):
                raise InputError("Upstream commit identity is invalid")
            raw_url = f"https://raw.githubusercontent.com/{repo}/{revision}/{path}"
            license_bytes = fetch(f"https://raw.githubusercontent.com/{repo}/{revision}/LICENSE")
            if not license_bytes.strip():
                raise InputError("Candidate license is unavailable")
            if sha256(license_bytes) != old["license_sha256"]:
                status["pending_changes"] = True
                status["license_review_required"] = {
                    "source": name,
                    "before_sha256": old["license_sha256"],
                    "after_sha256": sha256(license_bytes),
                }
                (destination / license_file).write_bytes(license_bytes)
                raise InputError("Changed license requires review before retaining source content")
            content = fetch(raw_url)
            (destination / filename).write_bytes(content)
            (destination / license_file).write_bytes(license_bytes)
            records.append(
                {
                    "id": name,
                    "url": url,
                    "content_url": raw_url,
                    "revision": revision,
                    "file": filename,
                    "sha256": sha256(content),
                    "license": license_id,
                    "license_file": license_file,
                    "license_sha256": sha256(license_bytes),
                    "retrieved_at": instant,
                    "review_state": "candidate-unreviewed",
                }
            )
        diff = semantic_diff(
            read_document(baseline / "alz-checklist.json"),
            read_document(destination / "alz-checklist.json"),
            (baseline / "caf-design-areas.md").read_text("utf-8"),
            (destination / "caf-design-areas.md").read_text("utf-8"),
            {key: value["license_sha256"] for key, value in old_sources.items()},
            {s["id"]: s["license_sha256"] for s in records},
        )
        status.update(
            last_successful_poll=instant,
            pending_changes=any(
                old_sources[s["id"]]["sha256"] != s["sha256"]
                or old_sources[s["id"]]["license_sha256"] != s["license_sha256"]
                for s in records
            ),
            diff=diff,
        )
        (destination / "manifest.json").write_text(
            json.dumps(
                {
                    "snapshot_version": "candidate-" + instant,
                    "sources": records,
                    "review_state": "candidate-unreviewed",
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    except (OSError, InputError, ValueError, KeyError) as exc:
        status["warning"] = (
            "Source poll failed; the installed/reviewed catalog is unchanged. "
            "Candidate is incomplete or invalid: " + type(exc).__name__
        )
    (destination / "status.json").write_text(
        json.dumps(status, indent=2) + "\n",
        encoding="utf-8",
    )
    return status


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, default=Path("references") / "2026-11-04")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--previous-status", type=Path)
    parser.add_argument("--efficiency", action="store_true")
    parser.add_argument("--test-results", type=Path)
    parser.add_argument("--validation-candidate", action="store_true")
    args = parser.parse_args()
    if args.validation_candidate and not args.efficiency:
        parser.error("--validation-candidate requires --efficiency and actual test results")
    result = monitor(
        args.baseline,
        args.output,
        previous_status=read_document(args.previous_status) if args.previous_status else None,
    )
    if args.efficiency and not result["warning"]:
        from prepare_catalog_update import prepare, prepare_validation

        try:
            if not args.test_results:
                raise InputError("Efficiency candidates require actual --test-results")
            prepare(args.output, args.baseline, args.test_results.read_text("utf-8"))
            if args.validation_candidate:
                prepare_validation(args.output, args.baseline, args.test_results.read_text("utf-8"))
        except (OSError, ValueError, InputError, KeyError) as exc:
            result["warning"] = (
                "Extended source update blocked: " + type(exc).__name__ + ": " + str(exc)
            )
            (args.output / "PR-BODY.md").write_text(
                "## Source update blocked\n\n"
                + result["warning"]
                + "\n\nCandidate artifacts retained; installed catalog unchanged.\n",
                encoding="utf-8",
            )
            (args.output / "status.json").write_text(
                json.dumps(result, indent=2) + "\n", encoding="utf-8"
            )
    print(json.dumps({key: value for key, value in result.items() if key != "diff"}, indent=2))
    raise SystemExit(2 if result["warning"] else 0)
