"""Publish one candidate PR with workflow GITHUB_TOKEN, or retain an explicit blocker."""

import argparse
import json
import re
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

from alz_assessor.contracts import read_document


def command(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), capture_output=True, text=True, timeout=120, check=False)


def publish(
    directory: Path,
    repository: str,
    run_id: str,
    *,
    workspace: Path | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> dict:
    if not run_id.isdigit():
        raise ValueError("Run ID must be numeric")
    status = {
        "published": False,
        "checks_dispatched": False,
        "auto_merge_requested": False,
        "blocker": None,
    }
    path = directory / "publication-status.json"
    try:
        update = read_document(directory / "catalog-update.json")
        if update.get("classification") not in {"unchanged", "safe", "needs-review"}:
            raise ValueError("Unrecognised candidate classification")
        if update["classification"] == "unchanged":
            status["blocker"] = "No source changes; no PR needed."
            return status
        # GitHub enforces the PR-creation setting on the create operation itself.
        # Reading the administration endpoint would require an unnecessary permission.
        branch = "catalog-update-" + run_id
        target = (workspace or Path.cwd()) / "references" / "catalog-candidates" / run_id
        target.mkdir(parents=True, exist_ok=False)
        for name in (
            "candidate-catalog.json",
            "catalog-update.json",
            "PR-BODY.md",
            "manifest.json",
            "extended-source-status.json",
        ):
            (target / name).write_bytes((directory / name).read_bytes())
        operations = [
            ("git", "switch", "-c", branch),
            ("git", "add", str(target)),
            (
                "git",
                "-c",
                "user.name=github-actions[bot]",
                "-c",
                "user.email=41898282+github-actions[bot]@users.noreply.github.com",
                "commit",
                "-m",
                "Review classified catalog source candidate",
                "-m",
                "Co-authored-by: Copilot App <223556219+Copilot@users.noreply.github.com>",
            ),
            ("git", "push", "origin", branch),
        ]
        for operation in operations:
            if command(*operation).returncode:
                status["blocker"] = "Candidate branch publication failed; artifacts retained."
                return status
        created = command(
            "gh",
            "pr",
            "create",
            "--repo",
            repository,
            "--head",
            branch,
            "--title",
            ("Validation only: " if update.get("validation_only") is True else "")
            + "Catalog source candidate: "
            + update["classification"],
            "--body-file",
            str(directory / "PR-BODY.md"),
            "--label",
            "catalog-update",
            "--label",
            update["classification"],
        )
        if created.returncode:
            status["blocker"] = (
                "Workflow PR creation denied/failed; candidate branch and artifacts retained."
            )
            return status
        status["published"] = True
        status["pr"] = created.stdout.strip()
        local = command("git", "rev-parse", "HEAD")
        if local.returncode or not re.fullmatch("[0-9a-f]{40}", local.stdout.strip()):
            status["blocker"] = "Candidate commit identity unavailable; no checks dispatched."
            return status
        expected_head = local.stdout.strip()
        status["candidate_head"] = expected_head
        dispatched = command(
            "gh",
            "workflow",
            "run",
            "checks.yml",
            "--repo",
            repository,
            "--ref",
            branch,
        )
        if dispatched.returncode:
            status["blocker"] = (
                "Dispatch of checks.yml failed. The source-update workflow needs actions: write; "
                "the PR remains open without an auto-merge request."
            )
            return status
        status["checks_dispatched"] = True
        status["checks_workflow"] = "checks.yml"
        status["checks_ref"] = branch
        if update["classification"] == "safe":
            settings = command("gh", "api", f"repos/{repository}")
            if (
                settings.returncode
                or json.loads(settings.stdout).get("allow_auto_merge") is not True
            ):
                status["blocker"] = (
                    "Repository auto-merge is disabled or unreadable; safe PR left open."
                )
            else:
                required = {
                    f"checks ({os}, {version})"
                    for os in ("ubuntu-latest", "windows-latest")
                    for version in ("3.12", "3.13")
                }
                ready = False
                for attempt in range(30):
                    checks = command(
                        "gh",
                        "pr",
                        "checks",
                        "--repo",
                        repository,
                        status["pr"],
                        "--json",
                        "name,state",
                    )
                    actual = (
                        json.loads(checks.stdout)
                        if checks.returncode in (0, 8) and checks.stdout.strip()
                        else []
                    )
                    ready = required.issubset({item.get("name") for item in actual}) and all(
                        item.get("state") == "SUCCESS" for item in actual
                    )
                    if ready:
                        runs = command(
                            "gh",
                            "run",
                            "list",
                            "--repo",
                            repository,
                            "--workflow",
                            "checks.yml",
                            "--branch",
                            branch,
                            "--event",
                            "workflow_dispatch",
                            "--commit",
                            expected_head,
                            "--json",
                            "databaseId,headSha,status,conclusion",
                        )
                        matching = json.loads(runs.stdout) if runs.returncode == 0 else []
                        matching = [
                            run
                            for run in matching
                            if run.get("headSha") == expected_head
                            and run.get("status") == "completed"
                            and run.get("conclusion") == "success"
                        ]
                        ready = bool(matching)
                        if ready:
                            status["checks_run_id"] = matching[0]["databaseId"]
                    if ready or any(
                        item.get("state")
                        in {
                            "FAILURE",
                            "CANCELLED",
                            "TIMED_OUT",
                            "ACTION_REQUIRED",
                        }
                        for item in actual
                    ):
                        break
                    if attempt < 29:
                        sleep(20)
                if not ready:
                    status["blocker"] = (
                        "Candidate platform checks are not all green. GITHUB_TOKEN-created PRs "
                        "do not trigger ordinary push/PR workflows; no auto-merge was requested."
                    )
                    return status
                head = command(
                    "gh",
                    "pr",
                    "view",
                    "--repo",
                    repository,
                    status["pr"],
                    "--json",
                    "headRefOid,statusCheckRollup",
                )
                live = json.loads(head.stdout) if head.returncode == 0 else {}
                rollup = live.get("statusCheckRollup")
                live_ready = (
                    isinstance(rollup, list)
                    and required.issubset(
                        {check.get("name", check.get("context")) for check in rollup}
                    )
                    and all(
                        check.get("state") == "SUCCESS"
                        or (
                            check.get("status") == "COMPLETED"
                            and check.get("conclusion") == "SUCCESS"
                        )
                        for check in rollup
                    )
                )
                if head.returncode or live.get("headRefOid") != expected_head or not live_ready:
                    status["blocker"] = (
                        "Candidate head changed or live checks are not green; "
                        "no auto-merge request."
                    )
                    return status
                merged = command(
                    "gh",
                    "pr",
                    "merge",
                    "--repo",
                    repository,
                    "--auto",
                    "--merge",
                    "--match-head-commit",
                    expected_head,
                    status["pr"],
                )
                status["auto_merge_requested"] = merged.returncode == 0
                if merged.returncode:
                    status["blocker"] = (
                        "Safe auto-merge unavailable; PR left for normal review/check gates."
                    )
        return status
    finally:
        path.write_text(json.dumps(status, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    if not args.run_id.isdigit():
        raise SystemExit("Run ID must be numeric")
    print(json.dumps(publish(args.directory, args.repository, args.run_id), indent=2))
