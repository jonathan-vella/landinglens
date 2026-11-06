"""Record an actually merged cohort after exact-head CI and compiler verification."""

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from collections.abc import Callable
from os import fdopen, replace
from pathlib import Path
from typing import Any

from alz_assessor.contracts import digest

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "jonathan-vella/landinglens"
REQUIRED = {
    f"checks ({os}, {version})"
    for os in ("ubuntu-latest", "windows-latest")
    for version in ("3.12", "3.13")
}


def command(args: list[str]) -> Any:
    result = subprocess.run(args, capture_output=True, text=True, timeout=180, check=True)
    return json.loads(result.stdout) if result.stdout.strip() else None


def record(
    batch: str,
    pr: int,
    runs: list[int],
    wheel: Path,
    tests: int,
    skipped: int,
    *,
    root: Path = ROOT,
    run: Callable[[list[str]], Any] = command,
) -> dict[str, Any]:
    if not re.fullmatch(r"\d{2}", batch) or pr <= 0 or len(runs) != 2 or len(set(runs)) != 2:
        raise ValueError("Require one cohort, positive PR and two distinct checked runs")
    if tests <= 0 or not 0 <= skipped < tests:
        raise ValueError("Invalid actual local/installed test totals")
    review_root = root / "references" / "recommendation-batches"
    target = review_root / "ledger.json"
    base = target.read_bytes()
    ledger = json.loads(base)
    targets = json.loads((review_root / "targets.json").read_text("utf-8"))
    matrix = json.loads((review_root / f"batch-{batch}.json").read_text("utf-8"))
    expected = {r["guid"] for r in targets["targets"] if r["batch"] == batch}
    entries = [r for r in ledger["recommendations"] if r["batch"] == batch]
    if (
        not expected
        or {r["guid"] for r in matrix["recommendations"]} != expected
        or {r["guid"] for r in entries} != expected
        or len(entries) != len(expected)
        or ledger["fixed_targets_sha256"] != digest(targets)
    ):
        raise ValueError("Cohort matrix/ledger differs from fixed target membership")
    for entry in ledger["recommendations"]:
        if entry["status"] == "merged":
            prior = ledger.get("deliveries", {}).get(entry["batch"], {})
            if entry["pr"] != prior.get("pr") or entry["merge_commit"] != prior.get("merge_commit"):
                raise ValueError("Existing merged entry differs from its own cohort receipt")
    actual = run(["gh", "api", f"repos/{REPOSITORY}/pulls/{pr}"])
    if (
        actual.get("merged") is not True
        or actual.get("state") != "closed"
        or actual.get("base", {}).get("ref") != "main"
        or not re.fullmatch("[0-9a-f]{40}", actual.get("merge_commit_sha", ""))
        or not re.fullmatch("[0-9a-f]{40}", actual.get("head", {}).get("sha", ""))
        or not actual.get("merged_at")
    ):
        raise ValueError("Require a real merged main PR with exact head and merge identity")
    sha = actual["head"]["sha"]
    details = []
    for identity in runs:
        detail = run(
            [
                "gh",
                "run",
                "view",
                str(identity),
                "--repo",
                REPOSITORY,
                "--json",
                "headSha,status,conclusion,event,jobs,url,workflowName",
            ]
        )
        jobs = detail.get("jobs", [])
        if (
            detail.get("headSha") != sha
            or detail.get("status") != "completed"
            or detail.get("workflowName") != "Advisory CLI checks"
            or detail.get("conclusion") != "success"
            or {job.get("name") for job in jobs} != REQUIRED
            or len(jobs) != 4
            or any(
                job.get("status") != "completed" or job.get("conclusion") != "success"
                for job in jobs
            )
        ):
            raise ValueError("Every supported job must succeed on the exact merged head")
        details.append(detail)
    if {r["event"] for r in details} != {"push", "pull_request"}:
        raise ValueError("Require actual push and PR checks, not unrelated workflow runs")
    pr_run = runs[next(i for i, detail in enumerate(details) if detail["event"] == "pull_request")]
    cases = None
    with tempfile.TemporaryDirectory(prefix="landinglens-compiler-receipt-") as directory:
        run(["gh", "run", "download", str(pr_run), "--repo", REPOSITORY, "--dir", directory])
        for os in ("ubuntu-latest", "windows-latest"):
            for version in ("3.12", "3.13"):
                path = (
                    Path(directory) / f"compiler-coverage-{os}-{version}" / "compiler-coverage.json"
                )
                if path.stat().st_size > 64_000:
                    raise ValueError("Compiler receipt exceeds bound")
                proof = json.loads(path.read_text("utf-8"))
                actual_cases = proof.get("integration_cases")
                if (
                    proof.get("exercised") is not True
                    or proof.get("status") != "exercised"
                    or proof.get("skipped") != []
                    or not isinstance(actual_cases, list)
                    or not actual_cases
                    or any(not isinstance(case, str) for case in actual_cases)
                    or (cases is not None and cases != actual_cases)
                ):
                    raise ValueError(
                        "All four downloaded compiler artifacts must exercise every case"
                    )
                cases = actual_cases
    receipt = {
        "pr": actual["html_url"],
        "merge_commit": actual["merge_commit_sha"],
        "merged_at": actual["merged_at"],
        "checked_head": sha,
        "checks": [r["url"] for r in details],
        "acceptance": "Actual push/PR runs on the merged head passed all eight supported jobs. "
        "All four downloaded PR compiler artifacts exercised the same integration cases "
        "without skips. Normal exact-head merge and other applicable checks were gated "
        "before recording; this receipt does not imply protected-branch enforcement.",
        "compiler_integration_cases": cases,
        "local_installed_suite": {"tests": tests, "passed": tests - skipped, "skipped": skipped},
        "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "live_verification": "Source/fixture/saved/injected and exact installed-CLI verified. "
        "No new Azure access, traffic/runtime test or human decision is asserted.",
    }
    previous = ledger.setdefault("deliveries", {}).get(batch)
    if previous is not None and previous != receipt:
        raise ValueError("A delivered cohort receipt cannot be silently replaced")
    ledger["deliveries"][batch] = receipt
    for entry in entries:
        entry.update(
            status="merged",
            pr=receipt["pr"],
            merge_commit=receipt["merge_commit"],
            runtime_evidence=[
                "fixture/saved/injected verified",
                "exact installed CLI verified",
                f"deliveries.{batch}: all eight CI jobs and four compiler artifacts verified",
            ],
        )
    text = json.dumps(ledger, indent=2, ensure_ascii=True) + "\n"
    if b"\r\n" in base:
        text = text.replace("\n", "\r\n")
    content = text.encode("utf-8")
    descriptor, name = tempfile.mkstemp(prefix=".ledger-", suffix=".tmp", dir=target.parent)
    temporary = Path(name)
    try:
        with fdopen(descriptor, "wb") as stream:
            stream.write(content)
        if target.read_bytes() != base:
            raise ValueError("Ledger changed during verification; no concurrent edits overwritten")
        replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", required=True)
    parser.add_argument("--pr", required=True, type=int)
    parser.add_argument("--runs", required=True, nargs=2, type=int)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--tests", required=True, type=int)
    parser.add_argument("--skipped", required=True, type=int)
    args = parser.parse_args()
    print(
        json.dumps(
            record(args.batch, args.pr, args.runs, args.wheel, args.tests, args.skipped), indent=2
        )
    )
