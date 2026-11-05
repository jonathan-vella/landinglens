"""Capture metadata for actually reviewed scanner structures; no scanner execution."""

import hashlib
import json
from pathlib import Path

from alz_assessor.contracts import now
from alz_assessor.maintenance import public_fetch

ROOT = Path(__file__).resolve().parents[1]
PSRULE = "8da173a54028cc7f1fe0ac47ad0b1d98700c6d6a"
SARIF = "1742a253eb654bf8a4ed7c60eaef7412b2c23553"
SOURCES = [
    (
        "microsoft/PSRule",
        PSRULE,
        "src/PSRule/Rules/RuleRecord.cs",
        "LICENSE",
        "MIT",
        "Detailed JSON uses ruleName/ref, targetName/type and outcome; targetName is not "
        "assumed to be an ARM ID. Explicit caller index-to-ID mapping is required.",
    ),
    (
        "microsoft/PSRule",
        PSRULE,
        "tests/PSRule.Tests/Pipeline/Output/JsonOutputWriterTests.cs",
        "LICENSE",
        "MIT",
        "Actual JSON output fixtures use outcome Pass/Fail and info.moduleName. "
        "Arbitrary field/detail/source/raw data is withheld, not exported.",
    ),
    (
        "microsoft/PSRule",
        PSRULE,
        "docs/examples/sarif/basic-1.sarif",
        "LICENSE",
        "MIT",
        "Actual SARIF example has version 2.1.0, tool.driver, invocations and results; "
        "empty results do not establish recommendation compliance.",
    ),
    (
        "oasis-tcs/sarif-spec",
        SARIF,
        "sarif-2.1/schema/sarif-schema-2.1.0.json",
        "LICENSE.md",
        "OASIS TC repository terms",
        "Reviewed 2.1.0 result ruleId/kind/locations and invocation executionSuccessful. "
        "Kind omission has fail semantics; missing successful execution cannot prove a run "
        "completed. External properties and unsafe artifact locations are rejected.",
    ),
]


def main() -> None:
    target = ROOT / "references" / "scanner-sources.json"
    if target.exists():
        raise ValueError("Frozen scanner review exists; do not recollect or redate silently")
    records = []
    for repo, revision, path, license_path, terms, finding in SOURCES:
        base = f"https://raw.githubusercontent.com/{repo}/{revision}/"
        content, license_bytes = public_fetch(base + path), public_fetch(base + license_path)
        if not license_bytes.strip():
            raise ValueError("Source licence unavailable")
        records.append(
            {
                "url": base + path,
                "revision": revision,
                "sha256": hashlib.sha256(content).hexdigest(),
                "retrieved_at": now(),
                "license_url": base + license_path,
                "license": terms,
                "license_sha256": hashlib.sha256(license_bytes).hexdigest(),
                "retention": "Metadata and own factual findings only; "
                "no upstream schema/code copied.",
                "finding": finding,
            }
        )
    target.write_text(
        json.dumps({"review_state": "reviewed", "sources": records}, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
