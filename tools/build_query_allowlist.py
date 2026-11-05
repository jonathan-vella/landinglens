"""Reproduce the narrow reviewed upstream-query Signal allowlist offline."""

import hashlib
import json
from pathlib import Path

from alz_assessor.contracts import digest

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "src" / "alz_assessor" / "data"
ACCEPTED = {
    "e9c8f584-6d5e-473b-8dc5-acc9fbaab4e3",
    "b9d0dff5-bdd4-4cd8-88ed-5811610b2b2c",
}


def main() -> None:
    checklist = json.loads((ROOT / "references/2026-11-04/alz-checklist.json").read_text("utf-8"))
    audit = json.loads(
        (ROOT / "references/2026-11-04-wave1/candidate-audit.json").read_text("utf-8")
    )
    items = {item["guid"]: item for item in checklist["items"]}
    reviewed = []
    for candidate in audit["query_audit"]:
        guid = candidate["guid"]
        query = items[guid]["graph"]
        sha = hashlib.sha256(query.encode()).hexdigest()
        if sha != candidate["query_sha256"]:
            raise ValueError("Frozen query bytes differ from reviewed audit")
        allowed = guid in ACCEPTED
        if allowed and candidate["classification"] != "direct-predicate":
            raise ValueError("Only audited direct executable subsets may enter allowlist")
        reviewed.append(
            {
                "guid": guid,
                "query_sha256": sha,
                "allowed": allowed,
                "query": query if allowed else None,
                "expected_columns": {"id": "canonical-arm-id", "compliant": "boolean-or-null"}
                if allowed
                else {},
                "identity_column": "id" if allowed else None,
                "resource_type": "microsoft.network/firewallpolicies" if allowed else None,
                "permission_profile": audit["permission_profiles"][candidate["permission_profile"]],
                "rationale": (
                    "Reviewed explicit local Deny-mode observation with canonical id and "
                    "typed boolean. Missing/null, SKU capability, inheritance and filtering "
                    "do not establish compliance; "
                    "output is Signal only, never an evaluator predicate."
                    if allowed
                    else "Not allowlisted: "
                    + candidate["classification"]
                    + ". "
                    + candidate["population_applicability_and_missing_value_review"]
                ),
            }
        )
    result = {
        "schema_version": "1.0",
        "version": "2026-11-05.1",
        "kind": "query-allowlist",
        "review_state": "owner-delegated-reviewed-signal-subset",
        "reviewed_at": "2026-11-05T11:01:59Z",
        "reviewer": "owner-delegated-source-backed-review",
        "checklist_revision": "f131b93418892102b00c247fd9cf685e3d356522",
        "audit_sha256": digest(audit),
        "queries": reviewed,
        "warning": "Static source review, not live query compilation or permission proof. "
        "All results are Signals; empty queries never pass a control.",
    }
    for name, value in (
        ("query-allowlist.json", result),
        ("query-allowlist-binding.json", {"sha256": digest(result)}),
    ):
        path = DATA / name
        text = json.dumps(value, indent=2) + "\n"
        if not path.exists() or path.read_text("utf-8") != text:
            path.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
