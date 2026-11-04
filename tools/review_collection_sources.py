"""Freeze public API operations; never query an Azure tenant."""

import hashlib
import json
from pathlib import Path

from review_control_sources import fetch

ROOT = Path(__file__).resolve().parents[1]
SPECS = {
    "assignments": (
        "specification/resources/resource-manager/Microsoft.Authorization/"
        "policy/stable/2023-04-01/policyAssignments.json"
    ),
    "exemptions": (
        "specification/resources/resource-manager/Microsoft.Authorization/"
        "policy/preview/2022-07-01-preview/policyExemptions.json"
    ),
    "compliance": (
        "specification/policyinsights/resource-manager/Microsoft.PolicyInsights/"
        "PolicyInsights/stable/2019-10-01/policyStates.json"
    ),
}


def main() -> None:
    target = ROOT / "references" / "2026-11-04-controls" / "collection-apis.json"
    if target.exists():
        raise RuntimeError("Frozen review exists; do not overwrite")
    revision = json.loads(
        fetch(
            "https://api.github.com/repos/Azure/azure-rest-api-specs/commits/main",
        )
    )["sha"]
    records = []
    for name, path in SPECS.items():
        url = f"https://raw.githubusercontent.com/Azure/azure-rest-api-specs/{revision}/{path}"
        content = fetch(url)
        spec = json.loads(content)
        operations = []
        for route, methods in spec["paths"].items():
            for method, operation in methods.items():
                if method == "get" or (method == "post" and route.endswith("/queryResults")):
                    operations.append(
                        {
                            "method": method.upper(),
                            "path": route,
                            "operation": operation["operationId"],
                        }
                    )
        if not operations:
            raise RuntimeError("No reviewed read operations found")
        notes = [
            parameter.get("description", "")
            for parameter in spec.get("parameters", {}).values()
            if parameter.get("name") == "$filter"
        ]
        from datetime import UTC, datetime

        records.append(
            {
                "id": name,
                "url": url,
                "revision": revision,
                "retrieved_at": datetime.now(UTC).isoformat(),
                "sha256": hashlib.sha256(content).hexdigest(),
                "api_version": spec["info"]["version"],
                "operations": operations,
                "filter_semantics": notes,
                "reuse": "MIT; metadata only",
            }
        )
        print(name, spec["info"]["version"], json.dumps(notes))
    permissions_url = "https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/management-and-governance"
    content = fetch(permissions_url)
    text = content.decode("utf-8")
    start = text.lower().find("microsoft.policyinsights/policystates/queryresults/")
    if start < 0:
        raise RuntimeError("Policy query permission was not found in reviewed operation reference")
    print("Reviewed permission:", text[start : start + 250])
    target.write_text(
        json.dumps(
            {
                "sources": records,
                "permissions": {
                    "url": permissions_url,
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "reviewed_operation_excerpt": text[start : start + 250],
                },
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
