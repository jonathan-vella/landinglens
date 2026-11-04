"""Explicit maintainer review of pinned read-operation metadata; no Azure calls."""

import hashlib
import json
from pathlib import Path

from review_control_sources import fetch

from alz_assessor.contracts import now
from alz_assessor.terraform import InputError

REVISION = "b466b0ffcfd90c19380bf26440570a223a1e2020"
ROOT = "https://raw.githubusercontent.com/Azure/azure-rest-api-specs/" + REVISION
SOURCES = [
    (
        "resource-graph",
        "2022-10-01",
        "specification/resourcegraph/resource-manager/"
        "Microsoft.ResourceGraph/ResourceGraph/stable/2022-10-01/resourcegraph.json",
    ),
    (
        "definitions",
        "2023-04-01",
        "specification/resources/resource-manager/"
        "Microsoft.Authorization/policy/stable/2023-04-01/policyDefinitions.json",
    ),
    (
        "initiatives",
        "2023-04-01",
        "specification/resources/resource-manager/"
        "Microsoft.Authorization/policy/stable/2023-04-01/policySetDefinitions.json",
    ),
]


if __name__ == "__main__":
    target = Path(__file__).resolve().parents[1] / "references" / "2026-11-04-wave1"
    target = target / "collection-apis.json"
    if target.exists():
        raise InputError("Reviewed API metadata is frozen; create a reviewed successor")
    records = []
    for name, version, path in SOURCES:
        url = ROOT + "/" + path
        content = fetch(url)
        document = json.loads(content)
        if document["info"]["version"] != version:
            raise InputError("Actual API source version differs from reviewed version")
        operations = [
            {"method": method.upper(), "path": route, "operation": spec.get("operationId")}
            for route, methods in document["paths"].items()
            for method, spec in methods.items()
            if method == "get"
            or (
                name == "resource-graph"
                and method == "post"
                and route == "/providers/Microsoft.ResourceGraph/resources"
            )
        ]
        if not operations:
            raise InputError("Reviewed read operation not found in actual source")
        records.append(
            {
                "id": name,
                "url": url,
                "revision": REVISION,
                "api_version": version,
                "sha256": hashlib.sha256(content).hexdigest(),
                "retrieved_at": now(),
                "operations": operations,
                "schema_keys": sorted(document.get("definitions", {})),
                "reuse": "MIT; read-operation metadata and own factual notes only",
            }
        )
        if name == "resource-graph":
            print(
                json.dumps(
                    {
                        key: value
                        for key, value in document.get("definitions", {}).items()
                        if key in {"QueryRequest", "QueryResponse", "QueryRequestOptions"}
                    },
                    indent=2,
                )
            )
    target.write_text(
        json.dumps(
            {
                "sources": records,
                "review_notes": [
                    "ARG scopes live in the POST subscriptions body; query filters are not scope.",
                    "Only the fixed id/type projection is accepted; no upstream/arbitrary KQL.",
                    "Rows, counts, resultTruncated and skipToken determine page exhaustion, "
                    "not RBAC completeness; eventual consistency and child gaps remain explicit.",
                    "Definitions are listed at exact scopes; references resolve only inside "
                    "the boundary or as built-ins, without ancestor-scope read escalation.",
                    "Definition/rule/parameter hashes and associations are configuration, "
                    "not compliance. No policy rules or deployment actions are executed.",
                    "Pinned PolicyStates 2019-10-01 and exemption 2022-07-01-preview operations "
                    "remain; management-group exemption lists explicitly use atScope().",
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
