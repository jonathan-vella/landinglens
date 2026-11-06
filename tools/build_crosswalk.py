"""Reproduce the reviewed crosswalk offline; source capture is explicit and maintainer-only."""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import digest, now
from alz_assessor.crosswalk import validate_crosswalk
from alz_assessor.maintenance import public_fetch

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "src" / "alz_assessor" / "data"
REVIEW = ROOT / "references" / "crosswalk"
ALZ = "4eae565287844360a61545f9799400431adb6d0a"
POLICY = "f096d8de10fb25e71dd7f82b78ded110ec711d73"
PSRULE = "a40c77e029c6e6d95f7a809dc70219c9ee9a4242"
CHECKLIST = "f131b93418892102b00c247fd9cf685e3d356522"
AUDIT = "601062bee928d0a7c1d41dabfa123875af501b59"
REGISTRY = [
    (
        "alz-storage-assignment",
        "Azure/Azure-Landing-Zones-Library",
        ALZ,
        "platform/alz/policy_assignments/Deny-Storage-http.alz_policy_assignment.json",
        "platform/alz/2026.10.0",
        "Exact Deny-Storage-http assignment references built-in 404c3081 with Deny effect and "
        "2.*.* definition version. Placeholder scope is a library template, not deployed evidence.",
    ),
    (
        "builtin-storage-transfer",
        "Azure/azure-policy",
        POLICY,
        "built-in-policies/policyDefinitions/Storage/Storage_AuditForHTTPSEnabled_Audit.json",
        None,
        "Built-in 404c3081 version 2.0.0 checks explicit false and API-dependent absent values. "
        "Audit/Deny/Disabled effect and missing-property defaults differ from LandingLens's "
        "explicit-boolean-only predicate; compliance remains a Signal, not an equivalent pass.",
    ),
    (
        "psrule-storage-yaml",
        "Azure/PSRule.Rules.Azure",
        PSRULE,
        "src/PSRule.Rules.Azure/rules/Azure.Storage.Rule.yaml",
        "v1.48.0-B0228",
        "Azure.Storage.SecureTransfer / AZR-000196 accepts an omitted flag for API >=2019-04-01. "
        "This differs from LandingLens's explicit-property requirement; partial mapping only.",
    ),
    (
        "psrule-storage-powershell",
        "Azure/PSRule.Rules.Azure",
        PSRULE,
        "src/PSRule.Rules.Azure/rules/Azure.Storage.Rule.ps1",
        "v1.48.0-B0228",
        "Azure.Storage.ContainerSoftDelete / AZR-000289 checks child enabled plus days>=1, "
        "with CloudShell/HNS/FileStorage exclusions. Its population and child/default semantics "
        "are not equivalent to the whole checklist or LandingLens predicate.",
    ),
    (
        "psrule-storage-guidance",
        "Azure/PSRule.Rules.Azure",
        PSRULE,
        "docs/en/rules/Azure.Storage.SecureTransfer.md",
        "v1.48.0-B0228",
        "Actual rule guidance links built-in 404c3081 and documents API-dependent secure-transfer "
        "defaults. These are associations, not operational encryption verification.",
    ),
    (
        "checklist",
        "Azure/review-checklists",
        CHECKLIST,
        "checklists/alz_checklist.en.json",
        None,
        "Frozen 255-GUID checklist supplies exact 49 nonempty query hashes "
        "and recommendation intent.",
    ),
    (
        "candidate-audit",
        "jonathan-vella/landinglens",
        AUDIT,
        "references/2026-11-04-wave1/candidate-audit.json",
        None,
        "Reviewed static 49-query audit supplies per-GUID output/population limitations. "
        "No query was executed; query associations are related only, not an execution allowlist.",
    ),
]


def capture() -> None:
    path = REVIEW / "sources.json"
    if path.exists():
        raise ValueError("Reviewed crosswalk capture exists; never silently recollect or redate")
    sources = []
    for identity, repo, revision, filename, release, finding in REGISTRY:
        url = f"https://raw.githubusercontent.com/{repo}/{revision}/{filename}"
        content = public_fetch(url)
        # The local audit has no upstream licence grant of its own; its source is our own
        # factual review. The underlying checklist's MIT notice is retained separately.
        license_repo = "Azure/review-checklists" if identity == "candidate-audit" else repo
        license_revision = CHECKLIST if identity == "candidate-audit" else revision
        license_url = f"https://raw.githubusercontent.com/{license_repo}/{license_revision}/LICENSE"
        license_bytes = public_fetch(license_url)
        if b"MIT License" not in license_bytes:
            raise ValueError("Expected reviewed MIT source terms; inspect changed licence")
        sources.append(
            {
                "id": identity,
                "url": url,
                "revision": revision,
                "sha256": hashlib.sha256(content).hexdigest(),
                "retrieved_at": now(),
                "release": release,
                "license": "Own factual review; underlying checklist MIT"
                if identity == "candidate-audit"
                else "MIT",
                "license_url": license_url,
                "license_revision": license_revision,
                "license_sha256": hashlib.sha256(license_bytes).hexdigest(),
                "finding": finding,
            }
        )
    REVIEW.mkdir(exist_ok=True)
    path.write_text(json.dumps({"sources": sources}, indent=2) + "\n", encoding="utf-8")


def build(version: str) -> None:
    catalog = load_catalog()
    manifest = json.loads((REVIEW / "sources.json").read_text("utf-8"))
    checklist_bytes = (ROOT / "references" / "2026-11-04" / "alz-checklist.json").read_bytes()
    audit_bytes = (ROOT / "references" / "2026-11-04-wave1" / "candidate-audit.json").read_bytes()
    sources = {source["id"]: source for source in manifest["sources"]}
    for name, content in (("checklist", checklist_bytes), ("candidate-audit", audit_bytes)):
        if sources[name]["sha256"] != hashlib.sha256(content).hexdigest():
            raise ValueError("Frozen local source differs from actually captured source")
    checklist = json.loads(checklist_bytes)
    query_by_guid = {
        item["guid"]: item["graph"] for item in checklist["items"] if item.get("graph")
    }
    audit = {item["guid"]: item for item in json.loads(audit_bytes)["query_audit"]}
    if query_by_guid.keys() != audit.keys():
        raise ValueError("Checklist queries differ from reviewed audit membership")
    entries = []
    for control in catalog["controls"]:
        guid = control["upstream_guid"]
        targets: list[dict[str, Any]] = []
        if guid in query_by_guid:
            query_hash = hashlib.sha256(query_by_guid[guid].encode()).hexdigest()
            if query_hash != audit[guid]["query_sha256"]:
                raise ValueError("Audited query hash differs from actual checklist bytes")
            targets.append(
                {
                    "kind": "arg-query",
                    "id": query_hash,
                    "strength": "related",
                    "rationale": "Static candidate only; not an executable allowlist or outcome. "
                    + audit[guid]["population_applicability_and_missing_value_review"],
                    "source_ids": ["checklist", "candidate-audit"],
                }
            )
        if guid == "b03ed428-4617-4067-a787-85468b9ccf3f":
            for kind, identity, refs in [
                (
                    "alz-policy-assignment",
                    "Deny-Storage-http",
                    ["alz-storage-assignment", "builtin-storage-transfer"],
                ),
                (
                    "azure-policy-definition",
                    "/providers/Microsoft.Authorization/policyDefinitions/404c3081-a854-4457-ae30-26a93ef643f9",
                    ["builtin-storage-transfer"],
                ),
                (
                    "psrule",
                    "Azure.Storage.SecureTransfer",
                    ["psrule-storage-yaml", "psrule-storage-guidance"],
                ),
            ]:
                targets.append(
                    {
                        "kind": kind,
                        "id": identity,
                        "strength": "partial",
                        "rationale": "Same secure-transfer property intent, but external "
                        "API-dependent missing-value defaults/effects differ from LandingLens's "
                        "explicit boolean; "
                        "no assignment/scanner result establishes a checklist pass.",
                        "source_ids": ["checklist", *refs],
                    }
                )
        if guid == "159aac9f-863f-4f48-82cf-00c28fa97a0e":
            targets.append(
                {
                    "kind": "psrule",
                    "id": "Azure.Storage.ContainerSoftDelete",
                    "strength": "partial",
                    "rationale": "Checks enabled and retention days but has "
                    "CloudShell/HNS/FileStorage "
                    "population exclusions and child selection differences. No recovery test or "
                    "equivalent whole-recommendation outcome.",
                    "source_ids": ["checklist", "psrule-storage-powershell"],
                }
            )
        entries.append({"guid": guid, "control_id": control["control_id"], "targets": targets})
    result = validate_crosswalk(
        {
            "schema_version": "1.0",
            "kind": "crosswalk",
            "crosswalk_version": version,
            "catalog_sha256": digest(catalog),
            "review_state": "reviewed",
            "reviewed_at": max(source["retrieved_at"] for source in manifest["sources"]),
            "reviewer": "owner-delegated-source-backed-review",
            "sources": manifest["sources"],
            "entries": entries,
        },
        catalog,
    )
    for name, value in (
        ("crosswalk.json", result),
        ("crosswalk-binding.json", {"crosswalk_sha256": digest(result)}),
    ):
        path = DATA / name
        content = json.dumps(value, indent=2) + "\n"
        if not path.exists() or path.read_text("utf-8") != content:
            path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="Reviewed crosswalk successor version")
    parser.add_argument("--capture-reviewed-sources", action="store_true")
    args = parser.parse_args()
    if args.capture_reviewed_sources:
        capture()
    build(args.version)
