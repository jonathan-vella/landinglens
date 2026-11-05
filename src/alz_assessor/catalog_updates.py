"""Conservative candidate generation; installed catalogs are never replaced here."""

import copy
from typing import Any
from urllib.parse import urlsplit

from .contracts import digest, timestamp, validate
from .maintenance import indexed_items
from .terraform import InputError


def candidate_catalog(
    catalog: dict[str, Any],
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    at: str,
    external_changes: list[str] | None = None,
) -> dict[str, Any]:
    validate(catalog, "catalog")
    timestamp(at)
    old, new = indexed_items(before), indexed_items(after)
    controls = {control["upstream_guid"]: control for control in catalog["controls"]}
    if set(old) - set(controls):
        raise InputError("Candidate baseline checklist differs from catalog inventory")
    candidate = copy.deepcopy(catalog)
    classifications: list[dict[str, Any]] = []
    for guid in sorted(set(old) | set(new)):
        if guid not in old:
            category = new[guid]["category"]
            matching = {
                c["design_area"]
                for c in catalog["controls"]
                if c.get("upstream_category") == category
            }
            if len(matching) != 1:
                raise InputError(
                    "New GUID taxonomy is unreviewed; retain candidate snapshot for review"
                )
            source = new[guid]
            candidate["controls"].append(
                {
                    "control_id": "ALZ-" + guid,
                    "upstream_id": source["id"],
                    "upstream_guid": guid,
                    "design_area": matching.pop(),
                    "related_areas": [],
                    "upstream_category": category,
                    "applicability": ["platform", "application"],
                    "applicability_note": "Needs reviewer decision.",
                    "recommendation": source["text"],
                    "severity": source.get("severity", "Unknown"),
                    "automation": "assisted",
                    "method": "Human evidence required; source update unreviewed.",
                    "rule": None,
                    "lifecycle": "active",
                    "baseline": "microsoft-recommendation",
                    "rationale": "New source GUID requires reviewed evidence mapping "
                    "and applicability.",
                    "evidence_requirements": [
                        "Provide a source-backed review before asserting an outcome."
                    ],
                    "mapping_state": "candidate-needs-decision",
                    "flags": ["source-update-needs-review"],
                    "inventory_flags": [],
                    "references": [],
                }
            )
            classification, fields = "needs-review", ["new-guid"]
        elif guid not in new:
            control = next(c for c in candidate["controls"] if c["upstream_guid"] == guid)
            control.update(
                lifecycle="retired",
                retired_at=at,
                retirement_reason="Removed upstream GUID; candidate requires human review.",
            )
            classification, fields = "needs-review", ["removed-guid"]
        else:
            fields = [
                key
                for key in sorted(set(old[guid]) | set(new[guid]))
                if digest(old[guid].get(key)) != digest(new[guid].get(key))
            ]
            classification = (
                "unchanged"
                if not fields
                else "safe"
                if set(fields) <= {"link", "training"}
                else "needs-review"
            )
            if classification == "safe" and any(
                not isinstance(new[guid].get(field), str)
                or urlsplit(new[guid][field]).scheme != "https"
                or not urlsplit(new[guid][field]).netloc
                for field in fields
            ):
                classification = "needs-review"
            if fields:
                control = next(c for c in candidate["controls"] if c["upstream_guid"] == guid)
                control["recommendation"] = new[guid]["text"]
                if "severity" in fields:
                    control["severity"] = new[guid].get("severity", "Unknown")
                if classification == "needs-review":
                    control["flags"] = [*control["flags"], "source-update-needs-review"]
                # Bind source meaning and original GUID; do not invent new accepted predicates.
                control["references"].append(
                    {
                        "source_url": "https://github.com/Azure/review-checklists",
                        "source_sha256": digest(after),
                        "item_sha256": digest(new[guid]),
                        "pointer": guid,
                        "guidance": new[guid].get("link"),
                    }
                )
        classifications.append(
            {
                "guid": guid,
                "classification": classification,
                "fields": fields,
                "reviews_require_review": classification != "unchanged",
            }
        )
    external = external_changes or []
    if external:
        # Without a reviewed per-target mapping, conservatively invalidate every affected
        # baseline review rather than silently carrying it into changed crosswalk sources.
        for row in classifications:
            row["classification"] = "needs-review"
            row["reviews_require_review"] = True
            row["fields"] = sorted(set(row["fields"]) | {"external-crosswalk-source"})
        for control in candidate["controls"]:
            control["flags"] = sorted(set(control["flags"]) | {"external-source-needs-review"})
    changed = [row for row in classifications if row["classification"] != "unchanged"]
    overall = (
        "needs-review"
        if external or any(row["classification"] == "needs-review" for row in changed)
        else "safe"
        if changed
        else "unchanged"
    )
    candidate.update(
        catalog_version="candidate-" + at.replace(":", "-"),
        review_state="candidate-needs-human-review"
        if overall == "needs-review"
        else "candidate-safe",
        candidate_source_sha256=digest(after),
    )
    validate(candidate, "catalog")
    return {
        "candidate": candidate,
        "classification": overall,
        "changes": classifications,
        "external_changes": external,
        "base_catalog_sha256": digest(catalog),
        "warning": "Candidate only. No runtime replacement or unsafe automatic promotion.",
    }


def pr_body(update: dict[str, Any], tests: str) -> str:
    if not isinstance(tests, str) or not tests.strip():
        raise InputError("Source-update PR body requires actual test results")
    rows = ["| GUID | Class | Changed fields | Reviews |", "|---|---|---|---|"]
    rows += [
        "| "
        + row["guid"]
        + " | "
        + row["classification"]
        + " | "
        + ", ".join(row["fields"])
        + " | "
        + ("review required" if row["reviews_require_review"] else "unchanged")
        + " |"
        for row in update["changes"]
        if row["classification"] != "unchanged"
    ]
    return (
        "## Catalog source candidate\n\nClass: "
        + update["classification"]
        + "\n\n"
        + "\n".join(rows)
        + "\n\nExternal changes: "
        + ", ".join(update["external_changes"])
        + "\n\n## Actual checks\n\n"
        + tests
        + "\n\nOnly demonstrable link/training-only edits are safe. Wording, meaning, severity, "
        "queries, taxonomy, additions/removals and external crosswalk targets require human merge. "
        "All historical artifacts remain unchanged; candidate does not grant acceptance.\n"
    )
