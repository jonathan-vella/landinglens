"""Render the same minimized result model, never raw parameter/resource properties."""

import html
import json
from typing import Any

from .contracts import digest, validate
from .diagnostics import guidance
from .html_report import render_html


def report_model(assessment: dict[str, Any], minimize: bool = False) -> dict[str, Any]:
    validate(assessment, "assessment")
    result = {key: value for key, value in assessment.items() if key != "evidence"}
    result["evidence"] = [
        {
            key: bundle.get(key)
            for key in (
                "mode",
                "source",
                "scope",
                "collected_at",
                "inventory_complete",
                "artifact_hashes",
                "diagnostics",
                "metadata",
            )
        }
        for bundle in assessment["evidence"]
    ]
    result = json.loads(json.dumps(result))
    for entry in result["results"]:
        for mode in ("planned", "observed"):
            if entry.get(mode):
                entry[mode]["guidance"] = guidance(entry[mode]["reason"])
        if entry.get("comparison_reason"):
            entry["comparison_guidance"] = guidance(entry["comparison_reason"])
    for bundle in result["evidence"]:
        for diagnostic in bundle.get("diagnostics") or []:
            diagnostic["guidance"] = guidance(diagnostic["reason"])
        metadata = bundle.get("metadata") or {}
        bundle["metadata"] = {
            key: metadata[key]
            for key in (
                "provider_version",
                "compiler_version",
                "dependency_binding",
                "limitations",
                "scopes",
                "relationships",
                "completeness",
                "run_complete",
                "inventory_authorization_attested",
                "policy_warning",
                "source_binding",
                "warning",
            )
            if key in metadata
        }
        counts = metadata.get("policy_record_counts", {})
        bundle["metadata"]["policy_record_counts"] = {
            key: len(metadata[key]) if isinstance(metadata.get(key), list) else counts[key]
            for key in ("policy_assignments", "policy_exemptions", "policy_compliance")
            if isinstance(metadata.get(key), list)
            or (isinstance(counts, dict) and type(counts.get(key)) is int)
        }
    if minimize:
        result["presentation_only"] = True
        for entry in result["results"]:
            entry["logical_id"], entry["arm_id"] = (
                "target-" + digest(entry["logical_id"])[:12],
                None,
            )
            for mode in ("planned", "observed"):
                if entry.get(mode):
                    entry[mode]["evidence_links"] = ["[minimized]"]
                    for review in entry[mode].get("reviews", []):
                        review["reviewer"] = None
        for bundle in result["evidence"]:
            bundle["scope"] = None
            bundle["artifact_hashes"] = {
                f"input-{i}": value for i, value in enumerate(bundle["artifact_hashes"].values())
            }
            bundle["metadata"] = {"minimized": True}
            bundle["diagnostics"] = [
                {
                    "reason": item.get("reason"),
                    "facet": item.get("facet"),
                    "guidance": guidance(item["reason"]),
                }
                for item in bundle.get("diagnostics") or []
            ]
    return result


def render(assessment: dict[str, Any], format: str = "json", minimize: bool = False) -> str:
    model = report_model(assessment, minimize)
    if format == "json":
        return json.dumps(model, indent=2, allow_nan=False) + "\n"
    heading = (
        f"LandingLens advisory assessment | catalog {model['catalog_version']} | "
        f"{model['generated_at']}"
    )
    lines = [heading, "", json.dumps(model["coverage"], sort_keys=True), ""]
    for retired in model.get("retired_controls", []):
        lines += ["Retired/historical: " + json.dumps(retired, sort_keys=True), ""]
    for bundle in model["evidence"]:
        lines += [json.dumps(bundle, sort_keys=True), ""]
    area = None
    for entry in sorted(
        model["results"], key=lambda row: (row["design_area"], row["control_id"], row["logical_id"])
    ):
        if entry["design_area"] != area:
            area = entry["design_area"]
            lines += ["## " + area, ""]
        cells = [
            entry["upstream_id"],
            entry["logical_id"],
            "/".join(entry["applicability"]),
            entry["recommendation"],
        ]
        for mode in ("planned", "observed"):
            item = entry.get(mode)
            cells.append(
                mode + ": " + (json.dumps(item, sort_keys=True) if item else "unavailable")
            )
        cells.append(
            "comparison: "
            + str(entry["comparison"])
            + (" (" + entry["comparison_reason"] + ")" if entry.get("comparison_reason") else "")
        )
        if entry.get("comparison_guidance"):
            cells.append(json.dumps(entry["comparison_guidance"], sort_keys=True))
        cells.append(
            "guidance/evidence: "
            + json.dumps(
                {
                    key: entry.get(key)
                    for key in ("references", "flags", "evidence_requirements", "rationale")
                },
                sort_keys=True,
            )
        )
        lines += [" | ".join(cells), ""]
    text = "\n".join(lines)
    if format == "markdown":
        # Escape raw HTML, table delimiters and link syntax from untrusted input.
        return html.escape(text, quote=False).replace("|", "\\|").replace("[", "\\[")
    if format == "html":
        return render_html(model)
    raise ValueError("Unsupported report format")
