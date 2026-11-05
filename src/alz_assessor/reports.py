"""Render the same minimized result model, never raw parameter/resource properties."""

import html
import json
from typing import Any

from .contracts import digest, validate
from .diagnostics import guidance
from .html_report import render_html
from .priorities import sort_key


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
    if any("severity" in entry for entry in result["results"]):
        result["results"].sort(key=sort_key)
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
                "arg_warning",
                "inventory_transport",
                "source_binding",
                "warning",
                "archetype_bindings",
            )
            if key in metadata
        }
        counts = metadata.get("policy_record_counts", {})
        bundle["metadata"]["policy_record_counts"] = {
            key: len(metadata[key]) if isinstance(metadata.get(key), list) else counts[key]
            for key in (
                "policy_assignments",
                "policy_exemptions",
                "policy_compliance",
                "policy_definitions",
                "policy_set_definitions",
            )
            if isinstance(metadata.get(key), list)
            or (isinstance(counts, dict) and type(counts.get(key)) is int)
        }
    if minimize:
        result["presentation_only"] = True
        for suggestion in result.get("applicability_suggestions", []):
            suggestion["scope"] = None
        if "scanner_signals" in result:
            scanned = result["scanner_signals"]
            scanned["scope"] = None
            scanned["artifact_hashes"] = {
                f"input-{i}": value for i, value in enumerate(scanned["artifact_hashes"].values())
            }
            for record in scanned["records"]:
                record["resource_id"] = None
        for scanned in result.get("scanner_signal_runs", []):
            scanned["scope"] = None
            for record in scanned["records"]:
                record["resource_id"] = None
        for signal in (result.get("policy_signals") or {}).get("records", []):
            signal["resource_id"] = None
            signal["assignment_id"] = None
            if not isinstance(signal["definition_id"], str) or not signal[
                "definition_id"
            ].startswith("/providers/microsoft.authorization/"):
                signal["definition_id"] = None
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
    if "evidence_tiers" in model:
        lines += [
            "Evidence tiers: " + json.dumps(model["evidence_tiers"]["counts"], sort_keys=True),
            "Verified includes failures; Signals are not passes. Counts are once per control.",
            "",
        ]
    if "applicability_suggestions" in model:
        lines += [
            "Applicability suggestions (reviewer confirmation required): "
            + json.dumps(model["applicability_suggestions"], sort_keys=True),
            "",
        ]
    if "policy_signals" in model:
        lines += [
            "Policy Signals (not checklist outcomes): "
            + json.dumps(model["policy_signals"], sort_keys=True),
            "",
        ]
    for retired in model.get("retired_controls", []):
        lines += ["Retired/historical: " + json.dumps(retired, sort_keys=True), ""]
    for bundle in model["evidence"]:
        lines += [json.dumps(bundle, sort_keys=True), ""]
    area = None
    for entry in sorted(model["results"], key=sort_key):
        if entry["design_area"] != area:
            area = entry["design_area"]
            lines += ["## " + area, ""]
        cells = [
            entry["upstream_id"],
            entry["logical_id"],
            "/".join(entry["applicability"]),
            entry["recommendation"],
            *(["Severity: " + entry["severity"]] if "severity" in entry else []),
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
    if "scanner_signals" in model:
        lines += [
            "Scanner Signals (not checklist outcomes): "
            + json.dumps(model["scanner_signals"], sort_keys=True),
            "",
        ]
    if "scanner_signal_runs" in model:
        lines += [
            "Separate scanner runs: " + json.dumps(model["scanner_signal_runs"], sort_keys=True)
        ]
    text = "\n".join(lines)
    if format == "markdown":
        # Escape raw HTML, table delimiters and link syntax from untrusted input.
        return html.escape(text, quote=False).replace("|", "\\|").replace("[", "\\[")
    if format == "html":
        return render_html(model)
    raise ValueError("Unsupported report format")
