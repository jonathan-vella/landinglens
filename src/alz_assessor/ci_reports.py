"""Advisory SARIF and compact PR summaries over the sanitised report model."""

import html
import json
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from .contracts import digest
from .terraform import InputError


def safe_location(body: dict[str, Any], base: Path | None, minimized: bool) -> list[dict[str, Any]]:
    if base is None or minimized:
        return []
    root = base.resolve(strict=True)
    if not root.is_dir():
        raise InputError("SARIF base must be an existing directory")
    for link in body["evidence_links"]:
        if not isinstance(link, str):
            continue
        path_text = link.split("#", 1)[0]
        try:
            parsed = urlsplit(path_text)
        except ValueError:
            continue
        if parsed.scheme and not (len(parsed.scheme) == 1 and ":" in path_text[:3]):
            continue
        if (
            "\x00" in path_text
            or "%" in path_text
            or ".." in path_text.replace("\\", "/").split("/")
        ):
            continue
        path = Path(path_text)
        if not path.is_absolute():
            path = root / path
        try:
            path = path.resolve(strict=True)
        except (OSError, ValueError):
            continue
        if path.is_file() and path.is_relative_to(root):
            # Evidence has no verified source line. A file-only SARIF location is honest;
            # do not invent line 1 or a property offset to obtain an annotation.
            return [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": quote(path.relative_to(root).as_posix(), safe="/"),
                        }
                    }
                }
            ]
    return []


def sarif(model: dict[str, Any], base: Path | None = None) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for row in model["results"]:
        rules.setdefault(
            row["control_id"],
            {
                "id": row["control_id"],
                "name": row["upstream_id"],
                "shortDescription": {"text": row["recommendation"]},
                "properties": {
                    "designArea": row["design_area"],
                    "severity": row.get("severity", "Unknown"),
                },
            },
        )
        for mode in ("planned", "observed"):
            body = row.get(mode)
            if body is None:
                continue
            outcome = body["outcome"]
            kind = {"pass": "pass", "fail": "fail", "not_applicable": "notApplicable"}.get(
                outcome, "review"
            )
            level = (
                "none"
                if outcome in {"pass", "not_applicable"}
                else "error"
                if outcome == "error"
                else {"High": "error", "Medium": "warning", "Low": "note"}.get(
                    row.get("severity"), "warning"
                )
                if outcome == "fail"
                else "note"
            )
            result = {
                "ruleId": row["control_id"],
                "kind": kind,
                "level": level,
                "message": {
                    "text": f"{row['upstream_id']} ({mode}): {outcome}. "
                    f"{row['recommendation']} Reason: {body['reason']}"
                },
                "partialFingerprints": {
                    "landinglens/v1": digest(
                        {
                            "control": row["control_id"],
                            "target": row.get("arm_id") or row["logical_id"],
                            "mode": mode,
                            "rule": row["rule_sha256"],
                        }
                    )
                },
                "properties": {
                    "mode": mode,
                    "outcome": outcome,
                    "freshness": body["freshness"],
                    "evidenceTier": body.get("evidence_tier"),
                    "comparison": row.get("comparison"),
                    "exceptionDisposition": body.get("exception_disposition"),
                },
            }
            locations = safe_location(body, base, bool(model.get("presentation_only")))
            if locations:
                result["locations"] = locations
            results.append(result)
    return (
        json.dumps(
            {
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "LandingLens",
                                "version": "0.1.0",
                                "informationUri": "https://github.com/jonathan-vella/landinglens",
                                "rules": list(rules.values()),
                            }
                        },
                        "invocations": [
                            {"executionSuccessful": True, "endTimeUtc": model["generated_at"]}
                        ],
                        "results": results,
                        "properties": {
                            "catalogVersion": model["catalog_version"],
                            "coverage": model["coverage"],
                            "evidenceTiers": model.get("evidence_tiers"),
                            "warning": "Advisory only. Signals, unknowns and exceptions "
                            "are not passing technical evidence.",
                        },
                    }
                ],
            },
            indent=2,
            allow_nan=False,
        )
        + "\n"
    )


def cell(value: Any) -> str:
    return (
        html.escape(str(value), quote=False)
        .replace("|", "\\|")
        .replace("[", "\\[")
        .replace("\n", " ")
    )


def pr_summary(model: dict[str, Any]) -> str:
    coverage = model["coverage"]
    visibility = (
        "complete producer assertion" if coverage["inventory_complete"] else "incomplete/unverified"
    )
    lines = [
        "## LandingLens advisory summary",
        "",
        f"Catalog: {cell(model['catalog_version'])}. Controls: {coverage['controls']}. "
        f"Inventory: {visibility}.",
        "",
        "| Mode | Assessed instances | Completion | Pass rate among assessed |",
        "|---|---:|---:|---:|",
    ]
    for mode, metrics in coverage["modes"].items():

        def percent(key: str, metrics: dict[str, Any] = metrics) -> str:
            value = metrics.get(key)
            return "unavailable" if value is None else f"{100 * value:.1f}%"

        lines.append(
            f"| {mode} | {metrics['assessed']} | {percent('completion')} | "
            f"{percent('subset_pass_rate')} |"
        )
    if "evidence_tiers" in model:
        lines += [
            "",
            "Evidence tiers: "
            + cell(json.dumps(model["evidence_tiers"]["counts"], sort_keys=True))
            + ".",
        ]
    risks = [
        (row, mode, row[mode])
        for row in model["results"]
        for mode in ("planned", "observed")
        if row.get(mode) and row[mode]["outcome"] in {"fail", "error"}
    ]
    lines += ["", f"Failures/errors: {len(risks)}. Up to ten priority findings:", ""]
    for row, mode, body in risks[:10]:
        lines.append(
            f"- {cell(row['upstream_id'])} {cell(row.get('severity', 'Unknown'))} "
            f"({mode}): {cell(row['recommendation'])} [{body['outcome']}]."
        )
    if not risks:
        lines.append(
            "No assessed failures/errors recorded. This does not resolve unknown or manual work."
        )
    if "catalog_status" in model:
        lines += ["", cell(model["catalog_status"]["warning"])]
    lines += [
        "",
        "Signals are not passes. Exceptions do not rewrite technical results. "
        "Findings are advisory; this is not estate-wide compliance.",
    ]
    return "\n".join(lines) + "\n"
