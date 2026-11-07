"""Build a portable, read-only Browser canvas from saved planned assessments."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from alz_assessor.contracts import parse_document, validate
from alz_assessor.priorities import sort_key
from alz_assessor.reports import render, report_model
from alz_assessor.terraform import InputError


def build_preview(
    reports: list[tuple[str, Path]], output: Path, *, fictional: bool = False
) -> Path:
    if not 1 <= len(reports) <= 8:
        raise InputError("Supply between one and eight saved planned reports")
    labels = [label.strip() for label, _ in reports]
    if any(not label or len(label) > 80 for label in labels) or len(
        {label.casefold() for label in labels}
    ) != len(labels):
        raise InputError("Report labels must be nonempty, unique and at most 80 characters")
    if output.exists():
        raise InputError("Use a new output directory; existing files are never overwritten")
    data: dict[str, Any] = {"readOnly": True, "fictional": fictional, "reports": {}}
    full_reports: dict[str, str] = {}
    sources = []
    for index, ((_, path), label) in enumerate(zip(reports, labels, strict=True), 1):
        with path.open("rb") as stream:
            raw = stream.read(8_000_001)
        if len(raw) > 8_000_000:
            raise InputError("Saved assessment exceeds the 8 MB preview input limit")
        original = validate(parse_document(raw), "assessment")
        sources.append({"label": label, "sha256": hashlib.sha256(raw).hexdigest()})
        if original.get("presentation_only"):
            raise InputError("Use a saved assessment, not a minimized presentation")
        evidence = original.get("evidence", [])
        if not evidence:
            raise InputError("Saved assessment requires at least one evidence bundle")
        resource_count: int | None = 0
        for bundle in evidence:
            if "resources" not in bundle:
                resource_count = None
            elif not isinstance(bundle["resources"], list):
                raise InputError("Assessment evidence resources must be an array when present")
            elif resource_count is not None:
                resource_count += len(bundle["resources"])
        model = report_model(original, minimize=True)
        rows = []
        for row in sorted(model["results"], key=sort_key):
            kept = {
                key: row.get(key)
                for key in (
                    "control_id",
                    "upstream_id",
                    "recommendation",
                    "design_area",
                    "automation",
                    "severity",
                    "logical_id",
                    "rationale",
                    "evidence_requirements",
                    "planned",
                    "observed",
                    "comparison",
                    "comparison_reason",
                )
            }
            body_data = row.get("planned") or row.get("observed") or {}
            reviews_list = body_data.get("reviews") or []
            active_review = next(
                (r for r in reviews_list if not r.get("requires_review")),
                reviews_list[0] if reviews_list else None,
            )
            kept["review_status"] = {
                "recorded": bool(reviews_list),
                "active": bool(active_review and not active_review.get("requires_review")),
                "kind": active_review.get("kind") if active_review else None,
                "decision": (
                    active_review.get("decision")
                    or (
                        body_data.get("exception_disposition")
                        if active_review.get("kind") == "exceptions"
                        else (
                            body_data.get("outcome")
                            if body_data.get("reason") == "manual_attestation"
                            else None
                        )
                    )
                )
                if active_review
                else None,
            }
            references = []
            seen = set()
            for reference in row["references"]:
                url = reference.get("guidance") or reference.get("source_url")
                if not isinstance(url, str):
                    continue
                parsed = urlsplit(url)
                if (
                    parsed.scheme not in {"https", "http"}
                    or not parsed.netloc
                    or parsed.username
                    or url in seen
                ):
                    continue
                seen.add(url)
                references.append({"url": url, "label": parsed.netloc + parsed.path})
            kept["references"] = references
            rows.append(kept)
        mode_summary = (
            "comparison"
            if any(row.get("comparison") is not None for row in rows)
            else "observed"
            if all(bundle.get("mode") == "observed" for bundle in evidence)
            else "planned"
        )
        identifier = f"report-{index}"
        full_reports[identifier + ".html"] = render(original, "html", minimize=True)
        data["reports"][identifier] = {
            "label": label,
            "modeSummary": mode_summary,
            "rows": rows,
            "coverage": model["coverage"],
            "declaredResources": resource_count,
            "generatedAt": model["generated_at"],
            "catalogVersion": model["catalog_version"],
            "fullReport": identifier + ".html",
            "presentation": model,
        }
    payload = (
        json.dumps(data, ensure_ascii=True)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )
    template = Path(__file__).with_name("report_canvas.html").read_text(encoding="utf-8")
    if template.count("__REPORT_DATA__") != 1:
        raise InputError("Report canvas template requires exactly one data marker")
    page = template.replace("__REPORT_DATA__", payload)
    output.mkdir(parents=True)
    for name, content in {"index.html": page, **full_reports}.items():
        with (output / name).open("x", encoding="utf-8", newline="") as stream:
            stream.write(content)
    (output / "provenance.json").write_text(
        json.dumps(
            {
                "kind": "read-only-report-preview",
                "presentation_only": True,
                "new_evaluator": False,
                "fictional_inputs": fictional,
                "sources": sources,
                "html_sha256": hashlib.sha256((output / "index.html").read_bytes()).hexdigest(),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return output / "index.html"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--report",
        nargs=2,
        action="append",
        required=True,
        metavar=("LABEL", "ASSESSMENT_JSON"),
    )
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument(
        "--fictional", action="store_true", help="Label supplied inputs as fictional"
    )
    args = parser.parse_args()
    try:
        page = build_preview(
            [(label, Path(path)) for label, path in args.report],
            args.output_directory,
            fictional=args.fictional,
        )
    except (InputError, OSError) as error:
        parser.exit(2, f"Preview build failed: {error}\n")
    print(f"Open {page.resolve()} in the Browser canvas or your browser")


if __name__ == "__main__":
    main()
