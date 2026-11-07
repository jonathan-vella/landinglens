"""Reproduce the offline, scope-bound assessment and report package."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from alz_assessor.arm import arm_source
from alz_assessor.catalog import load_catalog
from alz_assessor.engine import assess

ROOT = Path(__file__).resolve().parents[3]
EXAMPLE = Path(__file__).resolve().parent
FIXTURES = ROOT / "tests" / "fixtures" / "multiregion-alz"
SCENARIOS = ("baseline", "defective", "remediated")
SURFACES = ("governance", "management", "connectivity", "workloads")


def run(command: list[str]) -> None:
    subprocess.run(command, cwd=ROOT, check=True)


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def render_summary(reports: dict[str, dict[str, dict[str, Path]]], scopes: dict[str, str]) -> str:
    lines = [
        "# Fictional offline ALZ assessment",
        "",
        "Planned configuration only. No Azure deployment, live collection, or",
        "operational assurance is represented. Each scope is assessed separately;",
        "resource-result counts are not compliance percentages.",
        "",
        "## Scope mapping",
        "",
        "| Assessment | Fictional scope |",
        "|---|---|",
    ]
    lines.extend(f"| {name} | `{scope}` |" for name, scope in scopes.items())
    lines.extend(
        [
            "",
            "## Assessment counts",
            "",
            "Counts below are per saved assessment. A recommendation can have",
            "multiple resource-result rows; the reports retain all 255 recommendations.",
            "",
            "| Scenario | Scope | Recommendations | Result rows | Resources | "
            "Pass | Fail | Manual | Unknown | Not applicable |",
            "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for scenario in SCENARIOS:
        for surface in SURFACES:
            assessment = read_json(reports[scenario][surface]["assessment"])
            counts = Counter(row["planned"]["outcome"] for row in assessment["results"])
            coverage = assessment["coverage"]
            lines.append(
                "| "
                + " | ".join(
                    [
                        scenario,
                        surface,
                        str(len({row["control_id"] for row in assessment["results"]})),
                        str(coverage["result_instances"]),
                        str(coverage["resource_instances"]),
                        str(counts["pass"]),
                        str(counts["fail"]),
                        str(counts["manual"]),
                        str(counts["unknown"]),
                        str(counts["not_applicable"]),
                    ]
                )
                + " |"
            )
    lines.extend(
        [
            "",
            "## Controlled changes and remediation",
            "",
            "The defective case sets both regional firewalls to `Off`, disables the",
            "selected Sweden hub/spoke peerings, and changes workspace retention from",
            "90 to 30 days. D07.06 and D01.13 are the supported configuration checks;",
            "the retention difference is reported as a fact because no owner-approved",
            "retention threshold is supplied.",
            "",
            "| Control | Scope | Baseline | Defective | Remediated |",
            "|---|---|---|---|---|",
        ]
    )
    for control_id, surfaces in (
        ("D07.06", ("connectivity",)),
        ("D01.13", ("connectivity", "workloads")),
    ):
        for surface in surfaces:
            values = []
            for scenario in SCENARIOS:
                assessment = read_json(reports[scenario][surface]["assessment"])
                outcomes = Counter(
                    row["planned"]["outcome"]
                    for row in assessment["results"]
                    if row["upstream_id"] == control_id
                )
                values.append(
                    ", ".join(f"{key}: {value}" for key, value in sorted(outcomes.items()))
                    or "no applicable rows"
                )
            lines.append(f"| {control_id} | {surface} | {values[0]} | {values[1]} | {values[2]} |")
    lines.extend(
        [
            "",
            "## Limitations",
            "",
            "- Unsupported local-network-gateway properties remain unknown; secure VPN",
            "  shared keys are intentionally absent.",
            "- Declared routes, peerings, gateways, and firewall settings do not prove",
            "  effective routing, tunnel health, enforcement, failover, or log ingestion.",
            "- Manual and unknown results remain visible; no reviewer decision is",
            "  fabricated and no cross-subscription composition is attempted.",
            "",
        ]
    )
    return "\n".join(lines)


def build_package(output: Path) -> None:
    if output.exists():
        raise ValueError(f"Output directory already exists: {output}")
    scopes = read_json(EXAMPLE / "scope-map.json")["scopes"]
    catalog = load_catalog()
    if len(set(scopes.values())) != 4:
        raise ValueError("Scope map must contain four distinct fictional scopes")
    output.mkdir(parents=True)
    reports: dict[str, dict[str, dict[str, Path]]] = {}
    manifest: dict[str, Any] = {
        "kind": "fictional-offline-alz-report-package",
        "scopes": scopes,
        "scenarios": {},
        "fictional": True,
        "live_collection": False,
        "azure_deployment": False,
    }

    for scenario in SCENARIOS:
        scenario_dir = output / scenario
        scenario_dir.mkdir()
        reports[scenario] = {}
        explorer_args = [
            sys.executable,
            str(ROOT / "tools" / "build_report_canvas.py"),
        ]
        manifest["scenarios"][scenario] = {}
        for surface in SURFACES:
            stem = f"{surface}"
            evidence_path = scenario_dir / f"{stem}.evidence.json"
            assessment_path = scenario_dir / f"{stem}.assessment.json"
            parameter_path = EXAMPLE / "scenarios" / scenario / f"{stem}.parameters.json"
            bundle = arm_source(
                FIXTURES / f"{surface}.json",
                scope=scopes[surface],
                parameters=parameter_path if surface != "governance" else None,
            )
            evidence_path.write_text(
                json.dumps(bundle, indent=2) + "\n", encoding="utf-8", newline="\n"
            )
            assessment = assess(
                bundle,
                catalog,
                landing_zone="platform",
                at=bundle["collected_at"],
                evidence_tiers=True,
            )
            assessment_path.write_text(
                json.dumps(assessment, indent=2) + "\n", encoding="utf-8", newline="\n"
            )
            outputs = {"evidence": evidence_path, "assessment": assessment_path}
            for report_format, suffix in (
                ("html", "html"),
                ("markdown", "md"),
                ("json", "json"),
                ("xlsx", "xlsx"),
            ):
                report_path = scenario_dir / f"{stem}.{suffix}"
                run(
                    [
                        sys.executable,
                        "-m",
                        "alz_assessor.cli",
                        "render",
                        str(assessment_path),
                        "--format",
                        report_format,
                        "--minimize",
                        "--output",
                        str(report_path),
                    ]
                )
                outputs[report_format] = report_path
            reports[scenario][surface] = outputs
            explorer_args.extend(
                ["--report", f"{scenario.title()} {surface.title()}", str(assessment_path)]
            )
            manifest["scenarios"][scenario][surface] = {
                name: {"path": str(path.relative_to(output)), "sha256": digest(path)}
                for name, path in outputs.items()
            }
        explorer_dir = scenario_dir / "explorer"
        run(explorer_args + ["--fictional", "--output-directory", str(explorer_dir)])
        manifest["scenarios"][scenario]["explorer"] = {
            "path": str((explorer_dir / "index.html").relative_to(output)),
            "sha256": digest(explorer_dir / "index.html"),
            "reports": list(SURFACES),
        }

    summary = output / "assessment-summary.md"
    summary.write_text(render_summary(reports, scopes), encoding="utf-8", newline="\n")
    links = "\n".join(
        f'<li><a href="{html.escape(name)}/explorer/index.html">'
        f"{html.escape(name.title())} scenario</a></li>"
        for name in SCENARIOS
    )
    (output / "index.html").write_text(
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        "<title>Fictional offline ALZ report package</title>"
        "<h1>Fictional offline ALZ assessment</h1>"
        "<p>Planned configuration only. No Azure deployment or live collection.</p>"
        f'<ul>{links}</ul><p><a href="assessment-summary.md">Assessment summary</a></p>'
        "</html>\n",
        encoding="utf-8",
        newline="\n",
    )
    manifest["summary"] = {
        "path": "assessment-summary.md",
        "sha256": digest(summary),
    }
    manifest_path = output / "package-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"Report package written to {output.resolve()}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    try:
        build_package(args.output_directory.resolve())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(2, f"Report package failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
