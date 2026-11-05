"""Accessible static views over the shared sanitized model; no browser evaluator."""

import html
import json
from typing import Any
from urllib.parse import urlsplit

from .priorities import sort_key
from .tiers import LABELS

THEME_SCRIPT = """
(() => {
  const param = new URLSearchParams(window.location.search).get("scoutTheme");
  const theme =
    param || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  document.documentElement.setAttribute("data-theme", theme);
})();
"""
STYLE = """
:root {
  color-scheme: light;
  --cp-bg: #f7f4ef;
  --cp-bg-elevated: #fcfbf8;
  --cp-surface: #ffffff;
  --cp-surface-soft: #f5f5f5;
  --cp-border: #dedede;
  --cp-border-strong: #919191;
  --cp-text: #242424;
  --cp-text-muted: #5c5c5c;
  --cp-text-soft: #6f6f6f;
  --cp-accent: #b11f4b;
  --cp-accent-hover: #9a1a41;
  --cp-accent-soft: rgba(177, 31, 75, 0.08);
  --cp-accent-fg: #ffffff;
  --cp-success: #16a34a;
  --cp-danger: #dc2626;
  --cp-warning: #f59e0b;
  --cp-link: #0078d4;
  --cp-shadow: 0 18px 48px rgba(0, 0, 0, 0.12);
  --cp-overlay: rgba(255, 255, 255, 0.8);
  --cp-panel: rgba(255, 255, 255, 0.86);
  --cp-panel-strong: rgba(255, 255, 255, 0.96);
  --cp-sheen: rgba(255, 255, 255, 0.55);
  --cp-highlight: rgba(177, 31, 75, 0.12);
}
html[data-theme="dark"] {
  color-scheme: dark;
  --cp-bg: #3d3b3a;
  --cp-bg-elevated: #343231;
  --cp-surface: #292929;
  --cp-surface-soft: #2e2e2e;
  --cp-border: #474747;
  --cp-border-strong: #5f5f5f;
  --cp-text: #dedede;
  --cp-text-muted: #919191;
  --cp-text-soft: #b0b0b0;
  --cp-accent: #fd8ea1;
  --cp-accent-hover: #fb7b91;
  --cp-accent-soft: rgba(253, 142, 161, 0.14);
  --cp-accent-fg: #1a1a1a;
  --cp-success: #4ade80;
  --cp-danger: #f87171;
  --cp-warning: #fbbf24;
  --cp-link: #4da6ff;
  --cp-shadow: 0 18px 48px rgba(0, 0, 0, 0.32);
  --cp-overlay: rgba(41, 41, 41, 0.88);
  --cp-panel: rgba(41, 41, 41, 0.72);
  --cp-panel-strong: rgba(41, 41, 41, 0.96);
  --cp-sheen: rgba(255, 255, 255, 0.04);
  --cp-highlight: rgba(253, 142, 161, 0.12);
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--cp-bg); color: var(--cp-text);
  font: 16px/1.6 "Segoe UI", Aptos, Calibri, -apple-system, BlinkMacSystemFont, sans-serif; }
main, header { max-width: 1200px; margin: auto; padding: 24px; }
h1, h2, h3 { line-height: 1.25; } h1 { margin-bottom: 8px; }
a { color: var(--cp-link); } :focus-visible { outline: 3px solid var(--cp-accent); }
.skip { position: absolute; left: -10000px; } .skip:focus { left: 16px; }
.muted { color: var(--cp-text-muted); } .notice { border-left: 4px solid var(--cp-accent); }
.cards { display: grid; grid-template-columns: repeat(auto-fit,minmax(180px,1fr)); gap: 16px; }
.card, .finding, .notice { background: var(--cp-surface); border: 1px solid var(--cp-border);
  border-radius: 16px; padding: 16px; margin-bottom: 16px; overflow-wrap: anywhere; }
.card strong { display: block; font-size: 1.8rem; }
nav ul { display: flex; flex-wrap: wrap; gap: 8px 24px; padding-left: 24px; }
label { display: inline-block; margin: 8px 16px 8px 0; }
input, select, button { font: inherit; padding: 8px; border-radius: .625rem;
  border: 1px solid var(--cp-border-strong); color: var(--cp-text);
  background: var(--cp-surface); max-width: min(32rem, calc(100vw - 64px)); }
button { cursor: pointer; } button:hover { border-color: var(--cp-accent); }
summary { cursor: pointer; font-weight: 600; } dt { font-weight: 600; margin-top: 8px; }
dd { margin-left: 16px; } code, pre { font-family: Consolas, "Courier New", Courier, monospace; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; font-size: .9rem; }
.status { display: inline-block; padding: 0 8px; border: 1px solid var(--cp-border);
  border-radius: .625rem; margin: 4px; background: var(--cp-surface-soft); }
.pass { color: var(--cp-success); } .fail, .error { color: var(--cp-danger); }
.mode { padding-left: 16px; border-left: 2px solid var(--cp-border); margin: 16px 0; }
@media print {
  html, html[data-theme="dark"] { color-scheme: light; }
  body { background: var(--cp-surface); color: var(--cp-text); font-size: 10pt; }
  .filters, .skip, button { display: none !important; }
  main, header { max-width: none; padding: 8px; }
  .finding { break-inside: avoid; border-radius: 0; }
  .finding[hidden] { display: block; }
  a { color: inherit; text-decoration: underline; }
}
"""
FILTER_SCRIPT = """
const rows = [...document.querySelectorAll(".finding")];
const search = document.getElementById("search");
const area = document.getElementById("area");
const status = document.getElementById("status");
function filter() {
  const query = search.value.toLocaleLowerCase();
  for (const row of rows) {
    row.hidden = !(row.textContent.toLocaleLowerCase().includes(query)
      && (!area.value || row.dataset.area === area.value)
      && (!status.value || row.dataset.status.split(" ").includes(status.value)));
  }
  document.getElementById("shown").textContent =
    `${rows.filter(row => !row.hidden).length} of ${rows.length} result instances shown`;
}
for (const input of [search, area, status]) input.addEventListener("input", filter);
document.getElementById("expand").addEventListener("click", () => {
  for (const row of rows) row.querySelector("details").open = true;
});
document.getElementById("collapse").addEventListener("click", () => {
  for (const row of rows) row.querySelector("details").open = false;
});
document.querySelector(".filters").hidden = false;
let beforePrint = [];
let printTheme = null;
window.addEventListener("beforeprint", () => {
  printTheme = document.documentElement.getAttribute("data-theme");
  document.documentElement.setAttribute("data-theme", "light");
  beforePrint = rows.map(row => row.querySelector("details").open);
  for (const row of rows) row.querySelector("details").open = true;
});
window.addEventListener("afterprint", () => {
  if (printTheme === null) document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", printTheme);
  rows.forEach((row, i) => { row.querySelector("details").open = beforePrint[i]; });
});
"""


def escaped(value: Any) -> str:
    return html.escape(str(value), quote=True)


def link(value: Any) -> str:
    if not isinstance(value, str):
        return escaped(value)
    try:
        parsed = urlsplit(value)
        safe = parsed.scheme == "https" and bool(parsed.hostname) and not parsed.username
    except ValueError:
        safe = False
    return (
        f'<a href="{escaped(value)}" rel="noreferrer noopener">{escaped(value)}</a>'
        if safe
        else escaped(value)
    )


def fields(values: dict[str, Any]) -> str:
    return (
        "<dl>"
        + "".join(
            f"<dt>{escaped(key)}</dt><dd>{escaped(value)}</dd>" for key, value in values.items()
        )
        + "</dl>"
    )


def render_html(model: dict[str, Any]) -> str:
    coverage = model["coverage"]
    areas = sorted({r["design_area"] for r in model["results"]})
    area_ids = {name: str(i) for i, name in enumerate(areas)}
    automated = coverage.get(
        "automated_controls",
        len({r["control_id"] for r in model["results"] if r.get("automation") == "automated"}),
    )
    parts = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<meta name="referrer" content="no-referrer">',
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        "style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
        "connect-src 'none'; img-src 'none'; base-uri 'none'; form-action 'none'\">",
        "<title>LandingLens advisory assessment</title>",
        '<script type="text/javascript">'
        + THEME_SCRIPT
        + "</script><style>"
        + STYLE
        + "</style></head><body>",
        '<a class="skip" href="#findings">Skip to findings</a><header>',
        "<h1>LandingLens advisory assessment</h1>",
        fields({"Catalog": model["catalog_version"], "Evaluation time": model["generated_at"]}),
        '<p class="notice">Advisory configuration evidence, not certification or '
        "estate-wide compliance. Policy assignments do not prove effectiveness.</p>",
    ]
    if model.get("presentation_only"):
        parts.append(
            '<p class="notice">Minimized presentation only: not comparable or replayable.</p>'
        )
    if "applicability_suggestions" in model:
        parts.append(
            "<details><summary>Applicability suggestions: "
            "reviewer confirmation required</summary><pre>"
            + escaped(json.dumps(model["applicability_suggestions"], indent=2))
            + "</pre></details>"
        )
    if "policy_signals" in model:
        parts.append(
            "<details><summary>Policy Signals: not checklist outcomes</summary><pre>"
            + escaped(json.dumps(model["policy_signals"], indent=2))
            + "</pre></details>"
        )
    if "scanner_signals" in model:
        parts.append(
            "<details><summary>Scanner Signals: not checklist outcomes</summary><pre>"
            + escaped(json.dumps(model["scanner_signals"], indent=2))
            + "</pre></details>"
        )
    if "scanner_signal_runs" in model:
        parts.append(
            "<details><summary>Separate planned and observed scanner Signals</summary><pre>"
            + escaped(json.dumps(model["scanner_signal_runs"], indent=2))
            + "</pre></details>"
        )
    parts += [
        '</header><main><section aria-labelledby="summary"><h2 id="summary">Summary</h2>',
        '<div class="cards">',
    ]
    for label, value in (
        ("Active controls", coverage.get("controls")),
        ("Automated controls", automated),
        ("Resource instances", coverage.get("resource_instances")),
        ("Result instances", coverage.get("result_instances")),
        ("Retired controls", len(model.get("retired_controls", []))),
        (
            "Inventory visibility",
            "complete (producer assertion)"
            if coverage.get("inventory_complete")
            else "incomplete / unverified",
        ),
    ):
        parts.append(f'<div class="card"><strong>{escaped(value)}</strong>{label}</div>')
    parts.append("</div>")
    if "evidence_tiers" in model:
        parts.append('<h3>Evidence tiers</h3><div class="cards">')
        for tier, value in model["evidence_tiers"]["counts"].items():
            parts.append(f'<div class="card"><strong>{escaped(value)}</strong>{LABELS[tier]}</div>')
        parts.append(
            "</div><p>Verified includes technical failures. Signals are not passes. "
            "Counts are once per control across targets and modes; manual stays separate.</p>"
        )
    parts.append(
        "<details><summary>Shared coverage model and denominators</summary><pre>"
        + escaped(json.dumps(coverage, sort_keys=True))
        + "</pre></details>"
    )
    for mode, metrics in coverage.get("modes", {}).items():
        parts.append(f"<h3>{escaped(mode.title())} evidence</h3>")
        values = {}
        for key in ("completion", "subset_pass_rate"):
            value = metrics.get(key)
            values[key] = "unavailable" if value is None else f"{100 * value:.1f}%"
        parts.append(
            fields(
                {
                    **values,
                    "Assessed instances": metrics.get("assessed"),
                    "Known applicable denominator": metrics.get("known_applicable"),
                    "Outcomes": json.dumps(metrics.get("outcomes", {}), sort_keys=True),
                }
            )
        )
    parts += [
        "<p>Completion and pass rate describe result instances, not all estate controls. "
        "Freshness and authorization completeness are independent.</p></section>",
        '<nav aria-label="Design areas"><h2>Design areas</h2><ul>',
    ]
    for area in areas:
        parts.append(f'<li><a href="#area-{area_ids[area]}">{escaped(area)}</a></li>')
    parts += [
        '</ul></nav><section id="findings" aria-labelledby="findings-title">',
        '<h2 id="findings-title">Findings and control details</h2>',
        '<div class="filters" hidden><label for="search">Search findings '
        '<input id="search" type="search"></label><label for="area">Design area '
        '<select id="area"><option value="">All areas</option>',
    ]
    for area in areas:
        parts.append(f'<option value="{area_ids[area]}">{escaped(area)}</option>')
    parts += [
        '</select></label><label for="status">Outcome <select id="status">'
        '<option value="">All outcomes</option>'
    ]
    for status in ("pass", "fail", "unknown", "error", "manual", "not_applicable"):
        parts.append(f'<option value="{status}">{status}</option>')
    parts += [
        '</select></label><button id="expand" type="button">Expand all</button> '
        '<button id="collapse" type="button">Collapse all</button></div>',
        f'<p id="shown" role="status" aria-live="polite">{len(model["results"])} '
        "result instances; all shown without JavaScript</p>",
    ]
    seen_areas = set()
    for row in sorted(
        model["results"],
        key=sort_key,
    ):
        area = row["design_area"]
        if area not in seen_areas:
            seen_areas.add(area)
            parts.append(f'<h3 id="area-{area_ids[area]}">{escaped(area)}</h3>')
        statuses = [row[m]["outcome"] for m in ("planned", "observed") if row.get(m)]
        parts.append(
            f'<article class="finding" data-area="{area_ids[area]}" '
            f'data-status="{escaped(" ".join(statuses))}"><details open><summary>'
            f"{escaped(row['upstream_id'])}: {escaped(row['recommendation'])}"
            "</summary>"
        )
        parts.append(
            fields(
                {
                    "Control ID": row["control_id"],
                    "Target": row.get("arm_id") or row["logical_id"],
                    "Automation": row.get("automation"),
                    **({"Severity": row["severity"]} if "severity" in row else {}),
                    "Applicability": "/".join(row["applicability"]),
                    "Comparison": row.get("comparison"),
                    "Comparison reason": row.get("comparison_reason"),
                }
            )
        )
        for mode in ("planned", "observed"):
            body = row.get(mode)
            if not body:
                continue
            parts.append(
                f'<section class="mode"><h4>{mode.title()}: '
                f'<span class="status {escaped(body["outcome"])}">'
                f"{escaped(body['outcome'])}</span></h4>"
            )
            parts.append(
                fields(
                    {
                        "Reason": body["reason"],
                        "Freshness": body["freshness"],
                        "Fact": body.get("fact"),
                        "Method": body.get("method"),
                        "Confidence": body.get("confidence"),
                        **(
                            {"Evidence tier": LABELS[body["evidence_tier"]]}
                            if "evidence_tier" in body
                            else {}
                        ),
                        "Exception disposition": body.get("exception_disposition"),
                        "Review validity": json.dumps(
                            body.get("disposition_validity"), sort_keys=True
                        ),
                        **body.get("guidance", {}),
                    }
                )
            )
            parts.append(
                "<h5>Evidence links</h5><ul>"
                + "".join("<li>" + link(value) + "</li>" for value in body["evidence_links"])
                + "</ul>"
            )
            parts.append(
                "<h5>Human review ownership and status</h5><pre>"
                + escaped(json.dumps(body.get("reviews", []), indent=2))
                + "</pre></section>"
            )
        parts.append(
            "<h4>Rule transparency and guidance</h4>"
            + fields(
                {
                    "Rationale": row.get("rationale"),
                    "Evidence requirements": json.dumps(
                        row.get("evidence_requirements"), sort_keys=True
                    ),
                    "Flags": json.dumps(row.get("flags"), sort_keys=True),
                    "Control hash": row.get("control_sha256"),
                    "Rule hash": row.get("rule_sha256"),
                }
            )
        )
        parts.append(
            "<ul>"
            + "".join(
                "<li>"
                + link(ref.get("guidance") or ref.get("source_url"))
                + "<pre>"
                + escaped(json.dumps(ref, sort_keys=True))
                + "</pre></li>"
                if isinstance(ref, dict)
                else "<li>" + escaped(ref) + "</li>"
                for ref in row.get("references", [])
            )
            + "</ul></details></article>"
        )
    parts.append("</section><section><h2>Retired / historical controls</h2>")
    for retired in model.get("retired_controls", []):
        parts.append(fields(retired))
    parts.append('</section><section id="provenance"><h2>Provenance and collection visibility</h2>')
    for bundle in model["evidence"]:
        parts.append("<pre>" + escaped(json.dumps(bundle, indent=2, sort_keys=True)) + "</pre>")
    parts.append(
        '</section></main><script type="text/javascript">'
        + FILTER_SCRIPT
        + "</script></body></html>"
    )
    return "".join(parts)
