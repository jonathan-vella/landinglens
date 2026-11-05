"""A local review form; Python owns validation, evaluation and persistence."""

import html
import json
from typing import Any

from .contracts import OUTCOMES
from .html_report import STYLE, THEME_SCRIPT

SCRIPT = """
let state = JSON.parse(document.getElementById("state").textContent);
const token = document.getElementById("capability").textContent;
const form = document.getElementById("review");
const control = document.getElementById("control");
const kind = document.getElementById("kind");
const decision = document.getElementById("decision");
const status = document.getElementById("message");
const fields = ["reviewer", "evidence", "rationale", "valid_from", "valid_until"];
const outcomes = JSON.parse(document.getElementById("outcomes").textContent);
function options(element, entries, blank = false) {
  element.replaceChildren();
  if (blank) entries = [["", "Choose a decision"], ...entries];
  for (const [value, label] of entries) {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = label;
    element.append(option);
  }
}
function localTime(value) {
  const date = new Date(value);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000)
    .toISOString().slice(0, 19);
}
function currentRecord() {
  return state.records.find(r => r.control_id === control.value && r.kind === kind.value);
}
function showRecord() {
  const row = state.controls.find(c => c.control_id === control.value);
  document.getElementById("technical").textContent =
    row ? `Original technical outcomes: ${row.results.join(", ")}` : "No unresolved controls.";
  const preparation = document.getElementById("preparation");
  preparation.replaceChildren();
  for (const text of (row ? [...row.evidence_requirements, row.limitations] : [])) {
    const item = document.createElement("li");
    item.textContent = text;
    preparation.appendChild(item);
  }
  document.getElementById("available-evidence").textContent =
    row ? JSON.stringify(row.available_evidence, null, 2) : "";
  options(decision, (kind.value === "exceptions"
    ? ["accepted", "rejected", "pending"] : outcomes).map(v => [v, v]), true);
  const record = currentRecord();
  for (const field of fields) {
    document.getElementById(field).value = record
      ? (field.startsWith("valid_") ? localTime(record[field]) : record[field])
      : (field === "valid_from" ? localTime(new Date()) : "");
  }
  decision.value = record ? record.decision : "";
  document.getElementById("replacement").hidden = !record;
  document.getElementById("replace_existing").checked = false;
  document.getElementById("record-status").textContent = record
    ? (record.requires_review ? "Existing review requires renewal or a changed-content review."
      : "Existing review is active. Saving a replacement requires explicit confirmation.")
    : "No saved review for this control and kind. All decisions are yours to supply.";
}
function selectControl() {
  const row = state.controls.find(c => c.control_id === control.value);
  options(kind, (row ? row.kinds : []).map(k => [
    k, k === "manual" ? "Manual evidence decision" : "Exception (technical result unchanged)"
  ]));
  showRecord();
}
function updateSummary() {
  const needsReview = state.records.filter(r => r.requires_review).length;
  document.getElementById("summary").textContent =
    `Revision ${state.revision}; ${state.records.length} saved review records; ` +
    `${needsReview} need renewal/content review. Evaluated at ${state.evaluated_at}. ` +
    (state.effort_remaining
      ? `Estimated remaining effort: ${state.effort_remaining.minutes} minutes. ` +
        state.effort_remaining.assumption : "");
  refreshWorkspace();
}
async function post(route, payload) {
  const response = await fetch(route, {
    method: "POST",
    headers: {"Content-Type": "application/json", "X-LandingLens-Review": token},
    body: JSON.stringify(payload)
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "Local review request failed.");
  return result;
}
control.addEventListener("change", selectControl);
kind.addEventListener("change", showRecord);
for (const button of document.querySelectorAll("[data-days]")) {
  button.addEventListener("click", () => {
    const from = document.getElementById("valid_from");
    if (!from.value) from.value = localTime(new Date());
    document.getElementById("valid_until").value =
      localTime(new Date(new Date(from.value).getTime() + Number(button.dataset.days) * 86400000));
  });
}
form.addEventListener("submit", async event => {
  event.preventDefault();
  const save = document.getElementById("save");
  save.disabled = true;
  try {
    const payload = {
      revision: state.revision, control_id: control.value, kind: kind.value,
      decision: decision.value,
      replace_existing: document.getElementById("replace_existing").checked
    };
    for (const field of fields) {
      const value = document.getElementById(field).value;
      payload[field] = field.startsWith("valid_") ? new Date(value).toISOString() : value;
    }
    state = await post("save", payload);
    updateSummary();
    showRecord();
    document.getElementById("report").src = `report?revision=${state.revision}`;
    status.textContent = `Saved revision ${state.revision}. Reviews and all report formats ` +
      "were written locally; the report below is refreshed. No Azure changes.";
  } catch (error) {
    status.textContent = `Not saved: ${error.message} Your previous revision is unchanged.`;
  } finally {
    save.disabled = !control.value;
  }
});
document.getElementById("stop").addEventListener("click", async () => {
  try {
    await post("stop", {});
    for (const element of document.querySelectorAll("input,select,textarea,button")) {
      element.disabled = true;
    }
    status.textContent = "Local listener stopped. Saved revision files remain on disk.";
  } catch (error) {
    status.textContent = `Could not stop the listener: ${error.message}`;
  }
});
options(control, state.controls.map(c => [c.control_id, c.label]));
selectControl();
updateSummary();
if (!state.controls.length) document.getElementById("save").disabled = true;
"""

WORKSPACE_SCRIPT = """
function refreshWorkspace() {
  const areas = document.getElementById("area-progress");
  areas.replaceChildren();
  for (const area of state.areas || []) {
    const item = document.createElement("li");
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = `${area.name}: ${area.remaining} remaining / ${area.total} controls`;
    button.addEventListener("click", () => {
      document.getElementById("area-filter").value = area.name;
      refreshWorkspace();
    });
    item.append(button); areas.append(item);
  }
  const oldArea = document.getElementById("area-filter").value;
  options(document.getElementById("area-filter"),
    [["", "All areas"], ...(state.areas || []).map(a => [a.name, a.name])]);
  document.getElementById("area-filter").value = oldArea;
  const query = document.getElementById("queue-search").value.toLocaleLowerCase();
  const visible = state.controls.filter(row =>
    (!document.getElementById("only-needs").checked || state.needs_me.includes(row.control_id)) &&
    (!oldArea || row.design_area === oldArea) &&
    (!document.getElementById("tier-filter").value ||
      row.tier === document.getElementById("tier-filter").value) &&
    (!document.getElementById("severity-filter").value ||
      row.severity === document.getElementById("severity-filter").value) &&
    row.label.toLocaleLowerCase().includes(query));
  const previous = control.value;
  options(control, visible.map(row => [
    row.control_id, `${row.severity || "Unknown"} | ${row.tier} | ${row.label}`
  ]));
  if (visible.some(row => row.control_id === previous)) control.value = previous;
  else if (visible.length) control.selectedIndex = 0;
  document.getElementById("queue-count").textContent =
    `${visible.length} shown; ${state.needs_me.length} controls need a decision.`;
  selectControl();
  document.getElementById("save").disabled = !control.value;
  const bulk = document.getElementById("bulk-options");
  bulk.replaceChildren();
  for (const row of visible.filter(row => row.tier === "signal")) {
    const line = document.createElement("div");
    const label = document.createElement("label");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox"; checkbox.dataset.bulkControl = row.control_id;
    label.append(checkbox, document.createTextNode(row.label));
    const select = document.createElement("select");
    select.dataset.bulkDecision = row.control_id;
    select.setAttribute("aria-label", `Explicit outcome for ${row.label}`);
    options(select, outcomes.map(value => [value, value]), true);
    line.append(label, select); bulk.append(line);
  }
  const question = document.getElementById("interview-question");
  const oldQuestion = question.value;
  options(question, [["", "Choose a question"],
    ...(state.interviews || []).map(item => [item.id, item.id])]);
  question.value = oldQuestion;
  showInterview();
}
function showInterview() {
  const selected = (state.interviews || []).find(item =>
    item.id === document.getElementById("interview-question").value);
  document.getElementById("interview-question-text").textContent =
    selected ? selected.question : "";
  const decisions = document.getElementById("interview-decisions");
  decisions.replaceChildren();
  for (const item of selected ? selected.template.decisions : []) {
    const row = state.controls.find(control => control.control_id === item.control_id);
    const label = document.createElement("label");
    label.textContent = row ? row.label : item.control_id;
    const select = document.createElement("select");
    select.dataset.interviewDecision = item.control_id;
    select.setAttribute("aria-label", `Explicit interview outcome for ${label.textContent}`);
    options(select, outcomes.map(value => [value, value]), true);
    label.append(select); decisions.append(label);
  }
}
function reviewFields() {
  const values = {};
  for (const field of fields) {
    const value = document.getElementById(field).value;
    values[field] = field.startsWith("valid_") ? new Date(value).toISOString() : value;
  }
  return values;
}
function refreshed(result) {
  state = result;
  updateSummary();
  document.getElementById("report").src = `report?revision=${state.revision}`;
}
document.getElementById("bulk-save").addEventListener("click", async () => {
  try {
    const selected = [...document.querySelectorAll("[data-bulk-control]:checked")];
    if (!selected.length) throw new Error(
      "Select at least one Signal and an explicit outcome for each.");
    const payload = {revision: state.revision, reviews: selected.map(item => {
      const id = item.dataset.bulkControl;
      const decision = [...document.querySelectorAll("[data-bulk-decision]")].find(
        element => element.dataset.bulkDecision === id).value;
      const existing = state.records.some(record =>
        record.control_id === id && record.kind === "manual");
      return {revision: state.revision, control_id: id, kind: "manual", decision,
        replace_existing: existing && document.getElementById("bulk-replace").checked,
        ...reviewFields()};
    })};
    refreshed(await post("save-many", payload));
    status.textContent = `Saved ${selected.length} explicit reviews ` +
      `in revision ${state.revision}. ` +
      "Technical predicates remain independent.";
  } catch (error) {
    status.textContent = `Not saved: ${error.message} Previous revision unchanged.`;
  }
});
document.getElementById("interview-save").addEventListener("click", async () => {
  try {
    const selected = state.interviews.find(item =>
      item.id === document.getElementById("interview-question").value);
    if (!selected) throw new Error("Select an interview question.");
    const response = JSON.parse(JSON.stringify(selected.template));
    Object.assign(response, reviewFields(), {
      answer: document.getElementById("interview-answer").value});
    for (const entry of response.decisions) {
      entry.outcome = [...document.querySelectorAll("[data-interview-decision]")].find(
        element => element.dataset.interviewDecision === entry.control_id).value;
    }
    const replace = document.getElementById("interview-replace").checked
      ? response.decisions.filter(entry => state.records.some(record =>
        record.control_id === entry.control_id &&
        record.kind === "manual")).map(entry => entry.control_id)
      : [];
    refreshed(await post("interview", {
      revision: state.revision, response, replace_existing: replace}));
    status.textContent = `Saved explicit interview decisions in revision ${state.revision}.`;
  } catch (error) {
    status.textContent = `Not saved: ${error.message} Previous revision unchanged.`;
  }
});
for (const id of ["queue-search", "area-filter", "tier-filter", "severity-filter", "only-needs"]) {
  document.getElementById(id).addEventListener("input", refreshWorkspace);
}
document.getElementById("interview-question").addEventListener("change", showInterview);
function moveQueue(delta) {
  if (!control.options.length) return;
  control.selectedIndex = Math.max(0,
    Math.min(control.options.length - 1, control.selectedIndex + delta));
  selectControl(); control.focus();
}
document.getElementById("next-control").addEventListener("click", () => moveQueue(1));
document.getElementById("previous-control").addEventListener("click", () => moveQueue(-1));
document.addEventListener("keydown", event => {
  if (event.altKey && ["ArrowDown", "ArrowUp"].includes(event.key)) {
    event.preventDefault(); moveQueue(event.key === "ArrowDown" ? 1 : -1);
  }
});
"""


def review_page(state: dict[str, Any], token: str, nonce: str) -> str:
    def data(value: Any) -> str:
        return (
            json.dumps(value, ensure_ascii=True, allow_nan=False)
            .replace("&", "\\u0026")
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
        )

    safe_nonce = html.escape(nonce, quote=True)
    styles = (
        STYLE
        + """
textarea { display: block; width: 100%; min-height: 80px; font: inherit; padding: 8px;
  color: var(--cp-text); background: var(--cp-surface);
  border: 1px solid var(--cp-border-strong); border-radius: .625rem; }
form label { display: block; } form input:not([type=checkbox]), select { width: 100%; }
iframe { width: 100%; height: 65vh; border: 1px solid var(--cp-border); border-radius: 16px; }
.workspace-grid { display: grid; gap: 16px;
  grid-template-columns: minmax(160px,1fr) minmax(220px,1.3fr) minmax(320px,2fr); }
.workspace-grid > * { min-width: 0; }
.workspace-grid select, .workspace-grid input { max-width: 100%; }
#area-progress { padding-left: 0; list-style: none; }
#area-progress button { text-align: left; width: 100%; margin-bottom: 8px; }
@media (max-width: 1000px) { .workspace-grid { grid-template-columns: 1fr; } }
.primary { background: var(--cp-accent); color: var(--cp-accent-fg); }
.primary:hover { background: var(--cp-accent-hover); }
"""
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LandingLens local review</title>
<script nonce="{safe_nonce}">{THEME_SCRIPT}</script>
<style nonce="{safe_nonce}">{styles}</style></head>
<body><header><h1>Review workspace</h1>
<p>One save validates your decision, keeps a new revision and regenerates every report.
No Azure calls, uploads or infrastructure changes.</p>
<p class="notice">Private local session. Files retain scope and reviewer identities.
Keep this address and the output directory private. Reviewer labels are assertions,
not authenticated approval signatures. Exceptions do not turn failures into passes.</p>
<p>Bound scope: <code>{html.escape(state["scope"])}</code></p>
<p id="summary"></p></header><main>
<noscript>This local editor needs JavaScript. The CLI review prepare/validate workflow
and saved reports remain available without JavaScript.</noscript>
<div class="workspace-grid">
<aside class="card" aria-label="Design-area progress"><h2>Design areas</h2>
<ul id="area-progress"></ul></aside>
<section class="card" aria-labelledby="needs-title"><h2 id="needs-title">Needs me</h2>
<label for="queue-search">Search</label><input id="queue-search" type="search">
<label for="area-filter">Area</label><select id="area-filter"></select>
<label for="tier-filter">Evidence tier</label><select id="tier-filter">
<option value="">All tiers</option><option value="verified">Verified</option>
<option value="signal">Signal</option><option value="needs_decision">Needs decision</option>
<option value="manual">Manual</option></select>
<label for="severity-filter">Severity</label><select id="severity-filter">
<option value="">All severities</option><option>High</option><option>Medium</option>
<option>Low</option><option>Unknown</option></select>
<label><input id="only-needs" type="checkbox" checked>Only controls needing review</label>
<p id="queue-count" role="status"></p>
<label for="control">Finding (scope-wide review)</label>
<select id="control" size="12" form="review" required></select>
<p><button id="previous-control" type="button">Previous</button>
<button id="next-control" type="button">Next</button></p>
<p>Keyboard: Alt+Up / Alt+Down.</p></section>
<section aria-label="Evidence and decisions">
<form id="review" class="card"><p id="technical"></p>
<details open><summary>Evidence to prepare and decision boundaries</summary>
<ul id="preparation"></ul></details>
<details><summary>Already available scoped inventory (not a decision)</summary>
<pre id="available-evidence"></pre></details>
<label for="kind">Review kind</label><select id="kind" required></select>
<label for="decision">Your decision</label><select id="decision" required></select>
<p id="record-status"></p>
<label for="reviewer">Reviewer label</label>
<input id="reviewer" required maxlength="200" autocomplete="off">
<label for="rationale">Justification</label>
<textarea id="rationale" required maxlength="4000"></textarea>
<label for="evidence">Supporting evidence or attributable owner statement</label>
<textarea id="evidence" required maxlength="4000"></textarea>
<label for="valid_from">Valid from (your local time)</label>
<input id="valid_from" type="datetime-local" step="1" required>
<label for="valid_until">Expires (your local time)</label>
<input id="valid_until" type="datetime-local" step="1" required>
<p><button type="button" data-days="30">30 days</button>
<button type="button" data-days="90">90 days</button></p>
<label id="replacement" hidden><input id="replace_existing" type="checkbox">
Replace this saved review; preserve its earlier revision.</label>
<p><button id="save" class="primary" type="submit">Save review and update reports</button></p>
</form>
<details class="card"><summary>Review selected Signals together</summary>
<p>Select each Signal and its explicit outcome. Shared reviewer, evidence,
justification and validity come from the form above. No outcome is prefilled.
Human confirmation does not replace an accepted technical predicate.</p>
<div id="bulk-options"></div>
<label><input id="bulk-replace" type="checkbox">Replace selected existing manual reviews</label>
<button id="bulk-save" type="button">Save selected explicit reviews</button></details>
<details class="card"><summary>Guided interview</summary>
<label for="interview-question">Question</label><select id="interview-question"></select>
<p id="interview-question-text"></p>
<label for="interview-answer">Shared narrative answer</label>
<textarea id="interview-answer" maxlength="4000"></textarea>
<div id="interview-decisions"></div>
<label><input id="interview-replace" type="checkbox">
Replace selected existing interview reviews</label>
<button id="interview-save" type="button">Save explicit interview decisions</button></details>
</section></div>
<p id="message" role="status" aria-live="polite"></p>
<h2>Updated report</h2>
<p>The embedded report is minimized. <a href="report" target="_blank" rel="noopener">
Open minimized report</a> |
<a href="full-report" target="_blank" rel="noopener">Open full private report (identities)</a></p>
<iframe id="report" title="Current minimized assessment report" src="report"></iframe>
<p><button id="stop" type="button">Stop local review</button></p>
</main>
<script nonce="{safe_nonce}" id="state" type="application/json">{data(state)}</script>
<script nonce="{safe_nonce}" id="outcomes" type="application/json">{data(sorted(OUTCOMES))}</script>
<script nonce="{safe_nonce}" id="capability" type="application/json">{html.escape(token)}</script>
<script nonce="{safe_nonce}">{SCRIPT + WORKSPACE_SCRIPT}</script>
</body></html>"""
