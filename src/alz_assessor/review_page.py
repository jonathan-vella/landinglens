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
    `${needsReview} require review. Evaluated at ${state.evaluated_at}.`;
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
    save.disabled = false;
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
<body><header><h1>Review and save</h1>
<p>One save validates your decision, keeps a new revision and regenerates every report.
No Azure calls, uploads or infrastructure changes.</p>
<p class="notice">Private local session. Files retain scope and reviewer identities.
Keep this address and the output directory private. Reviewer labels are assertions,
not authenticated approval signatures. Exceptions do not turn failures into passes.</p>
<p>Bound scope: <code>{html.escape(state["scope"])}</code></p>
<p id="summary"></p></header><main>
<noscript>This local editor needs JavaScript. The CLI review prepare/validate workflow
and saved reports remain available without JavaScript.</noscript>
<form id="review" class="card">
<label for="control">Finding (scope-wide review, not just one resource)</label>
<select id="control" required></select><p id="technical"></p>
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
<script nonce="{safe_nonce}">{SCRIPT}</script>
</body></html>"""
