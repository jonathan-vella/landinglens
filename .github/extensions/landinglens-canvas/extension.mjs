import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { CanvasError, createCanvas, joinSession } from "@github/copilot-sdk/extension";

const MAX_ASSESSMENT_BYTES = 8_000_000;
const ALLOWED_SCHEMA_VERSIONS = new Set(["1.0", "1.1", "1.2"]);
const MANUAL_DECISIONS = new Set(["pass", "fail", "not_applicable"]);
const EXCEPTION_DECISIONS = new Set(["accepted", "rejected"]);

const servers = new Map();
const instanceArtifacts = new Map();
const memoryArtifacts = new Map();

let activeSession = null;

function logInfo(message, sessionOverride) {
  const target = sessionOverride ?? activeSession;
  if (target && typeof target.log === "function") {
    target.log(message, { level: "info", ephemeral: true });
  }
}

export function deriveArtifactId(assessmentPath) {
  if (typeof assessmentPath !== "string" || !assessmentPath.trim()) {
    return "default";
  }
  const normalized = assessmentPath.trim().replace(/\\/g, "/");
  const digest = crypto.createHash("sha256").update(normalized).digest("hex").slice(0, 16);
  return `assessment-${digest}`;
}

function getStorageDirectory(sessionOverride) {
  const target = sessionOverride ?? activeSession;
  const workspacePath =
    (target && typeof target.workspacePath === "string" && target.workspacePath.trim()) ||
    process.env.LANDINGLENS_CANVAS_STATE_DIR ||
    path.join(os.tmpdir(), "landinglens-canvas-artifacts");
  fs.mkdirSync(workspacePath, { recursive: true });
  return workspacePath;
}

function getArtifactFilePath(artifactId, sessionOverride) {
  const safeId = String(artifactId || "default").replace(/[^A-Za-z0-9._-]/g, "_");
  return path.join(getStorageDirectory(sessionOverride), `landinglens-canvas-${safeId}.json`);
}

export function createEmptyState(artifactId = "default", title = "LandingLens ALZ Workspace") {
  return {
    artifactId,
    title,
    loaded: false,
    catalogVersion: null,
    generatedAt: null,
    schemaVersion: null,
    scopeMode: null,
    coverage: null,
    controlsCount: 0,
    resultsCount: 0,
    rows: [],
    filters: {
      outcome: "",
      design_area: "",
      severity: "",
      tier: "",
      comparison: "",
      query: "",
    },
    selectedControlId: null,
    drafts: {},
  };
}

export function loadDurableState(artifactId = "default", sessionOverride) {
  const filePath = getArtifactFilePath(artifactId, sessionOverride);
  try {
    if (fs.existsSync(filePath)) {
      const raw = fs.readFileSync(filePath, "utf8");
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === "object" && Array.isArray(parsed.rows)) {
        return {
          ...createEmptyState(artifactId, parsed.title),
          ...parsed,
          artifactId,
          filters: {
            ...createEmptyState(artifactId).filters,
            ...(parsed.filters || {}),
          },
          drafts: parsed.drafts && typeof parsed.drafts === "object" ? parsed.drafts : {},
        };
      }
    }
  } catch {
    // Fall back to in-memory or empty state if disk read fails.
  }
  if (memoryArtifacts.has(artifactId)) {
    return memoryArtifacts.get(artifactId);
  }
  const initial = createEmptyState(artifactId);
  memoryArtifacts.set(artifactId, initial);
  return initial;
}

export function saveDurableState(state, sessionOverride) {
  const artifactId = state.artifactId || "default";
  memoryArtifacts.set(artifactId, state);
  const filePath = getArtifactFilePath(artifactId, sessionOverride);
  fs.writeFileSync(filePath, JSON.stringify(state, null, 2), "utf8");
  return filePath;
}

function isSubpath(parentReal, candidateReal) {
  const rel = path.relative(parentReal, candidateReal);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

export function resolveSafeAssessmentPath(rawPath, sessionOverride) {
  if (typeof rawPath !== "string" || rawPath.trim().length === 0 || rawPath.includes("\0")) {
    throw new CanvasError("invalid_path", "Assessment path must be a non-empty string.");
  }
  const normalizedSegments = rawPath.replace(/\\/g, "/").split("/");
  if (normalizedSegments.includes("..")) {
    throw new CanvasError("invalid_path", "Path traversal ('..') is not permitted.");
  }

  const target = sessionOverride ?? activeSession;
  const allowedRoots = [process.cwd()];
  if (target && typeof target.workspacePath === "string" && target.workspacePath.trim()) {
    allowedRoots.push(target.workspacePath.trim());
  }

  const realRoots = [];
  for (const root of allowedRoots) {
    try {
      realRoots.push(fs.realpathSync(root));
    } catch {
      // Ignore non-existent optional roots.
    }
  }
  if (realRoots.length === 0) {
    throw new CanvasError("invalid_path", "No valid workspace root is available.");
  }

  const baseDir = realRoots[0];
  const candidate = path.isAbsolute(rawPath) ? path.normalize(rawPath) : path.resolve(baseDir, rawPath);

  let lstat;
  try {
    lstat = fs.lstatSync(candidate);
  } catch {
    throw new CanvasError("invalid_path", "Assessment file does not exist.");
  }
  if (lstat.isSymbolicLink()) {
    throw new CanvasError("invalid_path", "Symbolic links are not permitted for assessment files.");
  }

  let realCandidate;
  try {
    realCandidate = fs.realpathSync(candidate);
  } catch {
    throw new CanvasError("invalid_path", "Unable to resolve assessment file realpath.");
  }

  if (!realRoots.some((root) => isSubpath(root, realCandidate))) {
    throw new CanvasError(
      "invalid_path",
      "Assessment path must reside strictly within the repository or session workspace."
    );
  }

  let stat;
  try {
    stat = fs.statSync(realCandidate);
  } catch {
    throw new CanvasError("invalid_path", "Unable to stat assessment file.");
  }
  if (!stat.isFile()) {
    throw new CanvasError("invalid_path", "Assessment path must point to a regular file.");
  }
  if (stat.size > MAX_ASSESSMENT_BYTES) {
    throw new CanvasError(
      "invalid_path",
      `Assessment file exceeds the ${MAX_ASSESSMENT_BYTES} byte limit.`
    );
  }

  return realCandidate;
}

function pseudonymizeLogicalId(logicalId) {
  if (typeof logicalId !== "string" || !logicalId || logicalId === "scope") {
    return "scope";
  }
  const digest = crypto.createHash("sha256").update(logicalId).digest("hex").slice(0, 12);
  return `target-${digest}`;
}

export function sanitizeHttpsReferences(references) {
  if (!Array.isArray(references)) {
    return [];
  }
  const sanitized = [];
  const seen = new Set();
  for (const ref of references) {
    if (!ref || typeof ref !== "object") {
      continue;
    }
    const rawUrl = ref.guidance ?? ref.source_url ?? ref.url;
    if (typeof rawUrl !== "string" || !rawUrl.trim()) {
      continue;
    }
    let parsed;
    try {
      parsed = new URL(rawUrl);
    } catch {
      continue;
    }
    if (parsed.protocol !== "https:" || !parsed.hostname || parsed.username || parsed.password) {
      continue;
    }
    const normalizedUrl = parsed.toString();
    if (seen.has(normalizedUrl)) {
      continue;
    }
    seen.add(normalizedUrl);
    sanitized.push({
      url: normalizedUrl,
      label: typeof ref.label === "string" && ref.label.trim()
        ? ref.label.trim()
        : `${parsed.hostname}${parsed.pathname}`,
    });
  }
  return sanitized;
}

function projectModeBody(body, automation) {
  if (!body || typeof body !== "object") {
    return null;
  }
  const reviews = Array.isArray(body.reviews) ? body.reviews : [];
  const activeReview = reviews.find((r) => r && r.requires_review === false) || reviews[0] || null;
  const tier =
    typeof body.evidence_tier === "string"
      ? body.evidence_tier
      : automation === "manual"
      ? "manual"
      : body.outcome === "pass" || body.outcome === "fail"
      ? "verified"
      : body.machine_evidence === true
      ? "signal"
      : "needs_decision";

  return {
    outcome: typeof body.outcome === "string" ? body.outcome : "unknown",
    reason: typeof body.reason === "string" ? body.reason : "unknown",
    freshness: typeof body.freshness === "string" ? body.freshness : "unknown",
    evidence_tier: tier,
    exception_disposition:
      typeof body.exception_disposition === "string" ? body.exception_disposition : null,
    review_status: {
      recorded: reviews.length > 0,
      active: Boolean(activeReview && activeReview.requires_review === false),
      kind: activeReview && typeof activeReview.kind === "string" ? activeReview.kind : null,
      disposition:
        typeof body.exception_disposition === "string" ? body.exception_disposition : null,
    },
  };
}

export function projectMinimizedAssessment(doc) {
  if (
    !doc ||
    typeof doc !== "object" ||
    doc.kind !== "assessment" ||
    !ALLOWED_SCHEMA_VERSIONS.has(doc.schema_version) ||
    !Array.isArray(doc.results)
  ) {
    throw new CanvasError(
      "invalid_assessment",
      "Document must have kind === 'assessment', schema_version in ['1.0', '1.1', '1.2'], and a results array."
    );
  }

  const rows = doc.results.map((row) => {
    if (!row || typeof row !== "object" || typeof row.control_id !== "string") {
      throw new CanvasError("invalid_assessment", "Each result entry must contain a control_id.");
    }
    const automation = typeof row.automation === "string" ? row.automation : "unknown";
    const planned = projectModeBody(row.planned, automation);
    const observed = projectModeBody(row.observed, automation);
    const primary = observed ?? planned;
    const outcome = primary ? primary.outcome : "unknown";
    const tier = primary
      ? primary.evidence_tier
      : automation === "manual"
      ? "manual"
      : "needs_decision";

    return {
      control_id: row.control_id,
      upstream_id: typeof row.upstream_id === "string" ? row.upstream_id : row.control_id,
      recommendation: typeof row.recommendation === "string" ? row.recommendation : "",
      design_area: typeof row.design_area === "string" ? row.design_area : "Unknown",
      severity: typeof row.severity === "string" ? row.severity.toLowerCase() : "unknown",
      automation,
      logical_id: pseudonymizeLogicalId(row.logical_id),
      rationale: typeof row.rationale === "string" ? row.rationale : "",
      evidence_requirements: Array.isArray(row.evidence_requirements)
        ? row.evidence_requirements.filter((item) => typeof item === "string")
        : [],
      outcome,
      tier,
      comparison: typeof row.comparison === "string" ? row.comparison : null,
      comparison_reason: typeof row.comparison_reason === "string" ? row.comparison_reason : null,
      planned,
      observed,
      references: sanitizeHttpsReferences(row.references),
    };
  });

  const hasComparison = rows.some((r) => r.comparison !== null);
  const evidence = Array.isArray(doc.evidence) ? doc.evidence : [];
  const allObserved =
    evidence.length > 0 && evidence.every((bundle) => bundle && bundle.mode === "observed");
  const scopeMode = hasComparison
    ? "Planned vs. observed comparison"
    : allObserved
    ? "Saved observed evidence"
    : "Saved planned configuration";

  const uniqueControls = new Set(rows.map((r) => r.control_id));

  return {
    catalogVersion: typeof doc.catalog_version === "string" ? doc.catalog_version : "unknown",
    generatedAt: typeof doc.generated_at === "string" ? doc.generated_at : null,
    schemaVersion: doc.schema_version,
    scopeMode,
    coverage: doc.coverage && typeof doc.coverage === "object" ? doc.coverage : null,
    controlsCount: uniqueControls.size,
    resultsCount: rows.length,
    rows,
  };
}

export function computeMatchingRows(rows, filters = {}) {
  if (!Array.isArray(rows)) {
    return [];
  }
  const outcome = (filters.outcome || "").trim().toLowerCase();
  const designArea = (filters.design_area || "").trim().toLowerCase();
  const severity = (filters.severity || "").trim().toLowerCase();
  const tier = (filters.tier || "").trim().toLowerCase();
  const comparison = (filters.comparison || "").trim().toLowerCase();
  const query = (filters.query || "").trim().toLowerCase();

  return rows.filter((row) => {
    if (outcome && String(row.outcome || "").toLowerCase() !== outcome) {
      return false;
    }
    if (designArea && String(row.design_area || "").toLowerCase() !== designArea) {
      return false;
    }
    if (severity && String(row.severity || "").toLowerCase() !== severity) {
      return false;
    }
    if (tier && String(row.tier || "").toLowerCase() !== tier) {
      return false;
    }
    if (comparison && String(row.comparison || "").toLowerCase() !== comparison) {
      return false;
    }
    if (query) {
      const haystack = [
        row.control_id,
        row.upstream_id,
        row.recommendation,
        row.design_area,
        row.rationale,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      if (!haystack.includes(query)) {
        return false;
      }
    }
    return true;
  });
}

function broadcastInstanceState(instanceId, state) {
  const entry = servers.get(instanceId);
  if (!entry) {
    return;
  }
  entry.state = state;
  const payload = `data: ${JSON.stringify(state)}\n\n`;
  for (const client of entry.sseClients) {
    try {
      client.write(payload);
    } catch {
      entry.sseClients.delete(client);
    }
  }
}

function broadcastArtifactState(artifactId, state) {
  for (const [instanceId, mappedArtifactId] of instanceArtifacts.entries()) {
    if (mappedArtifactId === artifactId) {
      broadcastInstanceState(instanceId, state);
    }
  }
}

function getInstanceState(instanceId, sessionOverride) {
  const artifactId = instanceArtifacts.get(instanceId) || "default";
  const entry = servers.get(instanceId);
  if (entry && entry.state && entry.state.artifactId === artifactId) {
    return entry.state;
  }
  const state = loadDurableState(artifactId, sessionOverride);
  if (entry) {
    entry.state = state;
  }
  return state;
}

export async function handleLoadAssessment(ctx, sessionOverride) {
  const rawPath = ctx?.input?.path;
  const realCandidate = resolveSafeAssessmentPath(rawPath, sessionOverride);

  let parsed;
  try {
    const rawText = fs.readFileSync(realCandidate, "utf8");
    parsed = JSON.parse(rawText);
  } catch (err) {
    if (err instanceof CanvasError) {
      throw err;
    }
    throw new CanvasError("invalid_assessment", "Assessment file is not valid JSON.");
  }

  const projected = projectMinimizedAssessment(parsed);
  const instanceId = ctx?.instanceId || "default";
  const previousState = getInstanceState(instanceId, sessionOverride);
  const artifactId = deriveArtifactId(realCandidate);

  instanceArtifacts.set(instanceId, artifactId);
  const existingArtifactState = loadDurableState(artifactId, sessionOverride);

  const mergedDrafts = {
    ...(previousState.drafts || {}),
    ...(existingArtifactState.drafts || {}),
  };

  const firstControlId = projected.rows.length > 0 ? projected.rows[0].control_id : null;
  const nextState = {
    ...createEmptyState(artifactId, previousState.title),
    ...projected,
    artifactId,
    loaded: true,
    filters: existingArtifactState.filters || previousState.filters,
    selectedControlId:
      existingArtifactState.selectedControlId &&
      projected.rows.some((r) => r.control_id === existingArtifactState.selectedControlId)
        ? existingArtifactState.selectedControlId
        : firstControlId,
    drafts: mergedDrafts,
  };

  saveDurableState(nextState, sessionOverride);
  broadcastInstanceState(instanceId, nextState);
  broadcastArtifactState(artifactId, nextState);
  logInfo(`Loaded assessment (${projected.resultsCount} rows) into canvas ${instanceId}`, sessionOverride);

  return {
    loaded: true,
    catalogVersion: projected.catalogVersion,
    controlsCount: projected.controlsCount,
    resultsCount: projected.resultsCount,
  };
}

export async function handleFilterFindings(ctx, sessionOverride) {
  const instanceId = ctx?.instanceId || "default";
  const state = getInstanceState(instanceId, sessionOverride);
  const input = ctx?.input || {};

  const nextFilters = {
    outcome: typeof input.outcome === "string" ? input.outcome : state.filters.outcome,
    design_area:
      typeof input.design_area === "string" ? input.design_area : state.filters.design_area,
    severity: typeof input.severity === "string" ? input.severity : state.filters.severity,
    tier: typeof input.tier === "string" ? input.tier : state.filters.tier,
    comparison:
      typeof input.comparison === "string" ? input.comparison : state.filters.comparison,
    query: typeof input.query === "string" ? input.query : state.filters.query,
  };

  const matching = computeMatchingRows(state.rows, nextFilters);
  const nextState = {
    ...state,
    filters: nextFilters,
  };

  saveDurableState(nextState, sessionOverride);
  broadcastArtifactState(nextState.artifactId, nextState);
  broadcastInstanceState(instanceId, nextState);

  return {
    matchingCount: matching.length,
  };
}

export async function handleSelectControl(ctx, sessionOverride) {
  const instanceId = ctx?.instanceId || "default";
  const state = getInstanceState(instanceId, sessionOverride);
  const queryControl = typeof ctx?.input?.control === "string" ? ctx.input.control.trim() : "";
  if (!queryControl) {
    throw new CanvasError("control_not_found", "A non-empty control identifier is required.");
  }

  const needle = queryControl.toLowerCase();
  const match = state.rows.find(
    (row) =>
      String(row.control_id || "").toLowerCase() === needle ||
      String(row.upstream_id || "").toLowerCase() === needle
  );
  if (!match) {
    throw new CanvasError(
      "control_not_found",
      `Control '${queryControl}' was not found in the loaded assessment.`
    );
  }

  const nextState = {
    ...state,
    selectedControlId: match.control_id,
  };

  saveDurableState(nextState, sessionOverride);
  broadcastArtifactState(nextState.artifactId, nextState);
  broadcastInstanceState(instanceId, nextState);

  return {
    control_id: match.control_id,
    upstream_id: match.upstream_id,
    recommendation: match.recommendation,
    design_area: match.design_area,
    severity: match.severity,
    outcome: match.outcome,
  };
}

export function validateStageDecisionInput(input, loadedRows = []) {
  if (!input || typeof input !== "object") {
    throw new CanvasError("invalid_decision", "Decision payload is required.");
  }
  const {
    control_id,
    kind,
    decision,
    reviewer,
    rationale,
    evidence,
    valid_from,
    valid_until,
  } = input;

  if (typeof control_id !== "string" || !control_id.trim()) {
    throw new CanvasError("invalid_decision", "control_id must be a non-empty string.");
  }
  if (kind !== "manual" && kind !== "exceptions") {
    throw new CanvasError("invalid_decision", "kind must be 'manual' or 'exceptions'.");
  }
  if (kind === "manual" && !MANUAL_DECISIONS.has(decision)) {
    throw new CanvasError(
      "invalid_decision",
      "manual reviews must use decision in ['pass', 'fail', 'not_applicable']."
    );
  }
  if (kind === "exceptions" && !EXCEPTION_DECISIONS.has(decision)) {
    throw new CanvasError(
      "invalid_decision",
      "exceptions reviews must use decision in ['accepted', 'rejected']."
    );
  }
  if (typeof reviewer !== "string" || !reviewer.trim() || reviewer.length > 200) {
    throw new CanvasError(
      "invalid_decision",
      "reviewer must be a non-empty string of at most 200 characters."
    );
  }
  if (typeof rationale !== "string" || !rationale.trim() || rationale.length > 4000) {
    throw new CanvasError(
      "invalid_decision",
      "rationale must be a non-empty string of at most 4000 characters."
    );
  }
  if (typeof evidence !== "string" || !evidence.trim() || evidence.length > 4000) {
    throw new CanvasError(
      "invalid_decision",
      "evidence must be a non-empty string of at most 4000 characters."
    );
  }
  const fromTime = Date.parse(valid_from);
  const untilTime = Date.parse(valid_until);
  if (Number.isNaN(fromTime) || Number.isNaN(untilTime) || !(untilTime > fromTime)) {
    throw new CanvasError(
      "invalid_decision",
      "valid_until must be a valid ISO timestamp strictly after valid_from."
    );
  }

  let canonicalControlId = control_id.trim();
  if (Array.isArray(loadedRows) && loadedRows.length > 0) {
    const needle = canonicalControlId.toLowerCase();
    const matched = loadedRows.find(
      (r) =>
        String(r.control_id || "").toLowerCase() === needle ||
        String(r.upstream_id || "").toLowerCase() === needle
    );
    if (!matched) {
      throw new CanvasError(
        "control_not_found",
        `Control '${canonicalControlId}' was not found in the loaded assessment.`
      );
    }
    canonicalControlId = matched.control_id;
  }

  return {
    control_id: canonicalControlId,
    kind,
    decision,
    reviewer: reviewer.trim(),
    rationale: rationale.trim(),
    evidence: evidence.trim(),
    valid_from,
    valid_until,
    status: "draft_not_saved_or_approved",
    label: "Draft (not saved / not approved)",
    committed: false,
    staged_at: new Date().toISOString(),
  };
}

export async function handleStageDecision(ctx, sessionOverride) {
  const instanceId = ctx?.instanceId || "default";
  const state = getInstanceState(instanceId, sessionOverride);
  const draft = validateStageDecisionInput(ctx?.input, state.rows);

  const nextState = {
    ...state,
    selectedControlId: draft.control_id,
    drafts: {
      ...(state.drafts || {}),
      [draft.control_id]: draft,
    },
  };

  saveDurableState(nextState, sessionOverride);
  broadcastArtifactState(nextState.artifactId, nextState);
  broadcastInstanceState(instanceId, nextState);

  return {
    status: "draft_not_saved_or_approved",
    committed: false,
    draft,
  };
}

export function buildCspHeader(nonce) {
  return `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'`;
}

export function renderCanvasHtml(nonce, token, initialState) {
  const safeInitialJson = JSON.stringify(initialState)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>LandingLens ALZ Workspace</title>
  <style nonce="${nonce}">
    :root {
      --cp-bg: var(--background-color-default, #ffffff);
      --cp-text: var(--text-color-default, #1f2328);
      --cp-muted: var(--text-color-muted, #59636e);
      --cp-border: var(--border-color-default, #d1d9e0);
      --cp-focus: var(--color-focus-outline, #0969da);
      --cp-danger: var(--true-color-red, #cf222e);
      --cp-accent: var(--true-color-blue, #0969da);
      --cp-font-sans: var(--font-sans, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif);
      --cp-font-mono: var(--font-mono, "SFMono-Regular", Consolas, "Liberation Mono", monospace);
      --cp-font-size: var(--text-body-medium, 14px);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--cp-bg);
      color: var(--cp-text);
      font-family: var(--cp-font-sans);
      font-size: var(--cp-font-size);
      line-height: 1.5;
      display: flex;
      flex-direction: column;
      height: 100vh;
    }
    header {
      padding: 12px 16px;
      border-bottom: 1px solid var(--cp-border);
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }
    h1 {
      margin: 0;
      font-size: 16px;
      font-weight: 600;
    }
    .meta {
      color: var(--cp-muted);
      font-size: 12px;
      font-family: var(--cp-font-mono);
    }
    .toolbar {
      padding: 10px 16px;
      border-bottom: 1px solid var(--cp-border);
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
    }
    input, select, textarea, button {
      font: inherit;
      color: var(--cp-text);
      background: var(--cp-bg);
      border: 1px solid var(--cp-border);
      border-radius: 6px;
      padding: 6px 10px;
    }
    input:focus, select:focus, textarea:focus, button:focus {
      outline: 2px solid var(--cp-focus);
      outline-offset: 1px;
    }
    button {
      cursor: pointer;
      font-weight: 600;
    }
    .workspace {
      display: grid;
      grid-template-columns: minmax(260px, 1fr) minmax(340px, 1.4fr);
      flex: 1;
      min-height: 0;
    }
    .list-pane {
      border-right: 1px solid var(--cp-border);
      overflow-y: auto;
      padding: 8px;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .detail-pane {
      overflow-y: auto;
      padding: 16px;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }
    .row-item {
      text-align: left;
      padding: 10px;
      border: 1px solid var(--cp-border);
      border-radius: 6px;
      background: var(--cp-bg);
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    .row-item[aria-selected="true"] {
      border-color: var(--cp-accent);
      box-shadow: 0 0 0 1px var(--cp-accent);
    }
    .badge-row {
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
      font-size: 11px;
      font-family: var(--cp-font-mono);
    }
    .badge {
      padding: 2px 6px;
      border-radius: 4px;
      border: 1px solid var(--cp-border);
    }
    .badge-fail {
      color: var(--cp-danger);
      border-color: var(--cp-danger);
    }
    .badge-draft {
      color: var(--cp-accent);
      border-color: var(--cp-accent);
    }
    .card {
      border: 1px solid var(--cp-border);
      border-radius: 6px;
      padding: 12px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .draft-banner {
      border: 1px dashed var(--cp-accent);
      padding: 10px;
      border-radius: 6px;
      font-size: 12px;
    }
    .field-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px;
    }
    pre {
      margin: 0;
      padding: 8px;
      border: 1px solid var(--cp-border);
      border-radius: 4px;
      font-family: var(--cp-font-mono);
      font-size: 12px;
      overflow-x: auto;
      white-space: pre-wrap;
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1 id="canvas-title">LandingLens ALZ Workspace</h1>
      <div class="meta" id="canvas-subtitle">No assessment loaded</div>
    </div>
    <div class="meta" id="canvas-counts">0 / 0 controls</div>
  </header>
  <section class="toolbar" aria-label="Filters">
    <input id="filter-query" type="search" placeholder="Search control ID or recommendation...">
    <select id="filter-outcome" aria-label="Outcome filter">
      <option value="">All outcomes</option>
      <option value="pass">pass</option>
      <option value="fail">fail</option>
      <option value="unknown">unknown</option>
      <option value="not_applicable">not_applicable</option>
      <option value="error">error</option>
    </select>
    <select id="filter-severity" aria-label="Severity filter">
      <option value="">All severities</option>
      <option value="high">high</option>
      <option value="medium">medium</option>
      <option value="low">low</option>
      <option value="unknown">unknown</option>
    </select>
    <select id="filter-tier" aria-label="Evidence tier filter">
      <option value="">All tiers</option>
      <option value="verified">verified</option>
      <option value="signal">signal</option>
      <option value="needs_decision">needs_decision</option>
      <option value="manual">manual</option>
    </select>
    <select id="filter-comparison" aria-label="Comparison filter">
      <option value="">All comparisons</option>
      <option value="drift">drift</option>
      <option value="match">match</option>
      <option value="absent">absent</option>
      <option value="not_comparable">not_comparable</option>
    </select>
  </section>
  <main class="workspace">
    <div class="list-pane" id="control-list" role="listbox" aria-label="Controls"></div>
    <div class="detail-pane" id="control-detail"></div>
  </main>
  <script id="initial-state" type="application/json" nonce="${nonce}">${safeInitialJson}</script>
  <script nonce="${nonce}">
    (function () {
      const basePath = "/${token}";
      let state = JSON.parse(document.getElementById("initial-state").textContent);

      const titleEl = document.getElementById("canvas-title");
      const subtitleEl = document.getElementById("canvas-subtitle");
      const countsEl = document.getElementById("canvas-counts");
      const listEl = document.getElementById("control-list");
      const detailEl = document.getElementById("control-detail");

      const queryInput = document.getElementById("filter-query");
      const outcomeSelect = document.getElementById("filter-outcome");
      const severitySelect = document.getElementById("filter-severity");
      const tierSelect = document.getElementById("filter-tier");
      const comparisonSelect = document.getElementById("filter-comparison");

      function el(tag, attrs, children) {
        const node = document.createElement(tag);
        if (attrs) {
          for (const [k, v] of Object.entries(attrs)) {
            if (v === undefined || v === null) continue;
            if (k === "textContent") {
              node.textContent = String(v);
            } else if (k === "className") {
              node.className = String(v);
            } else {
              node.setAttribute(k, String(v));
            }
          }
        }
        if (Array.isArray(children)) {
          for (const child of children) {
            if (!child) continue;
            if (typeof child === "string") {
              node.appendChild(document.createTextNode(child));
            } else {
              node.appendChild(child);
            }
          }
        }
        return node;
      }

      function filterRows(rows, filters) {
        const outcome = (filters.outcome || "").toLowerCase();
        const area = (filters.design_area || "").toLowerCase();
        const severity = (filters.severity || "").toLowerCase();
        const tier = (filters.tier || "").toLowerCase();
        const comparison = (filters.comparison || "").toLowerCase();
        const q = (filters.query || "").toLowerCase();

        return (rows || []).filter(function (row) {
          if (outcome && String(row.outcome || "").toLowerCase() !== outcome) return false;
          if (area && String(row.design_area || "").toLowerCase() !== area) return false;
          if (severity && String(row.severity || "").toLowerCase() !== severity) return false;
          if (tier && String(row.tier || "").toLowerCase() !== tier) return false;
          if (comparison && String(row.comparison || "").toLowerCase() !== comparison) return false;
          if (q) {
            const text = [
              row.control_id,
              row.upstream_id,
              row.recommendation,
              row.design_area,
              row.rationale
            ].filter(Boolean).join(" ").toLowerCase();
            if (!text.includes(q)) return false;
          }
          return true;
        });
      }

      function render() {
        titleEl.textContent = state.title || "LandingLens ALZ Workspace";
        if (state.loaded) {
          subtitleEl.textContent = (state.scopeMode || "Assessment") + " • Catalog " + (state.catalogVersion || "unknown");
        } else {
          subtitleEl.textContent = "Waiting for load_assessment action";
        }

        const filters = state.filters || {};
        if ( document.activeElement !== queryInput ) queryInput.value = filters.query || "";
        outcomeSelect.value = filters.outcome || "";
        severitySelect.value = filters.severity || "";
        tierSelect.value = filters.tier || "";
        comparisonSelect.value = filters.comparison || "";

        const visible = filterRows(state.rows || [], filters);
        countsEl.textContent = visible.length + " / " + (state.rows ? state.rows.length : 0) + " controls";

        const listNodes = visible.map(function (row) {
          const isSelected = row.control_id === state.selectedControlId;
          const draft = state.drafts && state.drafts[row.control_id];
          const badges = [
            el("span", { className: "badge", textContent: row.upstream_id || row.control_id }),
            el("span", {
              className: "badge" + (row.outcome === "fail" ? " badge-fail" : ""),
              textContent: row.outcome || "unknown"
            }),
            el("span", { className: "badge", textContent: row.severity || "unknown" }),
            el("span", { className: "badge", textContent: row.tier || "needs_decision" })
          ];
          if (row.comparison) {
            badges.push(el("span", { className: "badge", textContent: "cmp:" + row.comparison }));
          }
          if (draft) {
            badges.push(el("span", { className: "badge badge-draft", textContent: "Draft staged" }));
          }
          const btn = el("button", {
            type: "button",
            className: "row-item",
            role: "option",
            "aria-selected": isSelected ? "true" : "false"
          }, [
            el("div", { className: "badge-row" }, badges),
            el("div", { textContent: row.recommendation || row.control_id })
          ]);
          btn.addEventListener("click", function () {
            state.selectedControlId = row.control_id;
            render();
          });
          return btn;
        });
        listEl.replaceChildren(...listNodes);

        const selected =
          (state.rows || []).find(function (r) { return r.control_id === state.selectedControlId; }) ||
          visible[0] ||
          null;

        if (!selected) {
          detailEl.replaceChildren(
            el("div", { className: "card" }, [
              el("strong", { textContent: "No control selected" }),
              el("span", {
                className: "meta",
                textContent: "Use load_assessment or adjust filters to inspect ALZ controls."
              })
            ])
          );
          return;
        }

        const detailNodes = [];
        detailNodes.push(
          el("div", { className: "card" }, [
            el("div", { className: "badge-row" }, [
              el("span", { className: "badge", textContent: selected.control_id }),
              el("span", { className: "badge", textContent: selected.upstream_id }),
              el("span", { className: "badge", textContent: selected.design_area }),
              el("span", { className: "badge", textContent: "severity: " + selected.severity }),
              el("span", { className: "badge", textContent: "tier: " + selected.tier }),
              el("span", { className: "badge", textContent: "outcome: " + selected.outcome })
            ]),
            el("h2", { textContent: selected.recommendation }),
            el("p", { textContent: selected.rationale || "No catalog rationale provided." })
          ])
        );

        if (Array.isArray(selected.evidence_requirements) && selected.evidence_requirements.length > 0) {
          const items = selected.evidence_requirements.map(function (req) {
            return el("li", { textContent: req });
          });
          detailNodes.push(
            el("div", { className: "card" }, [
              el("strong", { textContent: "Evidence Requirements" }),
              el("ul", {}, items)
            ])
          );
        }

        if (Array.isArray(selected.references) && selected.references.length > 0) {
          const refLinks = [];
          for (const ref of selected.references) {
            if (typeof ref.url === "string" && ref.url.startsWith("https://")) {
              refLinks.push(
                el("li", {}, [
                  el("a", {
                    href: ref.url,
                    target: "_blank",
                    rel: "noopener noreferrer",
                    textContent: ref.label || ref.url
                  })
                ])
              );
            }
          }
          if (refLinks.length > 0) {
            detailNodes.push(
              el("div", { className: "card" }, [
                el("strong", { textContent: "References (HTTPS verified)" }),
                el("ul", {}, refLinks)
              ])
            );
          }
        }

        const existingDraft = state.drafts && state.drafts[selected.control_id];
        if (existingDraft) {
          detailNodes.push(
            el("div", { className: "card draft-banner" }, [
              el("strong", { textContent: "Draft (not saved / not approved)" }),
              el("div", {
                textContent:
                  "Staged in canvas only. Does not write manual.json, exceptions.json, or a ReviewSession revision."
              }),
              el("pre", { textContent: JSON.stringify(existingDraft, null, 2) })
            ])
          );
        }

        detailEl.replaceChildren(...detailNodes);
      }

      function syncFiltersFromUi() {
        state.filters = {
          ...(state.filters || {}),
          query: queryInput.value,
          outcome: outcomeSelect.value,
          severity: severitySelect.value,
          tier: tierSelect.value,
          comparison: comparisonSelect.value
        };
        render();
      }

      queryInput.addEventListener("input", syncFiltersFromUi);
      outcomeSelect.addEventListener("change", syncFiltersFromUi);
      severitySelect.addEventListener("change", syncFiltersFromUi);
      tierSelect.addEventListener("change", syncFiltersFromUi);
      comparisonSelect.addEventListener("change", syncFiltersFromUi);

      render();

      if (typeof EventSource === "function") {
        const es = new EventSource(basePath + "/events");
        es.onmessage = function (ev) {
          try {
            state = JSON.parse(ev.data);
            render();
          } catch {
            // Ignore malformed SSE payload
          }
        };
      }
    })();
  </script>
</body>
</html>`;
}

function setSecurityHeaders(res, nonce) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Security-Policy", buildCspHeader(nonce));
  res.setHeader("X-Content-Type-Options", "nosniff");
}

function readJsonBody(req, maxBytes = 65_536) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        reject(new Error("Payload too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      try {
        const raw = Buffer.concat(chunks).toString("utf8");
        resolve(raw ? JSON.parse(raw) : {});
      } catch (err) {
        reject(err);
      }
    });
    req.on("error", reject);
  });
}

export async function startInstanceServer(instanceId, initialState, sessionOverride) {
  const token = crypto.randomBytes(24).toString("hex");
  const nonce = crypto.randomBytes(16).toString("base64");
  const sseClients = new Set();

  const entry = {
    instanceId,
    token,
    nonce,
    sseClients,
    state: initialState,
    server: null,
    port: 0,
    url: "",
  };

  const server = http.createServer(async (req, res) => {
    setSecurityHeaders(res, entry.nonce);

    const reqUrl = new URL(req.url || "/", `http://127.0.0.1:${entry.port || 80}`);
    const prefix = `/${entry.token}`;
    if (reqUrl.pathname !== prefix && !reqUrl.pathname.startsWith(`${prefix}/`)) {
      res.statusCode = 403;
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.end("403 Forbidden");
      return;
    }

    if (req.method === "POST") {
      const expectedOrigin = `http://127.0.0.1:${entry.port}`;
      const origin = req.headers.origin;
      if (!origin || origin !== expectedOrigin) {
        res.statusCode = 403;
        res.setHeader("Content-Type", "text/plain; charset=utf-8");
        res.end("403 Forbidden: Invalid Origin");
        return;
      }
    }

    const subPath = reqUrl.pathname.slice(prefix.length) || "/";

    if (req.method === "GET" && (subPath === "/" || subPath === "/index.html")) {
      res.statusCode = 200;
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.end(renderCanvasHtml(entry.nonce, entry.token, entry.state));
      return;
    }

    if (req.method === "GET" && subPath === "/state") {
      res.statusCode = 200;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify(entry.state));
      return;
    }

    if (req.method === "GET" && subPath === "/events") {
      res.statusCode = 200;
      res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
      res.setHeader("Connection", "keep-alive");
      res.write(`data: ${JSON.stringify(entry.state)}\n\n`);
      sseClients.add(res);
      req.on("close", () => {
        sseClients.delete(res);
      });
      return;
    }

    if (req.method === "POST" && subPath === "/stage") {
      try {
        const body = await readJsonBody(req);
        const result = await handleStageDecision({ instanceId, input: body }, sessionOverride);
        res.statusCode = 200;
        res.setHeader("Content-Type", "application/json; charset=utf-8");
        res.end(JSON.stringify(result));
      } catch (err) {
        res.statusCode = 400;
        res.setHeader("Content-Type", "application/json; charset=utf-8");
        res.end(
          JSON.stringify({
            error: err instanceof CanvasError ? err.code : "invalid_request",
            message: err instanceof Error ? err.message : "Invalid request",
          })
        );
      }
      return;
    }

    res.statusCode = 404;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.end("404 Not Found");
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });

  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  entry.server = server;
  entry.port = port;
  entry.url = `http://127.0.0.1:${port}/${token}/`;
  servers.set(instanceId, entry);
  return entry;
}

export async function closeInstanceServer(instanceId) {
  const entry = servers.get(instanceId);
  if (!entry) {
    return;
  }
  servers.delete(instanceId);
  for (const client of entry.sseClients) {
    try {
      client.end();
      client.destroy();
    } catch {
      // Ignore errors while closing SSE streams
    }
  }
  entry.sseClients.clear();
  await new Promise((resolve) => {
    entry.server.close(() => resolve());
  });
}

export const canvasDeclaration = createCanvas({
  id: "landinglens",
  displayName: "LandingLens ALZ Workspace",
  description: "Interactive Azure Landing Zones assessment explorer and draft decision workspace.",
  inputSchema: {
    type: "object",
    properties: {
      assessmentPath: { type: "string" },
      title: { type: "string" },
    },
    additionalProperties: false,
  },
  actions: [
    {
      name: "load_assessment",
      description:
        "Load and validate a LandingLens assessment JSON file from the repository or session workspace.",
      inputSchema: {
        type: "object",
        properties: {
          path: { type: "string", minLength: 1 },
        },
        required: ["path"],
        additionalProperties: false,
      },
      handler: async (ctx) => handleLoadAssessment(ctx),
    },
    {
      name: "filter_findings",
      description:
        "Filter assessment controls in the canvas by outcome, design_area, severity, tier, comparison, or query.",
      inputSchema: {
        type: "object",
        properties: {
          outcome: { type: "string" },
          design_area: { type: "string" },
          severity: { type: "string" },
          tier: { type: "string" },
          comparison: { type: "string" },
          query: { type: "string" },
        },
        additionalProperties: false,
      },
      handler: async (ctx) => handleFilterFindings(ctx),
    },
    {
      name: "select_control",
      description:
        "Focus a specific ALZ control by control_id or upstream_id (for example, 'D01.01') and return its summary.",
      inputSchema: {
        type: "object",
        properties: {
          control: { type: "string", minLength: 1 },
        },
        required: ["control"],
        additionalProperties: false,
      },
      handler: async (ctx) => handleSelectControl(ctx),
    },
    {
      name: "stage_decision",
      description:
        "Stage a non-committing review decision draft in the canvas UI (marked draft_not_saved_or_approved; never writes manual.json or exceptions.json).",
      inputSchema: {
        type: "object",
        properties: {
          control_id: { type: "string" },
          kind: { type: "string", enum: ["manual", "exceptions"] },
          decision: {
            type: "string",
            enum: ["pass", "fail", "not_applicable", "accepted", "rejected"],
          },
          reviewer: { type: "string", maxLength: 200 },
          rationale: { type: "string", maxLength: 4000 },
          evidence: { type: "string", maxLength: 4000 },
          valid_from: { type: "string" },
          valid_until: { type: "string" },
        },
        required: [
          "control_id",
          "kind",
          "decision",
          "reviewer",
          "rationale",
          "evidence",
          "valid_from",
          "valid_until",
        ],
        additionalProperties: false,
      },
      handler: async (ctx) => handleStageDecision(ctx),
    },
  ],
  open: async (ctx) => {
    const instanceId = ctx.instanceId;
    const requestedPath = ctx.input?.assessmentPath;
    const title = ctx.input?.title || "LandingLens ALZ Workspace";

    let artifactId = instanceArtifacts.get(instanceId) || "default";
    if (typeof requestedPath === "string" && requestedPath.trim()) {
      const resolved = resolveSafeAssessmentPath(requestedPath);
      artifactId = deriveArtifactId(resolved);
    }
    instanceArtifacts.set(instanceId, artifactId);

    let state = loadDurableState(artifactId);
    if (ctx.input?.title) {
      state = { ...state, title };
      saveDurableState(state);
    }

    let entry = servers.get(instanceId);
    if (!entry) {
      entry = await startInstanceServer(instanceId, state);
    } else {
      entry.state = state;
      broadcastInstanceState(instanceId, state);
    }

    if (typeof requestedPath === "string" && requestedPath.trim()) {
      await handleLoadAssessment({
        ...ctx,
        instanceId,
        input: { path: requestedPath },
      });
      entry = servers.get(instanceId);
    }

    return {
      url: entry.url,
      title: entry.state.title || title,
      status: entry.state.loaded
        ? `${entry.state.resultsCount} results loaded`
        : "Ready for assessment",
    };
  },
  onClose: async (ctx) => {
    await closeInstanceServer(ctx.instanceId);
  },
});

activeSession = await joinSession({
  canvases: [canvasDeclaration],
});
