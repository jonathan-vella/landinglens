from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

from alz_assessor.arm import arm_source
from alz_assessor.catalog import load_catalog
from alz_assessor.engine import assess

ROOT = Path(__file__).parents[1]
EXTENSION_DIR = ROOT / ".github" / "extensions" / "landinglens-canvas"
EXTENSION_MJS = EXTENSION_DIR / "extension.mjs"
MANIFEST_JSON = EXTENSION_DIR / "copilot-extension.json"


NODE_HARNESS = r"""
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { registerHooks } from "node:module";
import { pathToFileURL } from "node:url";

const workspaceDir = process.env.LANDINGLENS_TEST_WORKSPACE;
const assessmentPath = process.env.LANDINGLENS_TEST_ASSESSMENT;
const outsidePath = process.env.LANDINGLENS_TEST_OUTSIDE;
const extensionPath = process.env.LANDINGLENS_TEST_EXTENSION;

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "@github/copilot-sdk/extension") {
      return { url: "copilot-sdk://extension", shortCircuit: true };
    }
    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (url === "copilot-sdk://extension") {
      return {
        format: "module",
        shortCircuit: true,
        source: `
          export class CanvasError extends Error {
            constructor(code, message) {
              super(message);
              this.name = "CanvasError";
              this.code = code;
            }
          }
          export function createCanvas(decl) { return decl; }
          export const logs = [];
          export let joinedConfig = null;
          export const mockSession = {
            sessionId: "test-session-1",
            workspacePath: process.env.LANDINGLENS_TEST_WORKSPACE,
            log(msg, opts) { logs.push({ msg, opts }); },
          };
          export async function joinSession(config) {
            joinedConfig = config;
            return mockSession;
          }
        `,
      };
    }
    return nextLoad(url, context);
  },
});

const sdk = await import("@github/copilot-sdk/extension");
const ext = await import(pathToFileURL(extensionPath).href);
const canvas = sdk.joinedConfig.canvases[0];
const actions = Object.fromEntries(canvas.actions.map((a) => [a.name, a]));

function httpRequest(urlStr, options = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const req = http.request(
      {
        hostname: u.hostname,
        port: u.port,
        path: u.pathname + u.search,
        method: options.method || "GET",
        headers: options.headers || {},
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString("utf8"),
          });
        });
      }
    );
    req.on("error", reject);
    if (options.body) {
      req.write(options.body);
    }
    req.end();
  });
}

async function expectCanvasError(fn, expectedCode) {
  try {
    await fn();
  } catch (err) {
    if (err && err.code === expectedCode) {
      return true;
    }
    throw new Error(`Expected CanvasError(${expectedCode}), got: ${err?.code || err?.message}`);
  }
  throw new Error(`Expected CanvasError(${expectedCode}), but call succeeded`);
}

// 1. Open canvas instance
const opened = await canvas.open({
  sessionId: "test-session-1",
  extensionId: "project:landinglens-canvas",
  canvasId: "landinglens",
  instanceId: "panel-1",
  input: { title: "ALZ Test Canvas" },
});

const parsedUrl = new URL(opened.url);
const token = parsedUrl.pathname.split("/").filter(Boolean)[0];
const baseOrigin = `http://127.0.0.1:${parsedUrl.port}`;

// 2. Verify 403 without token and 200 with token + headers
const noTokenRes = await httpRequest(`${baseOrigin}/`);
const wrongTokenRes = await httpRequest(`${baseOrigin}/wrong-token/state`);
const htmlRes = await httpRequest(opened.url);

// 3. Connect SSE client and collect events
const sseEvents = [];
const sseReq = http.get(`${baseOrigin}/${token}/events`, (res) => {
  let buf = "";
  res.setEncoding("utf8");
  res.on("data", (chunk) => {
    buf += chunk;
    let idx;
    while ((idx = buf.indexOf("\n\n")) !== -1) {
      const rawEvent = buf.slice(0, idx).trim();
      buf = buf.slice(idx + 2);
      if (rawEvent.startsWith("data: ")) {
        sseEvents.push(JSON.parse(rawEvent.slice(6)));
      }
    }
  });
});

await new Promise((r) => setTimeout(r, 40));

// 4. Test load_assessment rejections (traversal, outside workspace, invalid schema)
await expectCanvasError(
  () =>
    actions.load_assessment.handler({
      instanceId: "panel-1",
      input: { path: "../outside.json" },
    }),
  "invalid_path"
);

await expectCanvasError(
  () =>
    actions.load_assessment.handler({
      instanceId: "panel-1",
      input: { path: outsidePath },
    }),
  "invalid_path"
);

const invalidSchemaFile = path.join(workspaceDir, "invalid-assessment.json");
fs.writeFileSync(
  invalidSchemaFile,
  JSON.stringify({ kind: "not_an_assessment", schema_version: "1.2", results: [] }),
  "utf8"
);
await expectCanvasError(
  () =>
    actions.load_assessment.handler({
      instanceId: "panel-1",
      input: { path: invalidSchemaFile },
    }),
  "invalid_assessment"
);

// 5. Load valid assessment
const loadResult = await actions.load_assessment.handler({
  instanceId: "panel-1",
  input: { path: assessmentPath },
});

// 6. Filter findings
const filterAll = await actions.filter_findings.handler({
  instanceId: "panel-1",
  input: { outcome: "fail" },
});
const filterReset = await actions.filter_findings.handler({
  instanceId: "panel-1",
  input: { outcome: "", query: "D01.01" },
});

// 7. Select control by upstream_id and test control_not_found
const selected = await actions.select_control.handler({
  instanceId: "panel-1",
  input: { control: "D01.01" },
});
await expectCanvasError(
  () =>
    actions.select_control.handler({
      instanceId: "panel-1",
      input: { control: "NON_EXISTENT_CONTROL" },
    }),
  "control_not_found"
);

// 8. Stage decision (validation + non-committing draft)
await expectCanvasError(
  () =>
    actions.stage_decision.handler({
      instanceId: "panel-1",
      input: {
        control_id: "D01.01",
        kind: "manual",
        decision: "accepted", // invalid for manual
        reviewer: "alice@example.com",
        rationale: "Testing invalid decision enum for manual kind",
        evidence: "https://learn.microsoft.com/azure",
        valid_from: "2026-11-01T00:00:00Z",
        valid_until: "2026-12-01T00:00:00Z",
      },
    }),
  "invalid_decision"
);

await expectCanvasError(
  () =>
    actions.stage_decision.handler({
      instanceId: "panel-1",
      input: {
        control_id: "D01.01",
        kind: "manual",
        decision: "pass",
        reviewer: "alice@example.com",
        rationale: "Testing invalid date order",
        evidence: "https://learn.microsoft.com/azure",
        valid_from: "2026-12-01T00:00:00Z",
        valid_until: "2026-11-01T00:00:00Z",
      },
    }),
  "invalid_decision"
);

const staged = await actions.stage_decision.handler({
  instanceId: "panel-1",
  input: {
    control_id: "D01.01",
    kind: "manual",
    decision: "pass",
    reviewer: "alice@example.com",
    rationale: "Verified in architecture review board.",
    evidence: "https://learn.microsoft.com/azure/cloud-adoption-framework",
    valid_from: "2026-11-01T00:00:00Z",
    valid_until: "2026-12-01T00:00:00Z",
  },
});

// 9. Verify POST /stage rejects invalid Origin and accepts matching Origin
const badOriginPost = await httpRequest(`${baseOrigin}/${token}/stage`, {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    Origin: "http://evil.example.com",
  },
  body: JSON.stringify({}),
});

const stateRes = await httpRequest(`${baseOrigin}/${token}/state`);
const stateJson = JSON.parse(stateRes.body);

// 10. Rehydrate on a second instanceId using the same assessmentPath
const reopened = await canvas.open({
  sessionId: "test-session-1",
  extensionId: "project:landinglens-canvas",
  canvasId: "landinglens",
  instanceId: "panel-2",
  input: { assessmentPath },
});
const reopenedStateRes = await httpRequest(`${reopened.url}state`);
const reopenedState = JSON.parse(reopenedStateRes.body);

await new Promise((r) => setTimeout(r, 40));
sseReq.destroy();
await canvas.onClose({ instanceId: "panel-1" });
await canvas.onClose({ instanceId: "panel-2" });

process.stdout.write(
  JSON.stringify({
    canvasId: canvas.id,
    displayName: canvas.displayName,
    actionNames: canvas.actions.map((a) => a.name),
    tokenLength: token.length,
    noTokenStatus: noTokenRes.status,
    wrongTokenStatus: wrongTokenRes.status,
    badOriginStatus: badOriginPost.status,
    htmlStatus: htmlRes.status,
    cacheControl: htmlRes.headers["cache-control"],
    csp: htmlRes.headers["content-security-policy"],
    htmlBody: htmlRes.body,
    loadResult,
    filterAll,
    filterReset,
    selected,
    staged,
    sseEventCount: sseEvents.length,
    stateRowSample: stateJson.rows[0],
    reopenedDraftExists: Boolean(reopenedState.drafts && reopenedState.drafts[selected.control_id]),
  })
);
"""


class CanvasExtensionTests(unittest.TestCase):
    catalog: dict[str, Any]

    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = load_catalog()

    def test_manifest_and_extension_source_guardrails(self) -> None:
        self.assertTrue(MANIFEST_JSON.is_file())
        manifest = json.loads(MANIFEST_JSON.read_text(encoding="utf-8"))
        self.assertEqual(manifest, {"name": "landinglens-canvas", "version": 1})

        self.assertTrue(EXTENSION_MJS.is_file())
        source = EXTENSION_MJS.read_text(encoding="utf-8")
        self.assertIn("@github/copilot-sdk/extension", source)
        self.assertNotIn("console.log", source)
        self.assertNotIn("innerHTML", source)

    def test_loopback_server_actions_security_and_durable_state(self) -> None:
        with (
            tempfile.TemporaryDirectory() as workspace_tmp,
            tempfile.TemporaryDirectory() as outside_tmp,
        ):
            workspace_root = Path(workspace_tmp)
            outside_root = Path(outside_tmp)

            template = workspace_root / "template.json"
            template.write_text(
                json.dumps(
                    {
                        "resources": [
                            {
                                "type": "Microsoft.Storage/storageAccounts",
                                "apiVersion": "2023-05-01",
                                "name": "stgaccount1",
                                "properties": {
                                    "supportsHttpsTrafficOnly": False,
                                    "minimumTlsVersion": "TLS1_0",
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            evidence = arm_source(
                template,
                scope="/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg1",
            )
            assessment = assess(evidence, self.catalog)
            # Inject an HTTP (non-HTTPS) reference on one result to verify HTTPS-only sanitization
            assessment["results"][0]["references"].append(
                {"guidance": "http://insecure.example.com/guide"}
            )

            assessment_file = workspace_root / "assessment.json"
            assessment_file.write_text(json.dumps(assessment), encoding="utf-8")

            outside_file = outside_root / "outside-assessment.json"
            outside_file.write_text(json.dumps(assessment), encoding="utf-8")

            env = {
                **os.environ,
                "LANDINGLENS_TEST_WORKSPACE": str(workspace_root),
                "LANDINGLENS_TEST_ASSESSMENT": str(assessment_file),
                "LANDINGLENS_TEST_OUTSIDE": str(outside_file),
                "LANDINGLENS_TEST_EXTENSION": str(EXTENSION_MJS),
            }
            proc = subprocess.run(
                ["node", "--input-type=module", "-e", NODE_HARNESS],
                cwd=str(ROOT),
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(
                proc.returncode,
                0,
                msg=f"Node harness failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}",
            )

            result = json.loads(proc.stdout)
            self.assertEqual(result["canvasId"], "landinglens")
            self.assertEqual(result["displayName"], "LandingLens ALZ Workspace")
            self.assertEqual(
                result["actionNames"],
                ["load_assessment", "filter_findings", "select_control", "stage_decision"],
            )
            self.assertEqual(result["tokenLength"], 48)
            self.assertEqual(result["noTokenStatus"], 403)
            self.assertEqual(result["wrongTokenStatus"], 403)
            self.assertEqual(result["badOriginStatus"], 403)
            self.assertEqual(result["htmlStatus"], 200)
            self.assertEqual(result["cacheControl"], "no-store")
            self.assertIn("default-src 'none'", result["csp"])
            self.assertIn("script-src 'nonce-", result["csp"])
            self.assertIn("style-src 'nonce-", result["csp"])
            self.assertIn("connect-src 'self'", result["csp"])
            self.assertIn("base-uri 'none'", result["csp"])
            self.assertIn("form-action 'none'", result["csp"])

            html_body = result["htmlBody"]
            self.assertNotIn("innerHTML", html_body)
            for token_name in (
                "--background-color-default",
                "--text-color-default",
                "--text-color-muted",
                "--border-color-default",
                "--color-focus-outline",
                "--font-sans",
                "--font-mono",
                "--text-body-medium",
                "--true-color-red",
                "--true-color-blue",
            ):
                self.assertIn(token_name, html_body)

            self.assertEqual(
                result["loadResult"],
                {
                    "loaded": True,
                    "catalogVersion": self.catalog["catalog_version"],
                    "controlsCount": 255,
                    "resultsCount": 255,
                },
            )
            self.assertGreaterEqual(result["filterAll"]["matchingCount"], 1)
            self.assertEqual(result["filterReset"]["matchingCount"], 1)

            selected = result["selected"]
            self.assertEqual(selected["upstream_id"], "D01.01")
            self.assertIn("control_id", selected)
            self.assertIn("recommendation", selected)

            staged = result["staged"]
            self.assertEqual(staged["status"], "draft_not_saved_or_approved")
            self.assertFalse(staged["committed"])
            self.assertEqual(staged["draft"]["status"], "draft_not_saved_or_approved")
            self.assertEqual(staged["draft"]["control_id"], selected["control_id"])

            # Verify minimized row projection strips arm_id and evidence_links and non-https URLs
            sample_row = result["stateRowSample"]
            self.assertNotIn("arm_id", sample_row)
            self.assertNotIn("evidence_links", sample_row.get("planned") or {})
            for ref in sample_row.get("references", []):
                self.assertTrue(ref["url"].startswith("https://"))

            # Verify SSE broadcast events and durable artifact rehydration across instances
            self.assertGreaterEqual(result["sseEventCount"], 5)
            self.assertTrue(result["reopenedDraftExists"])
            self.assertFalse((workspace_root / "manual.json").exists())
            self.assertFalse((workspace_root / "exceptions.json").exists())


if __name__ == "__main__":
    unittest.main()
