import contextlib
import copy
import http.client
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import UTC, datetime, timedelta
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from alz_assessor.catalog import load_catalog
from alz_assessor.cli import main
from alz_assessor.contracts import control_digest, document, read_document
from alz_assessor.reports import report_model
from alz_assessor.review_page import review_page
from alz_assessor.review_session import MAX_REQUEST, ReviewServer, ReviewSession
from alz_assessor.terraform import InputError

AT = "2026-11-04T00:00:00Z"
UNTIL = "2026-12-04T00:00:00Z"
FIXTURE = Path(__file__).parent / "fixtures" / "slice" / "observed.json"


class ReviewSessionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bundle = read_document(FIXTURE)
        self.bundle["resources"][0]["properties"]["supportsHttpsTrafficOnly"] = False
        self.catalog = load_catalog()
        self.automated = next(c for c in self.catalog["controls"] if c["upstream_id"] == "G04.01")
        self.manual = next(c for c in self.catalog["controls"] if not c.get("rule"))
        self.session = ReviewSession(
            self.bundle, self.catalog, self.root / "session", clock=lambda: AT
        )

    def payload(self, kind="exceptions", control=None, **changes):
        return {
            "revision": self.session.revision,
            "control_id": (control or self.automated)["control_id"],
            "kind": kind,
            "decision": "accepted" if kind == "exceptions" else "pass",
            "reviewer": "Fixture reviewer",
            "evidence": "authored://fixture-owner-statement",
            "rationale": "Authored local test; not a production approval.",
            "valid_from": AT,
            "valid_until": UNTIL,
            "replace_existing": False,
            **changes,
        }

    def test_save_automates_all_formats_preserves_facts_and_other_reviews(self):
        baseline = copy.deepcopy(self.session.report)
        old_bytes = (self.session.directory / "revision-0000" / "assessment.json").read_bytes()
        self.session.save(self.payload())
        self.session.save(self.payload("manual", self.manual))
        for directory in sorted(self.session.directory.glob("revision-*")):
            for name in (
                "evidence.json",
                "catalog.json",
                "assessment.json",
                "manual.json",
                "exceptions.json",
                "invocation.json",
                "report.json",
                "report.md",
                "report.html",
                "report-minimized.html",
            ):
                self.assertTrue((directory / name).is_file(), name)
        self.assertEqual(self.session.revision, 2)
        original = next(
            r for r in baseline["results"] if r["control_id"] == self.automated["control_id"]
        )["observed"]
        updated = next(
            r
            for r in self.session.report["results"]
            if r["control_id"] == self.automated["control_id"]
        )["observed"]
        self.assertEqual(updated["outcome"], "fail")
        self.assertEqual(updated["exception_disposition"], "accepted")
        for field in ("fact", "reason", "evidence_links", "freshness", "inventory_complete"):
            self.assertEqual(updated[field], original[field])
        manual = next(
            r
            for r in self.session.report["results"]
            if r["control_id"] == self.manual["control_id"]
        )["observed"]
        self.assertEqual(manual["outcome"], "pass")
        self.assertEqual(len(self.session.reviews["exceptions"]["entries"]), 1)
        self.assertEqual(self.session.evidence, self.bundle)
        self.assertEqual(
            (self.session.directory / "revision-0000" / "assessment.json").read_bytes(), old_bytes
        )
        minimized = (self.session.directory / "revision-0002" / "report-minimized.html").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("Fixture reviewer", minimized)
        self.assertNotIn(self.bundle["scope"], minimized)

    def test_replacements_require_confirmation_and_stale_pages_cannot_overwrite(self):
        first = self.payload()
        self.session.save(first)
        with self.assertRaisesRegex(InputError, "another page"):
            self.session.save(first)
        with self.assertRaisesRegex(InputError, "confirm replacement"):
            self.session.save(self.payload())
        self.session.save(self.payload(replace_existing=True, rationale="Explicit revision"))
        self.assertEqual(self.session.revision, 2)
        self.assertEqual(len(self.session.reviews["exceptions"]["entries"]), 1)
        self.assertEqual(
            self.session.reviews["exceptions"]["entries"][0]["rationale"], "Explicit revision"
        )

    def test_write_failure_does_not_publish_or_change_memory(self):
        before = self.session.state()
        with patch.object(Path, "rename", side_effect=OSError("test disk failure")):
            with self.assertRaises(OSError):
                self.session.save(self.payload())
        self.assertEqual(self.session.state(), before)
        self.assertEqual([p.name for p in self.session.directory.iterdir()], ["revision-0000"])

    def test_missing_fields_expiry_scope_content_and_decisions_fail_explicitly(self):
        bad = [
            {"decision": ""},
            {"decision": "approved"},
            {"reviewer": ""},
            {"evidence": " "},
            {"rationale": " "},
            {"reviewer": "x" * 201},
            {"valid_from": "2027-01-01T00:00:00Z"},
            {"valid_until": AT},
            {"valid_until": "not-a-date"},
            {"control_id": "unavailable"},
            {"kind": "manual", "decision": "pass"},
            {"revision": True},
            {"replace_existing": True},
            {"scope": self.bundle["scope"]},
            {"control_sha256": "0" * 64},
        ]
        for changes in bad:
            with self.subTest(changes=changes):
                with self.assertRaises(InputError):
                    self.session.save(self.payload(**changes))
                self.assertEqual(self.session.revision, 0)
        self.session.save(self.payload())
        self.session.clock = lambda: UNTIL
        self.assertFalse(self.session.state()["records"][0]["requires_review"])
        # A new evaluation must expire the existing review, not extend its dates.
        self.session.save(
            self.payload(
                "manual", self.manual, valid_from=UNTIL, valid_until="2027-01-01T00:00:00Z"
            )
        )
        old = next(r for r in self.session.state()["records"] if r["kind"] == "exceptions")
        self.assertTrue(old["requires_review"])
        self.assertEqual(old["valid_until"], UNTIL)
        self.assertTrue(
            all(r["observed"]["freshness"] == "stale" for r in self.session.report["results"])
        )

    def test_input_rejects_unscoped_rendered_old_and_duplicate_documents(self):
        unscoped = copy.deepcopy(self.bundle)
        unscoped["scope"] = None
        rendered = report_model(self.session.report)
        minimized = report_model(self.session.report, minimize=True)
        for value in (unscoped, rendered, minimized):
            with self.subTest(kind=value["kind"]):
                with self.assertRaises(InputError):
                    ReviewSession(value, self.catalog, self.root / "invalid", clock=lambda: AT)
                self.assertFalse((self.root / "invalid").exists())
        self.session.save(self.payload())
        valid = self.session.reviews["exceptions"]
        duplicate = copy.deepcopy(valid)
        duplicate["entries"] *= 2
        foreign = copy.deepcopy(valid)
        foreign["entries"][0]["scope"] = self.bundle["scope"].replace("/rg-management", "/other")
        wrong_kind = document("manual", schema_version="1.1", entries=[])
        for supplied in (duplicate, foreign, wrong_kind, {}):
            with self.assertRaises(InputError):
                ReviewSession(
                    self.bundle,
                    self.catalog,
                    self.root / "invalid",
                    exceptions=supplied,
                    clock=lambda: AT,
                )
        old = json.loads(
            files("alz_assessor").joinpath("data", "catalog-2026-11-04.1.json").read_text("utf-8")
        )
        with self.assertRaisesRegex(InputError, "version-1.1"):
            ReviewSession(self.bundle, old, self.root / "invalid", clock=lambda: AT)
        with self.assertRaises(FileExistsError):
            ReviewSession(self.bundle, self.catalog, self.session.directory, clock=lambda: AT)

    def test_existing_reviews_are_retained_changed_bindings_are_not_auto_approved(self):
        self.session.save(self.payload())
        records = copy.deepcopy(self.session.reviews["exceptions"])
        records["entries"][0]["control_sha256"] = "0" * 64
        imported = ReviewSession(
            self.bundle,
            self.catalog,
            self.root / "imported",
            exceptions=records,
            clock=lambda: AT,
        )
        self.assertTrue(imported.state()["records"][0]["requires_review"])
        result = next(
            r for r in imported.report["results"] if r["control_id"] == self.automated["control_id"]
        )["observed"]
        self.assertIsNone(result["exception_disposition"])
        self.assertEqual(imported.reviews["exceptions"], records)
        records["entries"][0]["control_sha256"] = control_digest(self.automated)
        restored = ReviewSession(
            self.bundle,
            self.catalog,
            self.root / "restored",
            exceptions=records,
            clock=lambda: AT,
        )
        self.assertFalse(restored.state()["records"][0]["requires_review"])
        self.assertEqual(restored.reviews["exceptions"], records)

    def start_server(self):
        server = ReviewServer(self.session)

        def run():
            while not server.stopping:
                server.handle_request()
            server.server_close()

        thread = threading.Thread(target=run, daemon=True)
        thread.start()

        def finish():
            server.stopping = True
            thread.join(6)
            self.assertFalse(thread.is_alive())
            server.server_close()

        self.addCleanup(finish)
        return server

    def request(self, server, method="GET", route="", payload=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=10)
        default = (
            {
                "Origin": server.origin,
                "X-LandingLens-Review": server.token,
                "Content-Type": "application/json",
            }
            if method == "POST"
            else {}
        )
        default.update(headers or {})
        try:
            connection.request(
                method,
                server.base_path + route,
                body=json.dumps(payload) if payload is not None else None,
                headers=default,
            )
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read().decode("utf-8")
        finally:
            connection.close()

    def test_http_saves_and_refreshes_report_with_no_arbitrary_file_routes(self):
        server = self.start_server()
        code, headers, page = self.request(server)
        self.assertEqual(code, 200)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn("frame-ancestors 'self'", headers["Content-Security-Policy"])
        self.assertIn("Save review and update reports", page)
        self.assertNotIn("authored://storage-fixture", page)
        self.assertEqual(
            self.request(
                server, headers={"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate"}
            )[0],
            200,
        )
        code, _, body = self.request(server, "POST", "save", self.payload())
        self.assertEqual(code, 200, body)
        self.assertEqual(json.loads(body)["revision"], 1)
        code, _, report = self.request(server, route="report?revision=1")
        self.assertEqual(code, 200)
        self.assertIn("accepted", report)
        self.assertNotIn(self.bundle["scope"], report)
        self.assertEqual(self.request(server, route="../evidence.json")[0], 404)
        self.assertEqual(self.request(server, "POST", "stop", {})[0], 200)

    def test_http_blocks_cross_origin_host_token_invalid_json_and_large_requests(self):
        server = self.start_server()
        for headers in (
            {"Origin": "https://example.invalid"},
            {"Origin": ""},
            {"X-LandingLens-Review": ""},
            {"Host": "example.invalid"},
            {"Sec-Fetch-Site": "cross-site"},
            {"Content-Type": "text/plain"},
        ):
            with self.subTest(headers=headers):
                self.assertEqual(
                    self.request(server, "POST", "save", self.payload(), headers)[0], 403
                )
        self.assertEqual(
            self.request(server, "POST", "save", {"rationale": "x" * MAX_REQUEST})[0], 413
        )
        self.assertEqual(
            self.request(
                server,
                "POST",
                "save",
                self.payload(),
                {
                    "Transfer-Encoding": "chunked",
                    "Content-Length": str(len(json.dumps(self.payload()).encode("utf-8"))),
                },
            )[0],
            403,
        )
        self.assertEqual(self.request(server, "POST", "save", [])[0], 400)
        self.assertEqual(self.session.revision, 0)
        for content in ('{"revision":0,"revision":0}', '{"bad":NaN}', '{"incomplete"'):
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=10)
            try:
                connection.request(
                    "POST",
                    server.base_path + "save",
                    body=content,
                    headers={
                        "Origin": server.origin,
                        "Content-Type": "application/json",
                        "X-LandingLens-Review": server.token,
                    },
                )
                response = connection.getresponse()
                self.assertEqual(response.status, 400)
                response.read()
            finally:
                connection.close()
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=10)
        try:
            connection.request("GET", "/wrong-capability/")
            response = connection.getresponse()
            self.assertEqual(response.status, 403)
            response.read()
        finally:
            connection.close()

    def test_http_disk_failure_is_visible_and_prior_report_is_kept(self):
        server = self.start_server()
        with patch.object(self.session, "_persist", side_effect=OSError("test only")):
            code, _, body = self.request(server, "POST", "save", self.payload())
        self.assertEqual(code, 500)
        self.assertIn("previous revision remains unchanged", body)
        self.assertEqual(self.session.revision, 0)
        self.assertEqual(self.request(server, route="report")[0], 200)

    def test_page_safely_embeds_untrusted_text_and_has_no_network_assets(self):
        state = self.session.state()
        state["controls"][0]["label"] = '</script><img src="https://evil.invalid" onerror="x">'
        page = review_page(state, "test-capability", "test-nonce")
        self.assertNotIn(state["controls"][0]["label"], page)
        self.assertIn("\\u003c/script\\u003e", page)
        self.assertNotIn("innerHTML", page)
        self.assertNotIn("<script src=", page)
        self.assertNotIn("<link ", page)
        self.assertIn('nonce="test-nonce"', page)
        self.assertIn('role="status"', page)
        self.assertNotIn('value="accepted"', page)

    def test_cli_retains_prepare_validate_and_rejects_invalid_serve_options(self):
        source = self.root / "evidence.json"
        source.write_text(json.dumps(self.bundle), encoding="utf-8")
        for options in (
            ["serve", source],
            ["serve", source, "--directory", self.root / "new", "--scope", self.bundle["scope"]],
            ["prepare", source],
        ):
            stderr = io.StringIO()
            with (
                patch("sys.argv", ["alz-assessor", "review", *map(str, options)]),
                contextlib.redirect_stderr(stderr),
            ):
                self.assertEqual(main(), 2)
            self.assertIn("Input error:", stderr.getvalue())

    def test_cli_installed_workflow_runs_outside_checkout_and_stops_cleanly(self):
        source = self.root / "evidence.json"
        live_time = datetime.now(UTC)
        bundle = copy.deepcopy(self.bundle)
        bundle["collected_at"] = live_time.isoformat()
        source.write_text(json.dumps(bundle), encoding="utf-8")
        log_path = self.root / "server.log"
        output = self.root / "cli-output"
        with log_path.open("w", encoding="utf-8") as log:
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "alz_assessor.cli",
                    "review",
                    "serve",
                    str(source),
                    "--directory",
                    str(output),
                    "--no-browser",
                ],
                stdout=log,
                stderr=log,
                cwd=self.root,
                env=os.environ.copy(),
            )
            try:
                url = None
                for _ in range(200):
                    content = log_path.read_text(encoding="utf-8")
                    line = next(
                        (s for s in content.splitlines() if s.startswith("Local review: ")), None
                    )
                    if line:
                        url = line.removeprefix("Local review: ")
                        break
                    if process.poll() is not None:
                        self.fail(content)
                    time.sleep(0.05)
                self.assertIsNotNone(url, log_path.read_text(encoding="utf-8"))
                parsed = urlsplit(url)
                connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
                try:
                    connection.request("GET", parsed.path)
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    response.read()
                    submission = self.payload(
                        valid_from=live_time.isoformat(),
                        valid_until=(live_time + timedelta(days=30)).isoformat(),
                    )
                    headers = {
                        "Origin": f"http://{parsed.netloc}",
                        "X-LandingLens-Review": parsed.path.strip("/"),
                        "Content-Type": "application/json",
                    }
                    connection.request(
                        "POST", parsed.path + "save", body=json.dumps(submission), headers=headers
                    )
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200, response.read().decode())
                    saved = read_document(output / "revision-0001" / "assessment.json")
                    result = next(
                        r
                        for r in saved["results"]
                        if r["control_id"] == self.automated["control_id"]
                    )["observed"]
                    self.assertEqual(result["outcome"], "fail")
                    self.assertEqual(result["exception_disposition"], "accepted")
                    connection.request(
                        "POST",
                        parsed.path + "stop",
                        body="{}",
                        headers=headers,
                    )
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    response.read()
                finally:
                    connection.close()
                self.assertEqual(process.wait(timeout=10), 0)
                self.assertTrue((output / "revision-0000" / "report.html").is_file())
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)
