"""Loopback-only human reviews with transactional local report generation."""

import copy
import json
import secrets
import shutil
import tempfile
import webbrowser
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .contracts import document, now, parse_document, require, scope_id, timestamp, validate
from .engine import assess
from .reports import render
from .review_page import review_page
from .reviews import prepare_reviews, validate_reviews
from .terraform import InputError

MAX_REQUEST = 32_000
REVIEW_FIELDS = ("reviewer", "evidence", "rationale", "valid_from", "valid_until")


class ReviewSession:
    def __init__(
        self,
        evidence: dict[str, Any],
        catalog: dict[str, Any],
        directory: Path,
        *,
        manual: dict[str, Any] | None = None,
        exceptions: dict[str, Any] | None = None,
        landing_zone: str = "platform",
        max_age_hours: float = 24,
        clock: Callable[[], str] = now,
    ) -> None:
        validate(evidence, "evidence")
        validate(catalog, "catalog")
        if evidence.get("presentation_only") or not isinstance(evidence.get("resources"), list):
            raise InputError("Use saved normalized evidence, not a rendered/minimized report")
        if catalog["schema_version"] != "1.1":
            raise InputError("Interactive reviews require a content-bound version-1.1 catalog")
        self.scope = scope_id(require(evidence, "scope", str))
        self.evidence, self.catalog = copy.deepcopy(evidence), copy.deepcopy(catalog)
        self.directory = directory.resolve()
        self.landing_zone, self.max_age_hours, self.clock = landing_zone, max_age_hours, clock
        self.revision = 0
        self.reviews = {
            "manual": copy.deepcopy(
                manual
                if manual is not None
                else document("manual", schema_version="1.1", entries=[])
            ),
            "exceptions": copy.deepcopy(
                exceptions
                if exceptions is not None
                else document("exceptions", schema_version="1.1", entries=[])
            ),
        }
        at = self.clock()
        for kind, records in self.reviews.items():
            validate(records, kind)
            if records["schema_version"] != "1.1" or len(records["entries"]) > 1_000:
                raise InputError("Supply at most 1,000 content-bound reviews per document")
            validate_reviews(records, self.catalog, self.scope, at)
        baseline = self.evaluate(at, {})
        unresolved = {
            row["control_id"]
            for row in baseline["results"]
            if row[self.evidence["mode"]]["outcome"] in {"manual", "unknown", "error", "fail"}
        }
        self.controls = [
            {
                "control_id": control["control_id"],
                "label": control["upstream_id"] + ": " + control["recommendation"],
                "kinds": ["exceptions"] if control.get("rule") else ["exceptions", "manual"],
                "results": sorted(
                    {
                        row[self.evidence["mode"]]["outcome"]
                        for row in baseline["results"]
                        if row["control_id"] == control["control_id"]
                    }
                ),
            }
            for control in self.catalog["controls"]
            if control["control_id"] in unresolved
            and control["lifecycle"] == "active"
            and landing_zone in control["applicability"]
        ]
        self.controls.sort(key=lambda c: ("fail" not in c["results"], c["label"]))
        self.report = self.evaluate(at, self.reviews)
        self.directory.mkdir(exist_ok=False)
        self._persist(self.report, self.reviews, self.revision)

    def evaluate(self, at: str, reviews: dict[str, dict[str, Any]]) -> dict[str, Any]:
        return assess(
            self.evidence,
            self.catalog,
            at=at,
            landing_zone=self.landing_zone,
            max_age_hours=self.max_age_hours,
            manual=reviews.get("manual"),
            exceptions=reviews.get("exceptions"),
        )

    def _persist(
        self, report: dict[str, Any], reviews: dict[str, dict[str, Any]], revision: int
    ) -> None:
        destination = self.directory / f"revision-{revision:04d}"
        if destination.exists():
            raise InputError("Review revision already exists; no files were overwritten")
        stage = Path(tempfile.mkdtemp(prefix=".pending-", dir=self.directory))
        try:
            for name, value in {
                "evidence": self.evidence,
                "catalog": self.catalog,
                "assessment": report,
                "invocation": {
                    "landing_zone": self.landing_zone,
                    "max_age_hours": self.max_age_hours,
                    "evaluated_at": report["generated_at"],
                },
                **reviews,
            }.items():
                content = json.dumps(value, indent=2, allow_nan=False) + "\n"
                if len(content.encode("utf-8")) > 8_000_000:
                    raise InputError("Saved review document exceeds the 8-MB input limit")
                (stage / f"{name}.json").write_text(content, encoding="utf-8")
            for format, extension in (("json", "json"), ("markdown", "md"), ("html", "html")):
                (stage / f"report.{extension}").write_text(render(report, format), encoding="utf-8")
            (stage / "report-minimized.html").write_text(
                render(report, "html", minimize=True), encoding="utf-8"
            )
            stage.rename(destination)
        finally:
            if stage.exists():
                shutil.rmtree(stage)

    def state(self) -> dict[str, Any]:
        records = []
        at = self.report["generated_at"]
        for kind, reviews in self.reviews.items():
            checks = validate_reviews(reviews, self.catalog, self.scope, at)["records"]
            for entry, check in zip(reviews["entries"], checks, strict=True):
                records.append(
                    {
                        "kind": kind,
                        "control_id": entry["control_id"],
                        "decision": entry.get("outcome" if kind == "manual" else "disposition"),
                        **{field: entry[field] for field in REVIEW_FIELDS},
                        "requires_review": check["requires_review"],
                    }
                )
        return {
            "revision": self.revision,
            "controls": self.controls,
            "records": records,
            "scope": self.scope,
            "evaluated_at": at,
        }

    def save(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict) or set(payload) != {
            "revision",
            "control_id",
            "kind",
            "decision",
            "replace_existing",
            *REVIEW_FIELDS,
        }:
            raise InputError("Supply exactly the documented review fields")
        if type(payload["revision"]) is not int or payload["revision"] != self.revision:
            raise InputError("The review changed in another page; reload before saving")
        kind = require(payload, "kind", str)
        control_id = require(payload, "control_id", str)
        selected = next((c for c in self.controls if c["control_id"] == control_id), None)
        if selected is None or kind not in selected["kinds"]:
            raise InputError("Select an unresolved control and an allowed review kind")
        for field in REVIEW_FIELDS:
            value = require(payload, field, str)
            if len(value) > (200 if field == "reviewer" else 4_000):
                raise InputError(f"{field} exceeds the review field limit")
        at = self.clock()
        entry = prepare_reviews(
            self.evaluate(at, {}), self.catalog, [control_id], self.scope, kind
        )["entries"][0]
        entry.pop("preparation")
        entry.update({field: payload[field].strip() for field in REVIEW_FIELDS})
        entry["outcome" if kind == "manual" else "disposition"] = require(payload, "decision", str)
        record = document(kind, schema_version="1.1", entries=[entry])
        validation = validate_reviews(record, self.catalog, self.scope, at)
        if not validation["ready_to_apply"]:
            raise InputError("A saved decision must be active now and bound to this control/scope")
        if timestamp(entry["valid_from"]) > timestamp(at):
            raise InputError("A saved decision cannot start in the future")
        updated = copy.deepcopy(self.reviews)
        existing = any(e["control_id"] == control_id for e in updated[kind]["entries"])
        if type(payload["replace_existing"]) is not bool or payload["replace_existing"] != existing:
            raise InputError("Explicitly confirm replacement of an existing review")
        updated[kind]["entries"] = [
            e for e in updated[kind]["entries"] if e["control_id"] != control_id
        ] + [entry]
        if len(updated[kind]["entries"]) > 1_000:
            raise InputError("Review document exceeds 1,000 records")
        report = self.evaluate(at, updated)
        self._persist(report, updated, self.revision + 1)
        self.revision += 1
        self.reviews, self.report = updated, report
        return self.state()


class ReviewServer(HTTPServer):
    def __init__(self, session: ReviewSession) -> None:
        super().__init__(("127.0.0.1", 0), ReviewHandler)
        self.session = session
        self.token = secrets.token_urlsafe(32)
        self.origin = f"http://127.0.0.1:{self.server_port}"
        self.base_path = "/" + self.token + "/"
        self.url = self.origin + self.base_path
        self.stopping = False
        self.timeout = 0.5


class ReviewHandler(BaseHTTPRequestHandler):
    server: ReviewServer

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, format: str, *args: Any) -> None:
        # Standard request logs would disclose the per-session capability.
        return

    def respond(self, status: int, content: str, mime: str, nonce: str = "") -> None:
        data = content.encode("utf-8")
        self.send_response(status)
        for name, value in {
            "Content-Type": mime + "; charset=utf-8",
            "Content-Length": str(len(data)),
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": (
                "default-src 'none'; "
                f"script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
                "connect-src 'self'; frame-src 'self'; frame-ancestors 'self'; "
                "form-action 'none'; base-uri 'none'"
                if nonce
                else "frame-ancestors 'self'; base-uri 'none'; form-action 'none'"
            ),
        }.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def error(self, status: int, message: str) -> None:
        self.respond(status, json.dumps({"error": message}), "application/json")

    def allowed(self) -> bool:
        if self.headers.get_all("Host") != [
            urlsplit(self.server.origin).netloc
        ] or not self.path.startswith(self.server.base_path):
            self.error(403, "Local session access refused")
            return False
        return True

    def do_GET(self) -> None:
        if not self.allowed():
            return
        route = urlsplit(self.path).path.removeprefix(self.server.base_path)
        if route == "":
            nonce = secrets.token_urlsafe(24)
            self.respond(
                200,
                review_page(self.server.session.state(), self.server.token, nonce),
                "text/html",
                nonce,
            )
        elif route in {"report", "full-report"}:
            self.respond(
                200,
                render(self.server.session.report, "html", minimize=route == "report"),
                "text/html",
            )
        else:
            self.error(404, "Unknown local review route")

    def do_POST(self) -> None:
        try:
            if len(self.headers.get_all("Content-Length", [])) != 1:
                self.error(400, "One explicit content length is required")
                return
            length = int(self.headers["Content-Length"])
            if not 0 < length <= MAX_REQUEST:
                # Drain a small rejected body so Windows can deliver the error without a TCP reset.
                if 0 < length <= MAX_REQUEST * 2:
                    self.rfile.read(length)
                self.error(413, "Review request exceeds the byte limit")
                return
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise InputError("Incomplete review request")
            if not self.allowed():
                return
            if (
                self.headers.get_all("Origin") != [self.server.origin]
                or self.headers.get_all("X-LandingLens-Review") != [self.server.token]
                or self.headers.get_all("Content-Type") != ["application/json"]
                or self.headers.get("Sec-Fetch-Site") not in {None, "none", "same-origin"}
                or self.headers.get("Transfer-Encoding") is not None
            ):
                self.error(403, "Same-origin JSON review submission required")
                return
            route = self.path.removeprefix(self.server.base_path)
            if route not in {"save", "stop"}:
                self.error(404, "Unknown local review route")
                return
            payload = parse_document(raw.decode("utf-8"))
            if route == "stop":
                if payload != {}:
                    raise InputError("Stop request must be an empty object")
                self.server.stopping = True
                result = {"stopped": True}
            else:
                result = self.server.session.save(payload)
        except (InputError, ValueError, UnicodeError) as exc:
            self.error(400, str(exc))
            return
        except OSError:
            self.error(500, "Review could not be saved; previous revision remains unchanged")
            return
        self.respond(200, json.dumps(result, allow_nan=False), "application/json")


def serve_reviews(session: ReviewSession, *, open_browser: bool = True) -> None:
    with ReviewServer(session) as server:
        print(f"Local review: {server.url}", flush=True)
        print(f"Private revision files: {session.directory}", flush=True)
        print("Stop in the page or press Ctrl+C. No Azure operations are performed.", flush=True)
        if open_browser and not webbrowser.open(server.url):
            print("Browser did not open; open the local review URL above.", flush=True)
        try:
            while not server.stopping:
                server.handle_request()
        except KeyboardInterrupt:
            print("Local review stopped; saved revisions remain on disk.", flush=True)
