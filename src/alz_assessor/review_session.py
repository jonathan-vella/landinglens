"""Loopback-only human reviews with transactional local report generation."""

import copy
import hashlib
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

from .contracts import (
    document,
    now,
    parse_document,
    read_document,
    require,
    scope_id,
    timestamp,
    validate,
)
from .engine import assess
from .priorities import SEVERITIES
from .reports import render, render_xlsx
from .review_page import review_page
from .reviews import prepare_reviews, review_context, validate_reviews
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
        evidence_tiers: bool = False,
    ) -> None:
        validate(evidence, "evidence")
        validate(catalog, "catalog")
        if evidence.get("presentation_only") or not isinstance(evidence.get("resources"), list):
            raise InputError("Use saved normalized evidence, not a rendered/minimized report")
        if catalog["schema_version"] != "1.1":
            raise InputError("Interactive reviews require a content-bound version-1.1 catalog")
        self.scope = scope_id(require(evidence, "scope", str))
        from .billing_evidence import minimized_evidence as minimized_budgets
        from .key_lifecycle_evidence import minimized_evidence as minimized_keys

        self.evidence = minimized_keys(minimized_budgets(copy.deepcopy(evidence)))
        self.catalog = copy.deepcopy(catalog)
        self.directory = directory.resolve()
        self.landing_zone, self.max_age_hours, self.clock = landing_zone, max_age_hours, clock
        self.evidence_tiers = evidence_tiers
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
                "design_area": control["design_area"],
                **({"severity": control["severity"]} if "severity" in control else {}),
                "evidence_requirements": control["evidence_requirements"],
                "limitations": control["rationale"],
                "available_evidence": review_context(control, self.evidence),
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
        self.controls.sort(
            key=lambda c: (
                SEVERITIES.index(c.get("severity", "Unknown")),
                "fail" not in c["results"],
                c["label"],
            )
        )
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
            evidence_tiers=self.evidence_tiers,
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
                    "workspace_version": "1.0",
                    "landing_zone": self.landing_zone,
                    "max_age_hours": self.max_age_hours,
                    "evaluated_at": report["generated_at"],
                    **({"evidence_tiers": True} if self.evidence_tiers else {}),
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
            (stage / "tracker.csv").write_text(render(report, "csv"), encoding="utf-8")
            (stage / "tracker.xlsx").write_bytes(render_xlsx(report))
            names = (
                "evidence.json",
                "catalog.json",
                "assessment.json",
                "invocation.json",
                "manual.json",
                "exceptions.json",
            )
            (stage / "session-manifest.json").write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "kind": "review-session-revision",
                        "revision": revision,
                        "files": {
                            name: hashlib.sha256((stage / name).read_bytes()).hexdigest()
                            for name in names
                        },
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
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
        triage = assess(
            self.evidence,
            self.catalog,
            at=at,
            manual=self.reviews["manual"],
            exceptions=self.reviews["exceptions"],
            landing_zone=self.landing_zone,
            max_age_hours=self.max_age_hours,
            evidence_tiers=True,
        )
        tiers = {item["control_id"]: item["tier"] for item in triage["evidence_tiers"]["controls"]}
        reviewed = {
            record["control_id"]
            for record in records
            if not record["requires_review"]
            and record["decision"] in {"pass", "fail", "not_applicable", "accepted", "rejected"}
        }
        controls = [
            {
                **control,
                "tier": tiers[control["control_id"]],
                "review_status": "recorded"
                if control["control_id"] in reviewed
                else "needs-review",
                "kinds": ["exceptions", "manual"]
                if tiers[control["control_id"]] == "signal"
                else control["kinds"],
            }
            for control in self.controls
        ]
        needs_me = [
            control["control_id"] for control in controls if control["control_id"] not in reviewed
        ]
        areas = [
            {
                "name": area,
                "total": sum(
                    control["design_area"] == area and control["lifecycle"] == "active"
                    for control in self.catalog["controls"]
                ),
                "remaining": sum(
                    control["design_area"] == area and control["control_id"] in needs_me
                    for control in controls
                ),
            }
            for area in self.catalog["design_areas"]
        ]
        from .interviews import BANK, prepare_interview, question_bank

        question_bank(self.catalog)
        templates = []
        available = {control["control_id"] for control in controls}
        baseline = self.evaluate(at, {})
        for identity, question in BANK.items():
            selected = [control for control in question["controls"] if control in available]
            if selected:
                templates.append(
                    {
                        "id": identity,
                        "question": question["question"],
                        "template": prepare_interview(
                            baseline, self.catalog, identity, self.scope, selected
                        ),
                    }
                )
        minutes = {"verified": 2, "signal": 5, "needs_decision": 10, "manual": 15}
        return {
            "workspace_version": "1.0",
            "revision": self.revision,
            **({"evidence_tiers": self.report["evidence_tiers"]} if self.evidence_tiers else {}),
            "controls": controls,
            "needs_me": needs_me,
            "areas": areas,
            "interviews": templates,
            "effort_remaining": {
                "minutes": sum(
                    minutes[control["tier"]]
                    for control in controls
                    if control["control_id"] in needs_me
                ),
                "assumption": "Planning estimate only: 2/5/10/15 minutes per remaining "
                "Verified/Signal/Needs decision/manual control, not measured effort.",
            },
            "records": records,
            "scope": self.scope,
            "evaluated_at": at,
        }

    def _apply(
        self, payload: Any, updated: dict[str, Any], at: str, baseline: dict[str, Any]
    ) -> None:
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
        tier = next(
            (
                item["tier"]
                for item in baseline["evidence_tiers"]["controls"]
                if item["control_id"] == control_id
            ),
            None,
        )
        allowed = selected["kinds"] if selected else []
        if tier == "signal":
            allowed = ["exceptions", "manual"]
        if selected is None or kind not in allowed:
            raise InputError("Select an unresolved control and an allowed review kind")
        for field in REVIEW_FIELDS:
            value = require(payload, field, str)
            if len(value) > (200 if field == "reviewer" else 4_000):
                raise InputError(f"{field} exceeds the review field limit")
        entry = prepare_reviews(baseline, self.catalog, [control_id], self.scope, kind)["entries"][
            0
        ]
        entry.pop("preparation")
        entry.update({field: payload[field].strip() for field in REVIEW_FIELDS})
        entry["outcome" if kind == "manual" else "disposition"] = require(payload, "decision", str)
        record = document(kind, schema_version="1.1", entries=[entry])
        validation = validate_reviews(record, self.catalog, self.scope, at)
        if not validation["ready_to_apply"]:
            raise InputError("A saved decision must be active now and bound to this control/scope")
        if timestamp(entry["valid_from"]) > timestamp(at):
            raise InputError("A saved decision cannot start in the future")
        existing = any(e["control_id"] == control_id for e in updated[kind]["entries"])
        if type(payload["replace_existing"]) is not bool or payload["replace_existing"] != existing:
            raise InputError("Explicitly confirm replacement of an existing review")
        updated[kind]["entries"] = [
            e for e in updated[kind]["entries"] if e["control_id"] != control_id
        ] + [entry]
        if len(updated[kind]["entries"]) > 1_000:
            raise InputError("Review document exceeds 1,000 records")

    def save(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise InputError("Supply exactly the documented review fields")
        return self.save_many({"revision": payload.get("revision"), "reviews": [payload]})

    def save_many(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict) or set(payload) != {"revision", "reviews"}:
            raise InputError("Supply exact revision and explicitly selected reviews")
        if type(payload["revision"]) is not int or payload["revision"] != self.revision:
            raise InputError("The review changed in another page; reload before saving")
        reviews = require(payload, "reviews", list)
        if not 1 <= len(reviews) <= 50:
            raise InputError("Select 1-50 explicit bound review decisions")
        at = self.clock()
        baseline = assess(
            self.evidence,
            self.catalog,
            at=at,
            landing_zone=self.landing_zone,
            max_age_hours=self.max_age_hours,
            evidence_tiers=True,
        )
        updated = copy.deepcopy(self.reviews)
        seen = set()
        for review in reviews:
            if not isinstance(review, dict):
                raise InputError("Each selected review must be an object")
            key = (require(review, "control_id", str), require(review, "kind", str))
            if key in seen:
                raise InputError("Duplicate selected review")
            seen.add(key)
            self._apply(review, updated, at, baseline)
        report = self.evaluate(at, updated)
        self._persist(report, updated, self.revision + 1)
        self.revision += 1
        self.reviews, self.report = updated, report
        return self.state()

    def save_interview(self, payload: Any) -> dict[str, Any]:
        from .interviews import compile_interview

        if not isinstance(payload, dict) or set(payload) != {
            "revision",
            "response",
            "replace_existing",
        }:
            raise InputError("Supply exact interview response, revision and replacements")
        if type(payload["revision"]) is not int or payload["revision"] != self.revision:
            raise InputError("The review changed in another page; reload before saving")
        replacements = require(payload, "replace_existing", list)
        if any(not isinstance(item, str) for item in replacements) or len(set(replacements)) != len(
            replacements
        ):
            raise InputError("Interview replacement selections must be unique explicit IDs")
        manual = compile_interview(payload["response"], self.catalog, at=self.clock())
        known = {entry["control_id"] for entry in manual["entries"]}
        if set(replacements) - known:
            raise InputError("Replacement is outside the selected interview")
        return self.save_many(
            {
                "revision": payload["revision"],
                "reviews": [
                    {
                        "revision": payload["revision"],
                        "control_id": entry["control_id"],
                        "kind": "manual",
                        "decision": entry["outcome"],
                        "replace_existing": entry["control_id"] in replacements,
                        **{field: entry[field] for field in REVIEW_FIELDS},
                    }
                    for entry in manual["entries"]
                ],
            }
        )

    @classmethod
    def resume(
        cls, source: Path, directory: Path, *, clock: Callable[[], str] = now
    ) -> "ReviewSession":
        if not source.is_dir() or source.is_symlink() or source.is_junction():
            raise InputError("Resume requires one regular saved revision directory")
        manifest_path = source / "session-manifest.json"
        if (
            not manifest_path.is_file()
            or manifest_path.is_symlink()
            or manifest_path.is_junction()
            or manifest_path.stat().st_nlink != 1
        ):
            raise InputError(
                "Resume requires a regular saved manifest; use explicit files for legacy revisions"
            )
        manifest = read_document(manifest_path)
        names = {
            "evidence.json",
            "catalog.json",
            "assessment.json",
            "invocation.json",
            "manual.json",
            "exceptions.json",
        }
        if (
            not isinstance(manifest, dict)
            or set(manifest) != {"schema_version", "kind", "revision", "files"}
            or (
                manifest["schema_version"] != "1.0"
                or manifest["kind"] != "review-session-revision"
                or not isinstance(manifest["files"], dict)
                or set(manifest["files"]) != names
            )
        ):
            raise InputError(
                "Unsupported saved workspace revision; use explicit legacy input files"
            )
        for name in names:
            path = source / name
            if (
                not path.is_file()
                or path.is_symlink()
                or path.is_junction()
                or path.stat().st_nlink != 1
            ):
                raise InputError("Saved workspace core members must be regular files without links")
            if (
                path.stat().st_size > 8_000_000
                or hashlib.sha256(path.read_bytes()).hexdigest() != manifest["files"][name]
            ):
                raise InputError("Saved workspace content hash or size changed")
        invocation = read_document(source / "invocation.json")
        if (
            not isinstance(invocation, dict)
            or set(invocation)
            - {
                "workspace_version",
                "landing_zone",
                "max_age_hours",
                "evaluated_at",
                "evidence_tiers",
            }
            or invocation.get("workspace_version") != "1.0"
        ):
            raise InputError("Unsupported saved workspace invocation")
        for field in ("landing_zone", "evaluated_at"):
            require(invocation, field, str)
        timestamp(invocation["evaluated_at"])
        if type(invocation.get("max_age_hours")) not in (int, float):
            raise InputError("Saved freshness selection must be numeric")
        if type(manifest["revision"]) is not int or manifest["revision"] < 0:
            raise InputError("Saved revision number must be a nonnegative integer")
        if type(invocation.get("evidence_tiers", False)) is not bool:
            raise InputError("Saved evidence-tier selection must be boolean")
        return cls(
            read_document(source / "evidence.json"),
            read_document(source / "catalog.json"),
            directory,
            manual=read_document(source / "manual.json"),
            exceptions=read_document(source / "exceptions.json"),
            landing_zone=invocation["landing_zone"],
            max_age_hours=invocation["max_age_hours"],
            evidence_tiers=invocation.get("evidence_tiers", False),
            clock=clock,
        )


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
            if route not in {"save", "save-many", "interview", "stop"}:
                self.error(404, "Unknown local review route")
                return
            payload = parse_document(raw.decode("utf-8"))
            if route == "stop":
                if payload != {}:
                    raise InputError("Stop request must be an empty object")
                self.server.stopping = True
                result = {"stopped": True}
            elif route == "save-many":
                result = self.server.session.save_many(payload)
            elif route == "interview":
                result = self.server.session.save_interview(payload)
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
