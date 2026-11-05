import copy
import http.client
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from alz_assessor.azure import Response
from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import document
from alz_assessor.query_signals import execute_query
from alz_assessor.review_page import review_page
from alz_assessor.review_session import ReviewServer, ReviewSession
from alz_assessor.terraform import InputError

AT = "2026-11-05T00:00:00Z"
SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"


def fixture_bundle(at=AT):
    return document(
        "evidence",
        schema_version="1.1",
        mode="observed",
        source="saved",
        collected_at=at,
        scope=SCOPE,
        inventory_complete=False,
        artifact_hashes={"fixture": "0" * 64},
        diagnostics=[],
        resources=[
            {
                "logical_id": "vault",
                "arm_id": SCOPE + "/providers/Microsoft.KeyVault/vaults/authored",
                "resource_type": "Microsoft.KeyVault/vaults",
                "state": "known",
                "reason": "",
                "source_location": "fixture://authored-vault",
                "properties": {
                    "enableRbacAuthorization": True,
                    "publicNetworkAccess": "Disabled",
                    "networkAcls": {"defaultAction": "Deny"},
                },
            }
        ],
    )


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.catalog = load_catalog()
        self.session = ReviewSession(
            fixture_bundle(),
            self.catalog,
            self.root / "session",
            clock=lambda: AT,
            evidence_tiers=True,
        )

    def payload(self, identity, outcome="pass", **changes):
        return {
            "revision": self.session.revision,
            "control_id": identity,
            "kind": "manual",
            "decision": outcome,
            "replace_existing": False,
            "reviewer": "Authored fixture reviewer",
            "rationale": "Authored test, not a real approval.",
            "evidence": "https://example.invalid/authored-evidence",
            "valid_from": AT,
            "valid_until": "2026-11-06T00:00:00Z",
            **changes,
        }

    def signals(self):
        return [
            control["control_id"]
            for control in self.session.state()["controls"]
            if control["tier"] == "signal"
        ]

    def test_three_pane_state_progress_priority_and_honest_effort_estimate(self):
        state = self.session.state()
        self.assertEqual(state["workspace_version"], "1.0")
        self.assertEqual(sum(area["total"] for area in state["areas"]), 255)
        self.assertEqual(len(self.signals()), 2)
        self.assertEqual(state["records"], [])
        self.assertIn("not measured effort", state["effort_remaining"]["assumption"])
        self.assertEqual(sum(area["remaining"] for area in state["areas"]), len(state["needs_me"]))
        html = review_page(state, "fixture-token", "fixture-nonce")
        for expected in (
            "workspace-grid",
            "Design-area progress",
            "Needs me",
            "Evidence and decisions",
            "tier-filter",
            "severity-filter",
            "Alt+Up",
            "interview-save",
            "bulk-save",
        ):
            self.assertIn(expected, html)
        self.assertNotIn("innerHTML", html)
        self.assertIn("else if (visible.length) control.selectedIndex = 0", html)

    def test_atomic_bulk_explicit_outcomes_preserve_previous_revision_and_exports(self):
        identities = self.signals()
        before = (self.session.directory / "revision-0000/assessment.json").read_bytes()
        payload = {
            "revision": 0,
            "reviews": [
                self.payload(identities[0], "pass"),
                self.payload(identities[1], "fail"),
            ],
        }
        state = self.session.save_many(payload)
        self.assertEqual(self.session.revision, 1)
        self.assertEqual(len(state["records"]), 2)
        self.assertFalse(any(identity in state["needs_me"] for identity in identities))
        self.assertEqual(
            (self.session.directory / "revision-0000/assessment.json").read_bytes(), before
        )
        for name in ("tracker.csv", "tracker.xlsx", "session-manifest.json"):
            self.assertTrue((self.session.directory / "revision-0001" / name).is_file())
        self.assertFalse(
            any(
                row["observed"]["evidence_tier"] == "verified"
                for row in self.session.report["results"]
                if row["control_id"] in identities
            )
        )
        with self.assertRaisesRegex(InputError, "another page"):
            self.session.save_many(payload)

    def test_confirming_automated_query_signal_never_overrides_technical_unknown(self):
        guid = "e9c8f584-6d5e-473b-8dc5-acc9fbaab4e3"
        bundle = execute_query(
            lambda *args: Response(
                200,
                {
                    "data": [
                        {
                            "id": SCOPE + "/providers/Microsoft.Network/firewallPolicies/authored",
                            "compliant": True,
                        }
                    ],
                    "count": 1,
                    "totalRecords": 1,
                    "resultTruncated": False,
                },
                {},
            ),
            guid,
            ["00000000-0000-0000-0000-000000000001"],
            at=AT,
        )
        session = ReviewSession(
            bundle, self.catalog, self.root / "query-session", clock=lambda: AT, evidence_tiers=True
        )
        identity = "ALZ-" + guid
        self.assertIn(
            "manual",
            next(row for row in session.state()["controls"] if row["control_id"] == identity)[
                "kinds"
            ],
        )
        session.save_many({"revision": 0, "reviews": [self.payload(identity)]})
        row = next(row for row in session.report["results"] if row["control_id"] == identity)
        self.assertEqual(row["observed"]["outcome"], "unknown")
        self.assertEqual(row["observed"]["evidence_tier"], "signal")
        self.assertEqual(session.state()["records"][0]["decision"], "pass")

    def test_bulk_partial_invalid_replacement_and_duplicates_write_nothing(self):
        identities = self.signals()
        before = self.session.state()
        for reviews in (
            [self.payload(identities[0]), self.payload(identities[1], "")],
            [self.payload(identities[0]), self.payload(identities[0])],
            [self.payload(identities[0], valid_until="2000-01-01T00:00:00Z")],
        ):
            with self.assertRaises(InputError):
                self.session.save_many({"revision": 0, "reviews": reviews})
            self.assertEqual(self.session.state(), before)
            self.assertEqual(len(list(self.session.directory.glob("revision-*"))), 1)
        self.session.save_many({"revision": 0, "reviews": [self.payload(identities[0])]})
        with self.assertRaisesRegex(InputError, "replacement"):
            self.session.save_many({"revision": 1, "reviews": [self.payload(identities[0])]})
        self.session.save_many(
            {
                "revision": 1,
                "reviews": [
                    self.payload(identities[0], "fail", replace_existing=True),
                ],
            }
        )
        self.assertEqual(self.session.revision, 2)

    def test_interview_and_verified_resume_preserve_bindings_and_original_times(self):
        template = copy.deepcopy(
            next(
                item
                for item in self.session.state()["interviews"]
                if item["id"] == "private-service-paths"
            )["template"]
        )
        fields = self.payload("unused")
        template.update(
            {
                key: fields[key]
                for key in ("reviewer", "rationale", "evidence", "valid_from", "valid_until")
            }
        )
        template["answer"] = "Authored private-path fixture reviewed, not a production statement."
        for decision in template["decisions"]:
            decision["outcome"] = "unknown"
        self.session.save_interview({"revision": 0, "response": template, "replace_existing": []})
        source = self.session.directory / "revision-0001"
        original = (source / "evidence.json").read_bytes()
        resumed = ReviewSession.resume(
            source, self.root / "resumed", clock=lambda: "2026-11-07T00:00:00Z"
        )
        self.assertEqual(resumed.evidence["collected_at"], AT)
        self.assertEqual(len(resumed.reviews["manual"]["entries"]), 2)
        self.assertTrue(all(record["requires_review"] for record in resumed.state()["records"]))
        self.assertEqual((source / "evidence.json").read_bytes(), original)
        (source / "manual.json").write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(InputError, "hash or size"):
            ReviewSession.resume(source, self.root / "bad", clock=lambda: AT)
        self.assertFalse((self.root / "bad").exists())

    def test_fixed_http_bulk_route_retains_origin_and_invalid_input_guards(self):
        server = ReviewServer(self.session)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            identity = self.signals()[0]
            payload = json.dumps({"revision": 0, "reviews": [self.payload(identity)]})
            for origin, expected in (("https://example.invalid", 403), (server.origin, 200)):
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=10)
                connection.request(
                    "POST",
                    server.base_path + "save-many",
                    payload,
                    {
                        "Origin": origin,
                        "Content-Type": "application/json",
                        "X-LandingLens-Review": server.token,
                    },
                )
                response = connection.getresponse()
                self.assertEqual(response.status, expected)
                response.read()
                connection.close()
            self.assertEqual(self.session.revision, 1)
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    def test_installed_resume_cli_uses_only_saved_invocation_and_rejects_tampering(self):
        source = self.session.directory / "revision-0000"
        (source / "invocation.json").write_text("{}", encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "alz_assessor.cli",
                "review",
                "serve",
                str(source),
                "--resume",
                "--directory",
                str(self.root / "cli-resume"),
                "--no-browser",
            ],
            cwd=self.root,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("hash or size", result.stderr)
        self.assertFalse((self.root / "cli-resume").exists())
