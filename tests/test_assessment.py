import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from alz_assessor.catalog import load_catalog
from alz_assessor.cli import main
from alz_assessor.comparison import compare
from alz_assessor.contracts import control_digest, document, now
from alz_assessor.engine import assess
from alz_assessor.reports import render
from alz_assessor.sources import terraform_source

FIXTURES = Path(__file__).parent / "fixtures"
SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"


class SliceTests(unittest.TestCase):
    def setUp(self):
        self.catalog = load_catalog()

    def source(self, secure=True, snapshots=True, scope=SCOPE):
        return terraform_source(
            FIXTURES / "slice",
            scope=scope,
            provider_version="4.50.0",
            snapshots=FIXTURES / "slice" / "snapshots.json" if snapshots else None,
            authorized_roots=[FIXTURES / "alz"],
            variable_inputs=[("var", {"secure": secure})],
        )

    def storage(self, assessment):
        return next(row for row in assessment["results"] if row["upstream_id"] == "G04.01")

    def observed(self, bundle):
        result = json.loads(json.dumps(bundle))
        result["mode"], result["source"], result["collected_at"] = "observed", "saved", now()
        return result

    def test_module_slice_pass_fail_missing_and_no_implicit_network_or_execution(self):
        for value, expected in ((True, "pass"), (False, "fail")):
            with patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden")):
                report = assess(self.source(value), self.catalog)
            self.assertEqual(self.storage(report)["planned"]["outcome"], expected)
        missing = assess(self.source(snapshots=False), self.catalog)
        self.assertEqual(self.storage(missing)["planned"]["outcome"], "unknown")
        self.assertFalse(missing["coverage"]["inventory_complete"])
        self.assertIn("module.security", str(missing))

    def test_match_drift_and_missing_identity_are_not_names(self):
        bundle = self.source()
        observed = self.observed(bundle)
        planned_report = assess(bundle, self.catalog)
        self.assertEqual(
            self.storage(compare(planned_report, assess(observed, self.catalog)))["comparison"],
            "match",
        )
        storage = next(
            r for r in observed["resources"] if r["resource_type"].endswith("storageAccounts")
        )
        storage["properties"]["supportsHttpsTrafficOnly"] = False
        self.assertEqual(
            self.storage(compare(planned_report, assess(observed, self.catalog)))["comparison"],
            "drift",
        )
        unbound = assess(self.source(scope=None), self.catalog)
        self.assertEqual(
            self.storage(compare(unbound, assess(observed, self.catalog)))["comparison"],
            "not_comparable",
        )
        storage["arm_id"] = storage["arm_id"].replace("rg-management", "other-group")
        observed["inventory_complete"] = False
        self.assertEqual(
            self.storage(compare(planned_report, assess(observed, self.catalog)))["comparison"],
            "not_comparable",
        )

    def test_absence_only_for_known_identity_complete_current_observed_inventory(self):
        planned = assess(self.source(), self.catalog)
        observed = self.observed(self.source())
        observed["resources"] = []
        self.assertEqual(
            self.storage(compare(planned, assess(observed, self.catalog)))["comparison"],
            "absent",
        )
        for complete, time in ((False, now()), (True, "2000-01-01T00:00:00Z")):
            observed["inventory_complete"], observed["collected_at"] = complete, time
            self.assertEqual(
                self.storage(compare(planned, assess(observed, self.catalog)))["comparison"],
                "not_comparable",
            )

    def test_exceptions_do_not_rewrite_failures(self):
        bundle = self.source(False)
        entry = {
            "control_id": self.storage(assess(bundle, self.catalog))["control_id"],
            "scope": SCOPE,
            "rationale": "temporary",
            "valid_from": "2020-01-01T00:00:00Z",
            "valid_until": "2099-01-01T00:00:00Z",
            "disposition": "accepted",
            "reviewer": "test-reviewer",
            "evidence": "review://explicit-fixture",
            "control_sha256": control_digest(
                next(
                    control
                    for control in self.catalog["controls"]
                    if control["control_id"]
                    == self.storage(assess(bundle, self.catalog))["control_id"]
                )
            ),
        }
        report = assess(
            bundle,
            self.catalog,
            exceptions=document(
                "exceptions",
                schema_version="1.1",
                entries=[entry],
            ),
        )
        row = self.storage(report)
        self.assertEqual(row["planned"]["outcome"], "fail")
        self.assertEqual(row["planned"]["exception_disposition"], "accepted")

    def test_formats_have_same_outcomes_and_escape_html(self):
        bundle = self.source()
        report = assess(bundle, self.catalog)
        row = self.storage(report)
        row["recommendation"] = '<script>alert("bad")</script>'
        for format in ("json", "markdown", "html"):
            output = render(report, format)
            self.assertIn("explicit_property_matches", output)
            self.assertIn("G04.01", output)
            if format != "json":
                self.assertNotIn("<script>", output)
                self.assertIn("&lt;script&gt;", output)
        self.assertNotIn('"properties":', render(report))

    def test_installed_cli_slice_advisory_exit_in_every_format(self):
        with tempfile.TemporaryDirectory() as directory:
            for value, expected in ((True, "pass"), (False, "fail")):
                arguments = [
                    "assess",
                    str(FIXTURES / "slice"),
                    "--input",
                    "terraform",
                    "--provider-version",
                    "4.50.0",
                    "--scope",
                    SCOPE,
                    "--snapshots",
                    str(FIXTURES / "slice" / "snapshots.json"),
                    "--authorize-root",
                    str(FIXTURES / "alz"),
                    "--var",
                    "secure=" + json.dumps(value),
                ]
                for format in ("json", "markdown", "html"):
                    destination = Path(directory) / ("report." + format)
                    with (
                        patch(
                            "sys.argv",
                            [
                                "alz-assessor",
                                *arguments,
                                "--format",
                                format,
                                "--output",
                                str(destination),
                            ],
                        ),
                        contextlib.redirect_stderr(io.StringIO()),
                    ):
                        self.assertEqual(main(), 0)
                    contents = destination.read_text("utf-8")
                    self.assertIn(expected, contents)
                    self.assertIn("G04.01", contents)


if __name__ == "__main__":
    unittest.main()
