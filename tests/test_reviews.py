import copy
import unittest

from test_contracts import SCOPE, evidence

from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import validate
from alz_assessor.engine import assess
from alz_assessor.reports import render
from alz_assessor.reviews import prepare_reviews, validate_reviews
from alz_assessor.terraform import InputError

AT = "2026-11-04T00:00:00Z"


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.catalog = load_catalog()
        self.report = assess(evidence(), self.catalog, at=AT)
        self.control = next(c for c in self.catalog["controls"] if not c.get("rule"))

    def prepare(self, kind="manual"):
        return prepare_reviews(
            self.report,
            self.catalog,
            [self.control["control_id"]],
            SCOPE,
            kind,
        )

    def complete(self, kind="manual"):
        record = self.prepare(kind)
        record.pop("is_template")
        record["entries"][0].update(
            reviewer="reviewer-1",
            evidence="review://record",
            rationale="Reviewed evidence",
            valid_from="2026-01-01T00:00:00Z",
            valid_until="2027-01-01T00:00:00Z",
            **({"outcome": "pass"} if kind == "manual" else {"disposition": "accepted"}),
        )
        return record

    def test_templates_are_deterministic_unasserted_and_not_ingestible(self):
        for kind in ("manual", "exceptions"):
            first = self.prepare(kind)
            self.assertEqual(first, self.prepare(kind))
            for key in ("reviewer", "rationale", "evidence", "valid_from", "valid_until"):
                self.assertIsNone(first["entries"][0][key])
            with self.assertRaisesRegex(InputError, "templates"):
                validate(first)
            with self.assertRaises(InputError):
                assess(evidence(), self.catalog, at=AT, **{kind: first})

    def test_completed_reviews_bind_and_import_without_external_actions(self):
        for kind in ("manual", "exceptions"):
            record = self.complete(kind)
            self.assertTrue(validate_reviews(record, self.catalog, SCOPE, AT)["ready_to_apply"])
            report = assess(evidence(), self.catalog, at=AT, **{kind: record})
            row = next(
                r for r in report["results"] if r["control_id"] == self.control["control_id"]
            )
            self.assertEqual(row["planned"]["outcome"], "pass" if kind == "manual" else "manual")
            for format in ("json", "markdown", "html"):
                self.assertIn("reviewer-1", render(report, format))
                self.assertNotIn("reviewer-1", render(report, format, minimize=True))

    def test_changed_expired_duplicate_and_wrong_scope_reviews(self):
        record = self.complete()
        self.control["recommendation"] += " changed"
        self.assertFalse(validate_reviews(record, self.catalog, SCOPE, AT)["ready_to_apply"])
        record["entries"][0]["valid_until"] = "2026-02-01T00:00:00Z"
        self.assertTrue(
            validate_reviews(record, self.catalog, SCOPE, AT)["records"][0]["requires_review"]
        )
        record["entries"].append(copy.deepcopy(record["entries"][0]))
        with self.assertRaisesRegex(InputError, "Duplicate"):
            validate_reviews(record, self.catalog, SCOPE, AT)
        with self.assertRaises(InputError):
            prepare_reviews(
                self.report,
                self.catalog,
                [self.control["control_id"]],
                SCOPE.replace("/test", "/other"),
            )

    def test_ambiguous_or_retired_selection_and_minimized_reports_fail(self):
        with self.assertRaises(InputError):
            prepare_reviews(self.report, self.catalog, ["does-not-exist"], SCOPE)
        self.report["presentation_only"] = True
        with self.assertRaises(InputError):
            self.prepare()
