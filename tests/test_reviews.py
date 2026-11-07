import copy
import unittest

from test_contracts import SCOPE, evidence

from alz_assessor.catalog import load_catalog
from alz_assessor.contracts import validate
from alz_assessor.engine import assess
from alz_assessor.reports import render
from alz_assessor.reviews import migrate_reviews, prepare_reviews, validate_reviews
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
            self.assertEqual(row["planned"]["reviews"][0]["rationale"], "Reviewed evidence")
            self.assertEqual(row["planned"]["reviews"][0]["evidence"], "review://record")
            for format in ("json", "markdown", "html", "csv"):
                full_out = render(report, format)
                min_out = render(report, format, minimize=True)
                self.assertIn("reviewer-1", full_out)
                self.assertIn("Reviewed evidence", full_out)
                self.assertNotIn("reviewer-1", min_out)
                self.assertNotIn("Reviewed evidence", min_out)
                self.assertNotIn("review://record", min_out)

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

    def test_migrate_reviews_auto_carries_unchanged_and_requires_confirmation_for_changed(self):
        second_control = next(
            c
            for c in self.catalog["controls"]
            if not c.get("rule") and c["control_id"] != self.control["control_id"]
        )
        record = prepare_reviews(
            self.report,
            self.catalog,
            [self.control["control_id"], second_control["control_id"]],
            SCOPE,
            "manual",
        )
        record.pop("is_template")
        for entry in record["entries"]:
            entry.update(
                reviewer="reviewer-1",
                evidence="review://record",
                rationale="Reviewed evidence",
                valid_from="2026-01-01T00:00:00Z",
                valid_until="2027-01-01T00:00:00Z",
                outcome="pass",
            )
        new_catalog = copy.deepcopy(self.catalog)
        new_catalog["catalog_version"] = "2026-12-01.1"
        target_second = next(
            c for c in new_catalog["controls"] if c["control_id"] == second_control["control_id"]
        )
        target_second["recommendation"] += " (updated wording)"

        migrated = migrate_reviews(record, self.catalog, new_catalog, SCOPE)
        by_id = {r["control_id"]: r for r in migrated["migration"]["records"]}
        self.assertEqual(by_id[self.control["control_id"]]["status"], "unchanged")
        self.assertEqual(
            by_id[second_control["control_id"]]["status"], "changed_requires_confirmation"
        )
        self.assertIn("recommendation", by_id[second_control["control_id"]]["diff"])
        validation = validate_reviews(migrated, new_catalog, SCOPE, AT)
        self.assertFalse(validation["ready_to_apply"])

        confirmed = migrate_reviews(
            record,
            self.catalog,
            new_catalog,
            SCOPE,
            confirmed_controls=[second_control["control_id"]],
        )
        self.assertTrue(validate_reviews(confirmed, new_catalog, SCOPE, AT)["ready_to_apply"])

        legacy = copy.deepcopy(record)
        legacy["schema_version"] = "1.0"
        for entry in legacy["entries"]:
            entry.pop("control_sha256", None)
        with self.assertRaisesRegex(InputError, "--confirm-control"):
            migrate_reviews(legacy, self.catalog, new_catalog, SCOPE)
        legacy_confirmed = migrate_reviews(
            legacy,
            self.catalog,
            new_catalog,
            SCOPE,
            confirmed_controls=[self.control["control_id"], second_control["control_id"]],
        )
        self.assertTrue(
            validate_reviews(legacy_confirmed, new_catalog, SCOPE, AT)["ready_to_apply"]
        )
