import copy
import unittest

from test_contracts import SCOPE, evidence, resource

from alz_assessor.catalog import load_catalog, reviewed_refresh
from alz_assessor.comparison import compare
from alz_assessor.contracts import control_digest, digest, document, validate
from alz_assessor.engine import assess
from alz_assessor.reports import render
from alz_assessor.terraform import InputError

AT = "2026-11-04T00:00:00Z"


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.legacy = load_catalog()
        self.catalog = copy.deepcopy(self.legacy)
        self.catalog.update(schema_version="1.1", catalog_version="test-1.1")
        self.manual = next(c for c in self.catalog["controls"] if not c.get("rule"))
        self.automatic = next(c for c in self.catalog["controls"] if c.get("rule"))

    def review(self, kind="manual", **changes):
        entry = {
            "control_id": self.manual["control_id"],
            "control_sha256": control_digest(self.manual),
            "scope": SCOPE,
            "reviewer": "architecture-reviewer-1",
            "evidence": "review://record-1",
            "rationale": "Explicitly reviewed evidence",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
            "outcome": "pass",
            "disposition": "accepted",
            **changes,
        }
        return document(kind, schema_version="1.1", entries=[entry])

    def row(self, result):
        return next(r for r in result["results"] if r["control_id"] == self.manual["control_id"])

    def test_bound_review_changed_content_expiry_and_legacy_visibility(self):
        review = self.review()
        result = assess(evidence(), self.catalog, manual=review, at=AT)
        self.assertEqual(result["schema_version"], "1.1")
        self.assertEqual(self.row(result)["planned"]["outcome"], "pass")
        self.assertFalse(self.row(result)["planned"]["reviews"][0]["requires_review"])
        self.manual["recommendation"] += " changed"
        result = assess(evidence(), self.catalog, manual=review, at=AT)
        self.assertEqual(self.row(result)["planned"]["outcome"], "manual")
        self.assertEqual(self.row(result)["planned"]["reviews"][0]["binding"], "changed_control")
        expired = self.review(valid_until="2026-02-01T00:00:00Z")
        self.assertEqual(
            self.row(assess(evidence(), self.catalog, manual=expired, at=AT))["planned"]["outcome"],
            "manual",
        )
        review["schema_version"] = "1.0"
        result = self.row(assess(evidence(), self.catalog, manual=review, at=AT))
        self.assertEqual(result["planned"]["reviews"][0]["binding"], "legacy_unbound")
        self.assertIsNone(result["planned"]["reviews"][0]["reviewer"])
        self.assertEqual(result["planned"]["outcome"], "manual")

    def test_scope_and_duplicate_conflicts_are_not_last_writer_wins(self):
        review = self.review(scope=SCOPE.replace("/test", "/other"))
        self.assertEqual(
            self.row(assess(evidence(), self.catalog, manual=review, at=AT))["planned"]["outcome"],
            "manual",
        )
        review["entries"].append(copy.deepcopy(review["entries"][0]))
        with self.assertRaisesRegex(InputError, "Duplicate"):
            validate(review)
        for field in ("control_sha256", "reviewer", "evidence"):
            invalid = self.review()
            invalid["entries"][0].pop(field)
            with self.assertRaises(InputError):
                validate(invalid)

    def test_retirement_keeps_history_and_all_formats_without_active_denominator(self):
        frozen = digest(self.legacy)
        self.manual.update(
            lifecycle="retired", retired_at=AT, retirement_reason="Reviewed upstream removal"
        )
        result = assess(evidence(), self.catalog, at=AT)
        self.assertEqual(result["coverage"]["controls"], 254)
        self.assertEqual(result["coverage"]["retired_controls"], 1)
        self.assertFalse(
            any(r["control_id"] == self.manual["control_id"] for r in result["results"])
        )
        for format in ("json", "markdown", "html"):
            self.assertIn("Reviewed upstream removal", render(result, format))
        self.assertEqual(digest(self.legacy), frozen)
        self.assertEqual(assess(evidence(), self.legacy, at=AT)["coverage"]["controls"], 255)

    def test_exact_matrix_change_review_is_required_and_malformed_reviews_fail_safely(self):
        self.catalog.update(review_state="reviewed", reviewed_at=AT)
        self.automatic["rule"]["expected"] = not self.automatic["rule"]["expected"]
        with self.assertRaises(InputError):
            reviewed_refresh(self.catalog, self.legacy)
        self.catalog["accepted_matrix_sha256"] = digest("matrix")
        old = next(
            c for c in self.legacy["controls"] if c["control_id"] == self.automatic["control_id"]
        )
        self.catalog["change_review"] = {
            "base_sha256": digest(self.legacy),
            "matrix_sha256": digest("matrix"),
            "reviewed_at": AT,
            "reviewer": "maintainer-1",
            "changes": [
                {
                    "control_id": old["control_id"],
                    "before_sha256": control_digest(old),
                    "after_sha256": control_digest(self.automatic),
                    "rationale": "Exact predicate and matrix review",
                }
            ],
        }
        self.assertIn(old["control_id"], reviewed_refresh(self.catalog, self.legacy)["changed"])
        for malformed in (None, [], "bad"):
            candidate = copy.deepcopy(self.catalog)
            candidate["change_review"] = malformed
            with self.assertRaises(InputError):
                reviewed_refresh(candidate, self.legacy)
        self.catalog["change_review"]["changes"] = [None]
        with self.assertRaises(InputError):
            reviewed_refresh(self.catalog, self.legacy)

    def test_incompatible_meanings_cannot_create_drift_or_absence(self):
        item = resource(SCOPE + "/providers/Microsoft.Storage/storageAccounts/test")
        item["properties"] = {"supportsHttpsTrafficOnly": True}
        planned = assess(evidence(resources=[item]), self.catalog, at=AT)
        bundle = evidence(mode="observed", resources=[item])
        observed = assess(bundle, self.catalog, at=AT)
        for r in observed["results"]:
            r["control_sha256"] = digest("changed")
        result = compare(planned, observed, at=AT)
        self.assertTrue(all(r["comparison"] == "not_comparable" for r in result["results"]))
        observed = assess(evidence(mode="observed"), self.catalog, at=AT)
        for r in observed["results"]:
            r["rule_sha256"] = digest("different")
        self.assertNotIn(
            "absent", {r["comparison"] for r in compare(planned, observed, AT)["results"]}
        )
        observed["schema_version"] = "1.0"
        with self.assertRaisesRegex(InputError, "contract versions"):
            compare(planned, observed, AT)

    def test_invalid_versions_and_supersession_fail_as_input_errors(self):
        for version in ([], {}, 1, None):
            with self.assertRaises(InputError):
                validate({**evidence(), "schema_version": version})
        self.manual["superseded_by"] = self.automatic["control_id"]
        self.automatic["superseded_by"] = self.manual["control_id"]
        with self.assertRaisesRegex(InputError, "Cyclic"):
            validate(self.catalog)
