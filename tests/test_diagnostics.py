import unittest

import test_assessment

from alz_assessor.diagnostics import GUIDANCE, REASON_GROUP, explain
from alz_assessor.engine import assess
from alz_assessor.priorities import sort_key
from alz_assessor.reports import render, report_model


class DiagnosticTests(unittest.TestCase):
    def test_every_registered_reason_has_bounded_safe_guidance(self):
        for reason in REASON_GROUP:
            with self.subTest(reason=reason):
                result = explain(reason)
                self.assertEqual(result["reason"], reason)
                self.assertTrue(result["supported"])
                self.assertTrue(
                    all(
                        len(result[k]) <= 200
                        for k in ("explanation", "required_evidence", "next_action")
                    )
                )
        self.assertEqual(set(GUIDANCE), set(REASON_GROUP.values()))
        for code in (
            "http_403",
            "unsupported_arm_function:someFunction",
            "missing attribute: private",
        ):
            self.assertTrue(explain(code)["supported"])
        result = explain("future_producer_reason")
        self.assertFalse(result["supported"])
        self.assertIn("Unsupported explanation", result["explanation"])
        self.assertEqual(result["reason"], "future_producer_reason")

    def test_guidance_preserves_outcomes_codes_and_all_formats(self):
        fixture = test_assessment.SliceTests()
        fixture.setUp()
        assessment = assess(fixture.source(snapshots=False), fixture.catalog)
        original = [
            (r["control_id"], r["logical_id"], r["planned"]["outcome"], r["planned"]["reason"])
            for r in sorted(assessment["results"], key=sort_key)
        ]
        model = report_model(assessment)
        self.assertEqual(
            original,
            [
                (r["control_id"], r["logical_id"], r["planned"]["outcome"], r["planned"]["reason"])
                for r in model["results"]
            ],
        )
        for format in ("json", "markdown", "html"):
            output = render(assessment, format)
            self.assertIn("required_evidence", output)
            self.assertIn("next_action", output)
            self.assertIn("required module snapshot missing", output)
