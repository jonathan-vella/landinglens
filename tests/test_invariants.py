import json
import tempfile
import unittest
from pathlib import Path

import test_contracts as helpers

from alz_assessor.catalog import load_catalog
from alz_assessor.engine import assess
from alz_assessor.reports import render
from alz_assessor.terraform import Analyzer, Limits

AT = "2026-11-04T01:00:00Z"


class InvariantTests(unittest.TestCase):
    def setUp(self):
        self.catalog = load_catalog()

    def storage(self, bundle):
        report = assess(bundle, self.catalog, at=AT)
        row = next(item for item in report["results"] if item["upstream_id"] == "G04.01")
        return report, row["planned"]["outcome"]

    def test_strict_booleans_unknown_states_and_evidence_loss(self):
        for value in (True, False, 0, 1, "true", "false", None, [], {}, {"unknown": "missing"}):
            resource = helpers.resource()
            resource["properties"] = {"supportsHttpsTrafficOnly": value}
            bundle = helpers.evidence(resources=[resource], complete=False)
            _, outcome = self.storage(bundle)
            self.assertEqual(
                outcome,
                "pass" if value is True else "fail" if value is False else "unknown",
            )
            for state in ("unknown", "inaccessible", "error"):
                resource["state"], resource["reason"] = state, state
                self.assertEqual(
                    self.storage(bundle)[1], "error" if state == "error" else "unknown"
                )
            resource["state"], resource["reason"] = "known", ""
            bundle["collected_at"] = "2025-01-01T00:00:00Z"
            self.assertEqual(self.storage(bundle)[1], "unknown")
            bundle["resources"] = []
            self.assertEqual(self.storage(bundle)[1], "unknown")

    def test_irrelevant_properties_never_leak_into_any_report(self):
        for index in range(12):
            sentinel = "PRIVATE-variable-" + str(index)
            resource = helpers.resource()
            resource["properties"] = {
                "supportsHttpsTrafficOnly": True,
                "password": sentinel,
                "extra": {"deep": [sentinel]},
            }
            bundle = helpers.evidence(resources=[resource], complete=False)
            bundle["metadata"] = {"unapproved": sentinel}
            report, outcome = self.storage(bundle)
            self.assertEqual(outcome, "pass")
            for format in ("json", "markdown", "html"):
                for minimize in (True, False):
                    output = render(report, format, minimize)
                    self.assertNotIn(sentinel, output)
                    if format == "json" and minimize:
                        self.assertTrue(json.loads(output)["presentation_only"])

    def test_generated_expansions_are_globally_bounded(self):
        for count in (0, 1, 3, 4, 17, 1000000):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "main.tf").write_text(
                    f'resource "test" "bounded" {{ count = {count} }}',
                    encoding="utf-8",
                )
                result = Analyzer(root, limits=Limits(instances=3)).analyze()
                self.assertLessEqual(len(result["resources"]), 3)
                if count > 3:
                    self.assertTrue(result["diagnostics"])
