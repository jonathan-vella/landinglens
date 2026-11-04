import hashlib
import json
import unittest
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "references" / "2026-11-04"


class ReferenceTests(unittest.TestCase):
    def test_source_and_license_hashes(self):
        manifest = json.loads((SNAPSHOT / "manifest.json").read_text(encoding="utf-8"))
        for source in manifest["sources"]:
            with self.subTest(source=source["id"]):
                self.assertTrue(source["url"].startswith("https://"))
                self.assertEqual(len(source["sha256"]), 64)
                self.assertIsNotNone(datetime.fromisoformat(source["retrieved_at"]).tzinfo)
                self.assertEqual(source["review_state"], "reviewed-see-review.md")
                if "file" in source:
                    self.assertEqual(
                        hashlib.sha256((SNAPSHOT / source["file"]).read_bytes()).hexdigest(),
                        source["sha256"],
                    )
                    self.assertEqual(
                        hashlib.sha256(
                            (SNAPSHOT / source["license_file"]).read_bytes()
                        ).hexdigest(),
                        source["license_sha256"],
                    )
        self.assertEqual(
            hashlib.sha256((SNAPSHOT / "inventory.json").read_bytes()).hexdigest(),
            manifest["inventory_sha256"],
        )

    def test_complete_inventory_and_per_item_provenance(self):
        checklist = json.loads((SNAPSHOT / "alz-checklist.json").read_text(encoding="utf-8"))
        inventory = json.loads((SNAPSHOT / "inventory.json").read_text(encoding="utf-8"))
        manifest = json.loads((SNAPSHOT / "manifest.json").read_text(encoding="utf-8"))
        source = next(s for s in manifest["sources"] if s["id"] == "alz-checklist")
        self.assertEqual(len(checklist["items"]), 255)
        self.assertEqual(len(inventory["items"]), 255)
        self.assertEqual(len({row["upstream_guid"] for row in inventory["items"]}), 255)
        for index, (item, row) in enumerate(
            zip(
                checklist["items"],
                inventory["items"],
                strict=True,
            )
        ):
            with self.subTest(guid=item["guid"]):
                self.assertEqual(row["upstream_guid"], item["guid"])
                self.assertEqual(row["upstream_id"], item["id"])
                self.assertEqual(row["pointer"], f"/items/{index}")
                self.assertEqual(
                    row["item_sha256"],
                    hashlib.sha256(
                        json.dumps(item, sort_keys=True, separators=(",", ":")).encode(),
                    ).hexdigest(),
                )
                self.assertTrue(row["disposition"].startswith("candidate-"))
                self.assertTrue(row["retrieved_at"])
                self.assertTrue(row["reason"])
                self.assertEqual(len(row["source_sha256"]), 64)
                self.assertEqual(row["source_sha256"], source["sha256"])
                self.assertEqual(row["source_revision"], source["revision"])
                self.assertEqual(row["retrieved_at"], source["retrieved_at"])
                self.assertEqual(row["mapping_state"], "candidate-not-verified")
        self.assertEqual(
            inventory["duplicate_display_ids"],
            {
                "B03.02": 2,
                "D05.08": 2,
                "D07.12": 2,
            },
        )
        self.assertEqual(
            inventory["item_field_occurrences"],
            dict(Counter(field for item in checklist["items"] for field in item)),
        )

    def test_exact_taxonomy_is_traced_to_reviewed_excerpt(self):
        inventory = json.loads((SNAPSHOT / "inventory.json").read_text(encoding="utf-8"))
        lines = (SNAPSHOT / "caf-design-areas.md").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(inventory["taxonomy"]), 8)
        for area in inventory["taxonomy"]:
            self.assertIn("[" + area["name"] + "]", lines[area["line"] - 1])
        billing = [
            row
            for row in inventory["items"]
            if row["upstream_category"].startswith("Azure Billing")
        ]
        self.assertEqual(len(billing), 15)
        self.assertTrue(all("billing-taxonomy-label-conflict" in row["flags"] for row in billing))

    def test_dependency_age_and_feed_decisions(self):
        dependencies = json.loads((ROOT / "docs" / "dependencies.json").read_text(encoding="utf-8"))
        self.assertEqual(len(dependencies), 9)
        for entry in dependencies:
            with self.subTest(package=entry["name"]):
                self.assertEqual(entry["decision"], "accepted-for-spike")
                self.assertTrue(entry["feed_contains_version"])
                self.assertFalse(entry["upstream_archived"])
                self.assertFalse(entry["upstream_disabled"])
                self.assertTrue(entry["upstream_pushed_at"])
                self.assertLessEqual(
                    datetime.fromisoformat(entry["newest_artifact_upload"]),
                    datetime.fromisoformat(entry["reviewed_at"]) - timedelta(days=7),
                )


if __name__ == "__main__":
    unittest.main()
