import unittest

from alz_assessor.catalog import load_catalog
from alz_assessor.network_evidence import REVIEW_PATHS, review_fact
from alz_assessor.registry import (
    DOMAINS,
    catalog_review_fact_paths,
    collect_domain_replay_properties,
    dispatch_domain_review_fact,
    network_review_paths,
)


class RegistryTests(unittest.TestCase):
    def test_domains_cover_all_catalog_review_fact_paths(self):
        catalog = load_catalog()
        allowed = catalog_review_fact_paths()
        self.assertEqual(set(network_review_paths()), REVIEW_PATHS)
        self.assertEqual(len(DOMAINS), 20)
        for control in catalog["controls"]:
            for path in control.get("review_fact_paths", []):
                self.assertIn(path, allowed)

    def test_domain_dispatch_and_replay_projection_are_deterministic(self):
        matched, value = dispatch_domain_review_fact({"tagCount": 3}, "tagCount")
        self.assertTrue(matched)
        self.assertEqual(value, 3)
        unmatched, none_val = dispatch_domain_review_fact({}, "sku.tier")
        self.assertFalse(unmatched)
        self.assertIsNone(none_val)
        self.assertEqual(review_fact({"tagCount": 3}, "tagCount"), 3)
        projected = collect_domain_replay_properties(
            "Microsoft.KeyVault/vaults", {"enableRbacAuthorization": True}
        )
        self.assertIsInstance(projected, dict)
