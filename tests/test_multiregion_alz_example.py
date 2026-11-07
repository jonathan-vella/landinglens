import hashlib
import json
import unittest
from collections import Counter
from pathlib import Path

from alz_assessor.arm import arm_source
from alz_assessor.catalog import load_catalog
from alz_assessor.engine import assess

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "docs" / "examples" / "bicep-multiregion-alz"
FIXTURES = ROOT / "tests" / "fixtures" / "multiregion-alz"
SCENARIOS = ("baseline", "defective", "remediated")
SURFACES = ("governance", "management", "connectivity", "workloads")
RESULT_ROWS = {"governance": 255, "management": 255, "connectivity": 266, "workloads": 258}


def json_file(path):
    return json.loads(path.read_text(encoding="utf-8"))


def file_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def outcome_counts(report, upstream_id):
    return Counter(
        row["planned"]["outcome"] for row in report["results"] if row["upstream_id"] == upstream_id
    )


class MultiRegionAlzExampleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scopes = json_file(EXAMPLE / "scope-map.json")["scopes"]
        cls.catalog = load_catalog()
        cls.bundles = {}
        cls.reports = {}
        for scenario in SCENARIOS:
            cls.bundles[scenario] = {}
            cls.reports[scenario] = {}
            for surface in SURFACES:
                parameters = (
                    EXAMPLE / "scenarios" / scenario / f"{surface}.parameters.json"
                    if surface != "governance"
                    else None
                )
                bundle = arm_source(
                    FIXTURES / f"{surface}.json",
                    scope=cls.scopes[surface],
                    parameters=parameters,
                )
                cls.bundles[scenario][surface] = bundle
                cls.reports[scenario][surface] = assess(
                    bundle,
                    cls.catalog,
                    at=bundle["collected_at"],
                    evidence_tiers=True,
                )

    def test_fixture_source_and_parameter_hashes(self):
        provenance = json_file(FIXTURES / "provenance.json")
        upstream = json_file(ROOT / provenance["upstream"]["module_provenance_file"])
        self.assertEqual(
            file_hash(ROOT / provenance["upstream"]["module_provenance_file"]),
            provenance["upstream"]["module_provenance_sha256"],
        )
        self.assertEqual(provenance["upstream"]["revision"], upstream["revision"])
        self.assertEqual(provenance["upstream"]["archive_sha256"], upstream["archive_sha256"])
        self.assertTrue(provenance["compiler"].endswith(upstream["compiler_version"]))
        self.assertEqual(file_hash(EXAMPLE / "scope-map.json"), provenance["scope_map_sha256"])
        for relative_path, expected in provenance["fixtures"].items():
            self.assertEqual(file_hash(FIXTURES / relative_path), expected)
        for relative_path, expected in provenance["sources"].items():
            self.assertEqual(file_hash(ROOT / relative_path), expected)
        for relative_path, expected in provenance["parameters"].items():
            self.assertEqual(file_hash(ROOT / relative_path), expected)
            self.assertNotIn(
                "sharedkey",
                (ROOT / relative_path).read_text(encoding="utf-8").casefold(),
            )

    def test_four_distinct_scope_bound_assessments_retain_all_controls(self):
        self.assertEqual(len(set(self.scopes.values())), 4)
        expected_controls = {control["control_id"] for control in self.catalog["controls"]}
        for scenario in SCENARIOS:
            for surface in SURFACES:
                with self.subTest(scenario=scenario, surface=surface):
                    bundle = self.bundles[scenario][surface]
                    report = self.reports[scenario][surface]
                    self.assertEqual(bundle["scope"].casefold(), self.scopes[surface].casefold())
                    if surface == "governance":
                        allowed_prefixes = (
                            "/providers/microsoft.management/managementgroups/",
                            "/subscriptions/",
                        )
                    else:
                        allowed_prefixes = (self.scopes[surface].casefold(),)
                    self.assertTrue(
                        all(
                            resource["arm_id"] is None
                            or resource["arm_id"].casefold().startswith(allowed_prefixes)
                            for resource in bundle["resources"]
                        )
                    )
                    self.assertEqual(
                        {row["control_id"] for row in report["results"]}, expected_controls
                    )
                    self.assertEqual(report["coverage"]["controls"], len(expected_controls))
                    self.assertEqual(report["coverage"]["result_instances"], RESULT_ROWS[surface])

    def test_controlled_defects_and_remediation(self):
        self.assertEqual(
            outcome_counts(self.reports["baseline"]["connectivity"], "D07.06"),
            Counter({"pass": 2}),
        )
        self.assertEqual(
            outcome_counts(self.reports["defective"]["connectivity"], "D07.06"),
            Counter({"fail": 2}),
        )
        self.assertEqual(
            outcome_counts(self.reports["remediated"]["connectivity"], "D07.06"),
            Counter({"pass": 2}),
        )
        for scenario, expected in (
            ("baseline", Counter({"pass": 4})),
            ("defective", Counter({"pass": 3, "fail": 1})),
            ("remediated", Counter({"pass": 4})),
        ):
            self.assertEqual(
                outcome_counts(self.reports[scenario]["connectivity"], "D01.13"), expected
            )
        for scenario, expected in (
            ("baseline", Counter({"pass": 2})),
            ("defective", Counter({"pass": 1, "fail": 1})),
            ("remediated", Counter({"pass": 2})),
        ):
            self.assertEqual(
                outcome_counts(self.reports[scenario]["workloads"], "D01.13"), expected
            )

    def test_no_unrelated_outcomes_regress_and_retention_is_not_invented(self):
        target_ids = {"D01.13", "D07.06"}
        for surface in SURFACES:
            baseline = self.reports["baseline"][surface]
            for scenario in ("defective", "remediated"):
                current = self.reports[scenario][surface]
                baseline_rows = {
                    (row["control_id"], row["logical_id"]): (
                        row["planned"]["outcome"],
                        row["planned"]["reason"],
                    )
                    for row in baseline["results"]
                    if row["upstream_id"] not in target_ids
                }
                current_rows = {
                    (row["control_id"], row["logical_id"]): (
                        row["planned"]["outcome"],
                        row["planned"]["reason"],
                    )
                    for row in current["results"]
                    if row["upstream_id"] not in target_ids
                }
                self.assertEqual(current_rows, baseline_rows)

        for scenario, expected_days in (
            ("baseline", 90),
            ("defective", 30),
            ("remediated", 90),
        ):
            workspaces = [
                resource
                for resource in self.bundles[scenario]["management"]["resources"]
                if resource["resource_type"].lower() == "microsoft.operationalinsights/workspaces"
            ]
            self.assertEqual(len(workspaces), 1)
            self.assertEqual(
                workspaces[0]["properties"]["logWorkspaceSummary"]["retentionInDays"],
                expected_days,
            )
        self.assertTrue(
            all(
                row["planned"]["outcome"] == "manual"
                for row in self.reports["defective"]["management"]["results"]
                if row["upstream_id"] == "F01.01"
            )
        )

    def test_local_gateways_and_unproven_vpn_properties_stay_unknown(self):
        bundle = self.bundles["baseline"]["connectivity"]
        gateways = [
            resource
            for resource in bundle["resources"]
            if resource["resource_type"].lower() == "microsoft.network/localnetworkgateways"
        ]
        self.assertEqual(len(gateways), 2)
        self.assertTrue(
            all(
                resource["state"] == "unknown"
                and resource["reason"] == "arm_resource_type_unsupported"
                and resource["properties"] == {}
                for resource in gateways
            )
        )
        unsupported = [
            item
            for item in bundle["diagnostics"]
            if item["reason"] == "arm_resource_type_unsupported"
        ]
        self.assertEqual(len(unsupported), 2)
        for upstream_id in ("D06.03", "D06.09", "D02.03"):
            self.assertTrue(
                all(
                    row["planned"]["outcome"] != "pass"
                    for row in self.reports["baseline"]["connectivity"]["results"]
                    if row["upstream_id"] == upstream_id
                )
            )


if __name__ == "__main__":
    unittest.main()
