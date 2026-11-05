import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from alz_assessor.arm import arm_source
from alz_assessor.arm import properties as arm_properties
from alz_assessor.azure import Collector, Response
from alz_assessor.catalog import load_catalog, reviewed_refresh
from alz_assessor.comparison import compare
from alz_assessor.contracts import control_digest, digest, validate
from alz_assessor.engine import assess
from alz_assessor.plan import plan_source
from alz_assessor.replay import export_bundle, replay_bundle, sanitize_evidence, semantic
from alz_assessor.reports import render
from alz_assessor.review_session import ReviewSession
from alz_assessor.reviews import prepare_reviews, review_context
from alz_assessor.sources import BLOB_SERVICE_TYPE, terraform_source, tf_properties
from alz_assessor.terraform import InputError, tree_hash

ROOT = Path(__file__).resolve().parents[1]
SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/batch"
STORAGE = SCOPE + "/providers/Microsoft.Storage/storageAccounts/store"
CHILD = STORAGE + "/blobServices/default"
VAULT = SCOPE + "/providers/Microsoft.KeyVault/vaults/vault"


class RecommendationBatchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.catalog = load_catalog(
            str(files("alz_assessor").joinpath("data").joinpath("catalog-2026-11-05.1.json"))
        )

    def write(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def arm(self, soft=True, purge=True, enabled=True, *, version="2024-11-01"):
        return arm_source(
            self.write(
                "template.json",
                {
                    "resources": [
                        {
                            "type": "Microsoft.KeyVault/vaults",
                            "apiVersion": version,
                            "name": "vault",
                            "properties": {
                                "enableSoftDelete": soft,
                                "enablePurgeProtection": purge,
                            },
                        },
                        {
                            "type": "Microsoft.Storage/storageAccounts",
                            "apiVersion": "2023-05-01",
                            "name": "store",
                            "properties": {"supportsHttpsTrafficOnly": True},
                        },
                        {
                            "type": BLOB_SERVICE_TYPE,
                            "apiVersion": "2023-05-01",
                            "name": "store/default",
                            "properties": {"containerDeleteRetentionPolicy": {"enabled": enabled}},
                        },
                    ]
                },
            ),
            scope=SCOPE,
        )

    def row(self, bundle, key, **options):
        report = assess(bundle, self.catalog, **options)
        return next(r for r in report["results"] if r["upstream_id"] == key)[bundle["mode"]]

    def test_fixed_target_set_original_hashes_and_exact_successor(self):
        root = ROOT / "references" / "recommendation-batches"
        targets = json.loads((root / "targets.json").read_text("utf-8"))
        ledger = json.loads((root / "ledger.json").read_text("utf-8"))
        historical = json.loads(
            files("alz_assessor").joinpath("data/catalog-2026-11-04.2.json").read_text("utf-8")
        )
        self.assertEqual(len(targets["targets"]), 251)
        self.assertEqual(len({t["guid"] for t in targets["targets"]}), 251)
        self.assertEqual(
            {t["guid"] for t in targets["targets"]},
            {c["upstream_guid"] for c in historical["controls"] if c["automation"] != "automated"},
        )
        self.assertEqual(
            {t["guid"] for t in ledger["recommendations"]},
            {t["guid"] for t in targets["targets"]},
        )
        self.assertEqual(ledger["fixed_targets_sha256"], digest(targets))
        self.assertTrue(
            all(5 <= n <= 10 for n in Counter(t["batch"] for t in targets["targets"]).values())
        )
        self.assertEqual(len(self.catalog["controls"]), 255)
        self.assertEqual(
            Counter(c["automation"] for c in self.catalog["controls"]),
            {"automated": 6, "assisted": 206, "manual": 43},
        )
        changes = reviewed_refresh(self.catalog, historical)
        self.assertEqual(len(changes["changed"]), 8)
        for control in self.catalog["controls"]:
            if control["control_id"] in targets["preserved_automated"]:
                self.assertEqual(
                    control_digest(control), targets["preserved_automated"][control["control_id"]]
                )
        invalid = copy.deepcopy(self.catalog)
        rule = next(c["rule"] for c in invalid["controls"] if c["upstream_id"] == "G02.03")
        rule["property"] = "enablePurgeProtection"
        with self.assertRaises(InputError):
            validate(invalid)

    def test_exact_explicit_boolean_matrix_and_missing_values(self):
        for soft, purge, expected in (
            (True, True, "pass"),
            (False, True, "fail"),
            (True, False, "fail"),
            (False, False, "fail"),
            (None, True, "unknown"),
            (True, None, "unknown"),
            ("true", True, "unknown"),
            (1, True, "unknown"),
            (True, {"unknown": "fixture"}, "unknown"),
        ):
            with self.subTest(soft=soft, purge=purge):
                bundle = self.arm(soft, purge)
                self.assertEqual(self.row(bundle, "G02.03")["outcome"], expected)
                self.assertEqual(len(self.row(bundle, "G02.03")["evidence_links"]), 2)
        for enabled, expected in (
            (True, "pass"),
            (False, "fail"),
            (None, "unknown"),
            ("true", "unknown"),
            (1, "unknown"),
            ({"unknown": "fixture"}, "unknown"),
        ):
            with self.subTest(enabled=enabled):
                self.assertEqual(self.row(self.arm(enabled=enabled), "G04.02")["outcome"], expected)

    def test_absence_partial_inventory_and_blob_flag_are_not_passes(self):
        bundle = self.arm()
        bundle["resources"] = bundle["resources"][:2]
        self.assertEqual(self.row(bundle, "G04.02")["outcome"], "unknown")
        bundle = self.arm()
        bundle["resources"][-1]["properties"] = {"deleteRetentionPolicy": {"enabled": True}}
        self.assertEqual(self.row(bundle, "G04.02")["outcome"], "unknown")
        for complete, expected in ((True, "not_applicable"), (False, "unknown")):
            bundle.update(resources=[], inventory_complete=complete)
            for key in ("G02.03", "G04.02"):
                self.assertEqual(self.row(bundle, key)["outcome"], expected)
        bundle = self.arm(version="2023-07-01")
        self.assertEqual(self.row(bundle, "G02.03")["outcome"], "unknown")

    def test_stale_denied_error_and_independent_facts(self):
        bundle = self.arm()
        bundle.update(mode="observed", source="saved", inventory_complete=False)
        self.assertEqual(self.row(bundle, "G02.03")["outcome"], "pass")
        self.assertEqual(self.row(bundle, "G04.02")["outcome"], "pass")
        for state, expected in (
            ("inaccessible", "unknown"),
            ("unknown", "unknown"),
            ("error", "error"),
        ):
            changed = copy.deepcopy(bundle)
            for record in changed["resources"]:
                record.update(state=state, reason="fixture_" + state)
            for key in ("G02.03", "G04.02"):
                self.assertEqual(self.row(changed, key)["outcome"], expected)
        bundle["collected_at"] = "2000-01-01T00:00:00Z"
        for key in ("G02.03", "G04.02"):
            self.assertEqual(self.row(bundle, key)["outcome"], "unknown")

    def tf_inputs(self, days):
        values = {
            "id": STORAGE,
            "name": "store",
            "resource_group_name": "batch",
            "https_traffic_only_enabled": True,
            "blob_properties": [{"container_delete_retention_policy": [{"days": days}]}],
        }
        source = self.root / "source"
        source.mkdir(exist_ok=True)
        self.write(
            "source/main.tf.json", {"resource": {"azurerm_storage_account": {"store": values}}}
        )
        plan = self.write(
            "plan.json",
            {
                "format_version": "1.2",
                "planned_values": {
                    "root_module": {
                        "resources": [
                            {
                                "mode": "managed",
                                "type": "azurerm_storage_account",
                                "address": "azurerm_storage_account.store",
                                "values": values,
                            }
                        ]
                    }
                },
            },
        )
        return source, plan

    def test_raw_and_optional_plan_retention_exact_boundaries_and_versions(self):
        for days, expected in (
            (0, "unknown"),
            (1, "pass"),
            (365, "pass"),
            (366, "unknown"),
            (True, "unknown"),
            ("7", "unknown"),
            (None, "unknown"),
            ({"unknown": "fixture"}, "unknown"),
        ):
            source, plan = self.tf_inputs(days)
            for adapter, path in ((terraform_source, source), (plan_source, plan)):
                with self.subTest(days=days, adapter=adapter.__name__):
                    bundle = adapter(path, scope=SCOPE, provider_version="4.50.0")
                    self.assertEqual(self.row(bundle, "G04.02")["outcome"], expected)
                    unsupported = adapter(path, scope=SCOPE, provider_version="4.49.0")
                    self.assertEqual(self.row(unsupported, "G04.02")["outcome"], "unknown")

    def test_explicit_module_snapshot_and_missing_module_stay_offline(self):
        root = self.root / "modules"
        root.mkdir()
        child = root / "storage"
        child.mkdir()
        (root / "main.tf").write_text(
            'module "storage" {\n source = "example.invalid/batch/storage/azurerm"\n'
            ' version = "1.0.0"\n}\n',
            encoding="utf-8",
        )
        (child / "main.tf").write_text(
            'resource "azurerm_storage_account" "store" {\n name = "store"\n'
            ' resource_group_name = "batch"\n blob_properties {\n'
            " container_delete_retention_policy {\n days = 1\n }\n }\n}\n",
            encoding="utf-8",
        )
        manifest = self.write(
            "modules/snapshots.json",
            {
                "modules": [
                    {
                        "source": "example.invalid/batch/storage/azurerm",
                        "version": "1.0.0",
                        "subdirectory": "",
                        "path": "storage",
                        "sha256": tree_hash(child),
                    }
                ]
            },
        )
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            bundle = terraform_source(
                root, snapshots=manifest, scope=SCOPE, provider_version="4.50.0"
            )
            self.assertEqual(self.row(bundle, "G04.02")["outcome"], "pass")
            missing = terraform_source(root, scope=SCOPE, provider_version="4.50.0")
            self.assertEqual(self.row(missing, "G04.02")["outcome"], "unknown")

    def test_terraform_vault_creation_default_is_not_inferred(self):
        source = self.root / "vault"
        source.mkdir()
        self.write(
            "vault/main.tf.json",
            {
                "resource": {
                    "azurerm_key_vault": {
                        "vault": {
                            "name": "vault",
                            "resource_group_name": "batch",
                            "purge_protection_enabled": True,
                            "soft_delete_retention_days": 7,
                        }
                    }
                }
            },
        )
        bundle = terraform_source(source, scope=SCOPE, provider_version="4.50.0")
        self.assertEqual(self.row(bundle, "G02.03")["outcome"], "unknown")

    def test_scoped_injected_management_reads_and_denial_identity(self):
        requested = []

        def transport(method, url):
            requested.append((method, url))
            if "/resources?" in url:
                return Response(
                    200,
                    {
                        "value": [
                            {"id": STORAGE, "type": "Microsoft.Storage/storageAccounts"},
                            {"id": VAULT, "type": "Microsoft.KeyVault/vaults"},
                        ]
                    },
                    {},
                )
            if "/blobservices/default?" in url:
                return Response(
                    200,
                    {
                        "id": CHILD,
                        "properties": {
                            "containerDeleteRetentionPolicy": {"enabled": True},
                            "private": "do-not-export",
                        },
                    },
                    {},
                )
            if "/vaults/vault?" in url:
                return Response(
                    200,
                    {
                        "id": VAULT,
                        "properties": {
                            "enableSoftDelete": True,
                            "enablePurgeProtection": True,
                        },
                    },
                    {},
                )
            if "/storageAccounts/store?" in url:
                return Response(200, {"id": STORAGE, "properties": {}}, {})
            return Response(200, {"value": []}, {})

        bundle = Collector(transport).collect(
            subscriptions=["00000000-0000-0000-0000-000000000001"],
            inventory_authorized=True,
        )
        self.assertEqual(self.row(bundle, "G02.03")["outcome"], "pass")
        self.assertEqual(self.row(bundle, "G04.02")["outcome"], "pass")
        self.assertNotIn("do-not-export", json.dumps(bundle))
        self.assertTrue(
            all(url.startswith("https://management.azure.com/") for _, url in requested)
        )

        def denied(method, url):
            return (
                Response(403, {}, {}) if "/blobservices/default?" in url else transport(method, url)
            )

        denied_bundle = Collector(denied).collect(
            subscriptions=["00000000-0000-0000-0000-000000000001"],
            inventory_authorized=True,
        )
        self.assertEqual(self.row(denied_bundle, "G04.02")["outcome"], "unknown")
        self.assertEqual(self.row(denied_bundle, "G02.03")["outcome"], "pass")

    def test_replay_all_historical_catalogs_comparison_and_rendered_guidance(self):
        bundle = self.arm()
        observed = copy.deepcopy(bundle)
        observed.update(mode="observed", source="saved")
        observed["resources"][0]["properties"]["enablePurgeProtection"] = False
        result = compare(assess(bundle, self.catalog), assess(observed, self.catalog))
        vault = next(r for r in result["results"] if r["upstream_id"] == "G02.03")
        self.assertEqual(vault["comparison"], "drift")
        for name in ("catalog-2026-11-04.1.json", "catalog-2026-11-04.2.json", "catalog.json"):
            catalog = json.loads(files("alz_assessor").joinpath("data/" + name).read_text("utf-8"))
            destination = self.root / name
            export_bundle(destination, bundle, catalog, at=bundle["collected_at"])
            self.assertEqual(
                semantic(replay_bundle(destination)),
                semantic(assess(bundle, catalog, at=bundle["collected_at"])),
            )
        report = assess(bundle, self.catalog)
        for format in ("json", "markdown", "html"):
            for minimize in (True, False):
                output = render(report, format, minimize=minimize)
                self.assertIn("policy-enforcement-not-local-tls-flag", output)
                self.assertIn("Reviewer decision", output)

    def test_compound_comparison_preserves_both_components_and_canonical_child_identity(self):
        planned = self.arm(soft=False, purge=True)
        observed = self.arm(soft=True, purge=False)
        observed.update(mode="observed", source="saved")
        result = compare(assess(planned, self.catalog), assess(observed, self.catalog))
        vault = next(r for r in result["results"] if r["upstream_id"] == "G02.03")
        self.assertEqual(vault["planned"]["outcome"], "fail")
        self.assertEqual(vault["observed"]["outcome"], "fail")
        self.assertEqual(vault["comparison"], "drift")
        observed["resources"][-1]["arm_id"] = CHILD + "-other"
        self.assertEqual(self.row(observed, "G04.02")["outcome"], "unknown")
        result = compare(assess(planned, self.catalog), assess(observed, self.catalog))
        child = next(r for r in result["results"] if r["upstream_id"] == "G04.02")
        self.assertEqual(child["comparison"], "not_comparable")

    def test_specific_review_preparation_reaches_templates_and_editor_without_decision(self):
        bundle = self.arm()
        report = assess(bundle, self.catalog)
        template = prepare_reviews(report, self.catalog, ["G02.04"], SCOPE)
        entry = template["entries"][0]
        self.assertIsNone(entry["reviewer"])
        self.assertIsNone(entry["outcome"])
        self.assertIn("MFA", " ".join(entry["preparation"]["evidence_requirements"]))
        session = ReviewSession(bundle, self.catalog, self.root / "review")
        control = next(c for c in session.controls if c["label"].startswith("G02.04:"))
        self.assertEqual(
            control["evidence_requirements"], entry["preparation"]["evidence_requirements"]
        )
        self.assertEqual(control["available_evidence"]["matching_resources"], 1)
        rendered = json.loads(render(report))
        template = prepare_reviews(rendered, self.catalog, ["G02.04"], SCOPE)
        context = template["entries"][0]["preparation"]["available_evidence"][0]
        self.assertFalse(context["normalized_resources_available"])
        self.assertIsNone(context["matching_resources"])

    def test_inventory_preparation_is_bounded_and_withholds_raw_properties(self):
        bundle = self.arm()
        vault = bundle["resources"][0]
        bundle["resources"] = [
            {
                **vault,
                "logical_id": f"vault-{index}",
                "arm_id": (VAULT + str(index)).lower(),
                "properties": {"unreviewed": "PRIVATE-SENTINEL"},
            }
            for index in range(101)
        ]
        control = next(c for c in self.catalog["controls"] if c["upstream_id"] == "G02.04")
        context = review_context(control, bundle)
        self.assertEqual(len(context["resources"]), 100)
        self.assertEqual(context["matching_resources"], 101)
        self.assertTrue(context["truncated"])
        self.assertNotIn("PRIVATE-SENTINEL", json.dumps(context))

    def test_partial_scalar_preparation_never_passes_the_whole_recommendation(self):
        bundle = self.arm()
        bundle["resources"][0]["properties"] = arm_properties(
            "Microsoft.KeyVault/vaults",
            {
                "enableRbacAuthorization": True,
                "publicNetworkAccess": "Disabled",
                "networkAcls": {"defaultAction": "Deny"},
            },
        )
        bundle["resources"][1]["properties"] = arm_properties(
            "Microsoft.Storage/storageAccounts", {"minimumTlsVersion": "TLS1_2"}
        )
        for key, path, expected in (
            ("G02.04", "enableRbacAuthorization", True),
            ("G02.07", "publicNetworkAccess", "Disabled"),
            ("G04.03", "minimumTlsVersion", "TLS1_2"),
        ):
            control = next(c for c in self.catalog["controls"] if c["upstream_id"] == key)
            context = review_context(control, bundle)
            self.assertEqual(context["resources"][0]["facts"][path], expected)
            self.assertEqual(self.row(bundle, key)["outcome"], "manual")
            restored = review_context(control, sanitize_evidence(bundle))
            self.assertEqual(context["resources"][0]["facts"], restored["resources"][0]["facts"])
        bundle["resources"][1]["properties"]["minimumTlsVersion"] = "PRIVATE-NONENUM-SENTINEL"
        self.assertNotIn("PRIVATE-NONENUM-SENTINEL", json.dumps(sanitize_evidence(bundle)))
        for rbac_key in ("rbac_authorization_enabled", "enable_rbac_authorization"):
            normalized = tf_properties("azurerm_key_vault", {rbac_key: True})
            self.assertIs(normalized["enableRbacAuthorization"], True)
        conflicting = tf_properties(
            "azurerm_key_vault",
            {"enable_rbac_authorization": True, "rbac_authorization_enabled": True},
        )
        self.assertIn("unknown", conflicting["enableRbacAuthorization"])
        for value in (None, True, 1, "TLS1_3", "tls1_2"):
            self.assertIn(
                "unknown",
                tf_properties("azurerm_storage_account", {"min_tls_version": value})[
                    "minimumTlsVersion"
                ],
            )
        for value in (None, "False", 0):
            self.assertIn(
                "unknown",
                tf_properties("azurerm_key_vault", {"public_network_access_enabled": value})[
                    "publicNetworkAccess"
                ],
            )
        self.assertIn(
            "unknown",
            arm_properties(
                "Microsoft.KeyVault/vaults", {"publicNetworkAccess": "SecuredByPerimeter"}
            )["publicNetworkAccess"],
        )
        self.assertEqual(
            tf_properties("azurerm_key_vault", {"public_network_access_enabled": False})[
                "publicNetworkAccess"
            ],
            "Disabled",
        )

    @unittest.skipUnless(os.environ.get("BICEP_COMPILER"), "Existing Bicep compiler not supplied")
    def test_real_no_restore_bicep_and_installed_cli(self):
        bicep = self.root / "batch.bicep"
        bicep.write_text(
            "resource vault 'Microsoft.KeyVault/vaults@2024-11-01' = {\n"
            " name: 'vault'\n location: 'westeurope'\n properties: {\n"
            "  sku: { family: 'A', name: 'standard' }\n"
            "  tenantId: '00000000-0000-0000-0000-000000000001'\n"
            "  accessPolicies: []\n enableSoftDelete: true\n enablePurgeProtection: true\n }\n}\n"
            "resource child 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {\n"
            " name: 'store/default'\n properties: {\n"
            "  containerDeleteRetentionPolicy: { enabled: true, days: 1 }\n }\n}\n",
            encoding="utf-8",
        )
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "alz_assessor.cli",
                "assess",
                str(bicep),
                "--input",
                "bicep",
                "--scope",
                SCOPE,
                "--compiler",
                os.environ["BICEP_COMPILER"],
            ],
            cwd=self.root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=60,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        for key in ("G02.03", "G04.02"):
            self.assertEqual(
                next(r for r in report["results"] if r["upstream_id"] == key)["planned"]["outcome"],
                "pass",
            )
