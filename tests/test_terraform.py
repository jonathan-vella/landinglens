import json
import os
import shutil
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from alz_assessor.terraform import Analyzer, InputError, Limits, tree_hash

FIXTURE = Path(__file__).parent / "fixtures" / "alz"


class TerraformTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write(self, text, name="main.tf"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def analyze(self, text=None, **kwargs):
        if text:
            self.write(text)
        return Analyzer(self.root, **kwargs).analyze()

    def test_literals_variables_locals_and_forward_references(self):
        result = self.analyze("""
variable "location" { default = "australiaeast" }
locals {
  second = local.first
  first = var.location
}
resource "test" "literal" {
  name = "literal"
  region = local.second
  enabled = true
  disabled = false
  nothing = null
  number = 30
  decimal = 1.5
  tags = { env = "dev" }
}
""")
        self.assertEqual(
            result["resources"][0]["properties"],
            {
                "name": "literal",
                "region": "australiaeast",
                "enabled": True,
                "disabled": False,
                "nothing": None,
                "number": 30,
                "decimal": 1.5,
                "tags": {"env": "dev"},
            },
        )

    def test_module_based_alz_with_nested_snapshots_offline(self):
        with (
            patch.object(socket.socket, "connect", side_effect=AssertionError("network")),
            patch(
                "subprocess.run",
                side_effect=AssertionError("Terraform execution"),
            ),
        ):
            result = Analyzer(FIXTURE, manifest=FIXTURE / "snapshots.json").analyze()
        by_address = {r["address"]: r["properties"] for r in result["resources"]}
        self.assertEqual(len(by_address), 4)
        self.assertEqual(
            by_address[
                "module.platform.module.management.azurerm_log_analytics_workspace.platform"
            ],
            {
                "name": "root-platform-management",
                "location": "australiaeast",
                "resource_group_name": "root-platform-management-rg",
                "sku": "PerGB2018",
                "retention_in_days": 30,
            },
        )
        self.assertEqual(
            by_address["module.platform.module.connectivity.azurerm_virtual_network.hub"][
                "address_space"
            ],
            ["10.0.0.0/16"],
        )
        self.assertEqual(result["outputs"]["platform_name"], "root-platform")
        self.assertEqual(result["diagnostics"], [])
        self.assertIn("module.platform:snapshot", result["input_sha256"])
        self.assertIn("snapshot-manifest", result["input_sha256"])

    def test_same_fixture_missing_nested_mapping_remains_unknown(self):
        target = self.root / "alz"
        shutil.copytree(FIXTURE, target)
        manifest = target / "snapshots.json"
        data = json.loads(manifest.read_text())
        data["modules"] = data["modules"][:1]
        manifest.write_text(json.dumps(data))
        with patch.object(socket.socket, "connect", side_effect=AssertionError("network")):
            result = Analyzer(target, manifest=manifest).analyze()
        self.assertEqual(len(result["resources"]), 3)
        self.assertIn("snapshot missing", result["diagnostics"][0]["reason"])
        application = next(r for r in result["resources"] if r["address"].startswith("azurerm_"))
        self.assertIn("unknown", application["properties"]["location"])
        self.assertEqual(application["properties"]["name"], "root-platform-application")

    def test_absent_snapshot_directory(self):
        target = self.root / "alz"
        shutil.copytree(FIXTURE, target)
        manifest = target / "snapshots.json"
        data = json.loads(manifest.read_text())
        data["modules"][1]["path"] = "missing"
        manifest.write_text(json.dumps(data))
        result = Analyzer(target, manifest=manifest).analyze()
        self.assertIn("snapshot absent", result["diagnostics"][0]["reason"])

    def test_no_snapshots_no_remote_fetch_and_no_fabricated_resources(self):
        with patch.object(socket.socket, "connect", side_effect=AssertionError("network")):
            result = Analyzer(FIXTURE).analyze()
        self.assertEqual(len(result["resources"]), 1)
        self.assertIn("unknown", result["outputs"]["platform_name"])
        self.assertIn("snapshot missing", result["diagnostics"][0]["reason"])

    def test_snapshot_hash_mismatch(self):
        target = self.root / "alz"
        shutil.copytree(FIXTURE, target)
        with (target / "snapshots" / "management" / "main.tf").open("a") as file:
            file.write("\n# altered\n")
        with self.assertRaisesRegex(InputError, "hash mismatch"):
            Analyzer(target, manifest=target / "snapshots.json").analyze()

    def test_snapshot_version_mismatch_is_not_reused(self):
        target = self.root / "alz"
        shutil.copytree(FIXTURE, target)
        manifest = target / "snapshots.json"
        data = json.loads(manifest.read_text())
        data["modules"][0]["version"] = "2.0.0"
        manifest.write_text(json.dumps(data))
        result = Analyzer(target, manifest=manifest).analyze()
        self.assertIn("snapshot missing", result["diagnostics"][0]["reason"])

    def test_local_module_scope_inputs_defaults_outputs_and_no_root_leak(self):
        self.write("""
variable "name" { default = "root" }
locals { name = "root-local" }
module "child" {
  source = "./child"
  name = "child"
}
resource "test" "root" {
  name = module.child.name
  default = module.child.default
  leak = module.child.leak
}
""")
        self.write(
            """
variable "name" {}
variable "default" { default = "child-default" }
locals { name = "${var.name}-local" }
output "name" { value = local.name }
output "default" { value = var.default }
output "leak" { value = var.root_only }
""",
            "child/main.tf",
        )
        self.write('name = "must-not-load"', "child/terraform.tfvars")
        result = self.analyze()
        props = result["resources"][0]["properties"]
        self.assertEqual(props["name"], "child-local")
        self.assertEqual(props["default"], "child-default")
        self.assertIn("unknown", props["leak"])

    def test_precedence_each_layer_and_interleaved_explicit_arguments(self):
        self.write("""
variable "name" { default = "default" }
resource "test" "example" { name = var.name }
""")

        def value(**kwargs):
            return Analyzer(self.root).analyze(**kwargs)["resources"][0]["properties"]["name"]

        self.assertEqual(value(), "default")
        self.assertEqual(value(environment={"name": "environment"}), "environment")
        self.write('name = "tfvars"', "terraform.tfvars")
        self.assertEqual(value(environment={"name": "environment"}), "tfvars")
        self.write('{"name": "json"}', "terraform.tfvars.json")
        self.assertEqual(value(), "json")
        self.write('name = "auto-a"', "a.auto.tfvars")
        self.assertEqual(value(), "auto-a")
        self.write('{"name": "auto-z"}', "z.auto.tfvars.json")
        self.assertEqual(value(), "auto-z")
        explicit = self.write('name = "explicit-file"', "selected.tfvars")
        self.assertEqual(
            value(
                variable_inputs=[
                    ("var", {"name": "first"}),
                    ("file", explicit),
                ]
            ),
            "explicit-file",
        )
        self.assertEqual(
            value(
                variable_inputs=[
                    ("file", explicit),
                    ("var", {"name": "last"}),
                ]
            ),
            "last",
        )

    def test_ambient_environment_is_not_read(self):
        self.write("""
variable "name" { default = "default" }
output "name" { value = var.name }
""")
        with patch.dict(os.environ, {"TF_VAR_name": "ambient"}):
            self.assertEqual(self.analyze()["outputs"]["name"], "default")

    def test_count_map_and_set_foreach(self):
        result = self.analyze("""
resource "test" "counted" {
  count = 2
  index = count.index
}
resource "test" "mapped" {
  for_each = { prod = "production", dev = "development" }
  name = each.key
  env = each.value
}
resource "test" "set" {
  for_each = toset(["b", "a", "a"])
  name = each.value
}
""")
        by_address = {r["address"]: r["properties"] for r in result["resources"]}
        self.assertEqual(len(by_address), 6)
        self.assertEqual(by_address["test.counted[1]"]["index"], 1)
        self.assertEqual(by_address['test.mapped["prod"]']["env"], "production")
        self.assertEqual(by_address['test.set["a"]']["name"], "a")

    def test_unknown_count_and_foreach_remain_symbolic(self):
        result = self.analyze("""
data "test" "query" {}
resource "test" "counted" { count = data.test.query.count }
resource "test" "each" { for_each = data.test.query.map }
""")
        self.assertEqual(len(result["resources"]), 2)
        self.assertTrue(all(r["address"].endswith("[*]") for r in result["resources"]))
        self.assertTrue(all("unknown" in r["properties"] for r in result["resources"]))
        self.assertEqual(len(result["diagnostics"]), 2)

    def test_count_zero_emits_no_instances(self):
        result = self.analyze('resource "test" "none" { count = 0 }')
        self.assertEqual(result["resources"], [])
        self.assertEqual(result["diagnostics"], [])

    def test_invalid_controllers_are_unknown(self):
        for controller in (
            "count = true",
            "count = -1",
            'for_each = ["a"]',
            "for_each = toset([1])",
            "count = 1\nfor_each = {}",
        ):
            with self.subTest(controller=controller):
                result = self.analyze('resource "test" "bad" { ' + controller + " }")
                self.assertIn("unknown", result["resources"][0]["properties"])

    def test_expansion_limit_is_explicit(self):
        result = self.analyze(
            'resource "test" "huge" { count = 1000000 }', limits=Limits(instances=3)
        )
        self.assertEqual(len(result["resources"]), 1)
        self.assertIn("limit exceeded", result["diagnostics"][0]["reason"])

    def test_global_limit_in_nested_modules(self):
        result = Analyzer(
            FIXTURE,
            manifest=FIXTURE / "snapshots.json",
            limits=Limits(instances=3),
        ).analyze()
        self.assertLessEqual(len(result["resources"]), 3)
        self.assertTrue(any("limit" in row["reason"] for row in result["diagnostics"]))

    def test_expanded_module_outputs(self):
        self.write("""
module "child" {
  source = "./child"
  for_each = { a = "one", b = "two" }
  name = each.value
}
output "name" { value = module.child["b"].name }
""")
        self.write('variable "name" {}\noutput "name" { value = var.name }', "child/main.tf")
        self.assertEqual(self.analyze()["outputs"]["name"], "two")

    def test_local_cycle_and_module_recursion_are_unknown(self):
        result = self.analyze("""
locals {
  a = local.b
  b = local.a
}
module "recursive" { source = "./" }
output "a" { value = local.a }
""")
        self.assertIn("cyclic", result["outputs"]["a"]["unknown"])
        self.assertIn("recursion", result["diagnostics"][0]["reason"])

    def test_expression_budget(self):
        result = self.analyze(
            'resource "test" "name" { name = "value" }', limits=Limits(expression_steps=1)
        )
        self.assertIn("limit", result["resources"][0]["properties"]["name"]["unknown"])

    def test_module_depth_bound(self):
        result = Analyzer(
            FIXTURE,
            manifest=FIXTURE / "snapshots.json",
            limits=Limits(module_depth=1),
        ).analyze()
        self.assertTrue(any("depth" in row["reason"] for row in result["diagnostics"]))

    def test_path_escape_rejected(self):
        self.write('module "escape" { source = "../outside" }')
        with self.assertRaisesRegex(InputError, "outside authorized"):
            self.analyze()

    def test_snapshot_requires_explicit_external_root_authorization(self):
        root = self.root / "root"
        root.mkdir()
        (root / "main.tf").write_text('module "x" { source = "../child" }')
        self.write('output "name" { value = "child" }', "child/main.tf")
        with self.assertRaisesRegex(InputError, "outside authorized"):
            Analyzer(root).analyze()
        result = Analyzer(root, authorized_roots=[self.root / "child"]).analyze()
        self.assertEqual(result["diagnostics"], [])

    def test_symlink_escape_rejected(self):
        self.write('module "escape" { source = "./linked" }')
        with tempfile.TemporaryDirectory() as external:
            try:
                (self.root / "linked").symlink_to(external, target_is_directory=True)
            except OSError:
                self.skipTest("Creating symlinks requires platform privilege")
            with self.assertRaisesRegex(InputError, "outside authorized"):
                self.analyze()

    def test_tf_json(self):
        self.write(
            json.dumps(
                {
                    "variable": {"enabled": {"default": False}, "count": {"default": 2}},
                    "resource": {
                        "test": {
                            "json": {
                                "count": "${var.count}",
                                "enabled": "${var.enabled}",
                                "name": "json-${count.index}",
                            }
                        }
                    },
                }
            ),
            "main.tf.json",
        )
        result = self.analyze()
        self.assertEqual(len(result["resources"]), 2)
        self.assertIs(result["resources"][0]["properties"]["enabled"], False)
        self.assertEqual(result["resources"][1]["properties"]["name"], "json-1")

    def test_native_template_coerces_scalar_and_rejects_collections(self):
        result = self.analyze("""
variable "n" { default = 2 }
variable "items" { default = ["a"] }
resource "test" "n" {
  name = "${var.n}"
  invalid = "${var.items}"
  literal = "$${var.n}"
}
""")
        props = result["resources"][0]["properties"]
        self.assertEqual(props["name"], "2")
        self.assertIn("unknown", props["invalid"])
        self.assertEqual(props["literal"], "${var.n}")

    def test_unknown_and_unsupported_expressions_do_not_execute(self):
        result = self.analyze("""
resource "test" "name" {
  secret = file("outside")
  computed = other.resource.id
  unknown = var.required
  unsupported = 1 + 1
  condition = var.missing ? "yes" : "no"
  known = true ? "yes" : "no"
}
""")
        props = result["resources"][0]["properties"]
        self.assertEqual(props.pop("known"), "yes")
        self.assertEqual(props.pop("unsupported"), 2)
        self.assertTrue(all("unknown" in value for value in props.values()))

    def test_sensitive_inputs_outputs_are_withheld(self):
        result = self.analyze("""
variable "secret" {
  sensitive = true
  default = "do-not-print"
}
resource "test" "x" { secret = var.secret }
output "secret" {
  sensitive = true
  value = "do-not-print"
}
""")
        self.assertNotIn("do-not-print", json.dumps(result))

    def test_dynamic_blocks_not_silently_discarded(self):
        result = self.analyze("""
resource "test" "x" {
  dynamic "rule" {
    for_each = ["a"]
    content { name = rule.value }
  }
}
""")
        self.assertEqual(result["resources"][0]["properties"]["rule"], [{"name": "a"}])

    def test_file_and_byte_limits(self):
        self.write('resource "test" "x" {}')
        for limits in (Limits(files=0), Limits(bytes=1)):
            with self.subTest(limits=limits), self.assertRaisesRegex(InputError, "limit"):
                self.analyze(limits=limits)

    def test_invalid_hcl_and_duplicate_declarations_fail_explicitly(self):
        for text in (
            'resource "broken" {',
            "locals { a = 1\na = 2 }",
            'variable "x" {}\nvariable "x" {}',
        ):
            with self.subTest(text=text), self.assertRaises(InputError):
                self.analyze(text)

    def test_invalid_and_ambiguous_snapshot_manifest(self):
        self.write('output "name" { value = "root" }')
        manifest = self.root / "snapshots.json"
        for data in ({}, {"modules": [{}]}):
            manifest.write_text(json.dumps(data))
            with self.assertRaises(InputError):
                Analyzer(self.root, manifest=manifest)
        data = json.loads((FIXTURE / "snapshots.json").read_text())
        data["modules"] *= 2
        manifest.write_text(json.dumps(data))
        with self.assertRaisesRegex(InputError, "Ambiguous"):
            Analyzer(self.root, manifest=manifest)

    def test_bindings_change_provenance(self):
        self.write('variable "name" {}\noutput "name" { value = var.name }')
        first = Analyzer(self.root).analyze(variable_inputs=[("var", {"name": "one"})])
        second = Analyzer(self.root).analyze(variable_inputs=[("var", {"name": "two"})])
        self.assertNotEqual(
            first["input_sha256"]["effective-root-bindings"],
            second["input_sha256"]["effective-root-bindings"],
        )

    def test_git_ref_and_subdirectory_snapshot_identity(self):
        source = "git::https://example.invalid/alz.git//modules/platform?ref=v1"
        self.write(f'module "child" {{ source = "{source}" }}')
        self.write('output "name" { value = "snapshot-child" }', "snapshot/main.tf")
        manifest = self.root / "snapshots.json"
        manifest.write_text(
            json.dumps(
                {
                    "modules": [
                        {
                            "source": source,
                            "version": "v1",
                            "subdirectory": "modules/platform",
                            "path": "snapshot",
                            "sha256": tree_hash(self.root / "snapshot"),
                        }
                    ]
                }
            )
        )
        with patch.object(socket.socket, "connect", side_effect=AssertionError("network")):
            result = Analyzer(self.root, manifest=manifest).analyze()
        self.assertEqual(result["diagnostics"], [])
        self.assertIn("module.child:snapshot", result["input_sha256"])
        data = json.loads(manifest.read_text())
        data["modules"][0]["subdirectory"] = "wrong"
        manifest.write_text(json.dumps(data))
        result = Analyzer(self.root, manifest=manifest).analyze()
        self.assertIn("snapshot missing", result["diagnostics"][0]["reason"])

    def test_counted_and_unknown_module_instances(self):
        self.write("""
module "child" {
  source = "./child"
  count = 2
  index = count.index
}
module "unknown" {
  source = "./child"
  count = var.missing
}
output "index" { value = module.child[1].index }
""")
        self.write(
            """
variable "index" {}
resource "test" "child" { index = var.index }
output "index" { value = var.index }
""",
            "child/main.tf",
        )
        result = self.analyze()
        self.assertEqual(result["outputs"]["index"], 1)
        self.assertEqual(result["resources"][1]["address"], "module.child[1].test.child")
        self.assertIn("symbolic", result["diagnostics"][0]["reason"])

    def test_nested_blocks_are_retained(self):
        result = self.analyze("""
resource "test" "x" {
  rule {
    name = "outer"
    condition { enabled = true }
  }
}
""")
        self.assertEqual(
            result["resources"][0]["properties"]["rule"],
            [
                {"name": "outer", "condition": [{"enabled": True}]},
            ],
        )

    def test_json_default_is_literal_not_expression_template(self):
        self.write(
            json.dumps(
                {
                    "variable": {"name": {"default": "${not-an-expression(}"}},
                    "output": {"name": {"value": "${var.name}"}},
                }
            ),
            "main.tf.json",
        )
        self.assertEqual(self.analyze()["outputs"]["name"], "${not-an-expression(}")

    def test_json_dynamic_block_is_unknown(self):
        self.write(
            json.dumps(
                {
                    "resource": {
                        "test": {
                            "x": {
                                "dynamic": {
                                    "rule": {"for_each": ["a"], "content": {"name": "literal"}}
                                },
                            }
                        }
                    }
                }
            ),
            "main.tf.json",
        )
        result = self.analyze()
        self.assertIn("unknown", result["resources"][0]["properties"]["dynamic"])

    def test_invalid_json_body_fails_without_traceback(self):
        for data in ({"resource": []}, {"variable": {"x": 1}}, {"resource": {"test": {"x": 1}}}):
            with self.subTest(data=data), self.assertRaises(InputError):
                self.write(json.dumps(data), "main.tf.json")
                self.analyze()

    def test_duplicate_resources_across_files_rejected(self):
        self.write('resource "test" "x" {}')
        self.write('resource "test" "x" {}', "other.tf")
        with self.assertRaisesRegex(InputError, "Duplicate declaration"):
            self.analyze()

    def test_unresolved_nested_variable_values_rejected(self):
        self.write('output "name" { value = "root" }')
        file = self.write("name = { invalid = var.missing }", "selected.tfvars")
        with self.assertRaisesRegex(InputError, "literal values"):
            Analyzer(self.root).analyze(variable_inputs=[("file", file)])

    def test_snapshot_hashing_is_bounded(self):
        self.write('output "name" { value = "root" }')
        with self.assertRaisesRegex(InputError, "limit"):
            tree_hash(self.root, Limits(bytes=1))

    def test_json_provider_and_terraform_blocks_are_not_resource_defaults(self):
        self.write(
            json.dumps(
                {
                    "terraform": {"required_version": ">= 1.0"},
                    "provider": {"azurerm": {"features": {}}},
                    "resource": {"azurerm_resource_group": {"test": {"name": "literal"}}},
                }
            ),
            "main.tf.json",
        )
        result = self.analyze()
        self.assertEqual(result["resources"][0]["properties"], {"name": "literal"})


if __name__ == "__main__":
    unittest.main()
