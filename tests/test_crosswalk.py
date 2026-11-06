import contextlib
import copy
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from alz_assessor.catalog import load_catalog
from alz_assessor.cli import main
from alz_assessor.contracts import control_digest, digest
from alz_assessor.crosswalk import inspect_crosswalk, load_crosswalk, validate_crosswalk
from alz_assessor.engine import assess
from alz_assessor.terraform import InputError

GUID = "b03ed428-4617-4067-a787-85468b9ccf3f"


class CrosswalkTests(unittest.TestCase):
    def setUp(self):
        self.catalog = load_catalog()
        self.crosswalk = load_crosswalk(self.catalog)

    def cli(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch("sys.argv", ["alz-assessor", "catalog", *args]),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            code = main()
        return code, stdout.getvalue(), stderr.getvalue()

    def test_exact_inventory_provenance_and_conservative_mapping_coverage(self):
        data = self.crosswalk
        self.assertEqual(len(data["entries"]), 255)
        self.assertEqual(
            {entry["guid"] for entry in data["entries"]},
            {control["upstream_guid"] for control in self.catalog["controls"]},
        )
        summary = inspect_crosswalk(data, self.catalog)
        self.assertEqual((summary["mapped_controls"], summary["targets"]), (51, 53))
        self.assertEqual(sum(not entry["targets"] for entry in data["entries"]), 204)
        targets = [target for entry in data["entries"] for target in entry["targets"]]
        self.assertEqual(sum(t["kind"] == "arg-query" for t in targets), 49)
        self.assertFalse(any(t["strength"] == "equivalent" for t in targets))
        self.assertTrue(
            all(t["strength"] == "related" for t in targets if t["kind"] == "arg-query")
        )
        mapped = inspect_crosswalk(data, self.catalog, "G04.01")["entries"][0]
        self.assertEqual(mapped["guid"], GUID)
        self.assertEqual(len(mapped["targets"]), 3)
        self.assertTrue(all(t["strength"] == "partial" for t in mapped["targets"]))
        sources = {source["id"]: source for source in data["sources"]}
        self.assertEqual(sources["alz-storage-assignment"]["release"], "platform/alz/2026.10.0")
        self.assertEqual(sources["psrule-storage-yaml"]["release"], "v1.48.0-B0228")
        for source in sources.values():
            self.assertEqual(len(source["sha256"]), 64)
            self.assertEqual(len(source["license_sha256"]), 64)
            self.assertIn(source["revision"], source["url"])
            self.assertTrue(source["finding"])

    def test_unmapped_and_ambiguous_display_ids_are_explicit(self):
        for selection in ("G04.01", GUID, "ALZ-" + GUID):
            self.assertEqual(
                inspect_crosswalk(self.crosswalk, self.catalog, selection)["entries"][0]["guid"],
                GUID,
            )
        empty = next(entry for entry in self.crosswalk["entries"] if not entry["targets"])
        self.assertEqual(
            inspect_crosswalk(self.crosswalk, self.catalog, empty["guid"])["entries"][0]["targets"],
            [],
        )
        for selection in ("B03.02", "D05.08", "D07.12", "missing", ""):
            with self.assertRaisesRegex(InputError, "ambiguous"):
                inspect_crosswalk(self.crosswalk, self.catalog, selection)

    def test_unreviewed_raw_fields_are_rejected_not_exported(self):
        for level in ("root", "source", "entry", "target"):
            data = copy.deepcopy(self.crosswalk)
            target = {
                "root": data,
                "source": data["sources"][0],
                "entry": data["entries"][0],
                "target": next(e["targets"][0] for e in data["entries"] if e["targets"]),
            }[level]
            target["raw"] = "PRIVATE-NOT-FOR-REPORTING"
            with self.assertRaisesRegex(InputError, "Unexpected"):
                validate_crosswalk(data, self.catalog)

    def test_invalid_guid_membership_duplicate_and_catalog_binding(self):
        for change in (
            lambda d: d["entries"].pop(),
            lambda d: d["entries"].append(copy.deepcopy(d["entries"][0])),
            lambda d: d["entries"][0].update(guid="not-a-guid"),
            lambda d: d["entries"][0].update(guid="00000000-0000-0000-0000-000000000000"),
            lambda d: d["entries"][0].update(control_id="ALZ-other"),
            lambda d: d.update(catalog_sha256="0" * 64),
            lambda d: d.update(schema_version="1.1"),
            lambda d: d.update(review_state="candidate"),
        ):
            data = copy.deepcopy(self.crosswalk)
            change(data)
            with self.assertRaises(InputError):
                validate_crosswalk(data, self.catalog)
        data = copy.deepcopy(self.crosswalk)
        data["entries"][1] = copy.deepcopy(data["entries"][0])
        with self.assertRaisesRegex(InputError, "duplicate"):
            validate_crosswalk(data, self.catalog)

    def test_sources_require_immutable_hash_bound_public_provenance(self):
        for field, value in (
            ("sha256", "bad"),
            ("license_sha256", None),
            ("revision", "main"),
            ("url", "https://example.invalid/private"),
            ("retrieved_at", "today"),
            ("url", "file:///private/evidence"),
            ("finding", " "),
            ("url", "https://raw.githubusercontent.com/repo/main/file"),
            ("license_revision", "main"),
        ):
            data = copy.deepcopy(self.crosswalk)
            data["sources"][0][field] = value
            with self.assertRaises(InputError):
                validate_crosswalk(data, self.catalog)
        data = copy.deepcopy(self.crosswalk)
        data["sources"].append(copy.deepcopy(data["sources"][0]))
        with self.assertRaisesRegex(InputError, "Duplicate"):
            validate_crosswalk(data, self.catalog)

    def test_targets_reject_missing_duplicate_conflicting_and_invalid_types(self):
        for field, value in (
            ("strength", "pass"),
            ("rationale", " "),
            ("kind", "execute-query"),
            ("source_ids", ["unknown"]),
            ("source_ids", []),
            ("source_ids", [{}]),
            ("source_ids", ["checklist", "checklist"]),
        ):
            data = copy.deepcopy(self.crosswalk)
            target = next(e["targets"][0] for e in data["entries"] if e["targets"])
            target[field] = value
            with self.assertRaises(InputError):
                validate_crosswalk(data, self.catalog)
        for kind, identity in (
            ("arg-query", "resources | project id"),
            ("azure-policy-definition", "/subscriptions/private/providers/policyDefinitions/test"),
            (
                "azure-policy-definition",
                "/providers/Microsoft.Authorization/policyDefinitions/" + "-" * 36,
            ),
            ("psrule", "unverified-name"),
            ("alz-policy-definition", "folder/name"),
        ):
            data = copy.deepcopy(self.crosswalk)
            target = next(e["targets"][0] for e in data["entries"] if e["targets"])
            target.update(kind=kind, id=identity)
            with self.assertRaises(InputError):
                validate_crosswalk(data, self.catalog)
        data = copy.deepcopy(self.crosswalk)
        entry = next(e for e in data["entries"] if e["targets"])
        duplicate = copy.deepcopy(entry["targets"][0])
        duplicate["strength"] = "equivalent"
        entry["targets"].append(duplicate)
        with self.assertRaisesRegex(InputError, "conflicting"):
            validate_crosswalk(data, self.catalog)

    def test_alz_name_requires_release_and_bounds_are_not_silently_truncated(self):
        data = copy.deepcopy(self.crosswalk)
        source = next(s for s in data["sources"] if s["id"] == "alz-storage-assignment")
        source["release"] = None
        with self.assertRaisesRegex(InputError, "platform/alz"):
            validate_crosswalk(data, self.catalog)
        for key in ("sources", "targets"):
            data = copy.deepcopy(self.crosswalk)
            if key == "sources":
                data["sources"] = data["sources"] * 15
            else:
                entry = next(e for e in data["entries"] if e["targets"])
                entry["targets"] = entry["targets"] * 101
            with self.assertRaisesRegex(InputError, "100|bound"):
                validate_crosswalk(data, self.catalog)

    def test_packaged_binding_and_explicit_file_validation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data = copy.deepcopy(self.crosswalk)
            (root / "data").mkdir()
            (root / "data" / "crosswalk.json").write_text(json.dumps(data), encoding="utf-8")
            (root / "data" / "crosswalk-binding.json").write_text(
                json.dumps({"crosswalk_sha256": "0" * 64}), encoding="utf-8"
            )
            with patch("alz_assessor.crosswalk.files", return_value=root):
                with self.assertRaisesRegex(InputError, "binding mismatch"):
                    load_crosswalk(self.catalog)
            path = root / "explicit.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            self.assertEqual(load_crosswalk(self.catalog, path), data)
            path.write_text('{"schema_version":"1.0","schema_version":"1.1"}', encoding="utf-8")
            with self.assertRaises(InputError):
                load_crosswalk(self.catalog, path)

    def test_assessment_and_original_control_meaning_are_not_modified(self):
        before = digest(self.catalog)
        hashes = [control_digest(c) for c in self.catalog["controls"]]
        bundle = json.loads(
            (Path(__file__).parent / "fixtures" / "slice" / "observed.json").read_text("utf-8")
        )
        assessment = assess(bundle, self.catalog, at=bundle["collected_at"])
        with patch("socket.socket.connect", side_effect=AssertionError("network forbidden")):
            inspect_crosswalk(self.crosswalk, self.catalog)
            load_crosswalk(self.catalog)
        self.assertEqual(digest(self.catalog), before)
        self.assertEqual([control_digest(c) for c in self.catalog["controls"]], hashes)
        self.assertEqual(
            digest(assess(bundle, self.catalog, at=bundle["collected_at"])), digest(assessment)
        )
        self.assertEqual(sum(c["automation"] == "automated" for c in self.catalog["controls"]), 11)

    def test_cli_inspect_validate_and_invalid_options(self):
        code, output, error = self.cli("crosswalk", "inspect", "--id", "G04.01")
        self.assertEqual((code, error), (0, ""))
        self.assertEqual(json.loads(output)["entries"][0]["guid"], GUID)
        code, output, error = self.cli("crosswalk", "validate")
        self.assertEqual((code, error), (0, ""))
        self.assertIs(json.loads(output)["valid"], True)
        self.assertNotIn("entries", json.loads(output))
        for args in (
            ("crosswalk",),
            ("crosswalk", "validate", "--id", GUID),
            ("crosswalk", "inspect", "--accept-reviewed"),
            ("inspect", "validate"),
            ("inspect", "--crosswalk", "missing"),
            ("crosswalk", "inspect", "--id", "D07.12"),
        ):
            code, _, error = self.cli(*args)
            self.assertEqual(code, 2)
            self.assertIn("Input error", error)

    def test_installed_subprocess_offline_inspect_and_validation_output(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "crosswalk.json"
            command = [sys.executable, "-m", "alz_assessor.cli", "catalog", "crosswalk"]
            result = subprocess.run(
                [*command, "inspect", "--id", GUID, "--output", str(output)],
                cwd=temp,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(output.read_text("utf-8"))
            self.assertEqual(data["entries"][0]["guid"], GUID)
            self.assertIn("not outcomes", data["warning"])
            result = subprocess.run(
                [*command, "validate"],
                cwd=temp,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["controls"], 255)

    def test_offline_builder_reproduces_bytes_and_actual_query_hashes(self):
        root = Path(__file__).parents[1]
        spec = importlib.util.spec_from_file_location(
            "build_crosswalk", root / "tools" / "build_crosswalk.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        originals = {
            name: files("alz_assessor").joinpath("data", name).read_bytes()
            for name in ("crosswalk.json", "crosswalk-binding.json")
        }
        with tempfile.TemporaryDirectory() as temp:
            module.DATA = Path(temp)
            for name, content in originals.items():
                (module.DATA / name).write_bytes(content)
            with patch.object(
                module, "public_fetch", side_effect=AssertionError("network forbidden")
            ):
                module.build(self.crosswalk["crosswalk_version"])
            for name, content in originals.items():
                self.assertEqual((module.DATA / name).read_bytes(), content)
            with patch.object(
                module, "public_fetch", side_effect=AssertionError("network forbidden")
            ):
                with self.assertRaisesRegex(ValueError, "never silently"):
                    module.capture()
