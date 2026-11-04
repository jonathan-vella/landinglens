"""Explicit, offline-by-default advisory workflows."""

import argparse
import io
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .arm import arm_source
from .azure import Collector, HttpTransport
from .bicep import compile_bicep
from .catalog import load_catalog, reviewed_refresh
from .comparison import compare
from .contracts import apply_identity_map, read_document, validate
from .diagnostics import explain
from .engine import assess
from .plan import plan_source
from .preflight import preflight, render_preflight
from .reports import render
from .sources import terraform_source
from .terraform import Analyzer, InputError, tree_hash


class VariableInput(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str | Sequence[Any] | None,
        option_string: str | None = None,
    ) -> None:
        if not isinstance(values, str):
            raise argparse.ArgumentError(self, "Expected a variable argument")
        previous = list(getattr(namespace, self.dest, None) or [])
        if option_string == "--var-file":
            previous.append(("file", values))
        else:
            try:
                name, value = values.split("=", 1)
                previous.append(("var", {name: json.loads(value)}))
            except (ValueError, json.JSONDecodeError) as exc:
                raise argparse.ArgumentError(self, "Use NAME=JSON_VALUE") from exc
        setattr(namespace, self.dest, previous)


def input_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument("source", type=Path)
    command.add_argument(
        "--input",
        choices=["terraform", "terraform-plan", "arm", "bicep", "evidence"],
        required=True,
    )
    command.add_argument("--parameters", type=Path)
    command.add_argument("--compiler")
    command.add_argument("--source-evidence", type=Path)
    command.add_argument("--plan-binding", type=Path)
    command.add_argument("--scope")
    command.add_argument("--provider-version")
    command.add_argument("--snapshots", type=Path)
    command.add_argument("--authorize-root", type=Path, action="append", default=[])
    command.add_argument("--var-file", dest="variable_inputs", action=VariableInput)
    command.add_argument("--var", dest="variable_inputs", action=VariableInput)
    command.add_argument("--identity-map", type=Path)


def validate_input_options(args: argparse.Namespace) -> None:
    allowed = {
        "snapshots": {"terraform"},
        "authorize_root": {"terraform"},
        "variable_inputs": {"terraform"},
        "parameters": {"arm", "bicep"},
        "compiler": {"bicep"},
        "provider_version": {"terraform", "terraform-plan"},
        "source_evidence": {"terraform-plan"},
        "plan_binding": {"terraform-plan"},
    }
    for name, modes in allowed.items():
        if getattr(args, name) and args.input not in modes:
            raise InputError(f"--{name.replace('_', '-')} is not valid for {args.input}")
    if args.input == "evidence" and args.scope:
        raise InputError("Saved evidence carries its own immutable scope; do not override it")


def load_evidence(args: argparse.Namespace) -> dict[str, Any]:
    validate_input_options(args)
    if args.input == "terraform":
        if args.command == "doctor" and args.snapshots:
            analyzer = Analyzer(
                args.source,
                manifest=args.snapshots,
                authorized_roots=args.authorize_root,
            )
            for entry in analyzer.snapshots:
                path = analyzer.safe(args.snapshots.parent / entry["path"])
                if not path.is_dir() or tree_hash(path, analyzer.limits) != entry["sha256"]:
                    raise InputError("Snapshot content hash mismatch")
        bundle = terraform_source(
            args.source,
            scope=args.scope,
            provider_version=args.provider_version,
            snapshots=args.snapshots,
            authorized_roots=args.authorize_root,
            variable_inputs=args.variable_inputs,
        )
    elif args.input == "terraform-plan":
        bundle = plan_source(
            args.source,
            scope=args.scope,
            provider_version=args.provider_version,
            source_binding=read_json(args.source_evidence) if args.source_evidence else None,
            binding=read_json(args.plan_binding) if args.plan_binding else None,
        )
    elif args.input in {"arm", "bicep"}:
        bundle = arm_source(
            args.source,
            scope=args.scope,
            parameters=args.parameters,
            compiler=args.compiler,
            bicep=args.input == "bicep",
        )
    else:
        bundle = read_json(args.source)
    if args.identity_map:
        bundle = apply_identity_map(bundle, read_json(args.identity_map))
    return validate(bundle, "evidence")


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="LandingLens advisory ALZ assessment")
    commands = parser.add_subparsers(dest="command", required=True)
    explanation = commands.add_parser(
        "explain", help="Explain a stable reason without taking action"
    )
    explanation.add_argument("reason")
    explanation.add_argument("--format", choices=["json", "text"], default="text")
    tf = commands.add_parser("spike-terraform", help="Analyze a bounded offline HCL2 subset")
    tf.add_argument("root", type=Path)
    tf.add_argument("--snapshots", type=Path)
    tf.add_argument("--authorize-root", type=Path, action="append", default=[])
    tf.add_argument("--var-file", dest="variable_inputs", action=VariableInput)
    tf.add_argument("--var", dest="variable_inputs", action=VariableInput)
    bicep = commands.add_parser("spike-bicep", help="Compile locally, always with --no-restore")
    bicep.add_argument("source", type=Path)
    bicep.add_argument("--compiler")
    assessment = commands.add_parser(
        "assess", help="Assess source or saved evidence, without deployment"
    )
    input_arguments(assessment)
    assessment.add_argument("--evidence-output", type=Path)
    assessment.add_argument("--manual", type=Path)
    assessment.add_argument("--exceptions", type=Path)
    assessment.add_argument("--catalog")
    assessment.add_argument(
        "--landing-zone", choices=["platform", "application"], default="platform"
    )
    assessment.add_argument("--at")
    assessment.add_argument("--max-age-hours", type=float, default=24)
    doctor = commands.add_parser("doctor", help="Inspect explicit input prerequisites offline")
    input_arguments(doctor)
    doctor.add_argument("--probe-compiler", action="store_true")
    doctor.add_argument("--format", choices=["json", "text"], default="json")
    doctor.add_argument("--output", type=Path)
    comparison = commands.add_parser(
        "compare", help="Compare saved planned and observed assessments"
    )
    comparison.add_argument("planned", type=Path)
    comparison.add_argument("observed", type=Path)
    rendering = commands.add_parser("render", help="Render an existing assessment")
    rendering.add_argument("source", type=Path)
    comparison.add_argument("--at")
    catalog_command = commands.add_parser(
        "catalog", help="Inspect, validate or explicitly refresh a reviewed local catalog"
    )
    catalog_command.add_argument("operation", choices=["inspect", "validate", "refresh"])
    catalog_command.add_argument("--source")
    catalog_command.add_argument("--id")
    catalog_command.add_argument("--reviewed", type=Path)
    catalog_command.add_argument("--accept-reviewed", action="store_true")
    catalog_command.add_argument("--output", type=Path)
    collection = commands.add_parser(
        "collect", help="Read-only explicit-scope Azure collection; existing credentials only"
    )
    selection = collection.add_mutually_exclusive_group(required=True)
    selection.add_argument("--subscription", action="append")
    selection.add_argument("--management-group")
    collection.add_argument("--token-env", default="LANDINGLENS_ARM_TOKEN")
    collection.add_argument("--inventory-authorized", action="store_true")
    collection.add_argument("--output", type=Path)
    for command in (assessment, comparison, rendering):
        command.add_argument("--format", choices=["json", "markdown", "html"], default="json")
        command.add_argument("--output", type=Path)
        command.add_argument("--minimize", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "explain":
            guidance = explain(args.reason)
            print(
                json.dumps(guidance, indent=2)
                if args.format == "json"
                else "\n".join(f"{key}: {value}" for key, value in guidance.items())
            )
            return 0
        if args.command == "spike-terraform":
            result = Analyzer(
                args.root,
                manifest=args.snapshots,
                authorized_roots=args.authorize_root,
            ).analyze(variable_inputs=args.variable_inputs)
        elif args.command == "spike-bicep":
            result = compile_bicep(args.source, args.compiler)
        elif args.command in {"assess", "doctor"}:
            validate_input_options(args)
            if args.command == "doctor":
                if args.probe_compiler and args.input != "bicep":
                    raise InputError("--probe-compiler is only valid for bicep input")
                result = preflight(
                    args.source,
                    args.input,
                    lambda: load_evidence(args),
                    scope=args.scope,
                    provider_version=args.provider_version,
                    compiler=args.compiler,
                    probe_compiler=args.probe_compiler,
                )
                output = render_preflight(result, args.format)
                if args.output:
                    args.output.write_text(output, encoding="utf-8")
                else:
                    sys.stdout.write(output)
                return 2 if result["readiness"] == "blocked" else 0
            bundle = load_evidence(args)
            if args.evidence_output:
                args.evidence_output.write_text(
                    json.dumps(bundle, indent=2) + "\n",
                    encoding="utf-8",
                )
            result = assess(
                bundle,
                load_catalog(args.catalog),
                landing_zone=args.landing_zone,
                at=args.at,
                max_age_hours=args.max_age_hours,
                manual=read_json(args.manual) if args.manual else None,
                exceptions=read_json(args.exceptions) if args.exceptions else None,
            )
        elif args.command == "compare":
            result = compare(read_json(args.planned), read_json(args.observed), args.at)
        elif args.command == "collect":
            token = os.environ.get(args.token_env)
            if not token:
                raise InputError(
                    "Existing token not found in selected environment variable; no login attempted"
                )
            result = Collector(HttpTransport(token)).collect(
                subscriptions=args.subscription,
                management_group=args.management_group,
                inventory_authorized=args.inventory_authorized,
            )
            if not result["metadata"]["run_complete"]:
                print(
                    "Warning: partial Azure collection; inspect completeness and diagnostics.",
                    file=sys.stderr,
                )
        elif args.command == "catalog":
            current = load_catalog(args.source)
            if args.operation == "refresh":
                if not args.reviewed or not args.accept_reviewed or not args.output:
                    raise InputError(
                        "Refresh requires --reviewed, --accept-reviewed and a new --output path"
                    )
                if args.output.exists():
                    raise InputError(
                        "Refresh output exists; frozen reviewed snapshots are not overwritten"
                    )
                candidate = read_json(args.reviewed)
                diff = reviewed_refresh(candidate, current)
                args.output.write_text(json.dumps(candidate, indent=2) + "\n", encoding="utf-8")
                print(json.dumps(diff, indent=2))
                return 0
            result = (
                current
                if args.operation == "inspect"
                else {
                    "valid": True,
                    "catalog_version": current["catalog_version"],
                    "controls": len(current["controls"]),
                }
            )
            if args.id:
                matches = [
                    item
                    for item in current["controls"]
                    if args.id
                    in {
                        item["control_id"],
                        item["upstream_id"],
                    }
                ]
                if not matches:
                    raise InputError("No matching catalog control")
                result = {"matches": matches}
        else:
            result = validate(read_json(args.source), "assessment")
        if args.command.startswith("spike-"):
            result = {
                key: value for key, value in result.items() if key not in {"outputs", "template"}
            }
            for resource in result.get("resources", []):
                resource.pop("properties", None)
            result["details_withheld"] = "Raw properties, outputs and compiled templates withheld"
        output = (
            json.dumps(result, indent=2) + "\n"
            if args.command.startswith("spike-") or args.command in {"catalog", "collect"}
            else render(result, args.format, args.minimize)
        )
        if getattr(args, "output", None):
            args.output.write_text(output, encoding="utf-8")
        else:
            sys.stdout.write(output)
        return 0
    except (InputError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2


def read_json(path: Path) -> dict[str, Any]:
    value = read_document(path)
    if not isinstance(value, dict):
        raise InputError("Expected a JSON document object")
    return value


if __name__ == "__main__":
    sys.exit(main())
