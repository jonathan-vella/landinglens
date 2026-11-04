"""Minimal feasibility commands, deliberately not the future assessment interface."""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .bicep import compile_bicep
from .terraform import Analyzer, InputError


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


def main() -> int:
    parser = argparse.ArgumentParser(description="LandingLens prerequisite spike (not an assessor)")
    commands = parser.add_subparsers(dest="command", required=True)
    tf = commands.add_parser("spike-terraform", help="Analyze a bounded offline HCL2 subset")
    tf.add_argument("root", type=Path)
    tf.add_argument("--snapshots", type=Path)
    tf.add_argument("--authorize-root", type=Path, action="append", default=[])
    tf.add_argument("--var-file", dest="variable_inputs", action=VariableInput)
    tf.add_argument("--var", dest="variable_inputs", action=VariableInput)
    bicep = commands.add_parser("spike-bicep", help="Compile locally, always with --no-restore")
    bicep.add_argument("source", type=Path)
    bicep.add_argument("--compiler")
    args = parser.parse_args()
    try:
        if args.command == "spike-terraform":
            result = Analyzer(
                args.root,
                manifest=args.snapshots,
                authorized_roots=args.authorize_root,
            ).analyze(variable_inputs=args.variable_inputs)
        else:
            result = compile_bicep(args.source, args.compiler)
        print(json.dumps(result, indent=2))
        return 0
    except (InputError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
