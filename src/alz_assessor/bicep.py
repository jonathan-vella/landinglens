"""Use only an already installed standalone Bicep compiler, never Azure CLI."""

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .terraform import InputError


def compile_bicep(source: Path, compiler: str | None = None) -> dict[str, Any]:
    executable = shutil.which(compiler or "bicep")
    if executable is None:
        raise InputError(
            "Bicep compiler not found. Supply --compiler with an already installed "
            "standalone compiler; no installation or restore was attempted.",
        )
    try:
        version = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if version.returncode:
            raise InputError(f"Cannot read Bicep compiler version: {version.stderr.strip()}")
        result = subprocess.run(
            [executable, "build", str(source.resolve()), "--no-restore", "--stdout"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InputError(f"Bicep invocation failed: {exc}") from exc
    if result.returncode:
        raise InputError(
            "Bicep compilation failed with restoration disabled. Supply local/cached "
            "module artifacts prepared separately; no resource evidence was produced.\n"
            + result.stderr.strip(),
        )
    try:
        template = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise InputError("Bicep returned invalid JSON; no resource evidence produced.") from exc
    if not isinstance(template, dict) or "$schema" not in template:
        raise InputError("Bicep returned no ARM template; no resource evidence produced.")
    return {
        "spike": True,
        "compiler_version": version.stdout.strip(),
        "template": template,
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "template_sha256": hashlib.sha256(result.stdout.encode()).hexdigest(),
        "diagnostics": result.stderr.strip(),
        "limitations": "Compilation only; not ARM evaluation or a complete dependency binding.",
    }
