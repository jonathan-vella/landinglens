"""Offline prerequisite inspection, not compilation or evidence completion."""

import json
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .contracts import scope_id
from .diagnostics import guidance
from .sources import PROVIDER_VERSION
from .terraform import InputError


def preflight(
    source: Path,
    mode: str,
    loader: Callable[[], dict[str, Any]],
    *,
    scope: str | None,
    provider_version: str | None,
    compiler: str | None,
    probe_compiler: bool,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def add(requirement: str, status: str, reason: str) -> None:
        checks.append(
            {
                "requirement": requirement,
                "status": status,
                "reason": reason,
                "guidance": guidance(reason),
            }
        )

    if not source.exists() or source.is_symlink():
        add("permitted_input", "blocked", "input_unavailable")
    elif mode == "terraform" and not source.is_dir():
        add("source_directory", "blocked", "input_invalid")
    elif mode != "terraform" and not source.is_file():
        add("source_file", "blocked", "input_invalid")
    else:
        if scope is not None:
            try:
                scope_id(scope)
            except InputError:
                add("identity_scope", "blocked", "identity_unresolved")
        if mode in {"terraform", "terraform-plan"} and provider_version != PROVIDER_VERSION:
            add("provider_mapping", "unsupported", "unverified_provider_version")
        if mode != "evidence" and not scope:
            add("identity_scope", "warning", "scope_required")
        if mode == "bicep":
            executable = shutil.which(compiler or "bicep")
            if executable is None:
                add("existing_compiler", "blocked", "compiler_unavailable")
            elif probe_compiler:
                try:
                    result = subprocess.run(
                        [executable, "--version"],
                        capture_output=True,
                        timeout=30,
                        check=False,
                    )
                    add(
                        "compiler_version_probe",
                        "ready" if result.returncode == 0 else "blocked",
                        "prerequisite_checked"
                        if result.returncode == 0
                        else "compiler_probe_failed",
                    )
                except (OSError, subprocess.TimeoutExpired):
                    add("compiler_version_probe", "blocked", "compiler_probe_failed")
            else:
                add("compiler_version_probe", "warning", "compiler_not_probed")
            add("compilation", "unsupported", "compilation_not_run")
        else:
            try:
                bundle = loader()
                for reason in sorted({d["reason"] for d in bundle["diagnostics"]}):
                    add("source_interpretation", "warning", reason)
                if not bundle["inventory_complete"]:
                    add("inventory", "warning", "incomplete_graph")
                if any(not r.get("arm_id") for r in bundle["resources"]):
                    add("resource_identity", "warning", "identity_unresolved")
                if any(r["state"] != "known" for r in bundle["resources"]):
                    add("resource_values", "warning", "property_unresolved_or_wrong_type")
                add("offline_input_validation", "ready", "prerequisite_checked")
            except (InputError, json.JSONDecodeError) as exc:
                reason = (
                    "snapshot_hash_mismatch"
                    if "Snapshot content hash mismatch" in str(exc)
                    else (
                        "input_path_not_authorized"
                        if "Path outside authorized roots" in str(exc)
                        else "input_invalid"
                    )
                )
                add("offline_input_validation", "blocked", reason)
            except (OSError, UnicodeError):
                add("offline_input_validation", "blocked", "input_unavailable")
    readiness = (
        "blocked"
        if any(c["status"] == "blocked" for c in checks)
        else "partial"
        if any(c["status"] in {"warning", "unsupported"} for c in checks)
        else "ready"
    )
    return {
        "schema_version": "1.1",
        "kind": "preflight",
        "input": mode,
        "readiness": readiness,
        "checks": checks,
        "warning": "Checked prerequisites only; not complete interpretation or Azure readiness.",
        **(
            {
                "terraform_guidance": (
                    "Prefer separately prepared Terraform plan JSON with --input terraform-plan. "
                    "Raw source is a supported bounded fallback with explicit local snapshots. "
                    "LandingLens never generates plans, contacts backends or downloads modules."
                )
            }
            if mode in {"terraform", "terraform-plan"}
            else {}
        ),
    }


def render_preflight(result: dict[str, Any], format: str) -> str:
    if format == "json":
        return json.dumps(result, indent=2) + "\n"
    return (
        "\n".join(
            [
                "LandingLens offline preflight: " + result["readiness"],
                result["warning"],
                *([result["terraform_guidance"]] if "terraform_guidance" in result else []),
                *(
                    f"{c['requirement']}: {c['status']} ({c['reason']})\n"
                    + c["guidance"]["next_action"]
                    for c in result["checks"]
                ),
            ]
        )
        + "\n"
    )
