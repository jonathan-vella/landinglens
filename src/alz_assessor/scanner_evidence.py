"""Saved scanner observations with explicit identities; never execute a scanner."""

import copy
import re
from datetime import timedelta
from typing import Any
from urllib.parse import unquote, urlsplit

from .contracts import canonical_id, digest, hashes, identity_type, require, scope_id, timestamp
from .crosswalk import load_crosswalk
from .terraform import InputError

WARNING = "Scanner observations are Signals, not checklist outcomes or proof of complete coverage."
ALIASES = {
    "AZR-000196": "Azure.Storage.SecureTransfer",
    "AZR-000289": "Azure.Storage.ContainerSoftDelete",
}


def safe_label(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.+ /-]{0,127}", value
    ):
        raise InputError("Scanner provenance requires a bounded plain name/version/baseline")
    return value


def artifact_paths(value: Any, depth: int = 0) -> None:
    if depth > 32:
        raise InputError("Scanner structure exceeds depth bound")
    if isinstance(value, dict):
        if "externalPropertyFileReferences" in value or "inlineExternalProperties" in value:
            raise InputError("External SARIF properties are not supported or retrieved")
        for key, entry in value.items():
            if key == "artifactLocation" and isinstance(entry, dict) and "uri" in entry:
                uri = require(entry, "uri", str)
                decoded = unquote(uri)
                parsed = urlsplit(decoded)
                if (
                    parsed.scheme
                    or parsed.netloc
                    or parsed.query
                    or parsed.fragment
                    or decoded.startswith(("/", "\\"))
                    or "\\" in decoded
                    or ":" in decoded
                    or "%" in decoded
                    or ".." in decoded.split("/")
                ):
                    raise InputError("Scanner artifact path must be relative and traversal-free")
            artifact_paths(entry, depth + 1)
    elif isinstance(value, list):
        for item in value:
            artifact_paths(item, depth + 1)


def import_scanner(bundle: dict[str, Any], export: Any, catalog: dict[str, Any]) -> dict[str, Any]:
    if (
        not isinstance(export, dict)
        or set(export)
        != {
            "schema_version",
            "kind",
            "format",
            "scanner",
            "scope",
            "mode",
            "evaluated_at",
            "artifact_hashes",
            "complete",
            "identities",
            "output",
        }
        or export.get("schema_version") != "1.0"
        or export.get("kind") != "scanner-export"
    ):
        raise InputError("Expected scanner-export contract 1.0 with explicit provenance")
    if export["format"] not in ("psrule-json", "sarif-2.1.0"):
        raise InputError("Unsupported saved scanner format")
    if export["mode"] != bundle["mode"]:
        raise InputError("Scanner source mode must match the explicit evidence mode")
    boundary = scope_id(require(export, "scope", str))
    if not isinstance(bundle.get("scope"), str) or boundary != bundle["scope"].lower():
        raise InputError("Scanner scope must equal the explicit evidence scope")
    timestamp(require(export, "evaluated_at", str))
    hashes(export["artifact_hashes"])
    require(export, "complete", bool)
    scanner = require(export, "scanner", dict)
    if set(scanner) != {"name", "version", "baseline"}:
        raise InputError("Supply scanner name, version and baseline explicitly")
    scanner = {key: safe_label(value) for key, value in scanner.items()}
    output = export["output"]
    artifact_paths(output)
    invocations_ok = True
    if export["format"] == "psrule-json":
        if scanner["name"] != "PSRule.Rules.Azure":
            raise InputError("PSRule JSON intake requires an explicit PSRule.Rules.Azure producer")
        if scanner["version"] != "1.48.0-B0228":
            raise InputError("Unreviewed PSRule for Azure JSON producer version")
        rows = output
    else:
        if not isinstance(output, dict) or output.get("version") != "2.1.0":
            raise InputError("SARIF version must be exactly 2.1.0")
        runs = require(output, "runs", list)
        if len(runs) != 1:
            raise InputError("Supply one SARIF run per explicit scanner export")
        run = runs[0]
        tool = require(run, "tool", dict)
        driver = require(tool, "driver", dict)
        if driver.get("name") != scanner["name"] or scanner["version"] not in (
            driver.get("version"),
            driver.get("semanticVersion"),
        ):
            raise InputError("SARIF driver identity differs from supplied scanner provenance")
        rows = require(run, "results", list)
        descriptors = driver.get("rules", [])
        if not isinstance(descriptors, list) or len(descriptors) > 10_000:
            raise InputError("SARIF driver rules require a bounded array")
        for row in rows:
            if isinstance(row, dict) and "ruleIndex" in row:
                rule_index = require(row, "ruleIndex", int)
                if rule_index != -1 and (
                    not 0 <= rule_index < len(descriptors)
                    or not isinstance(descriptors[rule_index], dict)
                    or descriptors[rule_index].get("id") != row.get("ruleId")
                ):
                    raise InputError("SARIF ruleId conflicts with its ruleIndex binding")
        invocations = require(run, "invocations", list)
        invocations_ok = bool(invocations) and all(
            isinstance(item, dict) and item.get("executionSuccessful") is True
            for item in invocations
        )
        for invocation in invocations:
            if isinstance(invocation, dict) and invocation.get("endTimeUtc") is not None:
                if timestamp(invocation["endTimeUtc"]) != timestamp(export["evaluated_at"]):
                    raise InputError(
                        "SARIF invocation time conflicts with supplied evaluation time"
                    )
    if (
        not isinstance(rows, list)
        or len(rows) > 10_000
        or any(not isinstance(row, dict) for row in rows)
    ):
        raise InputError("Scanner results must be an object array bounded to 10,000")
    identities = require(export, "identities", list)
    if len(identities) > len(rows):
        raise InputError("Scanner identity binding count exceeds result population")
    by_index = {}
    for binding in identities:
        if not isinstance(binding, dict) or set(binding) != {"index", "arm_id"}:
            raise InputError("Scanner binding requires exact result index and canonical ARM ID")
        index = require(binding, "index", int)
        if not 0 <= index < len(rows) or index in by_index:
            raise InputError("Duplicate or invalid scanner result index")
        identity = canonical_id(require(binding, "arm_id", str))
        if not identity.startswith(boundary + "/"):
            raise InputError("Scanner target is outside the explicit scope")
        by_index[index] = identity
    crosswalk = load_crosswalk(catalog)
    mapped: dict[str, list[tuple[str, str]]] = {}
    for entry in crosswalk["entries"]:
        for target in entry["targets"]:
            if target["kind"] == "psrule":
                mapped.setdefault(target["id"], []).append(
                    (entry["control_id"], target["strength"])
                )
    records, gaps = [], []
    for index, row in enumerate(rows):
        if export["format"] == "psrule-json":
            rule = row.get("ruleName")
            outcome = row.get("outcome")
            reference = row.get("ref")
            if isinstance(reference, str) and reference in ALIASES and rule != ALIASES[reference]:
                raise InputError("PSRule rule name conflicts with its reviewed reference")
            info = row.get("info")
            producer_matches = (
                isinstance(info, dict) and info.get("moduleName") == "PSRule.Rules.Azure"
            )
            status = outcome if outcome in ("Pass", "Fail", "Error", "None") else "Unknown"
        else:
            rule = row.get("ruleId")
            rule = ALIASES.get(rule, rule) if isinstance(rule, str) else None
            kind = row.get("kind")
            status = (
                {
                    "pass": "Pass",
                    "fail": "Fail",
                    "review": "Unknown",
                    "notApplicable": "None",
                    "open": "Unknown",
                    "informational": "Unknown",
                }.get(kind, "Unknown")
                if isinstance(kind, str)
                else ("Fail" if kind is None else "Unknown")
            )
            if row.get("suppressions"):
                status = "Unknown"
            producer_matches = (
                scanner["name"] == "PSRule.Rules.Azure" and scanner["version"] == "1.48.0-B0228"
            ) or (
                scanner["name"] == "PSRule"
                and isinstance(tool.get("extensions"), list)
                and any(
                    isinstance(extension, dict)
                    and extension.get("name") == "PSRule.Rules.Azure"
                    and extension.get("version") == "1.48.0-B0228"
                    for extension in tool["extensions"]
                )
            )
            # Another scanner's matching rule text is not PSRule provenance.
        if not isinstance(rule, str) or rule not in mapped or not producer_matches:
            gaps.append({"index": index, "reason": "scanner_rule_unmapped_or_producer_unverified"})
            continue
        resource_identity = by_index.get(index)
        for control_id, strength in mapped[rule]:
            flags = []
            if resource_identity is None:
                flags.append("scanner_identity_unresolved")
            if not export["complete"] or not invocations_ok:
                flags.append("scanner_run_partial_or_failed")
            if status not in ("Pass", "Fail"):
                flags.append("scanner_result_unknown_error_or_skipped")
            expected = {
                "Azure.Storage.SecureTransfer": "microsoft.storage/storageaccounts",
                "Azure.Storage.ContainerSoftDelete": (
                    "microsoft.storage/storageaccounts/blobservices"
                ),
            }[rule]
            if resource_identity is not None and identity_type(resource_identity) != expected:
                flags.append("scanner_target_type_unreviewed")
            records.append(
                {
                    "control_id": control_id,
                    "rule_id": rule,
                    "resource_id": resource_identity,
                    "status": status,
                    "mapping_strength": strength,
                    "evaluated_at": export["evaluated_at"],
                    "flags": flags,
                    "source_sha256": digest(row),
                }
            )
    result = copy.deepcopy(bundle)
    metadata = result.setdefault("metadata", {})
    if "scanner_evidence" in metadata:
        raise InputError("Existing scanner evidence cannot be silently replaced")
    metadata["scanner_evidence"] = {
        "schema_version": "1.0",
        "scanner": scanner,
        "mode": bundle["mode"],
        "scope": boundary,
        "artifact_hashes": {
            f"input-{i}": value for i, value in enumerate(export["artifact_hashes"].values())
        },
        "export_sha256": digest(export),
        "crosswalk_sha256": digest(crosswalk),
        "records": records,
        "gaps": gaps,
        "warning": WARNING,
    }
    result["artifact_hashes"]["scanner-export-content"] = digest(export)
    return result


def scanner_signals(bundle: dict[str, Any], at: str, max_age_hours: float) -> dict[str, Any] | None:
    raw = (bundle.get("metadata") or {}).get("scanner_evidence")
    if raw is None:
        return None
    validate_scanner(raw)
    if raw["mode"] != bundle["mode"] or raw["scope"] != (bundle.get("scope") or "").lower():
        raise InputError("Scanner normalised mode/scope binding differs from evidence")
    result = copy.deepcopy(raw)
    seen: dict[tuple[str, str | None], set[str]] = {}
    for record in result["records"]:
        key = (record["control_id"], record["resource_id"])
        seen.setdefault(key, set()).add(record["status"])
    for record in result["records"]:
        fresh = (
            timedelta(minutes=-5)
            <= timestamp(at) - timestamp(record["evaluated_at"])
            <= timedelta(hours=max_age_hours)
        )
        flags = record["flags"]
        if not fresh:
            flags.append("scanner_evidence_stale_or_future")
        if len(seen[(record["control_id"], record["resource_id"])]) > 1:
            flags.append("scanner_results_conflicted")
        record["usable"] = not flags
    return result


def validate_scanner(data: Any, *, assessment: bool = False, minimized: bool = False) -> None:
    if (
        not isinstance(data, dict)
        or set(data)
        != {
            "schema_version",
            "scanner",
            "mode",
            "scope",
            "artifact_hashes",
            "export_sha256",
            "crosswalk_sha256",
            "records",
            "gaps",
            "warning",
        }
        or data.get("schema_version") != "1.0"
        or data.get("warning") != WARNING
    ):
        raise InputError("Unexpected normalised scanner evidence")
    if data["mode"] not in ("planned", "observed"):
        raise InputError("Scanner evidence requires explicit mode")
    if data["scope"] is not None:
        scope_id(data["scope"])
    elif not minimized:
        raise InputError("Full scanner evidence requires explicit scope")
    scanner = require(data, "scanner", dict)
    if set(scanner) != {"name", "version", "baseline"}:
        raise InputError("Scanner provenance fields changed")
    for value in scanner.values():
        safe_label(value)
    hashes(data["artifact_hashes"])
    hashes({key: data[key] for key in ("export_sha256", "crosswalk_sha256")})
    records, gaps = require(data, "records", list), require(data, "gaps", list)
    if len(records) > 10_000 or len(gaps) > 10_000:
        raise InputError("Scanner evidence exceeds bounds")
    for record in records:
        if not isinstance(record, dict) or set(record) != {
            "control_id",
            "rule_id",
            "resource_id",
            "status",
            "mapping_strength",
            "evaluated_at",
            "flags",
            "source_sha256",
        } | ({"usable"} if assessment else set()):
            raise InputError("Unexpected scanner record fields")
        require(record, "control_id", str)
        if record["rule_id"] not in ALIASES.values() or record["status"] not in (
            "Pass",
            "Fail",
            "Error",
            "None",
            "Unknown",
        ):
            raise InputError("Unreviewed scanner rule or outcome")
        if record["mapping_strength"] not in ("partial", "related", "equivalent"):
            raise InputError("Unknown scanner mapping strength")
        if record["resource_id"] is not None:
            identity = canonical_id(record["resource_id"])
            if data["scope"] is not None and not identity.startswith(data["scope"] + "/"):
                raise InputError("Normalised scanner resource is outside its bound scope")
        elif assessment and record.get("usable") is True and not minimized:
            raise InputError("Usable full scanner Signals require canonical resource identity")
        expected_control = {
            "Azure.Storage.SecureTransfer": "ALZ-b03ed428-4617-4067-a787-85468b9ccf3f",
            "Azure.Storage.ContainerSoftDelete": "ALZ-159aac9f-863f-4f48-82cf-00c28fa97a0e",
        }[record["rule_id"]]
        if record["control_id"] != expected_control:
            raise InputError("Scanner rule differs from its reviewed control mapping")
        timestamp(require(record, "evaluated_at", str))
        hashes({"source": record["source_sha256"]})
        flags = require(record, "flags", list)
        if any(
            flag
            not in (
                "scanner_identity_unresolved",
                "scanner_run_partial_or_failed",
                "scanner_result_unknown_error_or_skipped",
                "scanner_target_type_unreviewed",
                "scanner_evidence_stale_or_future",
                "scanner_results_conflicted",
            )
            for flag in flags
        ):
            raise InputError("Unknown scanner evidence flag")
        if assessment:
            require(record, "usable", bool)
            if record["usable"] != (not flags):
                raise InputError("Scanner usability differs from flags")
    for gap in gaps:
        if not isinstance(gap, dict) or set(gap) != {"index", "reason"}:
            raise InputError("Unexpected scanner gap fields")
        if (
            require(gap, "index", int) < 0
            or gap["reason"] != "scanner_rule_unmapped_or_producer_unverified"
        ):
            raise InputError("Unknown scanner gap")
