"""Optional, separately bound Terraform plan JSON; never invoke Terraform."""

from pathlib import Path
from typing import Any

from .contracts import canonical_id, digest, document, now, read_document, validate
from .sources import (
    PROVIDER_VERSION,
    TF_TYPES,
    file_hash,
    tf_blob_service,
    tf_properties,
    tf_resource_id,
)
from .terraform import InputError


def plan_source(
    path: Path,
    *,
    scope: str | None = None,
    provider_version: str | None = None,
    source_binding: dict[str, Any] | None = None,
    binding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if path.stat().st_size > 2_000_000:
        raise InputError("Plan JSON exceeds byte limit")
    plan = read_document(path, 2_000_000)
    if not isinstance(plan, dict) or not str(plan.get("format_version", "")).startswith("1."):
        raise InputError("Unsupported Terraform plan JSON format")
    if not isinstance(plan.get("planned_values"), dict):
        raise InputError("Plan JSON requires planned_values")
    artifacts = {
        str(path): file_hash(path),
        "scope-provider-bindings": digest(
            {
                "scope": scope,
                "azurerm": provider_version,
            }
        ),
    }
    if source_binding is not None:
        validate(source_binding, "evidence")
        if source_binding["mode"] != "planned" or source_binding["source"] != "terraform":
            raise InputError("Plan association requires raw Terraform source evidence")
        if (
            not binding
            or binding.get("review_state") != "reviewed"
            or binding.get("plan_sha256") != file_hash(path)
            or binding.get("source_artifact_hashes") != source_binding["artifact_hashes"]
        ):
            raise InputError("Plan/source relationship requires a matching reviewed hash binding")
        artifacts["explicit-source-evidence"] = digest(source_binding["artifact_hashes"])
        artifacts["reviewed-plan-binding"] = digest(binding)
    elif binding is not None:
        raise InputError("Plan binding requires explicit source evidence")
    records: list[dict[str, Any]] = []
    diagnostics = []

    def walk(module: dict[str, Any], depth: int = 0) -> None:
        if depth > 16:
            raise InputError("Plan module depth limit exceeded")
        resources = module.get("resources", [])
        children = module.get("child_modules", [])
        if not isinstance(resources, list) or not isinstance(children, list):
            raise InputError("Plan resource and child-module collections must be lists")
        for resource in resources:
            if not isinstance(resource, dict):
                raise InputError("Planned resource must be an object")
            if resource.get("mode") != "managed":
                continue
            if len(records) >= 256:
                raise InputError("Plan resource limit exceeded")
            kind = resource.get("type")
            if not isinstance(kind, str) or not isinstance(resource.get("values"), dict):
                raise InputError("Malformed planned resource")
            if not isinstance(resource.get("address"), str) or not resource["address"]:
                raise InputError("Planned resource requires a logical address")
            values = dict(resource["values"])
            sensitive = resource.get("sensitive_values", {})
            if not isinstance(sensitive, dict):
                raise InputError("Invalid sensitive-values marker")
            for key, marker in sensitive.items():
                if marker:
                    values[key] = {"unknown": "sensitive_plan_value_withheld"}
            normalized = tf_properties(kind, values)
            arm_type = TF_TYPES.get(kind, kind)
            verified = provider_version == PROVIDER_VERSION
            candidate = tf_resource_id(scope, kind, values) if verified else None
            explicit_id = values.get("id")
            from .policy_strategy_evidence import TF_SCOPES

            if kind in TF_SCOPES or kind in {
                "azurerm_policy_definition",
                "azurerm_policy_set_definition",
            }:
                identity = candidate
                if isinstance(explicit_id, str) and (
                    candidate is None or canonical_id(explicit_id) != candidate
                ):
                    raise InputError("Policy plan ID conflicts with explicit typed scope/name")
            elif kind in {"azurerm_role_definition", "azurerm_active_directory_domain_service"}:
                from uuid import UUID

                from .contracts import identity_type

                key = (
                    "role_definition_resource_id"
                    if kind == "azurerm_role_definition"
                    else "resource_id"
                )
                actual_id = values.get(key)
                identity = (
                    canonical_id(actual_id) if verified and isinstance(actual_id, str) else None
                )
                if identity and identity_type(identity) != arm_type.lower():
                    raise InputError("Provider ARM resource identity has the wrong resource type")
                if identity and kind == "azurerm_role_definition":
                    target = values.get("scope")
                    if (
                        not isinstance(target, str)
                        or identity.rsplit(
                            "/providers/microsoft.authorization/roledefinitions/", 1
                        )[0]
                        != target.lower()
                    ):
                        raise InputError("Role-definition ARM identity conflicts with its scope")
                if identity and isinstance(explicit_id, str):
                    if kind == "azurerm_role_definition":
                        expected = identity + "|" + str(values.get("scope")).lower()
                        if explicit_id.lower() != expected:
                            raise InputError(
                                "Role-definition composite ID conflicts with ARM binding"
                            )
                    else:
                        prefix = identity + "/initialreplicasetid/"
                        suffix = explicit_id.lower().removeprefix(prefix)
                        try:
                            UUID(suffix)
                        except (ValueError, AttributeError) as exc:
                            raise InputError("Domain-service composite ID is not bound") from exc
                        if not explicit_id.lower().startswith(prefix):
                            raise InputError(
                                "Domain-service composite ID conflicts with ARM binding"
                            )
            elif kind == "azurerm_monitor_diagnostic_setting":
                identity = candidate
                if (
                    isinstance(explicit_id, str)
                    and candidate
                    and explicit_id.lower()
                    not in {
                        candidate,
                        (
                            str(values.get("target_resource_id")) + "|" + str(values.get("name"))
                        ).lower(),
                    }
                ):
                    raise InputError("Diagnostic plan ID conflicts with explicit target/name")
            else:
                identity = (
                    canonical_id(explicit_id) if verified and isinstance(explicit_id, str) else None
                )
            if identity and candidate and identity != candidate:
                raise InputError("Plan resource ID conflicts with explicit scope/name bindings")
            if identity and (not scope or not identity.startswith(scope.lower() + "/")):
                raise InputError("Plan resource ID is outside the explicit assessment scope")
            records.append(
                {
                    "logical_id": resource["address"],
                    "resource_type": arm_type,
                    "arm_id": identity,
                    "state": "known" if verified else "unknown",
                    "reason": "" if verified else "unverified_provider_version",
                    "source_location": str(path) + "#" + resource["address"],
                    "properties": normalized if verified else {},
                }
            )
            if kind == "azurerm_storage_account":
                records.append(tf_blob_service(records[-1], values))
            if len(records) > 256:
                raise InputError("Plan resource limit includes default blob-service children")
        for child in children:
            if not isinstance(child, dict):
                raise InputError("Invalid plan child module")
            walk(child, depth + 1)

    root = plan["planned_values"].get("root_module")
    if not isinstance(root, dict):
        raise InputError("Plan JSON has no root module")
    walk(root)
    if plan.get("complete") is False or plan.get("errored") is True:
        diagnostics.append({"reason": "plan_declares_incomplete_or_errored"})
    return validate(
        document(
            "evidence",
            mode="planned",
            source="terraform-plan",
            collected_at=now(),
            scope=scope,
            artifact_hashes=artifacts,
            inventory_complete=not diagnostics and provider_version == PROVIDER_VERSION,
            resources=records,
            diagnostics=diagnostics,
            metadata={
                "source_binding": "reviewed-explicit-hash-binding"
                if source_binding
                else "not-supplied",
                "warning": "Plan facts do not overwrite or prove equivalence to raw-source facts.",
            },
        )
    )
