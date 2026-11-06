"""Bounded ARM evaluation; unresolved runtime operations never execute."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from lark import Lark, Token, Tree
from lark.exceptions import LarkError

from .bicep import compile_bicep
from .contracts import (
    canonical_id,
    derive_id,
    digest,
    document,
    now,
    read_document,
    scope_id,
    validate,
)
from .sources import boolean, enumeration, file_hash, unknown
from .terraform import InputError, Unknown, exact_equal

PARSER = Lark(
    r"""
?start: expr
?expr: atom accessor* -> access
?atom: NAME "(" [expr ("," expr)*] ")" -> call
     | STRING -> string
     | SIGNED_INT -> integer
accessor: "." NAME -> attr
        | "[" expr "]" -> index
NAME: /[a-zA-Z_][a-zA-Z0-9_]*/
STRING: /'(?:[^']|'')*'/
%import common.SIGNED_INT
%import common.WS
%ignore WS
""",
    parser="lalr",
    maybe_placeholders=False,
)

API_VERSIONS = {
    "microsoft.storage/storageaccounts": {"2023-05-01"},
    "microsoft.network/firewallpolicies": {"2024-05-01"},
    "microsoft.keyvault/vaults": {"2024-11-01"},
    "microsoft.storage/storageaccounts/blobservices": {"2023-05-01"},
    "microsoft.network/azurefirewalls": {"2024-05-01"},
    "microsoft.network/virtualnetworks/subnets": {"2024-05-01"},
    "microsoft.network/ipgroups": {"2024-05-01"},
    "microsoft.network/virtualnetworks": {"2024-05-01"},
    "microsoft.network/privateendpoints": {"2024-05-01"},
    "microsoft.network/firewallpolicies/rulecollectiongroups": {"2024-05-01"},
    "microsoft.network/networksecuritygroups": {"2024-05-01"},
    "microsoft.network/networksecuritygroups/securityrules": {"2024-05-01"},
    "microsoft.network/virtualnetworkgateways": {"2024-05-01"},
    "microsoft.network/networkwatchers/flowlogs": {"2024-05-01"},
    "microsoft.network/routetables": {"2024-05-01"},
    "microsoft.network/virtualnetworks/virtualnetworkpeerings": {"2024-05-01"},
    "microsoft.network/loadbalancers": {"2024-05-01"},
    "microsoft.network/loadbalancers/backendaddresspools": {"2024-05-01"},
    "microsoft.network/expressrouteports": {"2024-05-01"},
    "microsoft.network/connections": {"2024-05-01"},
    "microsoft.authorization/roleassignments": {"2022-04-01"},
    "microsoft.network/frontdoorwebapplicationfirewallpolicies": {"2024-02-01"},
    "microsoft.cdn/profiles/securitypolicies": {"2024-02-01"},
    "microsoft.network/applicationgateways": {"2024-05-01"},
    "microsoft.network/applicationgatewaywebapplicationfirewallpolicies": {"2024-05-01"},
    "microsoft.network/publicipaddresses": {"2024-05-01"},
    "microsoft.network/networkinterfaces": {"2024-05-01"},
    "microsoft.insights/diagnosticsettings": {"2021-05-01-preview"},
}
PLANNED_API_VERSIONS = API_VERSIONS | {
    "microsoft.security/pricings": {"2024-01-01"},
    "microsoft.keyvault/managedhsms": {"2024-11-01"},
    "microsoft.compute/virtualmachines": {"2024-07-01"},
}


def unresolved(value: Any) -> bool:
    if isinstance(value, dict):
        return "unknown" in value or any(unresolved(v) for v in value.values())
    return isinstance(value, list) and any(unresolved(v) for v in value)


def properties(
    kind: str, values: Any, *, root: Any = None, observed: bool = False
) -> dict[str, Any]:
    from .identity_evidence import IDENTITY_KINDS, ROLE_KIND, identity_summary, role_properties
    from .security_evidence import projected_properties as security_properties

    if isinstance(values, dict) and kind.lower() == ROLE_KIND:
        return role_properties(values, terraform=False)
    result = _properties(kind, values, root=root, observed=observed)
    if kind.lower() in IDENTITY_KINDS and isinstance(root, dict) and "identity" in root:
        result["identitySummary"] = identity_summary(
            root["identity"], terraform=False, resource_type=kind
        )
    if isinstance(values, dict):
        result.update(security_properties(kind, values, root=root))
    return result


def _properties(
    kind: str, values: Any, *, root: Any = None, observed: bool = False
) -> dict[str, Any]:
    if not isinstance(values, dict):
        return {}
    if kind.lower() == "microsoft.storage/storageaccounts":
        return {
            "supportsHttpsTrafficOnly": boolean(values.get("supportsHttpsTrafficOnly")),
            "minimumTlsVersion": enumeration(
                values.get("minimumTlsVersion"), ("TLS1_0", "TLS1_1", "TLS1_2")
            ),
        }
    if kind.lower() == "microsoft.keyvault/vaults":
        acls = values.get("networkAcls")
        return {
            "enableSoftDelete": boolean(values.get("enableSoftDelete")),
            "enablePurgeProtection": boolean(values.get("enablePurgeProtection")),
            "enableRbacAuthorization": boolean(values.get("enableRbacAuthorization")),
            "publicNetworkAccess": enumeration(
                values.get("publicNetworkAccess"), ("Enabled", "Disabled")
            ),
            "networkAcls": {
                "defaultAction": enumeration(
                    acls.get("defaultAction") if isinstance(acls, dict) else None,
                    ("Allow", "Deny"),
                )
            },
        }
    if kind.lower() == "microsoft.storage/storageaccounts/blobservices":
        retention = values.get("containerDeleteRetentionPolicy")
        return {
            "containerDeleteRetentionPolicy": {
                "enabled": boolean(
                    retention.get("enabled") if isinstance(retention, dict) else None
                )
            }
        }
    if kind.lower() == "microsoft.network/firewallpolicies":
        dns = values.get("dnsSettings")
        proxy = dns.get("enableProxy") if isinstance(dns, dict) else None
        sku, intrusion = values.get("sku"), values.get("intrusionDetection")
        return {
            "dnsSettings": {"enableProxy": boolean(proxy)},
            "sku": {
                "tier": enumeration(
                    sku.get("tier") if isinstance(sku, dict) else None,
                    ("Basic", "Standard", "Premium"),
                )
            },
            "threatIntelMode": enumeration(values.get("threatIntelMode"), ("Alert", "Deny", "Off")),
            "intrusionDetection": {
                "mode": enumeration(
                    intrusion.get("mode") if isinstance(intrusion, dict) else None,
                    ("Alert", "Deny", "Off"),
                )
            },
        }
    from .network_evidence import projected_properties

    return projected_properties(kind, values, root=root, observed=observed)


class Expressions:
    def __init__(
        self,
        template: dict[str, Any],
        supplied: dict[str, Any],
        scope: str | None,
    ) -> None:
        self.parameters: dict[str, Any] = {}
        self.literal_parameters = set(supplied)
        self.variables = template.get("variables", {})
        self.scope = scope
        self.steps = 0
        self.active: set[str] = set()
        self.index = 0
        declarations = template.get("parameters", {})
        if not isinstance(declarations, dict) or not isinstance(self.variables, dict):
            raise InputError("ARM parameters and variables must be objects")
        if set(supplied) - set(declarations):
            raise InputError("Supplied ARM parameter is not declared")
        for key, entry in declarations.items():
            if not isinstance(entry, dict):
                raise InputError("ARM parameter declaration must be an object")
            value = supplied.get(key, entry.get("defaultValue", unknown("required_parameter")))
            if str(entry.get("type", "")).lower() in {"securestring", "secureobject"}:
                value = unknown("secure_parameter_withheld")
            self.parameters[key] = value

    def value(self, value: Any, depth: int = 0) -> Any:
        self.steps += 1
        if depth > 64 or self.steps > 10_000:
            return unknown("arm_expression_limit")
        if isinstance(value, str) and value.startswith("[["):
            return value[1:]
        if isinstance(value, str) and value.startswith("[") and value.endswith("]"):
            try:
                return self.node(PARSER.parse(value[1:-1]), depth + 1)
            except (LarkError, RecursionError):
                return unknown("unsupported_arm_expression")
        if isinstance(value, dict):
            return {key: self.value(item, depth + 1) for key, item in value.items()}
        if isinstance(value, list):
            return [self.value(item, depth + 1) for item in value]
        return value

    def node(self, node: Tree[Any] | Token, depth: int) -> Any:
        self.steps += 1
        if depth > 64 or self.steps > 10_000 or not isinstance(node, Tree):
            return unknown("arm_expression_limit")
        children = node.children
        if node.data == "integer":
            text = str(children[0])
            return int(text) if len(text) <= 1233 else unknown("numeric_size_limit")
        if node.data == "string":
            return str(children[0])[1:-1].replace("''", "'")
        if node.data == "access":
            current = self.node(children[0], depth + 1)
            for accessor in children[1:]:
                if not isinstance(accessor, Tree):
                    return unknown("invalid_arm_accessor")
                key = (
                    str(accessor.children[0])
                    if accessor.data == "attr"
                    else self.node(
                        accessor.children[0],
                        depth + 1,
                    )
                )
                if isinstance(current, dict) and isinstance(key, str):
                    current = current.get(key, unknown("arm_property_missing"))
                elif isinstance(current, list) and type(key) is int and 0 <= key < len(current):
                    current = current[key]
                else:
                    return unknown("arm_index_unresolved")
            return current
        if node.data != "call":
            return unknown("unsupported_arm_node")
        name = str(children[0]).lower()
        if name == "if" and len(children) == 4:
            condition = self.node(children[1], depth + 1)
            return (
                self.node(children[2 if condition else 3], depth + 1)
                if type(
                    condition,
                )
                is bool
                else unknown("arm_condition_unresolved")
            )
        args = [self.node(child, depth + 1) for child in children[1:]]
        if unresolved(args):
            return unknown("arm_argument_unresolved")
        if name in {"parameters", "variables"} and len(args) == 1 and isinstance(args[0], str):
            key = args[0]
            if name == "parameters":
                value = self.parameters.get(key, unknown("parameter_missing"))
                return value if key in self.literal_parameters else self.value(value, depth + 1)
            if key in self.active:
                return unknown("arm_variable_cycle")
            self.active.add(key)
            try:
                return self.value(self.variables.get(key, unknown("variable_missing")), depth + 1)
            finally:
                self.active.remove(key)
        if name in {"true", "false", "null"} and not args:
            return {"true": True, "false": False, "null": None}[name]
        if name == "copyindex" and not args:
            return self.index
        if name == "copyindex" and len(args) == 1 and type(args[0]) is int:
            return self.index + args[0]
        if name == "concat" and all(isinstance(arg, str) for arg in args):
            return "".join(args) if sum(map(len, args)) <= 2_000_000 else unknown("string_limit")
        if name in {"tolower", "toupper"} and len(args) == 1 and isinstance(args[0], str):
            return args[0].lower() if name == "tolower" else args[0].upper()
        if name == "equals" and len(args) == 2:
            result = exact_equal(args[0], args[1])
            return unknown(result.reason) if isinstance(result, Unknown) else result
        if name in {"not", "and", "or"} and args and all(type(arg) is bool for arg in args):
            if name == "not":
                return not args[0] if len(args) == 1 else unknown("invalid_not")
            return all(args) if name == "and" else any(args)
        if name == "length" and len(args) == 1 and isinstance(args[0], (dict, list, str)):
            return len(args[0])
        if (
            name == "resourcegroup"
            and not args
            and self.scope
            and "/resourcegroups/" in self.scope.lower()
        ):
            return {"id": self.scope, "name": self.scope.split("/")[-1]}
        if (
            name == "subscription"
            and not args
            and self.scope
            and self.scope.lower().startswith("/subscriptions/")
        ):
            return {
                "subscriptionId": self.scope.split("/")[2],
                "id": "/".join(self.scope.split("/")[:3]),
            }
        if name == "resourceid" and len(args) >= 2 and all(isinstance(arg, str) for arg in args):
            if self.scope and args[0].startswith("Microsoft."):
                return derive_id(self.scope, args[0], "/".join(args[1:])) or unknown(
                    "identity_unresolved"
                )
        return unknown("unsupported_arm_function:" + name)


def arm_source(
    source: Path,
    *,
    scope: str | None = None,
    parameters: Path | None = None,
    compiler: str | None = None,
    bicep: bool = False,
) -> dict[str, Any]:
    if source.stat().st_size > 2_000_000:
        raise InputError("ARM/Bicep source exceeds byte limit")
    if scope:
        scope_id(scope)
    compiled = compile_bicep(source, compiler) if bicep else None
    template = compiled["template"] if compiled else read_document(source, 2_000_000)
    if not isinstance(template, dict) or not isinstance(template.get("resources"), (list, dict)):
        raise InputError("ARM template requires a resources collection")
    supplied = {}
    artifacts = {str(source): file_hash(source), "scope-binding": digest(scope)}
    if compiled:
        artifacts["compiled-template"] = compiled["template_sha256"]
        artifacts["compiler-version"] = digest(compiled["compiler_version"])
    if parameters:
        if parameters.stat().st_size > 2_000_000:
            raise InputError("ARM parameter file exceeds byte limit")
        raw = read_document(parameters, 2_000_000)
        if not isinstance(raw, dict) or not isinstance(raw.get("parameters"), dict):
            raise InputError("Expected ARM deployment-parameters JSON")
        for key, value in raw["parameters"].items():
            if not isinstance(value, dict):
                raise InputError("ARM parameter value must be an object")
            supplied[key] = value.get("value", unknown("keyvault_parameter_not_retrieved"))
        artifacts[str(parameters)] = file_hash(parameters)
    records: list[dict[str, Any]] = []
    diagnostics: list[dict[str, str]] = []

    def walk(
        body: dict[str, Any],
        values: dict[str, Any],
        target_scope: str | None,
        prefix: str = "",
        depth: int = 0,
    ) -> None:
        if depth >= 16:
            diagnostics.append({"reason": "arm_deployment_depth_limit"})
            return
        context = Expressions(body, values, target_scope)
        resources = body.get("resources", [])
        if isinstance(resources, dict):
            items = list(resources.items())
        elif isinstance(resources, list):
            items = [(str(i), entry) for i, entry in enumerate(resources)]
        else:
            raise InputError("ARM resources must be a list or symbolic object")
        for label, entry in items:
            if not isinstance(entry, dict):
                raise InputError("ARM resource declaration must be an object")
            condition = context.value(entry.get("condition", True))
            if condition is False:
                continue
            copy = entry.get("copy")
            count = context.value(copy.get("count")) if isinstance(copy, dict) else 1
            known_count = type(count) is int and 0 <= count <= 256
            if not known_count:
                count = 1
                diagnostics.append(
                    {"reason": "arm_copy_unknown_or_expansion_limit", "address": label}
                )
            for index in range(count):
                if len(records) >= 256:
                    diagnostics.append({"reason": "arm_resource_limit"})
                    return
                context.index = index
                kind = context.value(entry.get("type"))
                name = context.value(entry.get("name"))
                version = context.value(entry.get("apiVersion"))
                logical = f"{prefix}{label}[{index}]"
                if kind == "Microsoft.Resources/deployments":
                    properties_value = entry.get("properties", {})
                    inner = (
                        properties_value.get("template")
                        if isinstance(properties_value, dict)
                        else None
                    )
                    if not isinstance(inner, dict) or condition is not True or not known_count:
                        diagnostics.append(
                            {
                                "reason": "unavailable_or_conditional_linked_template",
                                "address": logical,
                            }
                        )
                        continue
                    options = properties_value.get("expressionEvaluationOptions", {})
                    if not isinstance(options, dict) or options.get("scope") != "inner":
                        diagnostics.append(
                            {
                                "reason": "nested_template_expression_scope_unverified",
                                "address": logical,
                            }
                        )
                        continue
                    child_scope = target_scope
                    if "scope" in entry:
                        explicit = context.value(entry["scope"])
                        child_scope = scope_id(explicit) if isinstance(explicit, str) else None
                    elif "subscriptionId" in entry or "resourceGroup" in entry:
                        parent_sub = (
                            target_scope.split("/")[2]
                            if target_scope and target_scope.lower().startswith("/subscriptions/")
                            else None
                        )
                        subscription = context.value(entry.get("subscriptionId", parent_sub))
                        group = context.value(entry.get("resourceGroup"))
                        child_scope = (
                            scope_id(
                                f"/subscriptions/{subscription}"
                                + (f"/resourceGroups/{group}" if group is not None else "")
                            )
                            if isinstance(subscription, str)
                            and (group is None or isinstance(group, str))
                            else None
                        )
                    if child_scope is None:
                        diagnostics.append(
                            {"reason": "nested_deployment_scope_unresolved", "address": logical}
                        )
                        continue
                    bindings = properties_value.get("parameters", {})
                    if not isinstance(bindings, dict) or any(
                        not isinstance(value, dict) for value in bindings.values()
                    ):
                        raise InputError("Nested deployment parameters must contain objects")
                    child = {
                        key: context.value(value.get("value", unknown("nested_parameter_missing")))
                        for key, value in bindings.items()
                    }
                    walk(inner, child, child_scope, logical + ".", depth + 1)
                    continue
                arm_type = kind if isinstance(kind, str) else "unknown"
                supported = (
                    version in PLANNED_API_VERSIONS.get(arm_type.lower(), set())
                    if isinstance(version, str)
                    else False
                )
                applicable = arm_type.lower() in PLANNED_API_VERSIONS
                state = (
                    "known"
                    if condition is True and known_count and (supported or not applicable)
                    else "unknown"
                )
                if arm_type.lower() == "microsoft.storage/storageaccounts/blobservices" and (
                    not isinstance(name, str) or name.split("/")[-1] != "default"
                ):
                    state = "unknown"
                binding = target_scope
                diagnostic_target = (
                    target_scope
                    if arm_type.lower() == "microsoft.insights/diagnosticsettings"
                    and "scope" not in entry
                    else None
                )
                if "scope" in entry:
                    explicit_scope = context.value(entry["scope"])
                    if arm_type.lower() == "microsoft.insights/diagnosticsettings":
                        if isinstance(explicit_scope, str):
                            if explicit_scope.startswith("Microsoft."):
                                parts = explicit_scope.split("/")
                                explicit_scope = derive_id(
                                    target_scope,
                                    "/".join([parts[0], *parts[1::2]]),
                                    "/".join(parts[2::2]),
                                )
                            if isinstance(explicit_scope, str):
                                diagnostic_target = canonical_id(explicit_scope)
                        if not (
                            target_scope
                            and diagnostic_target
                            and (
                                diagnostic_target == target_scope.lower()
                                or diagnostic_target.startswith(target_scope.lower() + "/")
                            )
                        ):
                            binding, state = None, "unknown"
                    else:
                        binding = (
                            scope_id(explicit_scope) if isinstance(explicit_scope, str) else None
                        )
                identity = (
                    canonical_id(
                        diagnostic_target
                        + "/providers/Microsoft.Insights/diagnosticSettings/"
                        + name
                    )
                    if diagnostic_target
                    and state == "known"
                    and isinstance(name, str)
                    and name
                    and "/" not in name
                    else derive_id(binding, kind, name)
                    if state == "known"
                    else None
                )
                records.append(
                    {
                        "logical_id": logical,
                        "resource_type": arm_type,
                        "arm_id": identity,
                        "original_arm_id": identity,
                        "api_version": version if isinstance(version, str) else None,
                        "properties": properties(
                            arm_type,
                            context.value(entry.get("properties", {})),
                            root={
                                "scope": diagnostic_target,
                                "name": name,
                                "zones": context.value(entry.get("zones")),
                                "sku": context.value(entry.get("sku")),
                                **(
                                    {"identity": context.value(entry["identity"])}
                                    if "identity" in entry
                                    else {}
                                ),
                            },
                        )
                        if state == "known"
                        else {},
                        "state": state,
                        "reason": ""
                        if state == "known"
                        else "arm_condition_copy_or_api_unresolved",
                        "source_location": str(source) + "#/resources/" + logical,
                    }
                )
                if condition is not True:
                    diagnostics.append({"reason": "arm_condition_unknown", "address": logical})
                if identity is None:
                    diagnostics.append({"reason": "arm_identity_unresolved", "address": logical})
                if "resources" in entry:
                    diagnostics.append(
                        {
                            "reason": "nested_child_resources_require_explicit_full_declarations",
                            "address": logical,
                        }
                    )

    walk(template, supplied, scope)
    return validate(
        document(
            "evidence",
            mode="planned",
            source="bicep" if bicep else "arm",
            collected_at=now(),
            scope=scope,
            artifact_hashes=artifacts,
            resources=records,
            inventory_complete=not diagnostics,
            diagnostics=diagnostics,
            metadata={
                "compiler_version": compiled["compiler_version"] if compiled else None,
                "dependency_binding": (
                    "Compiled template bytes bind resolved dependencies; "
                    "individual cache-source hashes unavailable"
                )
                if compiled
                else "Direct template and explicit parameter artifact hashes",
                "limitations": (
                    "Bounded expressions; runtime references, linked/child declarations, "
                    "unverified nested expression scope and unsupported APIs remain unknown."
                ),
            },
        )
    )
