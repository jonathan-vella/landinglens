"""Bounded ARM evaluation; unresolved runtime operations never execute."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
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
    "microsoft.network/expressroutecircuits": {"2024-05-01"},
    "microsoft.network/connections": {"2024-05-01"},
    "microsoft.authorization/roleassignments": {"2022-04-01"},
    "microsoft.network/frontdoorwebapplicationfirewallpolicies": {"2024-02-01"},
    "microsoft.cdn/profiles/securitypolicies": {"2024-02-01"},
    "microsoft.network/applicationgateways": {"2024-05-01"},
    "microsoft.network/applicationgatewaywebapplicationfirewallpolicies": {"2024-05-01"},
    "microsoft.network/publicipaddresses": {"2024-05-01"},
    "microsoft.network/networkinterfaces": {"2024-05-01"},
    "microsoft.insights/diagnosticsettings": {"2021-05-01-preview"},
    "microsoft.network/privatednszones": {"2024-06-01"},
    "microsoft.network/privatednszones/virtualnetworklinks": {"2024-06-01"},
    "microsoft.network/dnsresolvers": {"2022-07-01"},
    "microsoft.network/dnsresolvers/inboundendpoints": {"2022-07-01"},
    "microsoft.network/dnsresolvers/outboundendpoints": {"2022-07-01"},
    "microsoft.network/dnsforwardingrulesets": {"2022-07-01"},
    "microsoft.network/dnsforwardingrulesets/forwardingrules": {"2022-07-01"},
    "microsoft.network/dnsforwardingrulesets/virtualnetworklinks": {"2022-07-01"},
    "microsoft.network/bastionhosts": {"2024-05-01"},
}
PLANNED_API_VERSIONS = API_VERSIONS | {
    "microsoft.network/firewallpolicies": {"2024-05-01", "2024-10-01"},
    "microsoft.network/azurefirewalls": {"2024-05-01", "2024-10-01"},
    "microsoft.network/routetables": {"2024-05-01", "2024-07-01"},
    "microsoft.network/virtualnetworks/virtualnetworkpeerings": {"2024-05-01", "2024-01-01"},
    "microsoft.consumption/budgets": {"2024-08-01"},
    "microsoft.recoveryservices/vaults": {"2024-01-01"},
    "microsoft.recoveryservices/vaults/backupstorageconfig": {"2023-02-01"},
    "microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems": {
        "2024-01-01"
    },
    "microsoft.recoveryservices/vaults/replicationfabrics/"
    "replicationprotectioncontainers/replicationprotecteditems": {"2024-04-01"},
    "microsoft.dataprotection/backupvaults": {"2024-04-01"},
    "microsoft.compute/virtualmachines/extensions": {"2024-07-01"},
    "microsoft.sql/servers/failovergroups": {"2023-08-01"},
    "microsoft.cdn/profiles": {"2024-02-01"},
    "microsoft.operationalinsights/workspaces/tables": {"2023-09-01"},
    "microsoft.operationalinsights/workspaces/dataexports": {"2020-08-01"},
    "microsoft.storage/storageaccounts/blobservices/containers/immutabilitypolicies": {
        "2023-05-01"
    },
    "microsoft.guestconfiguration/guestconfigurationassignments": {"2024-04-05"},
    "microsoft.hybridcompute/machines": {"2024-07-10"},
    "microsoft.authorization/locks": {"2020-05-01"},
    "microsoft.insights/activitylogalerts": {"2020-10-01"},
    "microsoft.insights/actiongroups": {"2023-01-01"},
    "microsoft.network/securitypartnerproviders": {"2024-05-01"},
    "microsoft.network/vpngateways": {"2024-05-01"},
    "microsoft.network/virtualwans": {"2024-05-01"},
    "microsoft.network/virtualhubs": {"2024-05-01"},
    "microsoft.network/virtualhubs/ipconfigurations": {"2024-05-01"},
    "microsoft.network/virtualhubs/hubvirtualnetworkconnections": {"2024-05-01"},
    "microsoft.network/virtualhubs/hubroutetables": {"2024-05-01"},
    "microsoft.network/virtualhubs/routingintent": {"2024-05-01"},
    "microsoft.network/networkwatchers/connectionmonitors": {"2024-05-01"},
    "microsoft.insights/metricalerts": {"2018-03-01"},
    "microsoft.security/pricings": {"2024-01-01"},
    "microsoft.keyvault/managedhsms": {"2024-11-01"},
    "microsoft.compute/virtualmachines": {"2024-07-01"},
    "microsoft.portal/dashboards": {"2020-09-01-preview"},
    "microsoft.management/managementgroups": {"2020-05-01"},
    "microsoft.management/managementgroups/settings": {"2020-05-01"},
    "microsoft.operationalinsights/workspaces": {"2023-09-01", "2025-07-01"},
    "microsoft.securityinsights/onboardingstates": {"2024-03-01", "2025-09-01"},
    "microsoft.insights/scheduledqueryrules": {"2023-12-01"},
    "microsoft.eventgrid/topics": {"2022-06-15"},
    "microsoft.compute/availabilitysets": {"2024-07-01"},
    "microsoft.authorization/roledefinitions": {"2022-04-01"},
    "microsoft.aad/domainservices": {"2022-12-01"},
    "microsoft.authorization/policydefinitions": {"2023-04-01"},
    "microsoft.authorization/policysetdefinitions": {"2023-04-01"},
    "microsoft.authorization/policyassignments": {"2023-04-01"},
    "microsoft.managedservices/registrationdefinitions": {"2022-10-01"},
    "microsoft.managedservices/registrationassignments": {"2022-10-01"},
    "microsoft.costmanagement/views": {"2019-11-01"},
}


def unresolved(value: Any) -> bool:
    if isinstance(value, dict):
        return "unknown" in value or any(unresolved(v) for v in value.values())
    return isinstance(value, list) and any(unresolved(v) for v in value)


def properties(
    kind: str, values: Any, *, root: Any = None, observed: bool = False
) -> dict[str, Any]:
    from .billing_evidence import projected_properties as billing_properties
    from .governance_evidence import projected_properties as governance_properties
    from .identity_evidence import IDENTITY_KINDS, ROLE_KIND, identity_summary, role_properties
    from .identity_evidence import projected_properties as identity_properties
    from .key_lifecycle_evidence import projected_properties as key_properties
    from .logging_evidence import projected_properties as logging_properties
    from .network_policy_evidence import projected_properties as network_policy_properties
    from .operations_evidence import projected_properties as operations_properties
    from .organization_evidence import projected_properties as organization_properties
    from .platform_health_evidence import projected_properties as platform_health_properties
    from .policy_strategy_evidence import projected_properties as policy_strategy_properties
    from .recovery_evidence import projected_properties as recovery_properties
    from .security_evidence import projected_properties as security_properties
    from .tenant_evidence import projected_properties as tenant_properties
    from .topology_evidence import projected_properties as topology_properties

    if isinstance(values, dict) and kind.lower() == ROLE_KIND:
        return role_properties(values, terraform=False)
    result = _properties(kind, values, root=root, observed=observed)
    if kind.lower() in IDENTITY_KINDS and isinstance(root, dict) and "identity" in root:
        result["identitySummary"] = identity_summary(
            root["identity"], terraform=False, resource_type=kind
        )
    if isinstance(values, dict):
        result.update(billing_properties(kind, values, root=root))
        result.update(security_properties(kind, values, root=root))
        result.update(key_properties(kind, values))
        result.update(governance_properties(kind, values, root=root))
        result.update(organization_properties(kind, values))
        result.update(logging_properties(kind, values, root=root))
        result.update(platform_health_properties(kind, values, root=root))
        result.update(recovery_properties(kind, values, root=root))
        result.update(network_policy_properties(kind, values))
        result.update(identity_properties(kind, values, root=root))
        result.update(policy_strategy_properties(kind, values))
        result.update(tenant_properties(kind, values))
        result.update(topology_properties(kind, values))
        result.update(operations_properties(kind, values))
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
        self.indices: dict[str, int] = {}
        self.lambda_values: dict[str, Any] = {}
        self.reference: Callable[[list[Any]], Any] | None = None
        self.variable_copies: dict[str, dict[str, Any]] = {}
        self.copy_values: dict[str, Any] = {}
        declarations = template.get("parameters", {})
        if not isinstance(declarations, dict) or not isinstance(self.variables, dict):
            raise InputError("ARM parameters and variables must be objects")
        copies = self.variables.get("copy", [])
        if not isinstance(copies, list) or len(copies) > 256:
            raise InputError("ARM variable copies must be a bounded list")
        for copy in copies:
            if (
                not isinstance(copy, dict)
                or not isinstance(copy.get("name"), str)
                or copy["name"] in self.variable_copies
                or copy["name"] in self.variables
            ):
                raise InputError("ARM variable copy names must be unique")
            self.variable_copies[copy["name"]] = copy
        if set(supplied) - set(declarations):
            raise InputError("Supplied ARM parameter is not declared")
        for key, entry in declarations.items():
            if not isinstance(entry, dict):
                raise InputError("ARM parameter declaration must be an object")
            parameter_type = entry
            seen_types: set[str] = set()
            while "$ref" in parameter_type:
                reference = parameter_type["$ref"]
                definitions = template.get("definitions", {})
                if (
                    not isinstance(reference, str)
                    or not reference.startswith("#/definitions/")
                    or reference in seen_types
                    or len(seen_types) >= 16
                    or not isinstance(definitions, dict)
                ):
                    parameter_type = {"type": "unresolved"}
                    break
                seen_types.add(reference)
                definition = definitions.get(reference.removeprefix("#/definitions/"))
                if not isinstance(definition, dict):
                    parameter_type = {"type": "unresolved"}
                    break
                parameter_type = definition
            if "nullable" in entry and type(entry["nullable"]) is not bool:
                raise InputError("ARM nullable parameter marker must be a boolean")
            default = None if entry.get("nullable") is True else unknown("required_parameter")
            value = supplied.get(key, entry.get("defaultValue", default))
            if value is None and entry.get("nullable") is not True:
                value = entry.get("defaultValue", unknown("nonnullable_parameter_null"))
                self.literal_parameters.discard(key)
            if str(parameter_type.get("type", "")).lower() in {"securestring", "secureobject"}:
                value = unknown("secure_parameter_withheld")
            elif parameter_type.get("type") == "unresolved":
                value = unknown("arm_parameter_type_unresolved")
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
            result = {
                key: self.value(item, depth + 1) for key, item in value.items() if key != "copy"
            }
            if "copy" in value:
                copies = value["copy"]
                if not isinstance(copies, list) or len(copies) > 256:
                    return unknown("invalid_arm_property_copy")
                for copy in copies:
                    if (
                        not isinstance(copy, dict)
                        or not isinstance(copy.get("name"), str)
                        or copy["name"] in result
                    ):
                        return unknown("invalid_arm_property_copy")
                    result[copy["name"]] = self.expand(copy, depth + 1)
            return result
        if isinstance(value, list):
            return [self.value(item, depth + 1) for item in value]
        return value

    def expand(self, copy: dict[str, Any], depth: int) -> Any:
        count = self.value(copy.get("count"), depth + 1)
        if type(count) is not int or not 0 <= count <= 256:
            return unknown("arm_variable_copy_limit_or_unknown")
        previous = self.indices.copy()
        try:
            result = []
            for index in range(count):
                self.indices[copy["name"]] = index
                result.append(self.value(copy.get("input"), depth + 1))
            return result
        finally:
            self.indices = previous

    def node(self, node: Tree[Any] | Token, depth: int) -> Any:
        result: Any
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
        if name == "coalesce":
            for child in children[1:]:
                value = self.node(child, depth + 1)
                if value is not None:
                    return value
            return None
        if name in {"map", "filter", "reduce"}:
            expected = 4 if name == "reduce" else 3
            if len(children) != expected:
                return unknown("invalid_arm_lambda")
            collection = self.node(children[1], depth + 1)
            expression = children[-1]
            if (
                not isinstance(collection, list)
                or len(collection) > 256
                or not isinstance(expression, Tree)
                or expression.data != "access"
                or len(expression.children) != 1
            ):
                return unknown("invalid_or_overbound_arm_lambda")
            function = expression.children[0]
            if (
                not isinstance(function, Tree)
                or function.data != "call"
                or str(function.children[0]).lower() != "lambda"
                or len(function.children) < 3
            ):
                return unknown("invalid_arm_lambda")
            keys = [self.node(child, depth + 1) for child in function.children[1:-1]]
            if (
                not all(isinstance(key, str) for key in keys)
                or len(set(keys)) != len(keys)
                or len(keys) not in ({2} if name == "reduce" else {1, 2})
            ):
                return unknown("invalid_arm_lambda_parameters")
            accumulated = self.node(children[2], depth + 1) if name == "reduce" else None
            result = []
            previous = self.lambda_values
            try:
                for index, item in enumerate(collection):
                    values = [accumulated, item] if name == "reduce" else [item, index]
                    self.lambda_values = previous | dict(zip(keys, values, strict=False))
                    value = self.node(function.children[-1], depth + 1)
                    if name == "filter" and type(value) is not bool:
                        return unknown("arm_filter_condition_unresolved")
                    if name == "reduce":
                        accumulated = value
                    elif name == "map":
                        result.append(value)
                    elif value:
                        result.append(item)
            finally:
                self.lambda_values = previous
            return accumulated if name == "reduce" else result
        args = [self.node(child, depth + 1) for child in children[1:]]
        if name == "reference":
            return self.reference(args) if self.reference else unknown("arm_reference_unresolved")
        if name == "lambdavariables" and len(args) == 1 and isinstance(args[0], str):
            return self.lambda_values.get(args[0], unknown("arm_lambda_variable_missing"))
        if name == "tryget" and len(args) >= 2:
            current = args[0]
            for key in args[1:]:
                if current is None:
                    return None
                if isinstance(current, dict) and "unknown" in current:
                    return unknown("arm_argument_unresolved")
                if isinstance(current, dict) and isinstance(key, str):
                    current = current.get(key)
                elif isinstance(current, list) and type(key) is int:
                    current = current[key] if 0 <= key < len(current) else None
                else:
                    return unknown("invalid_arm_tryget")
            return current
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
                if key in self.variable_copies:
                    if key not in self.copy_values:
                        copy = self.variable_copies[key]
                        self.copy_values[key] = self.expand(copy, depth + 1)
                    return self.copy_values[key]
                return self.value(self.variables.get(key, unknown("variable_missing")), depth + 1)
            finally:
                self.active.remove(key)
        if name in {"true", "false", "null"} and not args:
            return {"true": True, "false": False, "null": None}[name]
        if name == "copyindex" and not args:
            return self.index
        if name == "copyindex" and len(args) == 1 and type(args[0]) is int:
            return self.index + args[0]
        if name == "copyindex" and 1 <= len(args) <= 2 and isinstance(args[0], str):
            named_index = self.indices.get(args[0])
            offset = args[1] if len(args) == 2 else 0
            return (
                named_index + offset
                if named_index is not None and type(offset) is int
                else unknown("arm_copy_index_unresolved")
            )
        if name == "createarray" and len(args) <= 256:
            return args
        if (
            name == "array"
            and len(args) == 1
            and (isinstance(args[0], (str, list, dict)) or type(args[0]) is int)
        ):
            return args[0] if isinstance(args[0], list) else [args[0]]
        if name == "format" and args and isinstance(args[0], str):
            pattern = args[0]
            if (
                len(pattern) > 2_000_000
                or re.search(r"\{(?!\d+\})|(?<!\d)\}", pattern)
                or any(not isinstance(arg, str) and type(arg) is not int for arg in args[1:])
            ):
                return unknown("unsupported_arm_format")
            try:
                result = pattern.format(*args[1:])
            except (IndexError, KeyError, ValueError):
                return unknown("invalid_arm_format")
            return result if len(result) <= 2_000_000 else unknown("string_limit")
        if name == "union" and args and all(isinstance(arg, dict) for arg in args):
            result = {}
            for arg in args:
                for key, value in arg.items():
                    if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                        return unknown("nested_arm_union_unsupported")
                    result[key] = value
            return result if len(result) <= 256 else unknown("arm_object_limit")
        if name == "contains" and len(args) == 2:
            container, item = args
            if isinstance(container, (str, dict)) and isinstance(item, str):
                return (
                    item in container
                    if isinstance(container, str)
                    else item.casefold() in {key.casefold() for key in container}
                )
            if isinstance(container, list):
                return any(exact_equal(item, value) is True for value in container)
        if name == "indexof" and len(args) == 2 and isinstance(args[0], list):
            return next(
                (
                    index
                    for index, value in enumerate(args[0])
                    if exact_equal(value, args[1]) is True
                ),
                -1,
            )
        if name in {"startswith", "endswith"} and len(args) == 2:
            if all(isinstance(arg, str) for arg in args):
                value, part = args[0].lower(), args[1].lower()
                return value.startswith(part) if name == "startswith" else value.endswith(part)
        if name == "split" and len(args) == 2 and all(isinstance(arg, str) for arg in args):
            if not args[1]:
                return unknown("invalid_arm_split")
            parts = args[0].split(args[1], 256)
            return parts if len(parts) <= 256 else unknown("arm_array_limit")
        if name == "last" and len(args) == 1 and isinstance(args[0], (str, list)) and args[0]:
            return args[0][-1]
        if name == "int" and len(args) == 1:
            if type(args[0]) is int:
                return args[0]
            if isinstance(args[0], str) and re.fullmatch(r"-?\d{1,1233}", args[0]):
                return int(args[0])
        if name == "cidrhost" and len(args) == 2 and isinstance(args[0], str):
            if type(args[1]) is int:
                try:
                    network = ipaddress.ip_network(args[0], strict=True)
                    return str(network[args[1]]) if args[1] >= 0 else unknown("invalid_cidr_host")
                except (ValueError, IndexError):
                    return unknown("invalid_cidr_host")
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
        if name == "empty" and len(args) == 1 and isinstance(args[0], (dict, list, str)):
            return len(args[0]) == 0
        if name == "empty" and args == [None]:
            return True
        if name == "createobject":
            keys = args[::2]
            if (
                len(args) % 2
                or len(keys) > 256
                or not all(isinstance(key, str) for key in keys)
                or len({key.casefold() for key in keys}) != len(keys)
            ):
                return unknown("invalid_or_overbound_arm_object")
            return dict(zip(keys, args[1::2], strict=True))
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
            if len(args) >= 4 and args[2].startswith("Microsoft."):
                binding = scope_id(f"/subscriptions/{args[0]}/resourceGroups/{args[1]}")
                return derive_id(binding, args[2], "/".join(args[3:])) or unknown(
                    "identity_unresolved"
                )
        if (
            name == "subscriptionresourceid"
            and len(args) >= 2
            and all(isinstance(arg, str) for arg in args)
            and args[0].startswith("Microsoft.")
            and self.scope
            and self.scope.lower().startswith("/subscriptions/")
        ):
            return derive_id(
                "/".join(self.scope.split("/")[:3]), args[0], "/".join(args[1:])
            ) or unknown("identity_unresolved")
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
    instances = 0

    def walk(
        body: dict[str, Any],
        values: dict[str, Any],
        target_scope: str | None,
        prefix: str = "",
        depth: int = 0,
        *,
        emit: bool = True,
    ) -> Expressions | None:
        nonlocal instances
        if depth >= 16:
            diagnostics.append({"reason": "arm_deployment_depth_limit"})
            return None
        context = Expressions(body, values, target_scope)
        resources = body.get("resources", [])
        if isinstance(resources, dict):
            items = list(resources.items())
        elif isinstance(resources, list):
            items = [(str(i), entry) for i, entry in enumerate(resources)]
        else:
            raise InputError("ARM resources must be a list or symbolic object")
        children: dict[tuple[str, int], tuple[dict[str, Any], dict[str, Any], str]] = {}
        active_references: set[tuple[str, int]] = set()
        referenced: dict[tuple[str, ...], Any] = {}

        def deployment(
            entry: dict[str, Any], label: str, index: int
        ) -> tuple[dict[str, Any], dict[str, Any], str] | None:
            key = (label, index)
            if key in children:
                return children[key]
            properties_value = entry.get("properties", {})
            inner = properties_value.get("template") if isinstance(properties_value, dict) else None
            if not isinstance(inner, dict):
                diagnostics.append({"reason": "unavailable_or_conditional_linked_template"})
                return None
            options = properties_value.get("expressionEvaluationOptions", {})
            if not isinstance(options, dict) or options.get("scope") != "inner":
                diagnostics.append({"reason": "nested_template_expression_scope_unverified"})
                return None
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
                    if isinstance(subscription, str) and (group is None or isinstance(group, str))
                    else None
                )
            if child_scope is None:
                diagnostics.append({"reason": "nested_deployment_scope_unresolved"})
                return None
            bindings = properties_value.get("parameters", {})
            if not isinstance(bindings, dict):
                raise InputError("Nested deployment parameters must contain objects")
            child = {}
            for name, binding in bindings.items():
                if isinstance(binding, dict):
                    descriptor = context.value(binding)
                elif isinstance(binding, str) and binding.startswith("[") and binding.endswith("]"):
                    descriptor = context.value(binding)
                else:
                    raise InputError("Nested deployment parameters must contain objects")
                if isinstance(descriptor, dict):
                    child[name] = descriptor.get("value", unknown("nested_parameter_missing"))
                    if "unknown" in descriptor:
                        child[name] = unknown("nested_parameter_binding_unresolved")
                        diagnostics.append({"reason": "nested_parameter_binding_unresolved"})
                else:
                    raise InputError("Nested deployment parameters must contain objects")
            children[key] = (inner, child, child_scope)
            return children[key]

        def reference(args: list[Any]) -> Any:
            nonlocal instances
            if (
                not 1 <= len(args) <= 3
                or not all(isinstance(arg, str) for arg in args)
                or not isinstance(resources, dict)
            ):
                return unknown("arm_reference_not_local_symbolic")
            match = re.fullmatch(r"([a-zA-Z_][a-zA-Z0-9_]*)(?:\[(\d{1,3})\])?", args[0])
            if not match:
                return unknown("arm_reference_not_local_symbolic")
            label, text = match.groups()
            entry = resources.get(label)
            index = int(text) if text is not None else 0
            key = (label, index)
            if not isinstance(entry, dict) or entry.get("existing") is True:
                return unknown("arm_reference_not_local_declaration")
            if key in active_references:
                return unknown("arm_reference_cycle")
            cache_key = tuple(args)
            if cache_key in referenced:
                return referenced[cache_key]
            if instances >= 256:
                return unknown("arm_instance_limit")
            instances += 1
            previous_index, previous_indices = context.index, context.indices.copy()
            active_references.add(key)
            try:
                copy = entry.get("copy")
                count = context.value(copy.get("count")) if isinstance(copy, dict) else 1
                if (
                    type(count) is not int
                    or not 0 <= index < count <= 256
                    or (text is not None) != isinstance(copy, dict)
                ):
                    return unknown("arm_reference_copy_unresolved")
                context.index = index
                if isinstance(copy, dict) and isinstance(copy.get("name"), str):
                    context.indices[copy["name"]] = index
                if context.value(entry.get("condition", True)) is not True:
                    return unknown("arm_reference_condition_unresolved")
                if len(args) >= 2 and context.value(entry.get("apiVersion")) != args[1]:
                    return unknown("arm_reference_api_mismatch")
                if context.value(entry.get("type")) != "Microsoft.Resources/deployments":
                    if len(args) != 3 or args[2].lower() != "full":
                        return unknown("arm_runtime_resource_reference")
                    name = context.value(entry.get("name"))
                    kind = context.value(entry.get("type"))
                    result = {
                        "unknown": "partial_declared_resource_reference",
                        "name": name,
                        "location": context.value(entry.get("location")),
                        "id": derive_id(target_scope, kind, name)
                        if isinstance(kind, str) and isinstance(name, str) and "scope" not in entry
                        else unknown("identity_unresolved"),
                    }
                    referenced[cache_key] = result
                    return result
                if len(args) == 3:
                    return unknown("arm_module_reference_shape_unsupported")
                child = deployment(entry, label, index)
                if child is None:
                    return unknown("arm_module_output_unresolved")
                inner, bindings, child_scope = child
                frame = walk(inner, bindings, child_scope, depth=depth + 1, emit=False)
                if frame is None:
                    return unknown("arm_module_output_depth_limit")
                outputs = inner.get("outputs", {})
                if not isinstance(outputs, dict) or len(outputs) > 256:
                    return unknown("invalid_arm_outputs")
                result = {
                    "outputs": {
                        name: {
                            "value": frame.value(output.get("value"))
                            if isinstance(output, dict)
                            and "value" in output
                            and isinstance(output.get("type"), str)
                            and output["type"].lower()
                            in {"string", "int", "bool", "array", "object"}
                            else unknown("arm_output_copy_secure_or_unresolved")
                        }
                        for name, output in outputs.items()
                    }
                }
                referenced[cache_key] = result
                return result
            finally:
                context.index, context.indices = previous_index, previous_indices
                active_references.remove(key)

        context.reference = reference
        if not emit:
            return context
        for label, entry in items:
            if not isinstance(entry, dict):
                raise InputError("ARM resource declaration must be an object")
            if "existing" in entry and type(entry["existing"]) is not bool:
                raise InputError("ARM existing resource marker must be a boolean")
            if entry.get("existing") is True:
                diagnostics.append(
                    {"reason": "existing_resource_reference_not_inventory", "address": label}
                )
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
                if instances >= 256:
                    diagnostics.append({"reason": "arm_instance_limit", "address": label})
                    return context
                instances += 1
                if len(records) >= 256:
                    diagnostics.append({"reason": "arm_resource_limit"})
                    return None
                context.index = index
                if isinstance(copy, dict) and isinstance(copy.get("name"), str):
                    context.indices = {copy["name"]: index}
                else:
                    context.indices = {}
                condition = context.value(entry.get("condition", True))
                if condition is False:
                    continue
                kind = context.value(entry.get("type"))
                name = context.value(entry.get("name"))
                version = context.value(entry.get("apiVersion"))
                logical = f"{prefix}{label}[{index}]"
                if kind == "Microsoft.Resources/deployments":
                    if condition is not True or not known_count:
                        diagnostics.append(
                            {
                                "reason": "unavailable_or_conditional_linked_template",
                                "address": logical,
                            }
                        )
                        continue
                    child_frame = deployment(entry, label, index)
                    if child_frame is None:
                        continue
                    inner, child, child_scope = child_frame
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
                if arm_type.lower() == "microsoft.aadiam/diagnosticsettings":
                    state = "unknown"
                    diagnostics.append(
                        {
                            "reason": "tenant_directory_diagnostics_scope_unsupported",
                            "address": logical,
                        }
                    )
                if arm_type.lower() == "microsoft.storage/storageaccounts/blobservices" and (
                    not isinstance(name, str) or name.split("/")[-1] != "default"
                ):
                    state = "unknown"
                binding = target_scope
                from .operations_evidence import GUEST, LOCK, lock_scope

                operations_extension = arm_type.lower() in {GUEST, LOCK}
                generic_target = None
                operations_target = target_scope if arm_type.lower() == LOCK else None
                onboarding_target = None
                diagnostic_target = (
                    target_scope
                    if arm_type.lower() == "microsoft.insights/diagnosticsettings"
                    and "scope" not in entry
                    else None
                )
                if "scope" in entry:
                    explicit_scope = context.value(entry["scope"])
                    if operations_extension:
                        if isinstance(explicit_scope, str) and explicit_scope.startswith(
                            "Microsoft."
                        ):
                            parts = explicit_scope.split("/")
                            explicit_scope = derive_id(
                                target_scope,
                                "/".join([parts[0], *parts[1::2]]),
                                "/".join(parts[2::2]),
                            )
                        operations_target = lock_scope(explicit_scope)
                    elif arm_type.lower() in {
                        "microsoft.insights/diagnosticsettings",
                        "microsoft.securityinsights/onboardingstates",
                    }:
                        if isinstance(explicit_scope, str):
                            if explicit_scope.startswith("Microsoft."):
                                parts = explicit_scope.split("/")
                                explicit_scope = derive_id(
                                    target_scope,
                                    "/".join([parts[0], *parts[1::2]]),
                                    "/".join(parts[2::2]),
                                )
                            if isinstance(explicit_scope, str):
                                if (
                                    arm_type.lower()
                                    == "microsoft.securityinsights/onboardingstates"
                                ):
                                    from .protection_evidence import typed_reference

                                    target = typed_reference(
                                        explicit_scope,
                                        ("microsoft.operationalinsights/workspaces",),
                                    )
                                    onboarding_target = target if isinstance(target, str) else None
                                else:
                                    diagnostic_target = canonical_id(explicit_scope)
                        extension_target = onboarding_target or diagnostic_target
                        if not (
                            target_scope
                            and extension_target
                            and (
                                extension_target == target_scope.lower()
                                or extension_target.startswith(target_scope.lower() + "/")
                            )
                        ):
                            binding, state = None, "unknown"
                    else:
                        if isinstance(explicit_scope, str) and explicit_scope.startswith(
                            "Microsoft."
                        ):
                            parts = explicit_scope.split("/")
                            explicit_scope = derive_id(
                                target_scope,
                                "/".join([parts[0], *parts[1::2]]),
                                "/".join(parts[2::2]),
                            )
                        binding = (
                            canonical_id(explicit_scope)
                            if isinstance(explicit_scope, str)
                            else None
                        )
                        if binding and "/providers/" in binding and binding != target_scope:
                            generic_target, binding = binding, target_scope
                            if not (
                                target_scope
                                and generic_target.startswith(target_scope.lower() + "/")
                            ):
                                binding, state = None, "unknown"
                if operations_extension:
                    from .contracts import identity_type

                    if not (
                        target_scope
                        and operations_target
                        and (
                            operations_target == target_scope.lower()
                            or operations_target.startswith(target_scope.lower() + "/")
                        )
                        and (
                            arm_type.lower() == LOCK
                            or identity_type(operations_target)
                            in {
                                "microsoft.compute/virtualmachines",
                                "microsoft.hybridcompute/machines",
                            }
                        )
                        and isinstance(name, str)
                        and name
                        and "/" not in name
                    ):
                        binding, state = None, "unknown"
                if arm_type.lower() == "microsoft.securityinsights/onboardingstates" and (
                    not onboarding_target or name != "default"
                ):
                    binding, state = None, "unknown"
                identity = (
                    canonical_id(operations_target + "/providers/" + arm_type + "/" + name)
                    if operations_extension and operations_target and state == "known"
                    else canonical_id(
                        onboarding_target
                        + "/providers/Microsoft.SecurityInsights/onboardingStates/default"
                    )
                    if onboarding_target and state == "known"
                    else canonical_id(
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
                if (
                    generic_target
                    and binding
                    and state == "known"
                    and isinstance(name, str)
                    and "/" not in name
                ):
                    identity = canonical_id(f"{generic_target}/providers/{arm_type}/{name}")
                if (
                    arm_type.lower()
                    in {
                        "microsoft.management/managementgroups",
                        "microsoft.management/managementgroups/settings",
                    }
                    and state == "known"
                ):
                    from .organization_evidence import explicit_identity

                    identity = explicit_identity(arm_type, name, binding)
                records.append(
                    {
                        "logical_id": logical,
                        "_frame": prefix,
                        "resource_type": arm_type,
                        "arm_id": identity,
                        "original_arm_id": identity,
                        "api_version": version if isinstance(version, str) else None,
                        "properties": properties(
                            arm_type,
                            context.value(entry.get("properties", {})),
                            root={
                                "apiVersion": version,
                                "location": context.value(entry.get("location")),
                                "scope": diagnostic_target,
                                "name": name,
                                "zones": context.value(entry.get("zones")),
                                "sku": context.value(entry.get("sku")),
                                "kind": context.value(entry.get("kind")),
                                **(
                                    {"tags": context.value(entry["tags"])}
                                    if "tags" in entry
                                    else {}
                                ),
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

        return context

    walk(template, supplied, scope)
    normalized: list[dict[str, Any]] = []
    identities: dict[str, dict[str, Any]] = {}
    frames: dict[str, set[str]] = {}
    for record in records:
        frame = record.pop("_frame")
        identity = record["arm_id"]
        prior = identities.get(identity) if identity else None
        if prior is None:
            normalized.append(record)
            if identity:
                identities[identity] = record
                frames[identity] = {frame}
            continue
        if frame in frames[identity]:
            raise InputError("Duplicate or ambiguous ARM resource identity")
        frames[identity].add(frame)
        equivalent = all(
            exact_equal(prior[key], record[key]) is True
            for key in ("resource_type", "api_version", "properties", "state")
        )
        reason = (
            "equivalent_projected_resource_declarations"
            if equivalent
            else "conflicting_resource_declarations"
        )
        diagnostics.append(
            {"reason": reason, "address": prior["logical_id"] + " | " + record["logical_id"]}
        )
        if not equivalent:
            prior.update(state="unknown", properties={}, reason=reason)
    records = normalized
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
                    "Bounded local copies, lambdas and declared module outputs; "
                    "runtime references, "
                    "linked/child declarations, "
                    "unverified nested expression scope and unsupported APIs remain unknown."
                ),
            },
        )
    )
