"""Bounded, offline Terraform feasibility spike, not a Terraform runtime."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import hcl2
from lark import Token, Tree
from lark.exceptions import LarkError


class InputError(ValueError):
    """An input cannot be safely analyzed."""


@dataclass(frozen=True)
class Unknown:
    reason: str


@dataclass
class Expression:
    node: Tree[Any]
    json_template: bool = False


@dataclass(frozen=True)
class Namespace:
    name: str


@dataclass
class Body:
    attributes: dict[str, Any] = field(default_factory=dict)
    blocks: list[Block] = field(default_factory=list)


@dataclass
class Block:
    kind: str
    labels: list[str]
    body: Body
    file: str


@dataclass(frozen=True)
class Limits:
    instances: int = 256
    module_depth: int = 16
    expression_steps: int = 10_000
    files: int = 256
    bytes: int = 2_000_000


DEFAULT_LIMITS = Limits()


def trees(node: Tree[Any]) -> list[Tree[Any]]:
    return [
        child
        for child in node.children
        if isinstance(child, Tree) and child.data != "new_line_or_comment"
    ]


def word(node: Tree[Any]) -> str:
    return str(node.children[0])


def read_body(node: Tree[Any], file: str) -> Body:
    body = Body()
    for child in trees(node):
        parts = trees(child)
        if child.data == "attribute":
            name = word(parts[0])
            if name in body.attributes:
                raise InputError(f"Duplicate attribute {name} in {file}")
            body.attributes[name] = Expression(parts[-1])
        elif child.data == "block":
            kind = word(parts[0])
            labels = []
            for label in parts[1:-1]:
                if label.data == "string":
                    tokens = list(label.scan_values(lambda v: isinstance(v, Token)))
                    labels.append(json.loads("".join(str(t) for t in tokens)))
                else:
                    labels.append(word(label))
            body.blocks.append(Block(kind, labels, read_body(parts[-1], file), file))
    return body


def json_value(value: Any) -> Any:
    if isinstance(value, str):
        # Terraform JSON strings are templates; exact interpolations retain their type.
        node = hcl2.parses_to_tree("value = " + json.dumps(value))
        return Expression(trees(trees(node)[0])[0].children[-1], json_template=True)
    if isinstance(value, list):
        return [json_value(v) for v in value]
    if isinstance(value, dict):
        return {k: json_value(v) for k, v in value.items()}
    return value


def json_body(data: dict[str, Any], file: str, top: bool = True) -> Body:
    body = Body()
    for key, value in data.items():
        if key == "//":
            continue
        if top and key in {
            "variable",
            "module",
            "output",
            "resource",
            "data",
            "locals",
            "provider",
            "terraform",
        }:
            if not isinstance(value, dict):
                raise InputError(f"Expected object for {key} in {file}")
            if key in {"locals", "terraform"}:
                body.blocks.append(Block(key, [], json_body(value, file, False), file))
            else:
                for label, attributes in value.items():
                    if not isinstance(attributes, dict):
                        raise InputError(f"Expected block body object in {file}")
                    if key in {"resource", "data"}:
                        for name, resource in attributes.items():
                            if not isinstance(resource, dict):
                                raise InputError(f"Expected resource body object in {file}")
                            body.blocks.append(
                                Block(
                                    key,
                                    [label, name],
                                    json_body(resource, file, False),
                                    file,
                                )
                            )
                    else:
                        # Defaults, source and version are literal contexts in Terraform JSON.
                        literal_keys = (
                            {"default", "type", "description"}
                            if key == "variable"
                            else {"source", "version"}
                            if key == "module"
                            else set()
                        )
                        parsed = Body(
                            attributes={
                                name: value if name in literal_keys else json_value(value)
                                for name, value in attributes.items()
                                if name != "//"
                            }
                        )
                        body.blocks.append(
                            Block(
                                key,
                                [label],
                                parsed,
                                file,
                            )
                        )
        else:
            body.attributes[key] = json_value(value)
    return body


def parse_file(path: Path, limit: int = 2_000_000) -> Body:
    if path.stat().st_size > limit:
        raise InputError(f"Input exceeds byte limit: {path}")
    try:
        text = path.read_text(encoding="utf-8-sig")
        if path.name.endswith(".json"):
            data = json.loads(text)
            if not isinstance(data, dict):
                raise InputError(f"Expected a JSON object: {path}")
            return json_body(data, str(path))
        return read_body(trees(hcl2.parses_to_tree(text))[0], str(path))
    except (LarkError, json.JSONDecodeError, RecursionError) as exc:
        raise InputError(f"Cannot parse {path}: {type(exc).__name__}") from exc


def tree_hash(root: Path, limits: Limits = DEFAULT_LIMITS) -> str:
    """Hash sorted relative paths and bytes, with unambiguous length delimiters."""
    digest = hashlib.sha256()
    paths = []
    byte_count = 0
    for path in root.rglob("*"):
        if path.is_symlink() or path.is_junction():
            raise InputError(f"Snapshot contains a link: {path}")
        paths.append(path)
        if path.is_file():
            byte_count += path.stat().st_size
        if len(paths) > limits.files or byte_count > limits.bytes:
            raise InputError("Snapshot file/byte limit exceeded")
    for path in sorted(paths):
        if path.is_file():
            name = path.relative_to(root).as_posix().encode()
            content = path.read_bytes()
            digest.update(len(name).to_bytes(8, "big") + name)
            digest.update(len(content).to_bytes(8, "big") + content)
    return digest.hexdigest()


def module_revision(source: str, version: Any) -> tuple[Any, str]:
    path, _, query = source.partition("?")
    scheme = path.find("://")
    separator = path.find("//", scheme + 3 if scheme >= 0 else 0)
    subdirectory = path[separator + 2 :] if separator >= 0 else ""
    refs = parse_qs(query).get("ref", [])
    return version or (refs[0] if len(refs) == 1 else ""), subdirectory


def serialize(value: Any) -> Any:
    if isinstance(value, Namespace):
        return {"unknown": f"unresolved namespace: {value.name}"}
    if isinstance(value, Unknown):
        return {"unknown": value.reason}
    if isinstance(value, dict):
        return {k: serialize(v) for k, v in value.items()}
    if isinstance(value, set):
        return [serialize(v) for v in sorted(value)]
    if isinstance(value, (list, tuple)):
        return [serialize(v) for v in value]
    return value


class Context:
    def __init__(
        self,
        analyzer: Analyzer,
        body: Body,
        inputs: dict[str, Any],
        path: Path,
        address: str,
        ancestors: tuple[Path, ...],
    ) -> None:
        self.analyzer, self.body, self.path = analyzer, body, path
        self.address, self.ancestors = address, ancestors
        self.cache: dict[str, Any] = {}
        self.active: set[str] = set()
        self.locals: dict[str, Any] = {}
        self.variables: dict[str, Any] = {}
        self.modules: dict[str, Block] = {}
        self.outputs: dict[str, Any] = {}
        declarations: set[tuple[str, ...]] = set()
        for block in body.blocks:
            expected_labels = {"variable": 1, "module": 1, "output": 1, "resource": 2, "data": 2}
            if block.kind in expected_labels and len(block.labels) != expected_labels[block.kind]:
                raise InputError(f"Invalid labels for {block.kind}: {path}")
            if block.kind in expected_labels:
                declaration = (block.kind, *block.labels)
                if declaration in declarations:
                    raise InputError(f"Duplicate declaration {declaration}: {path}")
                declarations.add(declaration)
            attrs = block.body.attributes
            if block.kind == "locals":
                for name, value in attrs.items():
                    if name in self.locals:
                        raise InputError(f"Duplicate local {name}: {path}")
                    self.locals[name] = value
            elif block.kind in {"variable", "module", "output"}:
                name = block.labels[0]
                target = {
                    "variable": self.variables,
                    "module": self.modules,
                    "output": self.outputs,
                }[block.kind]
                if name in target:
                    raise InputError(f"Duplicate {block.kind} {name}: {path}")
                if block.kind == "variable":
                    # Root overrides are values, not expressions in the root's scope.
                    target[name] = inputs.get(
                        name,
                        attrs.get("default", Unknown("required variable")),
                    )
                    if "sensitive" in attrs or "ephemeral" in attrs:
                        target[name] = Unknown("sensitive/ephemeral input withheld by spike")
                elif block.kind == "module":
                    target[name] = block
                else:
                    target[name] = attrs.get("value", Unknown("output has no value"))
                    if "sensitive" in attrs or "ephemeral" in attrs:
                        target[name] = Unknown("sensitive/ephemeral output withheld by spike")

    def lookup(self, namespace: str, key: str) -> Any:
        cache_key = f"{namespace}.{key}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        if cache_key in self.active:
            return Unknown(f"cyclic reference: {cache_key}")
        if len(self.active) >= 64:
            return Unknown("reference depth limit exceeded")
        self.active.add(cache_key)
        try:
            if namespace == "module":
                block = self.modules.get(key)
                result = self.analyzer.module(block, self) if block else Unknown("missing module")
            else:
                values = {"var": self.variables, "local": self.locals}
                result = self.eval(values.get(namespace, {}).get(key, Unknown(cache_key)))
            self.cache[cache_key] = result
            return result
        finally:
            self.active.remove(cache_key)

    def eval(self, value: Any, instance: dict[str, Any] | None = None) -> Any:
        if isinstance(value, Expression):
            if value.json_template:
                # Only JSON's single-interpolation template preserves non-string types.
                node = value.node
                if node.data == "expr_term" and trees(node)[0].data == "string":
                    parts = trees(trees(node)[0])
                    if len(parts) == 1 and trees(parts[0]):
                        interpolation = trees(parts[0])[0]
                        if interpolation.data == "interpolation":
                            return self.node(trees(interpolation)[0], instance or {}, 0)
            return self.node(value.node, instance or {}, 0)
        if isinstance(value, dict):
            return {k: self.eval(v, instance) for k, v in value.items()}
        if isinstance(value, list):
            return [self.eval(v, instance) for v in value]
        return value

    def node(self, node: Tree[Any], instance: dict[str, Any], depth: int) -> Any:
        self.analyzer.steps += 1
        if self.analyzer.steps > self.analyzer.limits.expression_steps or depth > 64:
            return Unknown("expression limit exceeded")
        children = trees(node)
        kind = str(node.data)

        def ev(child: Tree[Any]) -> Any:
            return self.node(child, instance, depth + 1)

        if kind in {"expr_term", "interpolation", "object_elem_key"}:
            return ev(children[0])
        if kind == "int_lit":
            return int(word(node))
        if kind == "float_lit":
            return float(word(node))
        if kind == "literal_value":
            return {"true": True, "false": False, "null": None}[word(node)]
        if kind == "identifier":
            name = word(node)
            return instance.get(name, Namespace(name))
        if kind == "string":
            parts = []
            for part in children:
                inner = trees(part)
                if inner:
                    result = ev(inner[0])
                    if isinstance(result, Unknown):
                        return result
                    if isinstance(result, (dict, list, set, Namespace)) or result is None:
                        return Unknown("invalid template interpolation")
                    parts.append(result)
                else:
                    token = word(part)
                    # HCL escaped interpolation/directives are literal text.
                    token = token.replace("$${", "${").replace("%%{", "%{")
                    parts.append(json.loads('"' + token + '"'))
            return "".join(
                json.dumps(part) if isinstance(part, bool) else str(part) for part in parts
            )
        if kind == "tuple":
            return [ev(child) for child in children]
        if kind == "object":
            result = {}
            for element in children:
                pair = trees(element)
                key_node = trees(pair[0])[0]
                leaf = trees(key_node)
                if leaf and leaf[0].data == "identifier":
                    key = word(leaf[0])
                else:
                    key = ev(pair[0])
                if not isinstance(key, str):
                    return Unknown("unknown or non-string object key")
                result[key] = ev(pair[-1])
            return result
        if kind in {"get_attr_expr_term", "index_expr_term"}:
            base = ev(children[0])
            key = (
                word(trees(children[1])[0])
                if kind == "get_attr_expr_term"
                else ev(
                    trees(children[1])[0],
                )
            )
            if isinstance(base, Namespace):
                return (
                    self.lookup(base.name, key) if isinstance(key, str) else Unknown("unknown key")
                )
            if isinstance(base, Unknown):
                return base
            if isinstance(base, dict) and isinstance(key, str):
                return base.get(key, Unknown(f"missing attribute: {key}"))
            if isinstance(base, list) and type(key) is int and 0 <= key < len(base):
                return base[key]
            return Unknown("unresolved attribute/index")
        if kind == "conditional":
            condition = ev(children[0])
            if type(condition) is not bool:
                return Unknown("unknown/non-boolean condition")
            return ev(children[1] if condition else children[2])
        if kind == "function_call":
            name = word(children[0])
            args = [ev(arg) for arg in trees(children[-1])] if len(children) > 1 else []
            if name == "toset" and len(args) == 1 and isinstance(args[0], list):
                if all(isinstance(v, str) for v in args[0]):
                    return set(args[0])
            return Unknown(f"unsupported function: {name}")
        return Unknown(f"unsupported expression: {kind}")


class Analyzer:
    def __init__(
        self,
        root: Path,
        *,
        manifest: Path | None = None,
        authorized_roots: list[Path] | None = None,
        limits: Limits = DEFAULT_LIMITS,
    ) -> None:
        self.root, self.limits = root.resolve(), limits
        self.authorized = [self.root] + [p.resolve() for p in (authorized_roots or [])]
        self.snapshots: list[dict[str, Any]] = []
        self.manifest_path = manifest.resolve() if manifest else None
        if manifest:
            data = json.loads(manifest.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or not isinstance(data.get("modules"), list):
                raise InputError("Snapshot manifest must contain a modules array")
            self.snapshots = data["modules"]
            required = {"source", "version", "subdirectory", "path", "sha256"}
            for entry in self.snapshots:
                if (
                    not isinstance(entry, dict)
                    or not required <= entry.keys()
                    or not all(isinstance(entry[key], str) for key in required)
                    or not entry["version"]
                    or len(entry["sha256"]) != 64
                ):
                    raise InputError("Invalid snapshot entry; source/version/path/hash required")
            self.provenance_manifest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            keys = [(s["source"], s["version"], s["subdirectory"]) for s in self.snapshots]
            if len(keys) != len(set(keys)):
                raise InputError("Ambiguous module snapshot mappings")
        self.steps = self.instances = self.file_count = self.byte_count = 0
        self.resources: list[dict[str, Any]] = []
        self.diagnostics: list[dict[str, str]] = []
        self.provenance: dict[str, str] = {}

    def diagnostic(self, address: str, reason: str) -> Unknown:
        self.diagnostics.append({"address": address, "reason": reason})
        return Unknown(reason)

    def safe(self, path: Path) -> Path:
        resolved = path.resolve()
        if not any(resolved.is_relative_to(root) for root in self.authorized):
            raise InputError(f"Path outside authorized roots: {path}")
        return resolved

    def load(self, path: Path) -> Body:
        body = Body()
        files = sorted([*path.glob("*.tf"), *path.glob("*.tf.json")])
        if not files:
            raise InputError(f"No Terraform source files: {path}")
        for file in files:
            self.track_file(file)
            parsed = parse_file(file, self.limits.bytes)
            if parsed.attributes:
                raise InputError(f"Unexpected top-level attributes: {file}")
            body.blocks.extend(parsed.blocks)
        return body

    def track_file(self, file: Path) -> None:
        self.safe(file)
        self.file_count += 1
        self.byte_count += file.stat().st_size
        if self.file_count > self.limits.files or self.byte_count > self.limits.bytes:
            raise InputError("Source/variable file/byte limit exceeded")
        self.provenance[str(file)] = hashlib.sha256(file.read_bytes()).hexdigest()

    def expand(self, block: Block, context: Context) -> list[tuple[str, dict[str, Any]]] | Unknown:
        attrs = block.body.attributes
        if "count" in attrs and "for_each" in attrs:
            return Unknown("count and for_each are mutually exclusive")
        if "count" in attrs:
            count = context.eval(attrs["count"])
            if type(count) is not int or count < 0:
                return Unknown("symbolic or invalid count")
            if count > self.limits.instances - self.instances:
                return Unknown("instance expansion limit exceeded")
            return [(f"[{i}]", {"count": {"index": i}}) for i in range(count)]
        if "for_each" in attrs:
            collection = context.eval(attrs["for_each"])
            if isinstance(collection, set) and all(isinstance(v, str) for v in collection):
                collection = {key: key for key in sorted(collection)}
            if not isinstance(collection, dict) or not all(
                isinstance(key, str) for key in collection
            ):
                return Unknown("symbolic or invalid for_each (map or string set required)")
            if len(collection) > self.limits.instances - self.instances:
                return Unknown("instance expansion limit exceeded")
            return [
                (f"[{json.dumps(key)}]", {"each": {"key": key, "value": val}})
                for key, val in sorted(collection.items())
            ]
        if self.instances >= self.limits.instances:
            return Unknown("instance expansion limit exceeded")
        return [("", {})]

    def module(self, block: Block, parent: Context) -> Any:
        address = f"{parent.address}module.{block.labels[0]}"
        expanded = self.expand(block, parent)
        if isinstance(expanded, Unknown):
            return self.diagnostic(address, expanded.reason)
        results: dict[str, Any] = {}
        for suffix, instance in expanded:
            if self.instances >= self.limits.instances:
                results[suffix] = self.diagnostic(address, "instance expansion limit exceeded")
                continue
            self.instances += 1
            attrs = block.body.attributes
            source = parent.eval(attrs.get("source"), instance)
            version = parent.eval(attrs.get("version", ""), instance)
            if not isinstance(source, str):
                return self.diagnostic(address, "module source unresolved")
            if source.startswith(("./", "../")):
                path = self.safe(parent.path / source)
            else:
                version, subdirectory = module_revision(source, version)
                mapping = next(
                    (
                        s
                        for s in self.snapshots
                        if s["source"] == source
                        and s["version"] == version
                        and s["subdirectory"] == subdirectory
                    ),
                    None,
                )
                if mapping is None or self.manifest_path is None:
                    results[suffix] = self.diagnostic(address, "required module snapshot missing")
                    continue
                path = self.safe(self.manifest_path.parent / mapping["path"])
                if not path.is_dir():
                    results[suffix] = self.diagnostic(address, "required module snapshot absent")
                    continue
                if tree_hash(path, self.limits) != mapping["sha256"]:
                    raise InputError(f"Snapshot content hash mismatch: {address}")
                self.provenance[f"{address}{suffix}:snapshot"] = mapping["sha256"]
            inputs = {
                name: parent.eval(value, instance)
                for name, value in attrs.items()
                if name not in {"source", "version", "count", "for_each", "providers", "depends_on"}
            }
            results[suffix] = self.walk(path, inputs, address + suffix + ".", parent.ancestors)
        if "count" in block.body.attributes:
            return list(results.values())
        if "for_each" in block.body.attributes:
            return {json.loads(key[1:-1]): value for key, value in results.items()}
        return results.get("", Unknown("module has no instance"))

    def walk(
        self,
        path: Path,
        inputs: dict[str, Any],
        address: str = "",
        ancestors: tuple[Path, ...] = (),
    ) -> Any:
        path = self.safe(path)
        if path in ancestors or len(ancestors) >= self.limits.module_depth:
            return self.diagnostic(address, "module recursion/depth limit exceeded")
        if not path.is_dir():
            return self.diagnostic(address, "local module directory missing")
        context = Context(self, self.load(path), inputs, path, address, (*ancestors, path))
        # Resolve all module calls, including ones whose outputs are not referenced.
        for name in context.modules:
            context.lookup("module", name)
        for block in context.body.blocks:
            if block.kind != "resource":
                continue
            resource_address = address + ".".join(block.labels)
            expanded = self.expand(block, context)
            if isinstance(expanded, Unknown):
                self.diagnostic(resource_address, expanded.reason)
                self.resources.append(
                    {
                        "address": resource_address + "[*]",
                        "properties": expanded,
                        "file": block.file,
                    }
                )
                continue
            for suffix, instance in expanded:
                if self.instances >= self.limits.instances:
                    self.diagnostic(resource_address, "instance expansion limit exceeded")
                    break
                self.instances += 1
                props = self.properties(block.body, context, instance)
                props.pop("count", None)
                props.pop("for_each", None)
                self.resources.append(
                    {
                        "address": resource_address + suffix,
                        "properties": props,
                        "file": block.file,
                    }
                )
        return {name: context.eval(value) for name, value in context.outputs.items()}

    def properties(
        self,
        body: Body,
        context: Context,
        instance: dict[str, Any],
        depth: int = 0,
    ) -> dict[str, Any]:
        if depth >= 64:
            return {"unknown": Unknown("nested block depth limit exceeded")}
        result = {key: context.eval(value, instance) for key, value in body.attributes.items()}
        if "dynamic" in result:
            result["dynamic"] = Unknown("JSON dynamic blocks unsupported in prerequisite spike")
        for nested in body.blocks:
            if nested.kind in result and not isinstance(result[nested.kind], list):
                raise InputError(f"Conflicting nested block/attribute: {nested.kind}")
            if nested.kind == "dynamic":
                result.setdefault("dynamic", []).append(
                    Unknown("dynamic blocks not implemented in prerequisite spike"),
                )
            else:
                result.setdefault(nested.kind, []).append(
                    self.properties(nested.body, context, instance, depth + 1),
                )
        return result

    def analyze(
        self,
        *,
        variable_inputs: list[tuple[str, Any]] | None = None,
        environment: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        inputs = dict(environment or {})
        conventional = [self.root / "terraform.tfvars", self.root / "terraform.tfvars.json"]
        conventional += sorted(
            [
                *self.root.glob("*.auto.tfvars"),
                *self.root.glob("*.auto.tfvars.json"),
            ]
        )
        for file in conventional:
            if file.is_file():
                inputs.update(self.variables_file(file))
        for kind, value in variable_inputs or []:
            if kind == "file":
                inputs.update(self.variables_file(Path(value)))
            elif kind == "var":
                inputs.update(value)
            else:
                raise InputError(f"Unknown variable input kind: {kind}")
        self.provenance["effective-root-bindings"] = hashlib.sha256(
            json.dumps(serialize(inputs), sort_keys=True).encode(),
        ).hexdigest()
        if self.manifest_path:
            self.provenance["snapshot-manifest"] = self.provenance_manifest
        try:
            outputs = self.walk(self.root, inputs)
        except RecursionError as exc:
            raise InputError("Source nesting exceeds safe recursion bounds") from exc
        return serialize(
            {
                "spike": True,
                "resources": self.resources,
                "outputs": outputs,
                "diagnostics": self.diagnostics,
                "input_sha256": self.provenance,
                "coverage": "bounded subset; not an assessment or provider-default inference",
            }
        )

    def variables_file(self, file: Path) -> dict[str, Any]:
        file = self.safe(file)
        self.track_file(file)
        if file.name.endswith(".json"):
            data = json.loads(file.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise InputError(f"Expected variable object: {file}")
            return data
        body = parse_file(file, self.limits.bytes)
        if body.blocks:
            raise InputError(f"Variable files cannot contain blocks: {file}")
        context = Context(self, Body(), {}, file.parent, "", ())
        values = {name: context.eval(value) for name, value in body.attributes.items()}

        def unresolved(value: Any) -> bool:
            if isinstance(value, (Unknown, Namespace)):
                return True
            if isinstance(value, dict):
                return any(unresolved(v) for v in value.values())
            if isinstance(value, (list, tuple, set)):
                return any(unresolved(v) for v in value)
            return False

        if unresolved(values):
            raise InputError(f"Variable files must contain literal values: {file}")
        return values
