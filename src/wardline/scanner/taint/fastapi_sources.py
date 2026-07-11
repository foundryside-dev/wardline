"""Pure, syntax-only classification of FastAPI route parameters."""

from __future__ import annotations

import ast
from collections.abc import Mapping
from dataclasses import dataclass

_FASTAPI_CONSTRUCTORS = frozenset({"fastapi.FastAPI", "fastapi.routing.APIRouter", "fastapi.APIRouter"})
_ROUTE_METHODS = frozenset(
    {"get", "post", "put", "patch", "delete", "options", "head", "trace", "api_route", "websocket"}
)
_PYDANTIC_BASES = frozenset({"pydantic.BaseModel", "pydantic.main.BaseModel"})
_DEPENDS = frozenset({"fastapi.Depends", "fastapi.params.Depends"})
_UNKNOWN_ANNOTATION = "<unknown-annotation>"
_UNKNOWN_BINDING = "<unknown-binding>"
_ANNOTATION_NODE_BUDGET = 128
_DOTTED_NODE_BUDGET = 128


@dataclass(frozen=True, slots=True)
class RouteBindingSnapshot:
    aliases: dict[str, str]
    receivers: frozenset[str]
    models: frozenset[str]


def _record_function_snapshots(
    node: ast.AST,
    snapshot: RouteBindingSnapshot,
    snapshots: dict[int, RouteBindingSnapshot],
) -> None:
    for descendant in ast.walk(node):
        if isinstance(descendant, (ast.FunctionDef, ast.AsyncFunctionDef)):
            snapshots.setdefault(id(descendant), snapshot)


def resolve_dotted(node: ast.expr, aliases: Mapping[str, str]) -> str | None:
    """Resolve a name/attribute chain through the module import alias map."""
    attributes: list[str] = []
    current = node
    for _ in range(_DOTTED_NODE_BUDGET):
        if isinstance(current, ast.Attribute):
            attributes.append(current.attr)
            current = current.value
            continue
        if isinstance(current, ast.Name):
            root = aliases.get(current.id, current.id)
            return ".".join((root, *reversed(attributes)))
        return None
    return _UNKNOWN_ANNOTATION


def _assigned_names(stmt: ast.stmt) -> set[str]:
    if isinstance(stmt, ast.Assign):
        return {target.id for target in stmt.targets if isinstance(target, ast.Name)}
    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
        return {stmt.target.id}
    return set()


def _model_owner(name: str) -> str:
    """Return the defining module for a top-level model qualname."""
    return name.rpartition(".")[0]


def _import_from_base(node: ast.ImportFrom, module: str, *, is_package: bool) -> str | None:
    level = node.level or 0
    if level == 0:
        return node.module
    package_parts = module.split(".") if is_package else module.split(".")[:-1]
    ascend = level - 1
    base_parts = package_parts[:-ascend] if ascend else package_parts
    if ascend > len(package_parts):
        base_parts = []
    parts = [*base_parts]
    if node.module is not None:
        parts.append(node.module)
    return ".".join(parts) or None


def discover_fastapi_route_receivers(
    tree: ast.Module,
    aliases: Mapping[str, str],
    *,
    module: str,
    known_models: frozenset[str],
    is_package: bool = False,
) -> dict[int, RouteBindingSnapshot]:
    """Return source-ordered binding snapshots for each top-level function definition."""
    del aliases  # the static import map is intentionally replaced by ordered bindings
    receivers: set[str] = set()
    bindings: dict[str, str] = {}
    models = {name for name in known_models if _model_owner(name) != module}
    snapshots: dict[int, RouteBindingSnapshot] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Import):
            for item in stmt.names:
                if item.asname is not None:
                    bindings[item.asname] = item.name
                else:
                    root = item.name.split(".")[0]
                    bindings[root] = root
            continue
        if isinstance(stmt, ast.ImportFrom):
            base = _import_from_base(stmt, module, is_package=is_package)
            if base is None:
                continue
            for item in stmt.names:
                if item.name != "*":
                    bindings[item.asname or item.name] = f"{base}.{item.name}"
            continue
        if isinstance(stmt, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            qualname = f"{module}.{stmt.name}"
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                snapshot = RouteBindingSnapshot(dict(bindings), frozenset(receivers), frozenset(models))
                _record_function_snapshots(stmt, snapshot, snapshots)
                models.discard(qualname)
            elif isinstance(stmt, ast.ClassDef):
                bases = {
                    candidate
                    for base in stmt.bases
                    if (candidate := _module_candidate(resolve_dotted(base, bindings), module)) is not None
                }
                is_model = bool(bases & (_PYDANTIC_BASES | models))
                models.discard(qualname)
                if is_model:
                    models.add(qualname)
                snapshot = RouteBindingSnapshot(dict(bindings), frozenset(receivers), frozenset(models))
                _record_function_snapshots(stmt, snapshot, snapshots)
            receivers.discard(stmt.name)
            bindings[stmt.name] = qualname
            continue
        targets = _assigned_names(stmt)
        if not targets:
            continue
        value = stmt.value if isinstance(stmt, (ast.Assign, ast.AnnAssign)) else None
        recognized = isinstance(value, ast.Call) and resolve_dotted(value.func, bindings) in _FASTAPI_CONSTRUCTORS
        receiver_alias = isinstance(value, ast.Name) and value.id in receivers
        alias_target = resolve_dotted(value, bindings) if isinstance(value, (ast.Name, ast.Attribute)) else None
        for target in targets:
            if recognized or receiver_alias:
                receivers.add(target)
            else:
                receivers.discard(target)
            if alias_target is not None:
                bindings[target] = alias_target
            else:
                bindings[target] = f"{_UNKNOWN_BINDING}.{target}"
            models.discard(f"{module}.{target}")
    return snapshots


def _module_candidate(name: str | None, module: str) -> str | None:
    if name is None or "." in name:
        return name
    return f"{module}.{name}"


def discover_pydantic_models(
    tree: ast.Module,
    *,
    module: str,
    aliases: Mapping[str, str],
    known_models: frozenset[str],
    is_package: bool = False,
) -> frozenset[str]:
    """Discover direct and transitive top-level ``BaseModel`` subclasses."""
    del aliases  # the static import map is intentionally replaced by ordered bindings
    found = {name for name in known_models if _model_owner(name) != module}
    bindings: dict[str, str] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Import):
            for item in stmt.names:
                if item.asname is not None:
                    bindings[item.asname] = item.name
                else:
                    root = item.name.split(".")[0]
                    bindings[root] = root
            continue
        if isinstance(stmt, ast.ImportFrom):
            base = _import_from_base(stmt, module, is_package=is_package)
            if base is None:
                continue
            for item in stmt.names:
                if item.name != "*":
                    bindings[item.asname or item.name] = f"{base}.{item.name}"
            continue
        if isinstance(stmt, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            qualname = f"{module}.{stmt.name}"
            if isinstance(stmt, ast.ClassDef):
                bases = {
                    candidate
                    for base in stmt.bases
                    if (candidate := _module_candidate(resolve_dotted(base, bindings), module)) is not None
                }
                is_model = bool(bases & (_PYDANTIC_BASES | found))
                found.discard(qualname)
                if is_model:
                    found.add(qualname)
            else:
                found.discard(qualname)
            bindings[stmt.name] = qualname
            continue
        assigned = _assigned_names(stmt)
        if not assigned:
            continue
        value = stmt.value if isinstance(stmt, (ast.Assign, ast.AnnAssign)) else None
        alias_target = resolve_dotted(value, bindings) if isinstance(value, (ast.Name, ast.Attribute)) else None
        for name in assigned:
            found.discard(f"{module}.{name}")
            if alias_target is not None:
                bindings[name] = alias_target
            else:
                bindings[name] = f"{_UNKNOWN_BINDING}.{name}"
    return frozenset(found)


def _is_fastapi_route(node: ast.FunctionDef | ast.AsyncFunctionDef, route_receivers: frozenset[str]) -> bool:
    return any(
        isinstance(dec, ast.Call)
        and isinstance(dec.func, ast.Attribute)
        and isinstance(dec.func.value, ast.Name)
        and dec.func.value.id in route_receivers
        and dec.func.attr in _ROUTE_METHODS
        for dec in node.decorator_list
    )


def _parameter_defaults(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, ast.expr]:
    positional = [*node.args.posonlyargs, *node.args.args]
    defaults = (
        {
            arg.arg: default
            for arg, default in zip(positional[-len(node.args.defaults) :], node.args.defaults, strict=True)
        }
        if node.args.defaults
        else {}
    )
    defaults.update(
        {
            arg.arg: default
            for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=True)
            if default is not None
        }
    )
    return defaults


def route_dependency_parameters(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    aliases: Mapping[str, str],
    route_receivers: frozenset[str],
) -> dict[str, str | None]:
    """Return route dependency parameters mapped to their provider binding."""
    if not _is_fastapi_route(node, route_receivers):
        return {}
    dependencies: dict[str, str | None] = {}
    for name, default in _parameter_defaults(node).items():
        if isinstance(default, ast.Call) and resolve_dotted(default.func, aliases) in _DEPENDS:
            provider = resolve_dotted(default.args[0], aliases) if default.args else None
            dependencies[name] = provider
    parameters = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    for arg in parameters:
        annotation = arg.annotation
        if not isinstance(annotation, ast.Subscript) or resolve_dotted(annotation.value, aliases) != "typing.Annotated":
            continue
        elements = annotation.slice.elts if isinstance(annotation.slice, ast.Tuple) else [annotation.slice]
        for metadata in elements[1:]:
            if isinstance(metadata, ast.Call) and resolve_dotted(metadata.func, aliases) in _DEPENDS:
                dependencies[arg.arg] = resolve_dotted(metadata.args[0], aliases) if metadata.args else None
                break
    return dependencies


def _annotation_candidates(node: ast.expr, aliases: Mapping[str, str]) -> set[str]:
    candidates: set[str] = set()
    worklist = [node]
    visited = 0
    while worklist and visited < _ANNOTATION_NODE_BUDGET:
        current = worklist.pop()
        visited += 1
        if isinstance(current, ast.BinOp) and isinstance(current.op, ast.BitOr):
            worklist.extend((current.left, current.right))
            continue
        if isinstance(current, ast.Subscript):
            outer = resolve_dotted(current.value, aliases)
            elements = current.slice.elts if isinstance(current.slice, ast.Tuple) else [current.slice]
            if outer in {"typing.Annotated", "typing.Optional"}:
                worklist.append(elements[0])
            else:
                if outer is not None:
                    candidates.add(outer)
                worklist.extend(elements)
            continue
        resolved = resolve_dotted(current, aliases)
        if resolved is not None:
            candidates.add(resolved)
    if worklist:
        candidates.add(_UNKNOWN_ANNOTATION)
    return candidates


def route_body_parameters(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    module: str,
    aliases: Mapping[str, str],
    route_receivers: frozenset[str],
    pydantic_models: frozenset[str],
) -> frozenset[str]:
    """Return Pydantic model parameters supplied as bodies to a recognized route."""
    if not _is_fastapi_route(node, route_receivers):
        return frozenset()
    dependencies = route_dependency_parameters(node, aliases=aliases, route_receivers=route_receivers)
    parameters = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    body_params: set[str] = set()
    for arg in parameters:
        annotations = _annotation_candidates(arg.annotation, aliases) if arg.annotation else set()
        model_names = {_module_candidate(annotation, module) for annotation in annotations}
        if (_UNKNOWN_ANNOTATION in annotations or model_names & pydantic_models) and arg.arg not in dependencies:
            body_params.add(arg.arg)
    return frozenset(body_params)
