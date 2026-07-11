"""Pure, syntax-only classification of FastAPI route parameters."""

from __future__ import annotations

import ast
from collections.abc import Mapping

_FASTAPI_CONSTRUCTORS = frozenset({"fastapi.FastAPI", "fastapi.routing.APIRouter", "fastapi.APIRouter"})
_ROUTE_METHODS = frozenset(
    {"get", "post", "put", "patch", "delete", "options", "head", "trace", "api_route", "websocket"}
)
_PYDANTIC_BASES = frozenset({"pydantic.BaseModel", "pydantic.main.BaseModel"})
_DEPENDS = frozenset({"fastapi.Depends", "fastapi.params.Depends"})


def resolve_dotted(node: ast.expr, aliases: Mapping[str, str]) -> str | None:
    """Resolve a name/attribute chain through the module import alias map."""
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        parent = resolve_dotted(node.value, aliases)
        return f"{parent}.{node.attr}" if parent else None
    return None


def _resolve_bound(node: ast.expr, aliases: Mapping[str, str], shadowed: set[str]) -> str | None:
    root = node
    while isinstance(root, ast.Attribute):
        root = root.value
    if isinstance(root, ast.Name) and root.id in shadowed:
        return resolve_dotted(node, {})
    return resolve_dotted(node, aliases)


def _assigned_names(stmt: ast.stmt) -> set[str]:
    if isinstance(stmt, ast.Assign):
        return {target.id for target in stmt.targets if isinstance(target, ast.Name)}
    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
        return {stmt.target.id}
    return set()


def discover_fastapi_route_receivers(tree: ast.Module, aliases: Mapping[str, str]) -> frozenset[str]:
    """Return module names bound directly to a recognized FastAPI application/router."""
    receivers: set[str] = set()
    shadowed: set[str] = set()
    for stmt in tree.body:
        if isinstance(stmt, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            receivers.discard(stmt.name)
            shadowed.add(stmt.name)
            continue
        targets = _assigned_names(stmt)
        if not targets:
            continue
        value = stmt.value if isinstance(stmt, (ast.Assign, ast.AnnAssign)) else None
        recognized = (
            isinstance(value, ast.Call) and _resolve_bound(value.func, aliases, shadowed) in _FASTAPI_CONSTRUCTORS
        )
        for target in targets:
            if recognized:
                receivers.add(target)
            else:
                receivers.discard(target)
            shadowed.add(target)
    return frozenset(receivers)


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
) -> frozenset[str]:
    """Discover direct and transitive top-level ``BaseModel`` subclasses."""
    found = {name for name in known_models if not name.startswith(f"{module}.")}
    shadowed: set[str] = set()
    changed = True
    while changed:
        changed = False
        for stmt in tree.body:
            assigned = _assigned_names(stmt)
            if assigned:
                shadowed.update(assigned)
                for name in assigned:
                    found.discard(f"{module}.{name}")
                continue
            if not isinstance(stmt, ast.ClassDef):
                continue
            cls = stmt
            qualname = f"{module}.{cls.name}"
            bases = {
                candidate
                for base in cls.bases
                if (candidate := _module_candidate(_resolve_bound(base, aliases, shadowed), module)) is not None
            }
            if qualname not in found and (bases & (_PYDANTIC_BASES | found)):
                found.add(qualname)
                changed = True
            shadowed.add(cls.name)
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
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _annotation_candidates(node.left, aliases) | _annotation_candidates(node.right, aliases)
    if isinstance(node, ast.Subscript):
        outer = resolve_dotted(node.value, aliases)
        elements = node.slice.elts if isinstance(node.slice, ast.Tuple) else [node.slice]
        if outer in {"typing.Annotated", "typing.Optional"}:
            return _annotation_candidates(elements[0], aliases)
        base = resolve_dotted(node.value, aliases)
        return {base} if base is not None else set()
    resolved = resolve_dotted(node, aliases)
    return {resolved} if resolved is not None else set()


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
        if model_names & pydantic_models and arg.arg not in dependencies:
            body_params.add(arg.arg)
    return frozenset(body_params)
