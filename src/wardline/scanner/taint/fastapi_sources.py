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


def discover_fastapi_route_receivers(tree: ast.Module, aliases: Mapping[str, str]) -> frozenset[str]:
    """Return module names bound directly to a recognized FastAPI application/router."""
    receivers: set[str] = set()
    for stmt in tree.body:
        if not (
            isinstance(stmt, (ast.Assign, ast.AnnAssign))
            and isinstance(stmt.value, ast.Call)
            and resolve_dotted(stmt.value.func, aliases) in _FASTAPI_CONSTRUCTORS
        ):
            continue
        targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
        receivers.update(target.id for target in targets if isinstance(target, ast.Name))
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
    found = set(known_models)
    classes = [stmt for stmt in tree.body if isinstance(stmt, ast.ClassDef)]
    changed = True
    while changed:
        changed = False
        for cls in classes:
            qualname = f"{module}.{cls.name}"
            bases = {
                candidate
                for base in cls.bases
                if (candidate := _module_candidate(resolve_dotted(base, aliases), module)) is not None
            }
            if qualname not in found and (bases & (_PYDANTIC_BASES | found)):
                found.add(qualname)
                changed = True
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
) -> frozenset[str]:
    """Return parameters injected by ``Depends`` on a recognized FastAPI route."""
    if not _is_fastapi_route(node, route_receivers):
        return frozenset()
    return frozenset(
        name
        for name, default in _parameter_defaults(node).items()
        if isinstance(default, ast.Call) and resolve_dotted(default.func, aliases) in _DEPENDS
    )


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
        annotation = resolve_dotted(arg.annotation, aliases) if arg.annotation else None
        model_name = _module_candidate(annotation, module)
        if model_name in pydantic_models and arg.arg not in dependencies:
            body_params.add(arg.arg)
    return frozenset(body_params)
