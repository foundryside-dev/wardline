"""Pure, syntax-only classification of FastAPI route parameters."""

from __future__ import annotations

import ast
from collections import ChainMap
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass

_FASTAPI_CONSTRUCTORS = frozenset({"fastapi.FastAPI", "fastapi.routing.APIRouter", "fastapi.APIRouter"})
_ROUTE_METHODS = frozenset(
    {"get", "post", "put", "patch", "delete", "options", "head", "trace", "api_route", "websocket"}
)
_PYDANTIC_BASES = frozenset({"pydantic.BaseModel", "pydantic.main.BaseModel", "pydantic.v1.BaseModel"})
_DEPENDS = frozenset({"fastapi.Depends", "fastapi.params.Depends"})
_UNKNOWN_ANNOTATION = "<unknown-annotation>"
_UNKNOWN_BINDING = "<unknown-binding>"
_ANNOTATION_NODE_BUDGET = 128
_DOTTED_NODE_BUDGET = 128


@dataclass(frozen=True, slots=True)
class RouteBindingSnapshot:
    body_parameters: frozenset[str]
    dependency_bindings: dict[str, str | None]


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


def _is_route_candidate(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(
        isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.func.attr in _ROUTE_METHODS
        for dec in node.decorator_list
    )


def _has_nested_scope(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(
        isinstance(descendant, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and descendant is not node
        for descendant in ast.walk(node)
    )


def _walk_route_scope(
    statements: list[ast.stmt],
    *,
    module: str,
    scope: str,
    is_package: bool,
    bindings: MutableMapping[str, str],
    receivers: set[str],
    models: set[str],
    snapshots: dict[int, RouteBindingSnapshot],
) -> None:
    for stmt in statements:
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
            qualname = f"{scope}.{stmt.name}"
            if isinstance(stmt, ast.ClassDef):
                bases = {
                    candidate
                    for base in stmt.bases
                    if (candidate := _module_candidate(resolve_dotted(base, bindings), module)) is not None
                }
                is_model = bool(bases & (_PYDANTIC_BASES | models))
                models.discard(qualname)
                if is_model:
                    models.add(qualname)
                _walk_route_scope(
                    stmt.body,
                    module=module,
                    scope=qualname,
                    is_package=is_package,
                    bindings=ChainMap({}, bindings),
                    receivers=set(receivers),
                    models=set(models),
                    snapshots=snapshots,
                )
            else:
                if _is_route_candidate(stmt):
                    route_receivers = frozenset(receivers)
                    snapshots[id(stmt)] = RouteBindingSnapshot(
                        body_parameters=route_body_parameters(
                            stmt,
                            module=module,
                            aliases=bindings,
                            route_receivers=route_receivers,
                            pydantic_models=frozenset(models),
                        ),
                        dependency_bindings=route_dependency_parameters(
                            stmt,
                            aliases=bindings,
                            route_receivers=route_receivers,
                        ),
                    )
                if _has_nested_scope(stmt):
                    child_bindings: MutableMapping[str, str] = ChainMap({}, bindings)
                    child_receivers = set(receivers)
                    for arg in [
                        *stmt.args.posonlyargs,
                        *stmt.args.args,
                        *stmt.args.kwonlyargs,
                    ]:
                        child_bindings[arg.arg] = f"{_UNKNOWN_BINDING}.{arg.arg}"
                        child_receivers.discard(arg.arg)
                    if stmt.args.vararg is not None:
                        child_bindings[stmt.args.vararg.arg] = f"{_UNKNOWN_BINDING}.{stmt.args.vararg.arg}"
                        child_receivers.discard(stmt.args.vararg.arg)
                    if stmt.args.kwarg is not None:
                        child_bindings[stmt.args.kwarg.arg] = f"{_UNKNOWN_BINDING}.{stmt.args.kwarg.arg}"
                        child_receivers.discard(stmt.args.kwarg.arg)
                    _walk_route_scope(
                        stmt.body,
                        module=module,
                        scope=f"{qualname}.<locals>",
                        is_package=is_package,
                        bindings=child_bindings,
                        receivers=child_receivers,
                        models=set(models),
                        snapshots=snapshots,
                    )
                models.discard(qualname)
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
            canonical_target = f"{scope}.{target}"
            if alias_target != canonical_target:
                models.discard(canonical_target)


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
    snapshots: dict[int, RouteBindingSnapshot] = {}
    _walk_route_scope(
        tree.body,
        module=module,
        scope=module,
        is_package=is_package,
        bindings={},
        receivers=set(),
        models={name for name in known_models if _model_owner(name) != module},
        snapshots=snapshots,
    )
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
            canonical_target = f"{module}.{name}"
            if alias_target in found:
                found.add(canonical_target)
            elif alias_target != canonical_target:
                found.discard(canonical_target)
            if alias_target is not None:
                bindings[name] = alias_target
            else:
                bindings[name] = f"{_UNKNOWN_BINDING}.{name}"
    return frozenset(found)


def discover_callable_aliases(
    tree: ast.Module,
    *,
    module: str,
    is_package: bool = False,
) -> dict[str, str]:
    """Return final proven top-level assignment aliases to callable identities."""
    bindings: dict[str, str] = {}
    aliases: dict[str, str] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Import):
            for item in stmt.names:
                local = item.asname or item.name.split(".")[0]
                bindings[local] = item.name if item.asname is not None else local
            continue
        if isinstance(stmt, ast.ImportFrom):
            base = _import_from_base(stmt, module, is_package=is_package)
            if base is not None:
                for item in stmt.names:
                    if item.name != "*":
                        bindings[item.asname or item.name] = f"{base}.{item.name}"
            continue
        if isinstance(stmt, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            canonical = f"{module}.{stmt.name}"
            bindings[stmt.name] = canonical
            aliases.pop(canonical, None)
            continue
        assigned = _assigned_names(stmt)
        if not assigned:
            continue
        value = stmt.value if isinstance(stmt, (ast.Assign, ast.AnnAssign)) else None
        target = resolve_dotted(value, bindings) if isinstance(value, (ast.Name, ast.Attribute)) else None
        for name in assigned:
            canonical = f"{module}.{name}"
            if target is not None:
                bindings[name] = target
                aliases[canonical] = target
            else:
                bindings[name] = f"{_UNKNOWN_BINDING}.{name}"
                aliases.pop(canonical, None)
    return aliases


def discover_parameter_types(
    tree: ast.Module,
    *,
    module: str,
    is_package: bool = False,
) -> dict[int, dict[str, str]]:
    """Resolve function parameter annotations against source-ordered lexical bindings."""
    resolved: dict[int, dict[str, str]] = {}

    def walk_scope(
        statements: list[ast.stmt],
        *,
        scope: str,
        bindings: MutableMapping[str, str],
    ) -> None:
        for stmt in statements:
            if isinstance(stmt, ast.Import):
                for item in stmt.names:
                    local = item.asname or item.name.split(".")[0]
                    bindings[local] = item.name if item.asname is not None else local
                continue
            if isinstance(stmt, ast.ImportFrom):
                base = _import_from_base(stmt, module, is_package=is_package)
                if base is not None:
                    for item in stmt.names:
                        if item.name != "*":
                            bindings[item.asname or item.name] = f"{base}.{item.name}"
                continue
            if isinstance(stmt, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                qualname = f"{scope}.{stmt.name}"
                if isinstance(stmt, ast.ClassDef):
                    walk_scope(stmt.body, scope=qualname, bindings=ChainMap({}, bindings))
                else:
                    parameter_types: dict[str, str] = {}
                    parameters = [
                        *stmt.args.posonlyargs,
                        *stmt.args.args,
                        *stmt.args.kwonlyargs,
                    ]
                    if stmt.args.vararg is not None:
                        parameters.append(stmt.args.vararg)
                    if stmt.args.kwarg is not None:
                        parameters.append(stmt.args.kwarg)
                    for parameter in parameters:
                        if parameter.annotation is not None:
                            annotation = resolve_dotted(parameter.annotation, bindings)
                            if annotation is not None:
                                parameter_types[parameter.arg] = annotation
                    resolved[id(stmt)] = parameter_types

                    child_bindings: MutableMapping[str, str] = ChainMap({}, bindings)
                    for parameter in parameters:
                        child_bindings[parameter.arg] = f"{_UNKNOWN_BINDING}.{parameter.arg}"
                    walk_scope(
                        stmt.body,
                        scope=f"{qualname}.<locals>",
                        bindings=child_bindings,
                    )
                bindings[stmt.name] = qualname
                continue
            assigned = _assigned_names(stmt)
            if not assigned:
                continue
            value = stmt.value if isinstance(stmt, (ast.Assign, ast.AnnAssign)) else None
            target = resolve_dotted(value, bindings) if isinstance(value, (ast.Name, ast.Attribute)) else None
            for name in assigned:
                bindings[name] = target if target is not None else f"{_UNKNOWN_BINDING}.{name}"

    walk_scope(tree.body, scope=module, bindings={})
    return resolved


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
        if isinstance(current, ast.Constant) and isinstance(current.value, str):
            if not current.value.strip():
                continue
            try:
                parsed = ast.parse(current.value, mode="eval")
            except (MemoryError, RecursionError, SyntaxError, ValueError):
                candidates.add(_UNKNOWN_ANNOTATION)
            else:
                worklist.append(parsed.body)
            continue
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
            if resolved.startswith(f"{_UNKNOWN_BINDING}."):
                candidates.add(_UNKNOWN_ANNOTATION)
            else:
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
