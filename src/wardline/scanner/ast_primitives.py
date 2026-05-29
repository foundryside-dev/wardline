# src/wardline/scanner/ast_primitives.py
"""Reusable, stdlib-only AST primitives ported from ``wardline.old``.

- ``build_import_alias_map`` — local-name -> fully-qualified-name from a module's
  top-level imports (resolving relative imports).
- ``iter_calls_in_function_body`` — every ``ast.Call`` in a function body without
  descending into nested function/class/lambda scopes.

Both are exercised only by unit tests in SP1a; their first engine consumer is
the SP1d callgraph. (The ``resolve_*`` call resolvers from ``.old`` land then.)
"""

from __future__ import annotations

import ast
from collections.abc import Iterator


def build_import_alias_map(
    tree: ast.Module,
    module_path: str = "",
    *,
    is_package: bool = False,
) -> dict[str, str]:
    """Build ``{local_name: fully_qualified_name}`` from module-level imports.

    Only top-level statements are processed (not imports inside functions). Star
    imports (``from X import *``) are ignored — they cannot be resolved without
    executing the import.

    Args:
        tree: parsed AST module.
        module_path: dotted module path of the file being analysed (e.g.
            ``"mypackage.submod"``); required to resolve relative imports.
        is_package: whether ``module_path`` names a package initializer
            (``pkg/__init__.py`` -> ``module_path="pkg"``, ``is_package=True``)
            so ``from . import y`` resolves against the current package.
    """
    alias_map: dict[str, str] = {}

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local_name = (
                    alias.asname if alias.asname else alias.name.split(".")[0]
                )
                alias_map[local_name] = (
                    alias.name if alias.asname else alias.name.split(".")[0]
                )
            continue
        if isinstance(node, ast.ImportFrom):
            if node.module is None and (node.level or 0) == 0:
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                local_name = alias.asname if alias.asname else alias.name
                level = node.level or 0
                if level > 0 and module_path:
                    parts = module_path.split(".")
                    package_parts = parts if is_package else parts[:-1]
                    ascend = level - 1
                    if ascend == 0:
                        base_parts = package_parts
                    elif ascend <= len(package_parts):
                        base_parts = package_parts[:-ascend]
                    else:
                        # Over-ascends past the package root — only reachable for
                        # source that could not be imported; treat as empty base.
                        base_parts = []
                    base = ".".join(base_parts)
                    if node.module:
                        fqn = (
                            f"{base}.{node.module}.{alias.name}"
                            if base
                            else f"{node.module}.{alias.name}"
                        )
                    else:
                        fqn = f"{base}.{alias.name}" if base else alias.name
                elif node.module is not None:
                    fqn = f"{node.module}.{alias.name}"
                else:
                    continue
                alias_map[local_name] = fqn

    return alias_map


def iter_calls_in_function_body(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> Iterator[ast.Call]:
    """Yield every ``ast.Call`` in ``node``'s body without descending into nested
    function scopes.

    Stops at ``FunctionDef``, ``AsyncFunctionDef``, ``Lambda``, and ``ClassDef``
    — each introduces a new scope whose body calls are attributed elsewhere.
    Header expressions that execute in the enclosing scope (decorators, default
    values, base classes, metaclass keywords) are still attributed to ``node``.
    """

    def walk_node(current: ast.AST) -> Iterator[ast.Call]:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in current.decorator_list:
                yield from walk_node(decorator)
            yield from _walk_argument_defaults(current.args)
            return
        if isinstance(current, ast.ClassDef):
            for decorator in current.decorator_list:
                yield from walk_node(decorator)
            for base in current.bases:
                yield from walk_node(base)
            for keyword in current.keywords:
                yield from walk_node(keyword.value)
            return
        if isinstance(current, ast.Lambda):
            yield from _walk_argument_defaults(current.args)
            return
        if isinstance(current, ast.Call):
            yield current
        for child in ast.iter_child_nodes(current):
            yield from walk_node(child)

    def _walk_argument_defaults(args: ast.arguments) -> Iterator[ast.Call]:
        for default in args.defaults:
            yield from walk_node(default)
        for kw_default in args.kw_defaults:
            if kw_default is None:
                continue
            yield from walk_node(kw_default)

    for stmt in node.body:
        yield from walk_node(stmt)
