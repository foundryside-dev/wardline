# src/wardline/scanner/ast_primitives.py
"""Reusable, stdlib-only AST primitives ported from ``wardline.old``.

- ``build_import_alias_map`` — local-name -> fully-qualified-name from a module's
  top-level imports (resolving relative imports).
- ``iter_calls_in_function_body`` — every ``ast.Call`` in a function body without
  descending into nested function/class/lambda scopes.
- ``resolve_call_fqn`` — resolve a call node to a fully-qualified name using
  local FQNs and import aliases (ported from ``.old`` SP1c).

``resolve_same_class_call_fqn`` and ``resolve_nested_call_fqn`` remain deferred
to SP1d (the first consumer is the full callgraph).
"""

from __future__ import annotations

import ast
from collections.abc import Iterator, Mapping


def build_import_alias_map(
    tree: ast.Module,
    module_path: str = "",
    *,
    is_package: bool = False,
    star_exports: Mapping[str, Mapping[str, str]] | None = None,
) -> dict[str, str]:
    """Build ``{local_name: fully_qualified_name}`` from module-level imports.

    Only top-level statements are processed (not imports inside functions). Absolute
    star imports (``from X import *``) are resolved ONLY when ``X`` is in
    ``star_exports`` — a statically-known export set (e.g. Wardline's own trust
    vocabulary), never read from the target's source and never by executing it. Every
    other star import (relative, or an unknown module) is ignored, leaving the engine
    to surface the coverage gap as a ``WLN-ENGINE-UNKNOWN-IMPORT`` FACT (fail-closed).

    Args:
        tree: parsed AST module.
        module_path: dotted module path of the file being analysed (e.g.
            ``"mypackage.submod"``); required to resolve relative imports.
        is_package: whether ``module_path`` names a package initializer
            (``pkg/__init__.py`` -> ``module_path="pkg"``, ``is_package=True``)
            so ``from . import y`` resolves against the current package.
        star_exports: ``{source_module_fqn: {local_name: target_fqn}}`` of the
            statically-known exports to materialise for an absolute ``from X import *``.
    """
    alias_map: dict[str, str] = {}

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local_name = alias.asname if alias.asname else alias.name.split(".")[0]
                alias_map[local_name] = alias.name if alias.asname else alias.name.split(".")[0]
            continue
        if isinstance(node, ast.ImportFrom):
            if node.module is None and (node.level or 0) == 0:
                continue
            # Absolute star import of a statically-known module: materialise its
            # known exports (no execution, no target-source read). Relative star
            # imports and unknown modules fall through and stay unresolved.
            if (node.level or 0) == 0 and node.module is not None and any(a.name == "*" for a in node.names):
                for local_name, fqn in (star_exports or {}).get(node.module, {}).items():
                    alias_map[local_name] = fqn
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
                        fqn = f"{base}.{node.module}.{alias.name}" if base else f"{node.module}.{alias.name}"
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

    # Perf opt: Using explicit stack over recursive "yield from" to eliminate generator nesting
    # overhead in hot path traversal. Elements are pushed in reverse to maintain left-to-right processing order.
    stack: list[ast.AST] = []
    stack.extend(reversed(node.body))

    while stack:
        current = stack.pop()

        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for kw_default in reversed(current.args.kw_defaults):
                if kw_default is not None:
                    stack.append(kw_default)
            for default in reversed(current.args.defaults):
                if default is not None:
                    stack.append(default)
            for decorator in reversed(current.decorator_list):
                if decorator is not None:
                    stack.append(decorator)
            continue

        if isinstance(current, ast.ClassDef):
            for keyword in reversed(current.keywords):
                if keyword.value is not None:
                    stack.append(keyword.value)
            for base in reversed(current.bases):
                if base is not None:
                    stack.append(base)
            for decorator in reversed(current.decorator_list):
                if decorator is not None:
                    stack.append(decorator)
            continue

        if isinstance(current, ast.Lambda):
            for kw_default in reversed(current.args.kw_defaults):
                if kw_default is not None:
                    stack.append(kw_default)
            for default in reversed(current.args.defaults):
                if default is not None:
                    stack.append(default)
            continue

        if isinstance(current, ast.Call):
            yield current

        for field in reversed(current._fields):
            try:
                value = getattr(current, field)
            except AttributeError:
                continue
            if isinstance(value, list):
                stack.extend(n for n in reversed(value) if isinstance(n, ast.AST))
            elif isinstance(value, ast.AST):
                stack.append(value)


def resolve_self_method_fqn(
    call: ast.Call,
    *,
    caller_class_fqn: str | None,
    project_fqns: frozenset[str],
) -> str | None:
    """Resolve a ``self.method()`` / ``cls.method()`` call to a project FQN.

    Returns the callee FQN when the call is ``self.<attr>(...)`` or
    ``cls.<attr>(...)``, the caller is a method of a known class
    (``caller_class_fqn`` is not None), and ``{caller_class_fqn}.{attr}`` is a
    project function. Otherwise None.

    Constructor calls (``ClassName()``) are intentionally NOT resolved here: an
    unresolved call raises the caller's pessimistic floor (over-taint, the safe
    direction). Closure-captured ``self`` (``self`` referenced inside a nested
    def) is likewise not resolved — ``caller_class_fqn`` is None for a closure
    qualname (it ends in ``.<locals>.<name>``), a documented under-taint limit.
    """
    if caller_class_fqn is None:
        return None
    func = call.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id in {"self", "cls"}:
        candidate = f"{caller_class_fqn}.{func.attr}"
        if candidate in project_fqns:
            return candidate
    return None


def resolve_call_fqn(
    call: ast.Call,
    alias_map: dict[str, str],
    local_fqns: frozenset[str],
    module_prefix: str,
) -> str | None:
    """Resolve an ``ast.Call`` to a fully-qualified name, or None if unresolvable.

    Resolution order:
      1. A bare name matching a local function FQN (``{module_prefix}.{name}``).
      2. A bare name or attribute receiver found in ``alias_map`` (an import).
      3. Otherwise None.
    """
    if isinstance(call.func, ast.Name):
        bare_name = call.func.id
        local_candidate = f"{module_prefix}.{bare_name}" if module_prefix else bare_name
        if local_candidate in local_fqns:
            return local_candidate
        return alias_map.get(bare_name)

    node = call.func
    attrs = []
    while isinstance(node, ast.Attribute):
        attrs.append(node.attr)
        node = node.value

    if isinstance(node, ast.Name):
        leftmost_name = node.id
        attrs.reverse()
        local_candidate = f"{module_prefix}.{leftmost_name}" if module_prefix else leftmost_name
        if not attrs and local_candidate in local_fqns:
            return local_candidate

        prefix_fqn = alias_map.get(leftmost_name)
        if prefix_fqn is not None:
            parts = [prefix_fqn] + attrs
            return ".".join(parts)

    return None
