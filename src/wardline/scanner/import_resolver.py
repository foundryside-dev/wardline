"""Import alias resolution for two-hop rejection path analysis.

Builds a per-file mapping from local names to fully-qualified names
by walking module-level Import and ImportFrom statements.
"""
from __future__ import annotations

import ast


def build_import_alias_map(
    tree: ast.Module,
    module_path: str = "",
) -> dict[str, str]:
    """Build {local_name: fully_qualified_name} from module-level imports.

    Only processes top-level statements (not imports inside functions).
    Star imports (``from X import *``) are ignored — they cannot be
    resolved without executing the import.

    Args:
        tree: Parsed AST module.
        module_path: Dotted module path of the file being analysed
            (e.g. ``"mypackage.submod"``).  Required to resolve
            relative imports (``from .validators import check``).
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
            for alias in node.names:
                if alias.name == "*":
                    continue
                local_name = alias.asname if alias.asname else alias.name
                level = node.level or 0
                if level > 0 and module_path:
                    # Relative import: climb `level` packages up from module_path
                    parts = module_path.split(".")
                    # level=1 means current package (drop module name),
                    # level=2 means parent package, etc.
                    base = ".".join(parts[:-level]) if level <= len(parts) else ""
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


def resolve_call_fqn(
    call: ast.Call,
    alias_map: dict[str, str],
    local_fqns: frozenset[str],
    module_prefix: str,
) -> str | None:
    """Resolve an ast.Call to a fully-qualified name.

    Resolution order:
    1. If bare name matches a local FunctionDef FQN → return the local FQN
    2. If bare name or attribute prefix is in alias_map → resolve via import
    3. Otherwise → None (unresolvable)
    """
    if isinstance(call.func, ast.Name):
        bare_name = call.func.id
        local_candidate = f"{module_prefix}.{bare_name}" if module_prefix else bare_name
        if local_candidate in local_fqns:
            return local_candidate
        return alias_map.get(bare_name)

    if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
        prefix_fqn = alias_map.get(call.func.value.id)
        if prefix_fqn is not None:
            return f"{prefix_fqn}.{call.func.attr}"

    return None
