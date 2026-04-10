"""Call-graph taint utilities — trust order, least_trusted(), call-graph extraction.

Part of the L3 call-graph taint propagation system (WP 2.1).
"""

from __future__ import annotations

import ast

from wardline.core.taints import TaintState
from wardline.scanner.rules.base import walk_skip_nested_defs

L3_LOW_RESOLUTION_THRESHOLD = 0.70

TRUST_RANK: dict[TaintState, int] = {
    TaintState.INTEGRAL: 0,
    TaintState.ASSURED: 1,
    TaintState.GUARDED: 2,
    TaintState.UNKNOWN_ASSURED: 3,
    TaintState.UNKNOWN_GUARDED: 4,
    TaintState.EXTERNAL_RAW: 5,
    TaintState.UNKNOWN_RAW: 6,
    TaintState.MIXED_RAW: 7,
}

# Use explicit check, not assert (survives Python -O)
if len(TRUST_RANK) != len(TaintState):
    raise ValueError(f"TRUST_RANK covers {len(TRUST_RANK)} states but TaintState has {len(TaintState)}")


def least_trusted(a: TaintState, b: TaintState) -> TaintState:
    """Return the less-trusted of two taint states (higher rank)."""
    return a if TRUST_RANK[a] >= TRUST_RANK[b] else b


# ── Call-graph extraction ────────────────────────────────────────


def extract_call_edges(
    tree: ast.Module,
    qualname_map: dict[int, str],
) -> tuple[dict[str, set[str]], dict[str, int], dict[str, int]]:
    """Extract intra-module call edges from an AST.

    Args:
        tree: Parsed AST module.
        qualname_map: ``{id(node): qualname}`` for all functions in the module,
            as produced by :func:`~wardline.scanner._qualnames.build_qualname_map`.

    Returns:
        Tuple of ``(adjacency, resolved_counts, unresolved_counts)`` where:

        - **adjacency**: ``{caller_qualname: {callee_qualname, ...}}`` — resolved
          intra-module call edges.
        - **resolved_counts**: ``{caller_qualname: int}`` — number of resolved
          call sites per caller.
        - **unresolved_counts**: ``{caller_qualname: int}`` — number of unresolved
          (external / dynamic) call sites per caller.
    """
    # Build reverse lookup maps from qualname_map
    # module_defs: {bare_name: qualname} for module-level functions
    # class_methods: {class_name: {method_name: qualname}} for methods
    # class_names: set of top-level class names (for constructor resolution)
    module_defs: dict[str, str] = {}
    class_methods: dict[str, dict[str, str]] = {}
    class_names: set[str] = set()

    for _node_id, qualname in qualname_map.items():
        parts = qualname.split(".")
        if len(parts) == 1:
            # Module-level function: "foo"
            module_defs[parts[0]] = qualname
        elif len(parts) == 2:
            # Could be a class method: "ClassName.method"
            cls_name, method_name = parts
            # Check if this is actually under a class by looking for other
            # methods in the same class or by examining the qualname structure.
            # We track all two-part qualnames as potential class methods.
            try:
                class_methods[cls_name]
            except KeyError:
                class_methods[cls_name] = {}
            class_methods[cls_name][method_name] = qualname
        elif len(parts) >= 3:
            # Nested: e.g. "ClassName.method.inner" — register in class_methods
            # for the top-level class if applicable.
            cls_name = parts[0]
            try:
                class_methods[cls_name]
            except KeyError:
                class_methods[cls_name] = {}
            # Register using full method path under the class
            method_path = ".".join(parts[1:])
            class_methods[cls_name][method_path] = qualname

    # Identify class names: classes are qualname prefixes that have methods
    # but are not themselves functions. We detect them from two-part qualnames.
    # Also scan the AST for ClassDef nodes at module level.
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.ClassDef):
            class_names.add(node.name)
            # Also register the class name in module_defs if it is not already
            # there (classes are callable — resolves to __init__)

    # Build adjacency list
    adjacency: dict[str, set[str]] = {}
    resolved_counts: dict[str, int] = {}
    unresolved_counts: dict[str, int] = {}

    # Walk all function nodes
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        caller_qualname = qualname_map.get(id(node))
        if caller_qualname is None:
            continue

        edges: set[str] = set()
        resolved = 0
        unresolved = 0

        # Determine the caller's class (if any) for self-method resolution
        caller_parts = caller_qualname.split(".")
        caller_class: str | None = None
        if len(caller_parts) >= 2 and caller_parts[0] in class_names:
            caller_class = caller_parts[0]

        # Walk the function body for Call nodes, skipping nested function defs
        # so that inner function calls are not attributed to the outer function.
        for child in walk_skip_nested_defs(node):
            if not isinstance(child, ast.Call):
                continue

            func = child.func

            if isinstance(func, ast.Name):
                name = func.id
                # Rule 1: module-level function call
                try:
                    target = module_defs[name]
                    edges.add(target)
                    resolved += 1
                except KeyError:
                    # Rule 3: constructor call — ClassName()
                    if name in class_names:
                        init_qualname = f"{name}.__init__"
                        try:
                            _ = class_methods[name]["__init__"]
                            edges.add(init_qualname)
                            resolved += 1
                        except KeyError:
                            # Class exists but no __init__ defined
                            unresolved += 1
                    else:
                        # Could be a parameter, builtin, or import — unresolved
                        unresolved += 1

            elif (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "self"
                and caller_class is not None
            ):
                # Rule 2: self.method() call
                method_name = func.attr
                try:
                    callee_qualname = class_methods[caller_class][method_name]
                    edges.add(callee_qualname)
                    resolved += 1
                except KeyError:
                    unresolved += 1
            else:
                # Everything else (chained attrs, subscripts, etc.) — unresolved
                unresolved += 1

        adjacency[caller_qualname] = edges
        resolved_counts[caller_qualname] = resolved
        unresolved_counts[caller_qualname] = unresolved

    return adjacency, resolved_counts, unresolved_counts
