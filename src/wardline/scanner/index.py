# src/wardline/scanner/index.py
"""Per-file entity discovery (stdlib + ``wardline.core`` only).

An *entity* is a ``FunctionDef`` or ``AsyncFunctionDef`` — the unit the taint
engine seeds. Classes are traversed as *scope* only (they contribute to
qualnames) and are not emitted. ``@overload`` stubs are dropped before
deduplication; duplicate qualnames are resolved first-wins (source order), so a
``@property`` getter wins over its setter and an earlier redefinition wins over
a later one.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from wardline.core.finding import Location
from wardline.core.qualname import is_overload_stub, reconstruct_qualname


@dataclass(frozen=True, slots=True)
class Entity:
    """A discovered function/method with its Clarion-aligned identity."""

    qualname: str  # full dotted ``module.__qualname__`` (reconciliation key)
    kind: str  # "function" | "method"
    node: ast.FunctionDef | ast.AsyncFunctionDef
    location: Location


def discover_file_entities(
    tree: ast.Module, *, module: str, path: str
) -> list[Entity]:
    """Discover function/method entities in *tree*, in source order.

    Args:
        tree: the parsed module AST.
        module: the file's dotted module name (from
            :func:`wardline.core.qualname.module_dotted_name`). Callers MUST skip
            files where that returned ``None`` (a top-level ``__init__.py``).
        path: project-relative POSIX path, recorded on each entity's Location.

    The first definition wins when two produce the same qualname. ``@overload``
    stubs are dropped *before* this deduplication, so a real implementation
    following stubs is the surviving entity. Note: on a plain redefinition
    (``def f`` twice) first-wins keeps the *lexically first* node, which is the
    shadowed/dead one at runtime — consumers reconcile on ``qualname`` and must
    not assume the seeded node is the runtime-live object.
    """
    entities: list[Entity] = []
    seen: set[str] = set()

    def visit(node: ast.AST, scope: list[ast.AST], *, parent_is_class: bool) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not is_overload_stub(child):
                    # ``scope`` is outermost->innermost; reconstruct wants
                    # innermost->outermost.
                    local = reconstruct_qualname(child.name, list(reversed(scope)))
                    qualname = f"{module}.{local}"
                    if qualname not in seen:
                        seen.add(qualname)
                        entities.append(
                            Entity(
                                qualname=qualname,
                                kind="method" if parent_is_class else "function",
                                node=child,
                                location=Location(
                                    path=path,
                                    line_start=child.lineno,
                                    line_end=child.end_lineno,
                                    col_start=child.col_offset,
                                    col_end=child.end_col_offset,
                                ),
                            )
                        )
                # A function nested inside this one is a "function", not a method.
                visit(child, [*scope, child], parent_is_class=False)
            elif isinstance(child, ast.ClassDef):
                visit(child, [*scope, child], parent_is_class=True)
            else:
                # Non-scope node (If/With/Try/...): scope and class-ness unchanged.
                visit(child, scope, parent_is_class=parent_is_class)

    visit(tree, [], parent_is_class=False)
    return entities
