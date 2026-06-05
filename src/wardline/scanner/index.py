# src/wardline/scanner/index.py
"""Per-file entity discovery (stdlib + ``wardline.core`` only).

An *entity* is a ``FunctionDef`` or ``AsyncFunctionDef`` — the unit the taint
engine seeds. Classes are traversed as *scope* only (they contribute to
qualnames) and are not emitted. ``@overload`` stubs are dropped before
deduplication; normal duplicate qualnames are resolved last-wins to match
Python rebinding, while ``@property`` setters/deleters keep the original getter.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from wardline.core.finding import Location
from wardline.core.qualname import is_overload_stub, reconstruct_qualname


@dataclass(frozen=True, slots=True)
class Entity:
    """A discovered function/method with its Loomweave-aligned identity."""

    qualname: str  # full dotted ``module.__qualname__`` (reconciliation key)
    kind: str  # "function" | "method"
    node: ast.FunctionDef | ast.AsyncFunctionDef
    location: Location


def discover_class_qualnames(tree: ast.Module, *, module: str) -> set[str]:
    """Discover the qualnames of every class in *tree*.

    Mirrors :func:`discover_file_entities`' scope traversal so class qualnames
    are produced by the SAME :func:`reconstruct_qualname` that produces method
    qualnames. The callgraph builder relies on this identity: for a method
    ``module.Class.method``, ``rsplit('.', 1)[0]`` equals ``module.Class`` and
    is therefore a member of this set. Any divergence in qualname construction
    would silently break ``self.method()`` resolution.
    """
    classes: set[str] = set()

    def visit(node: ast.AST, scope: list[ast.AST]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                local = reconstruct_qualname(child.name, list(reversed(scope)))
                classes.add(f"{module}.{local}")
                visit(child, [*scope, child])
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(child, [*scope, child])
            else:
                visit(child, scope)

    visit(tree, [])
    return classes


def discover_file_entities(tree: ast.Module, *, module: str, path: str) -> list[Entity]:
    """Discover function/method entities in *tree*, in source order.

    Args:
        tree: the parsed module AST.
        module: the file's dotted module name (from
            :func:`wardline.core.qualname.module_dotted_name`). Callers MUST skip
            files where that returned ``None`` (a top-level ``__init__.py``).
        path: project-relative POSIX path, recorded on each entity's Location.

    Plain redefinitions use last-wins semantics, matching Python's runtime
    rebinding. ``@overload`` stubs are dropped *before* this deduplication, so a
    real implementation following stubs is the surviving entity. ``@property``
    setter/deleter functions intentionally do not replace the getter entity,
    because the property object remains bound to the shared method qualname.
    """
    entities: list[Entity] = []
    entity_index: dict[str, int] = {}

    def property_decorator_kind(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
        for decorator in node.decorator_list:
            if (
                isinstance(decorator, ast.Attribute)
                and decorator.attr in {"setter", "deleter"}
                and isinstance(decorator.value, ast.Name)
                and decorator.value.id == node.name
            ):
                return decorator.attr
        return None

    def make_entity(
        child: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        qualname: str,
        parent_is_class: bool,
    ) -> Entity:
        return Entity(
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

    def remove_shadowed_function(qualname: str) -> None:
        shadowed_nested_prefix = f"{qualname}.<locals>."
        remove_at = [
            idx
            for idx, entity in enumerate(entities)
            if entity.qualname == qualname or entity.qualname.startswith(shadowed_nested_prefix)
        ]
        for idx in reversed(remove_at):
            entities.pop(idx)
        entity_index.clear()
        entity_index.update({entity.qualname: idx for idx, entity in enumerate(entities)})

    def add_or_replace_entity(entity: Entity) -> None:
        existing_idx = entity_index.get(entity.qualname)
        if existing_idx is not None:
            remove_shadowed_function(entity.qualname)
        entity_index[entity.qualname] = len(entities)
        entities.append(entity)

    def visit(node: ast.AST, scope: list[ast.AST], *, parent_is_class: bool) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not is_overload_stub(child):
                    # ``scope`` is outermost->innermost; reconstruct wants
                    # innermost->outermost.
                    local = reconstruct_qualname(child.name, list(reversed(scope)))
                    qualname = f"{module}.{local}"
                    prop_kind = property_decorator_kind(child)
                    if prop_kind is not None:
                        qualname = f"{qualname}:{prop_kind}"
                    add_or_replace_entity(make_entity(child, qualname=qualname, parent_is_class=parent_is_class))
                # A function nested inside this one is a "function", not a method.
                visit(child, [*scope, child], parent_is_class=False)
            elif isinstance(child, ast.ClassDef):
                visit(child, [*scope, child], parent_is_class=True)
            else:
                # Non-scope node (If/With/Try/...): scope and class-ness unchanged.
                visit(child, scope, parent_is_class=parent_is_class)

    visit(tree, [], parent_is_class=False)
    return entities
