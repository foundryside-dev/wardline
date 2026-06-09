"""The minimal Rust index: parse tree -> callable ``RustEntity`` list + NodeId stamping.

Walks the module scope in source order, minting each callable's qualname via the
``qualname`` dialect (ADR-049) and stamping its ``NodeId`` from the shared keying
authority. **Only callables are emitted** (free fns, inherent methods, trait methods,
assoc fns) — structs and modules are scope-only, closures and nested ``fn``s are never
emitted because the walk never descends a ``function_item`` body (ADR-049). A finding
inside a closure/nested fn attributes to the enclosing named fn via ``line_start``.

This is the single-file, file-module-rooted slice-1 view: the caller supplies ``module``
(crate name from ``Cargo.toml`` + cross-file route are SP2). tree-sitter types appear
only under ``TYPE_CHECKING`` so importing this module never pulls the ``wardline[rust]``
extra.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING

from wardline.core.finding import Location
from wardline.core.node_id import NodeId
from wardline.rust import qualname as q
from wardline.rust.nodeid import mint_node_ids
from wardline.rust.parse import parse_rust

if TYPE_CHECKING:
    from collections.abc import Iterable

    from tree_sitter import Node, Tree

    from wardline.rust.nodeid import NodeIdMap

__all__ = ["RustEntity", "discover_rust_entities", "index_entities"]

_ITEM_TYPES = frozenset({"function_item", "mod_item", "impl_item", "struct_item"})


@dataclass(frozen=True, slots=True)
class RustEntity:
    """A callable Rust entity. ``kind`` is Wardline's *semantic* split
    (``function``/``method``); the qualname id-kind is ``function`` for both (ADR-049).

    ``node`` is the ``function_item`` CST node (valid while the source tree is alive) —
    the analyzer reuses it (under the *same* ``NodeIdMap``, spec §5) to seed the fn's
    trust tier and run dataflow over its body."""

    qualname: str
    kind: str
    node_id: NodeId
    location: Location
    node: Node


def index_entities(tree: Tree, nmap: NodeIdMap, *, module: str, path: str = "") -> list[RustEntity]:
    """Emit the callable entities of an already-parsed ``tree`` under its ``nmap``.

    The analyzer calls this so index/dataflow/rules share ONE tree and ONE keying
    authority (spec §5 — re-parsing would mint divergent NodeIds and fail quietly).
    """
    entities: list[RustEntity] = []
    _walk_scope(tree.root_node.children, module, nmap, entities, path)
    return entities


def discover_rust_entities(source: str, *, module: str, path: str = "") -> list[RustEntity]:
    """Parse ``source`` and emit its callable entities, qualname-rooted at ``module``.

    The corpus-facing API: parses internally (``module`` is the supplied file-module root,
    since deriving it from ``Cargo.toml`` is SP2). ``path`` only labels ``Location``.
    """
    tree = parse_rust(source)
    return index_entities(tree, mint_node_ids(tree), module=module, path=path)


def _walk_scope(
    child_nodes: Iterable[Node],
    module: str,
    nmap: NodeIdMap,
    entities: list[RustEntity],
    path: str,
) -> None:
    # Attributes are *preceding siblings* of the item they decorate, so fold each
    # pending cfg predicate onto the next item. Any non-attribute node resets it.
    items: list[tuple[Node, str | None]] = []
    pending_cfg: str | None = None
    for child in child_nodes:
        if child.type == "attribute_item":
            pred = q.cfg_predicate_of(child)
            if pred is not None:
                pending_cfg = pred
            continue
        if child.type in _ITEM_TYPES:
            items.append((child, pending_cfg))
        pending_cfg = None

    # The @cfg suffix is added only on a bare-path COLLISION (ADR-049): a lone
    # cfg-gated item gets no suffix. Collisions are per-kind; we emit only callables,
    # so count function names. Inherent impls carry NO source-order ordinal (ADR-049
    # amend, Option b): same-(type, generic-sig) impls share one `impl#<...>` key and
    # their methods merge under it.
    fn_name_counts = Counter(_name(node) for node, _ in items if node.type == "function_item")

    # Pre-cfg impl-segment twin counts (mirrors extract.rs `impl_twin_counts`): two
    # impls of the same (type, generic-sig) — incl. cfg-twins — share one key and would
    # collide; a cfg-gated member of such a group is split by an `@cfg(...)` suffix on
    # the impl key (now the ONLY distinguisher for inherent twins, the ordinal is gone).
    impl_segments: dict[int, str] = {}
    impl_twin_counts: Counter[str] = Counter()
    for node, _cfg in items:
        if node.type == "impl_item":
            seg = _impl_segment(node)
            if seg is not None:
                impl_segments[node.id] = seg
                impl_twin_counts[seg] += 1

    for node, cfg in items:
        if node.type == "function_item":
            name = _name(node)
            qualname = f"{module}.{name}"
            if cfg is not None and fn_name_counts[name] > 1:
                qualname += f"@cfg({cfg})"
            entities.append(_entity(qualname, "function", node, nmap, path))
        elif node.type == "mod_item":
            body = node.child_by_field_name("body")
            if body is not None:  # `mod foo;` (external) has no body to descend
                _walk_scope(body.children, f"{module}.{_name(node)}", nmap, entities, path)
        elif node.type == "impl_item":
            seg = impl_segments.get(node.id)
            if seg is None:
                continue
            if cfg is not None and impl_twin_counts[seg] > 1:
                seg += f"@cfg({cfg})"
            _emit_impl_methods(node, f"{module}.{seg}", nmap, entities, path)
        # struct_item: scope-only, never a callable -> not emitted.


def _impl_segment(impl_node: Node) -> str | None:
    """The pre-cfg ``<SelfType>.impl[...]`` / ``<SelfType>.impl#<...>`` segment, or
    ``None`` if the impl has no self type. No ordinal (ADR-049 amend)."""
    type_node = impl_node.child_by_field_name("type")
    if type_node is None:
        return None
    self_type = q.render_self_type(type_node)
    trait_node = impl_node.child_by_field_name("trait")
    if trait_node is not None:
        return f"{self_type}.impl[{q.render_trait_segment(trait_node)}]"
    return f"{self_type}.impl#<{q.render_positional_generics(impl_node)}>"


def _emit_impl_methods(
    impl_node: Node, impl_qualname: str, nmap: NodeIdMap, entities: list[RustEntity], path: str
) -> None:
    body = impl_node.child_by_field_name("body")
    if body is None:
        return
    for child in body.named_children:
        if child.type == "function_item":
            entities.append(_entity(f"{impl_qualname}.{_name(child)}", "method", child, nmap, path))


def _name(node: Node) -> str:
    name = node.child_by_field_name("name")
    if name is not None and name.text is not None:
        return name.text.decode("utf-8")
    return ""


def _entity(qualname: str, kind: str, node: Node, nmap: NodeIdMap, path: str) -> RustEntity:
    start = node.start_point
    end = node.end_point
    location = Location(
        path=path,
        line_start=start[0] + 1,
        line_end=end[0] + 1,
        col_start=start[1],
        col_end=end[1],
    )
    return RustEntity(qualname=qualname, kind=kind, node_id=nmap.node_id(node), location=location, node=node)
