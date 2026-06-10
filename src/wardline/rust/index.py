"""The Rust index: parse tree -> full ADR-049 entity surface + NodeId stamping.

Walks the module scope in source order, minting every entity's qualname via the
``qualname`` dialect (ADR-049) and stamping its ``NodeId`` from the shared keying
authority. **The full ten-kind surface is emitted** (Phase 1b): the file-scope
``module`` entity FIRST, then — at their source positions — free items over the
nine named kinds (function/struct/enum/trait/type_alias/const/static/macro plus
inline ``mod``), the merged ``impl`` entity (once, at its FIRST contributing
block), and impl methods re-parented onto the impl entity (``module -> impl ->
method`` containment, mirroring extract.rs ``emit_impl``).

Not emitted, matching the oracle: closures and nested ``fn``s (the walk never
descends a ``function_item`` body — a finding inside one attributes to the
enclosing named fn via ``line_start``), trait-body items (extract.rs deliberately
never walks trait bodies — a trait definition is only its ``trait`` entity), bare
macro INVOCATIONS, external ``mod foo;`` declarations, and ``union`` items
(outside the ten-kind set, the oracle's ``_ => None`` arm).

cfg twins are counted per-(kind, name) over the nine named item kinds (extract.rs
``twin_counts``): ``fn S`` and ``struct S`` never interfere — the entity id's kind
segment already separates them — and the ``@cfg(...)`` suffix is applied only on a
within-kind collision. Impl blocks have their own pre-cfg twin counter keyed on
the full impl segment.

This is the single-file, file-module-rooted view: the caller supplies ``module``
(the SP2 whole-tree pass — ``Cargo.toml`` crate roots + cross-file routes — lives
in ``crate_roots.py``/``analyzer._module_for`` and feeds it in).
tree-sitter types appear only under ``TYPE_CHECKING`` so importing this module
never pulls the ``wardline[rust]`` extra.
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

# tree-sitter node type -> ADR-049 id-kind, for the free leaf items emitted directly
# at their source position. `mod_item` (recursed) and `impl_item` (merged) are handled
# by their own arms; a bare macro invocation is an `expression_statement`, never here.
_LEAF_KINDS: dict[str, str] = {
    "function_item": "function",
    "struct_item": "struct",
    "enum_item": "enum",
    "trait_item": "trait",
    "type_item": "type_alias",
    "const_item": "const",
    "static_item": "static",
    "macro_definition": "macro",
}
_ITEM_TYPES = frozenset(_LEAF_KINDS) | frozenset({"mod_item", "impl_item"})

# Comment nodes are token-stream-INVISIBLE to the oracle (syn/proc-macro2 drop them
# before extract.rs ever runs), so a comment interposed between a #[cfg] attribute
# and its item must not reset the pending-cfg accumulation. Covers `//`, `/* */`,
# AND `///` doc comments (tree-sitter parses a doc comment as a line_comment too;
# to syn it is a #[doc] attribute — either way, never a cfg). Corpus row:
# cfg_attr_comment_interposition.
_COMMENT_TYPES = frozenset({"line_comment", "block_comment"})


@dataclass(frozen=True, slots=True)
class RustEntity:
    """One emitted Rust entity. ``kind`` spans the full ADR-049 id-kind set
    (``module``/``struct``/``function``/``enum``/``trait``/``type_alias``/``const``/
    ``static``/``macro``/``impl``) plus Wardline's *semantic* ``method`` for impl fns —
    the qualname id-kind is ``function`` for both (``qualname.entity_id`` maps it).

    ``parent`` is the qualname of the containing module or impl entity (``None`` for
    the file-scope module) — the ``module -> impl -> method`` containment chain.

    ``node`` is the entity's CST node (valid while the source tree is alive) — for
    callables the analyzer reuses it (under the *same* ``NodeIdMap``, spec §5) to seed
    the fn's trust tier and run dataflow over its body."""

    qualname: str
    kind: str
    node_id: NodeId
    location: Location
    node: Node
    parent: str | None


def index_entities(tree: Tree, nmap: NodeIdMap, *, module: str, path: str = "") -> list[RustEntity]:
    """Emit the entities of an already-parsed ``tree`` under its ``nmap``.

    The analyzer calls this so index/dataflow/rules share ONE tree and ONE keying
    authority (spec §5 — re-parsing would mint divergent NodeIds and fail quietly).
    The file-scope ``module`` entity is emitted FIRST (corpus row order), spanning
    the root node.
    """
    root = tree.root_node
    entities: list[RustEntity] = [_entity(module, "module", root, nmap, path, parent=None)]
    _walk_scope(root.children, module, nmap, entities, path)
    return entities


def discover_rust_entities(source: str, *, module: str, path: str = "") -> list[RustEntity]:
    """Parse ``source`` and emit its entities, qualname-rooted at ``module``.

    The corpus-facing API: parses internally (``module`` is the supplied file-module root —
    the scan path derives it via ``crate_roots``/``analyzer._module_for``; corpus cases
    supply it directly). ``path`` only labels ``Location``.
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
    # Attributes are *preceding siblings* of the item they decorate, so accumulate
    # every pending cfg predicate RAW onto the next item (mirrors extract.rs
    # `cfg_predicates` — ALL stacked #[cfg]s feed the discriminant, normalisation
    # happens exactly once in `cfg_discriminant`). Any non-attribute node resets it.
    items: list[tuple[Node, list[str]]] = []
    pending_cfgs: list[str] = []
    for child in child_nodes:
        if child.type in _COMMENT_TYPES:
            # Token-stream-invisible (see _COMMENT_TYPES): skip WITHOUT resetting
            # pending_cfgs — a `// note` between #[cfg] and the fn must not detach
            # the cfg and hand two twins the same bare colliding path.
            continue
        if child.type == "attribute_item":
            pred = q.cfg_predicate_of(child)
            if pred is not None:
                pending_cfgs.append(pred)
            continue
        if child.type in _ITEM_TYPES:
            items.append((child, pending_cfgs))
        pending_cfgs = []

    # The @cfg suffix is added only on a bare-path COLLISION (ADR-049): a lone
    # cfg-gated item gets no suffix. Counting is per-(kind, name) over the nine
    # NAMED item kinds (extract.rs `twin_counts`) — the id's kind segment already
    # separates `fn S` from `struct S`, so a unique (kind, name) keeps the bare path.
    twin_counts: Counter[tuple[str, str]] = Counter()
    for node, _cfg in items:
        key = _named_item_key(node)
        if key is not None:
            twin_counts[key] += 1

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

    # Method-level cfg-twin counts (ADR-049 Amendment 5): keyed on the FINAL impl
    # qualname (post impl-level cfg) + method name, counted across ALL merged blocks —
    # so an impl-level cfg-twin (already split into distinct impl entities) gets no
    # redundant method suffix, while methods merging across same-key blocks do.
    final_impl_quals: dict[int, str] = {}
    method_twin_counts: Counter[tuple[str, str]] = Counter()
    for node, cfgs in items:
        if node.type == "impl_item":
            seg = impl_segments.get(node.id)
            if seg is None:
                continue
            if cfgs and impl_twin_counts[seg] > 1:
                seg += q.cfg_discriminant(cfgs)
            final_qual = f"{module}.{seg}"
            final_impl_quals[node.id] = final_qual
            for method, _mcfgs in _impl_methods_with_cfgs(node):
                method_twin_counts[(final_qual, _name(method))] += 1

    # First block with a given (cfg-augmented) impl qualname emits the ONE merged impl
    # entity; later same-key blocks only append methods (extract.rs `seen_impl_ids`).
    # The set is PER-INVOCATION (each nested scope gets a fresh one); that is sound
    # because the impl qualname embeds the full module path, so two impls in different
    # scopes can never share a key — dedup only ever needs to see one scope at a time.
    seen_impl_quals: set[str] = set()

    for node, cfgs in items:
        if node.type == "mod_item":
            body = node.child_by_field_name("body")
            if body is None:  # `mod foo;` (external) has no body to descend
                continue
            name = _name(node)
            nested = f"{module}.{name}"
            if cfgs and twin_counts[("module", name)] > 1:
                nested += q.cfg_discriminant(cfgs)
            # The inline-mod entity is emitted AT its source position, BEFORE its
            # members (corpus nested_inline_mod row order; extract.rs inline-mod arm).
            entities.append(_entity(nested, "module", node, nmap, path, parent=module))
            _walk_scope(body.children, nested, nmap, entities, path)
        elif node.type == "impl_item":
            impl_qualname = final_impl_quals.get(node.id)
            if impl_qualname is None:
                continue
            if impl_qualname not in seen_impl_quals:
                seen_impl_quals.add(impl_qualname)
                entities.append(_entity(impl_qualname, "impl", node, nmap, path, parent=module))
            _emit_impl_methods(node, impl_qualname, nmap, entities, path, method_twin_counts)
        else:
            kind = _LEAF_KINDS[node.type]
            name = _name(node)
            qualname = f"{module}.{name}"
            if cfgs and twin_counts[(kind, name)] > 1:
                qualname += q.cfg_discriminant(cfgs)
            entities.append(_entity(qualname, kind, node, nmap, path, parent=module))


def _named_item_key(node: Node) -> tuple[str, str] | None:
    """The per-(kind, name) twin-counter key of a named item, or ``None`` for items
    that don't participate (impl blocks have their own counter; an external ``mod foo;``
    emits nothing, matching extract.rs counting only ``content: Some(_)`` mods)."""
    if node.type == "mod_item":
        if node.child_by_field_name("body") is None:
            return None
        return ("module", _name(node))
    kind = _LEAF_KINDS.get(node.type)
    if kind is None:
        return None
    return (kind, _name(node))


def _impl_segment(impl_node: Node) -> str | None:
    """The pre-cfg ``<SelfType>.impl[...]`` / ``<SelfType>.impl#<...>`` segment, or
    ``None`` if the impl has no self type. The self type carries its concrete generic args
    (ADR-049 §2 self-type-args amendment — ``Foo<i32>`` vs ``Foo<u32>`` are distinct keys,
    the impl's own params positional); no ordinal (ADR-049 amend Option b)."""
    type_node = impl_node.child_by_field_name("type")
    if type_node is None:
        return None
    self_type = q.render_self_type(type_node, q.impl_type_param_names(impl_node))
    trait_node = impl_node.child_by_field_name("trait")
    if trait_node is not None:
        return f"{self_type}.impl[{q.render_trait_segment(trait_node)}]"
    return f"{self_type}.impl#<{q.render_positional_generics(impl_node)}>"


def _impl_methods_with_cfgs(impl_node: Node) -> list[tuple[Node, list[str]]]:
    """``(function_item, raw cfg predicates)`` pairs of an impl body, with the SAME
    pending-cfg accumulation discipline as ``_walk_scope`` (comments transparent,
    attributes accumulate, any other node resets)."""
    body = impl_node.child_by_field_name("body")
    if body is None:
        return []
    out: list[tuple[Node, list[str]]] = []
    pending_cfgs: list[str] = []
    for child in body.children:
        if child.type in _COMMENT_TYPES:
            continue
        if child.type == "attribute_item":
            pred = q.cfg_predicate_of(child)
            if pred is not None:
                pending_cfgs.append(pred)
            continue
        if child.type == "function_item":
            out.append((child, pending_cfgs))
        pending_cfgs = []
    return out


def _emit_impl_methods(
    impl_node: Node,
    impl_qualname: str,
    nmap: NodeIdMap,
    entities: list[RustEntity],
    path: str,
    method_twin_counts: Counter[tuple[str, str]],
) -> None:
    for child, mcfgs in _impl_methods_with_cfgs(impl_node):
        # Methods re-parent onto the impl ENTITY (module -> impl -> method), and the
        # method qualname builds from the cfg-AUGMENTED impl qualname (extract.rs).
        # A cfg-gated TWIN method (same final impl qualname + name, counted across
        # merged blocks) carries its own @cfg suffix (ADR-049 Amendment 5).
        name = _name(child)
        qualname = f"{impl_qualname}.{name}"
        if mcfgs and method_twin_counts[(impl_qualname, name)] > 1:
            qualname += q.cfg_discriminant(mcfgs)
        entities.append(_entity(qualname, "method", child, nmap, path, parent=impl_qualname))


def _name(node: Node) -> str:
    name = node.child_by_field_name("name")
    if name is not None and name.text is not None:
        return name.text.decode("utf-8")
    return ""


def _entity(qualname: str, kind: str, node: Node, nmap: NodeIdMap, path: str, *, parent: str | None) -> RustEntity:
    start = node.start_point
    end = node.end_point
    location = Location(
        path=path,
        line_start=start[0] + 1,
        line_end=end[0] + 1,
        col_start=start[1],
        col_end=end[1],
    )
    return RustEntity(
        qualname=qualname, kind=kind, node_id=nmap.node_id(node), location=location, node=node, parent=parent
    )
