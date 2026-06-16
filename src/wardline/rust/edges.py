"""Anchored Rust edges — ``imports`` + ``implements`` (changeset §6, Phase 1b).

The shared conformance corpus is entity-only, so the contract here is changeset
``docs/integration/2026-06-09-loomweave-rust-qualname-phase1b-changeset.md`` §6 plus
the loomweave oracle source for what §6 leaves open
(``crates/loomweave-plugin-rust/src/{resolve.rs,extract.rs}``):

* Both edge kinds are **anchored** (carry the source byte span) and therefore never
  ``inferred`` confidence (ADR-026 decision 3); both are **resolved-or-dropped** — an
  external or unresolvable target yields NO edge, never a dangling one (D1).
* ``imports``: one per module-scope ``use`` leaf. ``from_id`` is the ENCLOSING module
  entity (a file-scope ``use`` → the file module; a ``use`` inside an inline ``mod`` →
  that mod's entity; a fn-body ``use`` is not a module property and emits nothing).
  Use-tree groups fan out, ``as`` aliases resolve the REAL imported path, a ``self``
  group leaf names the prefix module (extract.rs ``collect_use_leaves``). A glob
  ``use a::*`` over an in-project module → ``ambiguous`` to that module entity, else
  dropped (resolve.rs ``resolve_use_path``). Span = the whole ``use`` statement.
* ``implements``: one per trait-impl ENTITY whose trait resolves in-project —
  merged same-key twin blocks share one impl entity and so emit exactly ONE edge
  (extract.rs ``seen_impl_ids``). Trait lookup STRIPS generic args
  (``trait_path_for_lookup``); a negative impl (``impl !Tr for Foo``) asserts
  NON-implementation and emits nothing. Span = the implemented-trait path node only.
* Resolution (resolve.rs ``resolve_non_glob``/``resolve_ids``): attempt 1 looks the
  normalized dotted path up as-is; attempt 2 (ONLY when attempt 1 found nothing AND
  the original path is a BARE single segment) retries crate-root-relative — the
  bare-segment gate is the H5 guard: a multi-segment miss (``serde::Serialize``)
  stays dropped, never re-prefixed. 0 candidates → drop; exactly 1 → ``resolved``;
  >1 (a legal value/type-namespace qualname collision) → ``ambiguous`` with ``to_id``
  = FIRST id by sorted order (deterministic, never null).
* ``crate::``/``self::``/``super::`` resolve against the module routes. Upstream 1b
  maps ``self`` to the crate root and DEFERS ``super::`` to External because it does
  not thread the defining module through (resolve.rs ``normalize_path``); wardline
  DOES thread the enclosing module (it is the imports ``from_id``), so ``self::`` is
  module-relative and ``super::`` pops module segments — the semantics that same
  oracle comment names as correct (``super::a::S`` from ``c.m.n`` means ``c.m.a.S``).
  A ``super::`` walking above the crate root drops.

WIRING NOTE: edges are deliberately NOT in the analyzer/scan output surface yet.
The identity corpus (``tests/golden/identity/rust/``) captures them by calling
``index_rust_file`` + ``discover_rust_edges`` directly; runtime/federation wiring
(emitting them over the Weft wire) is future work.

tree-sitter types appear only under ``TYPE_CHECKING`` so importing this module never
pulls the ``wardline[rust]`` extra.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from wardline.rust import qualname as q
from wardline.rust.index import RustEntity, index_entities
from wardline.rust.nodeid import mint_node_ids
from wardline.rust.parse import parse_rust

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence

    from tree_sitter import Node, Tree

__all__ = ["RustEdge", "RustParsedFile", "discover_rust_edges", "index_rust_file"]

Confidence = Literal["resolved", "ambiguous"]
_RESOLVED: Confidence = "resolved"
_AMBIGUOUS: Confidence = "ambiguous"

# tree-sitter node types that form a `use`/trait path; comments may interpose inside
# a use_list and are token-stream-invisible to the oracle (syn drops them).
_COMMENT_TYPES = frozenset({"line_comment", "block_comment"})


@dataclass(frozen=True, slots=True)
class RustEdge:
    """One anchored edge (the §6 ``RawEdge`` wire shape). ``confidence`` is only ever
    ``resolved`` or ``ambiguous`` — an anchored edge may never be ``inferred``."""

    kind: Literal["imports", "implements"]
    from_id: str
    to_id: str
    source_byte_start: int
    source_byte_end: int
    confidence: Confidence


@dataclass(frozen=True, slots=True)
class RustParsedFile:
    """One file's parse products: the tree (alive — entities' nodes point into it),
    its SP2 module route (``analyzer._module_for`` / ``rust_module_route``), and the
    entities ``index_entities`` emitted for it. Build via :func:`index_rust_file`
    (or assemble from an existing tree/entity pass — never re-parse)."""

    tree: Tree
    module: str
    entities: tuple[RustEntity, ...]


def index_rust_file(source: str, *, module: str, path: str = "") -> RustParsedFile:
    """Parse + index one file into a :class:`RustParsedFile` (ONE parse, one
    ``NodeIdMap`` — the standalone helper the identity-corpus capture calls so it
    gets the tree AND the entities without re-parsing)."""
    tree = parse_rust(source)
    entities = index_entities(tree, mint_node_ids(tree), module=module, path=path)
    return RustParsedFile(tree=tree, module=module, entities=tuple(entities))


def discover_rust_edges(files: Sequence[RustParsedFile]) -> list[RustEdge]:
    """Discover the anchored ``imports``/``implements`` edges of a whole-tree pass.

    ``files`` are the per-file parse products of the SAME scan (one entry per ``.rs``
    file, each already parsed + indexed — see :class:`RustParsedFile`). The whole-tree
    symbol table is built from the UNION of every file's entities, so cross-file
    ``use crate::…`` paths resolve against the real crate-prefixed routes. Returns
    edges per file in input order (each file's imports in source order, then its
    implements in entity order). Resolved-or-dropped throughout.
    """
    table = _symbol_table(file_entities for f in files for file_entities in f.entities)
    edges: list[RustEdge] = []
    for f in files:
        from_crate = f.module.split(".", 1)[0]
        modules_by_node = {e.node.id: e for e in f.entities if e.kind == "module"}
        file_module = modules_by_node.get(f.tree.root_node.id)
        if file_module is not None:
            _imports_in_scope(f.tree.root_node.children, file_module, from_crate, modules_by_node, table, edges)
        for entity in f.entities:
            if entity.kind == "impl":
                _implements_for(entity, f.module, from_crate, table, edges)
    return edges


# --------------------------------------------------------------------------- #
# Symbol table + resolution (mirrors resolve.rs)
# --------------------------------------------------------------------------- #


def _symbol_table(entities: Iterable[RustEntity]) -> dict[str, list[str]]:
    """qualname -> sorted entity ids (the resolver's reverse index). Two entities may
    legally share a qualname across kinds (``fn S`` / ``struct S`` — the id's kind
    segment separates them); the sorted id list is what makes the multi-kind
    Ambiguous target deterministic (resolve.rs ``resolve_ids``: first by sorted order)."""
    table: dict[str, set[str]] = {}
    for entity in entities:
        table.setdefault(entity.qualname, set()).add(q.entity_id(entity.kind, entity.qualname))
    return {qualname: sorted(ids) for qualname, ids in table.items()}


def _normalize_path(path: str, from_crate: str, enclosing_module: str) -> str | None:
    """``::``-path -> dotted qualname against the module routes, or ``None`` (drop).

    ``crate::a::B`` -> ``<crate>.a.B``; ``self::B`` -> ``<enclosing>.B``;
    ``super::X`` pops one module segment per ``super`` (above the crate root ->
    ``None``); any other leading segment is kept as-is (a real crate-qualified path
    resolves, an external one misses the table -> dropped by the caller).
    """
    segs = path.split("::")
    if segs[0] == "crate":
        return ".".join([from_crate, *segs[1:]])
    if segs[0] == "self":
        return ".".join([enclosing_module, *segs[1:]])
    if segs[0] == "super":
        supers = 0
        while supers < len(segs) and segs[supers] == "super":
            supers += 1
        module_parts = enclosing_module.split(".")
        if supers >= len(module_parts):  # walked above the crate root
            return None
        return ".".join(module_parts[: len(module_parts) - supers] + segs[supers:])
    return ".".join(segs)


def _resolve_non_glob(
    path: str,
    from_crate: str,
    enclosing_module: str,
    table: dict[str, list[str]],
    keep: Callable[[str], bool],
) -> tuple[Confidence, str] | None:
    """resolve.rs ``resolve_non_glob`` + ``resolve_ids``: attempt 1 as-is; attempt 2
    (crate-root-relative) ONLY when attempt 1's RAW candidate slice is empty AND the
    original path is a bare single segment (the H5 guard). Then 0 -> drop, 1 ->
    resolved, >1 -> ambiguous(first by sorted order)."""
    dotted = _normalize_path(path, from_crate, enclosing_module)
    if dotted is None:
        return None
    ids = table.get(dotted, [])
    if not ids and "::" not in path:
        ids = table.get(f"{from_crate}.{dotted}", [])
    matched = sorted(candidate for candidate in ids if keep(candidate))
    if not matched:
        return None
    if len(matched) == 1:
        return (_RESOLVED, matched[0])
    return (_AMBIGUOUS, matched[0])


def _resolve_use_path(
    path: str, from_crate: str, enclosing_module: str, table: dict[str, list[str]]
) -> tuple[Confidence, str] | None:
    """resolve.rs ``resolve_use_path``: a glob (``a::*``) over an in-project module ->
    ambiguous(module id), else dropped; a non-glob path -> :func:`_resolve_non_glob`
    with no kind filter."""
    if path.endswith("::*"):
        dotted = _normalize_path(path[: -len("::*")], from_crate, enclosing_module)
        if dotted is None:
            return None
        module_id = next(
            (candidate for candidate in table.get(dotted, []) if candidate.startswith("rust:module:")),
            None,
        )
        return (_AMBIGUOUS, module_id) if module_id is not None else None
    return _resolve_non_glob(path, from_crate, enclosing_module, table, lambda _candidate: True)


# --------------------------------------------------------------------------- #
# imports — module-scope use statements (mirrors extract.rs emit_use_edges)
# --------------------------------------------------------------------------- #


def _imports_in_scope(
    children: Iterable[Node],
    module_entity: RustEntity,
    from_crate: str,
    modules_by_node: dict[int, RustEntity],
    table: dict[str, list[str]],
    edges: list[RustEdge],
) -> None:
    """Walk ONE module scope's item list: emit an edge per resolving use leaf, recurse
    into inline-mod bodies under THAT mod's entity. Only module scopes are walked —
    a use inside a fn/impl body is not a module property and emits nothing."""
    from_id = q.entity_id("module", module_entity.qualname)
    for child in children:
        if child.type == "use_declaration":
            argument = child.child_by_field_name("argument")
            if argument is None:
                continue
            leaves: list[str] = []
            _collect_use_leaves(argument, "", leaves)
            for leaf in leaves:
                resolution = _resolve_use_path(leaf, from_crate, module_entity.qualname, table)
                if resolution is None:
                    continue  # external / unresolvable — dropped, never dangling
                confidence, to_id = resolution
                # Span = the whole `use` statement (extract.rs source_range_of(it)).
                edges.append(RustEdge("imports", from_id, to_id, child.start_byte, child.end_byte, confidence))
        elif child.type == "mod_item":
            body = child.child_by_field_name("body")
            nested = modules_by_node.get(child.id)
            if body is None or nested is None:  # `mod foo;` external decl / no entity
                continue
            _imports_in_scope(body.children, nested, from_crate, modules_by_node, table, edges)


def _collect_use_leaves(node: Node, prefix: str, out: list[str]) -> None:
    """Flatten a use tree into ``::``-joined leaf paths (extract.rs
    ``collect_use_leaves``): a Group fans out per branch under the shared prefix; a
    Rename (``a::B as C``) contributes the REAL path ``a::B`` (alias dropped); a
    Glob terminates a ``<prefix>::*`` leaf; a ``self`` group leaf terminates the
    prefix path UNCHANGED (it names the enclosing module — appending the literal
    segment would miss the table and silently drop the module edge)."""

    def joined(seg: str) -> str:
        return f"{prefix}::{seg}" if prefix else seg

    t = node.type
    if t == "use_list":
        for item in node.named_children:
            if item.type not in _COMMENT_TYPES:
                _collect_use_leaves(item, prefix, out)
    elif t == "scoped_use_list":
        path = node.child_by_field_name("path")
        inner = node.child_by_field_name("list")
        if inner is not None:
            new_prefix = joined("::".join(_path_segments(path))) if path is not None else prefix
            _collect_use_leaves(inner, new_prefix, out)
    elif t == "use_as_clause":
        path = node.child_by_field_name("path")
        if path is not None:
            out.append(joined("::".join(_path_segments(path))))
    elif t == "use_wildcard":
        path = next((c for c in node.named_children if c.type not in _COMMENT_TYPES), None)
        glob_prefix = joined("::".join(_path_segments(path))) if path is not None else prefix
        out.append(f"{glob_prefix}::*" if glob_prefix else "*")
    elif t == "self":
        if prefix:  # a bare `use self;` carries an empty prefix and contributes nothing
            out.append(prefix)
    else:  # identifier / scoped_identifier / crate / super — a plain path leaf
        out.append(joined("::".join(_path_segments(node))))


def _path_segments(node: Node) -> list[str]:
    """A (possibly scoped) path node -> its ``::`` segments, leading
    ``crate``/``self``/``super`` kept verbatim for ``_normalize_path`` to map."""
    if node.type in ("scoped_identifier", "scoped_type_identifier"):
        path = node.child_by_field_name("path")
        name = node.child_by_field_name("name")
        segments = _path_segments(path) if path is not None else []
        if name is not None:
            segments.append(_text(name))
        return segments
    return [_text(node)]


# --------------------------------------------------------------------------- #
# implements — one per trait-impl entity (mirrors extract.rs emit_impl)
# --------------------------------------------------------------------------- #


def _implements_for(
    entity: RustEntity,
    file_module: str,
    from_crate: str,
    table: dict[str, list[str]],
    edges: list[RustEdge],
) -> None:
    """Emit at most one ``implements`` edge for an ``impl`` ENTITY. The index already
    merged same-key twin blocks to one entity (anchored at the FIRST block), so
    per-entity emission IS the one-edge-per-impl rule (extract.rs ``seen_impl_ids``)."""
    impl_node = entity.node
    trait_node = impl_node.child_by_field_name("trait")
    if trait_node is None:  # inherent impl — nothing to implement
        return
    # A negative impl (`impl !Tr for Foo`) asserts NON-implementation: no edge
    # (extract.rs bang guard). The `!` is a direct child between `impl` and the trait.
    if any(child.type == "!" for child in impl_node.children):
        return
    lookup = "::".join(_trait_path_segments(trait_node))
    if not lookup:
        return
    # `self::`/`super::` in the trait path resolve against the impl's OWN enclosing
    # module (its parent qualname — the module the index parented it to).
    resolution = _resolve_non_glob(
        lookup,
        from_crate,
        entity.parent or file_module,
        table,
        lambda candidate: candidate.startswith("rust:trait:"),
    )
    if resolution is None:
        return  # external trait — dropped at emit
    confidence, to_id = resolution
    # Span = the implemented-trait path node ONLY (extract.rs source_range_of(trait_path)),
    # generic args included (`MyTrait<i32>`) — never the whole impl block.
    edges.append(
        RustEdge(
            "implements",
            q.entity_id("impl", entity.qualname),
            to_id,
            trait_node.start_byte,
            trait_node.end_byte,
            confidence,
        )
    )


def _trait_path_segments(trait_node: Node) -> list[str]:
    """The implemented-trait path's segments with generic args STRIPPED (extract.rs
    ``trait_path_for_lookup``: the resolver keys on the trait's bare-ident qualname,
    so ``impl MyTrait<i32> for Foo`` MUST look up ``MyTrait``)."""
    if trait_node.type == "generic_type":
        base = trait_node.child_by_field_name("type")
        return _path_segments(base) if base is not None else []
    return _path_segments(trait_node)


def _text(node: Node) -> str:
    return node.text.decode("utf-8") if node.text is not None else ""
