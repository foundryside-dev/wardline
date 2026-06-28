"""The Rust qualname dialect — Loomweave ADR-049 (Wardline is the *second producer*).

Wardline MINTS the same locator string Loomweave's whole-tree ``syn`` extractor emits;
it never parses Loomweave's locator. The vendored corpus
(``tests/conformance/qualnames_rust.json``) is the byte-for-byte oracle. ``:`` is the
reserved separator and ``[ ] # < > @ $`` are legal segments of the dialect.

ADR-049 AMENDMENT 4 (2026-06-11, implemented): every CONCRETE generic arg — type or const,
in both the trait fragment and the self-type prefix — renders through
``escape_reserved(strip_ws(arg))``: whitespace-stripped first (the oracle now strips const
args too, closing the proc-macro2-spacing gap), then the injective reserved-char escape
(``%`` -> ``%25``, then ``:`` -> ``%3A``). ``impl From<std::io::Error> for Foo`` ->
``Foo.impl[From<std%3A%3Aio%3A%3AError>]``; ``impl Foo<{ 1 + 2 }>`` -> ``Foo<{1+2}>.impl#<>``.
The same escape covers the NON-``Type::Path`` self-type fallback (reference/tuple/slice/ptr:
``impl Serializer for &mut fmt::Formatter`` -> ``&mutfmt%3A%3AFormatter``). The escape happens
in the producer BEFORE the id is assembled — ``entity_id``'s ``:`` rejection stays strict.
Corpus rows: ``path_typed_generic_arg_trait``/``_inherent``, ``const_generic_arg_spacing``,
``reference_self_type_path_escape``.

ADR-049 AMENDMENTS 6+7 (2026-06-11, implemented): the residual-collision LADDER for impl
qualnames — ``@cfg -> stage S (self-type written path) -> stage T (trait written path) ->
method-@cfg`` — lives in ``index._walk_scope``; this module supplies the witness/render
primitives. ``written_path_of`` is the qself-free Type::Path detector (segment idents
joined ``::``, a leading ``::`` preserved, generic args ignored); ``self_type_witness``
is the stage-S witness (escaped written path, or the Amendment-4 textual render for a
qself-bearing/non-path self type); ``trait_written_path`` + ``render_trait_segment_qualified``
are the stage-T witness and fired-group rendering (escaped written trait path, final
segment keeping the existing generic-args rendering — a single-segment path renders
byte-identically to the bare fragment). All witnesses are SINGLE-FILE computable: written
paths as-typed, no name resolution (the second-producer constraint).

ADR-049 AMENDMENT 8 (2026-06-11, implemented): ``rust_module_route`` stays the
PURE-FILESYSTEM route by design — ``#[path]``-aware routing is the SEPARATE entry point
``mounts.MountOverlay.logical_module_path`` (mount overlay first, this route as the
default), pinned by the corpus ``module_mounts`` section. Amendment 9 (``const _``
skip-emission) lives in ``index._walk_scope``.

This module holds the pure string/CST-node renderers; ``index.py`` walks the tree and
assembles full qualnames from them. tree-sitter types appear only under ``TYPE_CHECKING``
so importing this module never pulls the ``wardline[rust]`` extra.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from tree_sitter import Node

__all__ = [
    "RUST_ONTOLOGY_VERSION",
    "RUST_PLUGIN_ID",
    "cfg_discriminant",
    "cfg_predicate_of",
    "entity_id",
    "impl_type_param_names",
    "normalize_cfg_predicate",
    "render_positional_generics",
    "render_self_type",
    "render_self_type_parts",
    "render_trait_segment",
    "render_trait_segment_qualified",
    "rust_module_route",
    "self_type_witness",
    "trait_written_path",
    "written_path_of",
]

_ROOT_STEMS = frozenset({"lib", "main", "mod"})

# The ADR-049 producer identity (mirrors loomweave plugin.toml: `plugin_id = "rust"`,
# `ontology_version = "0.4.0"`) — Wardline mints the SAME entity ids as the oracle.
RUST_PLUGIN_ID = "rust"
RUST_ONTOLOGY_VERSION = "0.4.0"

# The ten ADR-049 id-kinds (plugin.toml `entity_kinds`). Wardline's semantic `method`
# is NOT an id-kind — `entity_id` maps it to `function` itself.
_ID_KINDS = frozenset(
    {"module", "struct", "function", "enum", "trait", "type_alias", "const", "static", "macro", "impl"}
)


def entity_id(kind: str, qualname: str) -> str:
    """The federation entity id ``{plugin}:{kind}:{qualname}`` for an emitted entity.

    Wardline's semantic ``method`` maps to the id-kind ``function`` HERE (callers pass
    ``RustEntity.kind`` verbatim, never pre-mapping); any kind outside the ten-kind
    ADR-049 set raises ``ValueError`` — mirroring loomweave's ``build_entity_id``
    validation posture (reject, never silently coin a new kind).
    """
    if kind == "method":
        kind = "function"
    if kind not in _ID_KINDS:
        msg = f"unknown Rust entity kind {kind!r} (not in the ADR-049 ten-kind set)"
        raise ValueError(msg)
    return f"{RUST_PLUGIN_ID}:{kind}:{qualname}"


def rust_module_route(*, crate: str, src_root: str, file: str) -> str:
    """Route a source ``file`` to its dotted module path (ADR-049 §module_route).

    ``lib.rs``/``main.rs``/``mod.rs`` contribute no segment; every other ``.rs`` file
    contributes its stem; directories nest. The crate name is the root segment.
    ``#[path]`` is NOT honoured (a known SP2 gap — routing is purely by file path).
    """
    from pathlib import PurePosixPath

    rel = PurePosixPath(file).relative_to(PurePosixPath(src_root))
    segments = list(rel.parts)
    # drop the ".rs" stem of the file; a root stem contributes nothing
    last = PurePosixPath(segments[-1]).stem if segments else ""
    segments = segments[:-1] + ([] if last in _ROOT_STEMS else [last])
    return ".".join([crate, *segments])


def normalize_cfg_predicate(text: str) -> str:
    """Canonicalise a ``cfg(...)`` predicate for a stable ``@cfg`` discriminant.

    ``text`` is the RAW argument token-tree text, with or without its outer parens
    (``"(unix)"`` / ``"unix"`` / ``"(any(windows, unix))"``); the outer cfg-argument
    parens (if present) are stripped to the bare predicate and all whitespace is
    removed. Top-level ``any(...)``/``all(...)`` predicates recursively normalise and
    sort their arguments using only top-level commas, so nested predicates cannot
    collide by being split apart. Leaf predicates escape reserved entity-id chars
    (``_escape_reserved``: ``%`` -> ``%25`` first, then ``:`` -> ``%3A`` — injective,
    so ``feature="a:b"`` and a literal source ``feature="a%3Ab"`` stay distinct).
    """
    return _normalize_cfg_predicate(text, depth=0)


_MAX_CFG_NORMALIZE_DEPTH = 128


def _normalize_cfg_predicate(text: str, *, depth: int) -> str:
    stripped = "".join(text.split())
    stripped = _strip_wrapping_parens(stripped)
    if depth >= _MAX_CFG_NORMALIZE_DEPTH:
        return _escape_reserved(stripped)
    for fn in ("any", "all"):
        inner = _call_inner(stripped, fn)
        if inner is not None:
            split = _split_top_level_commas(inner)
            if split is None:
                return _escape_reserved(stripped)
            parts = sorted(_normalize_cfg_predicate(part, depth=depth + 1) for part in split)
            return f"{fn}({','.join(parts)})"
    return _escape_reserved(stripped)


def _strip_wrapping_parens(text: str) -> str:
    if not (text.startswith("(") and text.endswith(")")):
        return text
    if _matching_rparen(text, 0) != len(text) - 1:
        return text
    return text[1:-1]


def _call_inner(text: str, fn: str) -> str | None:
    prefix = fn + "("
    if not text.startswith(prefix):
        return None
    open_index = len(fn)
    if _matching_rparen(text, open_index) != len(text) - 1:
        return None
    return text[len(prefix) : -1]


def _matching_rparen(text: str, open_index: int) -> int | None:
    depth = 0
    in_string = False
    escaped = False
    for index, char in enumerate(text[open_index:], start=open_index):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
            if depth < 0:
                return None
    return None


def _split_top_level_commas(text: str) -> list[str] | None:
    parts: list[str] = []
    start = 0
    depth = 0
    in_string = False
    escaped = False
    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                return None
        elif char == "," and depth == 0:
            parts.append(text[start:index])
            start = index + 1
    if in_string or depth != 0:
        return None
    parts.append(text[start:])
    return parts


def _escape_reserved(s: str) -> str:
    """Escape every reserved entity-id char so a cfg predicate can never inject the
    reserved ``:`` separator into a qualname (mirrors qualname.rs ``escape_reserved``).
    Order matters for injectivity: the ``%`` introducer is encoded FIRST."""
    return s.replace("%", "%25").replace(":", "%3A")


def cfg_discriminant(predicates: Sequence[str]) -> str:
    """Fold ALL of an item's RAW ``#[cfg(...)]`` predicates into the stable ``@cfg(...)``
    discriminant suffix (mirrors qualname.rs ``cfg_discriminant`` BYTE-FOR-BYTE): each
    predicate normalised+escaped exactly once (``normalize_cfg_predicate``), the set
    sorted (order-independent — NOT source order), joined with ``&``. Folding every
    predicate is what keeps stacked cfg-twins (``#[cfg(feature="a")] #[cfg(unix)]`` vs
    ``#[cfg(feature="b")] #[cfg(unix)]``) distinct. Applied by ``index.py`` only on a
    bare-path COLLISION, exactly like the oracle's extract.rs twin counter.

    Raises ``ValueError`` on an empty input: ``@cfg()`` is never a meaningful
    discriminant (the oracle's ``cfg_suffix`` guards the empty case BEFORE calling
    ``cfg_discriminant``), and rendering it would silently collide every
    "discriminated" twin onto one key — a caller bug, surfaced loudly."""
    if not predicates:
        msg = "cfg_discriminant() requires at least one raw #[cfg] predicate"
        raise ValueError(msg)
    return f"@cfg({'&'.join(sorted(normalize_cfg_predicate(p) for p in predicates))})"


def cfg_predicate_of(attribute_item: Node) -> str | None:
    """The RAW cfg predicate text of an ``attribute_item`` node (outer argument parens
    included, source spacing intact — e.g. ``#[cfg(feature = "a")]`` ->
    ``'(feature = "a")'``), or ``None`` if it is not a ``#[cfg(...)]`` attribute.

    Deliberately UN-normalised, mirroring extract.rs ``cfg_predicates`` (raw token
    text): collection is raw, and ``cfg_discriminant`` is the single place predicates
    are normalised + reserved-char-escaped — normalising here too would double-escape
    (``a:b`` -> ``a%253Ab``).

    The ONE exception to "raw source span": comment nodes inside the predicate
    (``#[cfg(any(unix, /* why */ windows))]``) are excised — the oracle's predicate
    is ``list.tokens.to_string()`` and proc-macro2 token streams carry no comments,
    so comment bytes were never part of the oracle's raw text either (corpus row
    ``cfg_predicate_internal_comment``). Everything else (parens, spacing, unescaped
    reserved chars) is kept verbatim.
    """
    if not attribute_item.named_children:
        return None
    attribute = attribute_item.named_children[0]
    if attribute.type != "attribute" or not attribute.named_children:
        return None
    path = attribute.named_children[0]
    if path.text != b"cfg":
        return None
    args = attribute.child_by_field_name("arguments")
    if args is None or args.text is None:
        return None
    return _text_excluding_comments(args)


# tree-sitter comment node types — `///` doc comments parse as line_comment too.
_COMMENT_TYPES = frozenset({"line_comment", "block_comment"})


def _text_excluding_comments(node: Node) -> str:
    """``node``'s raw source text with every comment node's byte span excised
    (the comment's SURROUNDING whitespace survives — ``normalize_cfg_predicate``
    strips all whitespace downstream, so only the comment bytes themselves matter)."""
    raw = node.text or b""
    base = node.start_byte
    spans: list[tuple[int, int]] = []
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type in _COMMENT_TYPES:
            spans.append((current.start_byte - base, current.end_byte - base))
            continue
        stack.extend(current.children)
    if not spans:
        return raw.decode("utf-8")
    spans.sort()
    kept = bytearray()
    pos = 0
    for start, end in spans:
        kept += raw[pos:start]
        pos = end
    kept += raw[pos:]
    return kept.decode("utf-8")


# Generic args that are NOT part of the locator key (qualname.rs trait_generic_args /
# self_ty_locator keep only GenericArgument::Type / ::Const): lifetimes and assoc-type
# bindings. Shared by the trait fragment and the self-type prefix.
_DROPPED_GENERIC_ARGS = frozenset({"lifetime", "type_binding"})


def impl_type_param_names(impl_node: Node) -> list[str]:
    """The impl's declared generic TYPE-parameter names in source (De Bruijn) order:
    ``impl<T, U> Foo`` -> ``["T", "U"]`` (mirrors qualname.rs ``declared_type_params`` =
    syn ``generics.type_params()``). Lifetimes and const params are excluded — only the
    positions used by the inherent ``#<...>`` signature AND by the self-type prefix to
    recognise which self-type args are the impl's OWN params (rendered positionally)."""
    tp = impl_node.child_by_field_name("type_parameters")
    if tp is None:
        return []
    names: list[str] = []
    for child in tp.named_children:
        if child.type == "type_parameter":
            name = child.child_by_field_name("name")
            # A blank name only arises from error recovery (`impl<>`); syn yields no such
            # param, so skipping it keeps the De Bruijn count true to the oracle.
            if name is not None and (text := _text(name)):
                names.append(text)
    return names


def render_self_type(type_node: Node, type_params: Sequence[str]) -> str:
    """The locator-relevant name of an impl's self type INCLUDING its concrete generic
    args (mirrors qualname.rs ``self_ty_locator``, ADR-049 §2 self-type-args amendment).

    ``base + args`` of ``render_self_type_parts`` — see there for the full rule."""
    base, args = render_self_type_parts(type_node, type_params)
    return base + args


def render_self_type_parts(type_node: Node, type_params: Sequence[str]) -> tuple[str, str]:
    """``(base, args)`` decomposition of the self-type render — the Amendment-6 ladder
    re-renders the BASE alone (stage S) while the ``<...>`` args suffix is stage-invariant.

    The base is the bare last path segment (``Foo`` in ``crate::m::Foo``); ``args`` is the
    surviving generic args in ``<...>`` — comma-joined, ``""`` when none survive. An arg
    that is exactly one of the impl's OWN declared params (``type_params``) renders
    positionally (``$N``, rename-stable: ``impl<T> Foo<T>`` -> ``Foo<$0>``); a CONCRETE
    arg (``i32``, ``Vec<u8>``, ``&T``) renders literally whitespace-free. Substitution is
    TOP-LEVEL only — a param NESTED in another arg (``Foo<Vec<T>>`` -> ``Foo<Vec<T>>``,
    NOT ``Foo<Vec<$0>>``) keeps its literal text (F2 nested-param rule; a nested-param
    corpus row is owed by Loomweave, so the unit guard in test_qualname.py is the only
    check against accidental recursive substitution). Lifetimes/bindings dropped; a
    non-generic self type renders the bare name. A non-``Type::Path`` OR qself-bearing
    self type (``&mut fmt::Formatter``, ``<A as B>::C`` — ``written_path_of`` is None)
    renders the Amendment-4 textual fallback as the base, args empty (Amendment 6 pins
    qself with the fallback: the witness/render must not double-escape)."""
    if type_node.type == "generic_type":
        base_node = type_node.child_by_field_name("type")
        if base_node is None or written_path_of(base_node) is None:
            # qself-bearing generic path (`<A as B>::C<T>`): whole-node A4 fallback.
            return _escape_reserved(_strip_ws(type_node)), ""
        base = _last_path_segment(base_node)
        targs = type_node.child_by_field_name("type_arguments")
        if targs is None:
            return base, ""
        # Drop dropped-kinds AND any arg that renders empty: a malformed empty turbofish
        # `Foo<>` error-recovers to a blank `type_identifier` (valid Rust never yields one,
        # so this never touches a real arg). Keeps the pure producer from emitting `Foo<>`;
        # the scan path gates such input on has_errors() before it reaches here anyway.
        rendered = [
            r
            for c in targs.named_children
            if c.type not in _DROPPED_GENERIC_ARGS
            if (r := _self_type_arg(c, type_params))
        ]
        return (base, f"<{','.join(rendered)}>") if rendered else (base, "")
    if type_node.type in ("type_identifier", "scoped_type_identifier") and written_path_of(type_node) is not None:
        return _last_path_segment(type_node), ""
    # Non-Type::Path fallback (reference/tuple/slice/raw-pointer self types): may carry a
    # ``::``-path (`&mut fmt::Formatter`), so it escapes like a concrete generic arg
    # (ADR-049 Amendment 4 self-type-fallback completion). A `:`-free fallback is unchanged.
    return _escape_reserved(_strip_ws(type_node)), ""


def written_path_of(node: Node) -> str | None:
    """The WRITTEN path of a qself-free Type::Path node — segment idents joined ``::``,
    a leading ``::`` contributing a leading separator (``impl Tr for ::a::X`` and
    ``impl Tr for a::X`` carry distinct witnesses), generic args never included — or
    ``None`` for a non-path / qself-bearing node (``<A as B>::C`` routes its
    ``bracketed_type`` head here and falls out). Mirrors the Amendment-6 witness rule:
    as-written, single-file, no name resolution."""
    if node.type in ("type_identifier", "identifier", "crate", "super", "self", "metavariable"):
        return _text(node)
    if node.type in ("scoped_type_identifier", "scoped_identifier"):
        name = node.child_by_field_name("name")
        if name is None:
            return None
        path = node.child_by_field_name("path")
        if path is None:
            # `::X` — a leading-:: anchor with no prefix path before the separator.
            return f"::{_text(name)}" if any(c.type == "::" for c in node.children) else _text(name)
        prefix = written_path_of(path)
        return None if prefix is None else f"{prefix}::{_text(name)}"
    return None


def self_type_witness(type_node: Node) -> tuple[str, bool]:
    """The stage-S witness of an impl's self type (ADR-049 Amendment 6) as
    ``(witness, is_path)``.

    For a qself-free ``Type::Path`` (a ``generic_type`` contributes its base — args are
    already normalized and MUST NOT affect the witness): ``escape_reserved`` over the
    written path, ``is_path=True`` — a fired group re-renders this member's base to the
    witness verbatim. Otherwise the Amendment-4 textual render (already escaped) with
    ``is_path=False`` — the member participates in distinctness but its rendering is
    never touched (re-applying the escape would double-escape)."""
    base = type_node.child_by_field_name("type") if type_node.type == "generic_type" else type_node
    written = written_path_of(base) if base is not None else None
    if written is not None:
        return _escape_reserved(written), True
    return _escape_reserved(_strip_ws(type_node)), False


def trait_written_path(trait_node: Node) -> str | None:
    """The stage-T witness (ADR-049 Amendment 7): the trait path AS WRITTEN — segment
    idents joined ``::``, leading ``::`` preserved, generic args ignored — or ``None``
    for a non-path trait node (out-of-corpus; such a member never drives a fire)."""
    base = trait_node.child_by_field_name("type") if trait_node.type == "generic_type" else trait_node
    return written_path_of(base) if base is not None else None


def _self_type_arg(arg_node: Node, type_params: Sequence[str]) -> str:
    """One self-type generic arg (mirrors qualname.rs ``self_ty_arg``): a bare
    ``type_identifier`` matching one of the impl's declared params -> its positional ``$N``
    token (rename-stable); anything else (concrete type, nested generic, reference, scoped
    path) -> a literal whitespace-free rendering. NOT recursive — only a top-level bare
    param substitutes."""
    if arg_node.type == "type_identifier":
        name = _text(arg_node)
        if name in type_params:
            return f"${type_params.index(name)}"
    return _escape_reserved(_strip_ws(arg_node))


def render_trait_segment(trait_node: Node) -> str:
    """The trait discriminator (mirrors qualname.rs ``trait_impl`` + ``trait_generic_args``):
    the trait path's last segment, plus its concrete type/const generic args — lifetimes
    AND associated-type bindings dropped, each arg whitespace-stripped — with the
    ``<...>`` omitted ENTIRELY when no args survive. ``std::fmt::Display`` -> ``Display``;
    ``From<i32>`` -> ``From<i32>``; ``Iterator<Item=u8>`` -> ``Iterator`` (binding dropped);
    ``Trait<'a>`` -> ``Trait`` (lifetime dropped, no empty brackets)."""
    if trait_node.type == "generic_type":
        base = trait_node.child_by_field_name("type")
        trait_name = _last_path_segment(base) if base is not None else ""
        args = _trait_generic_args(trait_node)
        return f"{trait_name}<{','.join(args)}>" if args else trait_name
    return _last_path_segment(trait_node)


def render_trait_segment_qualified(trait_node: Node) -> str:
    """The Amendment-7 FIRED-group trait fragment: ``escape_reserved`` over the
    ``::``-joined written trait path (leading ``::`` -> leading ``%3A%3A``), the final
    segment keeping the existing ``trait_generic_args`` rendering. A single-segment
    written path renders byte-identically to ``render_trait_segment``. Applied to EVERY
    member of a fired post-S group — never outside one (the corpus-pinned bare fragment
    is untouched for un-fired groups)."""
    written = trait_written_path(trait_node)
    if written is None:  # non-path trait node (out-of-corpus): bare rendering, defensively
        return render_trait_segment(trait_node)
    qualified = _escape_reserved(written)
    args = _trait_generic_args(trait_node) if trait_node.type == "generic_type" else []
    return f"{qualified}<{','.join(args)}>" if args else qualified


def _trait_generic_args(trait_node: Node) -> list[str]:
    """The surviving (concrete type/const) generic args of a ``generic_type`` trait node,
    each whitespace-stripped + escaped. Drops dropped-kinds AND empty-rendering args (a
    malformed ``From<>`` error-recovers to a blank arg; valid Rust never yields one)."""
    targs = trait_node.child_by_field_name("type_arguments")
    if targs is None:
        return []
    return [
        _escape_reserved(s) for c in targs.named_children if c.type not in _DROPPED_GENERIC_ARGS if (s := _strip_ws(c))
    ]


def render_positional_generics(impl_node: Node) -> str:
    """The impl's TYPE params rendered positionally (De Bruijn): ``impl<T>`` -> ``$0``;
    ``impl`` / ``impl<'a>`` / ``impl<const N: usize>`` -> ``""``. Only ``type_parameter``s
    count (mirrors syn ``generics.type_params()``); lifetime and const params do not. Keyed
    on the SAME name list as the self-type prefix (``impl_type_param_names``) so positions
    agree between ``Foo<$0>`` and ``impl#<$0>``."""
    count = len(impl_type_param_names(impl_node))
    return ",".join(f"${i}" for i in range(count))


def _text(node: Node) -> str:
    return node.text.decode("utf-8") if node.text is not None else ""


def _strip_ws(node: Node) -> str:
    """A whitespace-free textual rendering of a node's source text (mirrors qualname.rs
    ``strip_ws`` = ``to_token_stream().to_string()`` with all whitespace removed —
    removing whitespace from the source span converges to the same string for paths/types,
    where the only inter-token difference is spacing)."""
    return "".join(_text(node).split())


def _last_path_segment(node: Node) -> str:
    """The final identifier of a (possibly scoped) type path: ``a::b::Foo`` -> ``Foo``."""
    if node.type == "scoped_type_identifier":
        name = node.child_by_field_name("name")
        if name is not None:
            return _text(name)
    return _text(node)
