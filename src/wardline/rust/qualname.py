"""The Rust qualname dialect — Loomweave ADR-049 (Wardline is the *second producer*).

Wardline MINTS the same locator string Loomweave's whole-tree ``syn`` extractor emits;
it never parses Loomweave's locator. The vendored corpus
(``tests/conformance/qualnames_rust.json``) is the byte-for-byte oracle. ``:`` is the
reserved separator and ``[ ] # < > @ $`` are legal segments of the dialect.

KNOWN GAP (path-typed generic args): a trait OR self-type concrete generic arg that is itself
a ``::``-path renders a segment containing ``:`` — both in the trait fragment
(``impl From<std::io::Error>`` -> ``...impl[From<std::io::Error>].from``) and, since the
self-type-args amendment (ADR-049 §2), in the self-type prefix (``impl Foo<std::io::Error>``
-> ``...Foo<std::io::Error>.impl#<>...``). Loomweave renders the BYTE-IDENTICAL segment (its
``trait_generic_args`` / ``self_ty_locator`` keep ``::`` via ``strip_ws`` — the cfg-only
``escape_reserved`` does NOT cover generic args), then REJECTS the assembled locator at
``entity_id`` construction (``validate_no_colon``) and degrades the whole file. Wardline is
faithful in *rendering* but lacks that validate-and-degrade gate, so it currently emits a
``:``-bearing locator. The correct fix is an ADR-049 amendment defining a colon-free canonical
form for path-typed generic args, adopted by both producers in lockstep — a Wardline-only
normalization would itself diverge from the (still-unreleased) oracle. Low slice-1 blast radius
(RS-WL-* findings are ``provisional_identity`` and Wardline emits no federation entity yet).
Tracked: see the ``rust-bug-hunt-2026-06-09`` reserved-colon issue.

KNOWN GAP (const-generic-arg spacing): a multi-token *const* generic arg (``Foo<{N + 1}>``,
``Foo<-1>``) is rendered by the oracle via ``to_token_stream().to_string()`` — proc-macro2
CANONICAL spacing (``{ N + 1 }``), NOT whitespace-stripped — whereas Wardline ``_strip_ws``-es
every arg (``{N+1}``). Same impossibility class as the reserved-colon gap: matching would mean
reimplementing proc-macro2 token spacing, so the right fix is a lockstep ADR-049 amendment
(cleanest: the oracle ``strip_ws``-es const args too). Out-of-corpus, Tier-B; plain const args
(``Foo<3>``, ``Foo<i32>``, a bare const-param ident) already match byte-for-byte.

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
    "cfg_discriminant",
    "cfg_predicate_of",
    "impl_type_param_names",
    "normalize_cfg_predicate",
    "render_positional_generics",
    "render_self_type",
    "render_trait_segment",
    "rust_module_route",
]

_ROOT_STEMS = frozenset({"lib", "main", "mod"})


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
    """Canonicalise a ``cfg(...)`` predicate, mirroring loomweave ``qualname.rs``
    ``normalise_pred`` BYTE-FOR-BYTE (the @cfg discriminant is a parity surface).

    ``text`` is the RAW argument token-tree text, with or without its outer parens
    (``"(unix)"`` / ``"unix"`` / ``"(any(windows, unix))"``); the outer cfg-argument
    parens (if present) are stripped to the bare predicate, then — in the oracle's
    exact order: all whitespace removed; every reserved entity-id char escaped
    (``_escape_reserved``: ``%`` -> ``%25`` first, then ``:`` -> ``%3A`` — injective,
    so ``feature="a:b"`` and a literal source ``feature="a%3Ab"`` stay distinct); and
    a single top-level ``any(...)``/``all(...)`` wrapper's args sorted by a **naive**
    ``split(',')`` (NOT paren-aware — this is exactly the oracle's algorithm; deeper
    nesting is left as the deterministic stripped string, even though that mangles,
    because the contract is byte-equality with the oracle, not a "nicer" canonical
    form). The escape runs on the whole stripped predicate BEFORE the any()/all()
    split, exactly as in ``normalise_pred``.
    """
    stripped = "".join(text.split())
    if stripped.startswith("(") and stripped.endswith(")"):
        stripped = stripped[1:-1]
    stripped = _escape_reserved(stripped)
    for fn in ("any", "all"):
        prefix = fn + "("
        if stripped.startswith(prefix) and stripped.endswith(")"):
            inner = stripped[len(prefix) : -1]
            parts = sorted(inner.split(","))  # naive split — matches the oracle verbatim
            return f"{fn}({','.join(parts)})"
    return stripped


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
    bare-path COLLISION, exactly like the oracle's extract.rs twin counter."""
    return f"@cfg({'&'.join(sorted(normalize_cfg_predicate(p) for p in predicates))})"


def cfg_predicate_of(attribute_item: Node) -> str | None:
    """The RAW cfg predicate text of an ``attribute_item`` node (outer argument parens
    included, source spacing intact — e.g. ``#[cfg(feature = "a")]`` ->
    ``'(feature = "a")'``), or ``None`` if it is not a ``#[cfg(...)]`` attribute.

    Deliberately UN-normalised, mirroring extract.rs ``cfg_predicates`` (raw token
    text): collection is raw, and ``cfg_discriminant`` is the single place predicates
    are normalised + reserved-char-escaped — normalising here too would double-escape
    (``a:b`` -> ``a%253Ab``).
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
    return args.text.decode("utf-8")


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

    The bare last path segment (``Foo`` in ``crate::m::Foo``) plus its surviving generic
    args in ``<...>`` — comma-joined, ``<>`` omitted ENTIRELY when none survive. An arg
    that is exactly one of the impl's OWN declared params (``type_params``) renders
    positionally (``$N``, rename-stable: ``impl<T> Foo<T>`` -> ``Foo<$0>``); a CONCRETE
    arg (``i32``, ``Vec<u8>``, ``&T``) renders literally whitespace-free. Substitution is
    TOP-LEVEL only — a param NESTED in another arg (``Foo<Vec<T>>`` -> ``Foo<Vec<T>>``,
    NOT ``Foo<Vec<$0>>``) keeps its literal text (F2 nested-param rule; a nested-param
    corpus row is owed by Loomweave, so the unit guard in test_qualname.py is the only
    check against accidental recursive substitution). Lifetimes/bindings dropped; a
    non-generic self type renders the bare name; an exotic self type (tuple/array) renders
    whitespace-free (out-of-corpus, Tier-B)."""
    if type_node.type == "generic_type":
        base_node = type_node.child_by_field_name("type")
        base = _last_path_segment(base_node) if base_node is not None else ""
        targs = type_node.child_by_field_name("type_arguments")
        if targs is None:
            return base
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
        return f"{base}<{','.join(rendered)}>" if rendered else base
    if type_node.type in ("type_identifier", "scoped_type_identifier"):
        return _last_path_segment(type_node)
    return _strip_ws(type_node)


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
    return _strip_ws(arg_node)


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
        targs = trait_node.child_by_field_name("type_arguments")
        args = (
            # Drop dropped-kinds AND empty-rendering args (a malformed `From<>` error-recovers
            # to a blank arg; valid Rust never yields one) -> bare trait name, no empty `<>`.
            [s for c in targs.named_children if c.type not in _DROPPED_GENERIC_ARGS if (s := _strip_ws(c))]
            if targs is not None
            else []
        )
        return f"{trait_name}<{','.join(args)}>" if args else trait_name
    return _last_path_segment(trait_node)


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
