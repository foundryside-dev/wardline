"""The Rust qualname dialect — Loomweave ADR-049 (Wardline is the *second producer*).

Wardline MINTS the same locator string Loomweave's whole-tree ``syn`` extractor emits;
it never parses Loomweave's locator. The vendored corpus
(``tests/conformance/qualnames_rust.json``) is the byte-for-byte oracle. ``:`` is the
reserved separator and ``[ ] # < > @ $`` are legal segments of the dialect.

KNOWN GAP (path-typed generic args): a trait/self-type concrete generic arg that is itself
a ``::``-path — e.g. ``impl From<std::io::Error>`` — renders a segment containing ``:``
(``...impl[From<std::io::Error>].from``). Loomweave renders the BYTE-IDENTICAL segment (its
``trait_generic_args`` keeps ``::`` via ``strip_ws``), then REJECTS the assembled locator at
``entity_id`` construction (``validate_no_colon``) and degrades the whole file. Wardline is
faithful in *rendering* but lacks that validate-and-degrade gate, so it currently emits a
``:``-bearing locator. The correct fix is an ADR-049 amendment defining a colon-free canonical
form for path-typed generic args, adopted by both producers in lockstep — a Wardline-only
normalization would itself diverge from the (still-unreleased) oracle. Low slice-1 blast radius
(RS-WL-* findings are ``provisional_identity`` and Wardline emits no federation entity yet).
Tracked: see the ``rust-bug-hunt-2026-06-09`` reserved-colon issue.

This module holds the pure string/CST-node renderers; ``index.py`` walks the tree and
assembles full qualnames from them. tree-sitter types appear only under ``TYPE_CHECKING``
so importing this module never pulls the ``wardline[rust]`` extra.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tree_sitter import Node

__all__ = [
    "cfg_predicate_of",
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

    ``text`` is the argument token-tree text incl. its parens, e.g. ``"(unix)"`` or
    ``"(any(windows, unix))"``; the outer cfg-argument parens are stripped to the bare
    predicate, then: all whitespace removed, and a single top-level ``any(...)``/
    ``all(...)`` wrapper's args sorted by a **naive** ``split(',')`` (NOT paren-aware —
    this is exactly the oracle's algorithm; deeper nesting is left as the deterministic
    stripped string, even though that mangles, because the contract is byte-equality
    with the oracle, not a "nicer" canonical form).
    """
    stripped = "".join(text.split())
    if stripped.startswith("(") and stripped.endswith(")"):
        stripped = stripped[1:-1]
    for fn in ("any", "all"):
        prefix = fn + "("
        if stripped.startswith(prefix) and stripped.endswith(")"):
            inner = stripped[len(prefix) : -1]
            parts = sorted(inner.split(","))  # naive split — matches the oracle verbatim
            return f"{fn}({','.join(parts)})"
    return stripped


def cfg_predicate_of(attribute_item: Node) -> str | None:
    """The normalised cfg predicate of an ``attribute_item`` node, or ``None`` if it is
    not a ``#[cfg(...)]`` attribute. e.g. ``#[cfg(unix)]`` -> ``"unix"``.
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
    return normalize_cfg_predicate(args.text.decode("utf-8"))


# Trait generic args that are NOT part of the locator key (qualname.rs trait_generic_args
# keeps only GenericArgument::Type / ::Const): lifetimes and associated-type bindings.
_DROPPED_TRAIT_ARGS = frozenset({"lifetime", "type_binding"})


def render_self_type(type_node: Node) -> str:
    """The locator-relevant name of an impl's self type (mirrors qualname.rs
    ``self_ty_name``): the last path segment for a path type (``Foo`` in ``crate::m::Foo``
    and in ``Foo<T>``), else a whitespace-free textual rendering for an exotic self type
    (tuple/reference/array — out-of-corpus, Tier-B)."""
    if type_node.type == "generic_type":
        base = type_node.child_by_field_name("type")
        if base is not None:
            return _last_path_segment(base)
    if type_node.type in ("type_identifier", "scoped_type_identifier"):
        return _last_path_segment(type_node)
    return _strip_ws(type_node)


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
            [_strip_ws(c) for c in targs.named_children if c.type not in _DROPPED_TRAIT_ARGS]
            if targs is not None
            else []
        )
        return f"{trait_name}<{','.join(args)}>" if args else trait_name
    return _last_path_segment(trait_node)


def render_positional_generics(impl_node: Node) -> str:
    """The impl's TYPE params rendered positionally (De Bruijn): ``impl<T>`` -> ``$0``;
    ``impl`` / ``impl<'a>`` / ``impl<const N: usize>`` -> ``""``. Only ``type_parameter``s
    count (mirrors syn ``generics.type_params()``); lifetime and const params do not."""
    tp = impl_node.child_by_field_name("type_parameters")
    if tp is None:
        return ""
    count = sum(1 for c in tp.named_children if c.type == "type_parameter")
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
