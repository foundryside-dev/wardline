"""The Rust qualname dialect — Loomweave ADR-049 (Wardline is the *second producer*).

Wardline MINTS the same locator string Loomweave's whole-tree ``syn`` extractor emits;
it never parses Loomweave's locator. The vendored corpus
(``tests/conformance/qualnames_rust.json``) is the byte-for-byte oracle. Reserved char
is ``:`` (invalid); ``[ ] # < > @ $`` are legal segments of the dialect.

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
    """Canonicalise a ``cfg(...)`` predicate: strip all whitespace, sort ``any()/all()``
    args (ADR-049 §cfg_twins). ``text`` is the argument token-tree text, e.g. ``"(unix)"``
    or ``"(any(windows, unix))"``; the surrounding parens are stripped.
    """
    stripped = "".join(text.split())
    if stripped.startswith("(") and stripped.endswith(")"):
        stripped = stripped[1:-1]
    return _sort_cfg(stripped)


def _sort_cfg(expr: str) -> str:
    for fn in ("any", "all"):
        prefix = fn + "("
        if expr.startswith(prefix) and expr.endswith(")"):
            inner = expr[len(prefix) : -1]
            args = sorted(_sort_cfg(arg) for arg in _split_top_level(inner))
            return f"{fn}(" + ",".join(args) + ")"
    return expr


def _split_top_level(expr: str) -> list[str]:
    """Split on top-level commas (not those nested inside parentheses)."""
    parts: list[str] = []
    depth = 0
    start = 0
    for i, ch in enumerate(expr):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(expr[start:i])
            start = i + 1
    parts.append(expr[start:])
    return [p for p in parts if p]


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


def render_self_type(type_node: Node) -> str:
    """The base name of an impl's self type, generics stripped: ``Foo<T>`` -> ``Foo``."""
    if type_node.type == "generic_type":
        base = type_node.child_by_field_name("type")
        if base is not None:
            return _last_path_segment(base)
    return _last_path_segment(type_node)


def render_trait_segment(trait_node: Node) -> str:
    """The trait discriminator for a trait impl: last path segment + concrete generic
    args, lifetimes dropped. ``std::fmt::Display`` -> ``Display``; ``From<i32>`` ->
    ``From<i32>`` (concrete args are part of the key).
    """
    if trait_node.type == "generic_type":
        base = trait_node.child_by_field_name("type")
        base_name = _last_path_segment(base) if base is not None else ""
        targs = trait_node.child_by_field_name("type_arguments")
        args = [_text(c) for c in targs.named_children if c.type != "lifetime"] if targs is not None else []
        return base_name + "<" + ",".join(args) + ">"
    return _last_path_segment(trait_node)


def _text(node: Node) -> str:
    return node.text.decode("utf-8") if node.text is not None else ""


def _last_path_segment(node: Node) -> str:
    """The final identifier of a (possibly scoped) type path: ``a::b::Foo`` -> ``Foo``."""
    if node.type == "scoped_type_identifier":
        name = node.child_by_field_name("name")
        if name is not None:
            return _text(name)
    return _text(node)


def render_positional_generics(impl_node: Node) -> str:
    """The impl's generic params rendered positionally (De Bruijn): ``impl<T>`` -> ``$0``,
    ``impl`` -> ``""``. Type and const params count positionally; lifetimes are dropped.
    """
    tp = impl_node.child_by_field_name("type_parameters")
    if tp is None:
        return ""
    count = sum(1 for c in tp.named_children if c.type in ("type_parameter", "const_parameter"))
    return ",".join(f"${i}" for i in range(count))
