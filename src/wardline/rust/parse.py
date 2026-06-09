"""Parse Rust source into a tree-sitter CST (lazy-guarded, zero base dep).

A thin seam over ``require_rust()`` so the rest of the frontend takes ``str``/``bytes``
and gets back a ``Tree`` without each call site re-deriving the parser. tree-sitter
types appear only under ``TYPE_CHECKING`` so importing this module never pulls the
``wardline[rust]`` extra.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from wardline.rust._tree_sitter import require_rust

if TYPE_CHECKING:
    from tree_sitter import Tree

__all__ = ["has_errors", "parse_rust"]


def parse_rust(source: str | bytes) -> Tree:
    """Parse Rust ``source`` (str is UTF-8 encoded) into a tree-sitter ``Tree``."""
    _, parser = require_rust()
    data = source.encode("utf-8") if isinstance(source, str) else source
    return parser.parse(data)


def has_errors(tree: Tree) -> bool:
    """True if tree-sitter recovered from a syntax error anywhere in the parse.

    tree-sitter never fails to produce a tree: it wraps unparseable regions in ``ERROR``
    nodes (or drops loose tokens), so the item walk silently skips them and a malformed
    ``.rs`` yields zero or PARTIAL entities — a false all-clear. A scan must consult this
    and surface a diagnostic rather than report a clean result over a half-parsed file.
    """
    return tree.root_node.has_error
