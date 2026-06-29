"""Lazy loader for the tree-sitter Rust toolchain (the ``wardline[rust]`` extra).

Keeping the ``tree_sitter`` import inside ``require_rust`` — not at module top —
is what lets the rest of ``wardline.rust`` be imported for type-checking and
wiring without the extra installed, exactly like ``loomweave.require_blake3``.
``RustToolingError`` is re-exported here (its canonical home is the error
hierarchy in ``wardline.core.errors``) so callers import the loader and its
failure mode from one place.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from wardline.core.errors import RustToolingError

if TYPE_CHECKING:
    from tree_sitter import Language, Parser

__all__ = ["RustToolingError", "require_rust"]


def require_rust() -> tuple[Language, Parser]:
    """Return a ``(Language, Parser)`` pair ready to parse ``.rs`` bytes.

    A fresh ``Parser`` is returned on each call so no parser state leaks between
    callers; the grammar ``Language`` is cheap to re-wrap. Raises
    ``RustToolingError`` with an install hint if the extra is not present.
    """
    try:
        from tree_sitter import Language, Parser
        from tree_sitter_rust import language as _rust_language
    except ModuleNotFoundError as exc:
        from wardline.core.optional_deps import extra_install_hint

        raise RustToolingError(
            f"the Rust frontend needs tree-sitter — install with {extra_install_hint('rust')}"
        ) from exc
    grammar = Language(_rust_language())
    return grammar, Parser(grammar)
