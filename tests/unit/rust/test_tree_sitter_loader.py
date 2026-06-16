"""WP0: the lazy tree-sitter loader (the ``wardline[rust]`` extra).

``pytest.importorskip`` is the FIRST executable statement so that, under an
interpreter WITHOUT the extra, this module skips cleanly *before* importing
``wardline.rust`` — that is the empirical proof of Verification §6 (run this dir
under the extra-free venv and it skips, never ImportErrors).
"""

from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter", reason="wardline[rust] extra not installed")

from tree_sitter import Language, Parser  # noqa: E402  (after importorskip by design)

from wardline.core.errors import WardlineError  # noqa: E402
from wardline.rust._tree_sitter import RustToolingError, require_rust  # noqa: E402


def test_require_rust_returns_usable_language_and_parser() -> None:
    language, parser = require_rust()
    assert isinstance(language, Language)
    assert isinstance(parser, Parser)


def test_require_rust_round_trips_rust_source() -> None:
    _, parser = require_rust()
    tree = parser.parse(b"fn main(){}")
    assert tree.root_node.type == "source_file"
    # confirm it is the *Rust* grammar, not some other language
    assert any(child.type == "function_item" for child in tree.root_node.named_children)


def test_require_rust_returns_a_fresh_parser_each_call() -> None:
    # No shared parser state leaks between callers.
    _, p1 = require_rust()
    _, p2 = require_rust()
    assert p1 is not p2


def test_rust_tooling_error_is_a_wardline_error() -> None:
    # The lazy guard raises an actionable error inside the Wardline hierarchy.
    assert issubclass(RustToolingError, WardlineError)
