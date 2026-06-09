"""WP2: parse-error detection — the no-silent-under-scan signal.

tree-sitter always returns a tree; a malformed ``.rs`` produces ERROR nodes and the
item walk silently skips them, so ``discover_rust_entities`` under-emits without raising.
``has_errors`` is the signal a scan must consult to surface a diagnostic instead of a
false all-clear. (Emitting that diagnostic as a finding is WP6's done-criterion — here
we pin that the signal is available and that the silent under-scan is real.)
"""

from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter", reason="wardline[rust] extra not installed")

from wardline.rust.index import discover_rust_entities  # noqa: E402
from wardline.rust.parse import has_errors, parse_rust  # noqa: E402

_TRUNCATED = 'fn handler(req: Request) {\n    let x = req.param("cmd")\n    Command::new("sh").arg(x).output();\n'


def test_has_errors_false_on_well_formed_source() -> None:
    assert has_errors(parse_rust("fn main() { let x = 1; }\n")) is False


def test_has_errors_true_on_truncated_source() -> None:
    assert has_errors(parse_rust(_TRUNCATED)) is True


def test_malformed_source_under_emits_so_has_errors_is_the_required_guard() -> None:
    # The whole point: the truncated fn has a real signature but the broken body makes
    # the parse recover into ERROR/loose tokens, so the function entity is dropped — a
    # silent under-scan. has_errors is what lets the scan layer refuse the false clean.
    tree = parse_rust(_TRUNCATED)
    entities = discover_rust_entities(_TRUNCATED, module="demo.m")
    assert has_errors(tree) is True
    # 'handler' is silently lost to the recovery — proving the under-scan the guard exists for.
    assert not any(e.qualname == "demo.m.handler" for e in entities)
