"""Tests for wardline.scanner.fingerprint — AST fingerprint computation."""

from __future__ import annotations

import ast
import re
from typing import TYPE_CHECKING

from wardline.scanner.fingerprint import compute_ast_fingerprint

if TYPE_CHECKING:
    from pathlib import Path


class TestComputeAstFingerprint:
    def test_returns_16_char_hex(self, tmp_path: Path) -> None:
        f = tmp_path / "mod.py"
        f.write_text("def foo():\n    return 1\n", encoding="utf-8")
        result = compute_ast_fingerprint(f, "foo")
        assert result is not None
        assert len(result) == 16
        assert re.fullmatch(r"[0-9a-f]{16}", result)

    def test_deterministic(self, tmp_path: Path) -> None:
        f = tmp_path / "mod.py"
        f.write_text("def foo():\n    return 1\n", encoding="utf-8")
        assert compute_ast_fingerprint(f, "foo") == compute_ast_fingerprint(f, "foo")

    def test_whitespace_same_fingerprint(self, tmp_path: Path) -> None:
        f = tmp_path / "mod.py"
        f.write_text("def foo():\n    return 1\n", encoding="utf-8")
        fp1 = compute_ast_fingerprint(f, "foo")
        f.write_text("def foo():\n\n    return 1\n\n", encoding="utf-8")
        fp2 = compute_ast_fingerprint(f, "foo")
        assert fp1 == fp2

    def test_structural_change_different(self, tmp_path: Path) -> None:
        f = tmp_path / "mod.py"
        f.write_text("def foo():\n    return 1\n", encoding="utf-8")
        fp1 = compute_ast_fingerprint(f, "foo")
        f.write_text("def foo():\n    x = 1\n    return x\n", encoding="utf-8")
        fp2 = compute_ast_fingerprint(f, "foo")
        assert fp1 != fp2

    def test_nonexistent_file(self, tmp_path: Path) -> None:
        assert compute_ast_fingerprint(tmp_path / "nope.py", "foo") is None

    def test_nonexistent_qualname(self, tmp_path: Path) -> None:
        f = tmp_path / "mod.py"
        f.write_text("def foo():\n    pass\n", encoding="utf-8")
        assert compute_ast_fingerprint(f, "bar") is None

    def test_class_method(self, tmp_path: Path) -> None:
        f = tmp_path / "mod.py"
        f.write_text("class C:\n    def m(self):\n        pass\n", encoding="utf-8")
        result = compute_ast_fingerprint(f, "C.m")
        assert result is not None and len(result) == 16

    def test_nested_function(self, tmp_path: Path) -> None:
        f = tmp_path / "mod.py"
        f.write_text("def outer():\n    def inner():\n        pass\n", encoding="utf-8")
        assert compute_ast_fingerprint(f, "outer.inner") is not None

    def test_syntax_error(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.py"
        f.write_text("def broken(\n", encoding="utf-8")
        assert compute_ast_fingerprint(f, "broken") is None


class TestPreParsedTreeCache:
    """compute_ast_fingerprint with pre-parsed tree avoids re-parsing."""

    def test_tree_param_produces_same_result(self, tmp_path: Path) -> None:
        """Passing a pre-parsed tree gives the same fingerprint as auto-parsing."""
        f = tmp_path / "mod.py"
        source = "def foo():\n    return 1\ndef bar():\n    return 2\n"
        f.write_text(source, encoding="utf-8")

        fp_auto = compute_ast_fingerprint(f, "foo")
        tree = ast.parse(source, filename=str(f))
        fp_cached = compute_ast_fingerprint(f, "foo", tree=tree)

        assert fp_auto == fp_cached

    def test_multiple_qualnames_same_tree(self, tmp_path: Path) -> None:
        """Multiple qualnames from one tree all produce valid fingerprints."""
        f = tmp_path / "mod.py"
        source = "def foo():\n    return 1\ndef bar():\n    return 2\n"
        f.write_text(source, encoding="utf-8")

        tree = ast.parse(source, filename=str(f))
        fp_foo = compute_ast_fingerprint(f, "foo", tree=tree)
        fp_bar = compute_ast_fingerprint(f, "bar", tree=tree)

        assert fp_foo is not None
        assert fp_bar is not None
        assert fp_foo != fp_bar

    def test_tree_param_skips_file_read(self, tmp_path: Path) -> None:
        """When tree is provided, the file is never read."""
        f = tmp_path / "mod.py"
        source = "def foo():\n    return 1\n"
        f.write_text(source, encoding="utf-8")
        tree = ast.parse(source, filename=str(f))

        # Delete the file — if the function tries to read, it'll fail
        f.unlink()

        fp = compute_ast_fingerprint(f, "foo", tree=tree)
        assert fp is not None
        assert len(fp) == 16

    def test_none_tree_falls_back_to_file(self, tmp_path: Path) -> None:
        """tree=None behaves identically to no tree param."""
        f = tmp_path / "mod.py"
        f.write_text("def foo():\n    return 1\n", encoding="utf-8")

        fp_default = compute_ast_fingerprint(f, "foo")
        fp_none = compute_ast_fingerprint(f, "foo", tree=None)

        assert fp_default == fp_none

    def test_missing_qualname_with_tree(self, tmp_path: Path) -> None:
        """Unknown qualname returns None even with pre-parsed tree."""
        f = tmp_path / "mod.py"
        source = "def foo():\n    pass\n"
        f.write_text(source, encoding="utf-8")
        tree = ast.parse(source, filename=str(f))

        assert compute_ast_fingerprint(f, "no_such", tree=tree) is None
