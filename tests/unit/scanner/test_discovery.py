"""Tests for decorator discovery — import table, TYPE_CHECKING, annotations."""

from __future__ import annotations

import ast
import logging
import textwrap
from typing import TYPE_CHECKING

from wardline.scanner.discovery import (
    _build_import_table,
    _collect_type_checking_lines,
    _detect_dynamic_imports,
    _is_type_checking_test,
    _resolve_decorator,
    discover_annotations,
)

if TYPE_CHECKING:
    import pytest


def _parse(source: str) -> ast.Module:
    """Parse dedented source into an AST module."""
    return ast.parse(textwrap.dedent(source))


# ── TYPE_CHECKING block detection ────────────────────────────────


class TestTypeCheckingDetection:
    """Phase 1: identify lines inside ``if TYPE_CHECKING:`` blocks."""

    def test_direct_type_checking_import(self) -> None:
        tree = _parse("""\
            from typing import TYPE_CHECKING
            if TYPE_CHECKING:
                from wardline import external_boundary
            def foo(): pass
        """)
        tc_lines = _collect_type_checking_lines(tree)

        # The import inside the if block should be in tc_lines
        # Line 3 is the from-import inside the if block
        assert len(tc_lines) > 0
        # Line 4 (def foo) should NOT be in tc_lines
        # Find the FunctionDef node's line number
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "foo":
                assert node.lineno not in tc_lines

    def test_qualified_type_checking_import(self) -> None:
        tree = _parse("""\
            import typing
            if typing.TYPE_CHECKING:
                from wardline import external_boundary
            def bar(): pass
        """)
        tc_lines = _collect_type_checking_lines(tree)

        assert len(tc_lines) > 0
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "bar":
                assert node.lineno not in tc_lines

    def test_no_type_checking_block(self) -> None:
        tree = _parse("""\
            from wardline import external_boundary
            def foo(): pass
        """)
        tc_lines = _collect_type_checking_lines(tree)
        assert len(tc_lines) == 0

    def test_normal_if_not_detected(self) -> None:
        """An ``if`` block that isn't TYPE_CHECKING should not be filtered."""
        tree = _parse("""\
            DEBUG = True
            if DEBUG:
                from wardline import external_boundary
            def foo(): pass
        """)
        tc_lines = _collect_type_checking_lines(tree)
        assert len(tc_lines) == 0

    def test_arbitrary_alias_type_checking_not_detected(self) -> None:
        tree = _parse("""\
            import custom_typing
            if custom_typing.TYPE_CHECKING:
                from wardline import external_boundary
        """)
        if_node = next(node for node in ast.walk(tree) if isinstance(node, ast.If))
        assert not _is_type_checking_test(if_node.test)


# ── Import table construction ────────────────────────────────────


class TestImportTable:
    """Phase 2: build local name → canonical name mapping."""

    def test_direct_from_import(self) -> None:
        """``from wardline import external_boundary``"""
        tree = _parse("""\
            from wardline import external_boundary
        """)
        table = _build_import_table(tree, frozenset())

        assert table["external_boundary"] == "external_boundary"

    def test_submodule_from_import(self) -> None:
        """``from wardline.decorators.authority import external_boundary``"""
        tree = _parse("""\
            from wardline.decorators.authority import external_boundary
        """)
        table = _build_import_table(tree, frozenset())

        assert table["external_boundary"] == "external_boundary"

    def test_qualified_import(self) -> None:
        """``import wardline`` registers as qualified source."""
        tree = _parse("""\
            import wardline
        """)
        table = _build_import_table(tree, frozenset())

        assert "__qualified__:wardline" in table

    def test_non_wardline_import_ignored(self) -> None:
        """Non-wardline imports are not in the table."""
        tree = _parse("""\
            from os.path import join
            import json
        """)
        table = _build_import_table(tree, frozenset())

        assert len(table) == 0

    def test_unknown_wardline_name_ignored(self) -> None:
        """Importing a name from wardline that's not in the registry."""
        tree = _parse("""\
            from wardline import some_unknown_thing
        """)
        table = _build_import_table(tree, frozenset())

        assert "some_unknown_thing" not in table

    def test_type_checking_import_excluded(self) -> None:
        """Imports inside TYPE_CHECKING blocks are filtered out."""
        tree = _parse("""\
            from typing import TYPE_CHECKING
            if TYPE_CHECKING:
                from wardline import external_boundary
            from wardline import validates_shape
        """)
        tc_lines = _collect_type_checking_lines(tree)
        table = _build_import_table(tree, tc_lines)

        assert "external_boundary" not in table
        assert table["validates_shape"] == "validates_shape"

    def test_qualified_type_checking_excluded(self) -> None:
        """Qualified TYPE_CHECKING block excludes imports."""
        tree = _parse("""\
            import typing
            if typing.TYPE_CHECKING:
                from wardline import external_boundary
            from wardline import integrity_critical
        """)
        tc_lines = _collect_type_checking_lines(tree)
        table = _build_import_table(tree, tc_lines)

        assert "external_boundary" not in table
        assert table["integrity_critical"] == "integrity_critical"

    def test_tc_lines_argument_does_not_affect_top_level_imports(self) -> None:
        """Top-level import scanning does not depend on tc_lines filtering."""
        tree = _parse("""\
            from wardline import external_boundary
        """)
        table = _build_import_table(tree, frozenset({1}))
        assert table["external_boundary"] == "external_boundary"

    def test_multiple_decorators_imported(self) -> None:
        """Multiple decorators from one import statement."""
        tree = _parse("""\
            from wardline import external_boundary, validates_shape
        """)
        table = _build_import_table(tree, frozenset())

        assert table["external_boundary"] == "external_boundary"
        assert table["validates_shape"] == "validates_shape"


# ── Annotation map (end-to-end discovery) ────────────────────────


class TestDiscoverAnnotations:
    """Phase 3: full discovery pipeline — imports → decorators → annotations."""

    def test_direct_import_decorator(self) -> None:
        """``from wardline import X`` + ``@X`` on a function."""
        tree = _parse("""\
            from wardline import external_boundary
            @external_boundary
            def handler(): pass
        """)
        result = discover_annotations(tree, "test.py")

        key = ("test.py", "handler")
        assert key in result
        annotations = result[key]
        assert len(annotations) == 1
        ann = next(iter(annotations))
        assert ann.canonical_name == "external_boundary"
        assert ann.group == 1

    def test_submodule_import_decorator(self) -> None:
        """``from wardline.decorators.authority import X`` + ``@X``."""
        tree = _parse("""\
            from wardline.decorators.authority import validates_shape
            @validates_shape
            def validate(): pass
        """)
        result = discover_annotations(tree, "test.py")

        key = ("test.py", "validate")
        assert key in result
        ann = next(iter(result[key]))
        assert ann.canonical_name == "validates_shape"

    def test_qualified_import_decorator(self) -> None:
        """``import wardline`` + ``@wardline.external_boundary``."""
        tree = _parse("""\
            import wardline
            @wardline.external_boundary
            def handler(): pass
        """)
        result = discover_annotations(tree, "test.py")

        key = ("test.py", "handler")
        assert key in result
        ann = next(iter(result[key]))
        assert ann.canonical_name == "external_boundary"

    def test_type_checking_import_not_discovered(self) -> None:
        """Decorators imported under TYPE_CHECKING are invisible."""
        tree = _parse("""\
            from typing import TYPE_CHECKING
            if TYPE_CHECKING:
                from wardline import external_boundary
            @external_boundary
            def handler(): pass
        """)
        result = discover_annotations(tree, "test.py")

        # external_boundary is not in the import table, so
        # the decorator is not resolved
        assert ("test.py", "handler") not in result

    def test_qualified_type_checking_not_discovered(self) -> None:
        """Qualified TYPE_CHECKING import also invisible."""
        tree = _parse("""\
            import typing
            if typing.TYPE_CHECKING:
                from wardline import external_boundary
            @external_boundary
            def handler(): pass
        """)
        result = discover_annotations(tree, "test.py")

        assert ("test.py", "handler") not in result

    def test_undecorated_function_not_in_map(self) -> None:
        """Functions without wardline decorators don't appear."""
        tree = _parse("""\
            from wardline import external_boundary
            def plain(): pass
        """)
        result = discover_annotations(tree, "test.py")

        assert ("test.py", "plain") not in result

    def test_async_function_discovered(self) -> None:
        """Async functions are discovered the same as sync."""
        tree = _parse("""\
            from wardline import external_boundary
            @external_boundary
            async def handler(): pass
        """)
        result = discover_annotations(tree, "test.py")

        key = ("test.py", "handler")
        assert key in result

    def test_method_in_class(self) -> None:
        """Decorated method gets qualname with class prefix."""
        tree = _parse("""\
            from wardline import external_boundary
            class MyService:
                @external_boundary
                def handle(self): pass
        """)
        result = discover_annotations(tree, "svc.py")

        key = ("svc.py", "MyService.handle")
        assert key in result

    def test_multiple_decorators_on_one_function(self) -> None:
        """Function with two wardline decorators gets both annotations."""
        tree = _parse("""\
            from wardline import external_boundary, integrity_critical
            @external_boundary
            @integrity_critical
            def critical_handler(): pass
        """)
        result = discover_annotations(tree, "test.py")

        key = ("test.py", "critical_handler")
        assert key in result
        names = {a.canonical_name for a in result[key]}  # noqa: C401
        assert names == {"external_boundary", "integrity_critical"}

    def test_non_wardline_decorator_ignored(self) -> None:
        """Non-wardline decorators don't pollute the annotation map."""
        tree = _parse("""\
            from wardline import external_boundary
            from functools import lru_cache
            @lru_cache
            @external_boundary
            def cached_handler(): pass
        """)
        result = discover_annotations(tree, "test.py")

        key = ("test.py", "cached_handler")
        assert key in result
        # Only the wardline decorator should be in annotations
        assert len(result[key]) == 1
        ann = next(iter(result[key]))
        assert ann.canonical_name == "external_boundary"

    def test_decorator_with_call_syntax(self) -> None:
        """``@external_boundary()`` (with parens) is resolved."""
        tree = _parse("""\
            from wardline import external_boundary
            @external_boundary()
            def handler(): pass
        """)
        result = discover_annotations(tree, "test.py")

        key = ("test.py", "handler")
        assert key in result
        ann = next(iter(result[key]))
        assert ann.canonical_name == "external_boundary"

    def test_called_decorator_resolves_from_submodule_import(self) -> None:
        """Parameterized decorators still resolve from direct submodule imports."""
        tree = _parse("""\
            from wardline.decorators.lifecycle import feature_gated
            @feature_gated(flag="beta")
            def handler(): pass
        """)
        result = discover_annotations(tree, "test.py")

        key = ("test.py", "handler")
        assert key in result
        ann = next(iter(result[key]))
        assert ann.canonical_name == "feature_gated"

    def test_called_decorator_alias_resolves(self) -> None:
        """Aliased parameterized decorators resolve to their canonical name."""
        tree = _parse("""\
            from wardline.decorators.operations import compensatable as comp
            @comp(rollback=rollback_fn)
            def handler(): pass
        """)
        result = discover_annotations(tree, "test.py")

        key = ("test.py", "handler")
        assert key in result
        ann = next(iter(result[key]))
        assert ann.canonical_name == "compensatable"

    def test_empty_file(self) -> None:
        """Empty file produces empty annotation map."""
        tree = _parse("")
        result = discover_annotations(tree, "empty.py")

        assert result == {}

    def test_alias_import_resolves(self) -> None:
        """``from wardline import external_boundary as eb`` → ``eb`` resolves."""
        tree = _parse("""\
            from wardline import external_boundary as eb
            @eb
            def handler(): pass
        """)
        result = discover_annotations(tree, "test.py")

        key = ("test.py", "handler")
        assert key in result
        ann = next(iter(result[key]))
        assert ann.canonical_name == "external_boundary"

    def test_nested_function_decorator_discovered(self) -> None:
        """Decorators on nested functions are discovered with correct qualname."""
        tree = _parse("""\
            from wardline import external_boundary, validates_shape
            @external_boundary
            def outer():
                @validates_shape
                def inner(): pass
        """)
        result = discover_annotations(tree, "test.py")

        assert ("test.py", "outer") in result
        assert result[("test.py", "outer")][0].canonical_name == "external_boundary"

        assert ("test.py", "outer.inner") in result
        assert result[("test.py", "outer.inner")][0].canonical_name == "validates_shape"


# ── Edge cases: warnings ─────────────────────────────────────────


class TestEdgeCaseWarnings:
    """Edge case handling: star imports, dynamic imports, unresolved decorators."""

    def test_star_import_warns(self, caplog: pytest.LogCaptureFixture) -> None:
        """``from wardline import *`` logs a WARNING."""
        tree = _parse("""\
            from wardline import *
        """)
        with caplog.at_level(logging.WARNING, logger="wardline.scanner.discovery"):
            _build_import_table(tree, frozenset())

        assert any("Star import" in r.message for r in caplog.records)

    def test_star_import_non_wardline_no_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """``from os import *`` does NOT log a warning."""
        tree = _parse("""\
            from os import *
        """)
        with caplog.at_level(logging.WARNING, logger="wardline.scanner.discovery"):
            _build_import_table(tree, frozenset())

        assert not any("Star import" in r.message for r in caplog.records)

    def test_dynamic_import_importlib_returns_diagnostic(self) -> None:
        """``importlib.import_module("wardline")`` returns a diagnostic."""
        tree = _parse("""\
            import importlib
            mod = importlib.import_module("wardline")
        """)
        diagnostics = _detect_dynamic_imports(tree)

        assert len(diagnostics) == 1
        assert "importlib.import_module" in diagnostics[0].message

    def test_dynamic_import_dunder_returns_diagnostic(self) -> None:
        """``__import__("wardline")`` returns a diagnostic."""
        tree = _parse("""\
            mod = __import__("wardline")
        """)
        diagnostics = _detect_dynamic_imports(tree)

        assert len(diagnostics) == 1
        assert "__import__" in diagnostics[0].message

    def test_dynamic_import_non_wardline_returns_no_diagnostic(self) -> None:
        """Dynamic import of non-wardline module produces no diagnostic."""
        tree = _parse("""\
            import importlib
            mod = importlib.import_module("json")
            other = __import__("os")
        """)
        diagnostics = _detect_dynamic_imports(tree)

        assert diagnostics == []

    def test_unresolved_decorator_with_star_import_warns(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Decorator that looks wardline-related but can't be resolved warns."""
        tree = _parse("""\
            from wardline import *
            @external_boundary
            def handler(): pass
        """)
        with caplog.at_level(logging.WARNING, logger="wardline.scanner.discovery"):
            discover_annotations(tree, "test.py")

        warning_msgs = [r.message for r in caplog.records]
        # Should have the star import warning
        assert any("Star import" in m for m in warning_msgs)
        # Should have the unresolved decorator warning
        assert any("cannot be reliably resolved" in m for m in warning_msgs)


# ── Recursion depth limit ────────────────────────────────────────


class TestResolveDecoratorDepthLimit:
    """_resolve_decorator must not recurse unboundedly."""

    def test_deep_call_chain_returns_none(self) -> None:
        """A Call chain deeper than max_depth returns None instead of recursing."""
        # Build a deeply nested ast.Call chain: f()()()...()
        inner: ast.expr = ast.Name(id="external_boundary", ctx=ast.Load())
        for _ in range(60):
            inner = ast.Call(func=inner, args=[], keywords=[])

        import_table = {"external_boundary": "external_boundary"}
        # With default max_depth=50, this should return None (not recurse endlessly)
        result = _resolve_decorator(inner, import_table)
        assert result is None

    def test_shallow_call_chain_resolves(self) -> None:
        """A shallow Call chain within max_depth resolves normally."""
        inner: ast.expr = ast.Name(id="external_boundary", ctx=ast.Load())
        for _ in range(3):
            inner = ast.Call(func=inner, args=[], keywords=[])

        import_table = {"external_boundary": "external_boundary"}
        result = _resolve_decorator(inner, import_table)
        assert result == "external_boundary"


# ── Keyword arg extraction via discovery ─────────────────────────


class TestRestorationBoundaryKeywordExtraction:
    """Verify _extract_decorator_attrs extracts all keyword args from
    @restoration_boundary(...) through the full discovery pipeline."""

    def test_restoration_boundary_keyword_args_extracted(self) -> None:
        """All 5 keyword args on @restoration_boundary are captured in attrs."""
        tree = _parse("""\
            from wardline import restoration_boundary
            @restoration_boundary(
                restored_tier=1,
                structural_evidence=True,
                semantic_evidence=True,
                integrity_evidence="hmac",
                institutional_provenance="org-db",
            )
            def restore_record(): pass
        """)
        result = discover_annotations(tree, "test.py")

        key = ("test.py", "restore_record")
        assert key in result
        annotations = result[key]
        assert len(annotations) == 1
        ann = annotations[0]
        assert ann.canonical_name == "restoration_boundary"
        assert ann.group == 17
        assert ann.attrs["restored_tier"] == 1
        assert ann.attrs["structural_evidence"] is True
        assert ann.attrs["semantic_evidence"] is True
        assert ann.attrs["integrity_evidence"] == "hmac"
        assert ann.attrs["institutional_provenance"] == "org-db"
