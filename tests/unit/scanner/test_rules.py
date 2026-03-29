"""Tests for RuleBase — override guard, ABC enforcement, dispatch."""

from __future__ import annotations

import ast
import textwrap

import pytest

from wardline.core.severity import RuleId
from wardline.scanner.rules.base import RuleBase

# ── Valid subclass for testing dispatch ───────────────────────────


class _ValidRule(RuleBase):
    """A valid concrete rule for test dispatch."""

    RULE_ID: RuleId = RuleId.TEST_STUB

    def __init__(self) -> None:
        super().__init__()
        self.visited: list[tuple[str, bool]] = []

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        self.visited.append((node.name, is_async))


# ── Override Guard ────────────────────────────────────────────────


class TestOverrideGuard:
    """__init_subclass__ prevents overriding visit_FunctionDef."""

    def test_override_visit_function_def_raises(self) -> None:
        with pytest.raises(TypeError, match="must not override"):

            class BadRule(RuleBase):  # type: ignore[misc]
                def visit_FunctionDef(  # type: ignore[override]
                    self, node: ast.FunctionDef
                ) -> None:
                    pass

                def visit_function(
                    self,
                    node: ast.FunctionDef | ast.AsyncFunctionDef,
                    *,
                    is_async: bool,
                ) -> None:
                    pass

    def test_override_visit_async_function_def_raises(self) -> None:
        with pytest.raises(TypeError, match="must not override"):

            class BadAsyncRule(RuleBase):  # type: ignore[misc]
                def visit_AsyncFunctionDef(  # type: ignore[override]
                    self, node: ast.AsyncFunctionDef
                ) -> None:
                    pass

                def visit_function(
                    self,
                    node: ast.FunctionDef | ast.AsyncFunctionDef,
                    *,
                    is_async: bool,
                ) -> None:
                    pass

    def test_error_is_from_init_subclass_not_typing_final(self) -> None:
        """@typing.final is static-only — the runtime TypeError
        comes from __init_subclass__, not from @typing.final."""
        try:

            class CheckSource(RuleBase):  # type: ignore[misc]
                def visit_FunctionDef(  # type: ignore[override]
                    self, node: ast.FunctionDef
                ) -> None:
                    pass

                def visit_function(
                    self,
                    node: ast.FunctionDef | ast.AsyncFunctionDef,
                    *,
                    is_async: bool,
                ) -> None:
                    pass

        except TypeError as e:
            # Our message, not typing.final's
            assert "must not override" in str(e)
            assert "visit_function() instead" in str(e)
        else:
            pytest.fail("Expected TypeError from __init_subclass__")


# ── ABC Enforcement ───────────────────────────────────────────────


class TestAbcEnforcement:
    """Missing visit_function raises TypeError at instantiation."""

    def test_missing_visit_function_raises_at_instantiation(self) -> None:
        # Definition succeeds — ABC enforcement is lazy
        class IncompleteRule(RuleBase):
            pass

        # Instantiation fails
        with pytest.raises(TypeError, match="visit_function"):
            IncompleteRule()  # type: ignore[abstract]

    def test_complete_rule_instantiates(self) -> None:
        rule = _ValidRule()
        assert rule.visited == []

    def test_missing_rule_id_raises_at_definition(self) -> None:
        with pytest.raises(TypeError, match="must define a RULE_ID"):

            class NoIdRule(RuleBase):
                def visit_function(
                    self,
                    node: ast.FunctionDef | ast.AsyncFunctionDef,
                    *,
                    is_async: bool,
                ) -> None:
                    pass


# ── Dispatch ──────────────────────────────────────────────────────


class TestDispatch:
    """visit_FunctionDef/visit_AsyncFunctionDef dispatch correctly."""

    def test_sync_function_dispatch(self) -> None:
        source = textwrap.dedent("""\
            def handler():
                pass
        """)
        tree = ast.parse(source)
        rule = _ValidRule()
        rule.visit(tree)
        assert ("handler", False) in rule.visited

    def test_async_function_dispatch(self) -> None:
        source = textwrap.dedent("""\
            async def async_handler():
                pass
        """)
        tree = ast.parse(source)
        rule = _ValidRule()
        rule.visit(tree)
        assert ("async_handler", True) in rule.visited

    def test_both_sync_and_async(self) -> None:
        source = textwrap.dedent("""\
            def sync_fn():
                pass

            async def async_fn():
                pass
        """)
        tree = ast.parse(source)
        rule = _ValidRule()
        rule.visit(tree)
        assert len(rule.visited) == 2
        names = {name for name, _ in rule.visited}
        assert names == {"sync_fn", "async_fn"}

    def test_nested_functions_visited(self) -> None:
        source = textwrap.dedent("""\
            def outer():
                def inner():
                    pass
        """)
        tree = ast.parse(source)
        rule = _ValidRule()
        rule.visit(tree)
        names = {name for name, _ in rule.visited}
        assert names == {"outer", "inner"}

    def test_method_in_class_visited(self) -> None:
        source = textwrap.dedent("""\
            class MyClass:
                def method(self):
                    pass

                async def async_method(self):
                    pass
        """)
        tree = ast.parse(source)
        rule = _ValidRule()
        rule.visit(tree)
        assert len(rule.visited) == 2
        assert ("method", False) in rule.visited
        assert ("async_method", True) in rule.visited


# ── except* syntax ──────────────────────────────────────────


class TestExceptStar:
    """except* syntax parses and rules visit the enclosing function."""

    def test_except_star_parseable(self) -> None:
        """except* syntax parses correctly."""
        source = textwrap.dedent("""\
            def handler():
                try:
                    pass
                except* ValueError:
                    pass
        """)
        tree = ast.parse(source)
        rule = _ValidRule()
        rule.visit(tree)
        assert ("handler", False) in rule.visited


# ── Super Ordering ────────────────────────────────────────────────


class TestSuperOrdering:
    """__init_subclass__ calls super() before the check."""

    def test_cooperative_mro_works(self) -> None:
        """A mixin with __init_subclass__ cooperates with RuleBase."""

        class TrackingMixin:
            _tracked: bool = False

            def __init_subclass__(cls, **kwargs: object) -> None:
                super().__init_subclass__(**kwargs)
                cls._tracked = True

        class TrackedRule(TrackingMixin, RuleBase):
            RULE_ID = RuleId.TEST_STUB

            def visit_function(
                self,
                node: ast.FunctionDef | ast.AsyncFunctionDef,
                *,
                is_async: bool,
            ) -> None:
                pass

        assert TrackedRule._tracked is True
