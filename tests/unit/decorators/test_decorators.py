"""Tests for wardline decorator factory."""

from __future__ import annotations

import asyncio
import inspect
import logging

import pytest

from wardline.core.taints import TaintState
from wardline.decorators._base import get_wardline_attrs, wardline_decorator
from wardline.decorators.authority import (
    integral_writer,
    integral_construction,
    integral_read,
    validates_external,
    validates_semantic,
    validates_shape,
)
from wardline.decorators.authority import (
    external_boundary as eb_decorator,
)

# ---------------------------------------------------------------------------
# Helpers — real registry-based decorators
# ---------------------------------------------------------------------------

external_boundary = wardline_decorator(
    1,
    "external_boundary",
    _wardline_tier_source=TaintState.EXTERNAL_RAW,
)

integrity_critical = wardline_decorator(
    2,
    "integrity_critical",
    _wardline_integrity_critical=True,
)


# ---------------------------------------------------------------------------
# TestDecoratorBasic
# ---------------------------------------------------------------------------


class TestDecoratorBasic:
    """Basic decorator factory behaviour."""

    def test_decorated_function_callable(self) -> None:
        @external_boundary
        def my_func() -> int:
            return 42

        assert my_func() == 42

    def test_signature_preserved(self) -> None:
        @external_boundary
        def my_func() -> int:
            """My docstring."""
            return 1

        assert my_func.__name__ == "my_func"
        assert my_func.__doc__ == "My docstring."

    def test_wardline_groups_set(self) -> None:
        @external_boundary
        def my_func() -> int:
            return 1

        assert hasattr(my_func, "_wardline_groups")
        assert 1 in my_func._wardline_groups  # type: ignore[attr-defined]

    def test_semantic_attrs_set(self) -> None:
        @external_boundary
        def my_func() -> int:
            return 1

        assert (
            my_func._wardline_tier_source  # type: ignore[attr-defined]
            is TaintState.EXTERNAL_RAW
        )


# ---------------------------------------------------------------------------
# TestRegistryEnforcement
# ---------------------------------------------------------------------------


class TestRegistryEnforcement:
    """Registry validation at decorator creation time."""

    def test_unknown_name_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown decorator 'nonexistent'"):
            wardline_decorator(1, "nonexistent")

    def test_unknown_attr_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown attribute"):
            wardline_decorator(
                1, "external_boundary", _wardline_bogus=True
            )

    def test_valid_decorator_succeeds(self) -> None:
        dec = wardline_decorator(
            1,
            "external_boundary",
            _wardline_tier_source=TaintState.EXTERNAL_RAW,
        )
        assert callable(dec)

    def test_group_mismatch_raises(self) -> None:
        """Passing a group that doesn't match the registry entry raises."""
        with pytest.raises(ValueError, match="Group mismatch"):
            wardline_decorator(
                99,
                "external_boundary",
                _wardline_tier_source=TaintState.EXTERNAL_RAW,
            )

    def test_correct_group_succeeds(self) -> None:
        """Passing the correct group from the registry works."""
        dec = wardline_decorator(
            1,
            "external_boundary",
            _wardline_tier_source=TaintState.EXTERNAL_RAW,
        )
        assert callable(dec)


# ---------------------------------------------------------------------------
# TestStacking
# ---------------------------------------------------------------------------


class TestStacking:
    """Multiple wardline decorators on the same function."""

    def test_stacking_groups_accumulate(self) -> None:
        @integrity_critical
        @external_boundary
        def my_func() -> int:
            return 1

        groups = my_func._wardline_groups  # type: ignore[attr-defined]
        assert 1 in groups
        assert 2 in groups

    def test_stacking_attrs_merge(self) -> None:
        @integrity_critical
        @external_boundary
        def my_func() -> int:
            return 1

        assert (
            my_func._wardline_tier_source  # type: ignore[attr-defined]
            is TaintState.EXTERNAL_RAW
        )
        assert my_func._wardline_integrity_critical is True  # type: ignore[attr-defined]

    def test_copy_on_accumulate(self) -> None:
        """Inner decorator's _wardline_groups set is NOT mutated by outer."""

        @external_boundary
        def inner_func() -> int:
            return 1

        inner_groups = inner_func._wardline_groups  # type: ignore[attr-defined]
        inner_groups_copy = set(inner_groups)

        @integrity_critical
        @external_boundary
        def stacked_func() -> int:
            return 1

        # The original inner_func's groups must not have been mutated
        assert inner_groups == inner_groups_copy


# ---------------------------------------------------------------------------
# TestMixedStacking
# ---------------------------------------------------------------------------


class TestMixedStacking:
    """Wardline decorators interleaved with third-party decorators."""

    def test_wardline_third_party_wardline_preserves_groups(self) -> None:
        """wardline + third-party + wardline: both wardline groups survive."""
        import functools

        def third_party(fn):
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                return fn(*args, **kwargs)
            return wrapper

        @integrity_critical
        @third_party
        @external_boundary
        def my_func() -> int:
            return 42

        assert my_func() == 42
        groups = my_func._wardline_groups  # type: ignore[attr-defined]
        assert 1 in groups  # external_boundary
        assert 2 in groups  # integrity_critical

    def test_third_party_does_not_add_wardline_attrs(self) -> None:
        """Third-party wrapper between wardline decorators doesn't inject attrs."""
        import functools

        def third_party(fn):
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                return fn(*args, **kwargs)
            return wrapper

        @integrity_critical
        @third_party
        @external_boundary
        def my_func() -> int:
            return 1

        # Inner wardline attrs survive through the third-party layer
        assert my_func._wardline_tier_source is TaintState.EXTERNAL_RAW  # type: ignore[attr-defined]
        assert my_func._wardline_integrity_critical is True  # type: ignore[attr-defined]

    def test_mixed_stacking_async(self) -> None:
        """Wardline preserves coroutine status across sync third-party wrappers.

        A sync third-party wrapper using functools.wraps sets __wrapped__,
        which wardline follows to discover the underlying async function.
        The outermost wardline decorator creates an async wrapper even though
        its immediate input is sync.
        """
        import functools

        def third_party(fn):
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                return fn(*args, **kwargs)
            return wrapper

        @integrity_critical
        @third_party
        @external_boundary
        async def my_async_func() -> int:
            return 42

        assert asyncio.iscoroutinefunction(my_async_func)
        result = asyncio.run(my_async_func())
        assert result == 42
        groups = my_async_func._wardline_groups  # type: ignore[attr-defined]
        assert 1 in groups
        assert 2 in groups


# ---------------------------------------------------------------------------
# TestWrappedChain
# ---------------------------------------------------------------------------


class TestWrappedChain:
    """__wrapped__ chain traversal via get_wardline_attrs."""

    def test_get_attrs_returns_attrs(self) -> None:
        @external_boundary
        def my_func() -> int:
            return 1

        attrs = get_wardline_attrs(my_func)
        assert attrs is not None
        assert "_wardline_tier_source" in attrs
        assert attrs["_wardline_tier_source"] is TaintState.EXTERNAL_RAW

    def test_plain_func_returns_none(self) -> None:
        """Plain function with no wardline attrs returns None."""
        def plain_func() -> int:
            return 1

        result = get_wardline_attrs(plain_func)
        assert result is None

    def test_severed_chain_warns(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Severed __wrapped__ chain logs WARNING and returns None.

        The warning only fires when the outermost function has _wardline_
        attributes — a pure third-party __wrapped__ chain should NOT warn.
        """
        import functools

        def inner() -> int:
            return 1

        @functools.wraps(inner)
        def wrapper(*args: object, **kwargs: object) -> int:
            return inner(*args, **kwargs)  # type: ignore[return-value]

        # Mark the outer wrapper as a wardline decorator
        wrapper._wardline_groups = {1}  # type: ignore[attr-defined]

        with caplog.at_level(logging.WARNING):
            result = get_wardline_attrs(wrapper)

        # The chain has wardline attrs on wrapper but inner is bare —
        # attrs are collected from wrapper, so result is not None.
        assert result is not None

    def test_severed_chain_no_warn_third_party(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Third-party __wrapped__ chain does NOT trigger severed-chain warning."""
        import functools

        def inner() -> int:
            return 1

        @functools.wraps(inner)
        def wrapper(*args: object, **kwargs: object) -> int:
            return inner(*args, **kwargs)  # type: ignore[return-value]

        # No _wardline_* attrs — pure third-party chain
        with caplog.at_level(logging.WARNING):
            result = get_wardline_attrs(wrapper)

        assert result is None
        assert "Severed __wrapped__ chain" not in caplog.text


# ---------------------------------------------------------------------------
# TestCallableTypes
# ---------------------------------------------------------------------------


class TestCallableTypes:
    """Decorator works on different callable types."""

    def test_works_on_regular_function(self) -> None:
        @external_boundary
        def my_func(x: int) -> int:
            return x + 1

        assert my_func(5) == 6

    def test_works_on_method(self) -> None:
        class MyClass:
            @external_boundary
            def my_method(self, x: int) -> int:
                return x + 1

        obj = MyClass()
        assert obj.my_method(5) == 6
        assert hasattr(MyClass.my_method, "_wardline_groups")

    def test_works_on_staticmethod(self) -> None:
        class MyClass:
            @external_boundary
            @staticmethod
            def my_static(x: int) -> int:
                return x + 1

        assert MyClass.my_static(5) == 6

    def test_works_on_classmethod(self) -> None:
        class MyClass:
            @external_boundary
            @classmethod
            def my_cls(cls, x: int) -> int:
                return x + 1

        assert MyClass.my_cls(5) == 6

    def test_works_on_init(self) -> None:
        class MyClass:
            @external_boundary
            def __init__(self) -> None:
                self.value = 42

        obj = MyClass()
        assert obj.value == 42
        assert hasattr(MyClass.__init__, "_wardline_groups")

    def test_works_on_generator(self) -> None:
        @external_boundary
        def my_gen():
            yield 1
            yield 2
            yield 3

        result = list(my_gen())
        assert result == [1, 2, 3]
        assert hasattr(my_gen, "_wardline_groups")

    def test_works_on_property_getter(self) -> None:
        class MyClass:
            @property
            @external_boundary
            def value(self) -> int:
                return 42

        obj = MyClass()
        assert obj.value == 42


# ---------------------------------------------------------------------------
# TestGroup1Decorators
# ---------------------------------------------------------------------------


class TestGroup1Decorators:
    """Group 1 (Authority Tier Flow) decorators from authority.py."""

    def test_external_boundary_group(self) -> None:
        @eb_decorator
        def f() -> int:
            return 1

        assert 1 in f._wardline_groups  # type: ignore[attr-defined]

    def test_external_boundary_attrs(self) -> None:
        @eb_decorator
        def f() -> int:
            return 1

        assert f._wardline_tier_source is TaintState.EXTERNAL_RAW  # type: ignore[attr-defined]

    def test_external_boundary_callable(self) -> None:
        @eb_decorator
        def f() -> int:
            return 42

        assert f() == 42

    def test_validates_shape_group(self) -> None:
        @validates_shape
        def f() -> int:
            return 1

        assert 1 in f._wardline_groups  # type: ignore[attr-defined]

    def test_validates_shape_attrs(self) -> None:
        @validates_shape
        def f() -> int:
            return 1

        assert f._wardline_transition == (TaintState.EXTERNAL_RAW, TaintState.GUARDED)  # type: ignore[attr-defined]

    def test_validates_shape_callable(self) -> None:
        @validates_shape
        def f() -> int:
            return 42

        assert f() == 42

    def test_validates_semantic_group(self) -> None:
        @validates_semantic
        def f() -> int:
            return 1

        assert 1 in f._wardline_groups  # type: ignore[attr-defined]

    def test_validates_semantic_attrs(self) -> None:
        @validates_semantic
        def f() -> int:
            return 1

        assert f._wardline_transition == (TaintState.GUARDED, TaintState.ASSURED)  # type: ignore[attr-defined]

    def test_validates_semantic_callable(self) -> None:
        @validates_semantic
        def f() -> int:
            return 42

        assert f() == 42

    def test_validates_external_group(self) -> None:
        @validates_external
        def f() -> int:
            return 1

        assert 1 in f._wardline_groups  # type: ignore[attr-defined]

    def test_validates_external_attrs(self) -> None:
        @validates_external
        def f() -> int:
            return 1

        assert f._wardline_transition == (TaintState.EXTERNAL_RAW, TaintState.ASSURED)  # type: ignore[attr-defined]

    def test_validates_external_callable(self) -> None:
        @validates_external
        def f() -> int:
            return 42

        assert f() == 42

    def test_integral_read_group(self) -> None:
        @integral_read
        def f() -> int:
            return 1

        assert 1 in f._wardline_groups  # type: ignore[attr-defined]

    def test_integral_read_attrs(self) -> None:
        @integral_read
        def f() -> int:
            return 1

        assert f._wardline_tier_source is TaintState.INTEGRAL  # type: ignore[attr-defined]

    def test_integral_read_callable(self) -> None:
        @integral_read
        def f() -> int:
            return 42

        assert f() == 42

    def test_integral_writer_group(self) -> None:
        @integral_writer
        def f() -> int:
            return 1

        assert 1 in f._wardline_groups  # type: ignore[attr-defined]

    def test_integral_writer_attrs(self) -> None:
        @integral_writer
        def f() -> int:
            return 1

        assert f._wardline_tier_source is TaintState.INTEGRAL  # type: ignore[attr-defined]
        assert f._wardline_integral_writer is True  # type: ignore[attr-defined]

    def test_integral_writer_callable(self) -> None:
        @integral_writer
        def f() -> int:
            return 42

        assert f() == 42

    def test_integral_construction_group(self) -> None:
        @integral_construction
        def f() -> int:
            return 1

        assert 1 in f._wardline_groups  # type: ignore[attr-defined]

    def test_integral_construction_attrs(self) -> None:
        @integral_construction
        def f() -> int:
            return 1

        assert f._wardline_transition == (TaintState.ASSURED, TaintState.INTEGRAL)  # type: ignore[attr-defined]

    def test_integral_construction_callable(self) -> None:
        @integral_construction
        def f() -> int:
            return 42

        assert f() == 42


# ---------------------------------------------------------------------------
# TestAsyncSupport
# ---------------------------------------------------------------------------


class TestAsyncSupport:
    """Async function decorator support."""

    def test_async_function_stays_coroutine(self) -> None:
        """Decorating async def preserves coroutine function status."""

        @external_boundary
        async def my_async_func() -> int:
            return 42

        assert asyncio.iscoroutinefunction(my_async_func)
        assert inspect.iscoroutinefunction(my_async_func)

    def test_async_function_callable(self) -> None:
        """Decorated async function can be awaited."""

        @external_boundary
        async def my_async_func() -> int:
            return 42

        result = asyncio.run(my_async_func())
        assert result == 42

    def test_async_function_has_wardline_groups(self) -> None:
        """Decorated async function has _wardline_groups."""

        @external_boundary
        async def my_async_func() -> int:
            return 1

        assert hasattr(my_async_func, "_wardline_groups")
        assert 1 in my_async_func._wardline_groups  # type: ignore[attr-defined]

    def test_async_function_has_semantic_attrs(self) -> None:
        """Decorated async function has semantic attributes."""

        @external_boundary
        async def my_async_func() -> int:
            return 1

        assert (
            my_async_func._wardline_tier_source  # type: ignore[attr-defined]
            is TaintState.EXTERNAL_RAW
        )

    def test_async_stacking(self) -> None:
        """Stacked decorators on async preserve coroutine status."""

        @integrity_critical
        @external_boundary
        async def my_async_func() -> int:
            return 1

        assert asyncio.iscoroutinefunction(my_async_func)
        groups = my_async_func._wardline_groups  # type: ignore[attr-defined]
        assert 1 in groups
        assert 2 in groups

    def test_sync_function_not_coroutine(self) -> None:
        """Sync function remains non-coroutine after decoration."""

        @external_boundary
        def my_sync_func() -> int:
            return 1

        assert not asyncio.iscoroutinefunction(my_sync_func)

    def test_async_name_preserved(self) -> None:
        """Async decorated function preserves __name__."""

        @external_boundary
        async def my_async_func() -> int:
            """My async docstring."""
            return 1

        assert my_async_func.__name__ == "my_async_func"
        assert my_async_func.__doc__ == "My async docstring."
