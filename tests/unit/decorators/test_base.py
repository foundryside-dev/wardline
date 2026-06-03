# tests/unit/decorators/test_base.py
from __future__ import annotations

import pytest

from wardline.core.taints import TaintState
from wardline.decorators._base import apply_marker, coerce_level


def test_coerce_level_accepts_enum_and_name() -> None:
    allowed = frozenset({TaintState.INTEGRAL, TaintState.ASSURED})
    assert coerce_level(TaintState.ASSURED, allowed=allowed, arg="level") is TaintState.ASSURED
    assert coerce_level("INTEGRAL", allowed=allowed, arg="level") is TaintState.INTEGRAL


def test_coerce_level_rejects_unknown_name() -> None:
    allowed = frozenset({TaintState.INTEGRAL})
    with pytest.raises(ValueError, match="not a valid TaintState"):
        coerce_level("NOPE", allowed=allowed, arg="level")


def test_coerce_level_rejects_disallowed_level() -> None:
    allowed = frozenset({TaintState.INTEGRAL})
    with pytest.raises(ValueError, match="must be one of"):
        coerce_level(TaintState.GUARDED, allowed=allowed, arg="level")


def test_apply_marker_stamps_group_and_attrs_and_returns_same_object() -> None:
    def f() -> int:
        return 1

    out = apply_marker(f, name="trusted", group=1, attrs={"_wardline_level": TaintState.INTEGRAL})
    assert out is f  # unchanged identity — no wrapper
    assert f._wardline_groups == frozenset({1})  # type: ignore[attr-defined]
    assert f._wardline_level is TaintState.INTEGRAL  # type: ignore[attr-defined]
    assert f() == 1  # behavior preserved


def test_apply_marker_rejects_unknown_name() -> None:
    with pytest.raises(ValueError, match="not in wardline registry"):
        apply_marker(lambda: None, name="bogus", group=1, attrs={})


def test_apply_marker_rejects_group_mismatch() -> None:
    with pytest.raises(ValueError, match="Group mismatch"):
        apply_marker(lambda: None, name="trusted", group=2, attrs={})


def test_apply_marker_rejects_unknown_attr() -> None:
    with pytest.raises(ValueError, match="Unknown attribute"):
        apply_marker(lambda: None, name="trusted", group=1, attrs={"_wardline_bogus": 1})


def test_apply_marker_rejects_non_callable() -> None:
    with pytest.raises(TypeError, match="requires a callable"):
        apply_marker(5, name="trusted", group=1, attrs={"_wardline_level": TaintState.INTEGRAL})  # type: ignore[arg-type]


def test_apply_marker_accumulates_groups() -> None:
    def f() -> None: ...

    apply_marker(f, name="external_boundary", group=1, attrs={})
    apply_marker(f, name="trusted", group=1, attrs={"_wardline_level": TaintState.INTEGRAL})
    assert f._wardline_groups == frozenset({1})  # type: ignore[attr-defined]


def test_apply_marker_double_decoration_preserves_distinct_attrs() -> None:
    # Two attr-bearing markers on one function: both attrs must survive.
    # (Cross-group accumulation is untestable until a group-2 registry entry
    # exists; only group 1 is defined in SP2a.)
    def f() -> None: ...

    apply_marker(f, name="trusted", group=1, attrs={"_wardline_level": TaintState.ASSURED})
    apply_marker(f, name="trust_boundary", group=1, attrs={"_wardline_to_level": TaintState.GUARDED})
    assert f._wardline_level is TaintState.ASSURED  # type: ignore[attr-defined]
    assert f._wardline_to_level is TaintState.GUARDED  # type: ignore[attr-defined]


def test_apply_marker_stamps_underlying_staticmethod() -> None:
    sm = staticmethod(lambda: 1)
    out = apply_marker(sm, name="external_boundary", group=1, attrs={})
    assert out is sm  # the descriptor object is returned unchanged
    assert sm.__func__._wardline_groups == frozenset({1})  # type: ignore[attr-defined]


def test_apply_marker_stamps_underlying_classmethod() -> None:
    def _impl(cls: object) -> int:
        return 1

    cm = classmethod(_impl)  # type: ignore[var-annotated]
    out = apply_marker(cm, name="trusted", group=1, attrs={"_wardline_level": TaintState.INTEGRAL})
    assert out is cm
    assert cm.__func__._wardline_level is TaintState.INTEGRAL  # type: ignore[attr-defined]


def test_trusted_marks_method_in_class_body() -> None:
    from wardline.decorators import trusted

    class C:
        @trusted
        def m(self) -> int:
            return 1

    assert C.m._wardline_level is TaintState.INTEGRAL  # type: ignore[attr-defined]
    assert C().m() == 1  # behaviour preserved


def test_taintstate_name_equals_value_coupling() -> None:
    # coerce_level("ASSURED") works only because every TaintState's value equals
    # its name. Pin that invariant here so a future enum-value change can't
    # silently break the by-name decorator contract.
    for member in TaintState:
        assert member.name == member.value
