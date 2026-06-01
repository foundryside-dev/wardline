# tests/unit/decorators/test_trust.py
from __future__ import annotations

import pytest

from wardline.core.taints import TaintState
from wardline.decorators import external_boundary, trust_boundary, trusted


def test_external_boundary_marks_group_only() -> None:
    @external_boundary
    def read(p: str) -> str:
        return p

    assert read._wardline_groups == frozenset({1})  # type: ignore[attr-defined]
    assert not hasattr(read, "_wardline_level")
    assert read("x") == "x"  # behaviour preserved


def test_trusted_bare_defaults_to_integral() -> None:
    @trusted
    def f() -> int:
        return 1

    assert f._wardline_level is TaintState.INTEGRAL  # type: ignore[attr-defined]
    assert f() == 1


def test_trusted_with_assured_name_and_enum() -> None:
    @trusted(level="ASSURED")
    def f() -> None: ...

    @trusted(level=TaintState.ASSURED)
    def g() -> None: ...

    assert f._wardline_level is TaintState.ASSURED  # type: ignore[attr-defined]
    assert g._wardline_level is TaintState.ASSURED  # type: ignore[attr-defined]


def test_trusted_rejects_disallowed_level() -> None:
    with pytest.raises(ValueError, match="must be one of"):

        @trusted(level="GUARDED")  # not a trusted-producer level
        def f() -> None: ...


def test_trust_boundary_records_to_level() -> None:
    @trust_boundary(to_level="ASSURED")
    def validate(x: str) -> str:
        return x

    assert validate._wardline_to_level is TaintState.ASSURED  # type: ignore[attr-defined]
    assert validate._wardline_groups == frozenset({1})  # type: ignore[attr-defined]
    assert validate("ok") == "ok"


def test_trust_boundary_accepts_guarded() -> None:
    @trust_boundary(to_level=TaintState.GUARDED)
    def shape(x: object) -> object:
        return x

    assert shape._wardline_to_level is TaintState.GUARDED  # type: ignore[attr-defined]


def test_trust_boundary_rejects_integral() -> None:
    with pytest.raises(ValueError, match="must be one of"):

        @trust_boundary(to_level="INTEGRAL")  # boundaries raise to GUARDED/ASSURED only
        def f(x: object) -> object:
            return x


def test_decorators_preserve_qualname() -> None:
    @trusted
    def named() -> None: ...

    assert named.__name__ == "named"
