from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.failopen_boundary import FailOpenBoundary

_BOUNDARY_HEADER = (
    "from wardline.decorators import trust_boundary, external_boundary\n"
    "@external_boundary\n"
    "def read_raw(p):\n"
    "    return p\n"
)


def _analyze(tmp_path: Path, src: str):
    p = tmp_path / "m.py"
    p.write_text(_BOUNDARY_HEADER + textwrap.dedent(src), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    analyzer.analyze([p], WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    return analyzer.last_context


def test_failopen_boundary_fires_on_substitution(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        @trust_boundary(to_level='ASSURED')
        def v(p):
            try:
                if not p:
                    raise ValueError
                return read_raw(p)
            except ValueError:
                return p
        """,
    )
    findings = FailOpenBoundary().check(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-113", "m.v")]
    assert findings[0].kind == Kind.DEFECT
    assert findings[0].severity == Severity.ERROR


def test_failopen_boundary_silent_on_re_raise(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        @trust_boundary(to_level='ASSURED')
        def v(p):
            try:
                if not p:
                    raise ValueError
                return read_raw(p)
            except ValueError:
                raise
        """,
    )
    assert FailOpenBoundary().check(ctx) == []


def test_failopen_boundary_silent_on_falsy_constant_return(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        @trust_boundary(to_level='ASSURED')
        def v(p):
            try:
                if not p:
                    raise ValueError
                return read_raw(p)
            except ValueError:
                return None
        """,
    )
    assert FailOpenBoundary().check(ctx) == []


def test_failopen_boundary_silent_on_non_boundary(tmp_path) -> None:
    # A plain @trusted function with body == return (no trust-raising) is not a boundary,
    # so we shouldn't trigger PY-WL-113 even if we swallow and return.
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def f(p):
            try:
                if not p:
                    raise ValueError
                return p
            except ValueError:
                return p
        """,
    )
    assert FailOpenBoundary().check(ctx) == []


def test_failopen_boundary_silent_on_undecorated(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        def f(p):
            try:
                if not p:
                    raise ValueError
                return p
            except ValueError:
                return p
        """,
    )
    assert FailOpenBoundary().check(ctx) == []
