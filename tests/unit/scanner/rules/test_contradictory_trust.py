from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.contradictory_trust import ContradictoryTrust


def _analyze(tmp_path: Path, src: str):
    p = tmp_path / "m.py"
    p.write_text(textwrap.dedent(src), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    analyzer.analyze([p], WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    return analyzer.last_context


def _run(ctx):
    return ContradictoryTrust().check(ctx)


def test_two_distinct_markers_fire_at_error(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted, external_boundary
        @trusted
        @external_boundary
        def f(p):
            return p
        """,
    )
    findings = _run(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-110", "m.f")]
    assert findings[0].kind == Kind.DEFECT
    assert findings[0].severity == Severity.ERROR  # declaration-gated, not modulated


def test_single_marker_does_not_fire(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted
        def f(p):
            return p
        """,
    )
    assert _run(ctx) == []


def test_marker_plus_nontrust_decorator_does_not_fire(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        def deco(fn):
            return fn
        @deco
        @trusted
        def g(p):
            return p
        """,
    )
    assert [f for f in _run(ctx) if f.qualname == "m.g"] == []


def test_undecorated_does_not_fire(tmp_path) -> None:
    ctx = _analyze(tmp_path, "def f(p):\n    return p\n")
    assert _run(ctx) == []


def test_two_distinct_markers_with_call_form_fire(tmp_path) -> None:
    # Markers in their called form (@trust_boundary(...) + @trusted(...)) still count.
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted, trust_boundary
        @trusted(level='ASSURED')
        @trust_boundary(to_level='ASSURED')
        def f(p):
            if not p:
                raise ValueError
            return p
        """,
    )
    assert [(x.rule_id, x.qualname) for x in _run(ctx)] == [("PY-WL-110", "m.f")]
