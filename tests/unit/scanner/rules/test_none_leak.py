from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.none_leak import NoneLeak


def _analyze(tmp_path: Path, src: str):
    p = tmp_path / "m.py"
    p.write_text(textwrap.dedent(src), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    analyzer.analyze([p], WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    return analyzer.last_context


def _ids(ctx):
    return [(f.rule_id, f.qualname) for f in NoneLeak().check(ctx)]


def test_mixed_value_and_bare_return_fires(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def maybe(flag):
            if flag:
                return 1
            return
        """,
    )
    findings = NoneLeak().check(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-109", "m.maybe")]
    assert findings[0].kind == Kind.DEFECT
    assert findings[0].severity == Severity.WARN


def test_explicit_return_none_also_fires(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def maybe(flag):
            if flag:
                return 1
            return None
        """,
    )
    assert _ids(ctx) == [("PY-WL-109", "m.maybe")]


def test_all_value_returns_do_not_fire(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def always(flag):
            if flag:
                return 1
            return 2
        """,
    )
    assert _ids(ctx) == []


def test_generator_does_not_fire(tmp_path) -> None:
    # A generator's bare `return` ends iteration; it is not a None value leak.
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def gen(flag):
            if flag:
                yield 1
            return
        """,
    )
    assert _ids(ctx) == []


def test_pure_none_returner_does_not_fire(tmp_path) -> None:
    # No value-bearing path -> not a mixed/leaky contract (a void-ish helper).
    ctx = _analyze(
        tmp_path,
        """
        from wardline.decorators import trusted
        @trusted(level='ASSURED')
        def sink(x):
            if x:
                return
            return None
        """,
    )
    assert _ids(ctx) == []


def test_undecorated_does_not_fire(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        def maybe(flag):
            if flag:
                return 1
            return
        """,
    )
    assert _ids(ctx) == []
