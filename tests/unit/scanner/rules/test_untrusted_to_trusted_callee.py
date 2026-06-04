from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.untrusted_to_trusted_callee import UntrustedReachesTrustedCallee

_HEADER = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted(level='ASSURED')\ndef store(x):\n    return 1\n"
)


def _analyze(tmp_path: Path, src: str):
    p = tmp_path / "m.py"
    p.write_text(_HEADER + textwrap.dedent(src), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    analyzer.analyze([p], WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    return analyzer.last_context


def _ids(ctx):
    return [(f.rule_id, f.qualname) for f in UntrustedReachesTrustedCallee().check(ctx)]


def test_external_raw_arg_to_trusted_callee_fires(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        def h(p):
            store(read_raw(p))
        """,
    )
    findings = UntrustedReachesTrustedCallee().check(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-105", "m.h")]
    assert findings[0].kind == Kind.DEFECT
    assert findings[0].severity == Severity.ERROR
    assert findings[0].properties["callee"] == "m.store"


def test_unknown_raw_arg_does_not_fire(tmp_path) -> None:
    # An undecorated param (UNKNOWN_RAW) is merely unprovable, not provably untrusted.
    ctx = _analyze(
        tmp_path,
        """
        def h(p):
            store(p)
        """,
    )
    assert _ids(ctx) == []


def test_validated_through_undecorated_does_not_fire(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        def validate(x):
            return x
        def h(p):
            store(validate(read_raw(p)))
        """,
    )
    assert _ids(ctx) == []


def test_untrusted_to_undecorated_callee_does_not_fire(tmp_path) -> None:
    # Callee is not a trust-declared producer -> no opt-in -> no finding.
    ctx = _analyze(
        tmp_path,
        """
        def plain(x):
            return x
        def h(p):
            plain(read_raw(p))
        """,
    )
    assert _ids(ctx) == []


def test_external_boundary_callee_is_not_a_sink(tmp_path) -> None:
    # Passing raw to an @external_boundary (a source, raw body) is expected -> no fire.
    ctx = _analyze(
        tmp_path,
        """
        def h(p):
            read_raw(read_raw(p))
        """,
    )
    assert _ids(ctx) == []


def test_self_method_call_fires(tmp_path) -> None:
    # Sibling method call (self.store) should resolve and trigger PY-WL-105.
    ctx = _analyze(
        tmp_path,
        """
        class Service:
            @trusted(level='ASSURED')
            def store(self, x):
                return 1
            
            def run(self, p):
                self.store(read_raw(p))
        """,
    )
    findings = UntrustedReachesTrustedCallee().check(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-105", "m.Service.run")]
    assert findings[0].properties["callee"] == "m.Service.store"


def test_args_unpacking_fires(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        def h(p):
            args = [read_raw(p)]
            store(*args)
        """,
    )
    assert _ids(ctx) == [("PY-WL-105", "m.h")]


def test_kwargs_unpacking_fires(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        def h(p):
            kwargs = {"x": read_raw(p)}
            store(**kwargs)
        """,
    )
    assert _ids(ctx) == [("PY-WL-105", "m.h")]


def test_multiple_kwargs_unpacking_combines_raw_before_clean(tmp_path) -> None:
    ctx = _analyze(
        tmp_path,
        """
        def h(p):
            raw_kwargs = {"x": read_raw(p)}
            clean_kwargs = {"x": 1}
            store(**raw_kwargs, **clean_kwargs)
        """,
    )
    assert _ids(ctx) == [("PY-WL-105", "m.h")]
