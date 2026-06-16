"""PY-WL-123 — tainted attribute NAME reaches setattr/getattr (CWE-915 mass assignment)."""

from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.untrusted_to_reflection import UntrustedToReflection

_HEADER = (
    "from wardline.decorators import external_boundary, trusted\n@external_boundary\ndef read_raw(p):\n    return p\n"
)


def _analyze(tmp_path: Path, src: str):
    p = tmp_path / "m.py"
    p.write_text(_HEADER + textwrap.dedent(src), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze([p], WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    return analyzer.last_context, list(findings)


def test_123_setattr_tainted_name_fires_warn(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p, obj):
            setattr(obj, read_raw(p), 1)
            return 1
        """,
    )
    findings = UntrustedToReflection().check(ctx)
    assert [(x.rule_id, x.qualname) for x in findings] == [("PY-WL-123", "m.f")]
    assert findings[0].kind == Kind.DEFECT
    assert findings[0].severity == Severity.WARN


def test_123_getattr_tainted_name_fires(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p, obj):
            return getattr(obj, read_raw(p))
        """,
    )
    assert [x.properties["sink"] for x in UntrustedToReflection().check(ctx)] == ["getattr"]


def test_123_tainted_value_with_literal_name_is_clean(tmp_path) -> None:
    # Only the attribute NAME slot (position 1) is the mass-assignment vector;
    # an untrusted VALUE assigned to a fixed attribute is ordinary data flow.
    ctx, _ = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p, obj):
            setattr(obj, 'name', read_raw(p))
            return 1
        """,
    )
    assert UntrustedToReflection().check(ctx) == []


def test_123_tainted_getattr_default_is_clean(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p, obj):
            return getattr(obj, 'name', read_raw(p))
        """,
    )
    assert UntrustedToReflection().check(ctx) == []


def test_123_tainted_receiver_is_clean(tmp_path) -> None:
    # A tainted RECEIVER with a literal name is not attribute injection.
    ctx, _ = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            return getattr(read_raw(p), 'name')
        """,
    )
    assert UntrustedToReflection().check(ctx) == []


def test_123_undecorated_is_suppressed(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        def f(p, obj):
            setattr(obj, read_raw(p), 1)
            return 1
        """,
    )
    assert UntrustedToReflection().check(ctx) == []


def test_123_registered_end_to_end(tmp_path) -> None:
    _, findings = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p, obj):
            setattr(obj, read_raw(p), 1)
            return 1
        """,
    )
    assert "PY-WL-123" in {f.rule_id for f in findings}
