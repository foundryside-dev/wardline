# tests/unit/scanner/rules/test_untrusted_to_import.py
"""Tests for PY-WL-115: untrusted module loaded via dynamic import sinks."""

from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.untrusted_to_import import UntrustedToImport

_HEADER = (
    "import importlib\n"
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\n"
    "def read_raw(p):\n"
    "    return p\n"
)


def _analyze(tmp_path: Path, src: str) -> tuple[WardlineAnalyzer, object]:
    p = tmp_path / "m.py"
    p.write_text(_HEADER + textwrap.dedent(src), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    analyzer.analyze([p], WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    return analyzer, analyzer.last_context


def test_115_raw_reaches_importlib(tmp_path) -> None:
    _, ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            mod_name = read_raw(p)
            importlib.import_module(mod_name)
            return 1
        """,
    )
    findings = UntrustedToImport().check(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-115", "m.f")]
    assert findings[0].kind == Kind.DEFECT
    assert findings[0].severity == Severity.WARN


def test_115_raw_reaches_dunder_import(tmp_path) -> None:
    _, ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def g(p):
            __import__(read_raw(p))
            return 1
        """,
    )
    findings = UntrustedToImport().check(ctx)
    assert [f.rule_id for f in findings] == ["PY-WL-115"]


def test_115_clean_import(tmp_path) -> None:
    _, ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def h(p):
            importlib.import_module('os')
            return 1
        """,
    )
    findings = UntrustedToImport().check(ctx)
    assert len(findings) == 0
