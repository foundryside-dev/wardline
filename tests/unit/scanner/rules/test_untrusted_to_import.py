# tests/unit/scanner/rules/test_untrusted_to_import.py
"""Tests for PY-WL-115: untrusted module loaded via dynamic code/module-load sinks."""

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
_HEADER_LINES = _HEADER.count("\n")


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
    assert [(f.rule_id, f.qualname, f.kind, f.severity) for f in findings] == [
        ("PY-WL-115", "m.g", Kind.DEFECT, Severity.WARN)
    ]
    # snippet: blank line, @trusted, def g, sink — the sink sits 4 lines into the snippet
    assert findings[0].location.line_start == _HEADER_LINES + 4


def test_115_raw_reaches_aliased_importlib(tmp_path) -> None:
    # `import importlib as il` exercises the shared alias-resolution path
    # (canonical_call_name), which the direct-spelling tests above do not.
    _, ctx = _analyze(
        tmp_path,
        """
        import importlib as il

        @trusted(level='ASSURED')
        def f(p):
            il.import_module(read_raw(p))
            return 1
        """,
    )
    findings = UntrustedToImport().check(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-115", "m.f")]
    assert findings[0].severity == Severity.WARN


def test_115_undecorated_function_suppressed(tmp_path) -> None:
    # No trust declaration → developer-freedom zone → the rule stays silent
    # even on a provably raw flow.
    _, ctx = _analyze(
        tmp_path,
        """
        def g(p):
            importlib.import_module(read_raw(p))
            return 1
        """,
    )
    findings = UntrustedToImport().check(ctx)
    assert findings == []


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


def test_115_dunder_import_clean(tmp_path) -> None:
    _, ctx = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def h(p):
            __import__('os')
            return 1
        """,
    )
    findings = UntrustedToImport().check(ctx)
    assert findings == []


def test_115_raw_reaches_runpy_run_path(tmp_path) -> None:
    _, ctx = _analyze(
        tmp_path,
        """
        import runpy

        @trusted(level='ASSURED')
        def f(p):
            path = read_raw(p)
            runpy.run_path(path)
            return 1
        """,
    )
    findings = UntrustedToImport().check(ctx)
    assert [(f.rule_id, f.qualname, f.kind, f.severity) for f in findings] == [
        ("PY-WL-115", "m.f", Kind.DEFECT, Severity.WARN)
    ]
    assert findings[0].properties["sink"] == "runpy.run_path"


def test_115_raw_reaches_runpy_run_module(tmp_path) -> None:
    _, ctx = _analyze(
        tmp_path,
        """
        import runpy

        @trusted(level='ASSURED')
        def f(p):
            runpy.run_module(read_raw(p))
            return 1
        """,
    )
    findings = UntrustedToImport().check(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-115", "m.f")]
    assert findings[0].properties["sink"] == "runpy.run_module"


def test_115_raw_reaches_spec_from_file_location(tmp_path) -> None:
    # The tainted FILE PATH arg is what makes the loader dangerous.
    _, ctx = _analyze(
        tmp_path,
        """
        import importlib.util

        @trusted(level='ASSURED')
        def f(p):
            importlib.util.spec_from_file_location('m', read_raw(p))
            return 1
        """,
    )
    findings = UntrustedToImport().check(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-115", "m.f")]
    assert findings[0].properties["sink"] == "importlib.util.spec_from_file_location"


def test_115_runpy_clean_constant_path(tmp_path) -> None:
    _, ctx = _analyze(
        tmp_path,
        """
        import runpy

        @trusted(level='ASSURED')
        def f(p):
            runpy.run_path('scripts/fixed.py')
            return 1
        """,
    )
    findings = UntrustedToImport().check(ctx)
    assert findings == []
