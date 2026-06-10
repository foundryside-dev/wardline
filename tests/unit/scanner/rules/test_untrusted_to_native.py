"""PY-WL-124 — untrusted path reaches a native-library load sink (ctypes, CWE-114)."""

from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.rules.untrusted_to_native import UntrustedToNative

_HEADER = (
    "import ctypes\n"
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\n"
    "def read_raw(p):\n"
    "    return p\n"
)


def _analyze(tmp_path: Path, src: str):
    p = tmp_path / "m.py"
    p.write_text(_HEADER + textwrap.dedent(src), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze([p], WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    return analyzer.last_context, list(findings)


def test_124_ctypes_cdll_fires_error(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            return ctypes.CDLL(read_raw(p))
        """,
    )
    findings = UntrustedToNative().check(ctx)
    assert [(x.rule_id, x.qualname) for x in findings] == [("PY-WL-124", "m.f")]
    assert findings[0].kind == Kind.DEFECT
    assert findings[0].severity == Severity.ERROR  # arbitrary native-code execution


def test_124_dll_variants_and_loadlibrary_fire(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            ctypes.WinDLL(read_raw(p))
            ctypes.OleDLL(read_raw(p))
            ctypes.PyDLL(read_raw(p))
            ctypes.cdll.LoadLibrary(read_raw(p))
            return 1
        """,
    )
    sinks = sorted(x.properties["sink"] for x in UntrustedToNative().check(ctx))
    assert sinks == [
        "ctypes.OleDLL",
        "ctypes.PyDLL",
        "ctypes.WinDLL",
        "ctypes.cdll.LoadLibrary",
    ]


def test_124_literal_library_path_is_clean(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f():
            return ctypes.CDLL('libm.so.6')
        """,
    )
    assert UntrustedToNative().check(ctx) == []


def test_124_undecorated_is_suppressed(tmp_path) -> None:
    ctx, _ = _analyze(
        tmp_path,
        """
        def f(p):
            return ctypes.CDLL(read_raw(p))
        """,
    )
    assert UntrustedToNative().check(ctx) == []


def test_124_registered_end_to_end(tmp_path) -> None:
    _, findings = _analyze(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            return ctypes.cdll.LoadLibrary(read_raw(p))
        """,
    )
    assert "PY-WL-124" in {f.rule_id for f in findings}
