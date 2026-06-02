"""Closure E — flow-sensitive call-arg taint at sink sites.

The sink rules (106/107/108) and PY-WL-105 historically read the FINAL per-variable
taint map (``function_var_taints``), which is flow-INSENSITIVE: a name reassigned
after the sink call was read at its final taint, so a trusted-at-the-sink value
that later becomes raw OVER-fired (a real FP), and a raw-at-the-sink value that
was later sanitised UNDER-fired (a fail-open). Reading the taint AT the sink
statement closes both — verified here in both directions.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind
from wardline.scanner.analyzer import WardlineAnalyzer

_HEADER = (
    "from wardline.decorators import external_boundary, trusted\n@external_boundary\ndef read_raw(p):\n    return p\n"
)


def _defects(tmp_path: Path, body: str) -> set[str]:
    p = tmp_path / "m.py"
    p.write_text(_HEADER + textwrap.dedent(body), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze([p], WardlineConfig(), root=tmp_path)
    return {f.rule_id for f in findings if f.kind is Kind.DEFECT}


def test_trusted_at_sink_then_reassigned_raw_does_not_fire(tmp_path: Path) -> None:
    # x is trusted AT the eval; only reassigned raw AFTER — must NOT fire (was an FP).
    defects = _defects(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            x = 'safe'
            eval(x)
            x = read_raw(p)
        """,
    )
    assert "PY-WL-107" not in defects, defects


def test_raw_at_sink_still_fires(tmp_path: Path) -> None:
    # x is raw AT the eval — genuine TP, must still fire (no fail-open).
    defects = _defects(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            x = read_raw(p)
            eval(x)
        """,
    )
    assert "PY-WL-107" in defects, defects


def test_raw_at_sink_then_sanitised_after_still_fires(tmp_path: Path) -> None:
    # The symmetric case the old flow-insensitive read got wrong (a fail-open):
    # raw AT the sink, sanitised only AFTER. Flow-sensitivity must FIRE here.
    defects = _defects(
        tmp_path,
        """
        @trusted(level='ASSURED')
        def f(p):
            x = read_raw(p)
            eval(x)
            x = 'safe'
        """,
    )
    assert "PY-WL-107" in defects, defects
