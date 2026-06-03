"""Closure A — cross-method class-attribute taint.

The engine is function-level: raw assigned to ``self.<attr>`` in one method and
returned/passed-to-a-sink from ANOTHER method used to escape (a fail-open FN that
weakened PY-WL-101/105 on OO code). A per-class attribute summary — the
least-trusted value written to ``self.<attr>`` across all methods — now seeds reads
of that attribute, so a trusted-tier method that surfaces a raw attribute fires.

Crucially this does NOT over-fire on the common OO shapes: a validated setter
writes a TRUSTED value (``@trust_boundary`` raises trust), so the summary stays
trusted and the trusted getter is clean. Measured FP=0 on hand-built lazy-init /
validated-setter / builder patterns and on the dogfood + corpus trees.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind
from wardline.scanner.analyzer import WardlineAnalyzer

_HEADER = (
    "from wardline.decorators import external_boundary, trust_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trust_boundary(to_level='ASSURED')\ndef validate(x):\n    if not x:\n        raise ValueError\n    return x\n"
)


def _defects(tmp_path: Path, body: str) -> set[str]:
    p = tmp_path / "m.py"
    p.write_text(_HEADER + textwrap.dedent(body), encoding="utf-8")
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze([p], WardlineConfig(), root=tmp_path)
    return {f.rule_id for f in findings if f.kind is Kind.DEFECT}


def test_raw_attr_returned_by_trusted_getter_fires(tmp_path: Path) -> None:
    # raw written to self.x in __init__, returned by a @trusted getter — a real FN
    # the function-level engine missed. Must FIRE PY-WL-101 now.
    defects = _defects(
        tmp_path,
        """
        class C:
            def __init__(self, p):
                self.x = read_raw(p)
            @trusted(level='ASSURED')
            def get(self):
                return self.x
        """,
    )
    assert "PY-WL-101" in defects, defects


def test_raw_attr_via_local_indirection_fires(tmp_path: Path) -> None:
    # self.x = v where v = read_raw(p) — indirection must still be caught (no fail-open).
    defects = _defects(
        tmp_path,
        """
        class C:
            def __init__(self, p):
                v = read_raw(p)
                self.x = v
            @trusted(level='ASSURED')
            def get(self):
                return self.x
        """,
    )
    assert "PY-WL-101" in defects, defects


def test_validated_setter_trusted_getter_is_clean(tmp_path: Path) -> None:
    # The canonical OO shape: a validated setter writes a TRUSTED value, so the
    # trusted getter is clean. Must NOT fire (this is the FP A must avoid).
    defects = _defects(
        tmp_path,
        """
        class C:
            def set(self, p):
                self.x = validate(read_raw(p))
            @trusted(level='ASSURED')
            def get(self):
                return self.x
        """,
    )
    assert "PY-WL-101" not in defects, defects


def test_lazy_init_validated_is_clean(tmp_path: Path) -> None:
    defects = _defects(
        tmp_path,
        """
        class C:
            def __init__(self):
                self.x = None
            def load(self, p):
                self.x = validate(read_raw(p))
            @trusted(level='ASSURED')
            def get(self):
                return self.x
        """,
    )
    assert "PY-WL-101" not in defects, defects


def test_raw_attr_reaches_sink_in_other_method_fires(tmp_path: Path) -> None:
    # Cross-method into a sink: raw stored in __init__, eval'd by a trusted method.
    defects = _defects(
        tmp_path,
        """
        class C:
            def __init__(self, p):
                self.code = read_raw(p)
            @trusted(level='ASSURED')
            def run(self):
                eval(self.code)
        """,
    )
    assert "PY-WL-107" in defects, defects


def test_helper_method_returning_assured_does_not_false_positive(tmp_path: Path) -> None:
    defects = _defects(
        tmp_path,
        """
        class Helper:
            @trusted(level='ASSURED')
            def get_assured(self, p):
                return validate(p)

        class C:
            def __init__(self, p):
                h = Helper()
                self.x = h.get_assured(p)
            @trusted(level='ASSURED')
            def get(self):
                return self.x
        """,
    )
    assert "PY-WL-101" not in defects, defects
