# tests/unit/core/test_assure.py
"""The ``assure`` coverage aggregator — trust-surface COVERAGE, not just defects.

Two gates: an END-TO-END run (real ``run_scan``) that pins the denominator /
coverage maths against hand-computed literals, and a UNIT exercise of the
``unknown`` / ``engine_limited`` honesty branch via a synthetic context (a real
engine under-scan is impractical to trip in a fixture).
"""

from __future__ import annotations

import ast
from datetime import date
from pathlib import Path
from types import MappingProxyType

from wardline.core.assure import _empty_posture, build_posture, posture_from_scan
from wardline.core.finding import Finding, Kind, Location, Severity
from wardline.core.paths import waivers_path
from wardline.core.run import ScanResult, ScanSummary
from wardline.core.taints import TaintState
from wardline.core.waivers import add_waiver
from wardline.scanner.context import AnalysisContext
from wardline.scanner.index import Entity

# An arbitrary valid 64-char lowercase-hex fingerprint — the waiver rollup is a
# config-level surface; it need not match any actual finding.
_WAIVER_FP = "a" * 64

# `leak` declares INTEGRAL but returns an @external_boundary (EXTERNAL_RAW) value →
# a real PY-WL-101 defect. Wardline taints data from DECLARED sources, not arbitrary
# builtins (a bare `return input()` is unknown-not-raw to the engine and would
# spuriously read as clean), so the leak flows through `src` — the engine's actual
# taint-source mechanism.
_MODULE = (
    "from wardline.decorators.trust import trusted, external_boundary\n"
    "\n"
    "@external_boundary\n"
    "def src():\n"
    "    return _read()\n"
    "\n"
    "def _read():\n"
    "    return object()\n"
    "\n"
    "@trusted(level='INTEGRAL')\n"
    "def clean():\n"
    "    return 1\n"
    "\n"
    "@trusted(level='INTEGRAL')\n"
    "def leak():\n"
    "    return src()\n"
)

def test_coverage_denominator_end_to_end(tmp_path: Path) -> None:
    (tmp_path / "m.py").write_text(_MODULE, encoding="utf-8")
    add_waiver(
        waivers_path(tmp_path),
        fingerprint=_WAIVER_FP,
        reason="third-party shim",
        expires=date(2026, 7, 1),
        root=tmp_path,
    )

    posture = build_posture(tmp_path, today=date(2026, 6, 3))
    got = posture.to_dict()

    # clean, leak, src are anchored (trust-declared); no undecorated entity counts.
    assert got["boundaries_total"] == 3
    # clean: declared INTEGRAL conforms; src: @external_boundary declares EXTERNAL_RAW
    # (∉ UNKNOWN_TIERS) with no active finding → conforms → clean.
    assert got["proven"] == 2
    # leak: declares INTEGRAL but returns an EXTERNAL_RAW value → PY-WL-101 active.
    assert got["defect_total"] == 1
    assert got["unknown"] == []
    assert got["engine_limited"] == 0
    # 3 of 3 reached a definite verdict — the defect counts as COVERED.
    assert got["coverage_pct"] == 100.0
    assert got["unanalyzed_rule_ids"] == []
    # 2026-07-01 − 2026-06-03 = 28 days.
    assert got["waiver_debt"] == [
        {
            "fingerprint": _WAIVER_FP,
            "expires": "2026-07-01",
            "days_left": 28,
            "reason": "third-party shim",
        }
    ]
    assert got["baselined_total"] == 0
    assert got["judged_total"] == 0


def _entity(qualname: str, line: int) -> Entity:
    node = ast.parse(f"def {qualname.split('.')[-1]}():\n    return 1\n").body[0]
    assert isinstance(node, ast.FunctionDef)
    return Entity(
        qualname=qualname,
        kind="function",
        node=node,
        location=Location(path="m.py", line_start=line),
    )


def test_unknown_and_engine_limited_branch() -> None:
    # Three anchored entities:
    #  m.a — present in function_return_taints, declared conforming → "clean".
    #  m.b — declared but ABSENT from function_return_taints (actual None) → "unknown",
    #        under_scan_reason=None → counts in `unknown` but NOT `engine_limited`.
    #  m.c — has a per-entity engine under-scan FACT → "unknown" WITH a reason →
    #        counts in BOTH `unknown` and `engine_limited`.
    entities = {
        "m.a": _entity("m.a", 1),
        "m.b": _entity("m.b", 4),
        "m.c": _entity("m.c", 7),
    }
    ctx = AnalysisContext(
        project_taints={},
        project_return_taints={
            "m.a": TaintState.INTEGRAL,
            "m.b": TaintState.INTEGRAL,
            "m.c": TaintState.INTEGRAL,
        },
        function_var_taints={},
        function_return_taints={
            "m.a": TaintState.INTEGRAL,
            "m.c": TaintState.INTEGRAL,
        },
        function_return_callee={},
        entities=MappingProxyType(entities),
        taint_provenance={},
        declared_qualnames=frozenset({"m.a", "m.b", "m.c"}),
    )
    under_scan = Finding(
        rule_id="WLN-ENGINE-FUNCTION-SKIPPED",
        message="recursion limit hit; entity skipped",
        severity=Severity.NONE,
        kind=Kind.FACT,
        location=Location(path="m.py", line_start=7),
        fingerprint="b" * 64,
        qualname="m.c",
    )
    result = ScanResult(
        findings=[under_scan],
        summary=ScanSummary(total=1, active=0, baselined=0, waived=0, judged=0),
        files_scanned=1,
        context=ctx,
    )

    posture = posture_from_scan(result, ctx, waivers=(), today=date(2026, 6, 3))
    got = posture.to_dict()

    assert got["boundaries_total"] == 3
    assert got["proven"] == 1
    assert len(got["unknown"]) == 2
    assert got["engine_limited"] == 1
    assert got["coverage_pct"] == round(100 * (3 - 2) / 3, 1) == 33.3
    # `unknown` is sorted by qualname: m.b before m.c.
    assert [u["qualname"] for u in got["unknown"]] == ["m.b", "m.c"]
    # m.b: no reason (absent actual), m.c: an under-scan reason.
    assert got["unknown"][0]["reason"] is None
    assert got["unknown"][1]["reason"] is not None and "recursion" in got["unknown"][1]["reason"]
    assert got["unknown"][0]["location"] == {"path": "m.py", "line": 4}
    assert "WLN-ENGINE-FUNCTION-SKIPPED" in got["unanalyzed_rule_ids"]


def test_empty_surface_coverage_is_null(tmp_path: Path) -> None:
    """An undecorated tree has no trust surface → coverage_pct must be None (null in
    JSON/MCP), not 100.0. A numeric 100.0 would read as "fully assured" to any agent
    using a numeric gate — a false-green (the project's #1 forbidden failure mode).

    Gates both the I/O shell (``build_posture``) and the ``_empty_posture`` helper
    directly, plus the ``posture_from_scan`` pure-core path with an empty
    ``declared_qualnames`` set.
    """
    # I/O shell path: real scan of a plain undecorated module.
    _PLAIN = "def f():\n    return 1\n"
    (tmp_path / "f.py").write_text(_PLAIN, encoding="utf-8")

    posture = build_posture(tmp_path, today=date(2026, 6, 3))
    got = posture.to_dict()

    assert got["boundaries_total"] == 0
    assert got["coverage_pct"] is None, (
        f"expected None but got {got['coverage_pct']!r}; "
        "a vacuous 100.0 reads as 'fully assured' to a numeric gate — false-green"
    )

    # _empty_posture helper path.
    from datetime import date as _date

    empty = _empty_posture(waivers=(), today=_date(2026, 6, 3))
    assert empty.coverage_pct is None
    assert empty.to_dict()["coverage_pct"] is None

    # posture_from_scan pure-core path with empty declared_qualnames.
    from types import MappingProxyType

    from wardline.core.run import ScanResult, ScanSummary

    empty_ctx = AnalysisContext(
        project_taints={},
        project_return_taints={},
        function_var_taints={},
        function_return_taints={},
        function_return_callee={},
        entities=MappingProxyType({}),
        taint_provenance={},
        declared_qualnames=frozenset(),
    )
    empty_result = ScanResult(
        findings=[],
        summary=ScanSummary(total=0, active=0, baselined=0, waived=0, judged=0),
        files_scanned=0,
        context=empty_ctx,
    )
    pure_posture = posture_from_scan(empty_result, empty_ctx, waivers=(), today=date(2026, 6, 3))
    assert pure_posture.coverage_pct is None
    assert pure_posture.to_dict()["coverage_pct"] is None
