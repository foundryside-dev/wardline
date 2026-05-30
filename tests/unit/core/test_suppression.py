from __future__ import annotations

from datetime import date

from wardline.core.baseline import Baseline
from wardline.core.finding import Finding, Kind, Location, Severity, SuppressionState
from wardline.core.suppression import apply_suppressions, gate_trips
from wardline.core.waivers import WaiverSet, parse_waivers

_FP_A = "a" * 64
_FP_B = "b" * 64
_TODAY = date(2026, 5, 30)


def _defect(fp: str, *, sev: Severity = Severity.ERROR, kind: Kind = Kind.DEFECT) -> Finding:
    return Finding(
        rule_id="PY-WL-101", message="m", severity=sev, kind=kind,
        location=Location(path="src/m.py", line_start=1), fingerprint=fp,
    )


def _empty_baseline() -> Baseline:
    return Baseline(frozenset())


def _no_waivers() -> WaiverSet:
    return WaiverSet(())


def test_baselined_finding_is_annotated() -> None:
    out = apply_suppressions([_defect(_FP_A)], Baseline(frozenset({_FP_A})), _no_waivers(), today=_TODAY)
    assert out[0].suppressed is SuppressionState.BASELINED


def test_waived_finding_is_annotated_with_reason() -> None:
    ws = WaiverSet(parse_waivers([{"fingerprint": _FP_A, "reason": "fp"}]))
    out = apply_suppressions([_defect(_FP_A)], _empty_baseline(), ws, today=_TODAY)
    assert out[0].suppressed is SuppressionState.WAIVED
    assert out[0].suppression_reason == "fp"


def test_waiver_wins_over_baseline() -> None:
    ws = WaiverSet(parse_waivers([{"fingerprint": _FP_A, "reason": "fp"}]))
    out = apply_suppressions([_defect(_FP_A)], Baseline(frozenset({_FP_A})), ws, today=_TODAY)
    assert out[0].suppressed is SuppressionState.WAIVED  # waiver precedence keeps expiry observable


def test_expired_waiver_falls_back_to_active_or_baseline() -> None:
    ws = WaiverSet(parse_waivers([{"fingerprint": _FP_A, "reason": "fp", "expires": "2026-05-29"}]))
    # expired, not baselined -> stays ACTIVE (resurfaces)
    out = apply_suppressions([_defect(_FP_A)], _empty_baseline(), ws, today=_TODAY)
    assert out[0].suppressed is SuppressionState.ACTIVE
    # expired, but baselined -> baseline still suppresses
    out2 = apply_suppressions([_defect(_FP_A)], Baseline(frozenset({_FP_A})), ws, today=_TODAY)
    assert out2[0].suppressed is SuppressionState.BASELINED


def test_non_defect_passes_through_active() -> None:
    out = apply_suppressions(
        [_defect(_FP_A, kind=Kind.METRIC)], Baseline(frozenset({_FP_A})), _no_waivers(), today=_TODAY
    )
    assert out[0].suppressed is SuppressionState.ACTIVE  # only DEFECT is suppressed


def test_gate_trips_only_on_active_defect_at_or_above_threshold() -> None:
    # non-suppressed ERROR defect, fail-on ERROR -> trips
    assert gate_trips([_defect(_FP_A, sev=Severity.ERROR)], Severity.ERROR) is True
    # below threshold
    assert gate_trips([_defect(_FP_A, sev=Severity.WARN)], Severity.ERROR) is False
    # exactly at threshold (>=)
    assert gate_trips([_defect(_FP_A, sev=Severity.CRITICAL)], Severity.CRITICAL) is True


def test_gate_ignores_suppressed_and_nondefect_and_none() -> None:
    baselined = apply_suppressions([_defect(_FP_A)], Baseline(frozenset({_FP_A})), _no_waivers(), today=_TODAY)
    assert gate_trips(baselined, Severity.ERROR) is False           # suppressed ignored
    assert gate_trips([_defect(_FP_A, kind=Kind.FACT)], Severity.INFO) is False  # non-defect ignored
    assert gate_trips([_defect(_FP_A, sev=Severity.NONE)], Severity.INFO) is False  # NONE never gates
