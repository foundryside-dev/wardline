from __future__ import annotations

from datetime import UTC, date, datetime

from wardline.core.baseline import Baseline
from wardline.core.finding import Finding, Kind, Location, Severity, SuppressionState
from wardline.core.judged import JudgedFP, JudgedSet
from wardline.core.suppression import apply_suppressions, gate_trips
from wardline.core.waivers import WaiverSet, parse_waivers

_FP_A = "a" * 64
_FP_B = "b" * 64
_TODAY = date(2026, 5, 30)


def _defect(fp: str, *, sev: Severity = Severity.ERROR, kind: Kind = Kind.DEFECT) -> Finding:
    return Finding(
        rule_id="PY-WL-101",
        message="m",
        severity=sev,
        kind=kind,
        location=Location(path="src/m.py", line_start=1),
        fingerprint=fp,
    )


def _empty_baseline() -> Baseline:
    return Baseline(frozenset())


def _no_waivers() -> WaiverSet:
    return WaiverSet(())


def test_defect_without_line_start_is_rejected() -> None:
    # Spec §12 invariant: a DEFECT entering suppression must carry line_start.
    bad = Finding(
        rule_id="PY-WL-101",
        message="m",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="src/m.py", line_start=None),
        fingerprint=_FP_A,
    )
    out = apply_suppressions([bad], _empty_baseline(), _no_waivers(), today=_TODAY)
    assert len(out) == 1
    assert out[0].rule_id == "WLN-ENGINE-LINELESS-DEFECT"
    assert out[0].kind == Kind.FACT


def test_engine_diagnostic_defect_without_line_start_surfaces() -> None:
    # Engine-diagnostic DEFECTs (<engine> path) build a line-independent
    # fingerprint; the line invariant must NOT apply, and they must surface.
    eng = Finding(
        rule_id="WLN-L3-MONOTONICITY-VIOLATION",
        message="monotone invariant broke",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="<engine>", line_start=None),
        fingerprint=_FP_A,
    )
    out = apply_suppressions([eng], _empty_baseline(), _no_waivers(), today=_TODAY)
    assert len(out) == 1
    assert out[0].rule_id == "WLN-L3-MONOTONICITY-VIOLATION"
    assert out[0].suppressed is SuppressionState.ACTIVE  # surfaces, not dropped


def test_collision_diagnostic_survives_suppression_and_trips_gate() -> None:
    # End-to-end posture lock for the no-collision guard (wardline-8fb773a7af):
    # the real build_collision_findings output is a lineless ENGINE_PATH ERROR
    # DEFECT. It must NOT be downgraded to a non-gating FACT (the lineless
    # downgrade exempts <engine>) and it MUST trip --fail-on ERROR — otherwise the
    # guard would be loud-but-ignorable and the masked finding stays hidden.
    from wardline.scanner.diagnostics import build_collision_findings

    fp = "f" * 64
    a = Finding("PY-WL-114", "first", Severity.ERROR, Kind.DEFECT, Location("a.py", 3), fp)
    b = Finding("PY-WL-114", "second", Severity.ERROR, Kind.DEFECT, Location("a.py", 3), fp)
    diags = build_collision_findings([a, b])
    assert len(diags) == 1 and diags[0].rule_id == "WLN-ENGINE-FINGERPRINT-COLLISION"

    out = apply_suppressions(diags, _empty_baseline(), _no_waivers(), today=_TODAY)
    assert out[0].rule_id == "WLN-ENGINE-FINGERPRINT-COLLISION"  # NOT downgraded
    assert out[0].kind is Kind.DEFECT
    assert out[0].suppressed is SuppressionState.ACTIVE
    assert gate_trips(out, Severity.ERROR) is True


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


def _judged(fp: str) -> JudgedFP:
    return JudgedFP(
        fingerprint=fp,
        rule_id="PY-WL-101",
        path="src/m.py",
        message="m",
        rationale="over-taint floor",
        model_id="m",
        confidence=0.9,
        recorded_at=datetime(2026, 5, 30, tzinfo=UTC),
        policy_hash="sha256:x",
    )


def test_judged_fp_is_suppressed_with_rationale() -> None:
    out = apply_suppressions(
        [_defect(_FP_A)],
        _empty_baseline(),
        _no_waivers(),
        today=_TODAY,
        judged=JudgedSet([_judged(_FP_A)]),
    )
    assert out[0].suppressed is SuppressionState.JUDGED
    assert out[0].suppression_reason == "over-taint floor"


def test_waiver_wins_over_judged() -> None:
    ws = WaiverSet(parse_waivers([{"fingerprint": _FP_A, "reason": "human waiver"}]))
    out = apply_suppressions(
        [_defect(_FP_A)],
        _empty_baseline(),
        ws,
        today=_TODAY,
        judged=JudgedSet([_judged(_FP_A)]),
    )
    assert out[0].suppressed is SuppressionState.WAIVED


def test_judged_wins_over_baseline() -> None:
    out = apply_suppressions(
        [_defect(_FP_A)],
        Baseline(frozenset({_FP_A})),
        _no_waivers(),
        today=_TODAY,
        judged=JudgedSet([_judged(_FP_A)]),
    )
    assert out[0].suppressed is SuppressionState.JUDGED


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
    assert gate_trips(baselined, Severity.ERROR) is False  # suppressed ignored
    assert gate_trips([_defect(_FP_A, kind=Kind.FACT)], Severity.INFO) is False  # non-defect ignored
    assert gate_trips([_defect(_FP_A, sev=Severity.NONE)], Severity.INFO) is False  # NONE never gates
