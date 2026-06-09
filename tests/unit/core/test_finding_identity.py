"""P1 scheme-infra S8: the single JOIN predicate the suppression layer calls.

``resolve_identity`` factors the waiver > judged > baseline match (and its
reason) out of ``apply_suppressions`` into one place — so a later phase (P4) can
populate ``drifted_from`` without touching the suppression-layer signature. This
phase: ``drifted_from`` is always None.
"""

from __future__ import annotations

from datetime import UTC, date, datetime

from wardline.core.baseline import Baseline
from wardline.core.finding_identity import IdentityResolution, resolve_identity
from wardline.core.judged import JudgedFP, JudgedSet
from wardline.core.waivers import WaiverSet, parse_waivers

_FP = "a" * 64
_TODAY = date(2026, 5, 30)


def _waivers(reason: str = "human waiver", expires: str | None = None) -> WaiverSet:
    item: dict[str, object] = {"fingerprint": _FP, "reason": reason}
    if expires is not None:
        item["expires"] = expires
    return WaiverSet(parse_waivers([item]))


def _judged() -> JudgedSet:
    return JudgedSet(
        [
            JudgedFP(
                fingerprint=_FP,
                rule_id="PY-WL-101",
                path="src/m.py",
                message="m",
                rationale="over-taint floor",
                model_id="m",
                confidence=0.9,
                recorded_at=datetime(2026, 5, 30, tzinfo=UTC),
                policy_hash="sha256:x",
            )
        ]
    )


def test_waiver_wins_over_judged_and_baseline() -> None:
    r = resolve_identity(_FP, baseline=Baseline(frozenset({_FP})), waivers=_waivers(), judged=_judged(), today=_TODAY)
    assert r == IdentityResolution(matched=True, matched_on="waiver", drifted_from=None, reason="human waiver")


def test_judged_when_no_waiver() -> None:
    r = resolve_identity(
        _FP, baseline=Baseline(frozenset({_FP})), waivers=WaiverSet(()), judged=_judged(), today=_TODAY
    )
    assert r.matched is True
    assert r.matched_on == "judged"
    assert r.reason == "over-taint floor"
    assert r.drifted_from is None


def test_baseline_when_neither_waiver_nor_judged() -> None:
    r = resolve_identity(
        _FP, baseline=Baseline(frozenset({_FP})), waivers=WaiverSet(()), judged=JudgedSet([]), today=_TODAY
    )
    assert r.matched is True
    assert r.matched_on == "baseline"
    assert r.reason is None  # baseline carries no reason


def test_no_match_is_unmatched() -> None:
    r = resolve_identity(_FP, baseline=Baseline(frozenset()), waivers=WaiverSet(()), judged=JudgedSet([]), today=_TODAY)
    assert r == IdentityResolution(matched=False, matched_on=None, drifted_from=None, reason=None)


def test_expired_waiver_does_not_match_falls_to_baseline() -> None:
    r = resolve_identity(
        _FP,
        baseline=Baseline(frozenset({_FP})),
        waivers=_waivers(expires="2026-05-29"),  # expired before today
        judged=JudgedSet([]),
        today=_TODAY,
    )
    assert r.matched_on == "baseline"  # expired waiver is not a match


def test_drifted_from_is_none_this_phase() -> None:
    r = resolve_identity(
        _FP, baseline=Baseline(frozenset({_FP})), waivers=WaiverSet(()), judged=JudgedSet([]), today=_TODAY
    )
    assert r.drifted_from is None
