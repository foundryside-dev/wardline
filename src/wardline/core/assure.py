# src/wardline/core/assure.py
"""The ``assure`` aggregator — trust-surface COVERAGE, not just defect count.

A defect report answers "what is wrong?"; ``assure`` answers the prior question a
fail-closed tool must own: "how much of the declared trust surface did the engine
reach a DEFINITE verdict on, and how much is honestly unknown?" The denominator is
the anchored (trust-declared) entities ONLY — undecorated code is the
developer-freedom zone and never counts.

Coverage measures "verdict reached EITHER WAY". A defect is COVERED: the engine
reached a definite (negative) verdict. The honesty gap is the ``unknown`` set —
entities whose trust could not be proven (no computed return taint, an undeclared /
``UNKNOWN_*`` tier, or an engine under-scan). ``engine_limited`` is the sub-count of
those that are unknown specifically because the engine under-scanned them (a parse /
recursion skip), as distinct from a developer simply not declaring trust.

Per-entity verdicts are delegated WHOLESALE to
:func:`wardline.core.dossier.classify_entity_trust` — the single source of truth —
so an ``assure`` rollup and a dossier ``TrustSection`` can never disagree.

Architecture: a PURE core (:func:`posture_from_scan`, no disk/scan) wrapped by an
I/O shell (:func:`build_posture`, loads config + waivers, runs the scan). The unit
test exercises the pure core directly. Zero-dependency: stdlib + existing wardline
modules only.

Determinism (the suite runs under ``pytest-randomly``): every list in the serialized
posture is sorted on a stable key — ``unknown`` by qualname, ``waiver_debt`` by
fingerprint, ``unanalyzed_rule_ids`` lexicographically.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import TYPE_CHECKING, Any

from wardline.core import config as config_mod
from wardline.core.dossier import UNDER_SCAN_RULE_IDS, classify_entity_trust
from wardline.core.run import run_scan
from wardline.core.waivers import Waiver, parse_waivers

if TYPE_CHECKING:
    from wardline.core.run import ScanResult
    from wardline.scanner.context import AnalysisContext


@dataclass(frozen=True, slots=True)
class UnknownBoundary:
    """One anchored entity whose trust verdict is "unknown" — the honesty gap.

    ``reason`` carries the engine under-scan FACT message when the body was not
    analysed (parse / recursion skip), else ``None`` (undeclared / unprovable)."""

    qualname: str
    tier: str | None  # declared tier, or None if undeclared
    path: str | None
    line: int | None
    reason: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "qualname": self.qualname,
            "tier": self.tier,
            "location": {"path": self.path, "line": self.line},
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class WaiverDebtEntry:
    """One configured waiver, with its days-to-expiry. ``days_left`` may be NEGATIVE
    (an expired waiver) — surfaced honestly, never dropped, so accepted debt that has
    lapsed its acceptance window stays visible. ``expires`` / ``days_left`` are
    ``None`` for a waiver with no expiry."""

    fingerprint: str
    expires: date | None
    days_left: int | None
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "expires": self.expires.isoformat() if self.expires is not None else None,
            "days_left": self.days_left,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class AssurancePosture:
    """The trust-surface coverage rollup. ``boundaries_total`` is the denominator
    (anchored entities only); ``proven`` + ``defect_total`` + ``len(unknown)`` ==
    ``boundaries_total``. ``coverage_pct`` is the share with a definite verdict
    (defects counted as covered); ``unknown`` is the honesty gap."""

    boundaries_total: int
    proven: int
    defect_total: int
    unknown: list[UnknownBoundary]
    engine_limited: int
    coverage_pct: float
    unanalyzed_rule_ids: list[str]
    waiver_debt: list[WaiverDebtEntry]
    baselined_total: int
    judged_total: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "boundaries_total": self.boundaries_total,
            "proven": self.proven,
            "defect_total": self.defect_total,
            "unknown": [u.to_dict() for u in self.unknown],
            "engine_limited": self.engine_limited,
            "coverage_pct": self.coverage_pct,
            "unanalyzed_rule_ids": list(self.unanalyzed_rule_ids),
            "waiver_debt": [w.to_dict() for w in self.waiver_debt],
            "baselined_total": self.baselined_total,
            "judged_total": self.judged_total,
        }


def _empty_posture(waivers: tuple[Waiver, ...], today: date) -> AssurancePosture:
    """An honest empty posture — no analysis context, so no trust surface to cover.

    ``coverage_pct`` is 100.0 by the same empty-denominator convention as a context
    with zero anchored entities: there is nothing left unknown. ``waiver_debt`` is
    DELIBERATELY still populated even on this branch — it is a config-level rollup
    independent of whether anything was analysable, so suppressing it would hide
    accepted debt behind an empty scan (a false-green). Every coverage list (``unknown``,
    ``unanalyzed_rule_ids``) is empty, as is correct with no surface analysed."""
    return AssurancePosture(
        boundaries_total=0,
        proven=0,
        defect_total=0,
        unknown=[],
        engine_limited=0,
        coverage_pct=100.0,
        unanalyzed_rule_ids=[],
        waiver_debt=_waiver_debt(waivers, today),
        baselined_total=0,
        judged_total=0,
    )


def _waiver_debt(waivers: tuple[Waiver, ...], today: date) -> list[WaiverDebtEntry]:
    """Roll up configured waivers into days-to-expiry entries, sorted by fingerprint.

    ``days_left`` is ``(expires - today).days`` — may be negative for a lapsed waiver
    (surfaced, not dropped). A waiver with no expiry carries ``None`` for both
    ``expires`` and ``days_left``."""
    entries = [
        WaiverDebtEntry(
            fingerprint=w.fingerprint,
            expires=w.expires,
            days_left=(w.expires - today).days if w.expires is not None else None,
            reason=w.reason,
        )
        for w in waivers
    ]
    return sorted(entries, key=lambda e: e.fingerprint)


def posture_from_scan(
    result: ScanResult,
    context: AnalysisContext,
    *,
    waivers: tuple[Waiver, ...],
    today: date,
) -> AssurancePosture:
    """Compute the coverage posture from an already-run scan — the PURE core.

    Iterates the anchored ``context.declared_qualnames`` (the denominator), classifies
    each via :func:`classify_entity_trust`, and tallies proven / defect / unknown.
    Coverage is the share with a definite verdict (defects covered); ``unknown`` is the
    honesty gap. No disk, no scan — exercised directly by the unit test."""
    boundaries_total = len(context.declared_qualnames)
    proven = 0
    defect_total = 0
    unknown: list[UnknownBoundary] = []
    engine_limited = 0

    for qualname in context.declared_qualnames:
        verdict = classify_entity_trust(result, context, qualname)
        if verdict.verdict == "clean":
            proven += 1
        elif verdict.verdict == "defect":
            defect_total += 1
        else:  # "unknown" — the honesty gap
            entity = context.entities.get(qualname)
            location = entity.location if entity is not None else None
            unknown.append(
                UnknownBoundary(
                    qualname=qualname,
                    tier=verdict.declared_tier,
                    path=location.path if location is not None else None,
                    line=location.line_start if location is not None else None,
                    reason=verdict.under_scan_reason,
                )
            )
            if verdict.under_scan_reason is not None:
                engine_limited += 1

    unknown.sort(key=lambda u: u.qualname)

    if boundaries_total == 0:
        coverage_pct = 100.0
    else:
        coverage_pct = round(100 * (boundaries_total - len(unknown)) / boundaries_total, 1)

    unanalyzed_rule_ids = sorted({f.rule_id for f in result.findings if f.rule_id in UNDER_SCAN_RULE_IDS})

    return AssurancePosture(
        boundaries_total=boundaries_total,
        proven=proven,
        defect_total=defect_total,
        unknown=unknown,
        engine_limited=engine_limited,
        coverage_pct=coverage_pct,
        unanalyzed_rule_ids=unanalyzed_rule_ids,
        waiver_debt=_waiver_debt(waivers, today),
        baselined_total=result.summary.baselined,
        judged_total=result.summary.judged,
    )


def build_posture(
    root: Path,
    *,
    config_path: Path | None = None,
    confine_to_root: bool = False,
    today: date | None = None,
) -> AssurancePosture:
    """Run a scan under ``root`` and return its trust-surface coverage posture — the
    I/O shell over :func:`posture_from_scan`.

    Loads config + waivers from the SAME path the scan uses (``config_path`` or
    ``root / "wardline.yaml"``) so the waiver rollup and the scan agree. When the scan
    yields no analysis context (nothing analysable), returns an honest empty posture
    rather than crashing."""
    if today is None:
        today = date.today()
    cfg_path = config_path or (root / "wardline.yaml")
    waivers = parse_waivers(config_mod.load(cfg_path).waivers)
    result = run_scan(root, config_path=config_path, confine_to_root=confine_to_root)
    if result.context is None:
        return _empty_posture(waivers, today)
    return posture_from_scan(result, result.context, waivers=waivers, today=today)
