# src/wardline/core/suppression.py
"""Apply baseline + waivers to findings, and the ``--fail-on`` gate predicate (SP3).

Pure functions: ``today`` is injected so the whole layer is hermetic. Only
``Kind.DEFECT`` findings are suppressed or gated; an ACTIVE waiver wins over the
baseline (it carries the reason + expiry, keeping expiry observable).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace
from datetime import date

from wardline.core.baseline import Baseline
from wardline.core.finding import ENGINE_PATH, Finding, Kind, Maturity, Severity, SuppressionState
from wardline.core.finding_identity import resolve_identity
from wardline.core.judged import JudgedSet
from wardline.core.waivers import WaiverSet

_MATCH_STATE: dict[str, SuppressionState] = {
    "waiver": SuppressionState.WAIVED,
    "judged": SuppressionState.JUDGED,
    "baseline": SuppressionState.BASELINED,
}

# Ascending trust-cost order for the --fail-on threshold. NONE is absent — facts
# and metrics never participate in the gate.
SEVERITY_ORDER: tuple[Severity, ...] = (Severity.INFO, Severity.WARN, Severity.ERROR, Severity.CRITICAL)
_RANK: dict[Severity, int] = {s: i for i, s in enumerate(SEVERITY_ORDER)}


def apply_suppressions(
    findings: Iterable[Finding],
    baseline: Baseline,
    waivers: WaiverSet,
    *,
    today: date,
    judged: JudgedSet | None = None,
) -> list[Finding]:
    judged = judged if judged is not None else JudgedSet([])
    out: list[Finding] = []
    for f in findings:
        if f.kind is not Kind.DEFECT:
            out.append(f)
            continue
        if f.location.path != ENGINE_PATH and f.location.line_start is None:
            import hashlib

            digest = hashlib.sha256()
            digest.update(f"WLN-ENGINE-LINELESS-DEFECT\x00{f.rule_id}\x00{f.location.path}".encode())
            warning_fp = digest.hexdigest()
            out.append(
                Finding(
                    rule_id="WLN-ENGINE-LINELESS-DEFECT",
                    message=(
                        f"DEFECT {f.rule_id} on path {f.location.path} has line_start=None — "
                        f"skipped to avoid fingerprint collision risk"
                    ),
                    severity=Severity.NONE,
                    kind=Kind.FACT,
                    location=f.location,
                    fingerprint=warning_fp,
                    properties={"rule_id": f.rule_id, "original_kind": "DEFECT"},
                )
            )
            continue
        # Provisional-identity findings (preview rules whose fingerprint will shift in a
        # later slice — e.g. the Rust RS-WL-* frontend) are baseline-INELIGIBLE by contract:
        # a fingerprint-keyed baseline/waiver/judged entry pinned to them now would silently
        # orphan when the identity changes. Never match them — they stay ACTIVE, so they
        # always gate and a committed suppression can never (even under --trust-suppressions)
        # clear them. This is what the CLI's "provisional identity (baseline-ineligible)"
        # banner promises; the guarantee lives here, not just in prose.
        if f.properties.get("provisional_identity") is True:
            out.append(f)
            continue
        # Precedence (waiver > judged > baseline) lives in resolve_identity — the
        # single JOIN predicate. BASELINED carries no reason (matches the historical
        # inline behaviour); WAIVED/JUDGED carry the resolver's reason.
        resolution = resolve_identity(f.fingerprint, baseline=baseline, waivers=waivers, judged=judged, today=today)
        if resolution.matched_on is None:
            out.append(f)
        elif resolution.matched_on == "baseline":
            out.append(replace(f, suppressed=SuppressionState.BASELINED))
        else:
            out.append(replace(f, suppressed=_MATCH_STATE[resolution.matched_on], suppression_reason=resolution.reason))
    return out


def severity_gates(severity: Severity, fail_on: Severity) -> bool:
    """True iff ``severity`` is a known gate severity at or above the ``fail_on``
    threshold. NONE (facts/metrics, absent from ``_RANK``) never gates."""
    rank = _RANK.get(severity)
    return rank is not None and rank >= _RANK[fail_on]


def gate_trips(findings: Iterable[Finding], fail_on: Severity) -> bool:
    """True iff any ACTIVE Kind.DEFECT finding has severity >= fail_on."""
    threshold = _RANK[fail_on]
    for f in findings:
        if f.kind is not Kind.DEFECT or f.suppressed is not SuppressionState.ACTIVE:
            continue
        if f.maturity is Maturity.PREVIEW:
            continue
        rank = _RANK.get(f.severity)
        if rank is not None and rank >= threshold:
            return True
    return False


def gate_breakdown(findings: Iterable[Finding], fail_on: Severity) -> tuple[int, int]:
    """Count gate-relevant DEFECTs at/above ``fail_on`` in the ANNOTATED population,
    split into ``(active, suppressed)``.

    Same predicate as :func:`gate_trips` (DEFECT, non-PREVIEW, severity >= threshold)
    but counts instead of short-circuiting and partitions by whether the finding is
    ACTIVE or repository-suppressed (baselined / waived / judged). Lets the gate verdict
    say *which* population tripped it without re-deriving the rule. Under the secure
    default the suppressed count is exactly the set that gates only because suppressions
    are ignored — the number an agent clears with ``--trust-suppressions``/``--new-since``.
    """
    threshold = _RANK[fail_on]
    active = 0
    suppressed = 0
    for f in findings:
        if f.kind is not Kind.DEFECT or f.maturity is Maturity.PREVIEW:
            continue
        rank = _RANK.get(f.severity)
        if rank is None or rank < threshold:
            continue
        if f.suppressed is SuppressionState.ACTIVE:
            active += 1
        else:
            suppressed += 1
    return active, suppressed
