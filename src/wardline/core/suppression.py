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
from wardline.core.judged import JudgedSet
from wardline.core.waivers import WaiverSet

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
        # Precedence: waiver (explicit human intent, carries expiry) > judged (LLM
        # FP-verdict, carries the rationale) > baseline (silent).
        waiver = waivers.match(f.fingerprint, today)
        judged_fp = judged.match(f.fingerprint)
        if waiver is not None:
            out.append(replace(f, suppressed=SuppressionState.WAIVED, suppression_reason=waiver.reason))
        elif judged_fp is not None:
            out.append(replace(f, suppressed=SuppressionState.JUDGED, suppression_reason=judged_fp.rationale))
        elif baseline.contains(f.fingerprint):
            out.append(replace(f, suppressed=SuppressionState.BASELINED))
        else:
            out.append(f)
    return out


def gate_trips(findings: Iterable[Finding], fail_on: Severity) -> bool:
    """True iff any ACTIVE Kind.DEFECT finding has severity >= fail_on."""
    threshold = _RANK[fail_on]
    for f in findings:
        if f.kind is not Kind.DEFECT or f.suppressed is not SuppressionState.ACTIVE:
            continue
        if f.maturity == Maturity.PREVIEW:
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
        if f.kind is not Kind.DEFECT or f.maturity == Maturity.PREVIEW:
            continue
        rank = _RANK.get(f.severity)
        if rank is None or rank < threshold:
            continue
        if f.suppressed is SuppressionState.ACTIVE:
            active += 1
        else:
            suppressed += 1
    return active, suppressed
