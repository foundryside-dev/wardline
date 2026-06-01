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
from wardline.core.finding import ENGINE_PATH, Finding, Kind, Severity, SuppressionState
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
        # Engine invariant (spec §12): a *rule* DEFECT (PY-WL-*) must carry a line,
        # or its line-based fingerprint's line discriminator collapses to "None" and
        # collision risk rises under the strict match. Rule findings always set
        # line_start; assert it to catch any future rule that emits a line-less DEFECT.
        # Engine-diagnostic DEFECTs (<engine> path, e.g. WLN-L3-MONOTONICITY-VIOLATION,
        # WLN-ENGINE-DIAGNOSTIC) are exempt: they are not tied to a source line and build
        # a line-independent fingerprint from identifying fields, so the invariant does
        # not apply — and they MUST surface (the "fail loud-but-survivable" safety net),
        # not abort the run.
        assert f.location.path == ENGINE_PATH or f.location.line_start is not None, (
            f"DEFECT {f.rule_id} entered suppression with line_start=None — weak fingerprint identity (collision risk)"
        )
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
        rank = _RANK.get(f.severity)
        if rank is not None and rank >= threshold:
            return True
    return False
