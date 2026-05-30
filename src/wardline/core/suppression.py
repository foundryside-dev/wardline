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
from wardline.core.finding import Finding, Kind, Severity, SuppressionState
from wardline.core.waivers import WaiverSet

# Ascending trust-cost order for the --fail-on threshold. NONE is absent — facts
# and metrics never participate in the gate.
SEVERITY_ORDER: tuple[Severity, ...] = (Severity.INFO, Severity.WARN, Severity.ERROR, Severity.CRITICAL)
_RANK: dict[Severity, int] = {s: i for i, s in enumerate(SEVERITY_ORDER)}


def apply_suppressions(
    findings: Iterable[Finding], baseline: Baseline, waivers: WaiverSet, *, today: date
) -> list[Finding]:
    out: list[Finding] = []
    for f in findings:
        if f.kind is not Kind.DEFECT:
            out.append(f)
            continue
        # Engine invariant (spec §12): a DEFECT must carry a line, or its fingerprint's
        # line discriminator collapses to "None" and collision risk rises under the
        # strict match. Rule findings always set line_start; assert it to catch any
        # future rule that emits a line-less DEFECT.
        assert f.location.line_start is not None, (
            f"DEFECT {f.rule_id} entered suppression with line_start=None — "
            f"weak fingerprint identity (collision risk)"
        )
        waiver = waivers.match(f.fingerprint, today)
        if waiver is not None:
            out.append(replace(f, suppressed=SuppressionState.WAIVED, suppression_reason=waiver.reason))
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
