# src/wardline/core/suppression.py
"""Apply baseline + waivers to findings, and the ``--fail-on`` gate predicate (SP3).

Pure functions: ``today`` is injected so the whole layer is hermetic. Only
``Kind.DEFECT`` findings are suppressed or gated; an ACTIVE waiver wins over the
baseline (it carries the reason + expiry, keeping expiry observable).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import replace
from datetime import date

from wardline.core.baseline import Baseline
from wardline.core.finding import ENGINE_PATH, Finding, Kind, Location, Severity, SuppressionState
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

# Intentionally empty. Any safe family must be registered here and exercise the
# explicit downgrade branch below with its own regression coverage.
_LINELESS_DEFECT_FACT_ALLOWLIST: frozenset[str] = frozenset()


def _allowlisted_lineless_defect_fact(finding: Finding) -> Finding:
    """Downgrade a specifically allowlisted lineless defect to an observable fact."""
    import hashlib

    identity = "\x00".join(("WLN-ENGINE-LINELESS-DEFECT", finding.rule_id, finding.location.path))
    return Finding(
        rule_id="WLN-ENGINE-LINELESS-DEFECT",
        message=(
            f"DEFECT {finding.rule_id} on path {finding.location.path} has line_start=None; "
            "skipped to avoid fingerprint collision risk"
        ),
        severity=Severity.NONE,
        kind=Kind.FACT,
        location=finding.location,
        fingerprint=hashlib.sha256(identity.encode("utf-8")).hexdigest(),
        properties={"rule_id": finding.rule_id, "original_kind": finding.kind.value},
    )


def _lineless_defect_diagnostic(finding: Finding) -> Finding:
    import hashlib

    identity = "\x00".join(
        (
            "WLN-ENGINE-LINELESS-DEFECT",
            finding.rule_id,
            finding.location.path,
            finding.fingerprint,
            finding.kind.value,
        )
    )
    properties: Mapping[str, str] = {
        "original_rule_id": finding.rule_id,
        "original_path": finding.location.path,
        "original_fingerprint": finding.fingerprint,
        "original_kind": finding.kind.value,
    }
    return Finding(
        rule_id="WLN-ENGINE-LINELESS-DEFECT",
        message=(
            f"DEFECT {finding.rule_id} on path {finding.location.path} has "
            "line_start=None; replaced with a gate-eligible engine diagnostic"
        ),
        severity=finding.severity,
        kind=Kind.DEFECT,
        location=Location(path=ENGINE_PATH),
        fingerprint=hashlib.sha256(identity.encode("utf-8")).hexdigest(),
        properties=properties,
    )


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
            if f.rule_id in _LINELESS_DEFECT_FACT_ALLOWLIST:
                out.append(_allowlisted_lineless_defect_fact(f))
            else:
                out.append(_lineless_defect_diagnostic(f))
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
        rank = _RANK.get(f.severity)
        if rank is not None and rank >= threshold:
            return True
    return False


def gate_breakdown(findings: Iterable[Finding], fail_on: Severity) -> tuple[int, int]:
    """Count gate-relevant DEFECTs at/above ``fail_on`` in the ANNOTATED population,
    split into ``(active, suppressed)``.

    Same predicate as :func:`gate_trips` (DEFECT, severity >= threshold) but counts
    instead of short-circuiting and partitions by whether the finding is
    ACTIVE or repository-suppressed (baselined / waived / judged). Lets the gate verdict
    say *which* population tripped it without re-deriving the rule. Under the secure
    default the suppressed count is exactly the set that gates only because suppressions
    are ignored — the number an agent clears with ``--trust-suppressions``/``--new-since``.
    """
    threshold = _RANK[fail_on]
    active = 0
    suppressed = 0
    for f in findings:
        if f.kind is not Kind.DEFECT:
            continue
        rank = _RANK.get(f.severity)
        if rank is None or rank < threshold:
            continue
        if f.suppressed is SuppressionState.ACTIVE:
            active += 1
        else:
            suppressed += 1
    return active, suppressed
