# src/wardline/core/triage.py
"""Triage orchestration (SP5): drive the judge over active DEFECTs.

Pure orchestration — the excerpt reader and the judge caller are injected, so the
whole flow is hermetic in tests. A transport failure (sibling outage) skips that
one finding and is counted, never crashes the run (charter: the judge is additive).
A ``JudgeContractError`` (malformed model output) is NOT caught here — it
propagates, because a corrupted audit primitive must surface.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from wardline.core.errors import DiscoveryError, JudgeTransportError
from wardline.core.finding import Finding, Kind, SuppressionState
from wardline.core.judge import JudgeRequest, JudgeResponse, JudgeVerdict


@dataclass(frozen=True, slots=True)
class TriageVerdict:
    finding: Finding
    response: JudgeResponse


@dataclass(frozen=True, slots=True)
class TriageResult:
    verdicts: list[TriageVerdict] = field(default_factory=list)
    n_skipped_cap: int = 0
    n_skipped_transport: int = 0
    n_skipped_excerpt: int = 0

    @property
    def n_true(self) -> int:
        return sum(1 for v in self.verdicts if v.response.verdict is JudgeVerdict.TRUE_POSITIVE)

    @property
    def n_false(self) -> int:
        return sum(1 for v in self.verdicts if v.response.verdict is JudgeVerdict.FALSE_POSITIVE)

    def false_positives(self) -> list[TriageVerdict]:
        return [v for v in self.verdicts if v.response.verdict is JudgeVerdict.FALSE_POSITIVE]


def finding_to_request(finding: Finding, *, excerpt: str) -> JudgeRequest:
    taint_summary = ", ".join(f"{k}={v}" for k, v in sorted(finding.properties.items())) or "(no taint detail)"
    assert finding.location.line_start is not None  # active DEFECTs always carry a line
    return JudgeRequest(
        rule_id=finding.rule_id,
        message=finding.message,
        severity=finding.severity.value,
        file_path=finding.location.path,
        line=finding.location.line_start,
        qualname=finding.qualname,
        fingerprint=finding.fingerprint,
        taint_summary=taint_summary,
        surrounding_code=excerpt,
    )


def run_triage(
    findings: Sequence[Finding],
    *,
    read_excerpt: Callable[[Finding], str],
    judge_caller: Callable[[JudgeRequest], JudgeResponse],
    max_findings: int | None = None,
) -> TriageResult:
    if max_findings is not None and max_findings <= 0:
        raise ValueError(f"max_findings must be positive, got {max_findings}")
    active = [f for f in findings if f.kind is Kind.DEFECT and f.suppressed is SuppressionState.ACTIVE]
    verdicts: list[TriageVerdict] = []
    n_cap = 0
    n_transport = 0
    n_excerpt = 0
    for i, finding in enumerate(active):
        if max_findings is not None and i >= max_findings:
            n_cap = len(active) - max_findings
            break
        # A per-finding excerpt failure (file moved/unreadable, path escape) is
        # recoverable: skip-and-count, mirroring the transport band. It must NOT abort
        # the whole run (which would discard verdicts already computed). A malformed
        # MODEL verdict still propagates (JudgeContractError uncaught) — that is the
        # audit primitive and must surface.
        try:
            excerpt = read_excerpt(finding)
        except DiscoveryError:
            n_excerpt += 1
            continue
        request = finding_to_request(finding, excerpt=excerpt)
        try:
            response = judge_caller(request)
        except JudgeTransportError:
            n_transport += 1
            continue
        verdicts.append(TriageVerdict(finding=finding, response=response))
    return TriageResult(
        verdicts=verdicts,
        n_skipped_cap=n_cap,
        n_skipped_transport=n_transport,
        n_skipped_excerpt=n_excerpt,
    )
