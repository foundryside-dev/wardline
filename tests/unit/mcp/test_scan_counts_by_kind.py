from __future__ import annotations

from wardline.core.finding import Finding, Kind, Location, Severity, SuppressionState
from wardline.mcp.server import _counts_by_kind


def _finding(
    kind: Kind,
    index: int,
    *,
    suppressed: SuppressionState = SuppressionState.ACTIVE,
) -> Finding:
    severity = Severity.ERROR if kind is Kind.DEFECT else Severity.NONE
    return Finding(
        rule_id=f"TEST-{index}",
        message=f"test finding {index}",
        severity=severity,
        kind=kind,
        location=Location(path="fixture.py", line_start=index + 1),
        fingerprint=f"fp-{index}",
        suppressed=suppressed,
    )


def test_counts_by_kind_uses_canonical_order_and_counts_suppressed_findings() -> None:
    findings = [
        _finding(Kind.DEFECT, 0),
        _finding(Kind.FACT, 1),
        _finding(Kind.CLASSIFICATION, 2),
        _finding(Kind.METRIC, 3),
        _finding(Kind.SUGGESTION, 4),
        _finding(Kind.DEFECT, 5, suppressed=SuppressionState.BASELINED),
    ]

    counts = _counts_by_kind(findings)

    assert list(counts) == [kind.value for kind in Kind]
    assert counts == {
        "defect": 2,
        "fact": 1,
        "classification": 1,
        "metric": 1,
        "suggestion": 1,
    }
    assert sum(counts.values()) == len(findings)


def test_counts_by_kind_zero_fills_absent_kinds() -> None:
    counts = _counts_by_kind([_finding(Kind.FACT, 0)])

    assert counts == {
        "defect": 0,
        "fact": 1,
        "classification": 0,
        "metric": 0,
        "suggestion": 0,
    }
