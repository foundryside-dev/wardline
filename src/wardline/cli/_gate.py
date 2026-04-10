"""Scan gate logic — three-tier signal model.

The severity matrix (§8.3) assigns each (rule, taint) pair a severity:

- **SUPPRESS** — pattern is expected at this taint state.  Excluded from
  the CI gate.  Tracked as a diagnostic counter.
- **WARNING** — pattern is suspicious but does not block.  Excluded from
  the CI gate.  Tracked as a separate counter.
- **ERROR** — pattern violates the tier's integrity contract.  Blocks
  the CI gate unless governed by an exception.

This creates an economic incentive: promoting data to a higher tier
(via validation boundaries) removes findings.  Leaving raw data in
hot code paths is expensive.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from wardline.core.severity import Severity

if TYPE_CHECKING:
    from collections.abc import Sequence

    from wardline.scanner.context import Finding


@dataclass(frozen=True)
class SeverityBreakdown:
    """Severity counts for a set of findings."""

    error_count: int
    warning_count: int
    suppress_count: int
    excepted_count: int
    gate_blocking: int


def count_gate_blocking(findings: Sequence[Finding]) -> int:
    """Count findings that block the CI gate.

    Only ERROR-severity findings without an active exception are
    gate-blocking.  WARNING and SUPPRESS findings are visible in
    the SARIF output but do not affect the exit code.
    """
    return sum(
        1
        for f in findings
        if f.severity == Severity.ERROR and f.exception_id is None
    )


def severity_breakdown(findings: Sequence[Finding]) -> SeverityBreakdown:
    """Compute severity counts for stderr summary and SARIF run properties."""
    error_count = 0
    warning_count = 0
    suppress_count = 0
    excepted_count = 0

    for f in findings:
        if f.severity == Severity.ERROR:
            error_count += 1
            if f.exception_id is not None:
                excepted_count += 1
        elif f.severity == Severity.WARNING:
            warning_count += 1
        elif f.severity == Severity.SUPPRESS:
            suppress_count += 1

    gate_blocking = error_count - excepted_count
    return SeverityBreakdown(
        error_count=error_count,
        warning_count=warning_count,
        suppress_count=suppress_count,
        excepted_count=excepted_count,
        gate_blocking=gate_blocking,
    )
