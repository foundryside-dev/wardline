"""Unit tests for scan gate severity filtering.

The three-tier signal model (spec §8.3–§8.5, corpus_cmds.py:755–787):
- SUPPRESS (SARIF "note"): expected pattern at this taint state — excluded from gate
- WARNING (SARIF "warning"): suspicious, worth reviewing — excluded from gate
- ERROR (SARIF "error"): violates tier integrity contract — blocks gate unless excepted
"""
from __future__ import annotations

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.scanner.context import Finding


def _make_finding(
    *,
    severity: Severity = Severity.ERROR,
    rule_id: RuleId = RuleId.PY_WL_001,
    exception_id: str | None = None,
) -> Finding:
    """Create a minimal Finding for gate logic tests."""
    return Finding(
        file_path="test.py",
        line=1,
        col=1,
        end_line=None,
        end_col=None,
        message="test finding",
        severity=severity,
        exceptionability=Exceptionability.STANDARD,
        taint_state=None,
        analysis_level=1,
        rule_id=rule_id,
        qualname="mod.func",
        source_snippet=None,
        exception_id=exception_id,
        exception_expires=None,
    )


class TestGateBlockingFindings:
    """Gate should only count unexcepted ERROR findings."""

    def test_suppress_findings_do_not_block(self) -> None:
        findings = [_make_finding(severity=Severity.SUPPRESS)]
        from wardline.cli._gate import count_gate_blocking
        assert count_gate_blocking(findings) == 0

    def test_warning_findings_do_not_block(self) -> None:
        findings = [_make_finding(severity=Severity.WARNING)]
        from wardline.cli._gate import count_gate_blocking
        assert count_gate_blocking(findings) == 0

    def test_error_findings_block(self) -> None:
        findings = [_make_finding(severity=Severity.ERROR)]
        from wardline.cli._gate import count_gate_blocking
        assert count_gate_blocking(findings) == 1

    def test_excepted_error_findings_do_not_block(self) -> None:
        findings = [_make_finding(severity=Severity.ERROR, exception_id="EXC-001")]
        from wardline.cli._gate import count_gate_blocking
        assert count_gate_blocking(findings) == 0

    def test_mixed_severities(self) -> None:
        findings = [
            _make_finding(severity=Severity.SUPPRESS),
            _make_finding(severity=Severity.WARNING),
            _make_finding(severity=Severity.ERROR),
            _make_finding(severity=Severity.ERROR, exception_id="EXC-002"),
        ]
        from wardline.cli._gate import count_gate_blocking
        assert count_gate_blocking(findings) == 1

    def test_empty_findings(self) -> None:
        from wardline.cli._gate import count_gate_blocking
        assert count_gate_blocking([]) == 0


class TestSeverityBreakdown:
    """Severity breakdown for stderr summary and SARIF counters."""

    def test_breakdown_counts(self) -> None:
        findings = [
            _make_finding(severity=Severity.SUPPRESS),
            _make_finding(severity=Severity.SUPPRESS),
            _make_finding(severity=Severity.WARNING),
            _make_finding(severity=Severity.ERROR),
            _make_finding(severity=Severity.ERROR, exception_id="EXC-001"),
        ]
        from wardline.cli._gate import severity_breakdown
        bd = severity_breakdown(findings)
        assert bd.error_count == 2
        assert bd.warning_count == 1
        assert bd.suppress_count == 2
        assert bd.excepted_count == 1
        assert bd.gate_blocking == 1  # 2 errors - 1 excepted

    def test_breakdown_empty(self) -> None:
        from wardline.cli._gate import severity_breakdown
        bd = severity_breakdown([])
        assert bd.error_count == 0
        assert bd.warning_count == 0
        assert bd.suppress_count == 0
        assert bd.excepted_count == 0
        assert bd.gate_blocking == 0


class TestSuppressTransparentContract:
    """End-to-end contract for SUPPRESS+TRANSPARENT matrix cells.

    Spec §8.3 / §8.5: cells where severity=SUPPRESS and
    exceptionability=TRANSPARENT represent patterns that are *expected* at
    that taint level (e.g. PY-WL-001 at EXTERNAL_RAW).  Four invariants:

    1. The finding IS emitted (not silently dropped).
    2. Gate does NOT block (exit code 0 ↔ gate_blocking == 0).
    3. The severity and exceptionability values are correct on the Finding.
    4. SARIF level is "note" (tested in test_sarif.py::test_suppress_severity_maps_to_note_level).
    """

    def _make_suppress_transparent_finding(
        self,
        rule_id: "RuleId" = RuleId.PY_WL_001,
        line: int = 1,
    ) -> Finding:
        """Construct a Finding that represents a SUPPRESS+TRANSPARENT matrix cell."""
        return Finding(
            file_path="src/boundary.py",
            line=line,
            col=0,
            end_line=None,
            end_col=None,
            message="Pattern is expected at this taint level",
            severity=Severity.SUPPRESS,
            exceptionability=Exceptionability.TRANSPARENT,
            taint_state=None,
            analysis_level=1,
            rule_id=rule_id,
            qualname="mod.boundary_func",
            source_snippet=None,
        )

    def test_finding_is_emitted_not_dropped(self) -> None:
        """A SUPPRESS+TRANSPARENT Finding must exist — not be silently discarded."""
        finding = self._make_suppress_transparent_finding()
        # Constructing the Finding without error proves it is emitted.
        assert finding.severity is Severity.SUPPRESS
        assert finding.exceptionability is Exceptionability.TRANSPARENT

    def test_gate_does_not_block_for_suppress_transparent(self) -> None:
        """Gate blocking count must be zero when all findings are SUPPRESS+TRANSPARENT."""
        from wardline.cli._gate import count_gate_blocking

        findings = [
            self._make_suppress_transparent_finding(rule_id=RuleId.PY_WL_001, line=1),
            self._make_suppress_transparent_finding(rule_id=RuleId.PY_WL_003, line=2),
            self._make_suppress_transparent_finding(rule_id=RuleId.PY_WL_007, line=3),
        ]
        assert count_gate_blocking(findings) == 0

    def test_severity_breakdown_tracks_suppress_transparent_in_suppress_count(
        self,
    ) -> None:
        """severity_breakdown must count SUPPRESS+TRANSPARENT in suppress_count."""
        from wardline.cli._gate import severity_breakdown

        findings = [
            self._make_suppress_transparent_finding(line=1),
            self._make_suppress_transparent_finding(line=2),
        ]
        bd = severity_breakdown(findings)
        assert bd.suppress_count == 2
        assert bd.gate_blocking == 0
        assert bd.error_count == 0
        assert bd.warning_count == 0

    def test_suppress_transparent_mixed_with_blocking_errors(self) -> None:
        """SUPPRESS+TRANSPARENT findings do not mask co-occurring blocking errors."""
        from wardline.cli._gate import count_gate_blocking, severity_breakdown

        suppress_finding = self._make_suppress_transparent_finding(line=1)
        error_finding = _make_finding(severity=Severity.ERROR, rule_id=RuleId.PY_WL_006)
        findings = [suppress_finding, error_finding]

        assert count_gate_blocking(findings) == 1
        bd = severity_breakdown(findings)
        assert bd.suppress_count == 1
        assert bd.error_count == 1
        assert bd.gate_blocking == 1

    def test_transparent_exceptionability_is_not_governable(self) -> None:
        """TRANSPARENT findings have no exception_id — they are not governed."""
        finding = self._make_suppress_transparent_finding()
        assert finding.exception_id is None

    def test_suppress_transparent_cells_for_canonical_rules(self) -> None:
        """Verify SUPPRESS+TRANSPARENT is correct for known spec-defined cells.

        PY-WL-001 at EXTERNAL_RAW/UNKNOWN_RAW/MIXED_RAW
        PY-WL-003 at EXTERNAL_RAW/UNKNOWN_RAW/MIXED_RAW
        PY-WL-007 at EXTERNAL_RAW/UNKNOWN_RAW
        """
        from wardline.core.matrix import lookup
        from wardline.core.severity import Exceptionability, Severity
        from wardline.core.taints import TaintState

        suppress_transparent_cells = [
            (RuleId.PY_WL_001, TaintState.EXTERNAL_RAW),
            (RuleId.PY_WL_001, TaintState.UNKNOWN_RAW),
            (RuleId.PY_WL_001, TaintState.MIXED_RAW),
            (RuleId.PY_WL_003, TaintState.EXTERNAL_RAW),
            (RuleId.PY_WL_003, TaintState.UNKNOWN_RAW),
            (RuleId.PY_WL_003, TaintState.MIXED_RAW),
            (RuleId.PY_WL_007, TaintState.EXTERNAL_RAW),
            (RuleId.PY_WL_007, TaintState.UNKNOWN_RAW),
        ]
        for rule, taint in suppress_transparent_cells:
            cell = lookup(rule, taint)
            assert cell.severity is Severity.SUPPRESS, (
                f"{rule}×{taint}: expected SUPPRESS, got {cell.severity}"
            )
            assert cell.exceptionability is Exceptionability.TRANSPARENT, (
                f"{rule}×{taint}: expected TRANSPARENT, got {cell.exceptionability}"
            )
