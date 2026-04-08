"""Tests for SCN-021 contradictory decorator-combination detection."""

from __future__ import annotations

import pytest

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.scanner.context import ScanContext, WardlineAnnotation
from wardline.scanner.rules.scn_021 import _COMBINATIONS, RuleScn021

from .conftest import parse_module_source


def _run_rule(
    source: str,
    *,
    qualname: str = "target",
    annotations: tuple[str, ...] | None = None,
    file_path: str = "/project/src/api/handler.py",
) -> RuleScn021:
    """Parse module source, set optional annotation context, and run SCN-021."""
    tree = parse_module_source(source)
    rule = RuleScn021(file_path=file_path)
    annotation_map = None
    if annotations is not None:
        annotation_map = {
            qualname: tuple(
                WardlineAnnotation(canonical_name=name, group=0, attrs={})
                for name in annotations
            )
        }
    rule.set_context(
        ScanContext(
            file_path=file_path,
            function_level_taint_map={qualname: None},  # type: ignore[arg-type]
            annotations_map=annotation_map,
        )
    )
    rule.visit(tree)
    return rule


class TestContradictoryCombinations:
    def test_fail_open_and_fail_closed_fire(self) -> None:
        rule = _run_rule(
            """\
@fail_open
@fail_closed
def target():
    return 1
"""
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.SCN_021
        assert rule.findings[0].severity == Severity.ERROR
        assert "@fail_open + @fail_closed" in rule.findings[0].message

    def test_exception_boundary_and_must_propagate_fire(self) -> None:
        rule = _run_rule(
            """\
@exception_boundary
@must_propagate
def target():
    return 1
"""
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].severity == Severity.ERROR

    def test_preserve_cause_and_exception_boundary_fire(self) -> None:
        rule = _run_rule(
            """\
@preserve_cause
@exception_boundary
def target():
    return 1
"""
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].severity == Severity.ERROR

    def test_data_flow_and_external_boundary_fire(self) -> None:
        """Entry #25: @data_flow + @external_boundary — contradictory flow direction."""
        rule = _run_rule(
            """\
@data_flow
@external_boundary
def target():
    return 1
""",
            annotations=("data_flow", "external_boundary"),
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].severity == Severity.ERROR
        assert "@data_flow" in rule.findings[0].message
        assert "@external_boundary" in rule.findings[0].message


class TestSuspiciousCombinations:
    def test_fail_open_and_deterministic_warn(self) -> None:
        rule = _run_rule(
            """\
@fail_open
@deterministic
def target():
    return 1
"""
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].severity == Severity.WARNING


class TestAnnotationContextResolution:
    def test_context_annotations_drive_detection_for_alias_imports(self) -> None:
        rule = _run_rule(
            """\
from wardline.decorators.operations import fail_open as fo
from wardline.decorators.operations import fail_closed as fc

@fo
@fc
def target():
    return 1
""",
            annotations=("fail_open", "fail_closed"),
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.SCN_021

    def test_single_decorator_is_silent(self) -> None:
        rule = _run_rule(
            """\
@fail_open
def target():
    return 1
"""
        )

        assert len(rule.findings) == 0


class TestAliasPairDedup:
    def test_fail_open_integrity_critical_produces_one_finding(self) -> None:
        """Entry #5 and #19 are the same pair — must produce exactly 1 finding."""
        rule = _run_rule(
            """\
@fail_open
@integrity_critical
def target():
    return 1
""",
            annotations=("fail_open", "integrity_critical"),
        )
        assert len(rule.findings) == 1
        assert rule.findings[0].severity == Severity.ERROR


class TestAllCombinations:
    @pytest.mark.parametrize(
        "spec",
        _COMBINATIONS,
        ids=[f"{s.left}+{s.right}" for s in _COMBINATIONS],
    )
    def test_combination_fires(self, spec) -> None:
        """Every entry in _COMBINATIONS must produce exactly 1 finding."""
        rule = _run_rule(
            f"""\
@{spec.left}
@{spec.right}
def target():
    return 1
""",
            annotations=(spec.left, spec.right),
        )
        findings = [f for f in rule.findings if f.rule_id == RuleId.SCN_021]
        assert len(findings) == 1, (
            f"Expected 1 finding for {spec.left}+{spec.right}, got {len(findings)}"
        )
        assert findings[0].severity == spec.severity
        assert findings[0].exceptionability == Exceptionability.UNCONDITIONAL


class TestNegativeCombinations:
    @pytest.mark.parametrize(
        "left,right",
        [
            ("fail_closed", "deterministic"),
            ("atomic", "fail_closed"),
            ("handles_pii", "integral_read"),
            ("thread_safe", "atomic"),
            ("test_only", "deprecated_by"),
            ("handles_secrets", "thread_safe"),
        ],
        ids=[f"{left}+{right}" for left, right in [
            ("fail_closed", "deterministic"),
            ("atomic", "fail_closed"),
            ("handles_pii", "integral_read"),
            ("thread_safe", "atomic"),
            ("test_only", "deprecated_by"),
            ("handles_secrets", "thread_safe"),
        ]],
    )
    def test_valid_combination_does_not_fire(self, left: str, right: str) -> None:
        rule = _run_rule(
            f"""\
@{left}
@{right}
def target():
    return 1
""",
            annotations=(left, right),
        )
        scn_findings = [f for f in rule.findings if f.rule_id == RuleId.SCN_021]
        assert len(scn_findings) == 0, (
            f"Valid combination {left}+{right} should not fire SCN-021"
        )


class TestSpecCoverage:
    """Verify _COMBINATIONS covers all 29 spec entries."""

    # Spec entries intentionally not in _COMBINATIONS:
    # #19: integrity_critical + fail_open — alias of #5, would duplicate
    _INTENTIONALLY_MISSING = frozenset({19})
    _SPEC_ENTRIES = frozenset(range(1, 30))  # 1..29

    def test_all_spec_entries_covered_or_documented(self) -> None:
        """Every spec entry is either in _COMBINATIONS or in _INTENTIONALLY_MISSING."""
        covered = {s.spec_entry for s in _COMBINATIONS if s.spec_entry is not None}
        expected = self._SPEC_ENTRIES - self._INTENTIONALLY_MISSING
        assert covered == expected, (
            f"Missing spec entries: {expected - covered}; "
            f"unexpected entries: {covered - expected}"
        )

    def test_extensions_have_no_spec_entry(self) -> None:
        """Implementation extensions must have spec_entry=None."""
        extensions = [s for s in _COMBINATIONS if s.spec_entry is None]
        assert len(extensions) == 5, (
            f"Expected 5 restoration_boundary extensions, got {len(extensions)}"
        )
        for ext in extensions:
            assert "restoration_boundary" in (ext.left, ext.right)

    def test_no_duplicate_spec_entries(self) -> None:
        """Each spec entry number appears at most once."""
        entries = [s.spec_entry for s in _COMBINATIONS if s.spec_entry is not None]
        assert len(entries) == len(set(entries)), (
            f"Duplicate spec entries: {[e for e in entries if entries.count(e) > 1]}"
        )
