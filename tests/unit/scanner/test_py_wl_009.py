"""Tests for PY-WL-009: Semantic boundary without prior shape validation."""

from __future__ import annotations

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.core.taints import TaintState
from wardline.manifest.models import BoundaryEntry
from wardline.scanner.context import ScanContext
from wardline.scanner.rules.py_wl_009 import RulePyWl009

from .conftest import parse_function_source, parse_module_source


def _run_rule(
    source: str,
    *,
    qualname: str = "target",
    taint: TaintState = TaintState.ASSURED,
    boundaries: tuple[BoundaryEntry, ...] = (),
    file_path: str = "/project/src/api/handler.py",
) -> RulePyWl009:
    """Parse source inside a function, set context, and run PY-WL-009."""
    tree = parse_function_source(source, name=qualname)
    rule = RulePyWl009(file_path=file_path)
    rule.set_context(
        ScanContext(
            file_path=file_path,
            function_level_taint_map={qualname: taint},
            boundaries=boundaries,
        )
    )
    rule.visit(tree)
    return rule


def _run_rule_module(
    source: str,
    *,
    qualname: str = "target",
    taint: TaintState = TaintState.ASSURED,
    boundaries: tuple[BoundaryEntry, ...] = (),
    file_path: str = "/project/src/api/handler.py",
) -> RulePyWl009:
    """Parse raw module source, set context, and run PY-WL-009."""
    tree = parse_module_source(source)
    rule = RulePyWl009(file_path=file_path)
    rule.set_context(
        ScanContext(
            file_path=file_path,
            function_level_taint_map={qualname: taint},
            boundaries=boundaries,
        )
    )
    rule.visit(tree)
    return rule


def _boundary(
    *,
    qualname: str = "target",
    transition: str = "semantic_validation",
    overlay_scope: str = "/project/src/api",
) -> BoundaryEntry:
    """Build a boundary declaration for the current test function."""
    return BoundaryEntry(
        function=qualname,
        transition=transition,
        overlay_scope=overlay_scope,
    )


class TestDeclaredBoundaryRequired:
    """PY-WL-009 applies only to declared semantic-validation boundaries."""

    def test_non_boundary_function_is_silent(self) -> None:
        rule = _run_rule(
            """\
if data["amount"] > 100:
    reject()
"""
        )

        assert len(rule.findings) == 0

    def test_semantic_boundary_without_shape_evidence_fires(self) -> None:
        rule = _run_rule(
            """\
if data["amount"] > 100:
    reject()
""",
            boundaries=(_boundary(),),
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_009
        assert rule.findings[0].severity == Severity.ERROR

    def test_combined_boundary_is_silent(self) -> None:
        rule = _run_rule(
            """\
if data["amount"] > 100:
    reject()
""",
            boundaries=(_boundary(transition="combined_validation"),),
        )

        assert len(rule.findings) == 0

    def test_semantic_boundary_outside_overlay_scope_does_not_activate(self) -> None:
        rule = _run_rule(
            """\
if data["amount"] > 100:
    reject()
""",
            boundaries=(_boundary(overlay_scope="/project/src/other"),),
        )

        assert len(rule.findings) == 0


class TestLocalShapeEvidence:
    """Local shape-validation evidence still suppresses within semantic boundaries."""

    def test_isinstance_in_conditional_before_semantic_check_silent(self) -> None:
        rule = _run_rule(
            """\
if not isinstance(data, dict):
    raise TypeError("expected dict")
if data["amount"] > MAX_AMOUNT:
    raise ValueError("too large")
""",
            boundaries=(_boundary(),),
        )

        assert len(rule.findings) == 0

    def test_bare_isinstance_expression_does_not_suppress(self) -> None:
        """A bare isinstance() whose result is discarded is not shape evidence.

        This prevents evasion by placing `isinstance(data, object)` as a
        standalone expression before semantic checks.
        """
        rule = _run_rule(
            """\
isinstance(data, dict)
if data["amount"] > MAX_AMOUNT:
    raise ValueError("too large")
""",
            boundaries=(_boundary(),),
        )

        assert len(rule.findings) >= 1

    def test_validate_schema_call_before_silent(self) -> None:
        rule = _run_rule(
            """\
validate_schema(data)
if data["amount"] > MAX_AMOUNT:
    raise ValueError("too large")
""",
            boundaries=(_boundary(),),
        )

        assert len(rule.findings) == 0

    def test_inline_membership_guard_silent(self) -> None:
        rule = _run_rule(
            """\
if "amount" in data and data["amount"] > MAX_AMOUNT:
    raise ValueError("too large")
""",
            boundaries=(_boundary(),),
        )

        assert len(rule.findings) == 0

    def test_shape_check_on_wrong_variable_still_fires(self) -> None:
        """Shape validation on a different variable does not suppress.

        ``isinstance(other, dict)`` validates ``other``, not ``data``.
        The semantic check on ``data["amount"]`` is still unguarded.
        """
        rule = _run_rule(
            """\
if not isinstance(other, dict):
    raise TypeError("expected dict")
if data["amount"] > MAX_AMOUNT:
    raise ValueError("too large")
""",
            boundaries=(_boundary(),),
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_009

    def test_shape_check_on_correct_variable_suppresses(self) -> None:
        """Shape validation on the same variable suppresses the finding."""
        rule = _run_rule(
            """\
if not isinstance(other, dict):
    raise TypeError("expected dict")
validate_schema(data)
if data["amount"] > MAX_AMOUNT:
    raise ValueError("too large")
""",
            boundaries=(_boundary(),),
        )

        assert len(rule.findings) == 0

    def test_validate_schema_on_wrong_variable_still_fires(self) -> None:
        """validate_schema(other) does not suppress a finding about data."""
        rule = _run_rule(
            """\
validate_schema(other)
if data["amount"] > MAX_AMOUNT:
    raise ValueError("too large")
""",
            boundaries=(_boundary(),),
        )

        assert len(rule.findings) == 1


class TestDecoratorFallback:
    """Direct wardline decorators count as boundary declarations."""

    def test_validates_semantic_decorator_fires_without_context(self) -> None:
        rule = _run_rule_module(
            """\
@validates_semantic
def target():
    if data["amount"] > 100:
        reject()
"""
        )

        assert len(rule.findings) == 1

    def test_validates_external_decorator_suppresses_without_context(self) -> None:
        rule = _run_rule_module(
            """\
@validates_external
def target():
    if data["amount"] > 100:
        reject()
"""
        )

        assert len(rule.findings) == 0


class TestNestedAndAsyncBehavior:
    """Nested scopes and async functions behave correctly."""

    def test_shape_check_in_nested_def_does_not_suppress_outer(self) -> None:
        rule = _run_rule_module(
            """\
def target():
    def helper():
        isinstance(data, dict)

    if data["amount"] > 100:
        reject()
""",
            boundaries=(_boundary(),),
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].line == 5

    def test_async_semantic_boundary_fires(self) -> None:
        rule = _run_rule_module(
            """\
async def target():
    if data["amount"] > 100:
        reject()
""",
            boundaries=(_boundary(),),
        )

        assert len(rule.findings) == 1


class TestSubscriptOnlyScope:
    """Attribute-only semantic checks remain outside this rule's scope."""

    def test_attribute_access_only_is_silent(self) -> None:
        rule = _run_rule(
            """\
if dto.amount > 100:
    reject()
""",
            boundaries=(_boundary(),),
        )

        assert len(rule.findings) == 0


class TestTaintMatrix:
    """PY-WL-009 is ERROR/UNCONDITIONAL across all taint states."""

    _SRC = """\
if data["amount"] > 100:
    reject()
"""

    def test_audit_trail_error_unconditional(self) -> None:
        rule = _run_rule(
            self._SRC,
            taint=TaintState.INTEGRAL,
            boundaries=(_boundary(),),
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].severity == Severity.ERROR
        assert rule.findings[0].exceptionability == Exceptionability.UNCONDITIONAL

    def test_unknown_shape_validated_error_unconditional(self) -> None:
        rule = _run_rule(
            self._SRC,
            taint=TaintState.UNKNOWN_GUARDED,
            boundaries=(_boundary(),),
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].severity == Severity.ERROR
        assert rule.findings[0].exceptionability == Exceptionability.UNCONDITIONAL

    def test_external_raw_error_unconditional(self) -> None:
        rule = _run_rule(
            self._SRC,
            taint=TaintState.EXTERNAL_RAW,
            boundaries=(_boundary(),),
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].severity == Severity.ERROR
        assert rule.findings[0].exceptionability == Exceptionability.UNCONDITIONAL

    def test_mixed_raw_error_unconditional(self) -> None:
        rule = _run_rule(
            self._SRC,
            taint=TaintState.MIXED_RAW,
            boundaries=(_boundary(),),
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].severity == Severity.ERROR
        assert rule.findings[0].exceptionability == Exceptionability.UNCONDITIONAL
