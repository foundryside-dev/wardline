"""Tests for PY-WL-008: Declared boundary with no rejection path."""

from __future__ import annotations

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.core.taints import TaintState
from wardline.manifest.models import BoundaryEntry
from wardline.scanner.context import ScanContext
from wardline.scanner.rules.py_wl_008 import RulePyWl008

from .conftest import parse_function_source, parse_module_source


def _run_rule(
    source: str,
    *,
    qualname: str = "target",
    taint: TaintState = TaintState.UNKNOWN_RAW,
    boundaries: tuple[BoundaryEntry, ...] = (),
    file_path: str = "/project/src/api/handler.py",
) -> RulePyWl008:
    """Parse source inside a function, set context, and run PY-WL-008."""
    tree = parse_function_source(source, name=qualname)
    rule = RulePyWl008(file_path=file_path)
    ctx = ScanContext(
        file_path=file_path,
        function_level_taint_map={qualname: taint},
        boundaries=boundaries,
    )
    rule.set_context(ctx)
    rule.visit(tree)
    return rule


def _run_rule_module(
    source: str,
    *,
    qualname: str = "target",
    taint: TaintState = TaintState.UNKNOWN_RAW,
    boundaries: tuple[BoundaryEntry, ...] = (),
    file_path: str = "/project/src/api/handler.py",
) -> RulePyWl008:
    """Parse raw module source, set context, and run PY-WL-008."""
    tree = parse_module_source(source)
    rule = RulePyWl008(file_path=file_path)
    ctx = ScanContext(
        file_path=file_path,
        function_level_taint_map={qualname: taint},
        boundaries=boundaries,
    )
    rule.set_context(ctx)
    rule.visit(tree)
    return rule


def _boundary(
    *,
    qualname: str = "target",
    transition: str = "shape_validation",
    overlay_scope: str = "/project/src/api",
) -> BoundaryEntry:
    """Build a boundary declaration for the current test function."""
    return BoundaryEntry(
        function=qualname,
        transition=transition,
        overlay_scope=overlay_scope,
    )


class TestDeclaredBoundaryRequired:
    """PY-WL-008 applies only to declared validation/restoration boundaries."""

    def test_non_boundary_function_is_silent(self) -> None:
        rule = _run_rule(
            """\
result = validate(data)
return data
"""
        )

        assert len(rule.findings) == 0

    def test_boundary_without_rejection_path_fires(self) -> None:
        rule = _run_rule(
            """\
result = validate(data)
return data
""",
            boundaries=(_boundary(),),
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_008
        assert rule.findings[0].severity == Severity.ERROR

    def test_semantic_boundary_without_rejection_path_fires(self) -> None:
        rule = _run_rule(
            """\
is_ok = check_business_rules(data)
process(data)
""",
            taint=TaintState.GUARDED,
            boundaries=(_boundary(transition="semantic_validation"),),
        )

        assert len(rule.findings) == 1

    def test_restoration_boundary_without_rejection_path_fires(self) -> None:
        rule = _run_rule(
            """\
record = deserialize(blob)
return record
""",
            boundaries=(_boundary(transition="restoration"),),
        )

        assert len(rule.findings) == 1

    def test_boundary_outside_overlay_scope_does_not_activate(self) -> None:
        rule = _run_rule(
            """\
result = validate(data)
return data
""",
            boundaries=(_boundary(overlay_scope="/project/src/other"),),
        )

        assert len(rule.findings) == 0


class TestStructuralRejectionPaths:
    """Spec-backed rejection paths suppress PY-WL-008."""

    def test_if_with_raise_silent(self) -> None:
        rule = _run_rule(
            """\
if not is_valid(data):
    raise ValueError("bad")
return data
""",
            boundaries=(_boundary(),),
        )

        assert len(rule.findings) == 0

    def test_assert_still_fires(self) -> None:
        rule = _run_rule(
            """\
assert is_valid(data)
return data
""",
            boundaries=(_boundary(),),
        )

        assert len(rule.findings) == 1

    def test_guarded_early_return_silent(self) -> None:
        rule = _run_rule(
            """\
if not valid:
    return None
return payload
""",
            boundaries=(_boundary(transition="restoration"),),
        )

        assert len(rule.findings) == 0

    def test_positive_guard_return_still_fires(self) -> None:
        rule = _run_rule(
            """\
if valid:
    return payload
return payload
""",
            boundaries=(_boundary(),),
        )

        assert len(rule.findings) == 1

    def test_bare_raise_silent(self) -> None:
        rule = _run_rule(
            """\
raise ValueError("invalid")
""",
            boundaries=(_boundary(),),
        )

        assert len(rule.findings) == 0


class TestDroppedHeuristics:
    """Old heuristic escapes are no longer accepted as rejection paths."""

    def test_rejection_like_helper_call_still_fires(self) -> None:
        rule = _run_rule(
            """\
result = validate(data)
abort_if_invalid(result)
return data
""",
            boundaries=(_boundary(),),
        )

        assert len(rule.findings) == 1

    def test_returning_validation_result_still_fires(self) -> None:
        rule = _run_rule(
            """\
result = validate(data)
return result
""",
            boundaries=(_boundary(),),
        )

        assert len(rule.findings) == 1


class TestDecoratorFallback:
    """Direct wardline decorators count as boundary declarations."""

    def test_validates_shape_decorator_without_context_fires(self) -> None:
        rule = _run_rule_module(
            """\
@validates_shape
def target():
    result = validate(data)
    return data
"""
        )

        assert len(rule.findings) == 1

    def test_restoration_boundary_decorator_with_rejection_is_silent(self) -> None:
        rule = _run_rule_module(
            """\
@restoration_boundary(restored_tier=3, structural_evidence=True)
def target():
    if not blob:
        raise ValueError("missing")
    return deserialize(blob)
"""
        )

        assert len(rule.findings) == 0


class TestRestorationBoundaryRejection:
    """Restoration boundaries must also have rejection paths."""

    def test_restoration_boundary_with_rejection_path_no_finding(self) -> None:
        rule = _run_rule(
            """\
if not isinstance(blob, bytes):
    raise TypeError("expected bytes")
record = deserialize(blob)
return record
""",
            boundaries=(_boundary(transition="restoration"),),
        )

        assert len(rule.findings) == 0

    def test_restoration_boundary_without_rejection_path_fires_finding(self) -> None:
        rule = _run_rule(
            """\
record = deserialize(blob)
return record
""",
            boundaries=(
                BoundaryEntry(
                    function="target",
                    transition="restoration",
                    restored_tier=2,
                    overlay_scope="/project/src/api",
                ),
            ),
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_008
        assert rule.findings[0].severity == Severity.ERROR
        assert rule.findings[0].exceptionability == Exceptionability.UNCONDITIONAL


class TestNestedAndAsyncBehavior:
    """Nested defs do not satisfy outer rejection requirements; async also works."""

    def test_nested_rejection_does_not_suppress_outer(self) -> None:
        rule = _run_rule_module(
            """\
def target():
    def helper():
        raise ValueError("bad")

    return data
""",
            boundaries=(_boundary(),),
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].line == 1

    def test_async_boundary_without_rejection_path_fires(self) -> None:
        rule = _run_rule_module(
            """\
async def target():
    await validate(data)
    return data
""",
            boundaries=(_boundary(),),
        )

        assert len(rule.findings) == 1


class TestTaintMatrix:
    """PY-WL-008 is ERROR/UNCONDITIONAL across all taint states."""

    def test_audit_trail_error_unconditional(self) -> None:
        rule = _run_rule(
            "return data\n",
            taint=TaintState.INTEGRAL,
            boundaries=(_boundary(),),
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].severity == Severity.ERROR
        assert rule.findings[0].exceptionability == Exceptionability.UNCONDITIONAL

    def test_external_raw_error_unconditional(self) -> None:
        rule = _run_rule(
            "return data\n",
            taint=TaintState.EXTERNAL_RAW,
            boundaries=(_boundary(),),
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].severity == Severity.ERROR
        assert rule.findings[0].exceptionability == Exceptionability.UNCONDITIONAL

    def test_pipeline_error_unconditional(self) -> None:
        rule = _run_rule(
            "return data\n",
            taint=TaintState.ASSURED,
            boundaries=(_boundary(),),
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].severity == Severity.ERROR
        assert rule.findings[0].exceptionability == Exceptionability.UNCONDITIONAL

    def test_mixed_raw_error_unconditional(self) -> None:
        rule = _run_rule(
            "return data\n",
            taint=TaintState.MIXED_RAW,
            boundaries=(_boundary(),),
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].severity == Severity.ERROR
        assert rule.findings[0].exceptionability == Exceptionability.UNCONDITIONAL


class TestDelegatedRejection:
    """Delegated rejection path resolution via rejection_path_index."""

    def test_nested_local_helper_resolves(self) -> None:
        """A nested helper function with a rejection path should suppress PY-WL-008."""
        source = """\
def target():
    def _check(data):
        if not data:
            raise ValueError("bad")
    _check(payload)
    return payload
"""
        tree = parse_module_source(source)
        rule = RulePyWl008(file_path="/project/src/api/handler.py")
        ctx = ScanContext(
            file_path="/project/src/api/handler.py",
            function_level_taint_map={"target": TaintState.UNKNOWN_RAW},
            boundaries=(_boundary(),),
            rejection_path_index=frozenset({
                "mymod.target._check",
            }),
            module_file_map={"mymod": "/project/src/api/handler.py"},
        )
        rule.set_context(ctx)
        rule.visit(tree)

        assert len(rule.findings) == 0

    def test_module_level_helper_still_resolves(self) -> None:
        """A module-level helper in the index should still resolve."""
        source = """\
def target():
    _validate(payload)
    return payload
"""
        tree = parse_module_source(source)
        rule = RulePyWl008(file_path="/project/src/api/handler.py")
        ctx = ScanContext(
            file_path="/project/src/api/handler.py",
            function_level_taint_map={"target": TaintState.UNKNOWN_RAW},
            boundaries=(_boundary(),),
            rejection_path_index=frozenset({
                "mymod._validate",
            }),
            module_file_map={"mymod": "/project/src/api/handler.py"},
        )
        rule.set_context(ctx)
        rule.visit(tree)

        assert len(rule.findings) == 0

    def test_nested_helper_not_in_index_still_fires(self) -> None:
        """A nested call not in the rejection index should still fire."""
        source = """\
def target():
    def _check(data):
        pass
    _check(payload)
    return payload
"""
        tree = parse_module_source(source)
        rule = RulePyWl008(file_path="/project/src/api/handler.py")
        ctx = ScanContext(
            file_path="/project/src/api/handler.py",
            function_level_taint_map={"target": TaintState.UNKNOWN_RAW},
            boundaries=(_boundary(),),
            rejection_path_index=frozenset(),
            module_file_map={"mymod": "/project/src/api/handler.py"},
        )
        rule.set_context(ctx)
        rule.visit(tree)

        assert len(rule.findings) == 1
