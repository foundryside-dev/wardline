"""Tests for PY-WL-001: Dict key access with fallback default."""

from __future__ import annotations

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.manifest.models import BoundaryEntry, OptionalFieldEntry
from wardline.scanner.context import ScanContext
from wardline.scanner.rules.py_wl_001 import RulePyWl001

from .conftest import parse_function_source, parse_module_source


def _run_rule(source: str) -> RulePyWl001:
    """Parse source inside a function and run PY-WL-001."""
    tree = parse_function_source(source)
    rule = RulePyWl001(file_path="test.py")
    rule.visit(tree)
    return rule


def _run_rule_module(source: str) -> RulePyWl001:
    """Parse raw module source and run PY-WL-001."""
    tree = parse_module_source(source)
    rule = RulePyWl001(file_path="test.py")
    rule.visit(tree)
    return rule


def _run_rule_with_context(
    source: str,
    *,
    boundaries: tuple[BoundaryEntry, ...] = (),
    optional_fields: tuple[OptionalFieldEntry, ...] = (),
    file_path: str = "/project/src/adapters/handler.py",
) -> RulePyWl001:
    """Parse source inside a function, set context with boundaries, run rule."""
    tree = parse_function_source(source)
    rule = RulePyWl001(file_path=file_path)
    ctx = ScanContext(
        file_path=file_path,
        function_level_taint_map={},
        boundaries=boundaries,
        optional_fields=optional_fields,
    )
    rule.set_context(ctx)
    rule.visit(tree)
    return rule


# ── Positive: .get() with default ────────────────────────────────


class TestGetWithDefault:
    """``d.get(key, default)`` fires PY-WL-001."""

    def test_get_with_default_fires(self) -> None:
        rule = _run_rule('d.get("key", "fallback")\n')

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001
        assert rule.findings[0].severity == Severity.SUPPRESS

    def test_get_with_none_default_fires(self) -> None:
        rule = _run_rule('d.get("key", None)\n')

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001

    def test_get_with_variable_default_fires(self) -> None:
        rule = _run_rule('d.get("key", fallback_value)\n')

        assert len(rule.findings) == 1


# ── Negative: .get() without default ─────────────────────────────


class TestGetWithoutDefault:
    """``d.get(key)`` (no default) does NOT fire PY-WL-001."""

    def test_get_without_default_silent(self) -> None:
        rule = _run_rule('d.get("key")\n')

        assert len(rule.findings) == 0

    def test_get_no_args_silent(self) -> None:
        """Edge case: .get() with no args (will fail at runtime, not our problem)."""
        rule = _run_rule("d.get()\n")

        assert len(rule.findings) == 0


# ── Positive: .pop() ────────────────────────────────────────────


class TestPop:
    """``d.pop(key, default)`` fires PY-WL-001 (value fabrication)."""

    def test_pop_with_default_fires(self) -> None:
        rule = _run_rule('d.pop("key", None)\n')

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001

    def test_pop_with_complex_default_fires(self) -> None:
        rule = _run_rule('d.pop("key", [])\n')

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001

    def test_pop_one_arg_silent(self) -> None:
        """pop with only key arg raises KeyError on miss — no fabrication."""
        rule = _run_rule('d.pop("key")\n')

        assert len(rule.findings) == 0

    def test_pop_no_args_silent(self) -> None:
        """Edge case: .pop() with no args — not our problem."""
        rule = _run_rule("d.pop()\n")

        assert len(rule.findings) == 0


# ── Positive: .setdefault() ──────────────────────────────────────


class TestSetdefault:
    """``d.setdefault(key, default)`` fires PY-WL-001."""

    def test_setdefault_with_default_fires(self) -> None:
        rule = _run_rule('d.setdefault("key", [])\n')

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001

    def test_setdefault_one_arg_silent(self) -> None:
        """setdefault with only key arg doesn't fire."""
        rule = _run_rule('d.setdefault("key")\n')

        assert len(rule.findings) == 0


# ── Positive: defaultdict ────────────────────────────────────────


class TestDefaultdict:
    """``defaultdict(factory)`` fires PY-WL-001."""

    def test_defaultdict_with_factory_fires(self) -> None:
        rule = _run_rule("defaultdict(list)\n")

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001

    def test_defaultdict_with_lambda_fires(self) -> None:
        rule = _run_rule("defaultdict(lambda: 0)\n")

        assert len(rule.findings) == 1

    def test_defaultdict_no_args_silent(self) -> None:
        """No-arg defaultdict has None factory (raises KeyError, no fabrication)."""
        rule = _run_rule("defaultdict()\n")

        assert len(rule.findings) == 0

    def test_collections_defaultdict_fires(self) -> None:
        """collections.defaultdict(list) fires."""
        rule = _run_rule("collections.defaultdict(list)\n")

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001


# ── schema_default() suppression ─────────────────────────────────


class TestSchemaDefaultGoverned:
    """schema_default() with matching boundary -> SUPPRESS (governed)."""

    def test_wrapped_get_with_boundary_and_optional_field_suppresses(self) -> None:
        boundary = BoundaryEntry(
            function="target",
            transition="shape_validation",
            overlay_scope="/project/src/adapters",
        )
        optional_field = OptionalFieldEntry(
            field="key",
            approved_default="fallback",
            rationale="Optional by partner contract",
            overlay_scope="/project/src/adapters",
        )
        rule = _run_rule_with_context(
            'schema_default(d.get("key", "fallback"))\n',
            boundaries=(boundary,),
            optional_fields=(optional_field,),
        )
        assert len(rule.findings) == 1
        f = rule.findings[0]
        assert f.rule_id == RuleId.PY_WL_001_GOVERNED_DEFAULT
        assert f.severity == Severity.SUPPRESS
        assert f.exceptionability == Exceptionability.TRANSPARENT

    def test_matching_scope_suppresses(self) -> None:
        """Positive test: file within non-empty overlay scope -> SUPPRESS."""
        boundary = BoundaryEntry(
            function="target",
            transition="validates_external",
            overlay_scope="/project/src/adapters",
        )
        optional_field = OptionalFieldEntry(
            field="key",
            approved_default="x",
            rationale="Optional by contract",
            overlay_scope="/project/src/adapters",
        )
        rule = _run_rule_with_context(
            'schema_default(d.get("key", "x"))\n',
            boundaries=(boundary,),
            optional_fields=(optional_field,),
            file_path="/project/src/adapters/handler.py",
        )
        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001_GOVERNED_DEFAULT

    def test_class_method_with_boundary_suppresses(self) -> None:
        source = '''
class MyClass:
    def handle(self):
        schema_default(d.get("key", "x"))
'''
        tree = parse_module_source(source)
        boundary = BoundaryEntry(
            function="MyClass.handle",
            transition="shape_validation",
            overlay_scope="/project/src/adapters",
        )
        optional_field = OptionalFieldEntry(
            field="key",
            approved_default="x",
            rationale="Optional by contract",
            overlay_scope="/project/src/adapters",
        )
        rule = RulePyWl001(file_path="/project/src/adapters/handler.py")
        ctx = ScanContext(
            file_path="/project/src/adapters/handler.py",
            function_level_taint_map={},
            boundaries=(boundary,),
            optional_fields=(optional_field,),
        )
        rule.set_context(ctx)
        rule.visit(tree)
        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001_GOVERNED_DEFAULT

    def test_most_specific_optional_field_scope_wins(self) -> None:
        parent_boundary = BoundaryEntry(
            function="target",
            transition="shape_validation",
            overlay_scope="/project/src",
        )
        child_boundary = BoundaryEntry(
            function="target",
            transition="shape_validation",
            overlay_scope="/project/src/adapters",
        )
        parent_optional_field = OptionalFieldEntry(
            field="key",
            approved_default="parent-default",
            rationale="Parent scope",
            overlay_scope="/project/src",
        )
        child_optional_field = OptionalFieldEntry(
            field="key",
            approved_default="child-default",
            rationale="Child scope",
            overlay_scope="/project/src/adapters",
        )

        rule = _run_rule_with_context(
            'schema_default(d.get("key", "child-default"))\n',
            boundaries=(parent_boundary, child_boundary),
            optional_fields=(parent_optional_field, child_optional_field),
            file_path="/project/src/adapters/handler.py",
        )

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001_GOVERNED_DEFAULT

    def test_multiple_boundaries_only_match_suppresses(self) -> None:
        boundaries = (
            BoundaryEntry(function="other", transition="shape_validation", overlay_scope="/project/src/adapters"),
            BoundaryEntry(function="target", transition="shape_validation", overlay_scope="/project/src/adapters"),
        )
        optional_field = OptionalFieldEntry(
            field="key",
            approved_default=42,
            rationale="Optional by contract",
            overlay_scope="/project/src/adapters",
        )
        rule = _run_rule_with_context(
            'schema_default(d.get("key", 42))\n',
            boundaries=boundaries,
            optional_fields=(optional_field,),
        )
        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001_GOVERNED_DEFAULT


class TestSchemaDefaultUngoverned:
    """schema_default() without matching boundary -> ERROR."""

    def test_no_boundary_emits_error(self) -> None:
        rule = _run_rule_with_context(
            'schema_default(d.get("key", "fallback"))\n',
        )
        assert len(rule.findings) == 1
        f = rule.findings[0]
        assert f.rule_id == RuleId.PY_WL_001_UNGOVERNED_DEFAULT
        assert f.severity == Severity.ERROR
        assert f.exceptionability == Exceptionability.STANDARD

    def test_wrong_function_emits_error(self) -> None:
        """Boundary qualname mismatch → UNGOVERNED per §A.3 clause 3."""
        boundary = BoundaryEntry(
            function="other_fn",
            transition="shape_validation",
            overlay_scope="/project/src/adapters",
        )
        optional_field = OptionalFieldEntry(
            field="key",
            approved_default=42,
            rationale="Optional by contract",
            overlay_scope="/project/src/adapters",
        )
        rule = _run_rule_with_context(
            'schema_default(d.get("key", 42))\n',
            boundaries=(boundary,),
            optional_fields=(optional_field,),
        )
        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001_UNGOVERNED_DEFAULT

    def test_wrong_transition_emits_error(self) -> None:
        """Non-governance transition on boundary → UNGOVERNED per §A.3 clause 3."""
        boundary = BoundaryEntry(
            function="target",
            transition="semantic_validation",
            overlay_scope="/project/src/adapters",
        )
        optional_field = OptionalFieldEntry(
            field="key",
            approved_default=42,
            rationale="Optional by contract",
            overlay_scope="/project/src/adapters",
        )
        rule = _run_rule_with_context(
            'schema_default(d.get("key", 42))\n',
            boundaries=(boundary,),
            optional_fields=(optional_field,),
        )
        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001_UNGOVERNED_DEFAULT

    def test_wrong_scope_emits_error(self) -> None:
        boundary = BoundaryEntry(
            function="target",
            transition="shape_validation",
            overlay_scope="/project/services",
        )
        optional_field = OptionalFieldEntry(
            field="key",
            approved_default=42,
            rationale="Optional by contract",
            overlay_scope="/project/services",
        )
        rule = _run_rule_with_context(
            'schema_default(d.get("key", 42))\n',
            boundaries=(boundary,),
            optional_fields=(optional_field,),
            file_path="/project/src/adapters/handler.py",
        )
        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001_UNGOVERNED_DEFAULT

    def test_empty_scope_does_not_match(self) -> None:
        """Empty overlay_scope must NOT match (E4)."""
        boundary = BoundaryEntry(
            function="target",
            transition="shape_validation",
            overlay_scope="",
        )
        optional_field = OptionalFieldEntry(
            field="key",
            approved_default=42,
            rationale="Optional by contract",
            overlay_scope="",
        )
        rule = _run_rule_with_context(
            'schema_default(d.get("key", 42))\n',
            boundaries=(boundary,),
            optional_fields=(optional_field,),
        )
        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001_UNGOVERNED_DEFAULT

    def test_no_context_emits_error(self) -> None:
        tree = parse_function_source(
            'schema_default(d.get("key", 42))\n'
        )
        rule = RulePyWl001(file_path="test.py")
        # No set_context call -- _context is None
        rule.visit(tree)

        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001_UNGOVERNED_DEFAULT
        assert rule.findings[0].severity == Severity.ERROR

    def test_case_sensitive_qualname(self) -> None:
        """Case-mismatched boundary qualname → UNGOVERNED (exact qualname match required)."""
        boundary = BoundaryEntry(
            function="Target",
            transition="shape_validation",
            overlay_scope="/project/src/adapters",
        )
        optional_field = OptionalFieldEntry(
            field="key",
            approved_default=42,
            rationale="Optional by contract",
            overlay_scope="/project/src/adapters",
        )
        rule = _run_rule_with_context(
            'schema_default(d.get("key", 42))\n',
            boundaries=(boundary,),
            optional_fields=(optional_field,),
        )
        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001_UNGOVERNED_DEFAULT

    def test_missing_optional_field_declaration_emits_error(self) -> None:
        boundary = BoundaryEntry(
            function="target",
            transition="shape_validation",
            overlay_scope="/project/src/adapters",
        )
        rule = _run_rule_with_context(
            'schema_default(d.get("key", 42))\n',
            boundaries=(boundary,),
        )
        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001_UNGOVERNED_DEFAULT
        assert rule.findings[0].exceptionability == Exceptionability.STANDARD

    def test_mismatched_approved_default_is_unconditional(self) -> None:
        boundary = BoundaryEntry(
            function="target",
            transition="shape_validation",
            overlay_scope="/project/src/adapters",
        )
        optional_field = OptionalFieldEntry(
            field="key",
            approved_default=[],
            rationale="Optional by contract",
            overlay_scope="/project/src/adapters",
        )
        rule = _run_rule_with_context(
            'schema_default(d.get("key", 42))\n',
            boundaries=(boundary,),
            optional_fields=(optional_field,),
        )
        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001_UNGOVERNED_DEFAULT
        assert rule.findings[0].exceptionability == Exceptionability.UNCONDITIONAL

    def test_non_schema_default_unchanged(self) -> None:
        """Regular default -> ERROR regardless of boundaries."""
        boundary = BoundaryEntry(
            function="target",
            transition="shape_validation",
            overlay_scope="/project/src/adapters",
        )
        rule = _run_rule_with_context(
            'd.get("key", "hardcoded")\n',
            boundaries=(boundary,),
        )
        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001


# ── Lambda .get() corpus specimen ────────────────────────────────


class TestLambdaGet:
    """Lambda containing .get() — corpus specimen for known behaviour."""

    def test_lambda_get_in_function_body(self) -> None:
        """Lambda .get() inside a function IS detected (ast.walk covers it)."""
        rule = _run_rule('fn = lambda d: d.get("key", "default")\n')

        # ast.walk inside visit_function covers lambda bodies
        assert len(rule.findings) == 1
        assert rule.findings[0].rule_id == RuleId.PY_WL_001


# ── Multiple patterns in one function ────────────────────────────


class TestMultiplePatterns:
    """Multiple violations in one function each produce a finding."""

    def test_multiple_gets_produce_multiple_findings(self) -> None:
        rule = _run_rule("""\
            a = d.get("x", 1)
            b = d.get("y", 2)
        """)

        assert len(rule.findings) == 2

    def test_mixed_patterns(self) -> None:
        rule = _run_rule("""\
            a = d.get("x", 1)
            b = d.setdefault("y", [])
            c = defaultdict(int)
        """)

        assert len(rule.findings) == 3


# ── No false positives ──────────────────────────────────────────


class TestNoFalsePositives:
    """Patterns that should NOT fire PY-WL-001."""

    def test_regular_method_call_silent(self) -> None:
        rule = _run_rule('d.items()\n')

        assert len(rule.findings) == 0

    def test_dict_subscript_silent(self) -> None:
        rule = _run_rule('x = d["key"]\n')

        assert len(rule.findings) == 0

    def test_regular_function_call_silent(self) -> None:
        rule = _run_rule("print(d)\n")

        assert len(rule.findings) == 0

    def test_get_on_non_dict_silent(self) -> None:
        """We can't distinguish dict.get from other .get — this fires.
        This is a known over-approximation at Level 1."""
        # Note: obj.get("x", default) fires because we can't do
        # type inference at Level 1. This is acceptable — Level 2
        # adds type-aware suppression.
        rule = _run_rule('obj.get("key", "default")\n')

        assert len(rule.findings) == 1  # Expected: fires (over-approx)
