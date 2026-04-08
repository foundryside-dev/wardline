"""PY-WL-009: Semantic boundary without prior shape validation.

Detects declared semantic-validation boundaries whose semantic checks
have no prior structural validation evidence within the boundary body.
Combined validation boundaries are excluded because they satisfy the
ordering requirement internally by definition.
"""

from __future__ import annotations

import ast

from wardline.core.severity import Exceptionability, RuleId
from wardline.manifest.scope import path_within_scope
from wardline.scanner.rules.base import RuleBase, decorator_name, receiver_name, walk_skip_nested_defs

_SEMANTIC_BOUNDARY_TRANSITIONS = frozenset({"semantic_validation"})
_COMBINED_BOUNDARY_TRANSITIONS = frozenset({
    "combined_validation",
    "external_validation",
})
_SEMANTIC_BOUNDARY_DECORATORS = frozenset({"validates_semantic"})
_COMBINED_BOUNDARY_DECORATORS = frozenset({"validates_external"})

# Function name fragments that indicate shape validation.
_SHAPE_VALIDATION_NAMES = frozenset({
    "validate_schema",
    "check_schema",
    "verify_schema",
    "validate_shape",
    "check_shape",
    "verify_shape",
    "validate_structure",
    "check_structure",
    "verify_structure",
})

# Substrings in function names that suggest shape validation.
_SHAPE_VALIDATION_SUBSTRINGS = ("schema", "shape", "structure")

# Generic method names that become shape validators when the receiver
# (object they're called on) has a schema-related name.
_SCHEMA_QUALIFIED_METHODS = frozenset({"validate", "is_valid"})


def _subscript_targets(node: ast.AST) -> frozenset[str]:
    """Extract variable names used as subscript targets in *node*.

    For ``data["key"]`` returns ``{"data"}``.  For ``a["x"] + b["y"]``
    returns ``{"a", "b"}``.  Attribute chains like ``self.data["key"]``
    yield the root ``"self"``.
    """
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Subscript):
            target = child.value
            # Walk through attribute chains to find the root Name.
            while isinstance(target, ast.Attribute):
                target = target.value
            if isinstance(target, ast.Name):
                names.add(target.id)
    return frozenset(names)


def _shape_check_target(node: ast.AST) -> str | None:
    """Extract the variable name being validated by a shape-check node.

    For calls like ``isinstance(data, dict)``, ``validate_schema(data)``,
    or ``schema.validate(data)`` returns the first-argument variable name.
    For membership tests like ``"key" in data`` returns the comparator
    variable name.  Returns ``None`` when the target cannot be determined.
    """
    if isinstance(node, ast.Call) and node.args:
        arg = node.args[0]
        while isinstance(arg, ast.Attribute):
            arg = arg.value
        if isinstance(arg, ast.Name):
            return arg.id
    if isinstance(node, ast.Compare) and _is_membership_test(node):
        # ``"key" in data`` — the right side of ``in`` is the container.
        for i, op in enumerate(node.ops):
            if isinstance(op, (ast.In, ast.NotIn)):
                comparator = node.comparators[i]
                while isinstance(comparator, ast.Attribute):
                    comparator = comparator.value
                if isinstance(comparator, ast.Name):
                    return comparator.id
    return None


def _has_shape_check_before(
    stmts: list[ast.stmt],
    *,
    stop_line: int,
    target_names: frozenset[str] = frozenset(),
) -> bool:
    """Check if any statement before *stop_line* is a shape validation.

    When *target_names* is non-empty, only shape checks whose validated
    variable overlaps with *target_names* count.  This prevents a shape
    check on variable ``x`` from suppressing a finding about ``y``.

    Shape validations include:
    - isinstance(...) calls whose result is consumed (in a conditional,
      assignment, or boolean expression — NOT a bare expression statement)
    - hasattr(...) calls (same consumption requirement)
    - ``"key" in data`` / ``key in data`` comparisons
    - Calls to functions with shape-validation names

    A bare ``isinstance(data, object)`` as an expression statement (result
    discarded) does NOT count — it performs no actual gating and can be
    used to trivially satisfy this check without providing real validation.
    """
    # Collect ids of boolean-returning shape calls (isinstance, hasattr) that
    # appear as bare expression statements (result discarded). These return
    # True/False but don't gate anything when the result is thrown away.
    # Contrast with validate_schema(data) which raises on failure — calling
    # it as a bare statement IS the gating mechanism.
    bare_expr_calls: set[int] = set()
    module = ast.Module(body=stmts, type_ignores=[])
    for node in walk_skip_nested_defs(module):
        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id in ("isinstance", "hasattr")
        ):
            bare_expr_calls.add(id(node.value))

    for node in walk_skip_nested_defs(module):
        if getattr(node, "lineno", 0) >= stop_line:
            continue
        is_shape = (
            (isinstance(node, ast.Call) and id(node) not in bare_expr_calls and _is_shape_validation_call(node))
            or (isinstance(node, ast.Compare) and _is_membership_test(node))
        )
        if is_shape and (not target_names or _shape_check_target(node) in target_names):
            return True
    return False


def _has_direct_decorator(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    names: frozenset[str],
) -> bool:
    """Check whether the function has any decorator whose terminal name matches."""
    return any(
        decorator_name(decorator) in names
        for decorator in node.decorator_list
    )


def _is_shape_validation_call(call: ast.Call) -> bool:
    """Check if a call is isinstance, hasattr, or a shape-validation function.

    Recognised patterns:
    - ``isinstance(x, T)`` / ``hasattr(x, "a")``
    - Bare calls whose name matches ``_SHAPE_VALIDATION_NAMES`` or contains
      a ``_SHAPE_VALIDATION_SUBSTRINGS`` fragment.
    - Method calls ``obj.method(...)`` where *method* matches the above.
    - Schema-qualified calls: ``jsonschema.validate()``, ``schema.is_valid()``
      — a generic method name in ``_SCHEMA_QUALIFIED_METHODS`` called on a
      receiver whose name contains a schema-related substring.
    """
    if isinstance(call.func, ast.Name):
        name = call.func.id
        if name in ("isinstance", "hasattr"):
            return True
        if name in _SHAPE_VALIDATION_NAMES:
            return True
        for sub in _SHAPE_VALIDATION_SUBSTRINGS:
            if sub in name.lower():
                return True
    if isinstance(call.func, ast.Attribute):
        attr = call.func.attr
        if attr in _SHAPE_VALIDATION_NAMES:
            return True
        for sub in _SHAPE_VALIDATION_SUBSTRINGS:
            if sub in attr.lower():
                return True
        # Schema-qualified: receiver.validate() where receiver name
        # contains a schema-related term (e.g. jsonschema.validate).
        if attr in _SCHEMA_QUALIFIED_METHODS:
            receiver = receiver_name(call.func.value)
            if receiver:
                receiver_lower = receiver.lower()
                for sub in _SHAPE_VALIDATION_SUBSTRINGS:
                    if sub in receiver_lower:
                        return True
    return False


def _is_membership_test(compare: ast.Compare) -> bool:
    """Check if a Compare node is ``x in y`` or ``x not in y``."""
    return any(isinstance(op, (ast.In, ast.NotIn)) for op in compare.ops)


def _has_subscript_access(node: ast.AST) -> bool:
    """Check if node contains a subscript access (``data["key"]``).

    Only matches ``ast.Subscript`` — NOT ``ast.Attribute``.  Attribute
    access (``obj.attr``) is shape-guaranteed by the type system: the
    class definition IS the shape declaration.  Subscript access on
    dicts/lists has no such guarantee and needs explicit shape validation.
    """
    return any(isinstance(child, ast.Subscript) for child in ast.walk(node))


def _test_contains_shape_check(test: ast.expr) -> bool:
    """Check if a conditional test already contains an inline shape validation.

    When a condition like ``isinstance(x, T) and x.attr > 0`` is found,
    the isinstance IS the shape guard for the attribute access in the same
    expression.  These should not be classified as unguarded semantic checks.
    """
    for child in ast.walk(test):
        if isinstance(child, ast.Call) and _is_shape_validation_call(child):
            return True
        if isinstance(child, ast.Compare) and _is_membership_test(child):
            return True
    return False


def _get_semantic_check_nodes(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[tuple[ast.AST, frozenset[str]]]:
    """Find if/assert nodes that perform semantic checks on subscript data.

    Returns a list of ``(node, target_names)`` tuples where *target_names*
    is the set of variable names accessed via subscript in the check.

    A semantic check is an if-test or assert that accesses data via
    subscript (``data["key"]``) and compares or tests a value — business
    logic validation on the data's content rather than its shape.

    Pure attribute access (``obj.attr``) is excluded — the type system
    guarantees attributes declared by the class definition.  Only
    subscript access (``data["key"]``) indicates potentially unvalidated
    shape.

    Conditions that already contain an inline shape check (isinstance,
    hasattr, membership test) are excluded — the shape guard in the
    condition itself covers the subscript access.
    """
    results: list[tuple[ast.AST, frozenset[str]]] = []
    for child in walk_skip_nested_defs(node):
        if not isinstance(child, (ast.If, ast.Assert)):
            continue
        if not _has_subscript_access(child.test):
            continue
        if _test_contains_shape_check(child.test):
            continue
        targets = _subscript_targets(child.test)
        results.append((child, targets))
    return results


class RulePyWl009(RuleBase):
    """Detect semantic validation without prior shape validation.

    Collects findings into ``self.findings`` during AST traversal.
    The engine reads this list after rule execution.
    """

    RULE_ID = RuleId.PY_WL_009
    DEFAULT_EXCEPTIONABILITY = Exceptionability.UNCONDITIONAL

    def __init__(self, *, file_path: str = "") -> None:
        super().__init__()
        self._file_path = file_path

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        """Walk semantic-validation boundaries for missing shape-validation evidence."""
        if self._is_combined_boundary(node):
            return
        if not self._is_semantic_boundary(node):
            return
        semantic_checks = _get_semantic_check_nodes(node)
        if not semantic_checks:
            return

        # For each semantic check, see if there's a shape check before it
        # that operates on the SAME variable being subscript-accessed.
        for check, target_names in semantic_checks:
            check_line = getattr(check, "lineno", 0)
            if not _has_shape_check_before(node.body, stop_line=check_line, target_names=target_names):
                self._emit_matrix_finding(
                    check,
                    "Semantic validation without prior shape validation"
                    " — business logic check on data that has not been structurally validated",
                )

    def _is_semantic_boundary(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> bool:
        """Return True when this function is a declared semantic validator."""
        if self._context is not None:
            for boundary in self._context.boundaries:
                if (
                    boundary.function == self._current_qualname
                    and boundary.transition in _SEMANTIC_BOUNDARY_TRANSITIONS
                    and path_within_scope(self._file_path, boundary.overlay_scope)
                ):
                    return True
        return _has_direct_decorator(node, _SEMANTIC_BOUNDARY_DECORATORS)

    def _is_combined_boundary(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> bool:
        """Return True when this function is a declared combined validator."""
        if self._context is not None:
            for boundary in self._context.boundaries:
                if (
                    boundary.function == self._current_qualname
                    and boundary.transition in _COMBINED_BOUNDARY_TRANSITIONS
                    and path_within_scope(self._file_path, boundary.overlay_scope)
                ):
                    return True
        return _has_direct_decorator(node, _COMBINED_BOUNDARY_DECORATORS)

