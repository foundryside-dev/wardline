"""PY-WL-001: Dict key access with fallback default.

Detects patterns where code silently fabricates values for missing
dictionary keys, bypassing validation:

- ``d.get(key, default)`` — ``.get()`` with a default argument
- ``d.pop(key, default)`` — ``.pop()`` with a fallback default
- ``d.setdefault(key, default)`` — mutates dict with fabricated default
- ``defaultdict(factory)`` — constructor registers a default factory

``schema_default()`` with a matching overlay boundary declaration
emits a SUPPRESS-severity finding (``PY-WL-001-GOVERNED-DEFAULT``).
Without a matching boundary, it emits ERROR (``PY-WL-001``).
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from wardline.core import matrix
from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.manifest.scope import path_within_scope, scope_specificity
from wardline.scanner.context import Finding
from wardline.scanner.rules.base import RuleBase, walk_skip_nested_defs

if TYPE_CHECKING:
    from wardline.manifest.models import OptionalFieldEntry


_UNPARSEABLE_DEFAULT = object()


class RulePyWl001(RuleBase):
    """Detect dict key access with fallback default patterns.

    Collects findings into ``self.findings`` during AST traversal.
    The engine reads this list after rule execution.
    """

    RULE_ID = RuleId.PY_WL_001
    _GOVERNED_TRANSITIONS = frozenset({
        "shape_validation",
        "external_validation",
        "combined_validation",
        "validates_shape",
        "validates_external",
    })

    def __init__(self, *, file_path: str = "") -> None:
        super().__init__()
        self._file_path = file_path

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        """Walk the function body looking for PY-WL-001 patterns.

        Uses ``walk_skip_nested_defs`` to avoid descending into nested
        function definitions — those are visited separately by the base
        class ``_dispatch`` / ``generic_visit``.
        """
        handled_calls: set[int] = set()
        for child in walk_skip_nested_defs(node):
            if not isinstance(child, ast.Call):
                continue
            if id(child) in handled_calls:
                continue
            wrapped_get = self._unwrap_schema_default_get(child)
            if wrapped_get is not None:
                handled_calls.add(id(wrapped_get))
            self._check_call(child)

    def _check_call(
        self,
        call: ast.Call,
    ) -> None:
        """Check a single Call node for PY-WL-001 patterns."""
        if self._unwrap_schema_default_get(call) is not None:
            self._emit_schema_default_finding(call)
            return

        # Pattern 1: d.get(key, default) — .get() with ≥2 args
        if self._is_method_call(call, "get") and len(call.args) >= 2:
            self._emit_finding(call)
            return

        # Pattern 2: d.pop(key, default) — .pop() with ≥2 args (default present)
        if self._is_method_call(call, "pop") and len(call.args) >= 2:
            self._emit_finding(call)
            return

        # Pattern 3: d.setdefault(key, default)
        if self._is_method_call(call, "setdefault") and len(call.args) >= 2:
            self._emit_finding(call)
            return

        # Pattern 4: defaultdict(factory)
        if self._is_defaultdict_call(call):
            self._emit_finding(call)

    @staticmethod
    def _is_method_call(call: ast.Call, method_name: str) -> bool:
        """Check if call is ``x.method_name(...)``."""
        return (
            isinstance(call.func, ast.Attribute)
            and call.func.attr == method_name
        )

    @staticmethod
    def _is_defaultdict_call(call: ast.Call) -> bool:
        """Check if call is ``defaultdict(factory)`` with a factory arg.

        ``defaultdict()`` with no args has a None factory that raises
        KeyError (no value fabrication), so we require >= 1 arg.
        Also matches ``collections.defaultdict(factory)``.
        """
        if len(call.args) < 1:
            return False
        if isinstance(call.func, ast.Name) and call.func.id == "defaultdict":
            return True
        return (
            isinstance(call.func, ast.Attribute)
            and call.func.attr == "defaultdict"
        )

    @staticmethod
    def _is_schema_default_call(node: ast.expr) -> bool:
        """Check if an expression is ``schema_default(...)``."""
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "schema_default"
        )

    def _unwrap_schema_default_get(self, call: ast.Call) -> ast.Call | None:
        """Return wrapped ``.get()`` call from ``schema_default(d.get(...))``."""
        if not self._is_schema_default_call(call) or len(call.args) != 1:
            return None
        wrapped = call.args[0]
        if (
            isinstance(wrapped, ast.Call)
            and self._is_method_call(wrapped, "get")
            and len(wrapped.args) >= 2
        ):
            return wrapped
        return None

    @staticmethod
    def _extract_field_name(call: ast.Call) -> str | None:
        """Extract literal field name from ``d.get(\"field\", default)``."""
        if not call.args:
            return None
        key_arg = call.args[0]
        if isinstance(key_arg, ast.Constant) and isinstance(key_arg.value, str):
            return key_arg.value
        return None

    @staticmethod
    def _extract_default_value(call: ast.Call) -> object:
        """Extract the runtime-equivalent literal default, or a sentinel."""
        if len(call.args) < 2:
            return _UNPARSEABLE_DEFAULT
        try:
            return ast.literal_eval(call.args[1])
        except (ValueError, SyntaxError):
            return _UNPARSEABLE_DEFAULT

    def _emit_finding(
        self,
        call: ast.Call,
    ) -> None:
        """Emit a PY-WL-001 finding."""
        taint = self._get_function_taint(self._current_qualname)
        cell = matrix.lookup(self.RULE_ID, taint)
        self.findings.append(
            Finding(
                rule_id=RuleId.PY_WL_001,
                file_path=self._file_path,
                line=call.lineno,
                col=call.col_offset,
                end_line=call.end_lineno,
                end_col=call.end_col_offset,
                message=(
                    "Dict key access with fallback default — "
                    "value fabricated for missing key without validation"
                ),
                severity=cell.severity,
                exceptionability=cell.exceptionability,
                taint_state=taint,
                analysis_level=1,
                source_snippet=None,
                qualname=self._current_qualname,
            )
        )

    def _emit_schema_default_finding(
        self,
        call: ast.Call,
    ) -> None:
        """Emit governed or ungoverned finding for ``schema_default(d.get(...))``."""
        taint = self._get_function_taint(self._current_qualname)
        wrapped_get = self._unwrap_schema_default_get(call)
        if wrapped_get is None:
            return

        field_name = self._extract_field_name(wrapped_get)
        default_value = self._extract_default_value(wrapped_get)
        optional_field = self._find_matching_optional_field(field_name)

        if (
            optional_field is not None
            and default_value == optional_field.approved_default
            and (
                self._is_governed_by_boundary(optional_field.overlay_scope)
                or self._is_governed_by_optional_field(optional_field)
            )
        ):
            self.findings.append(
                Finding(
                    rule_id=RuleId.PY_WL_001_GOVERNED_DEFAULT,
                    file_path=self._file_path,
                    line=call.lineno,
                    col=call.col_offset,
                    end_line=call.end_lineno,
                    end_col=call.end_col_offset,
                    message=(
                        "schema_default() governed by overlay boundary — "
                        "suppressed"
                    ),
                    severity=Severity.SUPPRESS,
                    exceptionability=Exceptionability.TRANSPARENT,
                    taint_state=taint,
                    analysis_level=1,
                    source_snippet=None,
                    qualname=self._current_qualname,
                )
            )
        else:
            message = (
                "schema_default() without approved overlay declaration — "
                "ungoverned default value"
            )
            exceptionability = Exceptionability.STANDARD
            if (
                optional_field is not None
                and default_value != optional_field.approved_default
            ):
                message = (
                    "schema_default() default does not match overlay approved "
                    "default"
                )
                exceptionability = Exceptionability.UNCONDITIONAL
            self.findings.append(
                Finding(
                    rule_id=RuleId.PY_WL_001_UNGOVERNED_DEFAULT,
                    file_path=self._file_path,
                    line=call.lineno,
                    col=call.col_offset,
                    end_line=call.end_lineno,
                    end_col=call.end_col_offset,
                    message=message,
                    severity=Severity.ERROR,
                    exceptionability=exceptionability,
                    taint_state=taint,
                    analysis_level=1,
                    source_snippet=None,
                    qualname=self._current_qualname,
                )
            )

    def _find_matching_optional_field(
        self, field_name: str | None
    ) -> OptionalFieldEntry | None:
        """Return scoped optional-field declaration for the current file/function."""
        if self._context is None or field_name is None:
            return None

        best_match: OptionalFieldEntry | None = None
        for optional_field in self._context.optional_fields:
            if (
                optional_field.field == field_name
                and optional_field.overlay_scope
                and path_within_scope(self._file_path, optional_field.overlay_scope)
                and (
                    best_match is None
                    or scope_specificity(optional_field.overlay_scope)
                    > scope_specificity(best_match.overlay_scope)
                )
            ):
                best_match = optional_field
        return best_match

    def _is_governed_by_optional_field(self, optional_field: OptionalFieldEntry) -> bool:
        """Check if the optional_field declaration itself constitutes governance.

        An optional_field entry with a non-empty overlay_scope that covers
        the current file is sufficient governance for schema_default() —
        the optional_fields list is the primary governance mechanism.
        """
        return bool(
            optional_field.overlay_scope
            and path_within_scope(self._file_path, optional_field.overlay_scope)
        )

    def _is_governed_by_boundary(self, overlay_scope: str) -> bool:
        """Check if current function has a matching governance boundary.

        Three conditions must ALL be met:
        1. Exact qualname match (boundary.function == self._current_qualname)
        2. Transition type is governance-relevant (shape or combined validation)
        3. File is within the boundary's overlay scope (non-empty, path-prefix)
        """
        if self._context is None:
            return False

        for boundary in self._context.boundaries:
            if (
                boundary.function == self._current_qualname
                and boundary.transition in self._GOVERNED_TRANSITIONS
                and overlay_scope
                and boundary.overlay_scope == overlay_scope
                and path_within_scope(self._file_path, overlay_scope)
            ):
                return True
        return False
