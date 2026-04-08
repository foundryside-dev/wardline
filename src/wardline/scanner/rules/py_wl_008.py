"""PY-WL-008: Declared boundary with no rejection path.

Detects declared validation and restoration boundaries whose bodies do
not contain a structural rejection path. Under the authoritative
binding/spec contract, PY-WL-008 applies to the boundary function itself:
the body must reject invalid input via a raised exception or a guarded
early return that clearly represents rejection.
"""

from __future__ import annotations

import ast

from wardline.core.severity import Exceptionability, RuleId
from wardline.manifest.scope import path_within_scope
from wardline.scanner.import_resolver import resolve_call_fqn
from wardline.scanner.rejection_path import has_rejection_path as _has_rejection_path
from wardline.scanner.rejection_path import iter_reachable_calls
from wardline.scanner.rules.base import RuleBase, decorator_name

_BOUNDARY_TRANSITIONS = frozenset({
    "shape_validation",
    "semantic_validation",
    "external_validation",
    "combined_validation",
    "restoration",
})

_BOUNDARY_DECORATORS = frozenset({
    "validates_shape",
    "validates_semantic",
    "validates_external",
})


def _has_direct_boundary_decorator(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    """Check for direct wardline boundary decorators in source."""
    return any(
        decorator_name(decorator) in _BOUNDARY_DECORATORS
        for decorator in node.decorator_list
    )


class RulePyWl008(RuleBase):
    """Detect declared boundaries with no rejection path.

    Collects findings into ``self.findings`` during AST traversal.
    The engine reads this list after rule execution.
    """

    RULE_ID = RuleId.PY_WL_008
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
        """Walk declared boundary bodies for a structural rejection path."""
        if not self._is_checked_boundary(node):
            return
        if _has_rejection_path(node):
            return
        if self._has_delegated_rejection(node):
            return
        self._emit_matrix_finding(node, "Declared validation/restoration boundary has no rejection path")

    def _has_delegated_rejection(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> bool:
        """Check if the boundary delegates rejection to a function in the index."""
        if self._context is None or not self._context.rejection_path_index:
            return False
        alias_map = dict(self._context.import_alias_map or {})
        index = self._context.rejection_path_index
        # Derive module prefix from the module_file_map (reverse lookup)
        module_prefix = ""
        if self._context.module_file_map:
            for mod_name, mod_path in self._context.module_file_map.items():
                if mod_path == self._context.file_path or mod_path == self._file_path:
                    module_prefix = mod_name
                    break
        local_fqns = frozenset(
            fqn for fqn in index if fqn.startswith(f"{module_prefix}.")
        ) if module_prefix else frozenset()

        # Build the enclosing qualname prefix so nested local helpers
        # (e.g. module.outer.inner) can be resolved from bare calls.
        enclosing_prefix = (
            f"{module_prefix}.{self._current_qualname}"
            if module_prefix and self._current_qualname
            else self._current_qualname or module_prefix
        )

        for child in iter_reachable_calls(node):
            fqn = resolve_call_fqn(child, alias_map, local_fqns, module_prefix)
            if fqn is not None and fqn in index:
                return True
            # Try resolving as a nested local helper under the enclosing function
            if enclosing_prefix and isinstance(child.func, ast.Name):
                nested_candidate = f"{enclosing_prefix}.{child.func.id}"
                if nested_candidate in index:
                    return True
        return False

    def _is_checked_boundary(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> bool:
        """Return True for validation/restoration boundaries under this rule."""
        if self._context is not None:
            for boundary in self._context.boundaries:
                if (
                    boundary.function == self._current_qualname
                    and boundary.transition in _BOUNDARY_TRANSITIONS
                    and path_within_scope(self._file_path, boundary.overlay_scope)
                ):
                    return True
        return _has_direct_boundary_decorator(node)

