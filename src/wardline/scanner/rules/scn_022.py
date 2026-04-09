"""SCN-022: Group 5 field-completeness verification.

For functions decorated with ``@all_fields_mapped(source="ClassName")``,
verifies that every annotated field of the source class is accessed as
an attribute on the function's first parameter. Unmapped fields produce
a finding — they represent silent data loss risk.
"""

from __future__ import annotations

import ast
from typing import ClassVar

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.scanner.context import Finding
from wardline.scanner.rules.base import RuleBase, walk_skip_nested_defs

_CLASSVAR_NAMES = frozenset({"ClassVar"})


class RuleScn022(RuleBase):
    """Verify field-completeness for @all_fields_mapped(source=X) functions."""

    RULE_ID: ClassVar[RuleId] = RuleId.SCN_022

    def __init__(self, *, file_path: str = "") -> None:
        super().__init__()
        self._file_path = file_path
        self._class_fields: dict[str, list[str]] = {}

    def visit(self, tree: ast.Module) -> None:  # type: ignore[override]
        """Pre-scan for class definitions, then visit functions."""
        # Collect annotated fields per class
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.ClassDef):
                fields = _extract_class_fields(node)
                self._class_fields[node.name] = fields
        # Now run normal visitor (dispatches to visit_function for each FunctionDef)
        super().visit(tree)

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        """Check @all_fields_mapped(source=X) functions for field coverage."""
        source_class = _get_source_from_decorators(node)
        if source_class is None:
            return

        if source_class not in self._class_fields:
            self.findings.append(Finding(
                rule_id=self.RULE_ID,
                file_path=self._file_path,
                line=node.lineno,
                col=node.col_offset,
                end_line=node.lineno,
                end_col=node.end_col_offset,
                message=f"@all_fields_mapped source class '{source_class}' "
                        f"not found in this file",
                severity=Severity.ERROR,
                exceptionability=Exceptionability.STANDARD,
                taint_state=self._get_function_taint(self._current_qualname),
                analysis_level=1,
                source_snippet=None,
                qualname=self._current_qualname,
                annotation_groups=self._get_annotation_groups(),
            ))
            return

        declared_fields = set(self._class_fields[source_class])
        accessed_fields = _collect_param_attr_accesses(node)
        unmapped = sorted(declared_fields - accessed_fields)

        for field_name in unmapped:
            self.findings.append(Finding(
                rule_id=self.RULE_ID,
                file_path=self._file_path,
                line=node.lineno,
                col=node.col_offset,
                end_line=node.lineno,
                end_col=node.end_col_offset,
                message=f"Field '{field_name}' of '{source_class}' is not "
                        f"accessed — possible silent data loss",
                severity=Severity.WARNING,
                exceptionability=Exceptionability.STANDARD,
                taint_state=self._get_function_taint(self._current_qualname),
                analysis_level=1,
                source_snippet=None,
                qualname=self._current_qualname,
                annotation_groups=self._get_annotation_groups(),
            ))


def _get_source_from_decorators(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> str | None:
    """Extract source= value from @all_fields_mapped(source="X") decorator."""
    for dec in node.decorator_list:
        if not isinstance(dec, ast.Call):
            continue
        # Match @all_fields_mapped(source="X")
        func = dec.func
        name: str | None = None
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr
        if name != "all_fields_mapped":
            continue
        for kw in dec.keywords:
            if kw.arg == "source" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                return kw.value.value
    return None


def _extract_class_fields(cls: ast.ClassDef) -> list[str]:
    """Extract annotated field names from a class body, excluding ClassVar."""
    fields: list[str] = []
    for stmt in cls.body:
        if not isinstance(stmt, ast.AnnAssign):
            continue
        if not isinstance(stmt.target, ast.Name):
            continue
        # Exclude ClassVar annotations
        if _is_classvar(stmt.annotation):
            continue
        # Exclude private/dunder fields
        if stmt.target.id.startswith("_"):
            continue
        fields.append(stmt.target.id)
    return fields


def _is_classvar(ann: ast.expr) -> bool:
    """Return True if annotation is ClassVar[...] or ClassVar."""
    if isinstance(ann, ast.Name) and ann.id in _CLASSVAR_NAMES:
        return True
    if isinstance(ann, ast.Subscript) and isinstance(ann.value, ast.Name):
        return ann.value.id in _CLASSVAR_NAMES
    return False


def _collect_param_attr_accesses(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    """Collect attribute names accessed on the first parameter."""
    if not node.args.args:
        return set()
    param_name = node.args.args[0].arg
    accessed: set[str] = set()
    for child in walk_skip_nested_defs(node):
        if (
            isinstance(child, ast.Attribute)
            and isinstance(child.value, ast.Name)
            and child.value.id == param_name
        ):
            accessed.add(child.attr)
    return accessed
