"""SCN-021: contradictory and suspicious decorator-combination detection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.scanner.context import Finding
from wardline.scanner.rules.base import RuleBase, decorator_name

if TYPE_CHECKING:
    import ast


@dataclass(frozen=True)
class _CombinationSpec:
    left: str
    right: str
    severity: Severity
    rationale: str
    spec_entry: int | None = None


_CONTRADICTORY = Severity.ERROR
_SUSPICIOUS = Severity.WARNING

_COMBINATIONS: tuple[_CombinationSpec, ...] = (
    _CombinationSpec("fail_open", "fail_closed", _CONTRADICTORY, "Mutually exclusive failure modes", spec_entry=1),
    _CombinationSpec(
        "fail_open",
        "integral_read",
        _CONTRADICTORY,
        "Tier 1 requires offensive programming; fail-open is structurally incompatible",
        spec_entry=2,
    ),
    _CombinationSpec("fail_open", "integral_writer", _CONTRADICTORY, "Audit writes must not silently degrade", spec_entry=3),
    _CombinationSpec(
        "fail_open",
        "integral_construction",
        _CONTRADICTORY,
        "Authoritative artefacts must not have fallback construction paths",
        spec_entry=4,
    ),
    _CombinationSpec(
        "fail_open", "integrity_critical", _CONTRADICTORY,
        "Audit-critical paths must not have fallback paths", spec_entry=5,
    ),
    _CombinationSpec(
        "external_boundary", "int_data", _CONTRADICTORY,
        "External and internal data sources are mutually exclusive", spec_entry=6,
    ),
    _CombinationSpec(
        "external_boundary", "integral_read", _CONTRADICTORY,
        "External data is Tier 4; Tier 1 reads are internal", spec_entry=7,
    ),
    _CombinationSpec(
        "external_boundary", "integral_construction", _CONTRADICTORY,
        "External data cannot be directly authoritative", spec_entry=8,
    ),
    _CombinationSpec(
        "validates_shape", "validates_semantic", _CONTRADICTORY,
        "Use validates_external for combined T4→T2 validation", spec_entry=9,
    ),
    _CombinationSpec(
        "validates_shape", "integral_read", _CONTRADICTORY,
        "Shape validation produces T3, not T1", spec_entry=10,
    ),
    _CombinationSpec(
        "validates_semantic", "external_boundary", _CONTRADICTORY,
        "Semantic validation operates on T3 input, not T4", spec_entry=11,
    ),
    _CombinationSpec(
        "exception_boundary",
        "must_propagate",
        _CONTRADICTORY,
        "Exception boundaries terminate; must-propagate requires forwarding",
        spec_entry=12,
    ),
    _CombinationSpec(
        "idempotent", "compensatable", _CONTRADICTORY,
        "Idempotent operations need no compensation", spec_entry=13,
    ),
    _CombinationSpec(
        "deterministic", "time_dependent", _CONTRADICTORY,
        "Time-dependent operations are inherently non-deterministic", spec_entry=14,
    ),
    _CombinationSpec(
        "deterministic", "external_boundary", _CONTRADICTORY,
        "External calls are non-deterministic by definition", spec_entry=15,
    ),
    _CombinationSpec(
        "integral_read",
        "restoration_boundary",
        _CONTRADICTORY,
        "Tier 1 reads access existing authoritative data; restoration reconstructs from raw representation",
        spec_entry=16,
    ),
    _CombinationSpec(
        "integral_writer",
        "restoration_boundary",
        _CONTRADICTORY,
        "Audit writes create new records; restoration reconstructs existing ones",
        spec_entry=17,
    ),
    _CombinationSpec(
        "external_boundary",
        "restoration_boundary",
        _CONTRADICTORY,
        "External boundaries receive new untrusted data; "
        "restoration reconstructs previously-known data",
    ),
    _CombinationSpec(
        "validates_shape",
        "restoration_boundary",
        _CONTRADICTORY,
        "Shape validators receive raw input for validation; "
        "restoration reconstructs previously-known data",
    ),
    _CombinationSpec(
        "validates_semantic",
        "restoration_boundary",
        _CONTRADICTORY,
        "Semantic validators receive shape-validated input; "
        "restoration reconstructs previously-known data",
    ),
    _CombinationSpec(
        "validates_external",
        "restoration_boundary",
        _CONTRADICTORY,
        "External validators receive raw external input; "
        "restoration reconstructs previously-known data",
    ),
    _CombinationSpec(
        "integral_construction",
        "restoration_boundary",
        _CONTRADICTORY,
        "Construction creates new authoritative objects from validated input; "
        "restoration reconstructs existing objects from raw representation",
    ),
    _CombinationSpec(
        "fail_closed",
        "emits_or_explains",
        _CONTRADICTORY,
        "Fail-closed raises on failure; emits-or-explains requires structured error output",
        spec_entry=18,
    ),
    # Spec entry #19 (integrity_critical + fail_open) is an alias of #5 — removed to prevent duplicate findings.
    _CombinationSpec(
        "validates_external", "validates_shape", _CONTRADICTORY,
        "validates_external already encompasses shape validation", spec_entry=20,
    ),
    _CombinationSpec(
        "validates_external",
        "validates_semantic",
        _CONTRADICTORY,
        "validates_external already encompasses semantic validation",
        spec_entry=21,
    ),
    _CombinationSpec("int_data", "validates_shape", _CONTRADICTORY, "Internal data does not need shape validation", spec_entry=22),
    _CombinationSpec(
        "preserve_cause",
        "exception_boundary",
        _CONTRADICTORY,
        "preserve_cause implies propagation; exception boundaries terminate",
        spec_entry=23,
    ),
    _CombinationSpec("compensatable", "integral_writer", _CONTRADICTORY, "Audit writes must not be compensated", spec_entry=24),
    _CombinationSpec(
        "data_flow",
        "external_boundary",
        _CONTRADICTORY,
        "@data_flow declares internal data production; @external_boundary declares external intake — contradictory flow direction",
        spec_entry=25,
    ),
    _CombinationSpec(
        "system_plugin", "integral_read", _CONTRADICTORY,
        "Plugins receive external input; Tier 1 reads are internal", spec_entry=26,
    ),
    _CombinationSpec(
        "fail_open", "deterministic", _SUSPICIOUS,
        "Fail-open with fallback defaults may produce non-deterministic output", spec_entry=27,
    ),
    _CombinationSpec(
        "compensatable", "deterministic", _SUSPICIOUS,
        "Compensation introduces state changes that may affect determinism", spec_entry=28,
    ),
    _CombinationSpec(
        "time_dependent", "idempotent", _SUSPICIOUS,
        "Time-dependent operations may not be idempotent across invocations", spec_entry=29,
    ),
)


class RuleScn021(RuleBase):
    """Detect contradictory and suspicious decorator combinations."""

    RULE_ID = RuleId.SCN_021

    def __init__(self, *, file_path: str = "") -> None:
        super().__init__()
        self._file_path = file_path

    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        names = self._decorator_names(node)
        if len(names) < 2:
            return

        for spec in _COMBINATIONS:
            if spec.left in names and spec.right in names:
                self._emit_finding(node, spec)

    def _decorator_names(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> frozenset[str]:
        """Resolve canonical decorator names, falling back to direct syntax."""
        names: set[str] = set()
        if self._context is not None and self._context.annotations_map is not None:
            for ann in self._context.annotations_map.get(self._current_qualname, ()):
                names.add(ann.canonical_name)
        if names:
            return frozenset(names)
        return frozenset(
            name
            for decorator in node.decorator_list
            if (name := decorator_name(decorator)) is not None
        )

    def _emit_finding(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        spec: _CombinationSpec,
    ) -> None:
        self.findings.append(
            Finding(
                rule_id=self.RULE_ID,
                file_path=self._file_path,
                line=getattr(node, "lineno", 0),
                col=getattr(node, "col_offset", 0),
                end_line=getattr(node, "end_lineno", None),
                end_col=getattr(node, "end_col_offset", None),
                message=(
                    f"SCN-021: @{spec.left} + @{spec.right} on the same function. "
                    f"{spec.rationale}."
                ),
                severity=spec.severity,
                exceptionability=Exceptionability.UNCONDITIONAL,
                taint_state=self._get_function_taint(self._current_qualname),
                analysis_level=1,
                source_snippet=None,
                qualname=self._current_qualname,
                annotation_groups=self._get_annotation_groups(),
            )
        )
