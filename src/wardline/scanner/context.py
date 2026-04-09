"""Scanner data models — Finding, ScanContext, and WardlineAnnotation.

All models are frozen to prevent accidental mutation during rule execution.
ScanContext's function_level_taint_map is deeply frozen via MappingProxyType.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import TYPE_CHECKING

from wardline.core.severity import Exceptionability, RuleId, Severity

if TYPE_CHECKING:
    from wardline.core.taints import TaintState
    from wardline.manifest.models import BoundaryEntry, OptionalFieldEntry
    from wardline.scanner.taint.callgraph_propagation import TaintProvenance


@dataclass(frozen=True, kw_only=True)
class Finding:
    """A single scanner finding — maps to one SARIF result.

    Frozen because findings are immutable records; mutation after
    creation is a bug.
    """

    rule_id: RuleId
    file_path: str
    line: int
    col: int
    end_line: int | None
    end_col: int | None
    message: str
    severity: Severity
    exceptionability: Exceptionability
    taint_state: TaintState | None
    analysis_level: int
    source_snippet: str | None
    qualname: str | None = None
    exception_id: str | None = None
    exception_expires: str | None = None
    original_rule: str | None = None
    retroactive_scan: bool = False
    # R1: §10.1 result-level properties
    annotation_groups: tuple[int, ...] = ()
    data_source: str | None = None  # Always None in v1.0 — requires taint provenance threading


@dataclass(frozen=True)
class WardlineAnnotation:
    """Discovered decorator metadata per call site.

    Captures what the decorator discovery pass found on a decorated
    function/method, consumed by taint assignment and rule execution.
    """

    canonical_name: str
    group: int
    attrs: MappingProxyType[str, object]

    def __post_init__(self) -> None:
        if isinstance(self.attrs, Mapping) and not isinstance(
            self.attrs, MappingProxyType
        ):
            object.__setattr__(
                self, "attrs", MappingProxyType(dict(self.attrs))
            )


@dataclass(frozen=True, kw_only=True)
class ScanContext:
    """Per-file context built once after pass 1 (decorator discovery + taint).

    Construction timing: built once after pass 1 completes with the
    finalized taint map. NOT constructed incrementally during pass 1.

    The function_level_taint_map is deeply frozen via MappingProxyType
    to prevent mutation during rule execution. ``frozen=True`` prevents
    attribute rebinding but does NOT prevent mutation of mutable
    containers — MappingProxyType makes the map truly read-only.
    """

    file_path: str
    # Maps (module_path, qualname) -> TaintState for each function
    function_level_taint_map: MappingProxyType[str, TaintState]
    # Maps qualname -> discovered wardline annotations for that function.
    annotations_map: (
        MappingProxyType[str, tuple[WardlineAnnotation, ...]] | None
    ) = None
    # Maps (file_path, qualname) -> discovered wardline annotations across the
    # whole scan. Used by rules that need project-wide visibility.
    project_annotations_map: (
        MappingProxyType[tuple[str, str], tuple[WardlineAnnotation, ...]] | None
    ) = None
    # Maps importable module path -> source file path for project-local modules.
    module_file_map: MappingProxyType[str, str] | None = None
    # Project-wide string literal counts, used for pragmatic stale-reference checks.
    string_literal_counts: MappingProxyType[str, int] | None = None
    boundaries: tuple[BoundaryEntry, ...] = ()
    optional_fields: tuple[OptionalFieldEntry, ...] = ()
    # Level 2: maps qualname -> {variable_name: TaintState}. None when L2 is off.
    variable_taint_map: (
        MappingProxyType[str, MappingProxyType[str, TaintState]] | None
    ) = None
    analysis_level: int = 1
    # Level 3: maps qualname -> TaintProvenance. None when L3 didn't run.
    taint_provenance: MappingProxyType[str, TaintProvenance] | None = None
    # Two-hop rejection path index: FQNs of functions with rejection paths.
    rejection_path_index: frozenset[str] = frozenset()
    # Per-file import alias map: {local_name: FQN}.
    import_alias_map: MappingProxyType[str, str] | None = None

    def __post_init__(self) -> None:
        if isinstance(self.function_level_taint_map, dict):
            object.__setattr__(
                self,
                "function_level_taint_map",
                MappingProxyType(self.function_level_taint_map),
            )
        if isinstance(self.annotations_map, dict):
            frozen_annotations = {
                k: tuple(v) for k, v in self.annotations_map.items()
            }
            object.__setattr__(
                self,
                "annotations_map",
                MappingProxyType(frozen_annotations),
            )
        if isinstance(self.project_annotations_map, dict):
            frozen_project_annotations = {
                k: tuple(v) for k, v in self.project_annotations_map.items()
            }
            object.__setattr__(
                self,
                "project_annotations_map",
                MappingProxyType(frozen_project_annotations),
            )
        if isinstance(self.module_file_map, dict):
            object.__setattr__(
                self,
                "module_file_map",
                MappingProxyType(self.module_file_map),
            )
        if isinstance(self.string_literal_counts, dict):
            object.__setattr__(
                self,
                "string_literal_counts",
                MappingProxyType(self.string_literal_counts),
            )
        if isinstance(self.variable_taint_map, dict):
            frozen = {
                k: MappingProxyType(v) if isinstance(v, dict) else v
                for k, v in self.variable_taint_map.items()
            }
            object.__setattr__(
                self,
                "variable_taint_map",
                MappingProxyType(frozen),
            )
        if isinstance(self.taint_provenance, dict):
            object.__setattr__(
                self,
                "taint_provenance",
                MappingProxyType(self.taint_provenance),
            )
        if isinstance(self.rejection_path_index, set):
            object.__setattr__(
                self,
                "rejection_path_index",
                frozenset(self.rejection_path_index),
            )
        if isinstance(self.import_alias_map, dict):
            object.__setattr__(
                self,
                "import_alias_map",
                MappingProxyType(self.import_alias_map),
            )


def populate_snippets(
    findings: list[Finding],
    source: str | None,
) -> list[Finding]:
    """Populate source_snippet on findings that lack it.

    Uses line-range extraction from source text. Returns new Finding
    instances (Finding is frozen — uses dataclasses.replace).

    Both the scan engine and the corpus pipeline call this function
    to avoid duplicating snippet-population logic.
    """
    if source is None:
        return list(findings)
    source_lines = source.splitlines()
    result: list[Finding] = []
    for f in findings:
        if f.source_snippet is None and 1 <= f.line <= len(source_lines):
            f = replace(f, source_snippet=source_lines[f.line - 1].strip())
        result.append(f)
    return result


def make_governance_finding(
    rule_id: RuleId,
    message: str,
    *,
    file_path: str = "<governance>",
    line: int = 1,
    severity: Severity = Severity.WARNING,
    qualname: str | None = None,
    exception_id: str | None = None,
    original_rule: str | None = None,
) -> Finding:
    """Create a governance pseudo-rule finding.

    Unified factory for governance findings used by both the scan CLI
    (run-level diagnostics) and the exception matcher (register-level
    diagnostics).
    """
    return Finding(
        rule_id=rule_id,
        file_path=file_path,
        line=line,
        col=0,
        end_line=None,
        end_col=None,
        message=message,
        severity=severity,
        exceptionability=Exceptionability.UNCONDITIONAL,
        taint_state=None,
        analysis_level=0,
        source_snippet=None,
        qualname=qualname,
        exception_id=exception_id,
        original_rule=original_rule,
    )
