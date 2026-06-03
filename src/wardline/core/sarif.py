# src/wardline/core/sarif.py
"""SARIF 2.1.0 emission (SP4a). Pure findings -> dict; stdlib-only.

A standard interchange format for any SARIF consumer (CI annotations, code-scanning
dashboards). Suppression rides SARIF's native ``result.suppressions`` channel;
the stable fingerprint rides ``partialFingerprints``.
"""

from __future__ import annotations

import ast
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

from wardline import __version__
from wardline.core.finding import Finding, Kind, Location, Severity, SuppressionState

if TYPE_CHECKING:
    from wardline.core.taints import TaintState
    from wardline.scanner.context import AnalysisContext

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFO_URI = "https://github.com/foundryside/wardline"

_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.ERROR: "error",
    Severity.WARN: "warning",
    Severity.INFO: "note",
    Severity.NONE: "none",
}


def _region(finding: Finding) -> dict[str, Any]:
    region: dict[str, Any] = {}
    location = finding.location
    if location.line_start is not None:
        region["startLine"] = location.line_start
    if location.line_end is not None:
        region["endLine"] = location.line_end
    if location.col_start is not None:
        region["startColumn"] = location.col_start
    if location.col_end is not None:
        region["endColumn"] = location.col_end
    return region


def _physical_location(location: Location) -> dict[str, Any]:
    phys: dict[str, Any] = {"artifactLocation": {"uri": location.path}}
    region: dict[str, Any] = {}
    if location.line_start is not None:
        region["startLine"] = location.line_start
    if location.line_end is not None:
        region["endLine"] = location.line_end
    if location.col_start is not None:
        region["startColumn"] = location.col_start
    if location.col_end is not None:
        region["endColumn"] = location.col_end
    if region:
        phys["region"] = region
    return phys


def _arg_taint_local(
    arg: ast.expr, module: str, var_taints: Mapping[str, TaintState], context: AnalysisContext, qualname: str
) -> TaintState | None:
    if isinstance(arg, ast.Starred):
        arg = arg.value
    if isinstance(arg, ast.Name):
        return var_taints.get(arg.id)
    if isinstance(arg, ast.Call):
        if (
            isinstance(arg.func, ast.Attribute)
            and isinstance(arg.func.value, ast.Name)
            and arg.func.value.id in {"self", "cls"}
        ):
            caller_entity = context.entities.get(qualname)
            if caller_entity is not None and caller_entity.kind == "method":
                enclosing_class = qualname.rsplit(".", 1)[0]
                candidate = f"{enclosing_class}.{arg.func.attr}"
                return context.project_return_taints.get(candidate)
        from wardline.scanner.rules._sink_helpers import dotted_name

        callee = dotted_name(arg.func)
        if callee is not None and "." not in callee and module:
            return context.project_return_taints.get(f"{module}.{callee}")
        return None
    if isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name) and arg.value.id in ("self", "cls"):
        enclosing_class = qualname.rsplit(".", 1)[0] if "." in qualname else ""
        return context.class_attr_taints.get(enclosing_class, {}).get(arg.attr)
    return None


def _find_assignment_callee(nodes: Sequence[ast.AST], name: str, entity_node: ast.AST) -> str | None:
    result: str | None = None
    for node in nodes:
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda))
            and node is not entity_node
        ):
            continue
        if isinstance(node, ast.Assign):
            from wardline.scanner.taint.variable_level import _return_callee

            callee = _return_callee(node.value)
            if callee is not None and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
                result = callee
        for child in ast.iter_child_nodes(node):
            nested = _find_assignment_callee([child] if isinstance(child, ast.stmt) else [], name, entity_node)
            if nested is not None:
                result = nested
    return result


def _find_sink_contributor(finding: Finding, context: AnalysisContext) -> str | None:
    if finding.qualname is None:
        return None

    if finding.rule_id == "PY-WL-101":
        return context.function_return_callee.get(finding.qualname)

    entity = context.entities.get(finding.qualname)
    if entity is None:
        return None

    line = finding.location.line_start
    if line is None:
        return None

    calls_at_line: list[ast.Call] = []

    def visit(node: ast.AST) -> None:
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda))
            and node is not entity.node
        ):
            return
        if isinstance(node, ast.Call) and getattr(node, "lineno", None) == line:
            calls_at_line.append(node)
        for child in ast.iter_child_nodes(node):
            visit(child)

    visit(entity.node)

    if not calls_at_line:
        return context.function_return_callee.get(finding.qualname)

    call = calls_at_line[0]
    snapshots = context.function_call_site_taints.get(finding.qualname, {})
    final = context.function_var_taints.get(finding.qualname, {})

    stmt_at_line: ast.stmt | None = None

    def find_stmt(node: ast.AST, cur_stmt: ast.stmt | None = None) -> None:
        nonlocal stmt_at_line
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda))
            and node is not entity.node
        ):
            return
        new_stmt = node if isinstance(node, ast.stmt) else cur_stmt
        if node is call:
            stmt_at_line = new_stmt
            return
        for child in ast.iter_child_nodes(node):
            find_stmt(child, new_stmt)

    find_stmt(entity.node)

    var_taints = snapshots.get(id(stmt_at_line)) if stmt_at_line is not None else None
    if var_taints is None:
        var_taints = final

    worst_arg: ast.expr | None = None
    worst_rank = -1

    from wardline.core.qualname import module_dotted_name

    module = module_dotted_name(entity.location.path) or ""

    from wardline.core.taints import RAW_ZONE, TRUST_RANK

    for arg in (*call.args, *(kw.value for kw in call.keywords)):
        t = _arg_taint_local(arg, module, var_taints, context, finding.qualname)
        if t is not None and t in RAW_ZONE:
            rank = TRUST_RANK[t]
            if rank > worst_rank:
                worst_rank = rank
                worst_arg = arg

    if worst_arg is None:
        return context.function_return_callee.get(finding.qualname)

    if isinstance(worst_arg, ast.Call):
        from wardline.scanner.rules._sink_helpers import dotted_name

        callee = dotted_name(worst_arg.func)
        if callee is not None:
            return callee

    if isinstance(worst_arg, ast.Name):
        assign_callee = _find_assignment_callee(entity.node.body, worst_arg.id, entity.node)
        if assign_callee is not None:
            return assign_callee

    return context.function_return_callee.get(finding.qualname)


def _build_code_flow(finding: Finding, context: AnalysisContext) -> dict[str, Any] | None:
    if finding.qualname is None:
        return None

    callee_name = _find_sink_contributor(finding, context)
    if callee_name is None:
        return None

    entity = context.entities.get(finding.qualname)
    if entity is None:
        return None

    from wardline.core.qualname import module_dotted_name

    real_module = module_dotted_name(entity.location.path) or ""

    if callee_name.startswith("self.") or callee_name.startswith("cls."):
        enclosing_class = finding.qualname.rsplit(".", 1)[0] if "." in finding.qualname else ""
        leaf = callee_name.split(".", 1)[1]
        callee_qualname = f"{enclosing_class}.{leaf}" if enclosing_class else leaf
    elif "." not in callee_name:
        callee_qualname = f"{real_module}.{callee_name}" if real_module else callee_name
    else:
        callee_qualname = callee_name

    steps = []
    visited = {finding.qualname}
    current: str | None = callee_qualname

    while current is not None and current not in visited:
        visited.add(current)
        curr_str = current
        entity = context.entities.get(curr_str)

        next_hop: str | None = None
        prov = context.taint_provenance.get(curr_str)
        if prov is not None and prov.via_callee is not None:
            next_hop = prov.via_callee
        else:
            ret_leaf = context.function_return_callee.get(curr_str)
            if ret_leaf is not None:
                if ret_leaf.startswith("self.") or ret_leaf.startswith("cls."):
                    enclosing_class = curr_str.rsplit(".", 1)[0] if "." in curr_str else ""
                    leaf = ret_leaf.split(".", 1)[1]
                    next_hop = f"{enclosing_class}.{leaf}" if enclosing_class else leaf
                elif "." not in ret_leaf:
                    real_module = ""
                    if entity is not None:
                        real_module = module_dotted_name(entity.location.path) or ""
                    next_hop = f"{real_module}.{ret_leaf}" if real_module else ret_leaf
                else:
                    next_hop = ret_leaf

        if entity is not None:
            steps.append({"location": entity.location, "qualname": curr_str})

        current = next_hop

    flow_locations = []
    for i, step in enumerate(reversed(steps)):
        loc = step["location"]
        assert isinstance(loc, Location)
        qn = step["qualname"]
        msg = f"Taint source: {qn}" if i == 0 else f"Taint flows through {qn}()"
        flow_locations.append(
            {
                "location": {"physicalLocation": _physical_location(loc), "message": {"text": msg}},
                "importance": "important",
            }
        )

    flow_locations.append(
        {
            "location": {
                "physicalLocation": _physical_location(finding.location),
                "message": {"text": finding.message},
            },
            "importance": "important",
        }
    )

    return {"threadFlows": [{"locations": flow_locations}]}


def _result(finding: Finding, rule_index: int, context: AnalysisContext | None = None) -> dict[str, Any]:
    physical: dict[str, Any] = {"artifactLocation": {"uri": finding.location.path}}
    region = _region(finding)
    if region:
        physical["region"] = region

    props: dict[str, Any] = {
        "kind": finding.kind.value,
        "internalSeverity": finding.severity.value,
    }
    if finding.qualname is not None:
        props["qualname"] = finding.qualname
    if finding.confidence is not None:
        props["confidence"] = finding.confidence
    if finding.related_entities:
        props["relatedEntities"] = list(finding.related_entities)
    if finding.properties:
        props["wardlineProperties"] = dict(finding.properties)

    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _LEVEL[finding.severity],
        "message": {"text": finding.message},
        "locations": [{"physicalLocation": physical}],
        "partialFingerprints": {"wardlineFingerprint/v1": finding.fingerprint},
        "properties": props,
    }
    if finding.suppressed is not SuppressionState.ACTIVE:
        suppression: dict[str, Any] = {"kind": "external", "status": "accepted"}
        if finding.suppression_reason is not None:
            suppression["justification"] = finding.suppression_reason
        result["suppressions"] = [suppression]

    if context is not None and finding.qualname is not None:
        code_flow = _build_code_flow(finding, context)
        if code_flow is not None:
            result["codeFlows"] = [code_flow]

    return result


def build_sarif(findings: Sequence[Finding], context: AnalysisContext | None = None) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log with a single run from *findings* (pure).

    ``Kind.METRIC`` findings (engine telemetry such as WLN-L3-LOW-RESOLUTION
    and WLN-ENGINE-METRICS) are excluded from the SARIF output. They carry
    diagnostic statistics about the scan run itself — not actionable code
    issues — and pollute GitHub Code Scanning with noise alerts. The full
    picture (including METRIC findings) is always available in the JSONL sink.
    """
    included = [f for f in findings if f.kind is not Kind.METRIC]
    rule_index: dict[str, int] = {}
    for finding in included:
        if finding.rule_id not in rule_index:
            rule_index[finding.rule_id] = len(rule_index)
    rules = [{"id": rid} for rid in rule_index]
    results = [_result(f, rule_index[f.rule_id], context) for f in included]
    return {
        "version": "2.1.0",
        "$schema": _SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "wardline",
                        "informationUri": _INFO_URI,
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


class SarifSink:
    def __init__(self, path: Path) -> None:
        self._path = path

    def write(self, findings: Sequence[Finding], context: AnalysisContext | None = None) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        content = json.dumps(build_sarif(findings, context), indent=2, ensure_ascii=False)
        self._path.write_text(content, encoding="utf-8")
