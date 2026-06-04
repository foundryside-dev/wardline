"""Public scanner projection for finding code-flow traces."""

from __future__ import annotations

import ast
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from wardline.core.finding import Finding, Location
from wardline.core.qualname import module_dotted_name
from wardline.core.taints import RAW_ZONE, TRUST_RANK, TaintState
from wardline.scanner.context import AnalysisContext
from wardline.scanner.rules._sink_helpers import dotted_name


@dataclass(frozen=True, slots=True)
class CodeFlowStep:
    location: Location
    message: str


@dataclass(frozen=True, slots=True)
class FindingCodeFlow:
    steps: tuple[CodeFlowStep, ...]


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
    module = module_dotted_name(entity.location.path) or ""

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
        callee = dotted_name(worst_arg.func)
        if callee is not None:
            return callee

    if isinstance(worst_arg, ast.Name):
        assign_callee = _find_assignment_callee(entity.node.body, worst_arg.id, entity.node)
        if assign_callee is not None:
            return assign_callee

    return context.function_return_callee.get(finding.qualname)


def build_finding_code_flow(finding: Finding, context: AnalysisContext) -> FindingCodeFlow | None:
    """Project scanner provenance into a stable code-flow DTO for formatters."""
    if finding.qualname is None:
        return None

    callee_name = _find_sink_contributor(finding, context)
    if callee_name is None:
        return None

    entity = context.entities.get(finding.qualname)
    if entity is None:
        return None

    real_module = module_dotted_name(entity.location.path) or ""

    if callee_name.startswith("self.") or callee_name.startswith("cls."):
        enclosing_class = finding.qualname.rsplit(".", 1)[0] if "." in finding.qualname else ""
        leaf = callee_name.split(".", 1)[1]
        callee_qualname = f"{enclosing_class}.{leaf}" if enclosing_class else leaf
    elif "." not in callee_name:
        callee_qualname = f"{real_module}.{callee_name}" if real_module else callee_name
    else:
        callee_qualname = callee_name

    steps: list[tuple[Location, str]] = []
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
            steps.append((entity.location, curr_str))

        current = next_hop

    flow_steps: list[CodeFlowStep] = []
    for i, (location, qualname) in enumerate(reversed(steps)):
        msg = f"Taint source: {qualname}" if i == 0 else f"Taint flows through {qualname}()"
        flow_steps.append(CodeFlowStep(location=location, message=msg))
    flow_steps.append(CodeFlowStep(location=finding.location, message=finding.message))

    return FindingCodeFlow(steps=tuple(flow_steps))
