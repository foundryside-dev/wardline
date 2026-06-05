# src/wardline/scanner/rules/stored_taint.py
"""PY-WL-120 — stored/persisted taint reaches trusted state without validation.

Fires when raw data loaded from persistent storage (such as file reads via ``open``/
``read_text`` or database cursor fetches) reaches a trusted state (returned by a
``@trusted`` function or passed to a ``@trusted`` callee) without being validated
(e.g., through a ``@trust_boundary``).
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Location, Maturity, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.taints import RAW_ZONE, TaintState
from wardline.scanner.rules._ast_helpers import own_nodes
from wardline.scanner.rules._sink_helpers import worst_arg_taint
from wardline.scanner.rules.metadata import RuleMetadata
from wardline.scanner.rules.severity_model import modulate

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext


def _is_storage_read_call(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name):
            if node.func.id in ("open", "read"):
                return True
        elif isinstance(node.func, ast.Attribute):
            if node.func.attr in ("read", "read_text", "read_bytes", "fetchone", "fetchall", "fetchmany"):
                return True
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
                and node.func.attr in ("open", "read")
            ):
                return True
    return False


def _collect_stored_vars(node: ast.AST) -> set[str]:
    stored_vars: set[str] = set()
    for child in own_nodes(node):
        if isinstance(child, ast.Assign):
            is_storage = False
            for val_node in own_nodes(child.value):
                if _is_storage_read_call(val_node):
                    is_storage = True
                    break
            if not is_storage:
                for val_node in own_nodes(child.value):
                    if isinstance(val_node, ast.Name) and val_node.id in stored_vars:
                        is_storage = True
                        break
            if is_storage:
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        stored_vars.add(target.id)
                    elif isinstance(target, (ast.Tuple, ast.List)):
                        for elt in target.elts:
                            if isinstance(elt, ast.Name):
                                stored_vars.add(elt.id)
        elif isinstance(child, ast.AnnAssign) and child.value is not None:
            is_storage = False
            for val_node in own_nodes(child.value):
                if _is_storage_read_call(val_node):
                    is_storage = True
                    break
            if not is_storage:
                for val_node in own_nodes(child.value):
                    if isinstance(val_node, ast.Name) and val_node.id in stored_vars:
                        is_storage = True
                        break
            if is_storage and isinstance(child.target, ast.Name):
                stored_vars.add(child.target.id)
    return stored_vars


METADATA = RuleMetadata(
    rule_id="PY-WL-120",
    base_severity=Severity.ERROR,
    kind=Kind.DEFECT,
    description="Stored/persisted taint reaches trusted state without validation.",
    examples_violation=(
        "@trusted(level='ASSURED')\ndef get_config():\n    data = open('config.txt').read()\n    return data",
    ),
    examples_clean=(
        "@trusted(level='ASSURED')\ndef get_config():\n    data = validate(open('config.txt').read())\n    return data",
    ),
    maturity=Maturity.PREVIEW,
)


class StoredTaint:
    rule_id = METADATA.rule_id
    metadata = METADATA

    def __init__(self, base_severity: Severity | None = None) -> None:
        self.base_severity = base_severity or METADATA.base_severity

    def check(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for qualname, entity in context.entities.items():
            # Only check if the function itself is a trusted producer or boundary
            tier = context.project_taints.get(qualname, TaintState.UNKNOWN_RAW)
            severity = modulate(self.base_severity, tier)
            if severity == Severity.NONE:
                continue

            stored_vars = _collect_stored_vars(entity.node)
            if not stored_vars:
                # Check if there is a direct return of a storage read call
                has_direct_read = False
                for node in own_nodes(entity.node):
                    if isinstance(node, ast.Return) and node.value is not None:
                        for val_node in own_nodes(node.value):
                            if _is_storage_read_call(val_node):
                                has_direct_read = True
                                break
                if not has_direct_read:
                    continue

            # 1. Check return statements
            for node in own_nodes(entity.node):
                if isinstance(node, ast.Return) and node.value is not None:
                    is_stored_return = False
                    if _is_storage_read_call(node.value):
                        is_stored_return = True
                    else:
                        for val_node in own_nodes(node.value):
                            if isinstance(val_node, ast.Name) and val_node.id in stored_vars:
                                is_stored_return = True
                                break
                            if _is_storage_read_call(val_node):
                                is_stored_return = True
                                break

                    if is_stored_return:
                        # Check return taint
                        ret_taint = context.function_return_taints.get(qualname)
                        if ret_taint is not None and ret_taint in RAW_ZONE:
                            findings.append(
                                Finding(
                                    rule_id=self.rule_id,
                                    message=(
                                        f"{qualname} returns stored/persisted data "
                                        f"({ret_taint.value}) without validation at line {node.lineno}"
                                    ),
                                    severity=severity,
                                    kind=Kind.DEFECT,
                                    location=Location(path=entity.location.path, line_start=node.lineno),
                                    fingerprint=_fp(
                                        rule_id=self.rule_id,
                                        path=entity.location.path,
                                        line_start=node.lineno,
                                        qualname=qualname,
                                        taint_path="stored->return",
                                    ),
                                    qualname=qualname,
                                    properties={"return_taint": ret_taint.value},
                                )
                            )

            # 2. Check call arguments to trusted/modulated callees
            for node in own_nodes(entity.node):
                if isinstance(node, ast.Call):
                    # Check if any argument is a stored variable or storage read
                    has_stored_arg = False
                    for arg in (*node.args, *(kw.value for kw in node.keywords)):
                        for val_node in own_nodes(arg):
                            if isinstance(val_node, ast.Name) and val_node.id in stored_vars:
                                has_stored_arg = True
                                break
                            if _is_storage_read_call(val_node):
                                has_stored_arg = True
                                break

                    if has_stored_arg:
                        # Resolve callee FQN
                        callee_qn = context.call_site_callees.get(id(node))
                        if callee_qn is not None:
                            callee_tier = context.project_taints.get(callee_qn)
                            # Only flag if callee is a trusted producer or boundary
                            if callee_tier is not None and callee_tier not in RAW_ZONE:
                                worst = worst_arg_taint(node, qualname, context)
                                if worst is not None and worst in RAW_ZONE:
                                    findings.append(
                                        Finding(
                                            rule_id=self.rule_id,
                                            message=(
                                                f"{qualname} passes stored/persisted data "
                                                f"({worst.value}) to trusted callee {callee_qn} "
                                                f"without validation at line {node.lineno}"
                                            ),
                                            severity=severity,
                                            kind=Kind.DEFECT,
                                            location=Location(path=entity.location.path, line_start=node.lineno),
                                            fingerprint=_fp(
                                                rule_id=self.rule_id,
                                                path=entity.location.path,
                                                line_start=node.lineno,
                                                qualname=qualname,
                                                taint_path=f"stored->{callee_qn}",
                                            ),
                                            qualname=qualname,
                                            properties={"callee": callee_qn, "arg_taint": worst.value},
                                        )
                                    )
        return findings
