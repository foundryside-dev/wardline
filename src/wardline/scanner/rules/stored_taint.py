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
from wardline.scanner.rules._sink_helpers import dotted_name, worst_arg_taint
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
    multi_emit=True,
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
                                        qualname=qualname,
                                        # >1 return per function is possible. Discriminate ENTITY-RELATIVE
                                        # (return line - def line, invariant to a comment ABOVE the function:
                                        # wlfp2/wardline-8654423823) + the return's lexical span + a ``return``
                                        # token. The ``:return`` token keeps this DISJOINT from the call-arg
                                        # site below (which ends in a callee name), so the two never collide.
                                        taint_path=f"{node.lineno - (entity.location.line_start or 0)}:{node.col_offset}:{node.end_col_offset}:return",  # noqa: E501
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
                        # Resolve callee FQN(s). For a branch-conditional receiver, consult
                        # the full candidate set so this fires on any trusted candidate
                        # regardless of AST order (shares wardline-499c22bbdd's root cause);
                        # otherwise the single call_site_callees entry.
                        candidate_qns = context.call_site_candidate_callees.get(id(node))
                        if candidate_qns:
                            callee_qns: list[str] = sorted(candidate_qns)
                        else:
                            single = context.call_site_callees.get(id(node))
                            callee_qns = [single] if single is not None else []
                        # Keep only candidates that are trusted producers/boundaries; emit
                        # ONE finding per call site (not one per candidate) deterministically
                        # keyed on the first, so a branch-conditional receiver with several
                        # trusted candidates is one defect (wardline-499c22bbdd panel).
                        firing_qns = [
                            qn
                            for qn in callee_qns
                            if (ct := context.project_taints.get(qn)) is not None and ct not in RAW_ZONE
                        ]
                        if firing_qns:
                            worst = worst_arg_taint(node, qualname, context)
                            if worst is not None and worst in RAW_ZONE:
                                callee_qn = firing_qns[0]
                                others = firing_qns[1:]
                                also = f" (branch-conditional; also reaches {', '.join(others)})" if others else ""
                                findings.append(
                                    Finding(
                                        rule_id=self.rule_id,
                                        message=(
                                            f"{qualname} passes stored/persisted data "
                                            f"({worst.value}) to trusted callee {callee_qn} "
                                            f"without validation at line {node.lineno}{also}"
                                        ),
                                        severity=severity,
                                        kind=Kind.DEFECT,
                                        location=Location(path=entity.location.path, line_start=node.lineno),
                                        fingerprint=_fp(
                                            rule_id=self.rule_id,
                                            path=entity.location.path,
                                            qualname=qualname,
                                            # Call-site-anchored, >1 finding per (rule, path, qualname)
                                            # possible. Discriminate SOURCE-only: an ENTITY-RELATIVE line
                                            # offset (call line - def line, invariant to a comment ABOVE the
                                            # function: wlfp2/wardline-8654423823) + the call's full lexical
                                            # SPAN + the callee spelling AS WRITTEN. Never the RESOLVED callee
                                            # qualname (drifts). The span separates a chain's outer/inner calls.
                                            taint_path=f"{node.lineno - (entity.location.line_start or 0)}:{node.col_offset}:{node.end_col_offset}:{dotted_name(node.func)}",  # noqa: E501
                                        ),
                                        qualname=qualname,
                                        properties={"callee": callee_qn, "arg_taint": worst.value},
                                    )
                                )
        return findings
