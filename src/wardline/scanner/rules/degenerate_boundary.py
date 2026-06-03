# src/wardline/scanner/rules/degenerate_boundary.py
"""PY-WL-119 — no-op validator boundary where return is equivalent to input.

A trust boundary (raises declared trust on return) that simply returns its input
parameter directly without any conditional checks, assertions, or validations is a
degenerate boundary. It does not perform any validation.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Maturity, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.taints import TRUST_RANK
from wardline.scanner.rules.metadata import RuleMetadata

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext


def _is_degenerate(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    param_names = {arg.arg for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)}
    if node.args.vararg:
        param_names.add(node.args.vararg.arg)
    if node.args.kwarg:
        param_names.add(node.args.kwarg.arg)

    non_trivial_stmts = []
    for stmt in node.body:
        if isinstance(stmt, ast.Pass):
            continue
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            continue
        non_trivial_stmts.append(stmt)

    if len(non_trivial_stmts) == 1 and isinstance(non_trivial_stmts[0], ast.Return):
        ret_val = non_trivial_stmts[0].value
        if isinstance(ret_val, ast.Name) and ret_val.id in param_names:
            return True
    return False


METADATA = RuleMetadata(
    rule_id="PY-WL-119",
    base_severity=Severity.ERROR,
    kind=Kind.DEFECT,
    description="No-op validator boundary where return is equivalent to input.",
    examples_violation=("@trust_boundary(to_level='ASSURED')\ndef validate(x):\n    return x",),
    examples_clean=(
        "@trust_boundary(to_level='ASSURED')\ndef validate(x):\n    if not x:\n        raise ValueError\n    return x",
    ),
    maturity=Maturity.PREVIEW,
)


class DegenerateBoundary:
    rule_id = METADATA.rule_id
    metadata = METADATA

    def __init__(self, base_severity: Severity | None = None) -> None:
        self.base_severity = base_severity or METADATA.base_severity

    def check(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for qualname, entity in context.entities.items():
            prov = context.taint_provenance.get(qualname)
            if prov is None or prov.source != "anchored":
                continue
            body = context.project_taints.get(qualname)
            ret = context.project_return_taints.get(qualname)
            if body is None or ret is None:
                continue
            # Trust-raising transition (== @trust_boundary): body less-trusted than return.
            if TRUST_RANK[body] <= TRUST_RANK[ret]:
                continue
            if not _is_degenerate(entity.node):
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    message=(
                        f"{qualname} declares a trust boundary ({body.value} -> {ret.value}) "
                        f"but returns the input directly without validation (degenerate boundary)"
                    ),
                    severity=self.base_severity,
                    kind=Kind.DEFECT,
                    location=entity.location,
                    fingerprint=_fp(
                        rule_id=self.rule_id,
                        path=entity.location.path,
                        line_start=entity.location.line_start,
                        qualname=qualname,
                        taint_path=f"{body.value}->{ret.value}",
                    ),
                    qualname=qualname,
                    properties={"body_taint": body.value, "return_taint": ret.value},
                )
            )
        return findings
