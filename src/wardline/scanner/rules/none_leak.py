# src/wardline/scanner/rules/none_leak.py
"""PY-WL-109 — None leaks from a trusted producer.

Fires on an anchored trusted producer whose **return annotation promises a non-None
type** yet a path yields ``None`` (a bare ``return`` or ``return None``) alongside a
value-bearing return — a PROVABLE contract violation: the function declares ``-> T``
(non-None) but leaks ``None`` (CWE-394 / a latent None-deref downstream).

Declaration-gated (base WARN). FP-guarded — the annotation is the load-bearing guard:
  - **requires an explicit non-None return annotation** (``-> T``). A function with NO
    annotation, or one declaring ``Optional[T]`` / ``T | None`` / ``-> None``, does NOT
    fire — that is a deliberately-nullable (or unstated) contract, not a leak. This is
    what keeps the rule off the single most common legitimate pattern (``Optional``
    returns), per the FP-economics review;
  - requires BOTH a value-bearing return AND a None-yielding return in scope;
  - **skips generators** (a bare ``return`` ends iteration — not a None value leak);
  - skips the trust-RAISING shape (body less trusted than declared — ``@trust_boundary``'s
    territory, policed by PY-WL-102), mirroring PY-WL-101's delegation.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.taints import RAW_ZONE, TRUST_RANK
from wardline.scanner.rules._ast_helpers import _own_statements
from wardline.scanner.rules.metadata import RuleMetadata

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext

METADATA = RuleMetadata(
    rule_id="PY-WL-109",
    base_severity=Severity.WARN,
    kind=Kind.DEFECT,
    description=(
        "A trusted producer has both a value-bearing return and a None-yielding return "
        "(bare return / return None) — None leaks from a function declaring trusted output."
    ),
    examples_violation=(
        "@trusted(level='ASSURED')\ndef f(flag) -> int:\n    if flag:\n        return g()\n    return",
    ),
    examples_clean=(
        "@trusted(level='ASSURED')\ndef f(flag) -> int | None:\n    if flag:\n        return g()\n    return None",
    ),
)


def _is_none_return(stmt: ast.Return) -> bool:
    """A bare ``return`` (value is None) or an explicit ``return None``."""
    return stmt.value is None or (isinstance(stmt.value, ast.Constant) and stmt.value.value is None)


def _annotation_allows_none(ann: ast.expr) -> bool:
    """True if a return annotation permits ``None``: bare ``None``, ``Optional[...]``,
    or a ``... | None`` union (recursively)."""
    if isinstance(ann, ast.Constant) and ann.value is None:
        return True
    if isinstance(ann, ast.Name) and ann.id == "None":
        return True
    if isinstance(ann, ast.Subscript):  # Optional[X] / Union[X, None]
        base = ann.value
        if (isinstance(base, ast.Name) and base.id == "Optional") or (
            isinstance(base, ast.Attribute) and base.attr == "Optional"
        ):
            return True
        if (isinstance(base, ast.Name) and base.id == "Union") or (
            isinstance(base, ast.Attribute) and base.attr == "Union"
        ):
            sl = ann.slice
            # Handle ast.Index wrapper on older Python versions (e.g. <3.9)
            if hasattr(ast, "Index") and isinstance(sl, ast.Index):
                sl = sl.value  # type: ignore
            if isinstance(sl, ast.Tuple):
                return any(_annotation_allows_none(elt) for elt in sl.elts)
            return _annotation_allows_none(sl)
    if isinstance(ann, ast.BinOp) and isinstance(ann.op, ast.BitOr):  # X | None
        return _annotation_allows_none(ann.left) or _annotation_allows_none(ann.right)
    return False


def _promises_non_none(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True iff the function has an explicit return annotation that does NOT permit
    None — the provable non-None contract 109 polices. No annotation → False."""
    return node.returns is not None and not _annotation_allows_none(node.returns)


def _is_generator(node: ast.AST) -> bool:
    """True if *node*'s own scope contains a ``yield``/``yield from`` (does not descend
    into nested def/class/lambda — those are separate scopes)."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(child, (ast.Yield, ast.YieldFrom)) or _is_generator(child):
            return True
    return False


class NoneLeak:
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
            declared = context.project_return_taints.get(qualname)
            if declared is None or declared in RAW_ZONE:
                continue  # trust-claim gate (same as PY-WL-101)
            body = context.project_taints.get(qualname)
            if body is not None and TRUST_RANK[body] > TRUST_RANK[declared]:
                continue  # trust-raising shape -> PY-WL-102's territory, not 109's
            if _is_generator(entity.node):
                continue
            if not _promises_non_none(entity.node):
                continue  # no explicit non-None contract -> not a provable leak (FP guard)
            has_value = has_none = False
            for stmt in _own_statements(entity.node):
                if isinstance(stmt, ast.Return):
                    if _is_none_return(stmt):
                        has_none = True
                    else:
                        has_value = True
            if not (has_value and has_none):
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    message=(
                        f"{qualname} declares trusted return {declared.value} but a path returns None "
                        f"(bare return / return None) — None leaks from a trusted producer"
                    ),
                    severity=self.base_severity,
                    kind=Kind.DEFECT,
                    location=entity.location,
                    fingerprint=_fp(
                        rule_id=self.rule_id,
                        path=entity.location.path,
                        line_start=entity.location.line_start,
                        qualname=qualname,
                        taint_path=f"None->{declared.value}",
                    ),
                    qualname=qualname,
                    properties={"declared_return": declared.value},
                )
            )
        return findings
