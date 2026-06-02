# src/wardline/scanner/rules/none_leak.py
"""PY-WL-109 — None leaks from a trusted producer.

Fires on an anchored trusted producer (declared return NOT in the raw zone) that has
BOTH a value-bearing return AND a None-yielding return (a bare ``return`` or
``return None``) in its own scope — an inconsistent contract: the function claims to
produce trusted data but some path yields ``None``, which downstream trusted code does
not expect (CWE-394 / a latent None-deref).

Declaration-gated (base WARN). Conservative to protect the FP budget:
  - requires BOTH shapes (a pure ``return None`` void-ish helper has no value path → no
    fire; an all-value function has no None path → no fire);
  - **skips generators** (a bare ``return`` ends iteration — not a None value leak);
  - skips the trust-RAISING shape (body less trusted than declared — that is
    ``@trust_boundary``'s territory, policed by PY-WL-102), mirroring PY-WL-101's
    delegation, so 109 polices ``@trusted``-style producers.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.taints import TRUST_RANK, TaintState
from wardline.scanner.rules._ast_helpers import _own_statements
from wardline.scanner.rules.metadata import RuleMetadata

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext

_RAW_ZONE: frozenset[TaintState] = frozenset({TaintState.EXTERNAL_RAW, TaintState.UNKNOWN_RAW, TaintState.MIXED_RAW})

METADATA = RuleMetadata(
    rule_id="PY-WL-109",
    base_severity=Severity.WARN,
    kind=Kind.DEFECT,
    description=(
        "A trusted producer has both a value-bearing return and a None-yielding return "
        "(bare return / return None) — None leaks from a function declaring trusted output."
    ),
    examples_violation=("@trusted(level='ASSURED')\ndef f(flag):\n    if flag:\n        return g()\n    return",),
    examples_clean=(
        "@trusted(level='ASSURED')\ndef f(flag):\n    if flag:\n        return g()\n    raise LookupError",
    ),
)


def _is_none_return(stmt: ast.Return) -> bool:
    """A bare ``return`` (value is None) or an explicit ``return None``."""
    return stmt.value is None or (isinstance(stmt.value, ast.Constant) and stmt.value.value is None)


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
            if declared is None or declared in _RAW_ZONE:
                continue  # trust-claim gate (same as PY-WL-101)
            body = context.project_taints.get(qualname)
            if body is not None and TRUST_RANK[body] > TRUST_RANK[declared]:
                continue  # trust-raising shape -> PY-WL-102's territory, not 109's
            if _is_generator(entity.node):
                continue
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
