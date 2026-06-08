# src/wardline/scanner/rules/boundary_without_rejection.py
"""PY-WL-102 — a trust boundary with no rejection path.

A trust-RAISING transition (declared return strictly MORE trusted than body —
the taint shape unique to ``@trust_boundary`` among the vocabulary) that contains
no ``raise`` and no falsy-constant ``return`` cannot actually reject bad input,
so it is not validating. Declaration-gated (the decorator is the opt-in), so it
emits at base severity (NOT tier-modulated).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.taints import TRUST_RANK
from wardline.scanner.rules._ast_helpers import has_rejection_path
from wardline.scanner.rules.metadata import RuleMetadata

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext

METADATA = RuleMetadata(
    rule_id="PY-WL-102",
    base_severity=Severity.ERROR,
    kind=Kind.DEFECT,
    description=(
        "A trust boundary (a function that raises declared trust on its return) "
        "has no rejection path — no raise, no falsy-constant return — so it cannot "
        "validate."
    ),
    examples_violation=("@trust_boundary(to_level='ASSURED')\ndef v(p):\n    return p",),
    examples_clean=(
        "@trust_boundary(to_level='ASSURED')\ndef v(p):\n    if not p:\n        raise ValueError\n    return p",
    ),
)


class BoundaryWithoutRejection:
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
            if has_rejection_path(entity.node):
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    message=(
                        f"{qualname} declares a trust boundary ({body.value} -> {ret.value}) "
                        f"but has no rejection path (no raise / no falsy return) — it cannot validate"
                    ),
                    severity=self.base_severity,
                    kind=Kind.DEFECT,
                    location=entity.location,
                    fingerprint=_fp(
                        rule_id=self.rule_id,
                        path=entity.location.path,
                        line_start=entity.location.line_start,
                        qualname=qualname,
                        # Join-key stability (weft-4a9d0f863c): one finding per anchored qualname,
                        # so (rule, path, line, qualname) is already unique. body/return tiers are
                        # resolved values that drift as the suite is extended — keep them off the key.
                        taint_path=None,
                    ),
                    qualname=qualname,
                    properties={"body_taint": body.value, "return_taint": ret.value},
                )
            )
        return findings
