# src/wardline/scanner/rules/degenerate_boundary.py
"""PY-WL-119 — no-op validator boundary where return is equivalent to input.

A trust boundary (raises declared trust on return) that simply returns its input
parameter directly without any conditional checks, assertions, or validations is a
degenerate boundary. It does not perform any validation.

**The boundary-integrity family partitions FOUR ways** (wardline-718048a518) —
at most one of {102, 111, 113, 119} fires per boundary. The degenerate shape is a
strict structural subset of PY-WL-102's "no rejection path", so 119 WINS on it
(more-specific rule) and 102 suppresses itself there — the same boundary is never
counted twice at ERROR in the gate population. The shared shape predicate is
``_ast_helpers.is_degenerate_boundary``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Maturity, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.taints import TRUST_RANK
from wardline.scanner.rules._ast_helpers import is_degenerate_boundary
from wardline.scanner.rules.metadata import RuleMetadata

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext


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
            if not is_degenerate_boundary(entity.node):
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
