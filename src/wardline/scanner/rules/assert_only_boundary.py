# src/wardline/scanner/rules/assert_only_boundary.py
"""PY-WL-111 — a trust boundary whose only rejection path is ``assert`` (CWE-617).

A trust-RAISING transition (declared return strictly MORE trusted than body — the
taint shape unique to ``@trust_boundary``) that rejects bad input *only* via
``assert`` validates in development but is stripped under ``python -O``: the
validation silently vanishes in production, and untrusted data passes the
"boundary" untouched. Declaration-gated (the decorator is the opt-in), so it
emits at base severity (NOT tier-modulated).

A PY-WL-102-adjacent refinement: 102 fires when a boundary cannot reject *at all*;
111 fires when it *appears* to reject but only via a guard that disappears in
production. The two partition the space — a boundary with a real ``raise`` or a
falsy-constant ``return`` trips neither (see ``asserts_are_sole_rejection`` /
``has_rejection_path`` in ``_ast_helpers``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.taints import TRUST_RANK
from wardline.scanner.rules._ast_helpers import asserts_are_sole_rejection
from wardline.scanner.rules.metadata import RuleMetadata

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext

METADATA = RuleMetadata(
    rule_id="PY-WL-111",
    base_severity=Severity.ERROR,
    kind=Kind.DEFECT,
    description=(
        "A trust boundary's only rejection path is `assert`, which `python -O` strips — "
        "the validation silently vanishes in production (CWE-617)."
    ),
    examples_violation=("@trust_boundary(to_level='ASSURED')\ndef v(p):\n    assert p\n    return p",),
    examples_clean=(
        "@trust_boundary(to_level='ASSURED')\ndef v(p):\n"
        "    assert isinstance(p, str)\n    if not p:\n        raise ValueError\n    return p",
    ),
)


class AssertOnlyBoundary:
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
            if not asserts_are_sole_rejection(entity.node):
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    message=(
                        f"{qualname} declares a trust boundary ({body.value} -> {ret.value}) "
                        f"but its only rejection path is assert — stripped under python -O, so the "
                        f"validation vanishes in production"
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
