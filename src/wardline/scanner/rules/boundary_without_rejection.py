# src/wardline/scanner/rules/boundary_without_rejection.py
"""PY-WL-102 — a trust boundary with no rejection path.

A trust-RAISING transition (declared return strictly MORE trusted than body —
the taint shape unique to ``@trust_boundary`` among the vocabulary) that contains
no rejection path of any recognised shape cannot actually reject bad input, so it
is not validating. Declaration-gated (the decorator is the opt-in), so it emits
at base severity (NOT tier-modulated).

Recognised rejection shapes (any one keeps the rule silent):
  - an own-scope ``raise`` or ``assert`` (the assert-only case is PY-WL-111's);
  - a rejection-shaped ``return`` — falsy constant, conditional expression with a
    rejecting branch (``return m.group(0) if m else None``), or a curated
    raising-conversion / lookup (``return int(p)`` / ``return Color[p]`` /
    ``return ALLOWED[p]`` — validate-by-construction);
  - a ONE-HOP, SAME-MODULE call to a helper whose own body has a real rejection
    (``_require_nonempty(p)``, a raising staticmethod, or wholesale delegation to
    another raising boundary). A helper that cannot raise never counts.

**The boundary-integrity family partitions FOUR ways** (wardline-718048a518) —
at most one of {102, 111, 113, 119} fires per boundary:
  - PY-WL-119 — the bare degenerate shape (single ``return <param>``): the
    more-specific rule wins, so 102 SUPPRESSES itself there (the suppression is
    structural — keyed on the shape, not on whether 119 is enabled);
  - PY-WL-102 — every OTHER shape with no rejection path (cannot reject at all);
  - PY-WL-111 — rejection only via ``assert`` (stripped under ``python -O``);
  - PY-WL-113 — a real rejection exists but a fail-open handler defeats it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.taints import TRUST_RANK
from wardline.scanner.rules._ast_helpers import (
    has_rejection_path,
    is_degenerate_boundary,
    rejecting_helper_calls,
)
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
    # NOT the bare `return p` shape — that is PY-WL-119's (the family partitions).
    examples_violation=("@trust_boundary(to_level='ASSURED')\ndef v(p):\n    x = p\n    return x",),
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
            # The bare degenerate shape is PY-WL-119's domain (more-specific wins).
            if is_degenerate_boundary(entity.node):
                continue
            # One-hop: a same-module raising helper IS this boundary's rejection path.
            if rejecting_helper_calls(entity, context.entities, context.call_site_callees):
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
