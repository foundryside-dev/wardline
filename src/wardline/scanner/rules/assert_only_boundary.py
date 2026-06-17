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
production. A boundary with a real ``raise`` / rejection-shaped ``return``
(see ``asserts_are_sole_rejection`` / ``has_rejection_path`` in ``_ast_helpers``)
— or a ONE-HOP same-module call to a helper that itself raises (the helper's
``raise`` survives ``python -O``, so the CWE-617 claim would be factually false)
— trips neither.

**The boundary-integrity family partitions FOUR ways** (wardline-718048a518) —
at most one of {102, 111, 113, 119} fires per boundary:
  - PY-WL-119 — the bare degenerate shape (single ``return <param>``);
  - PY-WL-102 — every other shape with no rejection path;
  - PY-WL-111 — rejection only via ``assert`` (this rule). This includes an
    assert INSIDE a ``try`` whose handler substitutes: the rejection is still
    assert-only, so 111 wins over 113 (documented precedence);
  - PY-WL-113 — a real rejection exists but a fail-open handler defeats it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.taints import TRUST_RANK
from wardline.scanner.rules._ast_helpers import (
    assert_only_helper_calls,
    asserts_are_sole_rejection,
    has_real_rejection,
    rejecting_helper_calls,
)
from wardline.scanner.rules._sink_helpers import module_alias_map
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
            alias_map = module_alias_map(qualname, context)
            if has_real_rejection(entity.node, alias_map):
                continue
            helper_asserts = assert_only_helper_calls(entity, context.entities, context.call_site_callees, alias_map)
            if not asserts_are_sole_rejection(entity.node, alias_map) and not helper_asserts:
                continue
            # One-hop: a same-module raising helper survives `python -O`, so the
            # assert is NOT the sole rejection and the CWE-617 claim would be false.
            if rejecting_helper_calls(entity, context.entities, context.call_site_callees, alias_map):
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
