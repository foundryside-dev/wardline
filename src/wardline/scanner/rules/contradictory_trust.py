# src/wardline/scanner/rules/contradictory_trust.py
"""PY-WL-110 — contradictory / ambiguous trust declaration.

Fires on an anchored entity whose decorator list carries **two or more distinct**
grammar trust markers (e.g. ``@trusted`` + ``@external_boundary``, or ``@trusted`` +
``@trust_boundary``). Such a stack is self-contradictory: one marker claims the
function produces trusted data, another claims it is a raw source or a validator —
the engine silently resolves the clash to the least-trusted seed, so the more-trusted
claim is quietly ignored. Flagging it surfaces the ambiguity rather than letting a
silent resolution hide intent.

Declaration-gated (base severity, NOT tier-modulated). It reads RESOLVED provenance
for the gate (``prov.source == "anchored"``) and only COUNTS markers in the decorator
list — it never infers taint from a decorator, so the engine-layering discipline
holds. Distinctness is by the grammar boundary type's canonical name; two ``@trusted``
markers are not contradictory.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.scanner.grammar import BUILTIN_BOUNDARY_TYPES
from wardline.scanner.rules.metadata import RuleMetadata

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext

# The recognised trust-marker names (the grammar boundary types' canonical names).
# A custom grammar's markers are the agent's own concern; the builtin rule keys on
# the builtin vocabulary, which is the contract Wardline ships.
_MARKER_NAMES: frozenset[str] = frozenset(bt.canonical_name for bt in BUILTIN_BOUNDARY_TYPES)

METADATA = RuleMetadata(
    rule_id="PY-WL-110",
    base_severity=Severity.WARN,  # declaration hygiene, not a proven taint exploit (promote via wardline.yaml)
    kind=Kind.DEFECT,
    description=(
        "An entity carries two or more distinct trust markers (e.g. @trusted + "
        "@external_boundary) — a contradictory declaration the engine resolves silently."
    ),
    examples_violation=("@trusted\n@external_boundary\ndef f(p):\n    return p",),
    examples_clean=("@trust_boundary(to_level='ASSURED')\ndef f(p):\n    if not p: raise ValueError\n    return p",),
)


def _marker_name(deco: ast.expr) -> str | None:
    """The trailing identifier of a decorator (``@a.b.trusted`` -> ``trusted``,
    ``@trusted(...)`` -> ``trusted``), or None for a non-name decorator."""
    node = deco.func if isinstance(deco, ast.Call) else deco
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


class ContradictoryTrust:
    rule_id = METADATA.rule_id
    metadata = METADATA

    def __init__(self, base_severity: Severity | None = None) -> None:
        self.base_severity = base_severity or METADATA.base_severity

    def check(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for qualname, entity in context.entities.items():
            prov = context.taint_provenance.get(qualname)
            if prov is None or prov.source != "anchored":
                continue  # opt-in: only where the engine confirmed a real trust marker
            markers = {name for deco in entity.node.decorator_list if (name := _marker_name(deco)) in _MARKER_NAMES}
            if len(markers) < 2:
                continue
            taint_path = "+".join(sorted(markers))
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    message=(
                        f"{qualname} carries contradictory trust markers ({taint_path}); the engine "
                        f"resolves the clash to the least-trusted seed, silently ignoring the rest"
                    ),
                    severity=self.base_severity,
                    kind=Kind.DEFECT,
                    location=entity.location,
                    fingerprint=_fp(
                        rule_id=self.rule_id,
                        path=entity.location.path,
                        line_start=entity.location.line_start,
                        qualname=qualname,
                        taint_path=taint_path,
                    ),
                    qualname=qualname,
                    properties={"markers": taint_path},
                )
            )
        return findings
