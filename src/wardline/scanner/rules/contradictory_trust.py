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
from collections.abc import Mapping
from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.scanner.grammar import BUILTIN_BOUNDARY_TYPES
from wardline.scanner.rules.metadata import RuleMetadata

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext

# The recognised trust-marker names (the grammar boundary types' canonical names)
# and the module prefixes they may be imported from. A custom grammar's markers are
# the agent's own concern; the builtin rule keys on the builtin vocabulary, which is
# the contract Wardline ships. Both names AND prefixes are derived from
# BUILTIN_BOUNDARY_TYPES so the rule cannot drift from the grammar — the prefix set
# is how ``wardline.decorators`` and the renamed ``weft_markers`` shim are BOTH
# recognised (wardline-d62845bb18: hardcoding only ``wardline.decorators`` silently
# missed contradictory stacks written against the recommended ``weft_markers`` shim).
_MARKER_NAMES: frozenset[str] = frozenset(bt.canonical_name for bt in BUILTIN_BOUNDARY_TYPES)
_MARKER_MODULE_PREFIXES: frozenset[str] = frozenset(bt.module_prefix for bt in BUILTIN_BOUNDARY_TYPES)

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


def _dotted_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base is not None else None
    return None


def _resolve_decorator_fqn(deco: ast.expr, alias_map: Mapping[str, str]) -> str | None:
    func = deco.func if isinstance(deco, ast.Call) else deco
    dotted = _dotted_name(func)
    if dotted is None:
        return None
    head, _, rest = dotted.partition(".")
    head_fqn = alias_map.get(head, head)
    return f"{head_fqn}.{rest}" if rest else head_fqn


def _marker_canonical_name(deco: ast.expr, alias_map: Mapping[str, str]) -> str | None:
    fqn = _resolve_decorator_fqn(deco, alias_map)
    if fqn is None:
        return None
    last = fqn.rsplit(".", 1)[-1]
    if last in _MARKER_NAMES and any(fqn.startswith(prefix + ".") for prefix in _MARKER_MODULE_PREFIXES):
        return last
    return None


class ContradictoryTrust:
    rule_id = METADATA.rule_id
    metadata = METADATA

    def __init__(self, base_severity: Severity | None = None) -> None:
        self.base_severity = base_severity or METADATA.base_severity

    def check(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        modules = list(context.alias_maps.keys())
        for qualname, entity in context.entities.items():
            prov = context.taint_provenance.get(qualname)
            if prov is None or prov.source != "anchored":
                continue  # opt-in: only where the engine confirmed a real trust marker

            # Find the module name that owns this entity
            mod_name = None
            for m in sorted(modules, key=len, reverse=True):
                if qualname == m or qualname.startswith(m + "."):
                    mod_name = m
                    break
            alias_map = (context.alias_maps.get(mod_name) if mod_name is not None else None) or {}

            markers = set()
            for deco in entity.node.decorator_list:
                name = _marker_canonical_name(deco, alias_map)
                if name is not None:
                    markers.add(name)

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
