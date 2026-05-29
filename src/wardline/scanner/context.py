# src/wardline/scanner/context.py
"""The analyzer's structured output + the (empty in SP1) rule-dispatch seam.

``AnalysisContext`` carries exactly what SP2 policy rules consume: the
project-scope taint map, per-function L2 variable taints, the entity index, and
the L3 provenance. ``RuleRegistry`` is the dispatch seam — SP1 registers no
rules, so ``run`` returns nothing; SP2 supplies the rule set.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Mapping

    from wardline.core.finding import Finding
    from wardline.core.taints import TaintState
    from wardline.scanner.index import Entity
    from wardline.scanner.taint.propagation import TaintProvenance


@dataclass(frozen=True, slots=True)
class AnalysisContext:
    """Engine output handed to SP2 rules (and to SP1f's own diagnostics).

    Inner mappings are wrapped in ``MappingProxyType`` at construction so the
    context is a genuinely read-only view — a consumer (or a retained reference
    to a source dict) cannot mutate engine output. ``function_var_taints``'s
    inner dicts are left as-is (cheap; rules treat them read-only by convention).
    """

    project_taints: Mapping[str, TaintState]
    function_var_taints: Mapping[str, Mapping[str, TaintState]]
    entities: Mapping[str, Entity]
    taint_provenance: Mapping[str, TaintProvenance]

    def __post_init__(self) -> None:
        object.__setattr__(self, "project_taints", MappingProxyType(dict(self.project_taints)))
        object.__setattr__(
            self, "function_var_taints", MappingProxyType(dict(self.function_var_taints))
        )
        object.__setattr__(self, "entities", MappingProxyType(dict(self.entities)))
        object.__setattr__(
            self, "taint_provenance", MappingProxyType(dict(self.taint_provenance))
        )


class _Rule(Protocol):
    rule_id: str

    def check(self, context: AnalysisContext) -> list[Finding]: ...


class RuleRegistry:
    """Ordered rule set. Empty in SP1 — SP2 registers the policy vocabulary."""

    def __init__(self) -> None:
        self._rules: list[_Rule] = []

    def register(self, rule: _Rule) -> None:
        self._rules.append(rule)

    @property
    def rules(self) -> tuple[_Rule, ...]:
        return tuple(self._rules)

    def run(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self._rules:
            findings.extend(rule.check(context))
        return findings
