# src/wardline/scanner/context.py
"""The analyzer's structured output + the (empty in SP1) rule-dispatch seam.

``AnalysisContext`` carries exactly what SP2 policy rules consume: the
project-scope taint map, per-function L2 variable taints, the entity index, and
the L3 provenance. ``RuleRegistry`` is the dispatch seam — SP1 registers no
rules, so ``run`` returns nothing; SP2 supplies the rule set.
"""

from __future__ import annotations

from collections.abc import Mapping as MappingABC
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Protocol

from wardline.core.finding import Maturity
from wardline.core.protocols import Rule

if TYPE_CHECKING:
    from collections.abc import Mapping

    from wardline.core.finding import Finding, Severity
    from wardline.core.taints import TaintState
    from wardline.scanner.index import Entity
    from wardline.scanner.taint.propagation import TaintProvenance


def _freeze_mapping(mapping: MappingABC[Any, Any]) -> MappingABC[Any, Any]:
    return MappingProxyType({key: _freeze_value(value) for key, value in mapping.items()})


def _freeze_value(value: Any) -> Any:
    if isinstance(value, MappingABC):
        return _freeze_mapping(value)
    if isinstance(value, set):
        return frozenset(value)
    return value


@dataclass(frozen=True, slots=True)
class AnalysisContext:
    """Engine output handed to SP2 rules (and to SP1f's own diagnostics).

    Nested mappings are wrapped in ``MappingProxyType`` at construction so the
    context is a genuinely read-only view — a consumer (or a retained reference
    to a source dict) cannot mutate engine output.

    ``project_return_taints`` is the effective return tier per function (anchored:
    declared; non-anchored: refined body). ``function_return_taints`` is the actual
    least-trusted returned-value taint per function, computed from L2 variable
    analysis — the precise input for PY-WL-101. ``function_return_callee`` is the
    callee that contributed each function's actual (least-trusted) return taint, or
    ``None`` when that worst return path is not a direct call (``return p`` /
    ``return some_var`` — chain resolution is deferred to SP9). This is the property
    ``explain_finding`` reports as the immediate tainted callee.
    """

    project_taints: Mapping[str, TaintState]
    project_return_taints: Mapping[str, TaintState]
    function_var_taints: Mapping[str, Mapping[str, TaintState]]
    function_return_taints: Mapping[str, TaintState]
    function_return_callee: Mapping[str, str | None]
    entities: Mapping[str, Entity]
    taint_provenance: Mapping[str, TaintProvenance]
    # FLOW-SENSITIVE per-statement snapshots: ``{qualname: {id(stmt): {var: taint}}}``,
    # the var-taint map on entry to each statement. The sink rules read the snapshot
    # of a sink call's enclosing statement to resolve arg taint AT the sink line (not
    # the flow-insensitive final map). Defaulted so direct constructions (tests) need
    # not supply it; absence degrades a consumer to the final-map read.
    function_call_site_taints: Mapping[str, Mapping[int, Mapping[str, TaintState]]] = field(default_factory=dict)
    # FLOW-SENSITIVE call-site argument taints: ``{qualname: {id(call): {arg_idx_or_kw: taint}}}``.
    function_call_site_arg_taints: Mapping[str, Mapping[int, Mapping[int | str | None, TaintState]]] = field(
        default_factory=dict
    )
    # Resolved call targets in the project: ``{id(call): callee_qn}``.
    call_site_callees: Mapping[int, str] = field(default_factory=dict)
    # Bound method call sites whose explicit args start after an implicit receiver:
    # ``{id(call): "instance" | "class"}``.
    call_site_implicit_receivers: Mapping[int, str] = field(default_factory=dict)
    # Branch-conditional dispatch: the FULL candidate callee set at a call site whose
    # receiver may hold >1 project class (``{id(call): frozenset(callee_qn)}``). A
    # superset of ``call_site_callees`` for those sites; sink rules consult it so they
    # fire on any trusted-sink candidate regardless of AST order (wardline-499c22bbdd).
    call_site_candidate_callees: Mapping[int, frozenset[str]] = field(default_factory=dict)
    # Cross-method class-attribute summary (closure A): ``{class_qualname: {attr: taint}}``,
    # the least-trusted value written to ``self.<attr>`` across the class's methods. Rules
    # resolve a ``self.<attr>``/``cls.<attr>`` read against it. Defaulted for direct
    # constructions; absence means no cross-method attribute taint (function-level only).
    class_attr_taints: Mapping[str, Mapping[str, TaintState]] = field(default_factory=dict)
    # Qualnames of entities the L1 provider seeded from a DECLARATION (a trust
    # decorator) — the "trust surface". Read by core/assure.py as the coverage
    # denominator. Additive + defaulted so direct constructions/tests need not
    # supply it; frozenset is already immutable so no proxy wrap is needed.
    declared_qualnames: frozenset[str] = frozenset()
    # Inter-module call edges: ``{caller: frozenset({callees})}``. Defaulted for
    # direct constructions; absence means no project edges available.
    project_edges: Mapping[str, frozenset[str]] = field(default_factory=dict)
    # Import alias maps per module: ``{module: {alias: target_fqn}}``.
    alias_maps: Mapping[str, Mapping[str, str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "project_taints", _freeze_mapping(self.project_taints))
        object.__setattr__(self, "project_return_taints", _freeze_mapping(self.project_return_taints))
        object.__setattr__(self, "function_var_taints", _freeze_mapping(self.function_var_taints))
        object.__setattr__(self, "function_return_taints", _freeze_mapping(self.function_return_taints))
        object.__setattr__(self, "function_return_callee", _freeze_mapping(self.function_return_callee))
        object.__setattr__(self, "entities", _freeze_mapping(self.entities))
        object.__setattr__(self, "taint_provenance", _freeze_mapping(self.taint_provenance))
        object.__setattr__(self, "function_call_site_taints", _freeze_mapping(self.function_call_site_taints))
        object.__setattr__(
            self,
            "function_call_site_arg_taints",
            _freeze_mapping(self.function_call_site_arg_taints),
        )
        object.__setattr__(self, "call_site_callees", _freeze_mapping(self.call_site_callees))
        object.__setattr__(
            self,
            "call_site_implicit_receivers",
            _freeze_mapping(self.call_site_implicit_receivers),
        )
        object.__setattr__(
            self,
            "call_site_candidate_callees",
            _freeze_mapping(self.call_site_candidate_callees),
        )
        object.__setattr__(self, "class_attr_taints", _freeze_mapping(self.class_attr_taints))
        object.__setattr__(
            self,
            "project_edges",
            _freeze_mapping({k: frozenset(v) for k, v in self.project_edges.items()}),
        )
        object.__setattr__(
            self,
            "alias_maps",
            _freeze_mapping(self.alias_maps),
        )


class _RuleClass(Protocol):
    """A rule *class*: a ``rule_id`` classvar plus a ``base_severity``-taking
    constructor that yields a :class:`_Rule`. This is what a ``TrustGrammar``
    registers (Track 2) — the registry instantiates it per-config so
    ``weft.toml [wardline]`` severity overrides apply."""

    rule_id: str

    def __call__(self, base_severity: Severity | None = ...) -> Rule: ...


class RuleRegistry:
    """Ordered rule set. Empty in SP1 — SP2 registers the policy vocabulary."""

    def __init__(self) -> None:
        self._rules: list[Rule] = []

    def register(self, rule: Rule) -> None:
        self._rules.append(rule)

    @property
    def rules(self) -> tuple[Rule, ...]:
        return tuple(self._rules)

    def run(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self._rules:
            rule_findings = rule.check(context)
            metadata = getattr(rule, "metadata", None)
            maturity = getattr(metadata, "maturity", None) if metadata is not None else None
            if maturity and maturity != Maturity.STABLE:
                rule_findings = [replace(f, maturity=maturity) for f in rule_findings]
            findings.extend(rule_findings)
        return findings
