"""WP5: the Rust analyzer — index + provider + dataflow + rules, one tree/nmap.

``analyze_source`` parses ONCE, mints ONE ``NodeIdMap``, and threads it through entity
indexing, per-function trust seeding (the ``@trusted`` provider), builder-dataflow, and the
verdict rules — so callgraph/dataflow/rule passes share the single keying authority (spec
§5; a re-parse would mint divergent NodeIds and fail quietly). The full ``Analyzer`` protocol
(``analyze(files, config, *, root)`` + ``last_context`` for ``run_scan``) lands in WP6.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from wardline.core.taints import TaintState
from wardline.rust.context import RustAnalysisContext, RustTriggerContext
from wardline.rust.dataflow import analyze_command_dataflow
from wardline.rust.index import index_entities
from wardline.rust.nodeid import mint_node_ids
from wardline.rust.parse import parse_rust
from wardline.rust.provider import RustTrustProvider
from wardline.rust.rules import RustProgramInjectionRule, RustShellInjectionRule

if TYPE_CHECKING:
    from wardline.core.finding import Finding

__all__ = ["RustAnalyzer"]

_FAIL_CLOSED = TaintState.UNKNOWN_RAW  # an unmarked fn declares no trust -> findings suppressed


class RustAnalyzer:
    """Slice-1 Rust analyzer. Holds the rule set and the last computed context."""

    def __init__(self) -> None:
        self._provider = RustTrustProvider()
        self._rules = (RustProgramInjectionRule(), RustShellInjectionRule())
        self._last_context: RustAnalysisContext | None = None

    @property
    def last_context(self) -> RustAnalysisContext | None:
        return self._last_context

    def analyze_source(self, source: str, *, module: str, path: str = "") -> list[Finding]:
        tree = parse_rust(source)
        nmap = mint_node_ids(tree)
        entities = index_entities(tree, nmap, module=module, path=path)

        project_taints: dict[str, TaintState] = {}
        triggers: list[RustTriggerContext] = []
        for entity in entities:
            seed = self._provider.taint_for(entity.node)
            tier = seed.body_taint if seed is not None else _FAIL_CLOSED
            project_taints[entity.qualname] = tier
            body = entity.node.child_by_field_name("body")
            if body is None:
                continue
            for trig in analyze_command_dataflow(body, nmap):
                triggers.append(RustTriggerContext(trigger=trig, qualname=entity.qualname, tier=tier, path=path))

        context = RustAnalysisContext(
            triggers=tuple(triggers),
            project_taints=project_taints,
            entities={e.qualname: e for e in entities},
        )
        self._last_context = context

        findings: list[Finding] = []
        for rule in self._rules:
            findings.extend(rule.check(context))
        return findings
