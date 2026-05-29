# src/wardline/scanner/taint/reverse_edge_index.py
"""Module-granular reverse-edge index for incremental dirty-set propagation.

Inverts the project's forward call graph at MODULE granularity (aligned with
the module-level summary cache_key) and supports a transitive closure over a
seed set of dirty modules: ``transitive_callers(dirty)`` returns ``dirty`` plus
every module that reaches a dirty module via reverse edges.

The index is built from an explicit ``fqn -> module`` map (which the resolver
already knows), NOT by string surgery on the FQN — a method FQN like
``pkg.a.Cls.method`` must reverse-key under module ``pkg.a``, not class
``pkg.a.Cls``.

Role note: in Wardline's resolver the forward edges and call counts are
recomputed fresh on every run, and the cache stores only source-determined
taint. So this closure is a PERFORMANCE over-approximation that bounds which
clean modules skip provider re-invocation — it is NOT a taint-correctness gate.
``cache_key`` is the correctness gate.
"""

from __future__ import annotations

from collections.abc import Mapping, Set
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ReverseModuleIndex:
    """Module-granularity reverse index derived from FQN-level forward edges.

    Intra-module edges are dropped: a module is always in its own dirty seed,
    so a self-reverse entry would be uninformative.
    """

    _reverse: Mapping[str, frozenset[str]]

    @classmethod
    def from_forward_edges(
        cls,
        forward: Mapping[str, Set[str]],
        *,
        fqn_to_module: Mapping[str, str],
    ) -> ReverseModuleIndex:
        """Build the reverse index. ``forward`` is ``{caller_fqn: {callee_fqn}}``;
        ``fqn_to_module`` maps every FQN appearing in ``forward`` to its module."""
        rev: dict[str, set[str]] = {}
        for caller_fqn, callee_fqns in forward.items():
            caller_mod = fqn_to_module[caller_fqn]
            for callee_fqn in callee_fqns:
                callee_mod = fqn_to_module[callee_fqn]
                if caller_mod == callee_mod:
                    continue  # intra-module — skip
                try:
                    rev[callee_mod].add(caller_mod)
                except KeyError:
                    rev[callee_mod] = {caller_mod}
        return cls(_reverse={k: frozenset(v) for k, v in rev.items()})

    def callers_of(self, callee_module: str) -> frozenset[str]:
        """Modules that call INTO ``callee_module`` (one reverse hop)."""
        try:
            return self._reverse[callee_module]
        except KeyError:
            return frozenset()

    def transitive_callers(self, seeds: frozenset[str]) -> frozenset[str]:
        """``seeds`` plus every transitively-reverse-reachable module."""
        closure: set[str] = set(seeds)
        frontier: set[str] = set(seeds)
        while frontier:
            next_frontier: set[str] = set()
            for mod in frontier:
                if mod not in self._reverse:
                    continue
                for caller_mod in self._reverse[mod]:
                    if caller_mod not in closure:
                        closure.add(caller_mod)
                        next_frontier.add(caller_mod)
            frontier = next_frontier
        return frozenset(closure)
