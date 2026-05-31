# src/wardline/scanner/taint/minimum_scope.py
"""Bounded minimum-scope taint propagation: direct flows plus one undecorated
intermediary hop. Intentionally smaller than SP1d's transitive SCC engine — it
is a cheap pre-L3 refinement, and any flow it misses is recovered by SP1d.

Ported from ``wardline.old`` with two simplifications (see the SP1c plan):
  - edges are enumerated via ``iter_calls_in_function_body`` (over-approximates
    by including statically-dead branches — the conservative direction);
  - ``self.method()`` resolution is deferred to SP1d's callgraph (its omission
    under-taints, which only SP1d's full resolution recovers).
The ``.old`` "decorator"-anchored concept maps to SP1b's provider-declared
source (``FunctionSeed.source == "provider"``).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from functools import reduce
from typing import NamedTuple

from wardline.core.taints import TRUST_RANK, TaintState, least_trusted
from wardline.scanner.ast_primitives import iter_calls_in_function_body, resolve_call_fqn
from wardline.scanner.index import Entity


class ProjectFileData(NamedTuple):
    """Per-file metadata for bounded call-edge resolution."""

    entities: tuple[Entity, ...]
    import_aliases: dict[str, str]
    module_path: str


@dataclass(frozen=True, slots=True)
class MinimumScopeProvenance:
    """Audit record for a function whose taint the minimum-scope pass changed."""

    via_callee: str | None
    resolved_callee_count: int  # distinct resolved callees (edges is a set)
    unresolved_call_count: int  # unresolved call *sites* (counted per occurrence)
    source: str = "minimum_scope"


def build_minimum_scope_edges(
    file_data: list[ProjectFileData],
) -> tuple[dict[str, frozenset[str]], dict[str, int]]:
    """Build project-local call edges keyed by caller qualname.

    Resolution (conservative): local bare-name functions and imported/project
    aliases via ``resolve_call_fqn``. Everything else is counted as unresolved.
    """
    global_fqns = frozenset(e.qualname for fd in file_data for e in fd.entities)

    edges: dict[str, frozenset[str]] = {}
    unresolved_counts: dict[str, int] = {}

    for fd in file_data:
        local_fqns = frozenset(e.qualname for e in fd.entities)
        for entity in fd.entities:
            resolved: set[str] = set()
            unresolved = 0
            for call in iter_calls_in_function_body(entity.node):
                callee_fqn = resolve_call_fqn(
                    call, fd.import_aliases, local_fqns, fd.module_path
                )
                if callee_fqn is not None and callee_fqn in global_fqns:
                    resolved.add(callee_fqn)
                else:
                    unresolved += 1
            edges[entity.qualname] = frozenset(resolved)
            unresolved_counts[entity.qualname] = unresolved

    return edges, unresolved_counts


def refine_minimum_scope_taints(
    *,
    target_functions: Iterable[str],
    edges: Mapping[str, frozenset[str]],
    seed_taints: Mapping[str, TaintState],
    seed_sources: Mapping[str, str],
    return_taints: Mapping[str, TaintState],
    unresolved_counts: Mapping[str, int],
) -> tuple[dict[str, TaintState], dict[str, MinimumScopeProvenance]]:
    """Refine each target's L1 taint using its callees, bounded to one
    undecorated intermediary hop.

    A callee whose source is ``"provider"`` is *anchored*: its declared return
    taint is used directly (no recursion). Other callees are refined one hop
    deeper. Callee taints are combined with the rank-meet ``least_trusted``
    (weakest-link), NOT ``taint_join``: this is a function-summary AGGREGATION of
    the influence of a *set* of callees, not a single value built by merging two
    provenances, so ``taint_join``'s provenance-clash ``MIXED_RAW`` is the wrong
    label — two clean-but-different-family callees (e.g. an ``ASSURED`` validator
    and an ``INTEGRAL`` literal helper) must not clash a clean caller to
    ``MIXED_RAW`` (rank 7, in the firing RAW_ZONE) and manufacture a PY-WL-101
    false positive. ``least_trusted`` keeps any raw callee's rank (sound: a raw
    callee still propagates and fires), without the spurious jump. Consistent
    with the L2 expression/control-flow combiners (wardline-4d94577013,
    wardline-4d9f840c24). The combined result is then floored so refinement never
    makes a function MORE trusted than its own seed. Provenance is recorded only
    for functions whose taint actually changed.
    """

    def _seed(func: str) -> TaintState:
        return seed_taints[func]

    def _opt_seed(func: str) -> TaintState | None:
        return seed_taints.get(func)

    def _edges(func: str) -> frozenset[str]:
        return edges.get(func, frozenset())

    def _unresolved(func: str) -> int:
        return unresolved_counts.get(func, 0)

    def _anchor_or_seed(func: str) -> TaintState:
        if seed_sources.get(func) == "provider":
            return return_taints.get(func, _seed(func))
        return _seed(func)

    def _refine(
        func: str, *, remaining_intermediaries: int, stack: frozenset[str]
    ) -> tuple[TaintState, str | None]:
        seed = _seed(func)
        if remaining_intermediaries < 0:
            return seed, None

        direct_callees = [
            callee
            for callee in sorted(_edges(func))
            if callee not in stack and callee != func and _opt_seed(callee) is not None
        ]
        if not direct_callees:
            return seed, None

        influenced: list[tuple[str, TaintState]] = []
        for callee in direct_callees:
            if seed_sources.get(callee) == "provider":
                influenced.append((callee, _anchor_or_seed(callee)))
                continue
            callee_taint, _ = _refine(
                callee,
                remaining_intermediaries=remaining_intermediaries - 1,
                stack=stack | {callee},
            )
            influenced.append((callee, callee_taint))

        # Aggregate the influence of this function's callee SET into one summary
        # taint via the rank-meet least_trusted (weakest-link), NOT taint_join:
        # a clean caller of two clean-but-different-family callees must stay clean,
        # not clash to MIXED_RAW (see this function's docstring). A raw callee
        # still propagates at its precise rank.
        combined = reduce(least_trusted, (taint for _, taint in influenced))
        # Floor: refinement only ever demotes (toward less-trusted), never
        # promotes. This single clamp also covers the unresolved-call case —
        # after it, TRUST_RANK[combined] >= TRUST_RANK[seed] unconditionally, so
        # functions with unresolved calls already keep their (no-less-trusted)
        # seed floor; no separate unresolved clamp is needed.
        if TRUST_RANK[seed] > TRUST_RANK[combined]:
            combined = seed

        via_callee = max(influenced, key=lambda item: (TRUST_RANK[item[1]], item[0]))[0]
        return combined, via_callee

    refined: dict[str, TaintState] = {}
    provenance: dict[str, MinimumScopeProvenance] = {}

    for func in target_functions:
        seed = _opt_seed(func)
        if seed is None:
            continue
        refined_taint, via_callee = _refine(
            func, remaining_intermediaries=1, stack=frozenset({func})
        )
        refined[func] = refined_taint
        if refined_taint != seed:
            provenance[func] = MinimumScopeProvenance(
                via_callee=via_callee,
                resolved_callee_count=len(_edges(func)),
                unresolved_call_count=_unresolved(func),
            )

    return refined, provenance
