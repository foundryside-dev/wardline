"""SCC decomposition and fixed-point call-graph taint propagation (L3).

Provides iterative Tarjan's SCC algorithm and the main propagation loop
that refines L1 function-level taints by analysing what each function calls.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from wardline.scanner.taint.callgraph import L3_LOW_RESOLUTION_THRESHOLD, TRUST_RANK

if TYPE_CHECKING:
    from collections.abc import Iterator

    from wardline.core.taints import TaintState
    from wardline.scanner.taint.function_level import TaintSource

logger = logging.getLogger(__name__)

# Multiplier for the per-SCC convergence safety bound.  The worklist is
# allowed at most ``_CONVERGENCE_BOUND_FACTOR * len(scc)`` iterations.
_CONVERGENCE_BOUND_FACTOR: int = 8


# ── Provenance dataclass ──────────────────────────────────────────


@dataclass(frozen=True)
class TaintProvenance:
    """Records how a function's L3 taint was determined.

    Every function in the propagation output has a provenance record.
    """

    source: Literal["decorator", "module_default", "callgraph", "fallback"]
    via_callee: str | None = None
    resolved_call_count: int = 0
    unresolved_call_count: int = 0


# ── Fixed-point propagation ───────────────────────────────────────


def propagate_callgraph_taints(
    edges: dict[str, set[str]],
    taint_map: dict[str, TaintState],
    taint_sources: dict[str, TaintSource],
    resolved_counts: dict[str, int],
    unresolved_counts: dict[str, int],
    *,
    return_taint_map: dict[str, TaintState],
) -> tuple[dict[str, TaintState], dict[str, TaintProvenance], list[tuple[str, str]]]:
    """Run SCC-based fixed-point propagation to refine L1 taints.

    Args:
        edges: Forward adjacency ``{caller: {callee, ...}}``.
        taint_map: L1 body-evaluation taint assignments (copied, not mutated).
        taint_sources: L1 provenance classification per function.
        resolved_counts: Resolved call-site counts per caller.
        unresolved_counts: Unresolved call-site counts per caller.
        return_taint_map: L1 return-value taint map. Used to resolve
            decorator-anchored callee contributions (OUTPUT tier).

    Returns:
        Tuple of ``(refined_taint_map, provenance_map, diagnostics)``.
        Diagnostics is a list of ``(code, message)`` tuples for
        L3_CONVERGENCE_BOUND and L3_LOW_RESOLUTION conditions.
    """
    from wardline.core.taints import TaintState

    if not taint_map:
        return {}, {}, []

    diagnostics: list[tuple[str, str]] = []

    # --- 1. Classify functions ------------------------------------------------
    anchored: set[str] = set()
    floating_down: set[str] = set()   # module_default
    floating_free: set[str] = set()   # fallback

    for func, src in taint_sources.items():
        if src == "decorator":
            anchored.add(func)
        elif src == "module_default":
            floating_down.add(func)
        else:
            floating_free.add(func)

    # --- 2. Initialize to L1 taints (copy unchanged) -------------------------
    current: dict[str, TaintState] = dict(taint_map)

    # Track which callee caused the refinement (for provenance)
    via_callee_map: dict[str, str | None] = {f: None for f in taint_map}

    # Track which functions were actually refined by L3
    refined: set[str] = set()

    # --- 3. Build reverse edge map --------------------------------------------
    reverse_edges: dict[str, set[str]] = {f: set() for f in taint_map}
    for caller, callees in edges.items():
        for callee in callees:
            try:
                reverse_edges[callee].add(caller)
            except KeyError:
                _rev = None  # callee not in taint_map — external call, skip reverse edge

    # --- 4. SCC decomposition -------------------------------------------------
    # Only include nodes that are in taint_map
    taint_keys = set(taint_map)
    scc_graph: dict[str, set[str]] = {}
    for func in taint_map:
        try:
            func_edges = edges[func]
        except KeyError:
            func_edges = set()
        scc_graph[func] = func_edges & taint_keys

    sccs = compute_sccs(scc_graph)

    # --- 5. Worklist iteration per SCC ----------------------------------------
    # Pre-compute rank-to-state reverse map (static, built once)
    rank_to_state = {r: s for s, r in TRUST_RANK.items()}

    for scc in sccs:
        # Skip all-anchored SCCs — they cannot change
        if scc <= anchored:
            continue

        safety_bound = _CONVERGENCE_BOUND_FACTOR * len(scc) * len(scc)
        iterations = 0

        # Phase 1: Compute external influence for each SCC member.
        # Only consider callees OUTSIDE the SCC (already at their final taint
        # since SCCs are processed in reverse-topo order).
        # Then initialize non-anchored SCC members to external-only estimate.
        has_external_influence: set[str] = set()
        for f in scc:
            if f in anchored:
                continue
            try:
                f_edges = edges[f]
            except KeyError:
                f_edges = set()
            ext_callees = (f_edges & taint_keys) - scc
            if ext_callees:
                has_external_influence.add(f)
                # For anchored callees, use return_taint (their static output tier).
                # For non-anchored callees, use current[] (L3-refined body taint).
                # This is correct because non-anchored functions always have
                # body_taint == return_taint (enforced by _walk_and_assign in
                # function_level.py), so current[c] serves as both.
                ext_ranks: list[int] = []
                for c in ext_callees:
                    if c in anchored:
                        try:
                            c_return_taint = return_taint_map[c]
                        except KeyError:
                            c_return_taint = current[c]
                        ext_ranks.append(TRUST_RANK[c_return_taint])
                    else:
                        ext_ranks.append(TRUST_RANK[current[c]])
                ext_max = max(ext_ranks)
                if f in floating_down:
                    l1_rank = TRUST_RANK[taint_map[f]]
                    ext_max = max(ext_max, l1_rank)
                elif f in floating_free:
                    # Fix 1: floor clamp for floating_free in Phase 1
                    l1_rank = TRUST_RANK[taint_map[f]]
                    ext_max = max(ext_max, l1_rank)
                # Fix 2: unresolved calls pessimistic floor in Phase 1
                try:
                    f_unresolved = unresolved_counts[f]
                except KeyError:
                    f_unresolved = 0
                if f_unresolved > 0:
                    ext_max = max(ext_max, TRUST_RANK[taint_map[f]])
                ext_taint = rank_to_state[ext_max]
                if ext_taint != current[f]:
                    current[f] = ext_taint
                    refined.add(f)
                    # Record via_callee from external callees.
                    # Use the same anchored/floating logic as rank computation.
                    best_callee: str | None = None
                    best_rank = -1
                    for c in sorted(ext_callees):
                        if c in anchored:
                            try:
                                c_return_taint = return_taint_map[c]
                            except KeyError:
                                c_return_taint = current[c]
                            c_rank = TRUST_RANK[c_return_taint]
                        else:
                            c_rank = TRUST_RANK[current[c]]
                        if c_rank > best_rank:
                            best_rank = c_rank
                            best_callee = c
                    via_callee_map[f] = best_callee

        # Phase 2: Worklist iteration within the SCC to propagate internal edges.
        # Start with all non-anchored members that have callers with new values.
        worklist = {f for f in scc if f not in anchored}

        while worklist:
            if iterations >= safety_bound:
                logger.warning(
                    "L3 convergence bound hit for SCC of size %d after %d iterations",
                    len(scc),
                    iterations,
                )
                diagnostics.append((
                    "L3_CONVERGENCE_BOUND",
                    f"SCC of size {len(scc)} hit iteration bound after {iterations} iterations",
                ))
                break

            func = min(worklist)  # deterministic pick
            worklist.discard(func)
            iterations += 1

            # Gather ALL callee taints (both inside and outside SCC)
            try:
                func_edges = edges[func]
            except KeyError:
                func_edges = set()
            callee_set = func_edges & taint_keys
            if not callee_set:
                # No resolved callees — stay at current taint
                continue

            # Compute max_rank (least trusted) among callees
            callee_ranks: list[int] = []
            for c in callee_set:
                if c in anchored:
                    try:
                        c_return_taint = return_taint_map[c]
                    except KeyError:
                        c_return_taint = current[c]
                    callee_ranks.append(TRUST_RANK[c_return_taint])
                else:
                    callee_ranks.append(TRUST_RANK[current[c]])
            max_callee_rank = max(callee_ranks, default=TRUST_RANK[TaintState.INTEGRAL])

            # Floor clamp for module_default: result >= L1 rank
            if func in floating_down:
                l1_rank = TRUST_RANK[taint_map[func]]
                result_rank = max(max_callee_rank, l1_rank)
            elif func in floating_free:
                # Fix 1: floor clamp — L3 must never make a function MORE
                # trusted than its L1 baseline.
                l1_rank = TRUST_RANK[taint_map[func]]
                result_rank = max(max_callee_rank, l1_rank)
            else:
                # anchored — skip (shouldn't reach here due to worklist filter)
                continue

            # Fix 2: unresolved calls pessimistic floor — if this function
            # has unresolved calls, it cannot be more trusted than its L1
            # baseline (unresolved calls could go anywhere).
            try:
                func_unresolved = unresolved_counts[func]
            except KeyError:
                func_unresolved = 0
            if func_unresolved > 0:
                result_rank = max(result_rank, TRUST_RANK[taint_map[func]])

            new_taint = rank_to_state[result_rank]

            if new_taint != current[func]:
                current[func] = new_taint
                refined.add(func)

                # Determine via_callee: the callee with highest rank (least trusted).
                # Use the same anchored/floating logic as rank computation.
                # Tie-break: alphabetically first qualname.
                best_callee_wl: str | None = None
                best_rank_wl = -1
                for c in sorted(callee_set):  # sorted for tie-breaking
                    if c in anchored:
                        try:
                            c_return_taint = return_taint_map[c]
                        except KeyError:
                            c_return_taint = current[c]
                        c_rank = TRUST_RANK[c_return_taint]
                    else:
                        c_rank = TRUST_RANK[current[c]]
                    if c_rank > best_rank_wl:
                        best_rank_wl = c_rank
                        best_callee_wl = c

                via_callee_map[func] = best_callee_wl

                # Add callers within this SCC to worklist
                try:
                    func_callers = reverse_edges[func]
                except KeyError:
                    func_callers = set()
                for caller in func_callers:
                    if caller in scc and caller not in anchored:
                        worklist.add(caller)

    # --- 6. Post-fixed-point assertions ---------------------------------------
    for func in anchored:
        if current[func] != taint_map[func]:
            logger.error(
                "L3 post-assertion FAILED: anchored function %s changed from %s to %s",
                func,
                taint_map[func],
                current[func],
            )
            return dict(taint_map), _seed_provenance_only(
                taint_map, taint_sources, resolved_counts, unresolved_counts,
            ), diagnostics

    for func in floating_down:
        if TRUST_RANK[current[func]] < TRUST_RANK[taint_map[func]]:
            logger.error(
                "L3 post-assertion FAILED: module_default function %s upgraded from %s to %s",
                func,
                taint_map[func],
                current[func],
            )
            return dict(taint_map), _seed_provenance_only(
                taint_map, taint_sources, resolved_counts, unresolved_counts,
            ), diagnostics

    # --- 6b. L3_LOW_RESOLUTION detection --------------------------------------
    for func in taint_map:
        try:
            res = resolved_counts[func]
        except KeyError:
            res = 0
        try:
            unres = unresolved_counts[func]
        except KeyError:
            unres = 0
        total_calls = res + unres
        if total_calls > 0:
            unresolved_ratio = unres / total_calls
            if unresolved_ratio > L3_LOW_RESOLUTION_THRESHOLD:
                pct = int(unresolved_ratio * 100)
                diagnostics.append((
                    "L3_LOW_RESOLUTION",
                    f"Function {func} has {pct}% unresolved calls "
                    f"({unres}/{total_calls})",
                ))

    # --- 7. Build provenance records ------------------------------------------
    provenance: dict[str, TaintProvenance] = {}
    for func in taint_map:
        if func in anchored:
            try:
                func_resolved = resolved_counts[func]
            except KeyError:
                func_resolved = 0
            try:
                func_unresolved = unresolved_counts[func]
            except KeyError:
                func_unresolved = 0
            provenance[func] = TaintProvenance(
                source="decorator",
                via_callee=None,
                resolved_call_count=func_resolved,
                unresolved_call_count=func_unresolved,
            )
        elif func in refined:
            try:
                func_resolved = resolved_counts[func]
            except KeyError:
                func_resolved = 0
            try:
                func_unresolved = unresolved_counts[func]
            except KeyError:
                func_unresolved = 0
            try:
                func_via_callee = via_callee_map[func]
            except KeyError:
                func_via_callee = None
            provenance[func] = TaintProvenance(
                source="callgraph",
                via_callee=func_via_callee,
                resolved_call_count=func_resolved,
                unresolved_call_count=func_unresolved,
            )
        elif func in floating_down:
            try:
                func_resolved = resolved_counts[func]
            except KeyError:
                func_resolved = 0
            try:
                func_unresolved = unresolved_counts[func]
            except KeyError:
                func_unresolved = 0
            provenance[func] = TaintProvenance(
                source="module_default",
                via_callee=None,
                resolved_call_count=func_resolved,
                unresolved_call_count=func_unresolved,
            )
        else:
            # fallback, unrefined
            try:
                func_resolved = resolved_counts[func]
            except KeyError:
                func_resolved = 0
            try:
                func_unresolved = unresolved_counts[func]
            except KeyError:
                func_unresolved = 0
            provenance[func] = TaintProvenance(
                source="fallback",
                via_callee=None,
                resolved_call_count=func_resolved,
                unresolved_call_count=func_unresolved,
            )

    return current, provenance, diagnostics


def _seed_provenance_only(
    taint_map: dict[str, TaintState],
    taint_sources: dict[str, TaintSource],
    resolved_counts: dict[str, int],
    unresolved_counts: dict[str, int],
) -> dict[str, TaintProvenance]:
    """Build provenance records without any L3 refinement (fallback path)."""
    provenance: dict[str, TaintProvenance] = {}
    for func in taint_map:
        try:
            src = taint_sources[func]
        except KeyError:
            src = "fallback"
        if src == "decorator":
            prov_source: Literal["decorator", "module_default", "callgraph", "fallback"] = "decorator"
        elif src == "module_default":
            prov_source = "module_default"
        else:
            prov_source = "fallback"
        try:
            func_resolved = resolved_counts[func]
        except KeyError:
            func_resolved = 0
        try:
            func_unresolved = unresolved_counts[func]
        except KeyError:
            func_unresolved = 0
        provenance[func] = TaintProvenance(
            source=prov_source,
            via_callee=None,
            resolved_call_count=func_resolved,
            unresolved_call_count=func_unresolved,
        )
    return provenance


def compute_sccs(graph: dict[str, set[str]]) -> list[set[str]]:
    """Compute strongly connected components using iterative Tarjan's algorithm.

    Returns SCCs in reverse topological order of the condensation DAG
    (callees/leaves first), which is the natural output order of Tarjan's.

    Uses an explicit stack to avoid Python's recursion limit on large graphs.
    """
    index_counter = 0
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    on_stack: dict[str, bool] = {}
    stack: list[str] = []
    result: list[set[str]] = []

    # Work stack frames: (node, neighbor_iterator, is_first_visit)
    work_stack: list[tuple[str, Iterator[str], bool]] = []

    for start_node in sorted(graph):
        try:
            indices[start_node]
        except KeyError:
            _idx = None  # start_node not yet indexed — proceed with DFS
        else:
            continue

        # Push initial frame
        try:
            start_neighbors = graph[start_node]
        except KeyError:
            start_neighbors = set()
        work_stack.append((start_node, iter(sorted(start_neighbors)), True))

        while work_stack:
            node, neighbors, is_first_visit = work_stack.pop()

            if is_first_visit:
                # First visit: assign index and lowlink
                indices[node] = index_counter
                lowlinks[node] = index_counter
                index_counter += 1
                stack.append(node)
                on_stack[node] = True

            # Try to advance through neighbors
            pushed_child = False
            for neighbor in neighbors:
                try:
                    neighbor_edges = graph[neighbor]
                except KeyError:
                    neighbor_edges = None  # neighbor not in graph — skip
                    continue
                try:
                    indices[neighbor]
                except KeyError:
                    # Unvisited neighbor: save current frame and push child
                    work_stack.append((node, neighbors, False))
                    work_stack.append((neighbor, iter(sorted(neighbor_edges or ())), True))
                    pushed_child = True
                    break
                else:
                    # Visited neighbor — update lowlink if on stack
                    try:
                        neighbor_on_stack = on_stack[neighbor]
                    except KeyError:
                        neighbor_on_stack = False
                    if neighbor_on_stack:
                        lowlinks[node] = min(lowlinks[node], indices[neighbor])

            if pushed_child:
                continue

            # All neighbors processed: check if this is an SCC root
            if lowlinks[node] == indices[node]:
                scc: set[str] = set()
                while True:
                    w = stack.pop()
                    on_stack[w] = False
                    scc.add(w)
                    if w == node:
                        break
                result.append(scc)

            # Update parent's lowlink
            if work_stack:
                parent_node = work_stack[-1][0]
                lowlinks[parent_node] = min(lowlinks[parent_node], lowlinks[node])

    return result
