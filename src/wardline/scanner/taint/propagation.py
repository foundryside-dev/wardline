"""SCC decomposition and fixed-point call-graph taint propagation (L3).

SP1d kernel: port of ``wardline.old``'s ``callgraph_propagation.py``, decoupled
from ``RuleId``/``Severity``/``Finding``. Diagnostics are plain
``(code: str, message: str)`` tuples with string constants below.

Provides iterative Tarjan's SCC algorithm and the main propagation loop
that refines L1 function-level taints by analysing what each function calls.

Callee taint combination uses the rank-meet least_trusted() (weakest-link).
Every callee-combination site here AGGREGATES the influence of a *set* of
callees into one function-summary taint — it never models a single value built
by merging two provenances — so taint_join()'s provenance-clash MIXED_RAW is the
wrong label (two clean-but-different-family callees would clash a clean caller to
MIXED_RAW, rank 7 in the firing RAW_ZONE, a PY-WL-101 false positive). The
migration to least_trusted here mirrors the L2 expression/control-flow combiners
(wardline-4d94577013, wardline-4d9f840c24). taint_join() itself still lives in
core/taints.py; the two operators remain distinct and must never be collapsed at
the operator level — this module simply uses the aggregation-correct one.
TRUST_RANK additionally backs ordering comparisons (floor clamps,
post-assertions, provenance tiebreaks).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from functools import reduce
from typing import TYPE_CHECKING, Literal

from wardline.core.taints import TRUST_RANK

if TYPE_CHECKING:
    from collections.abc import Iterator

    # TaintSourceClass's canonical definition lives in summary.py; imported here
    # (TYPE_CHECKING only) so the kernel signature and the FunctionSummary field
    # cannot drift apart.
    from wardline.core.taints import TaintState
    from wardline.scanner.taint.summary import TaintSourceClass

logger = logging.getLogger(__name__)

L3_LOW_RESOLUTION_THRESHOLD = 0.70
DIAG_CONVERGENCE_BOUND = "L3_CONVERGENCE_BOUND"
DIAG_MONOTONICITY_VIOLATION = "L3_MONOTONICITY_VIOLATION"
DIAG_LOW_RESOLUTION = "L3_LOW_RESOLUTION"

# Multiplier for the per-SCC convergence safety bound. Equals the TaintState
# lattice height (8 trust levels). The worklist is allowed at most
# ``_scc_convergence_bound(len(scc))`` == ``8 * |SCC| + 8`` transfer evaluations
# before we emit a diagnostic and return the best conservative approximation
# reached so far. See ``_scc_convergence_bound`` for the derivation.
_CONVERGENCE_BOUND_FACTOR: int = 8


def _scc_convergence_bound(scc_size: int) -> int:
    """Maximum transfer iterations for an SCC of ``scc_size`` members.

    Derivation:
    The TaintState lattice has height 8 (INTEGRAL=0 through MIXED_RAW=7 in
    TRUST_RANK, plus one saturation step). In a single synchronous round,
    each non-anchored SCC member can move at most one lattice step in the
    worst case — a strictly monotone chain of ``|SCC|`` members can take up
    to ``height * |SCC|`` rounds to reach fixed point. The ``+ epsilon`` term
    (``epsilon = 8 = height``) absorbs the seed / initialisation round(s)
    that establish the Phase 1b taint_sources before the first transfer
    iteration, plus one boundary round for join stabilisation with
    already-converged neighbours outside the SCC.

    For an isolated node (``|SCC| = 1``) the bound is 16 — deliberately
    loose relative to the reachable maximum so the diagnostic does not
    fire on trivial convergence. For larger SCCs the bound is tight
    enough to detect genuine divergence without permitting spurious
    iteration.

    Independent per-SCC: Tarjan's decomposition processes each SCC in
    isolation, so the total bound across a graph is the sum over SCCs.
    """
    return _CONVERGENCE_BOUND_FACTOR * scc_size + _CONVERGENCE_BOUND_FACTOR


def _check_monotonicity_violation(
    *,
    old_taint: TaintState,
    new_taint: TaintState,
) -> bool:
    """Return True if ``new_taint`` represents a strictly more trusted state.

    The lattice is monotone by construction — a non-anchored function's taint
    never moves toward higher trust during propagation. A strict decrease in
    ``TRUST_RANK[taint]`` for a non-anchored function indicates a
    transfer-function bug. This helper isolates the comparison so tests can
    exercise it with crafted inputs without monkeypatching internal kernel
    state (Phase 2b.2).

    Anchor-status is NOT checked here — callers that already know the function
    is anchored must short-circuit before invoking this helper. That
    separation keeps the check mechanically simple: given two TaintStates,
    is the second strictly more trusted than the first.
    """
    return TRUST_RANK[new_taint] < TRUST_RANK[old_taint]


# ── Provenance dataclass ──────────────────────────────────────────


@dataclass(frozen=True)
class TaintProvenance:
    """Records how a function's L3 taint was determined.

    Every function in the propagation output has a provenance record.
    """

    source: Literal[
        "anchored",
        "module_default",
        "minimum_scope",
        "callgraph",
        "fallback",
    ]
    via_callee: str | None = None
    resolved_call_count: int = 0
    unresolved_call_count: int = 0


def _compute_scc_round(
    *,
    scc: set[str],
    anchored: set[str],
    edges: dict[str, set[str]],
    taint_keys: set[str],
    current: dict[str, TaintState],
    return_taint_map: dict[str, TaintState],
    phase2_floor: dict[str, TaintState],
) -> tuple[dict[str, TaintState], dict[str, str | None]]:
    """Compute one synchronous SCC refinement round from a stable snapshot."""
    from wardline.core.taints import least_trusted

    updates: dict[str, TaintState] = {}
    via_callee: dict[str, str | None] = {}

    for func in sorted(scc - anchored):
        try:
            callee_set = edges[func] & taint_keys
        except KeyError:
            callee_set = set()
        if not callee_set:
            continue

        callee_taints: list[TaintState] = []
        best_callee: str | None = None
        best_rank = -1
        for callee in sorted(callee_set):
            if callee in anchored:
                callee_taint = return_taint_map[callee] if return_taint_map.__contains__(callee) else current[callee]
            else:
                callee_taint = current[callee]
            callee_taints.append(callee_taint)
            rank = TRUST_RANK[callee_taint]
            if rank > best_rank:
                best_rank = rank
                best_callee = callee

        # Aggregate this function's callee SET into one summary taint via the
        # rank-meet least_trusted (weakest-link), NOT taint_join: clean callees of
        # different families must not clash the caller to MIXED_RAW (a RAW_ZONE
        # false positive); a raw callee still propagates at its precise rank.
        combined = reduce(least_trusted, callee_taints)
        floor = phase2_floor[func]
        # The line-above floor pins TRUST_RANK[new_taint] >= TRUST_RANK[floor]
        # unconditionally, so the former inner unresolved-clamp guard
        # (rank[floor] > rank[new_taint]) was never true — dead code removed
        # (taint-combination audit, F2; minimum_scope.py:158-161 makes the same
        # point in prose). The unresolved floor is already applied at seed time
        # (phase2_floor incorporates the unresolved pessimistic floor from the
        # Phase-1 external-influence pass).
        new_taint = floor if TRUST_RANK[floor] > TRUST_RANK[combined] else combined

        updates[func] = new_taint
        via_callee[func] = best_callee

    return updates, via_callee


# ── Fixed-point propagation ───────────────────────────────────────


def propagate_callgraph_taints(
    edges: dict[str, set[str]],
    taint_map: dict[str, TaintState],
    taint_sources: dict[str, TaintSourceClass],
    resolved_counts: dict[str, int],
    unresolved_counts: dict[str, int],
    *,
    return_taint_map: dict[str, TaintState],
) -> tuple[
    dict[str, TaintState],
    dict[str, TaintProvenance],
    list[tuple[str, str]],
    dict[frozenset[str], int],
]:
    """Run SCC-based fixed-point propagation to refine L1 taints.

    Args:
        edges: Forward adjacency ``{caller: {callee, ...}}``.
        taint_map: L1 body-evaluation taint assignments (copied, not mutated).
        taint_sources: L1 provenance classification per function.
        resolved_counts: Resolved call-site counts per caller.
        unresolved_counts: Unresolved call-site counts per caller.
        return_taint_map: L1 return-value taint map. Used to resolve
            anchored callee contributions (OUTPUT tier).

    Returns:
        Tuple of ``(refined_taint_map, provenance_map, diagnostics,
        scc_iteration_counts)``. Diagnostics is a list of ``(code, message)``
        tuples for L3_CONVERGENCE_BOUND and L3_LOW_RESOLUTION conditions.
        ``scc_iteration_counts`` maps each SCC (identified by its
        ``frozenset`` of member FQNs) to the number of Phase-2 fixed-point
        rounds it consumed. Convergent SCCs record ``iterations + 1``
        (the convergent round IS a round of work, per Revision 2 NEW-3
        off-by-one correction); bound-hit SCCs record ``iterations``
        (the L3_CONVERGENCE_BOUND diagnostic already marks the cap).
        The Phase 3a resolver aggregates this dict into
        ``ResolverRunMetadata.convergence_iterations_{max,histogram}``.
    """
    from wardline.core.taints import least_trusted

    scc_iteration_counts: dict[frozenset[str], int] = {}

    if not taint_map:
        return {}, {}, [], {}

    diagnostics: list[tuple[str, str]] = []

    # --- 1. Classify functions ------------------------------------------------
    anchored: set[str] = set()
    floating_down: set[str] = set()  # module_default
    floating_free: set[str] = set()  # fallback

    for func, src in taint_sources.items():
        if src == "anchored":
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

    # --- 3. SCC decomposition -------------------------------------------------
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

    # --- 4. Fixed-point propagation per SCC -----------------------------------
    for scc in sccs:
        # Skip all-anchored SCCs — they cannot change
        if scc <= anchored:
            continue

        safety_bound = _scc_convergence_bound(len(scc))
        iterations = 0

        # Phase 1: Compute external influence for each SCC member.
        # Only consider callees OUTSIDE the SCC (already at their final taint
        # since SCCs are processed in reverse-topo order).
        # Then initialize non-anchored SCC members to external-only estimate.
        for f in scc:
            if f in anchored:
                continue
            try:
                f_edges = edges[f]
            except KeyError:
                f_edges = set()
            ext_callees = (f_edges & taint_keys) - scc
            if ext_callees:
                # For anchored callees, use return_taint (their static output tier).
                # For non-anchored callees, use current[] (L3-refined body taint).
                # This is correct because non-anchored functions always have
                # body_taint == return_taint (enforced by _walk_and_assign in
                # function_level.py), so current[c] serves as both.
                # Aggregate the external-callee SET into one summary taint via the
                # rank-meet least_trusted (weakest-link), NOT taint_join: this is a
                # function-summary aggregation of a set of callees, not a single
                # merged value, so clean-but-different-family externals must not
                # clash f to MIXED_RAW (a RAW_ZONE false positive); a raw external
                # still propagates at its precise rank.
                ext_taints: list[TaintState] = []
                for c in ext_callees:
                    if c in anchored:
                        try:
                            c_return_taint = return_taint_map[c]
                        except KeyError:
                            c_return_taint = current[c]
                        ext_taints.append(c_return_taint)
                    else:
                        ext_taints.append(current[c])
                ext_combined = reduce(least_trusted, ext_taints)

                # TRUST_RANK: ordering comparison, not taint combination (see §6)
                ext_taint = ext_combined
                # Every non-anchored function is in floating_down or floating_free (the
                # §1 classification has no fourth non-anchored bucket), so the False
                # arm of this guard is never taken for an f that reached here.
                if f in floating_down or f in floating_free:  # pragma: no branch
                    l1_rank = TRUST_RANK[taint_map[f]]
                    if l1_rank > TRUST_RANK[ext_taint]:
                        ext_taint = taint_map[f]
                # Unresolved calls pessimistic floor (ordering, not combination)
                try:
                    f_unresolved = unresolved_counts[f]
                except KeyError:
                    f_unresolved = 0
                if f_unresolved > 0 and TRUST_RANK[taint_map[f]] > TRUST_RANK[ext_taint]:
                    # Unreachable: the floating floor above already pinned
                    # ext_taint == taint_map[f] whenever rank[L1] > rank[ext] (the
                    # same predicate), and every non-anchored f is floating — so by
                    # this point rank[taint_map[f]] <= rank[ext_taint] always holds.
                    # Redundant clamp kept for parity (taint-combination audit, F2).
                    ext_taint = taint_map[f]  # pragma: no cover
                if ext_taint != current[f]:
                    current[f] = ext_taint
                    refined.add(f)
                    # TRUST_RANK: diagnostic provenance tiebreak, not taint combination
                    # Record via_callee from external callees.
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

        # Phase 1b: Seed only local multi-source joins within the SCC.
        # This preserves order-independent cross-classification when a node
        # merges multiple SCC-local inputs, without re-injecting stale L1 into
        # plain cycles or self-loops that do not perform a true join.
        for f in sorted(scc - anchored):
            try:
                f_edges = edges[f]
            except KeyError:
                f_edges = set()

            external_seed_taints: list[TaintState] = []
            local_seed_taints: list[TaintState] = []
            saw_other_local = False

            for c in sorted(f_edges & taint_keys):
                if c in anchored:
                    try:
                        c_taint = return_taint_map[c]
                    except KeyError:
                        c_taint = current[c]
                    external_seed_taints.append(c_taint)
                    continue

                if c not in scc:
                    # Outside-SCC non-anchored callees have already converged.
                    # Seed from their refined summary, not stale L1 return data.
                    external_seed_taints.append(current[c])
                    continue

                if c != f:
                    saw_other_local = True
                local_seed_taints.append(taint_map[c])

            if len(external_seed_taints) + len(local_seed_taints) < 2:
                continue

            if not saw_other_local:
                # Do not re-inject self-loop L1 classifications. Single-node
                # SCCs should read their refined summary, not stale seed data.
                local_seed_taints = []

            seed_taints = external_seed_taints + local_seed_taints
            if len(seed_taints) < 2:
                continue

            # Aggregate the multi-source seed SET into one summary taint via the
            # rank-meet least_trusted (weakest-link), NOT taint_join: a node that
            # draws on several SCC-local + external callees aggregates their
            # influence — it does not build one value by merging provenances — so
            # clean-but-different-family seeds must not clash f to MIXED_RAW (a
            # RAW_ZONE false positive); a raw seed still propagates at its rank.
            # least_trusted is order-independent (commutative, associative,
            # idempotent), preserving the order-independence this seed pass exists
            # to guarantee.
            seed_join = reduce(least_trusted, seed_taints)
            if TRUST_RANK[seed_join] > TRUST_RANK[current[f]]:
                current[f] = seed_join
                refined.add(f)

        # Freeze the post-seeding lower bound for this SCC.
        # Any local multi-source join discovered in Phase 1b is a real program
        # point in the SCC and must remain visible during Phase 2; otherwise a
        # later update can "wash out" the seed and make the result depend on
        # member visitation order.
        phase2_floor = {f: current[f] for f in scc if f not in anchored}

        # Phase 2: Compute full SCC rounds from a stable snapshot, then
        # commit updates synchronously. This removes the read-after-write
        # hazard from mutating current[] while other SCC members in the same
        # round still need to read the previous state.
        scc_key = frozenset(scc)
        converged = False
        while True:
            if iterations >= safety_bound:  # pragma: no cover
                # Unreachable by sound inputs. The bound is ``8 * |SCC| + 8`` — strictly
                # above the lattice height (8). The §2b.2 monotonicity commit guard pins
                # every non-anchored move toward strictly-less trust, so a member's taint
                # can change at most ``height`` (8) times before saturating at MIXED_RAW,
                # after which ``new == current`` halts change and the SCC converges. No
                # input respecting the transfer-function guards can exceed the bound; this
                # is the divergence safety net the bound's docstring describes as
                # deliberately loose relative to the reachable maximum.
                logger.warning(
                    "L3 convergence bound hit for SCC of size %d after %d iterations",
                    len(scc),
                    iterations,
                )
                diagnostics.append(
                    (
                        DIAG_CONVERGENCE_BOUND,
                        f"SCC of size {len(scc)} hit iteration bound after {iterations} iterations",
                    )
                )
                break

            updates, via_candidates = _compute_scc_round(
                scc=scc,
                anchored=anchored,
                edges=edges,
                taint_keys=taint_keys,
                current=current,
                return_taint_map=return_taint_map,
                phase2_floor=phase2_floor,
            )

            changed = False
            for func in sorted(scc - anchored):
                new_taint = updates[func] if updates.__contains__(func) else current[func]
                if new_taint == current[func]:
                    continue
                # Monotonicity invariant: a non-anchored function must never
                # move toward a *more* trusted taint (strictly lower TRUST_RANK)
                # under the §6 join algebra. If it does, a transfer function is
                # broken — emit L3_MONOTONICITY_VIOLATION at ERROR and pin the
                # function at the old (safer, less-trusted) value so downstream
                # results stay conservative.
                if _check_monotonicity_violation(
                    old_taint=current[func],
                    new_taint=new_taint,
                ):
                    diagnostics.append(
                        (
                            DIAG_MONOTONICITY_VIOLATION,
                            f"function {func!r} moved from {current[func].value} "
                            f"(rank {TRUST_RANK[current[func]]}) to {new_taint.value} "
                            f"(rank {TRUST_RANK[new_taint]}) "
                            f"without anchor — violates monotone fixed point",
                        )
                    )
                    # Pin to the old (less-trusted) value; skip the commit.
                    continue
                current[func] = new_taint
                refined.add(func)
                via_callee_map[func] = via_candidates.get(func)
                changed = True

            if not changed:
                converged = True
                break

            iterations += 1

        # Revision 2 NEW-3 off-by-one correction: the convergent round IS a
        # round of work (the round at which the SCC stopped changing), so
        # record ``iterations + 1`` on convergent exit. Bound-hit exits have
        # already been counted (``iterations`` reached ``safety_bound``).
        scc_iteration_counts[scc_key] = iterations + 1 if converged else iterations

    # --- 6. Post-fixed-point assertions ---------------------------------------
    for func in anchored:
        if current[func] != taint_map[func]:
            logger.error(
                "L3 post-assertion FAILED: anchored function %s changed from %s to %s",
                func,
                taint_map[func],
                current[func],
            )
            return (
                dict(taint_map),
                _seed_provenance_only(
                    taint_map,
                    taint_sources,
                    resolved_counts,
                    unresolved_counts,
                ),
                diagnostics,
                scc_iteration_counts,
            )

    # TRUST_RANK: ordering assertion, not taint combination (see §6)
    for func in floating_down:
        if TRUST_RANK[current[func]] < TRUST_RANK[taint_map[func]]:
            logger.error(
                "L3 post-assertion FAILED: module_default function %s upgraded from %s to %s",
                func,
                taint_map[func],
                current[func],
            )
            return (
                dict(taint_map),
                _seed_provenance_only(
                    taint_map,
                    taint_sources,
                    resolved_counts,
                    unresolved_counts,
                ),
                diagnostics,
                scc_iteration_counts,
            )

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
                diagnostics.append(
                    (
                        DIAG_LOW_RESOLUTION,
                        f"Function {func} has {pct}% unresolved calls ({unres}/{total_calls})",
                    )
                )

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
                source="anchored",
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
            except KeyError:  # pragma: no cover
                # Unreachable: via_callee_map is initialised with an entry for every
                # taint_map key (``{f: None for f in taint_map}``), and ``refined`` is a
                # subset of taint_map, so a refined func always has a via_callee entry.
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

    return current, provenance, diagnostics, scc_iteration_counts


def _seed_provenance_only(
    taint_map: dict[str, TaintState],
    taint_sources: dict[str, TaintSourceClass],
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
        if src == "anchored":
            prov_source: Literal["anchored", "module_default", "callgraph", "fallback"] = "anchored"
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
        except KeyError:  # pragma: no cover
            # Unreachable: start_node is drawn from ``sorted(graph)``, so it is always a
            # graph key. Defensive default kept for parity with the neighbor lookup.
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
                    except KeyError:  # pragma: no cover
                        # Unreachable: on_stack[node] is set at every node's first visit
                        # (and toggled False on SCC pop), so any *visited* neighbor (this
                        # branch only runs when ``indices[neighbor]`` exists) always has an
                        # on_stack entry. Defensive default kept for parity.
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
