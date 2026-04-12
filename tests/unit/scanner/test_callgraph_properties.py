"""Hypothesis property-based tests for L3 call-graph taint propagation.

Tests convergence, monotonicity, idempotence, anchored immutability,
and fallback callee-boundedness using randomly generated call graphs.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hypothesis import given, settings
from hypothesis import strategies as st

from wardline.core.taints import TaintState
from wardline.scanner.taint.callgraph import TRUST_RANK
from wardline.scanner.taint.callgraph_propagation import propagate_callgraph_taints

if TYPE_CHECKING:
    from wardline.scanner.taint.function_level import TaintSource

# ── Strategies ───────────────────────────────────────────────────

_ALL_TAINT_STATES = list(TaintState)
_ALL_SOURCES: list[TaintSource] = ["decorator", "module_default", "fallback"]

# L1 rank for INTEGRAL (most trusted, used as default for empty callee sets)
_L1_RANK = TRUST_RANK[TaintState.INTEGRAL]


def _node_names(n: int) -> list[str]:
    """Generate deterministic node names: f0, f1, ..., fN."""
    return [f"f{i}" for i in range(n)]


@st.composite
def call_graphs(draw: st.DrawFn) -> tuple[
    dict[str, set[str]],
    dict[str, TaintState],
    dict[str, TaintSource],
    dict[str, int],
    dict[str, int],
]:
    """Generate a random call graph with taint assignments.

    Returns (edges, taint_map, taint_sources, resolved_counts, unresolved_counts).
    """
    n = draw(st.integers(min_value=2, max_value=20))
    names = _node_names(n)

    # Random edges: draw a subset of all possible (caller, callee) pairs
    all_pairs = [(i, j) for i in range(n) for j in range(n)]
    chosen = draw(st.frozensets(
        st.sampled_from(all_pairs) if all_pairs else st.nothing(),
        max_size=max(1, n * n * 3 // 10),  # ~30% density cap
    ))
    edges: dict[str, set[str]] = {name: set() for name in names}
    for i, j in chosen:
        edges[names[i]].add(names[j])

    # Random taint state per node
    taint_map: dict[str, TaintState] = {}
    taint_sources: dict[str, TaintSource] = {}
    for name in names:
        taint_map[name] = draw(st.sampled_from(_ALL_TAINT_STATES))
        taint_sources[name] = draw(st.sampled_from(_ALL_SOURCES))

    # Resolved/unresolved counts derived from edges
    resolved_counts: dict[str, int] = {name: len(edges[name]) for name in names}
    unresolved_counts: dict[str, int] = {
        name: draw(st.integers(min_value=0, max_value=5)) for name in names
    }

    return edges, taint_map, taint_sources, resolved_counts, unresolved_counts


# ── Property tests ───────────────────────────────────────────────


@given(data=call_graphs())
@settings(max_examples=200)
def test_convergence(
    data: tuple[
        dict[str, set[str]],
        dict[str, TaintState],
        dict[str, TaintSource],
        dict[str, int],
        dict[str, int],
    ],
) -> None:
    """Random graphs with random taints -> propagation terminates."""
    edges, taint_map, taint_sources, resolved_counts, unresolved_counts = data
    # Must return without hanging or raising
    result_map, result_prov, _diags = propagate_callgraph_taints(
        edges, taint_map, taint_sources, resolved_counts, unresolved_counts, return_taint_map=taint_map,
)
    # Basic structural checks
    assert set(result_map) == set(taint_map)
    assert set(result_prov) == set(taint_map)


@given(data=call_graphs())
@settings(max_examples=200)
def test_module_default_monotone_downward(
    data: tuple[
        dict[str, set[str]],
        dict[str, TaintState],
        dict[str, TaintSource],
        dict[str, int],
        dict[str, int],
    ],
) -> None:
    """For module_default-sourced functions ONLY: trust_rank(result) >= trust_rank(initial).

    Fallback functions are explicitly excluded -- they CAN be refined upward.
    """
    edges, taint_map, taint_sources, resolved_counts, unresolved_counts = data
    result_map, _, _diags = propagate_callgraph_taints(
        edges, taint_map, taint_sources, resolved_counts, unresolved_counts, return_taint_map=taint_map,
)
    for func, source in taint_sources.items():
        if source == "module_default":
            initial_rank = TRUST_RANK[taint_map[func]]
            result_rank = TRUST_RANK[result_map[func]]
            assert result_rank >= initial_rank, (
                f"module_default function {func} upgraded from "
                f"{taint_map[func]} (rank {initial_rank}) to "
                f"{result_map[func]} (rank {result_rank})"
            )


@given(data=call_graphs())
@settings(max_examples=200)
def test_idempotence(
    data: tuple[
        dict[str, set[str]],
        dict[str, TaintState],
        dict[str, TaintSource],
        dict[str, int],
        dict[str, int],
    ],
) -> None:
    """Running propagation twice on same input produces identical output."""
    edges, taint_map, taint_sources, resolved_counts, unresolved_counts = data

    result1, prov1, _diags1 = propagate_callgraph_taints(
        edges, taint_map, taint_sources, resolved_counts, unresolved_counts, return_taint_map=taint_map,
)
    result2, prov2, _diags2 = propagate_callgraph_taints(
        edges, taint_map, taint_sources, resolved_counts, unresolved_counts, return_taint_map=taint_map,
)

    assert result1 == result2, (
        f"Non-idempotent: first run and second run differ.\n"
        f"Differences: {_diff_maps(result1, result2)}"
    )
    assert prov1 == prov2


@given(data=call_graphs())
@settings(max_examples=200)
def test_anchored_immutability(
    data: tuple[
        dict[str, set[str]],
        dict[str, TaintState],
        dict[str, TaintSource],
        dict[str, int],
        dict[str, int],
    ],
) -> None:
    """Anchored (decorator-sourced) functions' taints unchanged regardless of graph."""
    edges, taint_map, taint_sources, resolved_counts, unresolved_counts = data
    result_map, _, _diags = propagate_callgraph_taints(
        edges, taint_map, taint_sources, resolved_counts, unresolved_counts, return_taint_map=taint_map,
)
    for func, source in taint_sources.items():
        if source == "decorator":
            assert result_map[func] == taint_map[func], (
                f"Anchored function {func} changed from "
                f"{taint_map[func]} to {result_map[func]}"
            )


@given(data=call_graphs())
@settings(max_examples=200)
def test_fallback_bounded_by_callees(
    data: tuple[
        dict[str, set[str]],
        dict[str, TaintState],
        dict[str, TaintSource],
        dict[str, int],
        dict[str, int],
    ],
) -> None:
    """Fallback taint >= max(max_callee_rank, L1 rank) — floor-clamped.

    After the floor clamp fix, fallback functions are bounded by both their
    callees AND their L1 baseline.  The result rank is at least:
      max(max_callee_rank, L1_rank)
    """
    edges, taint_map, taint_sources, resolved_counts, unresolved_counts = data
    result_map, _, _diags = propagate_callgraph_taints(
        edges, taint_map, taint_sources, resolved_counts, unresolved_counts, return_taint_map=taint_map,
)
    for func, source in taint_sources.items():
        if source != "fallback":
            continue

        result_rank = TRUST_RANK[result_map[func]]
        l1_rank = TRUST_RANK[taint_map[func]]

        # Floor clamp: result must be at least as untrusted as L1
        assert result_rank >= l1_rank, (
            f"Fallback function {func} has rank {result_rank} "
            f"but L1 rank is {l1_rank}"
        )

        # When callees exist, result must also be at least as untrusted as callees
        callees_in_map = edges.get(func, set()) & set(taint_map)
        if callees_in_map:
            max_callee_rank = max(
                TRUST_RANK[result_map[c]] for c in callees_in_map
            )
            assert result_rank >= max_callee_rank, (
                f"Fallback function {func} has rank {result_rank} "
                f"but max callee rank is {max_callee_rank}"
            )

@given(data=call_graphs())
@settings(max_examples=200)
def test_join_commutativity_at_propagation_level(
    data: tuple[
        dict[str, set[str]],
        dict[str, TaintState],
        dict[str, TaintSource],
        dict[str, int],
        dict[str, int],
    ],
) -> None:
    """Propagation result is independent of callee set iteration order.

    Since taint_join is commutative and associative, the fold over callees
    must produce the same result regardless of iteration order. This is
    already enforced by sorted() in the worklist, but this test verifies
    the algebraic property holds at the propagation output level.
    """
    edges, taint_map, taint_sources, resolved_counts, unresolved_counts = data

    # Run twice with identical inputs — idempotence already tested,
    # but here we also verify that the result matches when we reverse
    # all edge sets (which changes iteration order of callees).
    reversed_edges = {k: set(sorted(v, reverse=True)) for k, v in edges.items()}

    result1, _, _ = propagate_callgraph_taints(
        edges, taint_map, taint_sources, resolved_counts, unresolved_counts,
        return_taint_map=taint_map,
    )
    result2, _, _ = propagate_callgraph_taints(
        reversed_edges, taint_map, taint_sources, resolved_counts, unresolved_counts,
        return_taint_map=taint_map,
    )

    assert result1 == result2, (
        f"Propagation not commutative over callee order.\n"
        f"Differences: {_diff_maps(result1, result2)}"
    )


# ── Helpers ──────────────────────────────────────────────────────


def _diff_maps(
    a: dict[str, TaintState], b: dict[str, TaintState],
) -> dict[str, tuple[TaintState, TaintState]]:
    """Return keys where maps differ."""
    return {k: (a[k], b[k]) for k in a if a.get(k) != b.get(k)}
