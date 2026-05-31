from __future__ import annotations

from wardline.core.taints import TaintState as T
from wardline.scanner.taint.propagation import (
    DIAG_CONVERGENCE_BOUND,
    DIAG_MONOTONICITY_VIOLATION,  # noqa: F401
    compute_sccs,
    propagate_callgraph_taints,
)


def _run(edges, taint_map, sources, *, return_map=None, unresolved=None):
    resolved = {k: len(v) for k, v in edges.items()}
    unresolved = unresolved or {k: 0 for k in taint_map}
    return_map = return_map if return_map is not None else dict(taint_map)
    return propagate_callgraph_taints(
        edges=edges, taint_map=taint_map, taint_sources=sources,
        resolved_counts=resolved, unresolved_counts=unresolved,
        return_taint_map=return_map,
    )


def test_compute_sccs_reverse_topo_order() -> None:
    g = {"A": {"B"}, "B": {"C"}, "C": set(), "D": {"E"}, "E": {"D"}}
    sccs = compute_sccs(g)
    # leaves first; the cycle {D,E} is one component
    assert {frozenset(s) for s in sccs} == {
        frozenset({"C"}), frozenset({"B"}), frozenset({"A"}), frozenset({"D", "E"}),
    }
    assert sccs.index({"C"}) < sccs.index({"B"}) < sccs.index({"A"})


def test_transitive_chain_all_fallback_propagates_raw() -> None:
    edges = {"A": {"B"}, "B": {"C"}, "C": set()}
    tm = {"A": T.INTEGRAL, "B": T.INTEGRAL, "C": T.UNKNOWN_RAW}
    src = {"A": "fallback", "B": "fallback", "C": "fallback"}
    refined, _prov, diags, _it = _run(edges, tm, src)
    assert refined == {"A": T.UNKNOWN_RAW, "B": T.UNKNOWN_RAW, "C": T.UNKNOWN_RAW}
    assert diags == []


def test_two_hop_anchored_mixed_leaf_flows_up() -> None:
    edges = {"A": {"B"}, "B": {"C"}, "C": set()}
    tm = {"A": T.UNKNOWN_RAW, "B": T.UNKNOWN_RAW, "C": T.MIXED_RAW}
    src = {"A": "fallback", "B": "fallback", "C": "anchored"}
    refined, _prov, _diags, _it = _run(edges, tm, src)
    assert refined == {"A": T.MIXED_RAW, "B": T.MIXED_RAW, "C": T.MIXED_RAW}


def test_module_default_trusted_chain_demotes() -> None:
    edges = {"A": {"B"}, "B": {"C"}, "C": set()}
    tm = {"A": T.INTEGRAL, "B": T.INTEGRAL, "C": T.UNKNOWN_RAW}
    src = {"A": "module_default", "B": "module_default", "C": "anchored"}
    refined, _prov, _diags, _it = _run(edges, tm, src)
    assert refined == {"A": T.UNKNOWN_RAW, "B": T.UNKNOWN_RAW, "C": T.UNKNOWN_RAW}


def test_anchored_trusted_leaf_does_not_promote_fallback_caller() -> None:
    edges = {"A": {"B"}, "B": set()}
    tm = {"A": T.UNKNOWN_RAW, "B": T.GUARDED}
    src = {"A": "fallback", "B": "anchored"}
    refined, _prov, _diags, _it = _run(edges, tm, src)
    assert refined["A"] == T.UNKNOWN_RAW  # floor holds — can't prove trust
    assert refined["B"] == T.GUARDED


def test_module_default_never_upgrades_toward_trust() -> None:
    edges = {"A": {"B"}, "B": set()}
    tm = {"A": T.UNKNOWN_RAW, "B": T.INTEGRAL}
    src = {"A": "module_default", "B": "anchored"}
    refined, _prov, _diags, _it = _run(edges, tm, src)
    assert refined["A"] == T.UNKNOWN_RAW


def test_two_anchored_callees_aggregate_via_least_trusted() -> None:
    # A calls a GUARDED and an EXTERNAL_RAW anchored callee. The callee SET is
    # aggregated via the rank-meet least_trusted (weakest-link), NOT taint_join:
    # least_trusted(GUARDED, EXTERNAL_RAW) = EXTERNAL_RAW (the precise raw rank),
    # NOT the spurious MIXED_RAW (rank 7) taint_join would manufacture. A is
    # fallback at UNKNOWN_RAW, so its floor keeps it at UNKNOWN_RAW regardless;
    # the point is the aggregation never jumps to MIXED_RAW.
    edges = {"A": {"B", "C"}, "B": set(), "C": set()}
    tm = {"A": T.UNKNOWN_RAW, "B": T.GUARDED, "C": T.EXTERNAL_RAW}
    src = {"A": "fallback", "B": "anchored", "C": "anchored"}
    refined, _prov, _diags, _it = _run(edges, tm, src)
    assert refined["A"] != T.MIXED_RAW


def test_clean_different_family_callees_stay_clean() -> None:
    # Clean-direction: A is a non-anchored module_default calling two
    # clean-but-DIFFERENT-family anchored callees — an ASSURED validator and an
    # INTEGRAL literal helper. A multi-callee function exercises every L3
    # combination site (Phase 1 external influence, Phase 1b seed-join, and the
    # Phase 2 _compute_scc_round) — all migrated to least_trusted. Both callees
    # are clean (not in RAW_ZONE), so A must stay clean: least_trusted(ASSURED,
    # INTEGRAL) = ASSURED — taint_join would clash to MIXED_RAW (rank 7, in
    # RAW_ZONE), a PY-WL-101 false positive. This is the FP the migration removes.
    edges = {"A": {"B", "C"}, "B": set(), "C": set()}
    tm = {"A": T.INTEGRAL, "B": T.ASSURED, "C": T.INTEGRAL}
    src = {"A": "module_default", "B": "anchored", "C": "anchored"}
    refined, _prov, _diags, _it = _run(edges, tm, src)
    assert refined["A"] == T.ASSURED  # clean, NOT MIXED_RAW


def test_one_raw_callee_among_clean_still_propagates() -> None:
    # Soundness companion to the clean-direction test: replace the INTEGRAL
    # helper with a raw EXTERNAL_RAW callee. least_trusted keeps the raw rank, so
    # A is still raw (would still fire) — no false negative introduced.
    edges = {"A": {"B", "C"}, "B": set(), "C": set()}
    tm = {"A": T.INTEGRAL, "B": T.ASSURED, "C": T.EXTERNAL_RAW}
    src = {"A": "module_default", "B": "anchored", "C": "anchored"}
    refined, _prov, _diags, _it = _run(edges, tm, src)
    assert refined["A"] == T.EXTERNAL_RAW  # raw still propagates


def test_cyclic_scc_converges() -> None:
    # A <-> B, B also calls raw C. The Phase-1b seed-join (site 4) aggregates the
    # INTEGRAL sibling with the raw external via least_trusted ->
    # least_trusted(INTEGRAL, UNKNOWN_RAW) = UNKNOWN_RAW (the precise raw rank),
    # NOT the spurious MIXED_RAW taint_join would produce. Raw still propagates
    # into the cycle. Converges (no convergence-bound diagnostic).
    edges = {"A": {"B"}, "B": {"A", "C"}, "C": set()}
    tm = {"A": T.INTEGRAL, "B": T.INTEGRAL, "C": T.UNKNOWN_RAW}
    src = {"A": "fallback", "B": "fallback", "C": "fallback"}
    refined, _prov, diags, _it = _run(edges, tm, src)
    assert refined["A"] == T.UNKNOWN_RAW
    assert refined["B"] == T.UNKNOWN_RAW
    assert refined["C"] == T.UNKNOWN_RAW
    assert not any(code == DIAG_CONVERGENCE_BOUND for code, _ in diags)


def test_cyclic_seed_join_clean_different_family_stays_clean() -> None:
    # Clean-direction through a true cycle (drives the Phase 1b seed-join's
    # multi-source SCC path): A <-> B cycle, B also calls a clean ASSURED
    # validator C (different family from the INTEGRAL cycle seeds). The
    # combination sites aggregate two clean-but-different families; least_trusted
    # keeps them clean (least_trusted(INTEGRAL, ASSURED) = ASSURED), NOT the
    # MIXED_RAW (RAW_ZONE) clash taint_join would manufacture inside the cycle.
    edges = {"A": {"B"}, "B": {"A", "C"}, "C": set()}
    tm = {"A": T.INTEGRAL, "B": T.INTEGRAL, "C": T.ASSURED}
    src = {"A": "module_default", "B": "module_default", "C": "anchored"}
    refined, _prov, diags, _it = _run(edges, tm, src)
    assert refined["A"] == T.ASSURED  # clean, NOT MIXED_RAW
    assert refined["B"] == T.ASSURED
    assert not any(code == DIAG_CONVERGENCE_BOUND for code, _ in diags)


def test_fallback_caller_clean_callees_floor_holds_not_mixed() -> None:
    # A fallback caller can't prove trust, so its UNKNOWN_RAW floor holds — but
    # the combination of its two clean-different-family anchored callees must
    # still aggregate via least_trusted (ASSURED), never spike to MIXED_RAW
    # before the floor clamp. Distinguishes "floored to UNKNOWN_RAW (rank 6)"
    # from "clashed to MIXED_RAW (rank 7)": both are raw, but only the latter is
    # the spurious provenance-clash label.
    edges = {"A": {"B", "C"}, "B": set(), "C": set()}
    tm = {"A": T.UNKNOWN_RAW, "B": T.ASSURED, "C": T.INTEGRAL}
    src = {"A": "fallback", "B": "anchored", "C": "anchored"}
    refined, _prov, _diags, _it = _run(edges, tm, src)
    assert refined["A"] == T.UNKNOWN_RAW  # floor, NOT MIXED_RAW


def test_long_chain_converges_without_bound_diagnostic() -> None:
    n = 20
    edges = {f"f{i}": {f"f{i+1}"} for i in range(n)}
    edges[f"f{n}"] = set()
    tm = {f"f{i}": (T.MIXED_RAW if i == n else T.INTEGRAL) for i in range(n + 1)}
    src = {f"f{i}": ("anchored" if i == n else "module_default") for i in range(n + 1)}
    refined, _prov, diags, _it = _run(edges, tm, src)
    assert all(refined[f"f{i}"] == T.MIXED_RAW for i in range(n))
    assert not any(code == DIAG_CONVERGENCE_BOUND for code, _ in diags)


def test_anchored_function_provenance_source() -> None:
    edges = {"A": {"B"}, "B": set()}
    tm = {"A": T.UNKNOWN_RAW, "B": T.GUARDED}
    src = {"A": "fallback", "B": "anchored"}
    _refined, prov, _diags, _it = _run(edges, tm, src)
    assert prov["B"].source == "anchored"
    assert prov["A"].source in {"callgraph", "fallback"}


def test_empty_taint_map_returns_empty() -> None:
    refined, prov, diags, it = propagate_callgraph_taints(
        edges={}, taint_map={}, taint_sources={},
        resolved_counts={}, unresolved_counts={}, return_taint_map={},
    )
    assert refined == {} and prov == {} and diags == [] and it == {}
