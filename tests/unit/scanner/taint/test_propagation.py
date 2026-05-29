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


def test_discriminating_join_two_anchored_callees_yields_mixed() -> None:
    # A calls a GUARDED and an EXTERNAL_RAW anchored callee. Combining with
    # taint_join yields MIXED_RAW — a result least_trusted (EXTERNAL_RAW) could
    # NEVER produce. This guards against collapsing the two operators.
    edges = {"A": {"B", "C"}, "B": set(), "C": set()}
    tm = {"A": T.UNKNOWN_RAW, "B": T.GUARDED, "C": T.EXTERNAL_RAW}
    src = {"A": "fallback", "B": "anchored", "C": "anchored"}
    refined, _prov, _diags, _it = _run(edges, tm, src)
    assert refined["A"] == T.MIXED_RAW
    assert refined["A"] != T.EXTERNAL_RAW


def test_cyclic_scc_converges() -> None:
    # A <-> B, B also calls raw C. The Phase-1b seed-join clashes the INTEGRAL
    # sibling with the raw external via taint_join -> MIXED_RAW. Converges (no
    # convergence-bound diagnostic).
    edges = {"A": {"B"}, "B": {"A", "C"}, "C": set()}
    tm = {"A": T.INTEGRAL, "B": T.INTEGRAL, "C": T.UNKNOWN_RAW}
    src = {"A": "fallback", "B": "fallback", "C": "fallback"}
    refined, _prov, diags, _it = _run(edges, tm, src)
    assert refined["A"] == T.MIXED_RAW
    assert refined["B"] == T.MIXED_RAW
    assert refined["C"] == T.UNKNOWN_RAW
    assert not any(code == DIAG_CONVERGENCE_BOUND for code, _ in diags)


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
