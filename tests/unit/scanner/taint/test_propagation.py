from __future__ import annotations

import logging

import wardline.scanner.taint.propagation as propagation
from wardline.core.taints import TaintState as T
from wardline.scanner.taint.propagation import (
    DIAG_CONVERGENCE_BOUND,
    DIAG_MONOTONICITY_VIOLATION,
    _check_monotonicity_violation,
    compute_sccs,
    propagate_callgraph_taints,
)


def _run(edges, taint_map, sources, *, return_map=None, unresolved=None):
    resolved = {k: len(v) for k, v in edges.items()}
    unresolved = unresolved or {k: 0 for k in taint_map}
    return_map = return_map if return_map is not None else dict(taint_map)
    return propagate_callgraph_taints(
        edges=edges,
        taint_map=taint_map,
        taint_sources=sources,
        resolved_counts=resolved,
        unresolved_counts=unresolved,
        return_taint_map=return_map,
    )


def test_compute_sccs_reverse_topo_order() -> None:
    g = {"A": {"B"}, "B": {"C"}, "C": set(), "D": {"E"}, "E": {"D"}}
    sccs = compute_sccs(g)
    # leaves first; the cycle {D,E} is one component
    assert {frozenset(s) for s in sccs} == {
        frozenset({"C"}),
        frozenset({"B"}),
        frozenset({"A"}),
        frozenset({"D", "E"}),
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
    refined, _prov, diags, _it = _run(edges, tm, src)
    # Exact value (wardline-e159060db7): the fallback floor must HOLD A at
    # UNKNOWN_RAW — `!= MIXED_RAW` also passed under a floor-drop mutation
    # (combined = EXTERNAL_RAW satisfies it). And the floor must hold at the
    # combination site itself, not via the monotonicity commit backstop: under
    # the floor-drop mutation the value survives only because the guard rejects
    # the move and emits L3_MONOTONICITY_VIOLATION — so no diagnostics allowed.
    assert refined["A"] == T.UNKNOWN_RAW
    assert diags == []


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
    refined, _prov, diags, _it = _run(edges, tm, src)
    assert refined["A"] == T.UNKNOWN_RAW  # floor, NOT MIXED_RAW
    # The floor must hold at the combination site, not via the monotonicity
    # commit guard (which would emit L3_MONOTONICITY_VIOLATION while preserving
    # the value) — see test_two_anchored_callees_aggregate_via_least_trusted.
    assert diags == []


def test_scc_round_floor_holds_inside_cycle_without_phase1_seed() -> None:
    # Exercises the `_compute_scc_round` floor in ISOLATION from Phase-1
    # initialization (wardline-e159060db7): A and B form a cycle, so B is inside
    # A's SCC and Phase 1's external-callee pass never touches A — the Phase-2
    # floor (current[A] = UNKNOWN_RAW) is the ONLY thing pinning A against its
    # anchored-INTEGRAL cycle partner. Mutation-probed: with the floor dropped
    # (`new_taint = combined`) the round proposes INTEGRAL for A and only the
    # monotonicity commit guard saves the VALUE while emitting
    # L3_MONOTONICITY_VIOLATION — hence both assertions are load-bearing.
    edges = {"A": {"B"}, "B": {"A"}}
    tm = {"A": T.UNKNOWN_RAW, "B": T.INTEGRAL}
    src = {"A": "fallback", "B": "anchored"}
    refined, _prov, diags, _it = _run(edges, tm, src)
    assert refined["A"] == T.UNKNOWN_RAW  # floor holds — fallback can't prove trust
    assert refined["B"] == T.INTEGRAL  # anchored partner unaffected
    assert diags == []


def test_long_chain_converges_without_bound_diagnostic() -> None:
    n = 20
    edges = {f"f{i}": {f"f{i + 1}"} for i in range(n)}
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
        edges={},
        taint_map={},
        taint_sources={},
        resolved_counts={},
        unresolved_counts={},
        return_taint_map={},
    )
    assert refined == {} and prov == {} and diags == [] and it == {}


# ── Fault-injection: the two defensive arms that sound inputs never trigger.
# With the transfer functions correct the engine stays monotone and anchored
# entries never change, so these branches are unreachable by any natural corpus
# (audit "could-not-drive"). We reach them by crafting a transfer-function bug:
# the monotonicity comparison is exercised directly through its isolated helper,
# and both kernel arms via a monkeypatched _compute_scc_round seam. ──


def test_check_monotonicity_violation_helper_detects_trust_increase() -> None:
    # The isolated comparison: a strict move toward MORE trust (lower rank) is a
    # violation; equal or less-trusted is not.
    assert _check_monotonicity_violation(old_taint=T.UNKNOWN_RAW, new_taint=T.INTEGRAL) is True
    assert _check_monotonicity_violation(old_taint=T.ASSURED, new_taint=T.EXTERNAL_RAW) is False
    assert _check_monotonicity_violation(old_taint=T.GUARDED, new_taint=T.GUARDED) is False


def test_monotonicity_violation_pins_and_diagnoses(monkeypatch) -> None:
    # A buggy transfer round proposes moving a NON-anchored function toward MORE
    # trust. The kernel must emit L3_MONOTONICITY_VIOLATION and pin the function
    # at its old (safer, less-trusted) value rather than commit the upgrade.
    calls = {"n": 0}

    def buggy_round(**_kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            # A is non-anchored at UNKNOWN_RAW; propose INTEGRAL (more trusted).
            return ({"A": T.INTEGRAL}, {"A": "B"})
        return ({}, {})

    monkeypatch.setattr(propagation, "_compute_scc_round", buggy_round)
    edges = {"A": {"B"}, "B": set()}
    tm = {"A": T.UNKNOWN_RAW, "B": T.GUARDED}
    src = {"A": "fallback", "B": "anchored"}
    refined, _prov, diags, _it = propagate_callgraph_taints(
        edges=edges,
        taint_map=tm,
        taint_sources=src,
        resolved_counts={"A": 1, "B": 0},
        unresolved_counts={"A": 0, "B": 0},
        return_taint_map={"A": T.UNKNOWN_RAW, "B": T.GUARDED},
    )
    assert any(code == DIAG_MONOTONICITY_VIOLATION for code, _ in diags)
    assert refined["A"] == T.UNKNOWN_RAW  # pinned to the old safer value, NOT INTEGRAL


def test_post_assertion_anchored_drift_bails_to_unrefined(monkeypatch, caplog) -> None:
    # A buggy round mutates an ANCHORED function's taint in-place. The
    # post-fixed-point assertion must detect the drift and bail to the unrefined
    # map with seed-only provenance (NO diagnostic — this arm only logs ERROR).
    def buggy_round(**kwargs):
        kwargs["current"]["B"] = T.MIXED_RAW  # corrupt anchored B
        return ({}, {})

    monkeypatch.setattr(propagation, "_compute_scc_round", buggy_round)
    edges = {"A": {"B"}, "B": set()}
    tm = {"A": T.UNKNOWN_RAW, "B": T.GUARDED}
    src = {"A": "fallback", "B": "anchored"}
    with caplog.at_level(logging.ERROR, logger=propagation.__name__):
        refined, prov, _diags, _it = propagate_callgraph_taints(
            edges=edges,
            taint_map=tm,
            taint_sources=src,
            resolved_counts={"A": 1, "B": 0},
            unresolved_counts={"A": 0, "B": 0},
            return_taint_map={"A": T.UNKNOWN_RAW, "B": T.GUARDED},
        )
    assert refined == tm  # bailed to the unrefined L1 map
    assert prov["A"].source == "fallback"  # seed-only provenance
    assert any("post-assertion FAILED" in r.message for r in caplog.records)


def test_post_assertion_module_default_upgrade_bails(monkeypatch, caplog) -> None:
    # A buggy round upgrades a MODULE_DEFAULT function toward MORE trust by direct
    # mutation (bypassing the monotonicity commit guard). The module_default
    # post-assertion must detect the upgrade and bail to the unrefined map.
    def buggy_round(**kwargs):
        kwargs["current"]["A"] = T.INTEGRAL  # A is module_default, started UNKNOWN_RAW
        return ({}, {})

    monkeypatch.setattr(propagation, "_compute_scc_round", buggy_round)
    edges = {"A": {"B"}, "B": set()}
    tm = {"A": T.UNKNOWN_RAW, "B": T.GUARDED}
    src = {"A": "module_default", "B": "anchored"}
    with caplog.at_level(logging.ERROR, logger=propagation.__name__):
        refined, prov, _diags, _it = propagate_callgraph_taints(
            edges=edges,
            taint_map=tm,
            taint_sources=src,
            resolved_counts={"A": 1, "B": 0},
            unresolved_counts={"A": 0, "B": 0},
            return_taint_map={"A": T.UNKNOWN_RAW, "B": T.GUARDED},
        )
    assert refined == tm  # bailed to the unrefined L1 map
    assert prov["A"].source == "module_default"  # seed-only provenance
    assert any("post-assertion FAILED" in r.message for r in caplog.records)


# ── Coverage: graceful degradation when the per-function side maps (edges /
# resolved_counts / unresolved_counts / return_taint_map) are PARTIAL — a func is
# present in taint_map but absent from a side map. The real resolver populates all
# maps in lockstep (build_call_edges emits a row per entity), but the kernel guards
# every lookup so a partial map degrades to a 0/empty default rather than raising.
# Driven directly through the public kernel (its own test surface). ──


def test_fallback_func_absent_from_all_count_maps_defaults_zero() -> None:
    refined, prov, diags, _it = propagate_callgraph_taints(
        edges={},
        taint_map={"A": T.UNKNOWN_RAW},
        taint_sources={"A": "fallback"},
        resolved_counts={},  # A absent everywhere
        unresolved_counts={},
        return_taint_map={},
    )
    assert refined == {"A": T.UNKNOWN_RAW}
    assert prov["A"].source == "fallback"
    assert prov["A"].resolved_call_count == 0
    assert prov["A"].unresolved_call_count == 0
    assert diags == []


def test_anchored_func_absent_from_count_maps_defaults_zero() -> None:
    _refined, prov, _diags, _it = propagate_callgraph_taints(
        edges={},
        taint_map={"A": T.GUARDED},
        taint_sources={"A": "anchored"},
        resolved_counts={},
        unresolved_counts={},
        return_taint_map={},
    )
    assert prov["A"].source == "anchored"
    assert prov["A"].resolved_call_count == 0
    assert prov["A"].unresolved_call_count == 0


def test_module_default_func_absent_from_count_maps_defaults_zero() -> None:
    _refined, prov, _diags, _it = propagate_callgraph_taints(
        edges={},
        taint_map={"A": T.UNKNOWN_RAW},
        taint_sources={"A": "module_default"},
        resolved_counts={},
        unresolved_counts={},
        return_taint_map={},
    )
    assert prov["A"].source == "module_default"
    assert prov["A"].resolved_call_count == 0


def test_refined_func_absent_from_count_maps_defaults_zero() -> None:
    # A is refined by raw callee B; neither is in the count maps, so the refined-branch
    # provenance defaults its counts to 0 while still recording the via_callee.
    refined, prov, _diags, _it = propagate_callgraph_taints(
        edges={"A": {"B"}, "B": set()},
        taint_map={"A": T.INTEGRAL, "B": T.UNKNOWN_RAW},
        taint_sources={"A": "fallback", "B": "fallback"},
        resolved_counts={},  # A and B absent
        unresolved_counts={},
        return_taint_map={"A": T.INTEGRAL, "B": T.UNKNOWN_RAW},
    )
    assert refined["A"] == T.UNKNOWN_RAW
    assert prov["A"].source == "callgraph"
    assert prov["A"].via_callee == "B"
    assert prov["A"].resolved_call_count == 0
    assert prov["A"].unresolved_call_count == 0


def test_cyclic_scc_with_missing_edges_and_anchored_return() -> None:
    # A<->B cycle; B also calls anchored C. C is ABSENT from both edges (no outgoing)
    # and return_taint_map, so the kernel falls back to current[C] for C's anchored
    # contribution and to an empty edge set for C — raw still propagates into the cycle.
    refined, _prov, diags, _it = propagate_callgraph_taints(
        edges={"A": {"B"}, "B": {"A", "C"}},  # C has no edges entry
        taint_map={"A": T.INTEGRAL, "B": T.INTEGRAL, "C": T.EXTERNAL_RAW},
        taint_sources={"A": "fallback", "B": "fallback", "C": "anchored"},
        resolved_counts={},
        unresolved_counts={},
        return_taint_map={},  # C absent -> uses current[C]
    )
    assert refined["A"] == T.EXTERNAL_RAW
    assert refined["B"] == T.EXTERNAL_RAW
    assert refined["C"] == T.EXTERNAL_RAW
    assert not any(code == DIAG_CONVERGENCE_BOUND for code, _ in diags)


def test_low_resolution_diagnostic_emitted_above_threshold() -> None:
    # >70% unresolved calls must emit L3_LOW_RESOLUTION with the percentage.
    from wardline.scanner.taint.propagation import DIAG_LOW_RESOLUTION

    _refined, _prov, diags, _it = propagate_callgraph_taints(
        edges={"A": set()},
        taint_map={"A": T.UNKNOWN_RAW},
        taint_sources={"A": "fallback"},
        resolved_counts={"A": 1},
        unresolved_counts={"A": 9},  # 9/10 = 90% unresolved
        return_taint_map={"A": T.UNKNOWN_RAW},
    )
    lowres = [msg for code, msg in diags if code == DIAG_LOW_RESOLUTION]
    assert len(lowres) == 1
    assert "90%" in lowres[0]


def test_low_resolution_func_absent_from_count_maps_no_diagnostic() -> None:
    # A func absent from both count maps has total_calls == 0, so no ratio is computed
    # and no L3_LOW_RESOLUTION fires (the resolved/unresolved KeyError->0 defaults).
    from wardline.scanner.taint.propagation import DIAG_LOW_RESOLUTION

    _refined, _prov, diags, _it = propagate_callgraph_taints(
        edges={"A": set()},
        taint_map={"A": T.UNKNOWN_RAW},
        taint_sources={"A": "fallback"},
        resolved_counts={},
        unresolved_counts={},
        return_taint_map={"A": T.UNKNOWN_RAW},
    )
    assert not any(code == DIAG_LOW_RESOLUTION for code, _ in diags)


def test_seed_provenance_only_handles_missing_source_and_counts() -> None:
    # The post-assertion-bail path builds provenance via _seed_provenance_only. Drive it
    # through a monkeypatched buggy round that corrupts an anchored entry, with a func
    # ABSENT from taint_sources (defaults to fallback) and from the count maps (0).
    def buggy_round(**kwargs):
        kwargs["current"]["B"] = T.MIXED_RAW  # corrupt anchored B
        return ({}, {})

    import wardline.scanner.taint.propagation as prop_mod

    orig = prop_mod._compute_scc_round
    try:
        prop_mod._compute_scc_round = buggy_round
        refined, prov, _diags, _it = propagate_callgraph_taints(
            edges={"A": {"B"}, "B": set()},
            taint_map={"A": T.UNKNOWN_RAW, "B": T.GUARDED},
            taint_sources={"B": "anchored"},  # A absent from sources -> fallback in seed-only
            resolved_counts={},  # both absent -> 0
            unresolved_counts={},
            return_taint_map={"A": T.UNKNOWN_RAW, "B": T.GUARDED},
        )
    finally:
        prop_mod._compute_scc_round = orig
    assert refined == {"A": T.UNKNOWN_RAW, "B": T.GUARDED}  # bailed to unrefined
    assert prov["A"].source == "fallback"  # A absent from sources -> fallback
    assert prov["A"].resolved_call_count == 0
    assert prov["B"].source == "anchored"


def test_mixed_scc_skips_anchored_member_in_phase1() -> None:
    # A<->B cycle where A is ANCHORED and B is non-anchored. The SCC is not all-anchored
    # (so it is processed), and Phase 1 must SKIP the anchored member A (continue) while
    # refining B from the cycle. A stays at its declared taint; B demotes to it.
    refined, _prov, diags, _it = propagate_callgraph_taints(
        edges={"A": {"B"}, "B": {"A"}},
        taint_map={"A": T.GUARDED, "B": T.INTEGRAL},
        taint_sources={"A": "anchored", "B": "fallback"},
        resolved_counts={"A": 1, "B": 1},
        unresolved_counts={"A": 0, "B": 0},
        return_taint_map={"A": T.GUARDED, "B": T.INTEGRAL},
    )
    assert refined["A"] == T.GUARDED  # anchored, unchanged
    assert refined["B"] == T.GUARDED  # demoted toward the anchored cycle member
    assert not any(code == DIAG_CONVERGENCE_BOUND for code, _ in diags)


def test_scc_phase1b_seed_join_commits_when_less_trusted() -> None:
    # A<->B cycle; B also calls external anchored C (EXTERNAL_RAW) and D (GUARDED). B
    # draws on >=2 sources, so the Phase-1b seed-join aggregates them via least_trusted
    # and, being LESS trusted than B's current state, commits — propagating raw into the
    # cycle. Asserts the multi-source seed path raises (demotes) the cycle correctly.
    refined, _prov, diags, _it = propagate_callgraph_taints(
        edges={"A": {"B"}, "B": {"A", "C", "D"}, "C": set(), "D": set()},
        taint_map={"A": T.INTEGRAL, "B": T.INTEGRAL, "C": T.EXTERNAL_RAW, "D": T.GUARDED},
        taint_sources={
            "A": "module_default",
            "B": "module_default",
            "C": "anchored",
            "D": "anchored",
        },
        resolved_counts={"A": 1, "B": 3, "C": 0, "D": 0},
        unresolved_counts={"A": 0, "B": 0, "C": 0, "D": 0},
        return_taint_map={"A": T.INTEGRAL, "B": T.INTEGRAL, "C": T.EXTERNAL_RAW, "D": T.GUARDED},
    )
    assert refined["B"] == T.EXTERNAL_RAW  # weakest-link of its external+local seed set
    assert refined["A"] == T.EXTERNAL_RAW  # raw propagated around the cycle
    assert not any(code == DIAG_CONVERGENCE_BOUND for code, _ in diags)


def test_scc_phase1b_seed_join_demotes_via_local_sibling() -> None:
    # Phase 1 only sees callees OUTSIDE the SCC, so it cannot demote B from an SCC-LOCAL
    # sibling. Phase 1b includes the local sibling: A<->B cycle, A seeded raw (UNKNOWN_RAW
    # module_default), B clean (INTEGRAL) with a clean EXTERNAL callee D. B's Phase-1b
    # seed set = {D(GUARDED), A(UNKNOWN_RAW local)} (>=2 sources); the seed-join is
    # UNKNOWN_RAW — strictly LESS trusted than B's current INTEGRAL — so the commit fires
    # and the raw local sibling propagates into B. This is the seed-join's whole purpose:
    # a local multi-source join Phase 1 missed.
    refined, _prov, diags, _it = propagate_callgraph_taints(
        edges={"A": {"B"}, "B": {"A", "D"}, "D": set()},
        taint_map={"A": T.UNKNOWN_RAW, "B": T.INTEGRAL, "D": T.GUARDED},
        taint_sources={"A": "module_default", "B": "module_default", "D": "anchored"},
        resolved_counts={"A": 1, "B": 2, "D": 0},
        unresolved_counts={"A": 0, "B": 0, "D": 0},
        return_taint_map={"A": T.UNKNOWN_RAW, "B": T.INTEGRAL, "D": T.GUARDED},
    )
    assert refined["B"] == T.UNKNOWN_RAW  # demoted by the raw local sibling A via the seed-join
    assert refined["A"] == T.UNKNOWN_RAW
    assert not any(code == DIAG_CONVERGENCE_BOUND for code, _ in diags)


def test_compute_sccs_skips_neighbor_absent_from_graph() -> None:
    # A references B, but B is NOT a key in the graph dict (an edge to a node the graph
    # does not describe). compute_sccs must skip the dangling neighbor (graph[neighbor]
    # KeyError -> skip) and still produce A as its own component, never raising.
    sccs = compute_sccs({"A": {"B"}})
    assert {frozenset(s) for s in sccs} == {frozenset({"A"})}
