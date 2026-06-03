from __future__ import annotations

import ast

import pytest

from wardline.core.config import WardlineConfig
from wardline.core.taints import _PROVENANCE_CLASH, combine
from wardline.core.taints import TaintState as T
from wardline.scanner.taint.propagation import propagate_callgraph_taints
from wardline.scanner.taint.summary import SUMMARY_SCHEMA_VERSION
from wardline.scanner.taint.summary_cache import _deserialise_summary, _serialise_summary
from wardline.scanner.taint.variable_level import compute_variable_taints


def test_combine_algebra() -> None:
    # 1. provenance_clash = False (default least_trusted rank-meet)
    token = _PROVENANCE_CLASH.set(False)
    try:
        assert combine(T.INTEGRAL, T.ASSURED) == T.ASSURED
        assert combine(T.INTEGRAL, T.EXTERNAL_RAW) == T.EXTERNAL_RAW
        assert combine(T.EXTERNAL_RAW, T.UNKNOWN_RAW) == T.UNKNOWN_RAW
    finally:
        _PROVENANCE_CLASH.reset(token)

    # 2. provenance_clash = True (taint_join provenance-clash)
    token = _PROVENANCE_CLASH.set(True)
    try:
        assert combine(T.INTEGRAL, T.ASSURED) == T.MIXED_RAW
        assert combine(T.INTEGRAL, T.EXTERNAL_RAW) == T.MIXED_RAW
        # Different raw families (EXTERNAL vs UNKNOWN) clash to MIXED_RAW
        assert combine(T.EXTERNAL_RAW, T.UNKNOWN_RAW) == T.MIXED_RAW
        # Same family (UNKNOWN_*), weaker member wins (pure demotion, no clash)
        assert combine(T.UNKNOWN_ASSURED, T.UNKNOWN_RAW) == T.UNKNOWN_RAW
    finally:
        _PROVENANCE_CLASH.reset(token)


def test_l2_variable_level_clash() -> None:
    source = """
def test_fn(x, y):
    z = x + y
"""
    tree = ast.parse(source)
    func_node = tree.body[0]
    assert isinstance(func_node, ast.FunctionDef)

    param_meets = {"x": T.INTEGRAL, "y": T.ASSURED}

    # 1. provenance_clash = False
    var_taints = compute_variable_taints(
        func_node,
        T.INTEGRAL,
        {},
        param_meets=param_meets,
        provenance_clash=False,
    )
    assert var_taints["z"] == T.ASSURED

    # 2. provenance_clash = True
    var_taints = compute_variable_taints(
        func_node,
        T.INTEGRAL,
        {},
        param_meets=param_meets,
        provenance_clash=True,
    )
    assert var_taints["z"] == T.MIXED_RAW


def test_l2_control_flow_merge_clash() -> None:
    source = """
def test_fn(cond, x, y):
    if cond:
        z = x
    else:
        z = y
"""
    tree = ast.parse(source)
    func_node = tree.body[0]
    assert isinstance(func_node, ast.FunctionDef)

    param_meets = {"x": T.INTEGRAL, "y": T.ASSURED, "cond": T.INTEGRAL}

    # 1. provenance_clash = False
    var_taints = compute_variable_taints(
        func_node,
        T.INTEGRAL,
        {},
        param_meets=param_meets,
        provenance_clash=False,
    )
    assert var_taints["z"] == T.ASSURED

    # 2. provenance_clash = True
    var_taints = compute_variable_taints(
        func_node,
        T.INTEGRAL,
        {},
        param_meets=param_meets,
        provenance_clash=True,
    )
    assert var_taints["z"] == T.MIXED_RAW


def test_l3_propagation_clash() -> None:
    edges = {"A": {"B", "C"}}
    taint_map = {"A": T.INTEGRAL, "B": T.INTEGRAL, "C": T.ASSURED}
    taint_sources = {"A": "fallback", "B": "anchored", "C": "anchored"}
    resolved_counts = {"A": 2}
    unresolved_counts: dict[str, int] = {}
    return_taint_map = {"B": T.INTEGRAL, "C": T.ASSURED}

    # 1. provenance_clash = False
    config_false = WardlineConfig(provenance_clash=False)
    refined, _, _, _ = propagate_callgraph_taints(
        edges=edges,
        taint_map=taint_map,
        taint_sources=taint_sources,
        resolved_counts=resolved_counts,
        unresolved_counts=unresolved_counts,
        return_taint_map=return_taint_map,
        config=config_false,
    )
    assert refined["A"] == T.ASSURED

    # 2. provenance_clash = True
    config_true = WardlineConfig(provenance_clash=True)
    refined, _, _, _ = propagate_callgraph_taints(
        edges=edges,
        taint_map=taint_map,
        taint_sources=taint_sources,
        resolved_counts=resolved_counts,
        unresolved_counts=unresolved_counts,
        return_taint_map=return_taint_map,
        config=config_true,
    )
    assert refined["A"] == T.MIXED_RAW


def test_summary_cache_mixed_raw_clash() -> None:
    key = "a" * 64
    s_dict = {
        "fqn": "m.f",
        "body_taint": "MIXED_RAW",
        "return_taint": "MIXED_RAW",
        "taint_source": "anchored",
        "unresolved_calls": 0,
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "cache_key": key,
    }

    # 1. provenance_clash = False (default: MIXED_RAW is illegal)
    token = _PROVENANCE_CLASH.set(False)
    try:
        with pytest.raises(ValueError, match="unreachable taint state"):
            _deserialise_summary(s_dict)
    finally:
        _PROVENANCE_CLASH.reset(token)

    # 2. provenance_clash = True (MIXED_RAW is legal)
    token = _PROVENANCE_CLASH.set(True)
    try:
        s = _deserialise_summary(s_dict)
        assert s.body_taint == T.MIXED_RAW
        assert s.return_taint == T.MIXED_RAW
        assert _serialise_summary(s)["body_taint"] == "MIXED_RAW"
    finally:
        _PROVENANCE_CLASH.reset(token)


def test_run_scan_provenance_clash_with_cache(tmp_path) -> None:
    from wardline.core.run import run_scan

    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "wardline.yaml").write_text("provenance_clash: true\n", encoding="utf-8")

    source = """from wardline.decorators import external_boundary, trusted

@external_boundary
def ext(p):
    return p

@trusted(level="ASSURED")
def ass(p):
    return p

# A function that combines them (via call propagation)
def clashing(cond, p):
    if cond:
        return ext(p)
    else:
        return ass(p)
"""
    (proj / "m.py").write_text(source, encoding="utf-8")

    cache = tmp_path / "cache"

    run_scan(proj, cache_dir=cache)
    assert cache.exists()

    res2 = run_scan(proj, cache_dir=cache)
    metrics = next(f for f in res2.findings if f.rule_id == "WLN-ENGINE-METRICS")
    hit_rate = metrics.properties["cache_hit_rate"]
    assert hit_rate > 0.0, "Cache was not hit! MIXED_RAW cache entry might have been dropped."


def test_run_scan_provenance_clash_loads_mixed_raw_cache(tmp_path) -> None:
    import json

    from wardline.core.run import run_scan
    from wardline.core.taints import TaintState as T
    from wardline.scanner.taint.decorator_provider import DecoratorTaintSourceProvider
    from wardline.scanner.taint.project_resolver import _RESOLVER_VERSION, compute_cache_key
    from wardline.scanner.taint.summary import SUMMARY_SCHEMA_VERSION, FunctionSummary
    from wardline.scanner.taint.summary_cache import _serialise_summary

    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "wardline.yaml").write_text("provenance_clash: true\n", encoding="utf-8")
    (proj / "m.py").write_text("def f(): pass\n", encoding="utf-8")

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()

    provider_fingerprint = DecoratorTaintSourceProvider().fingerprint()
    key = compute_cache_key(
        module_path="m",
        source_bytes=b"def f(): pass\n",
        schema_version=SUMMARY_SCHEMA_VERSION,
        resolver_version=_RESOLVER_VERSION,
        provider_fingerprint=provider_fingerprint,
    )

    s = FunctionSummary(
        fqn="m.f",
        body_taint=T.MIXED_RAW,
        return_taint=T.MIXED_RAW,
        taint_source="anchored",
        unresolved_calls=0,
        schema_version=SUMMARY_SCHEMA_VERSION,
        cache_key=key,
    )

    (cache_dir / f"{key}.json").write_text(json.dumps([_serialise_summary(s)]), encoding="utf-8")

    res = run_scan(proj, cache_dir=cache_dir)

    metrics = next(f for f in res.findings if f.rule_id == "WLN-ENGINE-METRICS")
    hit_rate = metrics.properties["cache_hit_rate"]
    assert hit_rate == 1.0, "Cache entry with MIXED_RAW was dropped during run_scan!"


def test_l3_propagation_clash_monotonicity_violation() -> None:
    from wardline.scanner.taint.propagation import _check_monotonicity_violation

    # MIXED_RAW (rank 7) to ASSURED (rank 1) is a monotonicity violation (more trusted)
    assert _check_monotonicity_violation(old_taint=T.MIXED_RAW, new_taint=T.ASSURED) is True
    # ASSURED (rank 1) to MIXED_RAW (rank 7) is NOT a monotonicity violation (less trusted)
    assert _check_monotonicity_violation(old_taint=T.ASSURED, new_taint=T.MIXED_RAW) is False
