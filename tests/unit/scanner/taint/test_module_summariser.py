from __future__ import annotations

from wardline.core.taints import TaintState as T
from wardline.scanner.taint.function_level import FunctionSeed
from wardline.scanner.taint.module_summariser import summarise_module
from wardline.scanner.taint.summary import SUMMARY_SCHEMA_VERSION


def _seed(q, body, ret, source) -> FunctionSeed:
    return FunctionSeed(qualname=q, body_taint=body, return_taint=ret, source=source)


def test_summaries_map_provider_seed_to_anchored() -> None:
    seeds = {
        "m.a": _seed("m.a", T.GUARDED, T.GUARDED, "provider"),
        "m.b": _seed("m.b", T.UNKNOWN_RAW, T.UNKNOWN_RAW, "default"),
    }
    summaries = summarise_module(
        module_path="m", seeds=seeds, unresolved_counts={"m.a": 0, "m.b": 2},
        source_bytes=b"x\n", resolver_version="sp1d", provider_fingerprint="default-v1",
    )
    by_fqn = {s.fqn: s for s in summaries}
    assert by_fqn["m.a"].taint_source == "anchored"
    assert by_fqn["m.a"].body_taint == T.GUARDED
    assert by_fqn["m.b"].taint_source == "fallback"
    assert by_fqn["m.b"].unresolved_calls == 2
    assert all(s.schema_version == SUMMARY_SCHEMA_VERSION for s in summaries)


def test_all_summaries_in_module_share_cache_key() -> None:
    seeds = {
        "m.a": _seed("m.a", T.UNKNOWN_RAW, T.UNKNOWN_RAW, "default"),
        "m.b": _seed("m.b", T.UNKNOWN_RAW, T.UNKNOWN_RAW, "default"),
    }
    summaries = summarise_module(
        module_path="m", seeds=seeds, unresolved_counts={"m.a": 0, "m.b": 0},
        source_bytes=b"x\n", resolver_version="sp1d", provider_fingerprint="default-v1",
    )
    keys = {s.cache_key for s in summaries}
    assert len(keys) == 1  # cache_key is module-granular


def test_missing_unresolved_count_defaults_zero() -> None:
    seeds = {"m.a": _seed("m.a", T.UNKNOWN_RAW, T.UNKNOWN_RAW, "default")}
    summaries = summarise_module(
        module_path="m", seeds=seeds, unresolved_counts={},
        source_bytes=b"x\n", resolver_version="sp1d", provider_fingerprint="default-v1",
    )
    assert summaries[0].unresolved_calls == 0


def test_identical_source_distinct_modules_get_distinct_keys() -> None:
    # Byte-identical source in two modules must not collide on one cache_key.
    seeds_a = {"a.f": _seed("a.f", T.UNKNOWN_RAW, T.UNKNOWN_RAW, "default")}
    seeds_b = {"b.f": _seed("b.f", T.UNKNOWN_RAW, T.UNKNOWN_RAW, "default")}
    common = dict(
        unresolved_counts={}, source_bytes=b"def f(): pass\n",
        resolver_version="sp1d", provider_fingerprint="default-v1",
    )
    key_a = summarise_module(module_path="a", seeds=seeds_a, **common)[0].cache_key
    key_b = summarise_module(module_path="b", seeds=seeds_b, **common)[0].cache_key
    assert key_a != key_b
