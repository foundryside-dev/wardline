from __future__ import annotations

from pathlib import Path

import pytest

from wardline.core.taints import TaintState as T
from wardline.scanner.taint.summary import SUMMARY_SCHEMA_VERSION, FunctionSummary
from wardline.scanner.taint.summary_cache import (
    SummaryCache,
    _cache_payload,
    _cache_payload_mac,
    _deserialise_summary,
    _serialise_summary,
)

_KEY = "a" * 64
_KEY2 = "b" * 64
_SECRET = b"unit-test-summary-cache-key"


def _summary(fqn: str, *, schema: int = SUMMARY_SCHEMA_VERSION, key: str = _KEY) -> FunctionSummary:
    return FunctionSummary(
        fqn=fqn,
        body_taint=T.UNKNOWN_RAW,
        return_taint=T.UNKNOWN_RAW,
        taint_source="fallback",
        unresolved_calls=0,
        schema_version=schema,
        cache_key=key,
    )


def test_put_then_get_hits() -> None:
    c = SummaryCache()
    summaries = (_summary("m.a"), _summary("m.b"))
    c.put(_KEY, summaries)
    assert c.get(_KEY) == summaries
    assert c.hits == 1 and c.misses == 0


def test_get_miss() -> None:
    c = SummaryCache()
    assert c.get(_KEY) is None
    assert c.misses == 1 and c.hits == 0


def test_hit_rate_zero_when_no_activity() -> None:
    assert SummaryCache().hit_rate() == 0.0


def test_hit_rate_fraction() -> None:
    c = SummaryCache()
    c.put(_KEY, (_summary("m.a"),))
    c.get(_KEY)  # hit
    c.get(_KEY2)  # miss
    assert c.hit_rate() == 0.5


def test_put_rejects_non_hex_key() -> None:
    c = SummaryCache()
    with pytest.raises(ValueError, match="cache_key"):
        c.put("../escape", (_summary("m.a", key="../escape"),))


def test_get_drops_stale_schema_entry() -> None:
    c = SummaryCache()
    # Construct a stale-schema summary by bypassing FunctionSummary's guard:
    # put() also guards, so build the stale entry via object.__setattr__ on a
    # valid instance to simulate a rehydrated stale entry reaching the store.
    good = _summary("m.a")
    object.__setattr__(good, "schema_version", SUMMARY_SCHEMA_VERSION + 99)
    c._entries[_KEY] = (good,)  # type: ignore[attr-defined]  # simulate stale store
    assert c.get(_KEY) is None
    assert c.misses == 1
    assert len(c) == 0  # stale entry evicted


def test_has_current_checks_freshness_without_counting_hits_or_misses() -> None:
    c = SummaryCache()
    c.put(_KEY, (_summary("m.a"),))
    assert c.has_current(_KEY) is True
    assert c.hits == 0 and c.misses == 0

    stale = _summary("m.b")
    object.__setattr__(stale, "schema_version", SUMMARY_SCHEMA_VERSION + 99)
    c._entries[_KEY2] = (stale,)  # type: ignore[attr-defined]  # simulate stale store
    assert c.has_current(_KEY2) is False
    assert c.hits == 0 and c.misses == 0
    assert _KEY2 not in c._entries  # type: ignore[attr-defined]


def test_analyzer_uses_summary_cache_public_api() -> None:
    analyzer = Path("src/wardline/scanner/analyzer.py").read_text(encoding="utf-8")
    assert "._entries" not in analyzer


def test_put_rejects_stale_schema_summary() -> None:
    c = SummaryCache()
    good = _summary("m.a")
    object.__setattr__(good, "schema_version", SUMMARY_SCHEMA_VERSION + 1)
    with pytest.raises(ValueError, match="schema_version"):
        c.put(_KEY, (good,))


def test_invalidate_and_clear() -> None:
    c = SummaryCache()
    c.put(_KEY, (_summary("m.a"),))
    c.invalidate(_KEY)
    assert c.get(_KEY) is None
    c.put(_KEY, (_summary("m.a"),))
    c.put(_KEY2, (_summary("n.a", key=_KEY2),))
    assert len(c) == 2
    c.clear()
    assert len(c) == 0


def test_invalidate_missing_key_is_noop() -> None:
    SummaryCache().invalidate(_KEY)  # no exception


def test_schema_version_property() -> None:
    assert SummaryCache().schema_version == SUMMARY_SCHEMA_VERSION


def test_save_and_load_roundtrip(tmp_path) -> None:
    c = SummaryCache(cache_dir=tmp_path, cache_auth_secret=_SECRET)
    summaries = (_summary("m.a"), _summary("m.b"))
    c.put(_KEY, summaries)
    c.save()
    c2 = SummaryCache(cache_dir=tmp_path, cache_auth_secret=_SECRET)
    c2.load()
    assert c2.get(_KEY) == summaries


def test_save_without_auth_secret_does_not_persist_entries(tmp_path) -> None:
    c = SummaryCache(cache_dir=tmp_path)
    c.put(_KEY, (_summary("m.a"),))
    c.save()
    assert list(tmp_path.iterdir()) == []


def test_load_drops_unsigned_cache_file_with_matching_key(tmp_path) -> None:
    import json

    payload = [_serialise_summary(_summary("m.a"))]
    (tmp_path / f"{_KEY}.json").write_text(json.dumps(payload), encoding="utf-8")

    c = SummaryCache(cache_dir=tmp_path, cache_auth_secret=_SECRET)
    c.load()

    assert len(c) == 0
    assert c.get(_KEY) is None


def test_load_drops_bad_mac_cache_file(tmp_path) -> None:
    import json

    payload = _cache_payload(_KEY, (_summary("m.a"),))
    payload["mac"] = "0" * 64
    (tmp_path / f"{_KEY}.json").write_text(json.dumps(payload), encoding="utf-8")

    c = SummaryCache(cache_dir=tmp_path, cache_auth_secret=_SECRET)
    c.load()

    assert len(c) == 0
    assert c.get(_KEY) is None


def test_warm_cache_honours_untrusted_sources_policy_change(tmp_path) -> None:
    # A warm run whose config newly names a function as an untrusted source must produce the
    # SAME defects as a cold run with that config — the cache key binds the effective-scan-
    # policy hash, so the prior policy-free CLEAN summary is not served (wardline-9d6a81b9e7).
    from wardline.core.config import WardlineConfig
    from wardline.core.finding import Kind
    from wardline.scanner.analyzer import WardlineAnalyzer

    src = tmp_path / "example.py"
    src.write_text(
        "from wardline.decorators import trusted\n"
        "@trusted(level='ASSURED')\n"
        "def read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\n"
        "def f(p, cursor):\n    cursor.execute(read_raw(p))\n",
        encoding="utf-8",
    )

    def defects(az: WardlineAnalyzer, cfg: WardlineConfig) -> list[str]:
        fs = list(az.analyze([src], cfg, root=tmp_path))
        return sorted({x.rule_id for x in fs if x.kind is Kind.DEFECT})

    cfg_clean = WardlineConfig()
    cfg_src = WardlineConfig(untrusted_sources=("example.read_raw",))

    cold = defects(WardlineAnalyzer(summary_cache=SummaryCache()), cfg_src)
    assert cold == ["PY-WL-118"]

    # Warm the cache with the policy-FREE run first, then re-run under the source policy.
    az = WardlineAnalyzer(summary_cache=SummaryCache())
    assert defects(az, cfg_clean) == []
    assert defects(az, cfg_src) == cold  # must NOT serve the stale-clean summary


def test_run_scan_ignores_unsigned_forged_summary_cache(tmp_path) -> None:
    import json

    from wardline.core.config import WardlineConfig
    from wardline.core.ruleset import ruleset_hash
    from wardline.core.run import run_scan
    from wardline.scanner.taint.decorator_provider import DecoratorTaintSourceProvider
    from wardline.scanner.taint.project_resolver import _RESOLVER_VERSION
    from wardline.scanner.taint.summary import compute_cache_key

    proj = tmp_path / "proj"
    proj.mkdir()
    source = (
        "from wardline.decorators import external_boundary, trusted\n"
        "@external_boundary\n"
        "def read_raw(p):\n"
        "    return p\n"
        "@trusted(level='ASSURED')\n"
        "def sink(x):\n"
        "    return x\n"
        "def f(p):\n"
        "    return sink(read_raw(p))\n"
    )
    (proj / "m.py").write_text(source, encoding="utf-8")

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    key = compute_cache_key(
        module_path="m",
        source_bytes=source.encode("utf-8"),
        schema_version=SUMMARY_SCHEMA_VERSION,
        resolver_version=_RESOLVER_VERSION,
        provider_fingerprint=DecoratorTaintSourceProvider().fingerprint(),
        scan_policy_hash=ruleset_hash(WardlineConfig()),
    )
    forged = tuple(
        FunctionSummary(
            fqn=fqn,
            body_taint=T.INTEGRAL,
            return_taint=T.INTEGRAL,
            taint_source="anchored",
            unresolved_calls=0,
            schema_version=SUMMARY_SCHEMA_VERSION,
            cache_key=key,
        )
        for fqn in ("m.read_raw", "m.sink", "m.f")
    )
    (cache_dir / f"{key}.json").write_text(json.dumps([_serialise_summary(s) for s in forged]), encoding="utf-8")

    result = run_scan(proj, cache_dir=cache_dir)
    metrics = next(f for f in result.findings if f.rule_id == "WLN-ENGINE-METRICS")

    assert metrics.properties["cache_hit_rate"] == 0.0
    assert any(f.rule_id == "PY-WL-101" for f in result.findings)


def test_load_drops_file_when_internal_cache_key_mismatches_filename(tmp_path) -> None:
    import json

    payload = _cache_payload(_KEY, (_summary("m.a", key=_KEY2),))
    payload["mac"] = _cache_payload_mac(_SECRET, payload)
    (tmp_path / f"{_KEY}.json").write_text(json.dumps(payload), encoding="utf-8")

    c = SummaryCache(cache_dir=tmp_path, cache_auth_secret=_SECRET)
    c.load()

    assert len(c) == 0
    assert c.get(_KEY) is None


def test_load_drops_file_when_records_mix_cache_keys(tmp_path) -> None:
    import json

    payload = _cache_payload(
        _KEY,
        (
            _summary("m.a", key=_KEY),
            _summary("m.b", key=_KEY2),
        ),
    )
    payload["mac"] = _cache_payload_mac(_SECRET, payload)
    (tmp_path / f"{_KEY}.json").write_text(json.dumps(payload), encoding="utf-8")

    c = SummaryCache(cache_dir=tmp_path, cache_auth_secret=_SECRET)
    c.load()

    assert len(c) == 0
    assert c.get(_KEY) is None


def test_load_drops_malformed_json(tmp_path) -> None:
    (tmp_path / f"{_KEY}.json").write_text("{not json", encoding="utf-8")
    c = SummaryCache(cache_dir=tmp_path, cache_auth_secret=_SECRET)
    c.load()  # must not raise
    assert len(c) == 0


def test_load_ignores_non_hex_stem_files(tmp_path) -> None:
    (tmp_path / "notes.json").write_text("[]", encoding="utf-8")
    c = SummaryCache(cache_dir=tmp_path, cache_auth_secret=_SECRET)
    c.load()
    assert len(c) == 0


def test_save_requires_cache_dir() -> None:
    with pytest.raises(ValueError, match="cache_dir"):
        SummaryCache().save()


def test_load_requires_cache_dir() -> None:
    with pytest.raises(ValueError, match="cache_dir"):
        SummaryCache().load()


def test_in_memory_cache_has_no_cache_dir() -> None:
    assert SummaryCache().cache_dir is None


# ── F5: the disk-persistent cache deserialiser rejects the unreachable trio
# {MIXED_RAW, UNKNOWN_GUARDED, UNKNOWN_ASSURED} — valid TaintState strings that
# the malformed-file drop guard would otherwise let through — but STILL accepts
# the full reachable set INCLUDING INTEGRAL (a @trusted function caches INTEGRAL).
# Taint-combination audit F5. ──


def _summary_dict(body: str, ret: str) -> dict[str, object]:
    return {
        "fqn": "m.f",
        "body_taint": body,
        "return_taint": ret,
        "taint_source": "anchored",
        "unresolved_calls": 0,
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "cache_key": _KEY,
    }


@pytest.mark.parametrize("state", ["MIXED_RAW", "UNKNOWN_GUARDED", "UNKNOWN_ASSURED"])
def test_deserialise_rejects_unreachable_body_taint(state: str) -> None:
    with pytest.raises(ValueError, match="unreachable taint state"):
        _deserialise_summary(_summary_dict(state, "INTEGRAL"))


@pytest.mark.parametrize("state", ["MIXED_RAW", "UNKNOWN_GUARDED", "UNKNOWN_ASSURED"])
def test_deserialise_rejects_unreachable_return_taint(state: str) -> None:
    with pytest.raises(ValueError, match="unreachable taint state"):
        _deserialise_summary(_summary_dict("INTEGRAL", state))


def test_deserialise_integral_roundtrips() -> None:
    # MANDATORY regression guard: a @trusted function produces INTEGRAL, so the
    # cache MUST round-trip INTEGRAL body/return taint. Rejecting it here would
    # silently break caching of trusted functions.
    s = FunctionSummary(
        fqn="m.f",
        body_taint=T.INTEGRAL,
        return_taint=T.INTEGRAL,
        taint_source="anchored",
        unresolved_calls=0,
        schema_version=SUMMARY_SCHEMA_VERSION,
        cache_key=_KEY,
    )
    out = _deserialise_summary(_serialise_summary(s))
    assert out == s
    assert out.body_taint == T.INTEGRAL and out.return_taint == T.INTEGRAL


def test_integral_survives_full_save_load_cycle(tmp_path) -> None:
    # End-to-end: a poisoned-but-valid trio state would be dropped by load(),
    # but a legitimate INTEGRAL summary must survive the disk round-trip.
    c = SummaryCache(cache_dir=tmp_path, cache_auth_secret=_SECRET)
    s = FunctionSummary(
        fqn="m.f",
        body_taint=T.INTEGRAL,
        return_taint=T.INTEGRAL,
        taint_source="anchored",
        unresolved_calls=0,
        schema_version=SUMMARY_SCHEMA_VERSION,
        cache_key=_KEY,
    )
    c.put(_KEY, (s,))
    c.save()
    c2 = SummaryCache(cache_dir=tmp_path, cache_auth_secret=_SECRET)
    c2.load()
    assert c2.get(_KEY) == (s,)


def test_load_drops_poisoned_trio_cache_file(tmp_path, caplog) -> None:
    # A hand-edited/corrupted cache file holding a valid-but-unreachable state is
    # dropped (cold-cache fallback), not injected — load() catches the ValueError.
    import json

    payload: dict[str, object] = {
        "schema_version": 1,
        "cache_key": _KEY,
        "summaries": [_summary_dict("MIXED_RAW", "MIXED_RAW")],
    }
    payload["mac"] = _cache_payload_mac(_SECRET, payload)
    (tmp_path / f"{_KEY}.json").write_text(json.dumps(payload), encoding="utf-8")
    c = SummaryCache(cache_dir=tmp_path, cache_auth_secret=_SECRET)
    c.load()  # must not raise
    assert len(c) == 0


# ── Coverage: load/save edge arms and the deserialiser's taint_source guard. ──


def test_save_cleans_up_temp_file_when_replace_fails(tmp_path, monkeypatch) -> None:
    # If os.replace fails mid-save, the temp file must be unlinked (no .tmp litter)
    # and the error re-raised — the except cleanup arm.
    import os

    c = SummaryCache(cache_dir=tmp_path, cache_auth_secret=_SECRET)
    c.put(_KEY, (_summary("m.a"),))

    def boom(_src, _dst):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError, match="simulated replace failure"):
        c.save()
    # No orphan temp files left behind.
    assert [p.name for p in tmp_path.iterdir() if p.suffix == ".tmp"] == []


def test_load_skips_non_json_files(tmp_path) -> None:
    # A non-.json file in the cache dir must be skipped (the suffix guard), not parsed.
    (tmp_path / f"{_KEY}.txt").write_text("garbage", encoding="utf-8")
    c = SummaryCache(cache_dir=tmp_path, cache_auth_secret=_SECRET)
    c.load()  # must not raise
    assert len(c) == 0


def test_load_drops_stale_schema_entry_from_disk(tmp_path) -> None:
    # A JSON file whose summary carries a DIFFERENT schema_version must NOT be
    # rehydrated. _deserialise_summary reconstructs a FunctionSummary, whose
    # __post_init__ rejects the foreign schema (ValueError) — so the file is dropped
    # via the malformed-entry handler. The end-state contract: nothing loaded.
    import json

    stale = _summary("m.a")
    object.__setattr__(stale, "schema_version", SUMMARY_SCHEMA_VERSION + 1)
    payload = _cache_payload(_KEY, (stale,))
    payload["mac"] = _cache_payload_mac(_SECRET, payload)
    (tmp_path / f"{_KEY}.json").write_text(json.dumps(payload), encoding="utf-8")
    c = SummaryCache(cache_dir=tmp_path, cache_auth_secret=_SECRET)
    c.load()
    assert len(c) == 0  # stale-schema file dropped (not rehydrated)


def test_deserialise_rejects_invalid_taint_source() -> None:
    # A taint_source outside the legal set must raise (the disk artifact is corrupt /
    # schema-foreign), never rehydrate into the pipeline.
    bad = {
        "fqn": "m.f",
        "body_taint": "INTEGRAL",
        "return_taint": "INTEGRAL",
        "taint_source": "not-a-source",
        "unresolved_calls": 0,
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "cache_key": _KEY,
    }
    with pytest.raises(ValueError, match="invalid taint_source"):
        _deserialise_summary(bad)
