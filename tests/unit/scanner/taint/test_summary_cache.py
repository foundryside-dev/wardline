from __future__ import annotations

import pytest

from wardline.core.taints import TaintState as T
from wardline.scanner.taint.summary import SUMMARY_SCHEMA_VERSION, FunctionSummary
from wardline.scanner.taint.summary_cache import (
    SummaryCache,
    _deserialise_summary,
    _serialise_summary,
)

_KEY = "a" * 64
_KEY2 = "b" * 64


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
    c = SummaryCache(cache_dir=tmp_path)
    summaries = (_summary("m.a"), _summary("m.b"))
    c.put(_KEY, summaries)
    c.save()
    c2 = SummaryCache(cache_dir=tmp_path)
    c2.load()
    assert c2.get(_KEY) == summaries


def test_load_drops_malformed_json(tmp_path) -> None:
    (tmp_path / f"{_KEY}.json").write_text("{not json", encoding="utf-8")
    c = SummaryCache(cache_dir=tmp_path)
    c.load()  # must not raise
    assert len(c) == 0


def test_load_ignores_non_hex_stem_files(tmp_path) -> None:
    (tmp_path / "notes.json").write_text("[]", encoding="utf-8")
    c = SummaryCache(cache_dir=tmp_path)
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
    c = SummaryCache(cache_dir=tmp_path)
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
    c2 = SummaryCache(cache_dir=tmp_path)
    c2.load()
    assert c2.get(_KEY) == (s,)


def test_load_drops_poisoned_trio_cache_file(tmp_path, caplog) -> None:
    # A hand-edited/corrupted cache file holding a valid-but-unreachable state is
    # dropped (cold-cache fallback), not injected — load() catches the ValueError.
    import json

    (tmp_path / f"{_KEY}.json").write_text(json.dumps([_summary_dict("MIXED_RAW", "MIXED_RAW")]), encoding="utf-8")
    c = SummaryCache(cache_dir=tmp_path)
    c.load()  # must not raise
    assert len(c) == 0


# ── Coverage: load/save edge arms and the deserialiser's taint_source guard. ──


def test_save_cleans_up_temp_file_when_replace_fails(tmp_path, monkeypatch) -> None:
    # If os.replace fails mid-save, the temp file must be unlinked (no .tmp litter)
    # and the error re-raised — the except cleanup arm.
    import os

    c = SummaryCache(cache_dir=tmp_path)
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
    c = SummaryCache(cache_dir=tmp_path)
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
    payload = [_serialise_summary(stale)]
    (tmp_path / f"{_KEY}.json").write_text(json.dumps(payload), encoding="utf-8")
    c = SummaryCache(cache_dir=tmp_path)
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
