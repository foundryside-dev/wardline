from __future__ import annotations

import pytest

from wardline.core.taints import TaintState as T
from wardline.scanner.taint.summary import SUMMARY_SCHEMA_VERSION, FunctionSummary
from wardline.scanner.taint.summary_cache import SummaryCache

_KEY = "a" * 64
_KEY2 = "b" * 64


def _summary(fqn: str, *, schema: int = SUMMARY_SCHEMA_VERSION, key: str = _KEY) -> FunctionSummary:
    return FunctionSummary(
        fqn=fqn, body_taint=T.UNKNOWN_RAW, return_taint=T.UNKNOWN_RAW,
        taint_source="fallback", unresolved_calls=0, schema_version=schema, cache_key=key,
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
    c.get(_KEY)        # hit
    c.get(_KEY2)       # miss
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
