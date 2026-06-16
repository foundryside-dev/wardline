from __future__ import annotations

import pytest

from wardline.core.taints import TaintState as T
from wardline.scanner.taint.summary import (
    SUMMARY_SCHEMA_VERSION,
    FunctionSummary,
    compute_cache_key,
)


def _key(**over) -> str:
    base = dict(
        module_path="pkg.mod",
        source_bytes=b"def f(): pass\n",
        schema_version=SUMMARY_SCHEMA_VERSION,
        resolver_version="sp1d",
        provider_fingerprint="default-v1",
        scan_policy_hash="sha256:policy-a",
    )
    base.update(over)
    return compute_cache_key(**base)


def test_cache_key_is_deterministic() -> None:
    assert _key() == _key()


def test_cache_key_changes_with_each_input() -> None:
    base = _key()
    assert _key(source_bytes=b"def g(): pass\n") != base
    assert _key(provider_fingerprint="sp2-vocab-7") != base
    assert _key(resolver_version="sp1e") != base
    assert _key(schema_version=SUMMARY_SCHEMA_VERSION + 1) != base
    # The effective-scan-policy identity is part of the key: a config that newly names an
    # untrusted source (changing ruleset_hash) must not collide with the prior key, else a
    # warm cache serves a stale-CLEAN summary (wardline-9d6a81b9e7).
    assert _key(scan_policy_hash="sha256:policy-b") != base


def test_cache_key_includes_module_identity() -> None:
    # Two modules with byte-identical source must NOT collide on one key —
    # otherwise the second module's summaries are dropped on a false cache hit.
    assert _key(module_path="pkg.a") != _key(module_path="pkg.b")


def test_cache_key_rejects_crlf_source() -> None:
    with pytest.raises(ValueError, match="CRLF"):
        _key(source_bytes=b"def f():\r\n    pass\r\n")


def test_cache_key_length_prefixed_no_collision() -> None:
    # ("ab","c") vs ("a","bc") must not collide across adjacent fields.
    assert compute_cache_key(
        module_path="m",
        source_bytes=b"ab",
        schema_version=1,
        resolver_version="c",
        provider_fingerprint="x",
        scan_policy_hash="p",
    ) != compute_cache_key(
        module_path="m",
        source_bytes=b"a",
        schema_version=1,
        resolver_version="bc",
        provider_fingerprint="x",
        scan_policy_hash="p",
    )


def test_summary_rejects_wrong_schema_version() -> None:
    with pytest.raises(ValueError, match="schema_version"):
        FunctionSummary(
            fqn="m.f",
            body_taint=T.UNKNOWN_RAW,
            return_taint=T.UNKNOWN_RAW,
            taint_source="fallback",
            unresolved_calls=0,
            schema_version=SUMMARY_SCHEMA_VERSION + 99,
            cache_key="x",
        )


def test_summary_rejects_negative_unresolved() -> None:
    with pytest.raises(ValueError, match="unresolved_calls"):
        FunctionSummary(
            fqn="m.f",
            body_taint=T.UNKNOWN_RAW,
            return_taint=T.UNKNOWN_RAW,
            taint_source="fallback",
            unresolved_calls=-1,
            schema_version=SUMMARY_SCHEMA_VERSION,
            cache_key="x",
        )


def test_summary_is_frozen() -> None:
    s = FunctionSummary(
        fqn="m.f",
        body_taint=T.UNKNOWN_RAW,
        return_taint=T.UNKNOWN_RAW,
        taint_source="fallback",
        unresolved_calls=0,
        schema_version=SUMMARY_SCHEMA_VERSION,
        cache_key="x",
    )
    with pytest.raises((AttributeError, TypeError)):
        s.fqn = "m.g"  # type: ignore[misc]
