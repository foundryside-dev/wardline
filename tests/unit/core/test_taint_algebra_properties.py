from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from wardline.core.taints import (
    _PROVENANCE_CLASH,
    RAW_ZONE,
    TRUST_RANK,
    TaintState,
    combine,
    least_trusted,
    taint_join,
)

# Strategy to generate random TaintState instances.
taint_states = st.sampled_from(TaintState)


@given(taint_states, taint_states)
def test_least_trusted_is_commutative(a: TaintState, b: TaintState) -> None:
    assert least_trusted(a, b) == least_trusted(b, a)


@given(taint_states, taint_states, taint_states)
def test_least_trusted_is_associative(a: TaintState, b: TaintState, c: TaintState) -> None:
    assert least_trusted(a, least_trusted(b, c)) == least_trusted(least_trusted(a, b), c)


@given(taint_states)
def test_least_trusted_is_idempotent(a: TaintState) -> None:
    assert least_trusted(a, a) == a


@given(taint_states)
def test_least_trusted_identity_and_absorbing(a: TaintState) -> None:
    # INTEGRAL is the identity (most trusted, rank 0)
    assert least_trusted(a, TaintState.INTEGRAL) == a
    # MIXED_RAW is absorbing (least trusted, rank 7)
    assert least_trusted(a, TaintState.MIXED_RAW) == TaintState.MIXED_RAW


@given(taint_states, taint_states)
def test_taint_join_is_commutative(a: TaintState, b: TaintState) -> None:
    assert taint_join(a, b) == taint_join(b, a)


@given(taint_states, taint_states, taint_states)
def test_taint_join_is_associative(a: TaintState, b: TaintState, c: TaintState) -> None:
    assert taint_join(a, taint_join(b, c)) == taint_join(taint_join(a, b), c)


@given(taint_states)
def test_taint_join_is_idempotent(a: TaintState) -> None:
    assert taint_join(a, a) == a


@given(taint_states)
def test_taint_join_absorbing(a: TaintState) -> None:
    # MIXED_RAW is absorbing
    assert taint_join(a, TaintState.MIXED_RAW) == TaintState.MIXED_RAW


@given(taint_states, taint_states)
def test_combine_delegation(a: TaintState, b: TaintState) -> None:
    # When _PROVENANCE_CLASH is False (default)
    token = _PROVENANCE_CLASH.set(False)
    try:
        assert combine(a, b) == least_trusted(a, b)
    finally:
        _PROVENANCE_CLASH.reset(token)

    # When _PROVENANCE_CLASH is True
    token = _PROVENANCE_CLASH.set(True)
    try:
        assert combine(a, b) == taint_join(a, b)
    finally:
        _PROVENANCE_CLASH.reset(token)


@given(taint_states, taint_states)
def test_monotonicity(a: TaintState, b: TaintState) -> None:
    # Monotonicity in TRUST_RANK (higher rank = less trusted)
    assert TRUST_RANK[least_trusted(a, b)] >= max(TRUST_RANK[a], TRUST_RANK[b])
    assert TRUST_RANK[taint_join(a, b)] >= max(TRUST_RANK[a], TRUST_RANK[b])


@given(taint_states, taint_states)
def test_raw_zone_upward_closure(a: TaintState, b: TaintState) -> None:
    # If any operand is in the RAW_ZONE, the result is in the RAW_ZONE.
    if a in RAW_ZONE or b in RAW_ZONE:
        assert least_trusted(a, b) in RAW_ZONE
        assert taint_join(a, b) in RAW_ZONE


def test_taint_join_has_no_identity() -> None:
    # For every element e in TaintState, there exists at least one element x in TaintState
    # such that taint_join(x, e) != x. This proves there is no identity element.
    for e in TaintState:
        has_counterexample = False
        for x in TaintState:
            if taint_join(x, e) != x:
                has_counterexample = True
                break
        assert has_counterexample, f"{e} acted as a left/right identity, which is invalid."
