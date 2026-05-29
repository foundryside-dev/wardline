# tests/unit/core/test_taints.py
from __future__ import annotations

import pytest

from wardline.core.taints import TRUST_RANK, TaintState, least_trusted, taint_join

_UA = TaintState.UNKNOWN_ASSURED
_UG = TaintState.UNKNOWN_GUARDED
_UR = TaintState.UNKNOWN_RAW
_MIXED = TaintState.MIXED_RAW

# Independent restatement of the join rule — deliberately NOT a copy of the
# implementation's _JOIN_TABLE, so any edit to the table fails this gate.
_SPECIAL: dict[frozenset[TaintState], TaintState] = {
    frozenset({_UA, _UR}): _UR,
    frozenset({_UG, _UR}): _UR,
    frozenset({_UA, _UG}): _UG,
}


def _expected_join(a: TaintState, b: TaintState) -> TaintState:
    if a == b:
        return a
    if a == _MIXED or b == _MIXED:
        return _MIXED
    return _SPECIAL.get(frozenset({a, b}), _MIXED)


@pytest.mark.parametrize("a", list(TaintState))
@pytest.mark.parametrize("b", list(TaintState))
def test_taint_join_exhaustive(a: TaintState, b: TaintState) -> None:
    assert taint_join(a, b) == _expected_join(a, b)


@pytest.mark.parametrize("a", list(TaintState))
@pytest.mark.parametrize("b", list(TaintState))
def test_taint_join_commutative(a: TaintState, b: TaintState) -> None:
    assert taint_join(a, b) == taint_join(b, a)


def test_mixed_raw_is_absorbing() -> None:
    for s in TaintState:
        assert taint_join(_MIXED, s) == _MIXED
        assert taint_join(s, _MIXED) == _MIXED


def test_taint_state_values_are_uppercase_names() -> None:
    for s in TaintState:
        assert s.value == s.name
        assert s.value.isupper()


def test_trust_rank_total_order() -> None:
    assert sorted(TaintState, key=lambda s: TRUST_RANK[s]) == [
        TaintState.INTEGRAL,
        TaintState.ASSURED,
        TaintState.GUARDED,
        TaintState.UNKNOWN_ASSURED,
        TaintState.UNKNOWN_GUARDED,
        TaintState.EXTERNAL_RAW,
        TaintState.UNKNOWN_RAW,
        TaintState.MIXED_RAW,
    ]
    assert set(TRUST_RANK.values()) == set(range(8))


@pytest.mark.parametrize("a", list(TaintState))
@pytest.mark.parametrize("b", list(TaintState))
def test_least_trusted_picks_higher_rank(a: TaintState, b: TaintState) -> None:
    assert TRUST_RANK[least_trusted(a, b)] == max(TRUST_RANK[a], TRUST_RANK[b])


def test_join_and_least_trusted_diverge_across_families() -> None:
    # The whole point of having both operators: same inputs, different outputs.
    assert taint_join(TaintState.INTEGRAL, TaintState.ASSURED) == _MIXED
    assert least_trusted(TaintState.INTEGRAL, TaintState.ASSURED) == TaintState.ASSURED
