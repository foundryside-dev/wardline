"""Tests for TaintState enum and taint_join lattice."""

import itertools
import json

import pytest

from wardline.core.taints import TaintState, taint_join

# --- TaintState enum tests ---


def test_taint_state_count() -> None:
    assert len(TaintState) == 8


def test_taint_state_values_are_uppercase() -> None:
    """All taint state values must be explicit uppercase strings."""
    for member in TaintState:
        assert member.value == member.value.upper(), (
            f"{member.name} has non-uppercase value: {member.value}"
        )


def test_serialisation_round_trip() -> None:
    """str(member) produces the canonical uppercase token."""
    assert str(TaintState.INTEGRAL) == "INTEGRAL"
    assert str(TaintState.ASSURED) == "ASSURED"
    assert str(TaintState.GUARDED) == "GUARDED"
    assert str(TaintState.EXTERNAL_RAW) == "EXTERNAL_RAW"
    assert str(TaintState.UNKNOWN_RAW) == "UNKNOWN_RAW"
    assert str(TaintState.UNKNOWN_GUARDED) == "UNKNOWN_GUARDED"
    assert str(TaintState.UNKNOWN_ASSURED) == "UNKNOWN_ASSURED"
    assert str(TaintState.MIXED_RAW) == "MIXED_RAW"


def test_json_serialisation() -> None:
    """StrEnum members serialise as plain strings via json.dumps."""
    assert json.dumps(TaintState.INTEGRAL) == '"INTEGRAL"'
    assert json.dumps(TaintState.MIXED_RAW) == '"MIXED_RAW"'


# --- taint_join lattice tests ---

ALL_STATES = list(TaintState)


def test_idempotency() -> None:
    """join(a, a) == a for all taint states."""
    for state in ALL_STATES:
        assert taint_join(state, state) is state, (
            f"join({state}, {state}) should be {state}"
        )


def test_commutativity_exhaustive() -> None:
    """join(a, b) == join(b, a) for all 64 ordered pairs."""
    for a in ALL_STATES:
        for b in ALL_STATES:
            assert taint_join(a, b) is taint_join(b, a), (
                f"join({a}, {b}) != join({b}, {a})"
            )


def test_mixed_raw_absorbing() -> None:
    """MIXED_RAW is the absorbing element: join(MIXED_RAW, X) == MIXED_RAW for all X."""
    for state in ALL_STATES:
        assert taint_join(TaintState.MIXED_RAW, state) is TaintState.MIXED_RAW, (
            f"join(MIXED_RAW, {state}) should be MIXED_RAW"
        )
        assert taint_join(state, TaintState.MIXED_RAW) is TaintState.MIXED_RAW, (
            f"join({state}, MIXED_RAW) should be MIXED_RAW"
        )


def test_associativity_spot_check() -> None:
    """Associativity: join(a, join(b, c)) == join(join(a, b), c) for representative triples."""
    triples = [
        (TaintState.INTEGRAL, TaintState.ASSURED, TaintState.EXTERNAL_RAW),
        (TaintState.UNKNOWN_RAW, TaintState.UNKNOWN_GUARDED, TaintState.UNKNOWN_ASSURED),
        (TaintState.GUARDED, TaintState.MIXED_RAW, TaintState.INTEGRAL),
        (TaintState.EXTERNAL_RAW, TaintState.UNKNOWN_RAW, TaintState.ASSURED),
        (TaintState.UNKNOWN_GUARDED, TaintState.INTEGRAL, TaintState.UNKNOWN_ASSURED),
    ]
    for a, b, c in triples:
        left = taint_join(a, taint_join(b, c))
        right = taint_join(taint_join(a, b), c)
        assert left is right, (
            f"Associativity failed: join({a}, join({b}, {c})) = {left} != {right} = join(join({a}, {b}), {c})"
        )


# --- Specific join results from spec §6 ---


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        # Cross-classification: always MIXED_RAW
        (TaintState.INTEGRAL, TaintState.ASSURED, TaintState.MIXED_RAW),
        (TaintState.ASSURED, TaintState.EXTERNAL_RAW, TaintState.MIXED_RAW),
        (TaintState.GUARDED, TaintState.ASSURED, TaintState.MIXED_RAW),
        (TaintState.INTEGRAL, TaintState.EXTERNAL_RAW, TaintState.MIXED_RAW),
        # Any classified + UNKNOWN_RAW: MIXED_RAW
        (TaintState.ASSURED, TaintState.UNKNOWN_RAW, TaintState.MIXED_RAW),
        (TaintState.INTEGRAL, TaintState.UNKNOWN_RAW, TaintState.MIXED_RAW),
        (TaintState.GUARDED, TaintState.UNKNOWN_RAW, TaintState.MIXED_RAW),
        # Any classified + UNKNOWN_GUARDED: MIXED_RAW
        (TaintState.EXTERNAL_RAW, TaintState.UNKNOWN_GUARDED, TaintState.MIXED_RAW),
        (TaintState.ASSURED, TaintState.UNKNOWN_GUARDED, TaintState.MIXED_RAW),
        # Any classified + UNKNOWN_ASSURED: MIXED_RAW
        (TaintState.GUARDED, TaintState.UNKNOWN_ASSURED, TaintState.MIXED_RAW),
        (TaintState.INTEGRAL, TaintState.UNKNOWN_ASSURED, TaintState.MIXED_RAW),
        # Within UNKNOWN family: demote to weaker validation
        (TaintState.UNKNOWN_RAW, TaintState.UNKNOWN_GUARDED, TaintState.UNKNOWN_RAW),
        (TaintState.UNKNOWN_RAW, TaintState.UNKNOWN_ASSURED, TaintState.UNKNOWN_RAW),
        (TaintState.UNKNOWN_GUARDED, TaintState.UNKNOWN_ASSURED, TaintState.UNKNOWN_GUARDED),
    ],
    ids=lambda x: x.value if isinstance(x, TaintState) else str(x),
)
def test_specific_join_results(a: TaintState, b: TaintState, expected: TaintState) -> None:
    """Verify specific join results from the spec's join table."""
    assert taint_join(a, b) is expected
    assert taint_join(b, a) is expected  # commutativity


# --- Bug fix: exhaustive associativity (wardline-c69e58f) ---


def test_associativity_exhaustive_8x8x8() -> None:
    """Associativity: join(join(a, b), c) == join(a, join(b, c)) for all 512 triples."""
    for a, b, c in itertools.product(ALL_STATES, repeat=3):
        left = taint_join(taint_join(a, b), c)
        right = taint_join(a, taint_join(b, c))
        assert left is right, (
            f"Associativity failed: join(join({a}, {b}), {c}) = {left} "
            f"!= {right} = join({a}, join({b}, {c}))"
        )


# --- Bug fix: string round-trip safety (wardline-81e7255) ---


def test_taint_join_string_round_trip() -> None:
    """taint_join(TaintState(str(a)), TaintState(str(b))) == taint_join(a, b) for all pairs."""
    for a, b in itertools.product(ALL_STATES, repeat=2):
        from_str = taint_join(TaintState(str(a)), TaintState(str(b)))
        direct = taint_join(a, b)
        assert from_str is direct, (
            f"String round-trip mismatch: taint_join(TaintState('{a}'), "
            f"TaintState('{b}')) = {from_str} != {direct} = taint_join({a}, {b})"
        )
