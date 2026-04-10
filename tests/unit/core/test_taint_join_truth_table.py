"""Complete 8x8 truth table for taint_join -- executable spec §6 reference."""

from __future__ import annotations

import pytest

from wardline.core.taints import TaintState, taint_join

_I = TaintState.INTEGRAL
_A = TaintState.ASSURED
_G = TaintState.GUARDED
_ER = TaintState.EXTERNAL_RAW
_UR = TaintState.UNKNOWN_RAW
_UG = TaintState.UNKNOWN_GUARDED
_UA = TaintState.UNKNOWN_ASSURED
_MR = TaintState.MIXED_RAW

# Complete 8x8 truth table. Each row: (left, right, expected).
# The table is symmetric (commutativity tested separately in test_taints.py).
# Only upper triangle + diagonal shown (36 unique pairs).
TRUTH_TABLE: list[tuple[TaintState, TaintState, TaintState]] = [
    # Self-joins (diagonal) -- identity
    (_I, _I, _I),
    (_A, _A, _A),
    (_G, _G, _G),
    (_ER, _ER, _ER),
    (_UR, _UR, _UR),
    (_UG, _UG, _UG),
    (_UA, _UA, _UA),
    (_MR, _MR, _MR),
    # Cross-classification joins -- all MIXED_RAW
    (_I, _A, _MR),
    (_I, _G, _MR),
    (_I, _ER, _MR),
    (_I, _UR, _MR),
    (_I, _UG, _MR),
    (_I, _UA, _MR),
    (_A, _G, _MR),
    (_A, _ER, _MR),
    (_A, _UR, _MR),
    (_A, _UG, _MR),
    (_A, _UA, _MR),
    (_G, _ER, _MR),
    (_G, _UR, _MR),
    (_G, _UG, _MR),
    (_G, _UA, _MR),
    (_ER, _UR, _MR),
    (_ER, _UG, _MR),
    (_ER, _UA, _MR),
    # Within UNKNOWN family -- demoting rules
    (_UR, _UG, _UR),   # weaker validation wins
    (_UR, _UA, _UR),   # weaker validation wins
    (_UG, _UA, _UG),   # weaker validation wins
    # MIXED_RAW absorbing -- all pairs with MIXED_RAW
    (_I, _MR, _MR),
    (_A, _MR, _MR),
    (_G, _MR, _MR),
    (_ER, _MR, _MR),
    (_UR, _MR, _MR),
    (_UG, _MR, _MR),
    (_UA, _MR, _MR),
]


class TestTaintJoinTruthTable:
    """Exhaustive truth table -- executable spec §6 reference."""

    @pytest.mark.parametrize(
        "left,right,expected",
        TRUTH_TABLE,
        ids=[f"{a.value}+{b.value}" for a, b, _ in TRUTH_TABLE],
    )
    def test_join_result(
        self, left: TaintState, right: TaintState, expected: TaintState
    ) -> None:
        assert taint_join(left, right) == expected

    @pytest.mark.parametrize(
        "left,right,expected",
        TRUTH_TABLE,
        ids=[f"{b.value}+{a.value}" for a, b, _ in TRUTH_TABLE],
    )
    def test_join_commutative(
        self, left: TaintState, right: TaintState, expected: TaintState
    ) -> None:
        """Reverse operand order produces same result."""
        assert taint_join(right, left) == expected

    def test_truth_table_covers_all_unique_pairs(self) -> None:
        """Verify truth table has exactly 36 entries (8 diagonal + 28 upper triangle)."""
        assert len(TRUTH_TABLE) == 36
        pairs = {(min(a, b, key=lambda x: x.value), max(a, b, key=lambda x: x.value)) for a, b, _ in TRUTH_TABLE}
        # 8 choose 2 = 28 off-diagonal + 8 diagonal = 36
        assert len(pairs) == 36
