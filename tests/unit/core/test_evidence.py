"""Tests for the §6.3 evidence-to-tier matrix.

Expected values encoded directly from the spec — NOT imported from
the implementation. Follows test_matrix.py independent-oracle discipline.
"""
from __future__ import annotations

import pytest

from wardline.core.taints import TaintState

EVIDENCE_MATRIX = [
    # (structural, semantic, integrity, institutional, expected)
    # --- 6 spec-table rows ---
    (True, True, True, True, TaintState.INTEGRAL),
    (True, True, False, True, TaintState.ASSURED),
    (True, False, False, True, TaintState.GUARDED),
    (True, True, False, False, TaintState.UNKNOWN_ASSURED),
    (True, False, False, False, TaintState.UNKNOWN_GUARDED),
    (False, False, False, False, TaintState.UNKNOWN_RAW),
    # --- Off-table: structural=False with downstream True ---
    (False, True, False, False, TaintState.UNKNOWN_RAW),
    (False, False, True, False, TaintState.UNKNOWN_RAW),
    (False, False, False, True, TaintState.UNKNOWN_RAW),
    (False, True, True, False, TaintState.UNKNOWN_RAW),
    (False, True, False, True, TaintState.UNKNOWN_RAW),
    (False, False, True, True, TaintState.UNKNOWN_RAW),
    (False, True, True, True, TaintState.UNKNOWN_RAW),
    # --- Off-table: structural=True, institutional-gate ---
    (True, True, True, False, TaintState.UNKNOWN_ASSURED),
    (True, False, True, False, TaintState.UNKNOWN_GUARDED),
    (True, False, True, True, TaintState.GUARDED),
]

@pytest.mark.parametrize(
    "structural,semantic,integrity,institutional,expected",
    EVIDENCE_MATRIX,
    ids=[
        "full_evidence_T1", "no_integrity_T2", "no_semantic_T3",
        "no_institutional_sem_UNKNOWN_SEM", "structural_only_UNKNOWN_SHAPE",
        "no_evidence_UNKNOWN_RAW",
        "no_structural_with_semantic", "no_structural_with_integrity",
        "no_structural_with_institutional", "no_structural_with_sem_int",
        "no_structural_with_sem_inst", "no_structural_with_int_inst",
        "no_structural_with_all_downstream",
        "institutional_gate_sem_int_no_inst",
        "institutional_gate_int_no_inst",
        "integrity_without_semantic_T3",
    ],
)
def test_evidence_matrix(
    structural: bool, semantic: bool, integrity: bool,
    institutional: bool, expected: TaintState,
) -> None:
    from wardline.core.evidence import max_restorable_tier
    assert max_restorable_tier(structural, semantic, integrity, institutional) == expected

def test_fixture_has_16_cells() -> None:
    """Guard: if the spec adds a row, this test reminds us to update."""
    assert len(EVIDENCE_MATRIX) == 16
