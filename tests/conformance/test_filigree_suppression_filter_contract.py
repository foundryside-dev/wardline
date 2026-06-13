"""Wardline-owned suppression-state vocabulary consumed by Filigree.

Filigree's finding-list ``suppression`` filter accepts Wardline's
``SuppressionState`` values plus its own local ``all`` no-filter sentinel. This
contract file is the producer-side anchor: if Wardline adds a suppression state,
the shared vector must change in the same commit and Filigree's consumer test
will fail until its filter grammar follows.
"""

from __future__ import annotations

import json
from pathlib import Path

from wardline.core.finding import SuppressionState

VECTOR_PATH = Path(__file__).parent / "filigree_suppression_filter_contract.json"


def _vector() -> dict:
    return json.loads(VECTOR_PATH.read_text(encoding="utf-8"))


def test_vector_matches_suppression_state_enum() -> None:
    vector = _vector()

    assert vector["contract"] == "weft/wardline-filigree-suppression-filter"
    assert set(vector["suppression_states"]) == {state.value for state in SuppressionState}


def test_filigree_filter_values_are_enum_plus_all_sentinel() -> None:
    vector = _vector()
    expected = {state.value for state in SuppressionState} | {vector["filigree_filter_sentinel"]}

    assert vector["filigree_filter_sentinel"] == "all"
    assert set(vector["filigree_filter_values"]) == expected
