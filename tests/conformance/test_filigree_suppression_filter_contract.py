"""Wardline-owned suppression-state vocabulary consumed by Filigree.

Filigree's finding-list ``suppression`` filter accepts Wardline's
``SuppressionState`` values plus its own local ``all`` no-filter sentinel. This
contract file is the producer-side anchor: if Wardline adds a suppression state,
the shared vector must change in the same commit and Filigree's consumer test
will fail until its filter grammar follows.

WARDLINE IS THE AUTHORITY for this seam — it OWNS the ``suppression_state``
vocabulary via ``wardline.core.finding.SuppressionState``. That makes the
two-sided protection a two-layer affair:

* Layer-1 (``test_vendored_contract_matches_blob_pin``): a git-blob byte-pin on
  the vendored contract, so any silent edit to the shared vector reds the default
  PR suite. On its OWN this is CIRCULAR — wardline pins wardline's own bytes.
* Producer-source recheck (``test_vector_matches_suppression_state_enum``): the
  non-circular break. It imports wardline's LIVE runtime ``SuppressionState`` enum
  and asserts its member values EQUAL the frozen contract's ``suppression_states``.
  The frozen bytes are tied to the live producer enum, so if the enum drifts from
  the contract (a member added/removed/renamed without re-vendoring), it reds.

RE-VENDOR PROCEDURE: if you deliberately change the contract bytes (e.g. add a
suppression state), recompute the blob SHA and update ``UPSTREAM_BLOB_SHA`` in the
SAME commit, and keep the enum in lockstep — the producer-source recheck will
otherwise red.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from wardline.core.finding import SuppressionState

VECTOR_PATH = Path(__file__).parent / "filigree_suppression_filter_contract.json"

# Layer-1 byte-pin: the git-blob SHA-1 of filigree_suppression_filter_contract.json.
# Recomputed below as hashlib.sha1(b"blob %d\0" % len(data) + data). Any edit to the
# vendored contract without a matching re-pin reds the default PR suite.
UPSTREAM_BLOB_SHA = "7bcb6993553e920438fe3854a8a62409362accb9"


def _vector() -> dict:
    return json.loads(VECTOR_PATH.read_text(encoding="utf-8"))


def test_vendored_contract_matches_blob_pin() -> None:
    """Layer-1 (default suite): the wardline-authored contract byte-pins to its git
    blob hash. ANY edit without a matching re-pin reds the default PR suite. On its
    own this pin is wardline-pins-wardline (circular); the non-circular protection is
    ``test_vector_matches_suppression_state_enum`` below, which rechecks the frozen
    bytes against the LIVE producer enum."""
    assert len(UPSTREAM_BLOB_SHA) == 40 and set(UPSTREAM_BLOB_SHA) <= set("0123456789abcdef"), (
        f"UPSTREAM_BLOB_SHA must be 40 lowercase hex chars (a git blob SHA-1): {UPSTREAM_BLOB_SHA!r}"
    )
    data = VECTOR_PATH.read_bytes()
    actual = hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()
    assert actual == UPSTREAM_BLOB_SHA, (
        f"the vendored suppression-filter contract changed (git blob {actual}, pinned {UPSTREAM_BLOB_SHA}) — "
        "if this was a deliberate re-vendor, update UPSTREAM_BLOB_SHA in the same commit, keep "
        "SuppressionState in lockstep, and re-run conformance (see the RE-VENDOR PROCEDURE at the "
        "top of this module); if not, revert the edit."
    )


def test_vector_matches_suppression_state_enum() -> None:
    """PRODUCER-SOURCE recheck (non-circular): import wardline's LIVE runtime
    ``SuppressionState`` enum and assert its member values EQUAL the frozen
    contract's ``suppression_states``. This ties the byte-pinned contract to the
    real producer enum, so an enum drift (member added/removed/renamed) without a
    re-vendor reds even though the byte-pin still passes."""
    vector = _vector()

    assert vector["contract"] == "weft/wardline-filigree-suppression-filter"
    assert set(vector["suppression_states"]) == {state.value for state in SuppressionState}


def test_filigree_filter_values_are_enum_plus_all_sentinel() -> None:
    vector = _vector()
    expected = {state.value for state in SuppressionState} | {vector["filigree_filter_sentinel"]}

    assert vector["filigree_filter_sentinel"] == "all"
    assert set(vector["filigree_filter_values"]) == expected
