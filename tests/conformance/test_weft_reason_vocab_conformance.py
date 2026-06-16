# tests/conformance/test_weft_reason_vocab_conformance.py
"""weft-reason vocabulary conformance (G1) — the drift guard for wardline's emit-failure
reason surface.

SOURCE OF TRUTH: the suite hub contract at contracts/weft-reason-vocab.json
(absolute on this machine: /home/john/weft/contracts/weft-reason-vocab.json). It defines a
CLOSED set of 11 canonical ``reason_class`` values and a carrier rule:

    every NON-clean carrier MUST include {reason_class, cause, fix} (fix MANDATORY);
    a clean carrier omits cause + fix.

wardline's reason surface is ``FailedFinding`` in ``wardline.core.filigree_emit``: it carries
a SHIPPED domain ``reason`` (one of {rejected, validation_error, scheme_mismatch, partial})
that predates the canonical vocabulary and is NOT renamed (it is on the wire). G1 conformance
is ADDITIVE: every domain ``reason`` maps onto a canonical ``reason_class`` via
``_REASON_CLASS_BY_REASON``, and every emitted ``FailedFinding`` carries the canonical
carrier triple alongside the domain fields.

These tests FAIL if the member ever drifts:
  * a new domain reason is added without a canonical mapping, OR
  * a domain reason maps to a class outside the canonical 11, OR
  * a FailedFinding stops carrying reason_class / cause / fix on its wire (carrier rule).

The canonical 11 are vendored below (faithful copy of the hub contract) so the guard is
hermetic; when the hub contract is reachable on disk, an extra assertion pins the vendored
copy to it so a hub-side change to the closed set surfaces here too.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from wardline.core.filigree_emit import (
    _FAILURE_REASONS,
    _FIX_BY_REASON,
    _REASON_CLASS_BY_REASON,
    FailedFinding,
)

# Faithful vendored copy of the closed canonical reason_class set
# (contracts/weft-reason-vocab.json -> reason_classes, version 1).
CANONICAL_REASON_CLASSES = frozenset(
    {
        "clean",
        "disabled",
        "unresolved_input",
        "rejected",
        "dead_path",
        "unreachable",
        "misrouted",
        "error",
        "scheme_mismatch",
        "stale",
        "partial",
    }
)

# The hub contract path (the suite source of truth). Resolved relative to this member's repo
# parent (../../../../weft/contracts/...) so a co-located ``weft`` checkout is found; the
# vendored copy above keeps the guard hermetic when the hub is not on disk.
#   this file: <home>/<user>/wardline/tests/conformance/<this>
#   parents:   0=conformance 1=tests 2=wardline 3=<user> -> sibling weft/ lives at parents[3]/weft
_HUB_CONTRACT = Path(__file__).resolve().parents[3] / "weft" / "contracts" / "weft-reason-vocab.json"


def test_vendored_canonical_set_is_exactly_eleven() -> None:
    # The contract is a CLOSED 11-class set. A change to this count must be a deliberate edit
    # tracked against the hub contract, never an accidental local addition.
    assert len(CANONICAL_REASON_CLASSES) == 11


def test_vendored_set_matches_hub_contract_when_present() -> None:
    # When the suite hub is checked out alongside this member, pin the vendored copy to the
    # real contract so a hub-side change to the closed set fails here instead of going unnoticed.
    if not _HUB_CONTRACT.exists():
        pytest.skip(f"hub contract not present at {_HUB_CONTRACT}; vendored copy is authoritative")
    contract = json.loads(_HUB_CONTRACT.read_text("utf-8"))
    hub_classes = frozenset(contract["reason_classes"])
    assert hub_classes == CANONICAL_REASON_CLASSES, (
        "vendored canonical reason_class set has drifted from the hub contract "
        f"({_HUB_CONTRACT}); reconcile this test with the contract."
    )
    carrier = contract["carrier"]
    assert set(carrier["required_on_non_clean"]) == {"reason_class", "cause", "fix"}
    assert set(carrier["clean_omits"]) == {"cause", "fix"}


def test_every_shipped_reason_maps_to_a_canonical_class() -> None:
    # The member's actual reason vocabulary is the shipped closed set ``_FAILURE_REASONS``.
    # Every member of it MUST have a canonical mapping, and every mapped class MUST be one of
    # the canonical 11. Drift in either direction (an unmapped new reason, or a mapping to a
    # non-canonical class) trips here.
    assert set(_REASON_CLASS_BY_REASON) == set(_FAILURE_REASONS), (
        "every shipped emit-failure reason must declare a canonical reason_class mapping; "
        f"unmapped: {set(_FAILURE_REASONS) - set(_REASON_CLASS_BY_REASON)}"
    )
    emitted_classes = set(_REASON_CLASS_BY_REASON.values())
    assert emitted_classes <= CANONICAL_REASON_CLASSES, (
        "wardline emits a reason_class outside the canonical weft-reason vocabulary: "
        f"{emitted_classes - CANONICAL_REASON_CLASSES}"
    )


def test_every_shipped_reason_declares_a_fix() -> None:
    # Carrier rule: ``fix`` is MANDATORY on every non-clean carrier. A FailedFinding is always
    # non-clean, so every shipped reason must have a non-empty fix string.
    assert set(_FIX_BY_REASON) == set(_FAILURE_REASONS)
    for reason, fix in _FIX_BY_REASON.items():
        assert fix and fix.strip(), f"reason {reason!r} has an empty fix; the carrier rule requires a fix"


@pytest.mark.parametrize("reason", sorted(_FAILURE_REASONS))
def test_failed_finding_carries_canonical_triple_on_wire(reason: str) -> None:
    # Every FailedFinding is a non-clean carrier, so its wire MUST carry the canonical triple
    # {reason_class, cause, fix}, with reason_class drawn from the canonical 11 and cause+fix
    # non-empty. The shipped domain fields (reason/detail) are preserved alongside.
    wire = FailedFinding(reason=reason, detail="x", fingerprint="wlfp2:abc").to_wire()
    assert wire["reason_class"] in CANONICAL_REASON_CLASSES
    assert wire["reason_class"] != "clean"  # a failure is never the clean true-negative
    assert wire["cause"] and wire["cause"].strip()
    assert wire["fix"] and wire["fix"].strip()
    # additive, not breaking: the shipped fields survive verbatim.
    assert wire["reason"] == reason
    assert wire["detail"] == "x"


def test_cause_is_non_empty_even_without_detail() -> None:
    # A non-clean carrier must carry a cause even when Filigree gave no detail string; the
    # domain reason itself is the fallback cause so the triple is never partial.
    wire = FailedFinding(reason="rejected").to_wire()
    assert wire["cause"] == "rejected"
    assert wire["fix"]
