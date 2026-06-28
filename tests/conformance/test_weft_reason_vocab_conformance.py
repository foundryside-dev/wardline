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

The hub contract is VENDORED byte-for-byte at ``tests/conformance/fixtures/weft-reason-vocab.json``
so the guard is hermetic AND byte-pinned. The conformance shape is the same
``byte_golden_corpus`` consumer pattern as the SEI oracle / Rust qualname corpus:

  * LAYER 1 (default suite, always runs): ``UPSTREAM_BLOB_SHA`` byte-pins the vendored copy
    to the upstream git blob hash. ANY edit to the vendored contract without a matching re-pin
    reds the default PR suite — the fail-closed protection that lets the Layer-2 drift recheck
    skip clean when the hub checkout is absent. The inline canonical-11 frozenset is pinned to
    this vendored JSON (always) AND to the live hub when present.
  * LAYER 2 (opt-in, ``-m reason_vocab_drift``): byte-compares the vendored copy against the
    hub-authoritative contract (``WARDLINE_WEFT_REPO``, default ``/home/john/weft``); skips
    clean when the hub checkout is absent (CI), FAILS on drift — the release-gate drift alarm.

RE-VENDOR PROCEDURE (a release-gate item — run ``pytest -m reason_vocab_drift -v`` before
every release; on drift, or on a deliberate upstream contract bump):
  1. ``cp $WARDLINE_WEFT_REPO/contracts/weft-reason-vocab.json
     tests/conformance/fixtures/weft-reason-vocab.json`` — byte-verbatim. NEVER hand-edit the
     vendored copy; the weft hub is the only author.
  2. Update ``UPSTREAM_BLOB_SHA`` to ``git hash-object`` of the vendored file in the SAME commit.
  3. Reconcile ``CANONICAL_REASON_CLASSES`` (and the wardline mapping) with the new contract and
     re-run conformance until byte-green — conform the member, never weaken the comparison.
"""

from __future__ import annotations

import hashlib
import json
import os
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

# The vendored hub contract (byte-for-byte copy of contracts/weft-reason-vocab.json). The
# Layer-1 byte-pin below freezes this file's git blob so any edit reds the default suite.
_VENDORED_CONTRACT = Path(__file__).parent / "fixtures" / "weft-reason-vocab.json"

# The git blob hash of the vendored contract as committed upstream (weft hub
# contracts/weft-reason-vocab.json, version 1). Re-vendors update this constant in the SAME
# commit as the new bytes — see the RE-VENDOR PROCEDURE in this module's header.
UPSTREAM_BLOB_SHA = "948f1d4b334fcedebd40449aa10b750bd3eed216"


def _hub_contract_source() -> Path | None:
    """The hub-authoritative contract path for the Layer-2 drift recheck, or None when no hub
    checkout is reachable. Honors ``WARDLINE_WEFT_REPO`` first (the sibling-relocation env var,
    mirroring the ``WARDLINE_LOOMWEAVE_REPO`` precedent), then the conventional ``/home/john/weft``
    absolute, then the local-dev ``../weft`` sibling relative to this repo root.
      this file: <home>/<user>/wardline/tests/conformance/<this>
      parents:   0=conformance 1=tests 2=wardline 3=<user> -> sibling weft/ lives at parents[3]/weft
    """
    # Env takes EXCLUSIVE precedence (first-configured, not first-existing): when
    # ``WARDLINE_WEFT_REPO`` is set, resolve the hub contract ONLY from it and skip
    # clean if it is absent under that root — the conventional ``/home/john/weft``
    # and the local-dev ``../weft`` convenience checkouts are consulted ONLY when
    # the env var is unset. This shares ONE resolution contract with the other
    # ``_drift`` rechecks (see test_loomweave_qualname_parity.py:150): an operator
    # who points the release-gate env var at a specific checkout that lacks the
    # file gets a clean skip, never a silent compare against a convenience sibling.
    if env := os.environ.get("WARDLINE_WEFT_REPO"):
        path = Path(env) / "contracts" / "weft-reason-vocab.json"
        return path if path.is_file() else None
    fallbacks = (
        Path("/home/john/weft") / "contracts" / "weft-reason-vocab.json",
        Path(__file__).resolve().parents[3] / "weft" / "contracts" / "weft-reason-vocab.json",
    )
    return next((path for path in fallbacks if path.is_file()), None)


def test_vendored_canonical_set_is_exactly_eleven() -> None:
    # The contract is a CLOSED 11-class set. A change to this count must be a deliberate edit
    # tracked against the hub contract, never an accidental local addition.
    assert len(CANONICAL_REASON_CLASSES) == 11


def test_vendored_contract_matches_upstream_blob_pin() -> None:
    # Layer 1 (default suite, always runs): the vendored contract byte-pins to the upstream git
    # blob hash. ANY edit to the vendored copy without a matching re-pin reds the default PR
    # suite — the fail-closed protection that lets the Layer-2 drift recheck skip clean when the
    # hub checkout is absent.
    assert len(UPSTREAM_BLOB_SHA) == 40 and set(UPSTREAM_BLOB_SHA) <= set("0123456789abcdef"), (
        f"UPSTREAM_BLOB_SHA must be 40 lowercase hex chars (a git blob SHA-1): {UPSTREAM_BLOB_SHA!r}"
    )
    data = _VENDORED_CONTRACT.read_bytes()
    actual = hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()
    assert actual == UPSTREAM_BLOB_SHA, (
        f"the vendored weft-reason contract changed (git blob {actual}, pinned {UPSTREAM_BLOB_SHA}) — "
        "if this was a deliberate re-vendor, update UPSTREAM_BLOB_SHA in the same commit and re-run "
        "conformance; if not, someone edited the vendored copy (forbidden — the weft hub is the only "
        "author; see the RE-VENDOR PROCEDURE at the top of this module)"
    )


def test_inline_set_matches_vendored_contract() -> None:
    # Always-runs hermetic pin: the inline canonical-11 frozenset must match the vendored JSON's
    # reason_classes exactly, and the carrier rule it carries. A hub-side bump re-vendored into
    # the JSON without reconciling the inline mirror reds here even on a bare checkout (no hub).
    contract = json.loads(_VENDORED_CONTRACT.read_text("utf-8"))
    assert frozenset(contract["reason_classes"]) == CANONICAL_REASON_CLASSES, (
        "inline CANONICAL_REASON_CLASSES drifted from the vendored "
        f"{_VENDORED_CONTRACT.name}; reconcile per the RE-VENDOR PROCEDURE."
    )
    carrier = contract["carrier"]
    assert set(carrier["required_on_non_clean"]) == {"reason_class", "cause", "fix"}
    assert set(carrier["clean_omits"]) == {"cause", "fix"}


@pytest.mark.reason_vocab_drift
def test_vendored_contract_matches_hub_source() -> None:
    # Layer 2 (opt-in, ``-m reason_vocab_drift``): the hub-authoritative contract must be
    # BYTE-IDENTICAL to the vendored copy — the release-gate drift alarm. Absent hub checkout
    # (CI/default suite) skips clean; divergence FAILS.
    #
    # Byte-exact (not JSON-semantic) by design: the RE-VENDOR PROCEDURE mandates a byte-verbatim
    # copy and Layer-1 pins the git blob, so a reordered/reformatted (JSON-equal byte-different)
    # copy would leave the blob-pin silently stale yet pass a parsed-dict compare. Raw-byte
    # comparison enforces the same invariant Layer-1 assumes (the sei_drift/loomweave_drift
    # precedent).
    source = _hub_contract_source()
    if source is None:
        pytest.skip("weft hub contract not found; set WARDLINE_WEFT_REPO to enable the drift check")
    if _VENDORED_CONTRACT.read_bytes() != source.read_bytes():
        pytest.fail(
            f"upstream {source} has drifted from the vendored "
            "tests/conformance/fixtures/weft-reason-vocab.json — re-vendor + conform: follow the "
            "RE-VENDOR PROCEDURE at the top of this module (byte-verbatim copy, bump UPSTREAM_BLOB_SHA "
            "in the same commit, re-run conformance)"
        )


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
