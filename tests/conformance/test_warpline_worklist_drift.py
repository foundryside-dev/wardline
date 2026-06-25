"""Warpline ``reverify_worklist.v1`` wire byte-pin + drift alarm — Wardline as consumer.

This is the two-layer drift alarm for the **Warpline reverify-worklist** seam
(``warpline.reverify_worklist.v1``). Warpline is the PRODUCER/authority for the
worklist envelope; Wardline is a CONSUMER (the ``wardline scan --affected -`` delta
scope, parsed by :func:`wardline.core.delta_scope.parse_affected_scope`). Warpline
freezes the canonical envelope as a committed contract golden vector
(``tests/fixtures/contracts/warpline/mcp-response-reverify.json``, locked by warpline's
own ``tests/contracts/test_warpline_contract_fixtures.py::
test_reverify_response_fixture_carries_honesty_fields``). Wardline VENDORS that vector
byte-verbatim and pins it here.

This is the same two-layer shape as ``test_sei_oracle.py`` (loomweave SEI) and
``test_loomweave_rust_qualname_parity.py`` (rust qualname corpus):

* **Layer 1 (default suite)** — ``UPSTREAM_BLOB_SHA`` below byte-pins the vendored
  copy's git blob hash. ANY byte change to the vendored wire reds the default PR
  suite loudly. This is the fail-closed protection that lets the Layer-2 recheck skip
  clean when the warpline sibling checkout is absent.
* **Layer 2 (opt-in, ``-m worklist_drift``)** — byte-compares the vendored copy against
  warpline's authoritative source (``WARDLINE_WARPLINE_REPO``, default
  ``/home/john/warpline``); skips clean when the sibling is absent (CI), FAILS on drift.

Beyond the pin, one behavior assertion proves Wardline *accepts* this exact wire (not
merely that the bytes match): the vendored envelope parses to ``source_kind=
"reverify_worklist_v1"`` and the load-bearing ``items[].entity.{locator, sei}`` fields
resolve to the expected affected entity. A pure blob pin would lock the bytes without
demonstrating consumption; this ties the pin to the seam it protects.

The hermetic delta-scope golden (``test_warpline_delta_scope.py``) vendors a faithful
worklist *shape* and pins the seven delta-scope behavior axes; this module pins the
exact upstream-authored *wire bytes* + the drift alarm against the real producer.

RE-VENDOR PROCEDURE (a release-gate item — run ``pytest -m worklist_drift -v`` before
every release; on drift, or on a deliberate upstream contract bump):
  1. Copy ``$WARDLINE_WARPLINE_REPO/tests/fixtures/contracts/warpline/mcp-response-reverify.json``
     byte-verbatim over the vendored copy. NEVER hand-edit the vendored fixture;
     warpline's contract test is the only author.
  2. Update ``UPSTREAM_BLOB_SHA`` to ``git hash-object`` of the vendored file
     (equivalently ``hashlib.sha1(b"blob %d\0" % len(data) + data)``) — same commit.
  3. Re-run conformance and CONFORM the consumer
     (``wardline.core.delta_scope.parse_affected_scope``) until green; never weaken the
     assertions.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from wardline.core.delta_scope import parse_affected_scope

VENDORED_WIRE = Path(__file__).parent / "fixtures" / "warpline_contract" / "mcp-response-reverify.json"

# The git blob hash of the vendored reverify-worklist wire as authored upstream by
# warpline (tests/fixtures/contracts/warpline/mcp-response-reverify.json). Warpline is
# the PRODUCER/authority for the ``warpline.reverify_worklist.v1`` envelope; Wardline is
# the CONSUMER and VENDORS the fixture byte-verbatim. This Layer-1 byte-pin runs in the
# DEFAULT PR suite, so ANY byte change to the vendored copy fails loudly — re-vendors are
# deliberate and update this constant in the SAME commit as the new bytes.
UPSTREAM_BLOB_SHA = "dabfc65451f4e9ceab6a5029bd25b6748a73af07"


def _warpline_wire_source() -> Path | None:
    """Locate warpline's authoritative reverify-wire fixture for the Layer-2 recheck.

    Env takes EXCLUSIVE precedence (first-configured, not first-existing): when
    ``WARDLINE_WARPLINE_REPO`` (the sibling-relocation env var, mirroring the
    ``WARDLINE_LOOMWEAVE_REPO`` precedent) is set, resolve the fixture ONLY from it and
    skip clean if it is absent under that root — the ``parents[3]`` local-dev convenience
    checkout (``../warpline`` from the repo root) is consulted ONLY when the env var is
    unset. This shares ONE resolution contract with the other ``_drift`` rechecks (see
    test_loomweave_qualname_parity.py:150): an operator who points the release-gate env
    var at a specific checkout that lacks the file gets a clean skip, never a silent
    compare against the local convenience sibling. CI runners (env unset, no sibling)
    skip clean — the documented basis for the clean skip is the sibling's ABSENCE on
    runners, not a guarantee independent of runner layout."""
    subpath = ("tests", "fixtures", "contracts", "warpline", "mcp-response-reverify.json")
    if env := os.environ.get("WARDLINE_WARPLINE_REPO"):
        path = Path(env).joinpath(*subpath)
        return path if path.exists() else None
    path = Path(__file__).resolve().parents[3] / "warpline" / Path(*subpath)
    return path if path.exists() else None


def test_vendored_wire_matches_upstream_blob_pin() -> None:
    """Layer 1 (default suite): the vendored reverify-worklist wire byte-pins to the
    upstream git blob hash. ANY edit to the vendored fixture without a matching re-pin
    reds the default PR suite — the fail-closed protection that lets the Layer-2 drift
    recheck skip clean when the warpline sibling checkout is absent."""
    assert len(UPSTREAM_BLOB_SHA) == 40 and set(UPSTREAM_BLOB_SHA) <= set("0123456789abcdef"), (
        f"UPSTREAM_BLOB_SHA must be 40 lowercase hex chars (a git blob SHA-1): {UPSTREAM_BLOB_SHA!r}"
    )
    data = VENDORED_WIRE.read_bytes()
    actual = hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()
    assert actual == UPSTREAM_BLOB_SHA, (
        f"the vendored reverify-worklist wire changed (git blob {actual}, pinned {UPSTREAM_BLOB_SHA}) — "
        "if this was a deliberate re-vendor, update UPSTREAM_BLOB_SHA in the same commit and re-run "
        "conformance; if not, someone edited the vendored copy (forbidden — warpline's contract test "
        "is the only author; see the RE-VENDOR PROCEDURE at the top of this module)"
    )


def test_vendored_wire_is_accepted_by_the_consumer() -> None:
    """The pinned wire is the one Wardline's delta-scope consumer actually accepts: the
    vendored ``warpline.reverify_worklist.v1`` envelope parses to ``source_kind=
    "reverify_worklist_v1"`` and the load-bearing ``items[].entity.{locator, sei}`` fields
    resolve to the affected entity. Ties the byte-pin to consumption, not just bytes."""
    payload = json.loads(VENDORED_WIRE.read_text(encoding="utf-8"))
    scope = parse_affected_scope(payload)

    assert scope.source_kind == "reverify_worklist_v1"
    assert scope.item_count == 1
    assert len(scope.entities) == 1
    (entity,) = tuple(scope.entities)
    assert entity.locator == "python:function:src/pkg/mod.py::fn"
    assert entity.sei == "loomweave:eid:0123456789abcdef0123456789abcdef"


@pytest.mark.worklist_drift
def test_vendored_wire_matches_warpline_source() -> None:
    """Layer 2 (opt-in, ``-m worklist_drift``): the sibling warpline checkout's
    authoritative reverify-wire fixture must be BYTE-IDENTICAL to the vendored copy — the
    release-gate drift alarm. Absent checkout (CI/default suite) skips clean; divergence
    FAILS.

    Byte-exact (not JSON-semantic) by design: the RE-VENDOR PROCEDURE mandates a
    byte-verbatim copy and the Layer-1 ``UPSTREAM_BLOB_SHA`` pins the git blob, so a copy
    that is reordered/reformatted (JSON-equal but byte-different) would leave the blob-pin
    silently stale yet pass a parsed-dict compare. Comparing raw bytes enforces the same
    byte-verbatim invariant Layer-1 assumes, matching the loomweave_drift / sei_drift
    precedent."""
    source = _warpline_wire_source()
    if source is None:
        pytest.skip("warpline repo not found; set WARDLINE_WARPLINE_REPO to enable the drift check")
    if VENDORED_WIRE.read_bytes() != source.read_bytes():
        pytest.fail(
            f"upstream {source} has drifted from the vendored "
            "tests/conformance/fixtures/warpline_contract/mcp-response-reverify.json — re-vendor + "
            "conform: follow the RE-VENDOR PROCEDURE at the top of this module (byte-verbatim copy, "
            "bump UPSTREAM_BLOB_SHA in the same commit, re-run conformance)"
        )
