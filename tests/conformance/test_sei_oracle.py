"""Weft SEI §8 conformance oracle — Wardline as consumer.

The scenario list is loaded from the vendored ``sei-conformance-oracle.json``
fixture, copied from Loomweave's authoritative fixture. Each scenario id is
claimed by one consumer assertion so a fixture change fails CI until Wardline
updates the corresponding behavior check.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from wardline.loomweave.identity import IdentityStatus, SeiCapability, SeiResolver

ORACLE_PATH = Path(__file__).parent / "fixtures" / "sei-conformance-oracle.json"

# The git blob hash of the vendored SEI conformance oracle as authored upstream by
# Loomweave (docs/federation/fixtures/sei-conformance-oracle.json). Loomweave is the
# PRODUCER/authority for the six-scenario §8 oracle; Wardline is the CONSUMER and
# VENDORS the fixture byte-verbatim. This Layer-1 byte-pin runs in the DEFAULT PR
# suite, so ANY byte change to the vendored copy fails loudly — re-vendors are
# deliberate and update this constant in the SAME commit as the new bytes.
#
# RE-VENDOR PROCEDURE (a release-gate item — run ``pytest -m sei_drift -v`` before
# every release; on drift, or on a deliberate upstream oracle bump):
#   1. Copy ``$WARDLINE_LOOMWEAVE_REPO/docs/federation/fixtures/sei-conformance-oracle.json``
#      byte-verbatim over the vendored copy. NEVER hand-edit the vendored fixture;
#      Loomweave's oracle (cargo gate ``sei_conformance_oracle``) is the only author.
#   2. Update ``UPSTREAM_BLOB_SHA`` to ``git hash-object`` of the vendored file
#      (equivalently ``hashlib.sha1(b"blob %d\0" % len(data) + data)``) — same commit.
#   3. Re-run conformance and CONFORM the consumer (``wardline.loomweave.identity``)
#      until green; never weaken the assertions.
UPSTREAM_BLOB_SHA = "0ea577025d94c028a0f682b7d29765079455718c"


def _load_oracle() -> dict[str, Any]:
    return json.loads(ORACLE_PATH.read_text(encoding="utf-8"))


def _scenario(scenario_id: str) -> dict[str, Any]:
    for item in _load_oracle()["scenarios"]:
        if item["id"] == scenario_id:
            return item
    raise AssertionError(f"missing SEI oracle scenario {scenario_id!r}")


def _loomweave_oracle_source() -> Path | None:
    # Env takes EXCLUSIVE precedence (first-configured, not first-existing): if
    # ``WARDLINE_LOOMWEAVE_REPO`` (or the legacy unnamespaced ``LOOMWEAVE_REPO``)
    # is set, resolve the sibling ONLY from it and skip clean if the oracle is
    # absent under it — the parents[3] local-dev convenience checkout is consulted
    # ONLY when no env var is set. This shares ONE resolution contract with the
    # other ``_drift`` rechecks (test_loomweave_qualname_parity.py:150): an
    # operator who points the release-gate env var at a specific checkout that
    # lacks the file gets a clean skip, never a silent compare against the local
    # convenience sibling. CI runners (env unset, no parents[3] sibling) skip
    # clean — the documented basis for the clean skip is the sibling's ABSENCE,
    # not a guarantee independent of runner layout.
    subpath = ("docs", "federation", "fixtures", "sei-conformance-oracle.json")
    for var in ("WARDLINE_LOOMWEAVE_REPO", "LOOMWEAVE_REPO"):
        if env := os.environ.get(var):
            path = Path(env).joinpath(*subpath)
            return path if path.exists() else None
    path = Path(__file__).resolve().parents[3] / "loomweave" / Path(*subpath)
    return path if path.exists() else None


COVERED_SCENARIOS = {
    "identity_round_trip_and_opacity",
    "rename",
    "move",
    "ambiguous",
    "delete",
    "capability_absent",
}


class FakeClient:
    def __init__(
        self,
        *,
        caps: dict[str, Any] | None = None,
        resolve: dict[str, Any] | None = None,
        resolve_sei: dict[str, Any] | None = None,
    ) -> None:
        self._caps = caps
        self._resolve = resolve
        self._resolve_sei = resolve_sei
        self.resolve_calls: list[str] = []

    def capabilities(self) -> dict[str, Any] | None:
        return self._caps

    def resolve_identity(self, locator: str) -> dict[str, Any] | None:
        self.resolve_calls.append(locator)
        return self._resolve

    def resolve_sei(self, sei: str) -> dict[str, Any] | None:
        return self._resolve_sei


def test_vendored_oracle_matches_upstream_blob_pin() -> None:
    """Layer 1 (default suite): the vendored SEI oracle byte-pins to the upstream
    git blob hash. ANY edit to the vendored fixture without a matching re-pin reds
    the default PR suite — the fail-closed protection that lets the Layer-2 drift
    recheck skip clean when the sibling checkout is absent."""
    assert len(UPSTREAM_BLOB_SHA) == 40 and set(UPSTREAM_BLOB_SHA) <= set("0123456789abcdef"), (
        f"UPSTREAM_BLOB_SHA must be 40 lowercase hex chars (a git blob SHA-1): {UPSTREAM_BLOB_SHA!r}"
    )
    data = ORACLE_PATH.read_bytes()
    actual = hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()
    assert actual == UPSTREAM_BLOB_SHA, (
        f"the vendored SEI oracle changed (git blob {actual}, pinned {UPSTREAM_BLOB_SHA}) — "
        "if this was a deliberate re-vendor, update UPSTREAM_BLOB_SHA in the same commit and "
        "re-run conformance; if not, someone edited the vendored copy (forbidden — Loomweave's "
        "oracle is the only author; see the RE-VENDOR PROCEDURE at the top of this module)"
    )


@pytest.mark.sei_drift
def test_vendored_oracle_matches_loomweave_source() -> None:
    """Layer 2 (opt-in, ``-m sei_drift``): the sibling loomweave checkout's
    authoritative oracle must be BYTE-IDENTICAL to the vendored copy — the
    release-gate drift alarm. Absent checkout (CI/default suite) skips clean;
    divergence FAILS.

    Byte-exact (not JSON-semantic) by design: the RE-VENDOR PROCEDURE mandates a
    byte-verbatim copy and the Layer-1 ``UPSTREAM_BLOB_SHA`` pins the git blob, so
    a copy that is reordered/reformatted (JSON-equal but byte-different) would leave
    the blob-pin silently stale yet pass a parsed-dict compare. Comparing raw bytes
    enforces the same byte-verbatim invariant Layer-1 assumes, matching the
    loomweave_drift precedent (test_loomweave_rust_qualname_parity.py)."""
    source = _loomweave_oracle_source()
    if source is None:
        pytest.skip("Loomweave repo not found; set WARDLINE_LOOMWEAVE_REPO to enable drift check")
    if ORACLE_PATH.read_bytes() != source.read_bytes():
        pytest.fail(
            f"upstream {source} has drifted from the vendored "
            "tests/conformance/fixtures/sei-conformance-oracle.json — re-vendor + conform: follow the "
            "RE-VENDOR PROCEDURE at the top of this module (byte-verbatim copy, bump UPSTREAM_BLOB_SHA "
            "in the same commit, re-run conformance)"
        )


def test_every_oracle_scenario_is_covered() -> None:
    fixture_ids = {item["id"] for item in _load_oracle()["scenarios"]}
    assert fixture_ids == COVERED_SCENARIOS


def test_identity_round_trip_and_opacity() -> None:
    scenario = _scenario("identity_round_trip_and_opacity")
    locator = "python:function:m.f"
    sei = "loomweave:eid:0123456789abcdef0123456789abcdef"
    client = FakeClient(
        caps={"sei": {"supported": True, "version": 1}},
        resolve={"sei": sei, "current_locator": locator, "content_hash": "h", "alive": True},
        resolve_sei={"current_locator": locator, "content_hash": "h", "alive": True},
    )
    resolver = SeiResolver.detect(client)

    binding = resolver.resolve_locator(locator)

    assert scenario["expect"]["resolve_locator"]["alive"] is True
    assert binding.identity is IdentityStatus.ALIVE
    assert binding.sei == sei
    assert binding.binding_key == sei
    assert binding.keyed_on_sei is True
    assert binding.sei.startswith("loomweave:eid:")
    assert binding.sei != locator
    assert resolver.resolve_identity_status(sei) is IdentityStatus.ALIVE


@pytest.mark.parametrize("scenario_id", ["rename", "move"])
def test_carried_sei_remains_alive_for_rename_and_move(scenario_id: str) -> None:
    scenario = _scenario(scenario_id)
    sei = "loomweave:eid:carried"
    client = FakeClient(caps={"sei": {"supported": True, "version": 1}}, resolve_sei={"sei": sei, "alive": True})
    resolver = SeiResolver.detect(client)

    assert scenario["expect"]["carry"] is True
    assert resolver.resolve_identity_status(sei) is IdentityStatus.ALIVE


@pytest.mark.parametrize("scenario_id", ["ambiguous", "delete"])
def test_orphaned_sei_surfaces_as_orphaned_for_ambiguous_and_delete(scenario_id: str) -> None:
    scenario = _scenario(scenario_id)
    sei = "loomweave:eid:orphaned"
    client = FakeClient(
        caps={"sei": {"supported": True, "version": 1}},
        resolve_sei={"sei": sei, "alive": False, "lineage": [{"event": "orphaned"}]},
    )
    resolver = SeiResolver.detect(client)

    assert "orphaned" in json.dumps(scenario["expect"])
    assert resolver.resolve_identity_status(sei) is IdentityStatus.ORPHANED


def test_capability_absent_degrades_gracefully() -> None:
    scenario = _scenario("capability_absent")
    locator = "python:function:any"
    client = FakeClient(caps={"linkages": {"http": True}})
    resolver = SeiResolver.detect(client)

    binding = resolver.resolve_locator(locator)

    assert scenario["expect"]["resolve_locator(any)"]["alive"] is False
    assert resolver.capability == SeiCapability(supported=False)
    assert binding.identity is IdentityStatus.UNAVAILABLE
    assert binding.sei is None
    assert binding.binding_key == locator
    assert client.resolve_calls == []
