"""Weft SEI §8 conformance oracle — Wardline as consumer.

The scenario list is loaded from the vendored ``sei-conformance-oracle.json``
fixture, copied from Loomweave's authoritative fixture. Each scenario id is
claimed by one consumer assertion so a fixture change fails CI until Wardline
updates the corresponding behavior check.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from wardline.loomweave.identity import IdentityStatus, SeiCapability, SeiResolver

ORACLE_PATH = Path(__file__).parent / "fixtures" / "sei-conformance-oracle.json"


def _load_oracle() -> dict[str, Any]:
    return json.loads(ORACLE_PATH.read_text(encoding="utf-8"))


def _scenario(scenario_id: str) -> dict[str, Any]:
    for item in _load_oracle()["scenarios"]:
        if item["id"] == scenario_id:
            return item
    raise AssertionError(f"missing SEI oracle scenario {scenario_id!r}")


def _loomweave_oracle_source() -> Path | None:
    candidates: list[Path] = []
    if env := os.environ.get("LOOMWEAVE_REPO"):
        candidates.append(Path(env) / "docs" / "federation" / "fixtures" / "sei-conformance-oracle.json")
    candidates.append(
        Path(__file__).resolve().parents[3]
        / "loomweave"
        / "docs"
        / "federation"
        / "fixtures"
        / "sei-conformance-oracle.json"
    )
    return next((path for path in candidates if path.exists()), None)


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


def test_vendored_oracle_matches_loomweave_source() -> None:
    source = _loomweave_oracle_source()
    if source is None:
        pytest.skip("Loomweave repo not found; set LOOMWEAVE_REPO to enable drift check")
    assert _load_oracle() == json.loads(source.read_text(encoding="utf-8"))


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
