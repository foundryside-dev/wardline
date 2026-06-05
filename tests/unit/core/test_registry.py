# tests/unit/core/test_registry.py
from __future__ import annotations

from collections.abc import Mapping

import pytest

from wardline.core.registry import REGISTRY, REGISTRY_VERSION, RegistryEntry
from wardline.core.taints import TaintState


def test_public_import_surface_present() -> None:
    # The Weft contract: Loomweave's plugin imports these three names.
    assert isinstance(REGISTRY_VERSION, str) and REGISTRY_VERSION
    assert isinstance(REGISTRY, Mapping)
    assert RegistryEntry.__name__ == "RegistryEntry"


def test_registry_holds_the_three_trust_decorators() -> None:
    assert set(REGISTRY) == {"external_boundary", "trust_boundary", "trusted"}
    for name, entry in REGISTRY.items():
        assert entry.canonical_name == name
        assert entry.group == 1


def test_registry_attrs_contract() -> None:
    assert dict(REGISTRY["external_boundary"].attrs) == {}
    assert REGISTRY["trust_boundary"].attrs["_wardline_to_level"] is TaintState
    assert REGISTRY["trusted"].attrs["_wardline_level"] is TaintState


def test_registry_entry_attrs_are_immutable() -> None:
    entry = REGISTRY["trusted"]
    with pytest.raises(TypeError):
        entry.attrs["_wardline_level"] = int  # type: ignore[index]


def test_registry_is_immutable() -> None:
    with pytest.raises(TypeError):
        REGISTRY["new"] = REGISTRY["trusted"]  # type: ignore[index]
