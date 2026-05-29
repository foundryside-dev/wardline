# src/wardline/core/registry.py
"""Canonical decorator registry — the single source of truth for Wardline's
trust vocabulary, and the import surface Clarion's plugin depends on.

Public surface (do not break — integration brief §Round 1, asterisk 2):
``wardline.core.registry.{REGISTRY, REGISTRY_VERSION, RegistryEntry}``.
SP2d additionally exports this as a versioned NG-25 descriptor so consumers
can *read* instead of *import*.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from wardline.core.taints import TaintState

# Version line for the generic rebuild's vocabulary (distinct from wardline.old's
# "1.1"). Bumped when the vocabulary's declaration surface changes; the taint
# provider derives its cache-key fingerprint from this (SP2b).
REGISTRY_VERSION = "wardline-generic-1"


@dataclass(frozen=True)
class RegistryEntry:
    """A registered trust decorator and its expected ``_wardline_*`` attributes.

    ``attrs`` maps each stamped attribute name to its expected value *type*.
    It is wrapped in ``MappingProxyType`` at construction for deep immutability.
    """

    canonical_name: str
    group: int
    attrs: Mapping[str, type]

    def __post_init__(self) -> None:
        object.__setattr__(self, "attrs", MappingProxyType(dict(self.attrs)))


_ENTRIES: dict[str, RegistryEntry] = {
    "external_boundary": RegistryEntry(
        canonical_name="external_boundary", group=1, attrs={}
    ),
    "trust_boundary": RegistryEntry(
        canonical_name="trust_boundary",
        group=1,
        attrs={"_wardline_to_level": TaintState},
    ),
    "trusted": RegistryEntry(
        canonical_name="trusted",
        group=1,
        attrs={"_wardline_level": TaintState},
    ),
}

# Consistency invariant: every key equals its entry's canonical_name.
for _name, _entry in _ENTRIES.items():
    if _name != _entry.canonical_name:
        raise ValueError(
            f"REGISTRY key {_name!r} != canonical_name {_entry.canonical_name!r}"
        )
del _name, _entry

REGISTRY: MappingProxyType[str, RegistryEntry] = MappingProxyType(_ENTRIES)
