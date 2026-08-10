# src/wardline/core/registry.py
"""Canonical decorator registry — the single source of truth for Wardline's
trust vocabulary, and the import surface Loomweave's plugin depends on.

Public surface (do not break — integration brief §Round 1, asterisk 2):
``wardline.core.registry.{REGISTRY, REGISTRY_VERSION, RegistryEntry, ArgKind,
MarkerCallForm}``.
SP2d additionally exports this as a versioned NG-25 descriptor so consumers
can *read* instead of *import*.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType

from wardline.core.taints import TaintState

# Version line for the generic rebuild's vocabulary (distinct from wardline.old's
# "1.1"). Bumped when the vocabulary's declaration surface changes; the taint
# provider derives its cache-key fingerprint from this (SP2b).
REGISTRY_VERSION = "wardline-generic-2"


class ArgKind(StrEnum):
    """The marker-argument grammar (declaration-surface-v2 §4.2, P14).

    Declares how the engine READS each keyword argument of a registered marker.
    S0 ships only ``LEVEL`` consumers. ``TOKEN_SET`` (tuples of value tokens,
    e.g. ``marks=``/``evidence=``) and ``REF`` (module-level declaration
    references, e.g. ``contract=``) get their generic readers with their first
    S2 consumers; S3 reuses TOKEN_SET for the Evidence domain. Every kind is
    fail-closed on any deviation from its form. There is no ignored/compat
    keyword concept: a keyword outside ``kwargs`` is PY-WL-130's DEFECT and the
    seed drops (the runtime signatures reject it too).
    """

    LEVEL = "level"
    TOKEN_SET = "token_set"
    REF = "ref"


class MarkerCallForm(StrEnum):
    """Whether a shipped marker is legal bare, called, or in either form."""

    BARE_ONLY = "bare_only"
    CALL_ONLY = "call_only"
    BARE_OR_CALL = "bare_or_call"


@dataclass(frozen=True)
class RegistryEntry:
    """A registered trust decorator and its expected ``_wardline_*`` attributes.

    ``attrs`` maps each stamped attribute name to its expected value *type*.
    ``kwargs`` is the declared keyword set the marker's call form accepts —
    exactly the runtime signature's keyword parameters, fused to the boundary
    types' ``level_args`` by the load-time tripwire in ``boundary_types``.
    ``arg_kinds`` maps declared keywords to their :class:`ArgKind` reading
    discipline. Mappings are wrapped in ``MappingProxyType`` at construction.
    """

    canonical_name: str
    group: int
    attrs: Mapping[str, type]
    kwargs: frozenset[str] = field(default_factory=frozenset)
    arg_kinds: Mapping[str, ArgKind] = field(default_factory=dict)
    call_form: MarkerCallForm = MarkerCallForm.BARE_OR_CALL

    def __post_init__(self) -> None:
        frozen_kwargs = frozenset(self.kwargs)
        frozen_arg_kinds = MappingProxyType(
            {name: ArgKind(kind) for name, kind in self.arg_kinds.items()}
        )
        object.__setattr__(self, "attrs", MappingProxyType(dict(self.attrs)))
        object.__setattr__(self, "kwargs", frozen_kwargs)
        object.__setattr__(self, "arg_kinds", frozen_arg_kinds)
        object.__setattr__(self, "call_form", MarkerCallForm(self.call_form))
        if set(frozen_arg_kinds) != frozen_kwargs:
            raise ValueError(f"{self.canonical_name}: arg_kinds keys must equal kwargs")


_ENTRIES: dict[str, RegistryEntry] = {
    "external_boundary": RegistryEntry(
        canonical_name="external_boundary",
        group=1,
        attrs={},
        call_form=MarkerCallForm.BARE_ONLY,
    ),
    "trust_boundary": RegistryEntry(
        canonical_name="trust_boundary",
        group=1,
        attrs={"_wardline_to_level": TaintState},
        kwargs=frozenset({"to_level"}),
        arg_kinds={"to_level": ArgKind.LEVEL},
        call_form=MarkerCallForm.CALL_ONLY,
    ),
    "trusted": RegistryEntry(
        canonical_name="trusted",
        group=1,
        attrs={"_wardline_level": TaintState},
        kwargs=frozenset({"level"}),
        arg_kinds={"level": ArgKind.LEVEL},
        call_form=MarkerCallForm.BARE_OR_CALL,
    ),
}

# Consistency invariant: every key equals its entry's canonical_name.
for _name, _entry in _ENTRIES.items():
    if _name != _entry.canonical_name:
        raise ValueError(f"REGISTRY key {_name!r} != canonical_name {_entry.canonical_name!r}")
del _name, _entry

REGISTRY: MappingProxyType[str, RegistryEntry] = MappingProxyType(_ENTRIES)
