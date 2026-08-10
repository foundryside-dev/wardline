# tests/unit/core/test_registry.py
from __future__ import annotations

from collections.abc import Mapping

import pytest

from wardline.core.registry import REGISTRY, REGISTRY_VERSION, ArgKind, MarkerCallForm, RegistryEntry
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


def test_registry_declares_marker_kwargs() -> None:
    # The declared keyword set per marker — spec §4.2. This is the DECLARATION
    # contract, not a transcription of the runtime signature
    # (src/wardline/decorators/trust.py): trust_boundary declares only to_level and
    # trusted only level, while external_boundary declares none because it is
    # BARE_ONLY — call form is decided first, so kwargs are never consulted for it.
    # (Its `fn` parameter is positional-or-keyword, so `external_boundary(fn=...)`
    # is legal Python; it still declares nothing on the decorated function, which is
    # exactly why the empty set is the right contract rather than `{"fn"}`.)
    assert REGISTRY["external_boundary"].kwargs == frozenset()
    assert REGISTRY["trust_boundary"].kwargs == frozenset({"to_level"})
    assert REGISTRY["trusted"].kwargs == frozenset({"level"})


def test_registry_arg_kinds_cover_the_level_args() -> None:
    assert dict(REGISTRY["trusted"].arg_kinds) == {"level": ArgKind.LEVEL}
    assert dict(REGISTRY["trust_boundary"].arg_kinds) == {"to_level": ArgKind.LEVEL}
    assert dict(REGISTRY["external_boundary"].arg_kinds) == {}


def test_registry_kwarg_invariants() -> None:
    for entry in REGISTRY.values():
        assert set(entry.arg_kinds) == entry.kwargs, entry.canonical_name


def test_shipped_call_forms_are_exact() -> None:
    assert REGISTRY["external_boundary"].call_form is MarkerCallForm.BARE_ONLY
    assert REGISTRY["trust_boundary"].call_form is MarkerCallForm.CALL_ONLY
    assert REGISTRY["trusted"].call_form is MarkerCallForm.BARE_OR_CALL


def test_registry_arg_kinds_are_immutable() -> None:
    import pytest

    with pytest.raises(TypeError):
        REGISTRY["trusted"].arg_kinds["level"] = ArgKind.REF  # type: ignore[index]


def test_registry_entry_deep_freezes_caller_inputs() -> None:
    kwargs = {"level"}
    kinds = {"level": ArgKind.LEVEL}
    entry = RegistryEntry(
        "x", 1, {}, kwargs=kwargs, arg_kinds=kinds,
        call_form=MarkerCallForm.BARE_OR_CALL,
    )
    kwargs.add("audit")
    kinds["level"] = ArgKind.REF
    assert entry.kwargs == frozenset({"level"})
    assert dict(entry.arg_kinds) == {"level": ArgKind.LEVEL}


def test_registry_rejects_untyped_declared_keyword() -> None:
    import pytest

    with pytest.raises(ValueError, match="arg_kinds keys must equal kwargs"):
        RegistryEntry("x", 1, {}, kwargs={"level"}, arg_kinds={})


def test_registry_kwargs_match_boundary_type_level_args() -> None:
    # One source of truth: the tripwire in boundary_types enforces this at import,
    # this test makes the fusion a named contract.
    from wardline.scanner.boundary_types import BUILTIN_BOUNDARY_TYPES

    for bt in BUILTIN_BOUNDARY_TYPES:
        assert REGISTRY[bt.canonical_name].kwargs == frozenset(
            la.arg_name for la in bt.level_args
        ), bt.canonical_name


def test_tripwire_covers_both_builtin_roots() -> None:
    # Spec §4.2: the load-time tripwire covers BOTH builtin roots. Pin that the
    # weft_markers rows are genuinely checked, not skipped, by asserting they carry
    # exactly the registry contract the loop enforces.
    from wardline.scanner.boundary_types import BUILTIN_BOUNDARY_TYPES

    roots = {bt.module_prefix.split(".")[0] for bt in BUILTIN_BOUNDARY_TYPES}
    assert roots == {"wardline", "weft_markers"}
    for bt in BUILTIN_BOUNDARY_TYPES:
        entry = REGISTRY[bt.canonical_name]
        assert entry.group == bt.group, bt.module_prefix
        assert entry.kwargs == frozenset(la.arg_name for la in bt.level_args), bt.module_prefix
        assert dict(entry.arg_kinds) == {
            la.arg_name: ArgKind.LEVEL for la in bt.level_args
        }, bt.module_prefix


def test_tripwire_leaves_no_module_scope_temporaries() -> None:
    # The trailing `del` must name every leaked temporary and nothing more — a
    # stale `del _la` would NameError at import and take the whole package down.
    import wardline.scanner.boundary_types as bt_mod

    assert not [
        n for n in vars(bt_mod)
        if n in {"_bt", "_entry", "_expected_kwargs", "_expected_kinds", "_la"}
    ]
