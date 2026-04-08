"""Tests for canonical decorator registry."""

import pytest

from wardline.core.registry import REGISTRY, REGISTRY_VERSION


def test_registry_is_immutable() -> None:
    """REGISTRY must be a MappingProxyType — mutation raises TypeError."""
    from types import MappingProxyType

    assert isinstance(REGISTRY, MappingProxyType)
    with pytest.raises(TypeError):
        REGISTRY["rogue"] = None  # type: ignore[index]


def test_registry_version_present() -> None:
    assert isinstance(REGISTRY_VERSION, str)
    assert len(REGISTRY_VERSION) > 0
    # Must be a valid version format (e.g., "0.1", "1.0")
    import re
    assert re.fullmatch(r"\d+\.\d+", REGISTRY_VERSION), (
        f"REGISTRY_VERSION must be 'major.minor' format, got: {REGISTRY_VERSION!r}"
    )


def test_registry_has_all_group1_decorators() -> None:
    """All 7 Group 1 decorators must be registered."""
    group1_names = {
        "external_boundary",
        "validates_shape",
        "validates_semantic",
        "validates_external",
        "integral_read",
        "integral_writer",
        "integral_construction",
    }
    registered = {name for name, entry in REGISTRY.items() if entry.group == 1}
    assert registered == group1_names


def test_registry_has_group2_decorator() -> None:
    """Group 2 integrity_critical must be registered."""
    assert "integrity_critical" in REGISTRY
    assert REGISTRY["integrity_critical"].group == 2


def test_group_10_matches_authoritative_binding() -> None:
    """Group 10 exports the authoritative failure-mode surface."""
    group10_names = {
        "emits_or_explains",
        "exception_boundary",
        "fail_closed",
        "fail_open",
        "must_propagate",
        "preserve_cause",
    }
    registered = {name for name, entry in REGISTRY.items() if entry.group == 10}
    assert registered == group10_names


def test_groups_7_to_15_match_authoritative_binding() -> None:
    """Groups 7-15 must match the authoritative Python binding surface."""
    expected = {
        7: {"parse_at_init"},
        8: {"handles_secrets"},
        9: {"idempotent", "atomic", "compensatable"},
        10: {
            "emits_or_explains",
            "exception_boundary",
            "fail_closed",
            "fail_open",
            "must_propagate",
            "preserve_cause",
        },
        11: {"declassifies", "handles_classified", "handles_pii"},
        12: {"deterministic", "time_dependent"},
        13: {"not_reentrant", "ordered_after", "thread_safe"},
        14: {"privileged_operation", "requires_identity"},
        15: {"deprecated_by", "feature_gated", "test_only"},
    }

    for group, names in expected.items():
        registered = {
            name for name, entry in REGISTRY.items() if entry.group == group
        }
        assert registered == names


def test_total_count() -> None:
    """40 decorators total after Group 16 data_flow addition."""
    assert len(REGISTRY) == 40



def test_entry_immutability_attrs() -> None:
    """attrs dict is wrapped in MappingProxyType — mutation raises TypeError."""
    entry = REGISTRY["external_boundary"]
    with pytest.raises(TypeError):
        entry.attrs["_wardline_new"] = bool  # type: ignore[index]


def test_entry_frozen() -> None:
    """RegistryEntry is a frozen dataclass — attribute assignment raises."""
    entry = REGISTRY["external_boundary"]
    with pytest.raises(AttributeError):
        entry.canonical_name = "hacked"  # type: ignore[misc]


def test_canonical_name_matches_key() -> None:
    """Every entry's canonical_name must match its dict key."""
    for name, entry in REGISTRY.items():
        assert entry.canonical_name == name


def test_all_entries_have_attrs() -> None:
    """Every entry must have at least one _wardline_* attribute."""
    for name, entry in REGISTRY.items():
        assert len(entry.attrs) > 0, f"{name} has no attrs"
        for attr_name in entry.attrs:
            assert attr_name.startswith("_wardline_"), (
                f"{name} has non-wardline attr: {attr_name}"
            )
