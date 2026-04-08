"""Canonical decorator registry — single source of truth for scanner + library."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from wardline.core.taints import TaintState

REGISTRY_VERSION = "1.0"

# Import-time consistency check added after REGISTRY is constructed (below).


@dataclass(frozen=True)
class RegistryEntry:
    """A registered wardline decorator with its expected attributes.

    The `attrs` dict maps `_wardline_*` attribute names to their expected types.
    Deeply frozen via MappingProxyType to prevent post-construction mutation.

    Pass plain dicts at construction time — __post_init__ wraps them.
    """

    canonical_name: str
    group: int
    attrs: MappingProxyType[str, type]

    def __post_init__(self) -> None:
        # Frozen dataclass prevents direct assignment — use object.__setattr__
        # to wrap mutable dicts in MappingProxyType for deep immutability.
        object.__setattr__(
            self, "attrs", MappingProxyType(dict(self.attrs))
        )


def _bool_entry(name: str, group: int) -> RegistryEntry:
    """Build a RegistryEntry for a simple boolean-marker decorator."""
    return RegistryEntry(
        canonical_name=name,
        group=group,
        attrs={f"_wardline_{name}": bool},  # type: ignore[arg-type]  # __post_init__ converts dict → MappingProxyType
    )


# Group 1: Authority Tier Flow (7 decorators)
# Group 2: Audit (1 decorator)
#
# Groups 3-15: Structural / operational decorators.
# Each is a simple boolean marker unless noted otherwise.
REGISTRY: MappingProxyType[str, RegistryEntry] = MappingProxyType({
    # --- Group 1: Authority Tier Flow ---
    "external_boundary": RegistryEntry(
        canonical_name="external_boundary",
        group=1,
        attrs={"_wardline_tier_source": TaintState},  # type: ignore[arg-type]  # __post_init__ converts
    ),
    "validates_shape": RegistryEntry(
        canonical_name="validates_shape",
        group=1,
        attrs={"_wardline_transition": tuple},  # type: ignore[arg-type]  # __post_init__ converts
    ),
    "validates_semantic": RegistryEntry(
        canonical_name="validates_semantic",
        group=1,
        attrs={"_wardline_transition": tuple},  # type: ignore[arg-type]  # __post_init__ converts
    ),
    "validates_external": RegistryEntry(
        canonical_name="validates_external",
        group=1,
        attrs={"_wardline_transition": tuple},  # type: ignore[arg-type]  # __post_init__ converts
    ),
    "integral_read": RegistryEntry(
        canonical_name="integral_read",
        group=1,
        attrs={"_wardline_tier_source": TaintState},  # type: ignore[arg-type]  # __post_init__ converts
    ),
    "integral_writer": RegistryEntry(
        canonical_name="integral_writer",
        group=1,
        attrs={  # type: ignore[arg-type]  # __post_init__ converts
            "_wardline_tier_source": TaintState,
            "_wardline_integral_writer": bool,
        },
    ),
    "integral_construction": RegistryEntry(
        canonical_name="integral_construction",
        group=1,
        attrs={"_wardline_transition": tuple},  # type: ignore[arg-type]  # __post_init__ converts
    ),
    # --- Group 2: Audit ---
    "integrity_critical": RegistryEntry(
        canonical_name="integrity_critical",
        group=2,
        attrs={"_wardline_integrity_critical": bool},  # type: ignore[arg-type]  # __post_init__ converts
    ),
    # --- Group 3: Plugin ---
    "system_plugin": _bool_entry("system_plugin", 3),
    # --- Group 4: Internal Data Provenance ---
    "int_data": _bool_entry("int_data", 4),
    # --- Group 5: Schema ---
    "all_fields_mapped": RegistryEntry(
        canonical_name="all_fields_mapped",
        group=5,
        attrs={  # type: ignore[arg-type]  # __post_init__ converts
            "_wardline_all_fields_mapped": bool,
            "_wardline_source": object,  # str | None — object allows both
        },
    ),
    "output_schema": _bool_entry("output_schema", 5),
    # --- Group 6: Boundaries ---
    "trust_boundary": _bool_entry("trust_boundary", 6),
    "tier_transition": _bool_entry("tier_transition", 6),
    # --- Group 7: Template Safety ---
    "parse_at_init": _bool_entry("parse_at_init", 7),
    # --- Group 8: Secrets ---
    "handles_secrets": _bool_entry("handles_secrets", 8),
    # --- Group 9: Operations ---
    "idempotent": _bool_entry("idempotent", 9),
    "atomic": _bool_entry("atomic", 9),
    "compensatable": RegistryEntry(
        canonical_name="compensatable",
        group=9,
        attrs={  # type: ignore[arg-type]  # __post_init__ converts
            "_wardline_compensatable": bool,
            "_wardline_rollback": object,
        },
    ),
    # --- Group 10: Failure Mode ---
    "fail_closed": _bool_entry("fail_closed", 10),
    "fail_open": _bool_entry("fail_open", 10),
    "emits_or_explains": _bool_entry("emits_or_explains", 10),
    "exception_boundary": _bool_entry("exception_boundary", 10),
    "must_propagate": _bool_entry("must_propagate", 10),
    "preserve_cause": _bool_entry("preserve_cause", 10),
    # --- Group 11: Data Sensitivity ---
    "handles_pii": RegistryEntry(
        canonical_name="handles_pii",
        group=11,
        attrs={  # type: ignore[arg-type]  # __post_init__ converts
            "_wardline_handles_pii": bool,
            "_wardline_pii_fields": tuple,
        },
    ),
    "handles_classified": RegistryEntry(
        canonical_name="handles_classified",
        group=11,
        attrs={  # type: ignore[arg-type]  # __post_init__ converts
            "_wardline_handles_classified": bool,
            "_wardline_classification_level": str,
        },
    ),
    "declassifies": RegistryEntry(
        canonical_name="declassifies",
        group=11,
        attrs={  # type: ignore[arg-type]  # __post_init__ converts
            "_wardline_declassifies": bool,
            "_wardline_from_level": str,
            "_wardline_to_level": str,
        },
    ),
    # --- Group 12: Determinism ---
    "deterministic": _bool_entry("deterministic", 12),
    "time_dependent": _bool_entry("time_dependent", 12),
    # --- Group 13: Concurrency ---
    "thread_safe": _bool_entry("thread_safe", 13),
    "ordered_after": RegistryEntry(
        canonical_name="ordered_after",
        group=13,
        attrs={  # type: ignore[arg-type]  # __post_init__ converts
            "_wardline_ordered_after": str,
        },
    ),
    "not_reentrant": _bool_entry("not_reentrant", 13),
    # --- Group 14: Access ---
    "requires_identity": _bool_entry("requires_identity", 14),
    "privileged_operation": _bool_entry("privileged_operation", 14),
    # --- Group 15: Lifecycle ---
    "test_only": _bool_entry("test_only", 15),
    "deprecated_by": RegistryEntry(
        canonical_name="deprecated_by",
        group=15,
        attrs={  # type: ignore[arg-type]  # __post_init__ converts
            "_wardline_deprecated_by": bool,
            "_wardline_deprecation_date": str,
            "_wardline_replacement": str,
        },
    ),
    "feature_gated": RegistryEntry(
        canonical_name="feature_gated",
        group=15,
        attrs={  # type: ignore[arg-type]  # __post_init__ converts
            "_wardline_feature_gated": bool,
            "_wardline_feature_flag": str,
        },
    ),
    # --- Group 16: Data Flow Annotations ---
    "data_flow": RegistryEntry(
        canonical_name="data_flow",
        group=16,
        attrs={  # type: ignore[arg-type]  # __post_init__ converts
            "_wardline_data_flow": bool,
            "_wardline_consumes": int,
            "_wardline_produces": int,
        },
    ),
    # --- Group 17: Restoration Boundaries ---
    "restoration_boundary": RegistryEntry(
        canonical_name="restoration_boundary",
        group=17,
        attrs={  # type: ignore[arg-type]  # __post_init__ converts
            "_wardline_restoration_boundary": bool,
            "_wardline_restored_tier": int,
            "_wardline_structural_evidence": bool,
            "_wardline_semantic_evidence": bool,
            "_wardline_integrity_evidence": object,
            "_wardline_institutional_provenance": object,
        },
    ),
})

# Import-time consistency: verify each key matches its entry's canonical_name.
_mismatched = {
    k for k, v in REGISTRY.items() if k != v.canonical_name
}
if _mismatched:
    raise ValueError(
        f"REGISTRY key/canonical_name mismatch: {sorted(_mismatched)}"
    )
del _mismatched
