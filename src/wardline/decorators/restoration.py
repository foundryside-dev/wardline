"""Group 17 decorator — restoration boundaries (§6.3).

Restoration boundaries govern the act by which raw serialised
representations may be restored to a tier supported by available
evidence. Distinct from Group 4 (int_data), which declares
provenance-sensitive data sources.

Restoration boundaries do NOT stamp runtime output tier — taint
assignment is scanner-only via max_restorable_tier(). The
_compute_output_tier() path returns None for this decorator because
it has no _wardline_transition or _wardline_tier_source.
"""

from __future__ import annotations

from wardline.decorators._base import wardline_decorator

__all__ = ["restoration_boundary"]

# Enumerated vocabulary for institutional_provenance values.
VALID_INSTITUTIONAL_PROVENANCE: frozenset[str] = frozenset({
    "org-db",
    "partner-api",
    "government-registry",
    "internal-authority",
    "contractual-sla",
})


def restoration_boundary(
    *,
    restored_tier: int,
    structural_evidence: bool = False,
    semantic_evidence: bool = False,
    integrity_evidence: str | None = None,
    institutional_provenance: str | None = None,
) -> object:
    """Mark a function as a restoration boundary (Group 17, §6.3).

    Args:
        restored_tier: The tier this restoration claims to achieve (1-4).
        structural_evidence: Whether shape validation is performed.
        semantic_evidence: Whether domain constraint checking is performed.
        integrity_evidence: Integrity mechanism name ("checksum", "signature",
            "hmac") or None if absent.
        institutional_provenance: Institutional attestation string from the
            enumerated vocabulary (``VALID_INSTITUTIONAL_PROVENANCE``), or None.
    """
    if restored_tier not in range(1, 5):
        raise ValueError(f"restored_tier must be 1-4, got {restored_tier}")
    if institutional_provenance is not None and institutional_provenance not in VALID_INSTITUTIONAL_PROVENANCE:
        raise ValueError(
            f"institutional_provenance must be one of "
            f"{sorted(VALID_INSTITUTIONAL_PROVENANCE)}, got {institutional_provenance!r}"
        )
    return wardline_decorator(
        17,
        "restoration_boundary",
        _wardline_restoration_boundary=True,
        _wardline_restored_tier=restored_tier,
        _wardline_structural_evidence=structural_evidence,
        _wardline_semantic_evidence=semantic_evidence,
        _wardline_integrity_evidence=integrity_evidence,
        _wardline_institutional_provenance=institutional_provenance,
    )
