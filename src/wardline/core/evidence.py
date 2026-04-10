"""§6.3 evidence-to-tier matrix — pure domain function."""

from __future__ import annotations

from wardline.core.taints import TaintState


def max_restorable_tier(
    structural: bool,
    semantic: bool,
    integrity: bool,
    institutional: bool,
) -> TaintState:
    """Return the maximum tier evidence supports per §6.3.

    The caller coerces string evidence values to bool before calling:
    ``integrity_evidence="hmac"`` → ``integrity=True``,
    ``integrity_evidence=None`` → ``integrity=False``.

    Institutional evidence is the gate between known-provenance tiers
    (T1–T3) and unknown-provenance states (UNKNOWN_*).
    """
    if not structural:
        return TaintState.UNKNOWN_RAW
    if not institutional:
        if semantic:
            return TaintState.UNKNOWN_ASSURED
        return TaintState.UNKNOWN_GUARDED
    # institutional is True from here
    if semantic and integrity:
        return TaintState.INTEGRAL  # Tier 1
    if semantic:
        return TaintState.ASSURED  # Tier 2
    return TaintState.GUARDED  # Tier 3
