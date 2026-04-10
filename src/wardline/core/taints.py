"""Taint state model — 8 canonical taint state tokens and join lattice."""

from __future__ import annotations

from enum import StrEnum


class TaintState(StrEnum):
    """Canonical taint states per spec §5.

    Values are explicit uppercase strings — do NOT use auto() which
    produces lowercase and would silently break SARIF output, matrix
    lookups, and corpus matching.
    """

    INTEGRAL = "INTEGRAL"
    ASSURED = "ASSURED"
    GUARDED = "GUARDED"
    EXTERNAL_RAW = "EXTERNAL_RAW"
    UNKNOWN_RAW = "UNKNOWN_RAW"
    UNKNOWN_GUARDED = "UNKNOWN_GUARDED"
    UNKNOWN_ASSURED = "UNKNOWN_ASSURED"
    MIXED_RAW = "MIXED_RAW"


# Taint context vocabulary — authoritative reference from spec §3.
# Maps taint state name → (function_suffix, variable_name) for code generation.
TAINT_CONTEXT: dict[str, tuple[str, str]] = {
    "INTEGRAL": ("system_config", "sys_config"),
    "ASSURED": ("verified_payload", "verified_payload"),
    "GUARDED": ("session_data", "session_data"),
    "UNKNOWN_ASSURED": ("claimed_token", "claimed_token"),
    "UNKNOWN_GUARDED": ("cached_profile", "cached_profile"),
    "UNKNOWN_RAW": ("unknown_input", "unknown_input"),
    "EXTERNAL_RAW": ("request_param", "request_param"),
    "MIXED_RAW": ("mixed_source", "mixed_source"),
}


# Non-trivial join pairs (upper triangle, excluding self-joins).
# Self-joins are handled via identity check: join(a, a) == a.
# Operand order is normalised for lookup: min(a, b), max(a, b) by value.
# All pairs not listed here produce MIXED_RAW.
_UR = TaintState.UNKNOWN_RAW
_USH = TaintState.UNKNOWN_GUARDED
_USE = TaintState.UNKNOWN_ASSURED

_JOIN_TABLE: dict[tuple[TaintState, TaintState], TaintState] = {
    # Within UNKNOWN family: demote to weaker validation.
    # Keys MUST be in normalized order (sorted by .value string) to match
    # the lookup normalization in taint_join().
    (_USE, _UR): _UR,
    (_USH, _UR): _UR,
    (_USE, _USH): _USH,
}


def taint_join(a: TaintState, b: TaintState) -> TaintState:
    """Compute the join of two taint states per spec §5.

    The join is commutative: join(a, b) == join(b, a).
    MIXED_RAW is the absorbing element: join(MIXED_RAW, X) == MIXED_RAW for all X.
    Self-joins are identity: join(a, a) == a.
    """
    if a == b:
        return a

    if a == TaintState.MIXED_RAW or b == TaintState.MIXED_RAW:
        return TaintState.MIXED_RAW

    # Normalise order for lookup (by string value for determinism)
    key = (min(a, b, key=lambda x: x.value), max(a, b, key=lambda x: x.value))
    if key in _JOIN_TABLE:
        return _JOIN_TABLE[key]
    # Pairs not in the join table collapse to the absorbing element.
    return TaintState.MIXED_RAW
