# src/wardline/core/taints.py
"""The taint-state lattice: 8 canonical states, their trust ranking, and the
two combination operators. Stdlib-only — no project or third-party imports.

Ported from ``wardline.old``: ``core/taints.py`` (``TaintState`` + ``taint_join``)
and ``scanner/taint/callgraph.py`` (``TRUST_RANK`` + ``least_trusted``). The
SARIF label table and codegen vocabulary (``TAINT_STATE_LABELS``,
``TAINT_CONTEXT``) are intentionally NOT ported — labels arrive with SARIF in
SP4; the codegen map is unused here.
"""

from __future__ import annotations

from enum import StrEnum
from types import MappingProxyType


class TaintState(StrEnum):
    """The 8 canonical taint states.

    Values are explicit uppercase strings (never ``auto()``, which lowercases),
    so serialized findings, cache keys, and conformance fixtures stay stable.
    """

    INTEGRAL = "INTEGRAL"
    ASSURED = "ASSURED"
    GUARDED = "GUARDED"
    EXTERNAL_RAW = "EXTERNAL_RAW"
    UNKNOWN_RAW = "UNKNOWN_RAW"
    UNKNOWN_GUARDED = "UNKNOWN_GUARDED"
    UNKNOWN_ASSURED = "UNKNOWN_ASSURED"
    MIXED_RAW = "MIXED_RAW"


# Trust ordering: 0 = most trusted ... 7 = least trusted / absorbing top.
TRUST_RANK: MappingProxyType[TaintState, int] = MappingProxyType(
    {
        TaintState.INTEGRAL: 0,
        TaintState.ASSURED: 1,
        TaintState.GUARDED: 2,
        TaintState.UNKNOWN_ASSURED: 3,
        TaintState.UNKNOWN_GUARDED: 4,
        TaintState.EXTERNAL_RAW: 5,
        TaintState.UNKNOWN_RAW: 6,
        TaintState.MIXED_RAW: 7,
    }
)


# Non-trivial ``taint_join`` pairs, keys normalized to (min, max) by ``.value``.
# Self-joins are identity; any pair touching MIXED_RAW yields MIXED_RAW; every
# other distinct pair NOT listed here collapses to MIXED_RAW. Within the
# UNKNOWN_* family the join demotes to the weaker validation.
_UR = TaintState.UNKNOWN_RAW
_UG = TaintState.UNKNOWN_GUARDED
_UA = TaintState.UNKNOWN_ASSURED

_JOIN_TABLE: dict[tuple[TaintState, TaintState], TaintState] = {
    (_UA, _UR): _UR,
    (_UG, _UR): _UR,
    (_UA, _UG): _UG,
}


def taint_join(a: TaintState, b: TaintState) -> TaintState:
    """Provenance-combination join (commutative; ``MIXED_RAW`` absorbing).

    Models *provenance compatibility*: combining values within one family
    yields that family's weaker member; combining values of DIFFERENT families
    is a provenance clash and yields ``MIXED_RAW``.

    This is DELIBERATELY NOT the trust-rank meet — see :func:`least_trusted` for
    pure rank demotion. The two operators agree only on self-joins, anything
    touching ``MIXED_RAW``, and within the ``UNKNOWN_*`` family; they diverge on
    every other cross-family pair (e.g. ``taint_join(INTEGRAL, ASSURED)`` is
    ``MIXED_RAW`` whereas ``least_trusted(INTEGRAL, ASSURED)`` is ``ASSURED``).
    Do not "simplify" one into the other.
    """
    if a == b:
        return a
    if a == TaintState.MIXED_RAW or b == TaintState.MIXED_RAW:
        return TaintState.MIXED_RAW
    key = (min(a, b, key=lambda x: x.value), max(a, b, key=lambda x: x.value))
    return _JOIN_TABLE.get(key, TaintState.MIXED_RAW)


def least_trusted(a: TaintState, b: TaintState) -> TaintState:
    """Return the less-trusted (higher ``TRUST_RANK``) of two states.

    Pure rank demotion, used by the L3 fixed-point's monotone propagation
    (non-anchored functions only ever move toward less-trusted). Distinct from
    :func:`taint_join` — see that docstring.
    """
    return a if TRUST_RANK[a] >= TRUST_RANK[b] else b
