# src/wardline/scanner/rules/severity_model.py
"""Compact tier-modulation severity model (SP2 §5).

A rule declares a ``base_severity``; ``modulate`` scales it by the function's
resolved taint tier. ``.old``'s 80-cell (rule × taint) matrix in ~10 lines:
trusted tiers keep the base, partial tiers downgrade one step, and the
developer-freedom / fail-closed tiers suppress to ``NONE``. The freedom-zone
suppression is what makes undecorated code (which resolves to ``UNKNOWN_RAW``)
silent — and Wardline self-host clean — under the tier-modulated rules.
"""

from __future__ import annotations

from wardline.core.finding import Severity
from wardline.core.taints import TaintState

_TRUSTED: frozenset[TaintState] = frozenset({TaintState.INTEGRAL, TaintState.ASSURED})
_PARTIAL: frozenset[TaintState] = frozenset(
    {TaintState.GUARDED, TaintState.UNKNOWN_ASSURED, TaintState.UNKNOWN_GUARDED}
)
# _FREEDOM = {EXTERNAL_RAW, UNKNOWN_RAW, MIXED_RAW} — the implicit else branch.
# INVARIANT (taint-combination audit, F1): MIXED_RAW is CURRENTLY UNREACHABLE; no
# sound analysis path produces it (least_trusted is closed over the reachable set
# {INTEGRAL, ASSURED, GUARDED, EXTERNAL_RAW, UNKNOWN_RAW}; F5's parser guards keep
# the trio out of the stdlib table and the disk cache). If it ever became
# reachable, this rule family and PY-WL-101 would DISAGREE: modulate's else branch
# below treats MIXED_RAW as freedom-zone and SUPPRESSES (returns NONE), whereas
# PY-WL-101 would FIRE on it as the ACTUAL return of a @trusted producer
# (body==declared, passing 101's :86-87 trust-raising gate), because at rank 7 it
# is strictly less trusted than any clean declared tier — a rank comparison, NOT
# _RAW_ZONE membership, which gates only the *declared* tier. The 101 firing is
# not unconditional: a MIXED_RAW *body* (the realistic route to a MIXED_RAW actual
# return) trips 101's :86-87 gate and delegates to PY-WL-102 instead. F5's guards
# are what keep that asymmetry latent. See
# docs/decisions/2026-05-31-wardline-taint-lattice-retain.md and
# docs/concepts/taint-algebra.md.

_DOWNGRADE: dict[Severity, Severity] = {
    Severity.CRITICAL: Severity.ERROR,
    Severity.ERROR: Severity.WARN,
    Severity.WARN: Severity.INFO,
    Severity.INFO: Severity.INFO,  # floor — never below INFO via downgrade
    Severity.NONE: Severity.NONE,
}


def modulate(base: Severity, taint: TaintState) -> Severity:
    """Modulate *base* severity by a function's resolved taint tier."""
    if taint in _TRUSTED:
        return base
    if taint in _PARTIAL:
        return _DOWNGRADE[base]
    if taint == TaintState.MIXED_RAW:
        return base
    return Severity.NONE  # freedom / fail-closed zone — suppressed
