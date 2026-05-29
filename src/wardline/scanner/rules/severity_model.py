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
    return Severity.NONE  # freedom / fail-closed zone — suppressed
