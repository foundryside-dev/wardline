"""Severity matrix — 72 cells mapping (rule, taint) to (severity, exceptionability).

The matrix encodes a single principle: **rules protect the integrity of
high-tier code paths, not the hygiene of low-tier code.**

Tier 4 (EXTERNAL_RAW) is the developer-freedom zone.  Python idioms like
``dict.get()``, ``getattr()``, ``hasattr()``, and ``key in dict`` are
expected and correct there.  The language permits these patterns for valid
reasons — the tier system carves out the code paths where they are not
permitted.

Severity scales with the *consequence* of the pattern at that tier:

- **T1 (INTEGRAL/INTEGRAL):** ERROR or UNCONDITIONAL — fabricated
  defaults or unchecked structure in authoritative code undermines the
  guarantees that tier exists to provide.
- **T2 (ASSURED/ASSURED):** ERROR/STANDARD — validated data should not
  need fallback defaults; if it does, that's suspicious but exceptionable.
- **T3 (GUARDED/GUARDED):** WARNING is the default — partially validated
  data may legitimately use defensive access; flag for review, don't block.
  Exceptions: PY-WL-003 (existence-checking), PY-WL-006 (audit-critical
  writes), PY-WL-008 (no rejection path), and PY-WL-009 (semantic without
  shape) are ERROR at T3 — these patterns are suspicious or unsafe
  regardless of partial validation.
- **T4 (EXTERNAL_RAW):** SUPPRESS or WARNING — this IS boundary code;
  the enforcement happens when data crosses upward, not at the access site.

A ``.get("timeout", 30)`` in CLI parsing is fine.  That same value reaching
a T1 decision path without passing through a validation boundary is the
violation — and the boundary transition rules (PY-WL-008, PY-WL-009) catch
that at the crossing point.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.core.taints import TaintState

_E = Severity.ERROR
_W = Severity.WARNING
_Su = Severity.SUPPRESS

_U = Exceptionability.UNCONDITIONAL
_St = Exceptionability.STANDARD
_R = Exceptionability.RELAXED
_T = Exceptionability.TRANSPARENT


@dataclass(frozen=True)
class SeverityCell:
    """A single cell in the severity matrix."""

    severity: Severity
    exceptionability: Exceptionability


# Column order matches spec §8.3:
# INTEGRAL, ASSURED, GUARDED, EXTERNAL_RAW,
# UNKNOWN_RAW, UNKNOWN_GUARDED, UNKNOWN_ASSURED, MIXED_RAW
_TAINT_ORDER = [
    TaintState.INTEGRAL,
    TaintState.ASSURED,
    TaintState.GUARDED,
    TaintState.EXTERNAL_RAW,
    TaintState.UNKNOWN_RAW,
    TaintState.UNKNOWN_GUARDED,
    TaintState.UNKNOWN_ASSURED,
    TaintState.MIXED_RAW,
]

# fmt: off
#
# Design intent — §8.5 calibration principle:
#
#   These boundaries exist because the language permits these patterns for
#   valid reasons.  The tier system carves out code paths where those patterns
#   are not permitted.
#
#   Rules protect the integrity of high-tier code paths, not the hygiene of
#   low-tier code.  T4 (EXTERNAL_RAW) is the developer-freedom zone — any
#   Python idiom is fine there.  Enforcement activates when data crosses a
#   boundary upward.  A .get("timeout", 30) in CLI parsing is fine; that
#   value reaching a T1 decision path without validation is the violation.
#
#   Severity scales with the CONSEQUENCE of the pattern at that tier, not
#   with the mere presence of the pattern.  SUPPRESS at T4 means "this
#   pattern is expected here"; ERROR at T1 means "this pattern undermines
#   the guarantees this tier exists to provide."
#
# Row data: (rule, [(severity, exceptionability) for each taint state])
_MATRIX_DATA: list[tuple[RuleId, list[tuple[Severity, Exceptionability]]]] = [
    # PY-WL-001 (dict key access with fallback default)
    # T1/T2: ERROR — fabricated defaults in authoritative/validated code undermine integrity
    # T3: WARNING — partially validated; flag for review but don't block
    # T4: SUPPRESS — boundary code legitimately uses .get() for optional config/input
    (RuleId.PY_WL_001, [(_E,_U), (_E,_St), (_W,_R), (_Su,_T), (_Su,_T), (_W,_R), (_E,_St), (_Su,_T)]),
    # PY-WL-002 (attribute access with fallback default)
    # Same gradient as PY-WL-001; T4 stays WARNING (not SUPPRESS) because
    # obj.attr-or-default has a falsy-substitution risk even at boundaries
    (RuleId.PY_WL_002, [(_E,_U), (_E,_St), (_W,_R), (_W,_R),  (_W,_R),  (_W,_R), (_E,_St), (_W,_St)]),
    # PY-WL-003 (existence-checking as structural gate)
    # T1/T2: ERROR — validated data should have known structure
    # T3: ERROR/STANDARD — existence checks in partially-validated code are suspicious
    #      (was UNCONDITIONAL; changed to STANDARD so exceptions are possible)
    # T4: SUPPRESS — existence-checking IS the validation mechanism at boundaries
    (RuleId.PY_WL_003, [(_E,_U), (_E,_U), (_E,_St), (_Su,_T), (_Su,_T), (_E,_St), (_E,_St), (_Su,_T)]),
    # PY-WL-004 = WL-003 (catching all exceptions broadly)
    (RuleId.PY_WL_004, [(_E,_U), (_E,_St), (_W,_St), (_W,_R), (_E,_St), (_W,_St), (_W,_St), (_E,_St)]),
    # PY-WL-005 = WL-004 (catching exceptions silently)
    # T1/T2: ERROR — silent catch in trusted code destroys diagnostic evidence
    # T3: WARNING — partially validated; flag for review
    # T4: WARNING/RELAXED — boundary code may legitimately suppress parse errors
    (RuleId.PY_WL_005, [(_E,_U), (_E,_St), (_W,_St), (_W,_R), (_E,_St), (_W,_St), (_W,_St), (_E,_St)]),
    # PY-WL-006 = WL-005 (audit-critical writes in broad handlers)
    (RuleId.PY_WL_006, [(_E,_U), (_E,_U), (_E,_St), (_E,_St), (_E,_St), (_E,_St), (_E,_St), (_E,_St)]),
    # PY-WL-007 = WL-006 (runtime type-checking internal data)
    (RuleId.PY_WL_007, [(_E,_St), (_W,_R), (_W,_R), (_Su,_T), (_Su,_T), (_W,_R), (_W,_R), (_W,_St)]),
    # PY-WL-008 = WL-007 (validation with no rejection path)
    (RuleId.PY_WL_008, [(_E,_U), (_E,_U), (_E,_U), (_E,_U), (_E,_U), (_E,_U), (_E,_U), (_E,_U)]),
    # PY-WL-009 = WL-008 (semantic validation without shape validation)
    (RuleId.PY_WL_009, [(_E,_U), (_E,_U), (_E,_U), (_E,_U), (_E,_U), (_E,_U), (_E,_U), (_E,_U)]),
]
# fmt: on

_severity_matrix_builder: dict[tuple[RuleId, TaintState], SeverityCell] = {}
for _rule, _cells in _MATRIX_DATA:
    for _taint, (_sev, _exc) in zip(_TAINT_ORDER, _cells, strict=True):
        _severity_matrix_builder[(_rule, _taint)] = SeverityCell(
            severity=_sev, exceptionability=_exc
        )

# Completeness check: every canonical rule must have all 8 taint entries.
_EXPECTED_RULES = frozenset(r for r, _ in _MATRIX_DATA)
_EXPECTED_COUNT = len(_EXPECTED_RULES) * len(_TAINT_ORDER)
if len(_severity_matrix_builder) != _EXPECTED_COUNT:
    raise ValueError(
        f"Severity matrix incomplete: expected {_EXPECTED_COUNT} cells "
        f"({len(_EXPECTED_RULES)} rules × {len(_TAINT_ORDER)} taints), "
        f"got {len(_severity_matrix_builder)}"
    )
del _EXPECTED_RULES, _EXPECTED_COUNT

SEVERITY_MATRIX: MappingProxyType[tuple[RuleId, TaintState], SeverityCell] = (
    MappingProxyType(_severity_matrix_builder)
)
del _severity_matrix_builder


def has_unconditional_cells(rule: RuleId) -> bool:
    """Return True if *rule* has any UNCONDITIONAL cells in the matrix."""
    return any(
        cell.exceptionability == Exceptionability.UNCONDITIONAL
        for (r, _t), cell in SEVERITY_MATRIX.items()
        if r == rule
    )


def lookup(rule: RuleId, taint: TaintState) -> SeverityCell:
    """Look up the severity cell for a (rule, taint) pair.

    Raises KeyError if the combination is not in the matrix
    (e.g., pseudo-rule-IDs are not analysis rules).
    """
    try:
        return SEVERITY_MATRIX[(rule, taint)]
    except KeyError:
        raise KeyError(
            f"No severity-matrix entry for ({rule!r}, {taint!r}). "
            f"Only canonical analysis rules (PY-WL-001..009) have matrix "
            f"entries — pseudo-rule-IDs and unmapped taint states are not "
            f"in the matrix."
        ) from None
