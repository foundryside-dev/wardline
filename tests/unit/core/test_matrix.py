"""Tests for severity matrix — independently encoded fixture.

IMPORTANT: This test file MUST NOT import from wardline.core.matrix.
The expected values are encoded independently to catch errors in the
matrix definition itself. The CI check verifies this constraint.
"""

import pytest

# Deliberately import only the enums, NOT the matrix module
from wardline.core.severity import Exceptionability, RuleId, Severity
from wardline.core.taints import TaintState

E = Severity.ERROR
W = Severity.WARNING
Su = Severity.SUPPRESS

U = Exceptionability.UNCONDITIONAL
St = Exceptionability.STANDARD
R = Exceptionability.RELAXED
T = Exceptionability.TRANSPARENT

# Independent fixture: (rule, taint, expected_severity, expected_exceptionability)
# Encoded directly from spec §7.3 table, NOT copied from matrix.py
# fmt: off
EXPECTED: list[tuple[RuleId, TaintState, Severity, Exceptionability]] = [
    # PY-WL-001 (dict key access with fallback default) — inherits WL-001
    (RuleId.PY_WL_001, TaintState.INTEGRAL, E, U),
    (RuleId.PY_WL_001, TaintState.ASSURED, E, St),
    (RuleId.PY_WL_001, TaintState.GUARDED, W, R),
    (RuleId.PY_WL_001, TaintState.EXTERNAL_RAW, Su, T),
    (RuleId.PY_WL_001, TaintState.UNKNOWN_RAW, Su, T),
    (RuleId.PY_WL_001, TaintState.UNKNOWN_GUARDED, W, R),
    (RuleId.PY_WL_001, TaintState.UNKNOWN_ASSURED, E, St),
    (RuleId.PY_WL_001, TaintState.MIXED_RAW, Su, T),

    # PY-WL-002 (attribute access with fallback default) — inherits WL-001
    (RuleId.PY_WL_002, TaintState.INTEGRAL, E, U),
    (RuleId.PY_WL_002, TaintState.ASSURED, E, St),
    (RuleId.PY_WL_002, TaintState.GUARDED, W, R),
    (RuleId.PY_WL_002, TaintState.EXTERNAL_RAW, W, R),
    (RuleId.PY_WL_002, TaintState.UNKNOWN_RAW, W, R),
    (RuleId.PY_WL_002, TaintState.UNKNOWN_GUARDED, W, R),
    (RuleId.PY_WL_002, TaintState.UNKNOWN_ASSURED, E, St),
    (RuleId.PY_WL_002, TaintState.MIXED_RAW, W, St),

    # PY-WL-003 = WL-002 (existence-checking as structural gate)
    (RuleId.PY_WL_003, TaintState.INTEGRAL, E, U),
    (RuleId.PY_WL_003, TaintState.ASSURED, E, U),
    (RuleId.PY_WL_003, TaintState.GUARDED, E, St),
    (RuleId.PY_WL_003, TaintState.EXTERNAL_RAW, Su, T),
    (RuleId.PY_WL_003, TaintState.UNKNOWN_RAW, Su, T),
    (RuleId.PY_WL_003, TaintState.UNKNOWN_GUARDED, E, St),
    (RuleId.PY_WL_003, TaintState.UNKNOWN_ASSURED, E, St),
    (RuleId.PY_WL_003, TaintState.MIXED_RAW, Su, T),

    # PY-WL-004 = WL-003 (catching all exceptions broadly)
    (RuleId.PY_WL_004, TaintState.INTEGRAL, E, U),
    (RuleId.PY_WL_004, TaintState.ASSURED, E, St),
    (RuleId.PY_WL_004, TaintState.GUARDED, W, St),
    (RuleId.PY_WL_004, TaintState.EXTERNAL_RAW, W, R),
    (RuleId.PY_WL_004, TaintState.UNKNOWN_RAW, E, St),
    (RuleId.PY_WL_004, TaintState.UNKNOWN_GUARDED, W, St),
    (RuleId.PY_WL_004, TaintState.UNKNOWN_ASSURED, W, St),
    (RuleId.PY_WL_004, TaintState.MIXED_RAW, E, St),

    # PY-WL-005 = WL-004 (catching exceptions silently)
    (RuleId.PY_WL_005, TaintState.INTEGRAL, E, U),
    (RuleId.PY_WL_005, TaintState.ASSURED, E, St),
    (RuleId.PY_WL_005, TaintState.GUARDED, W, St),
    (RuleId.PY_WL_005, TaintState.EXTERNAL_RAW, W, R),
    (RuleId.PY_WL_005, TaintState.UNKNOWN_RAW, E, St),
    (RuleId.PY_WL_005, TaintState.UNKNOWN_GUARDED, W, St),
    (RuleId.PY_WL_005, TaintState.UNKNOWN_ASSURED, W, St),
    (RuleId.PY_WL_005, TaintState.MIXED_RAW, E, St),

    # PY-WL-006 = WL-005 (audit-critical writes in broad handlers)
    (RuleId.PY_WL_006, TaintState.INTEGRAL, E, U),
    (RuleId.PY_WL_006, TaintState.ASSURED, E, U),
    (RuleId.PY_WL_006, TaintState.GUARDED, E, St),
    (RuleId.PY_WL_006, TaintState.EXTERNAL_RAW, E, St),
    (RuleId.PY_WL_006, TaintState.UNKNOWN_RAW, E, St),
    (RuleId.PY_WL_006, TaintState.UNKNOWN_GUARDED, E, St),
    (RuleId.PY_WL_006, TaintState.UNKNOWN_ASSURED, E, St),
    (RuleId.PY_WL_006, TaintState.MIXED_RAW, E, St),

    # PY-WL-007 = WL-006 (runtime type-checking internal data)
    (RuleId.PY_WL_007, TaintState.INTEGRAL, E, St),
    (RuleId.PY_WL_007, TaintState.ASSURED, W, R),
    (RuleId.PY_WL_007, TaintState.GUARDED, W, R),
    (RuleId.PY_WL_007, TaintState.EXTERNAL_RAW, Su, T),
    (RuleId.PY_WL_007, TaintState.UNKNOWN_RAW, Su, T),
    (RuleId.PY_WL_007, TaintState.UNKNOWN_GUARDED, W, R),
    (RuleId.PY_WL_007, TaintState.UNKNOWN_ASSURED, W, R),
    (RuleId.PY_WL_007, TaintState.MIXED_RAW, W, St),

    # PY-WL-008 = WL-007 (validation with no rejection path)
    (RuleId.PY_WL_008, TaintState.INTEGRAL, E, U),
    (RuleId.PY_WL_008, TaintState.ASSURED, E, U),
    (RuleId.PY_WL_008, TaintState.GUARDED, E, U),
    (RuleId.PY_WL_008, TaintState.EXTERNAL_RAW, E, U),
    (RuleId.PY_WL_008, TaintState.UNKNOWN_RAW, E, U),
    (RuleId.PY_WL_008, TaintState.UNKNOWN_GUARDED, E, U),
    (RuleId.PY_WL_008, TaintState.UNKNOWN_ASSURED, E, U),
    (RuleId.PY_WL_008, TaintState.MIXED_RAW, E, U),

    # PY-WL-009 = WL-008 (semantic validation without shape validation)
    (RuleId.PY_WL_009, TaintState.INTEGRAL, E, U),
    (RuleId.PY_WL_009, TaintState.ASSURED, E, U),
    (RuleId.PY_WL_009, TaintState.GUARDED, E, U),
    (RuleId.PY_WL_009, TaintState.EXTERNAL_RAW, E, U),
    (RuleId.PY_WL_009, TaintState.UNKNOWN_RAW, E, U),
    (RuleId.PY_WL_009, TaintState.UNKNOWN_GUARDED, E, U),
    (RuleId.PY_WL_009, TaintState.UNKNOWN_ASSURED, E, U),
    (RuleId.PY_WL_009, TaintState.MIXED_RAW, E, U),
]
# fmt: on


def test_fixture_has_72_cells() -> None:
    assert len(EXPECTED) == 72


@pytest.mark.parametrize(
    ("rule", "taint", "exp_sev", "exp_exc"),
    EXPECTED,
    ids=lambda x: x.value if hasattr(x, "value") else str(x),
)
def test_matrix_cell(
    rule: RuleId,
    taint: TaintState,
    exp_sev: Severity,
    exp_exc: Exceptionability,
) -> None:
    # Import here to keep the fixture independent at module level
    from wardline.core.matrix import lookup

    cell = lookup(rule, taint)
    assert cell.severity is exp_sev, (
        f"{rule}×{taint}: expected severity {exp_sev}, got {cell.severity}"
    )
    assert cell.exceptionability is exp_exc, (
        f"{rule}×{taint}: expected exceptionability {exp_exc}, "
        f"got {cell.exceptionability}"
    )


def test_lookup_raises_on_invalid_combo() -> None:
    from wardline.core.matrix import lookup

    with pytest.raises(KeyError):
        lookup(RuleId.TOOL_ERROR, TaintState.INTEGRAL)


def test_severity_matrix_is_immutable() -> None:
    """SEVERITY_MATRIX must be a MappingProxyType — mutation raises TypeError."""
    from types import MappingProxyType

    from wardline.core.matrix import SEVERITY_MATRIX

    assert isinstance(SEVERITY_MATRIX, MappingProxyType)
    with pytest.raises(TypeError):
        SEVERITY_MATRIX[(RuleId.PY_WL_001, TaintState.INTEGRAL)] = None  # type: ignore[index]


# Canonical analysis rules (those with matrix entries)
_CANONICAL_RULES = [
    RuleId.PY_WL_001, RuleId.PY_WL_002, RuleId.PY_WL_003,
    RuleId.PY_WL_004, RuleId.PY_WL_005, RuleId.PY_WL_006,
    RuleId.PY_WL_007, RuleId.PY_WL_008, RuleId.PY_WL_009,
]


# --- Bug fix: matrix well-formedness (wardline-dcb29c1) ---


def test_every_canonical_pair_has_entry() -> None:
    """Every (RuleId, TaintState) canonical pair must have a matrix entry."""
    from wardline.core.matrix import SEVERITY_MATRIX

    for rule in _CANONICAL_RULES:
        for taint in TaintState:
            assert (rule, taint) in SEVERITY_MATRIX, (
                f"Missing matrix entry for ({rule}, {taint})"
            )


def test_every_cell_has_valid_severity_and_exceptionability() -> None:
    """Every cell must contain valid Severity and Exceptionability values."""
    from wardline.core.matrix import SEVERITY_MATRIX, SeverityCell

    for (rule, taint), cell in SEVERITY_MATRIX.items():
        assert isinstance(cell, SeverityCell), (
            f"({rule}, {taint}): cell is not a SeverityCell"
        )
        assert isinstance(cell.severity, Severity), (
            f"({rule}, {taint}): severity {cell.severity!r} is not a Severity"
        )
        assert isinstance(cell.exceptionability, Exceptionability), (
            f"({rule}, {taint}): exceptionability {cell.exceptionability!r} "
            f"is not an Exceptionability"
        )


def test_no_duplicate_keys() -> None:
    """Matrix must not have duplicate (rule, taint) keys."""
    from wardline.core.matrix import SEVERITY_MATRIX

    keys = list(SEVERITY_MATRIX.keys())
    assert len(keys) == len(set(keys)), "Duplicate keys found in SEVERITY_MATRIX"


def test_no_matrix_import_at_module_level() -> None:
    """Verify this test file does not import from wardline.core.matrix at module level."""
    import ast
    from pathlib import Path

    source = Path(__file__).read_text()
    tree = ast.parse(source)
    # Check only top-level statements, not function bodies
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module:
            assert "matrix" not in node.module, (
                f"Module-level import of matrix found: {ast.dump(node)}"
            )


# --- Split-rule deviation documentation (§7.1) ---
# PY-WL-002 establishes its own matrix row per §7.1.
# These cells intentionally differ from WL-001's framework matrix.
# See ADR-003 for rationale.
SPLIT_RULE_DEVIATIONS: list[tuple[RuleId, TaintState, Severity, Exceptionability, str]] = [
    (RuleId.PY_WL_002, TaintState.EXTERNAL_RAW, W, R, "falsy-substitution risk (ADR-003)"),
    (RuleId.PY_WL_002, TaintState.UNKNOWN_RAW, W, R, "falsy-substitution risk (ADR-003)"),
    (RuleId.PY_WL_002, TaintState.MIXED_RAW, W, St, "falsy-substitution risk (ADR-003)"),
]


@pytest.mark.parametrize(
    "rule, taint, expected_sev, expected_exc, rationale",
    SPLIT_RULE_DEVIATIONS,
    ids=[f"{r.name}-{t.name}" for r, t, _, _, _ in SPLIT_RULE_DEVIATIONS],
)
def test_split_rule_deviation_is_documented(
    rule: RuleId,
    taint: TaintState,
    expected_sev: Severity,
    expected_exc: Exceptionability,
    rationale: str,
) -> None:
    """Split-rule deviations from framework matrix are intentional and documented."""
    from wardline.core.matrix import SEVERITY_MATRIX

    cell = SEVERITY_MATRIX[(rule, taint)]
    assert cell.severity == expected_sev, f"Deviation {rule}×{taint}: {rationale}"
    assert cell.exceptionability == expected_exc, f"Deviation {rule}×{taint}: {rationale}"
