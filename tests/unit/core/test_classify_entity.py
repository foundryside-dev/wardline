# tests/unit/core/test_classify_entity.py
"""Focused tests for the shared ``classify_entity_trust`` classifier.

This function is the single source of truth for per-entity verdict computation
(defect / clean / unknown).  The dossier's ``_build_trust`` delegates to it;
a later ``assure`` coverage report will call it directly — "identical by
construction" means both surfaces compute the same verdict.

The tests build minimal on-disk trees via ``run_scan`` so the classifier sees
real taint results, not mocked mappings.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from wardline.core.dossier import classify_entity_trust
from wardline.core.run import run_scan

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# A @trusted producer that returns a constant — always clean.
_CLEAN_SRC = """\
from wardline.decorators import trusted

@trusted(level='INTEGRAL')
def always_one() -> int:
    return 1
"""

# A @trusted producer that leaks an @external_boundary value through a
# mid function — L3 traces the taint; PY-WL-101 fires on ``leaky``.
# (Same pattern as test_dossier_assembler._LEAKY.)
_DEFECT_SRC = """\
from wardline.decorators import external_boundary, trusted

@external_boundary
def read_raw(p):
    return p

def mid(p):
    return read_raw(p)

@trusted(level='INTEGRAL')
def leaky(p):
    return mid(p)
"""

# Completely undecorated module — all functions live in the developer-freedom
# zone (engine infers UNKNOWN_*), so their verdict must be "unknown".
_UNDECORATED_SRC = """\
def plain(x: int) -> int:
    return x + 1
"""


def _proj(tmp_path: Path, name: str, src: str) -> Path:
    proj = tmp_path / name
    proj.mkdir()
    (proj / "m.py").write_text(src, encoding="utf-8")
    return proj


# ---------------------------------------------------------------------------
# Verdict: "clean"
# ---------------------------------------------------------------------------


def test_clean_integral_function_verdict(tmp_path: Path) -> None:
    proj = _proj(tmp_path, "clean", _CLEAN_SRC)
    result = run_scan(proj)
    assert result.context is not None
    etv = classify_entity_trust(result, result.context, "m.always_one")
    assert etv.verdict == "clean"


def test_clean_entity_declared_tier(tmp_path: Path) -> None:
    proj = _proj(tmp_path, "clean_tier", _CLEAN_SRC)
    result = run_scan(proj)
    assert result.context is not None
    etv = classify_entity_trust(result, result.context, "m.always_one")
    assert etv.declared_tier == "INTEGRAL"


def test_clean_entity_actual_tier_is_populated(tmp_path: Path) -> None:
    proj = _proj(tmp_path, "clean_actual", _CLEAN_SRC)
    result = run_scan(proj)
    assert result.context is not None
    etv = classify_entity_trust(result, result.context, "m.always_one")
    assert etv.actual_tier is not None


def test_clean_entity_no_under_scan_reason(tmp_path: Path) -> None:
    proj = _proj(tmp_path, "clean_noscan", _CLEAN_SRC)
    result = run_scan(proj)
    assert result.context is not None
    etv = classify_entity_trust(result, result.context, "m.always_one")
    assert etv.under_scan_reason is None


# ---------------------------------------------------------------------------
# Verdict: "defect"
# ---------------------------------------------------------------------------


def test_defect_function_verdict(tmp_path: Path) -> None:
    """PY-WL-101 fires on ``leaky`` (leaks an external-boundary value)."""
    proj = _proj(tmp_path, "defect", _DEFECT_SRC)
    result = run_scan(proj)
    assert result.context is not None
    etv = classify_entity_trust(result, result.context, "m.leaky")
    assert etv.verdict == "defect"


def test_defect_entity_declared_tier(tmp_path: Path) -> None:
    proj = _proj(tmp_path, "defect_tier", _DEFECT_SRC)
    result = run_scan(proj)
    assert result.context is not None
    etv = classify_entity_trust(result, result.context, "m.leaky")
    assert etv.declared_tier == "INTEGRAL"


# ---------------------------------------------------------------------------
# Verdict: "unknown"
# ---------------------------------------------------------------------------


def test_undecorated_function_is_unknown_not_clean(tmp_path: Path) -> None:
    """Fail-closed: undeclared code is never "clean"."""
    proj = _proj(tmp_path, "undec", _UNDECORATED_SRC)
    result = run_scan(proj)
    assert result.context is not None
    etv = classify_entity_trust(result, result.context, "m.plain")
    assert etv.verdict == "unknown"


def test_undecorated_function_declared_tier_is_in_unknown_tiers(tmp_path: Path) -> None:
    """Engine infers UNKNOWN_* for undeclared functions — declared_tier reflects that."""
    from wardline.core.dossier import UNKNOWN_TIERS

    proj = _proj(tmp_path, "undec_tier", _UNDECORATED_SRC)
    result = run_scan(proj)
    assert result.context is not None
    etv = classify_entity_trust(result, result.context, "m.plain")
    # The engine populates project_return_taints even for undeclared functions,
    # using an UNKNOWN_* inferred tier — that is not a declared posture and
    # classify_entity_trust correctly returns "unknown", not "clean".
    assert etv.declared_tier is None or etv.declared_tier in UNKNOWN_TIERS


# ---------------------------------------------------------------------------
# Return type is the frozen dataclass
# ---------------------------------------------------------------------------


def test_return_is_frozen(tmp_path: Path) -> None:
    proj = _proj(tmp_path, "frozen", _CLEAN_SRC)
    result = run_scan(proj)
    assert result.context is not None
    etv = classify_entity_trust(result, result.context, "m.always_one")
    with pytest.raises((AttributeError, TypeError)):
        etv.verdict = "tampered"  # type: ignore[misc]
