"""Pack-bridge acceptance: binding a third-party @trust_boundary vocabulary to wardline.

The generic pack-bridge mechanism (wardline-bd9d1e65cb): rather than asking a project to
re-annotate in wardline's vocabulary, a pack maps its existing
``@trust_boundary(tier=3, source_param=...)`` decorator to a wardline BoundaryType. This
proves the bridge end-to-end on a third-party-shaped target:

  * WITH the pack, every @trust_boundary function is a RECOGNIZED boundary (the scan
    stops being inert) and a boundary that returns raw untrusted data fires an ERROR.
  * WITHOUT the pack, the same code recognizes zero boundaries and fires nothing — the
    inert state that lets a --fail-on gate pass green while checking nothing.
"""

from __future__ import annotations

from pathlib import Path

from grammar.fixtures.thirdparty_trust_boundary_pack import GRAMMAR  # type: ignore[import-not-found]
from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind
from wardline.core.resolution_posture import compute_resolution_posture
from wardline.scanner.analyzer import WardlineAnalyzer, build_analyzer

_FIX = Path(__file__).resolve().parent / "fixtures"
_TARGET = _FIX / "target_thirdparty_boundary.py"


def _scan(grammar=None):  # noqa: ANN001, ANN202
    analyzer = build_analyzer(grammar=grammar) if grammar is not None else WardlineAnalyzer()
    return list(analyzer.analyze([_TARGET], WardlineConfig(), root=_FIX))


def test_pack_recognizes_thirdparty_boundaries_and_fires_on_leak() -> None:
    findings = _scan(GRAMMAR)
    # Both @trust_boundary functions are recognized as boundaries -> scan not inert.
    posture = compute_resolution_posture(findings)
    assert posture.recognized_boundaries == 2
    # A @trust_boundary that returns its untrusted source_param unvalidated fires an ERROR
    # (declared-validated vs actually-raw — the boundary-returns-untrusted contract).
    defects = [f for f in findings if f.kind is Kind.DEFECT]
    assert defects, "pack-bridged boundary produced no defect"
    leak = [f for f in defects if (f.qualname or "").endswith(".leaks")]
    assert leak, [f"{f.rule_id}:{f.qualname}" for f in defects]
    assert leak[0].rule_id == "PY-WL-119"
    # The clean validator must NOT fire.
    assert not [f for f in defects if (f.qualname or "").endswith(".validates")]


def test_without_pack_thirdparty_vocab_is_unrecognized() -> None:
    findings = _scan(None)
    # Default grammar does not read the third-party vocabulary -> zero boundaries, no defect.
    # This is the inert state the pack-bridge fixes.
    posture = compute_resolution_posture(findings)
    assert posture.recognized_boundaries == 0
    assert not [f for f in findings if f.kind is Kind.DEFECT]
