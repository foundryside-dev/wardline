from __future__ import annotations

from pathlib import Path

from wardline.core.finding import Kind, Severity
from wardline.core.run import gate_decision, run_scan


def test_self_hosting_pipeline_catches_real_violation() -> None:
    # NON-VACUOUS counterpart to test_wardline_scans_itself_clean: the self-hosting
    # scan pipeline (run_scan + gate_decision — the exact path the `wardline scan
    # src/ --fail-on ERROR` CI step exercises) MUST catch a real trust-boundary
    # violation. The fixture lives under tests/fixtures/ (NOT src/) so the src/
    # self-scan stays clean, but a tier-gated rule (PY-WL-101) fires here and the
    # ERROR gate trips — proving the pipeline CAN go red on a genuine defect.
    fixtures = Path(__file__).resolve().parent / "fixtures" / "self_hosting_violation"
    result = run_scan(fixtures)
    defects = [f for f in result.findings if f.kind == Kind.DEFECT]
    assert defects, "the violation fixture must produce a DEFECT"
    assert any(d.rule_id == "PY-WL-101" for d in defects), [d.rule_id for d in defects]
    assert any(d.severity is Severity.ERROR for d in defects if d.rule_id == "PY-WL-101")

    decision = gate_decision(result, Severity.ERROR)
    assert decision.tripped is True
    assert decision.verdict == "FAILED"
