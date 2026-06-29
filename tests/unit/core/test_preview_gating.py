"""Regression pins: PREVIEW-maturity rules gate exactly like STABLE ones.

wardline-4ada23bb09. The gate predicate silently skipped ``Maturity.PREVIEW``
findings, so six ERROR-severity preview rules — 118 (SQL injection), 119
(no-op boundary), 120 (stored taint), 121 (XXE), 122 (SSTI), 124 (native-lib
load) — fired as active ERROR defects but ``--fail-on ERROR`` passed GREEN on
them. ``maturity`` is an informational "predicates may still sharpen" label
(docs/concepts/rules.md: preview rules "participate in the gate, baseline,
waivers, and judge exactly like stable rules"); it must NOT affect the gate.

The bug survived because the rule suite asserted the FINDING fires but never
asserted the GATE trips. These pins close that gap: the unit invariant covers
EVERY preview rule (so the root cause cannot recur for a future preview rule),
and the end-to-end pins drive a real scan -> gate_decision for the two concrete
shapes the bug was reproduced on.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from wardline.core.finding import Finding, Kind, Location, Maturity, Severity
from wardline.core.run import gate_decision, run_scan
from wardline.core.suppression import gate_trips
from wardline.scanner.rules import BUILTIN_RULE_CLASSES

_PREVIEW_RULES = [cls for cls in BUILTIN_RULE_CLASSES if cls.metadata.maturity is Maturity.PREVIEW]


def _active_defect(*, rule_id: str, severity: Severity, maturity: Maturity) -> Finding:
    return Finding(
        rule_id=rule_id,
        message="synthetic",
        severity=severity,
        kind=Kind.DEFECT,
        location=Location(path="src/m.py", line_start=1),
        fingerprint="a" * 64,
        maturity=maturity,
    )


def test_preview_error_defect_trips_gate_at_error() -> None:
    # The exact inverse of the bug: an ACTIVE preview ERROR DEFECT must trip the
    # severity gate at ERROR. Before the fix this returned False.
    f = _active_defect(rule_id="PY-WL-119", severity=Severity.ERROR, maturity=Maturity.PREVIEW)
    assert gate_trips([f], Severity.ERROR) is True


def test_preview_maturity_does_not_change_gate_outcome() -> None:
    # maturity is informational only: a preview defect and a stable defect of the
    # same severity gate identically.
    preview = _active_defect(rule_id="PY-WL-119", severity=Severity.ERROR, maturity=Maturity.PREVIEW)
    stable = _active_defect(rule_id="PY-WL-101", severity=Severity.ERROR, maturity=Maturity.STABLE)
    assert gate_trips([preview], Severity.ERROR) == gate_trips([stable], Severity.ERROR) is True


@pytest.mark.parametrize("cls", _PREVIEW_RULES, ids=lambda c: c.metadata.rule_id)
def test_every_preview_rule_participates_in_gate(cls) -> None:
    # Universal invariant over the whole registry: no preview rule is silently
    # excluded from the gate at its own base severity. This is what makes the
    # root cause unable to recur when a NEW preview rule is added.
    md = cls.metadata
    f = _active_defect(rule_id=md.rule_id, severity=md.base_severity, maturity=Maturity.PREVIEW)
    assert gate_trips([f], md.base_severity) is True, f"{md.rule_id} (preview, {md.base_severity.value}) must gate"


def test_degenerate_boundary_119_gates_end_to_end(tmp_path: Path) -> None:
    # The filed repro: a @trust_boundary that returns its input unvalidated fires
    # PY-WL-119 at ERROR; --fail-on ERROR must TRIP, not pass green.
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "b.py").write_text(
        "from wardline.decorators import trust_boundary\n"
        "@trust_boundary(to_level='ASSURED')\ndef ingest(payload):\n    return payload\n",
        encoding="utf-8",
    )
    result = run_scan(proj)
    assert any(f.rule_id == "PY-WL-119" and f.severity is Severity.ERROR for f in result.findings)
    decision = gate_decision(result, Severity.ERROR)
    assert decision.tripped is True
    assert decision.would_trip_at == "ERROR"


def test_sql_injection_118_gates_end_to_end(tmp_path: Path) -> None:
    # Disproves the bug's "118 still gates" premise was wrong the OTHER way: 118 is
    # preview, so it did NOT gate. After the fix an untrusted -> cursor.execute()
    # flow in a trusted-tier function must trip --fail-on ERROR.
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "app.py").write_text(
        "from wardline.decorators import external_boundary, trusted\n"
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\ndef f(p, cursor):\n    cursor.execute(read_raw(p))\n",
        encoding="utf-8",
    )
    result = run_scan(proj)
    assert any(f.rule_id == "PY-WL-118" and f.severity is Severity.ERROR for f in result.findings)
    decision = gate_decision(result, Severity.ERROR)
    assert decision.tripped is True
    assert decision.would_trip_at == "ERROR"
