from pathlib import Path

from wardline.core.finding import Kind, Severity, SuppressionState
from wardline.core.run import ScanResult, ScanSummary, gate_decision, run_scan

FIXTURE = Path("tests/fixtures/sample_project")

# A trusted boundary returning an external-tainted value: PY-WL-101 ERROR defect.
# Mirrors `_LEAKY` in tests/unit/cli/test_cli.py — sample_project itself is clean.
_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def test_run_scan_returns_findings_summary_and_context() -> None:
    result = run_scan(FIXTURE)
    assert isinstance(result, ScanResult)
    assert isinstance(result.summary, ScanSummary)
    assert result.files_scanned >= 1
    # sample_project is a clean fixture: it yields exactly the engine-metrics
    # FACT and no DEFECTs (total == 1, active == 0). The asserts below pin the
    # invariants (total == len(findings); active == active-defect count), which
    # hold for any fixture regardless of how many defects it carries.
    assert result.summary.total == len(result.findings)
    # active is the count of non-suppressed DEFECTs (the gate population)
    active = sum(
        1 for f in result.findings
        if f.kind is Kind.DEFECT and f.suppressed is SuppressionState.ACTIVE
    )
    assert result.summary.active == active
    # context is carried for explain_finding to reuse
    assert result.context is not None


def test_gate_decision_trips_on_active_error(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")
    result = run_scan(proj)
    decision = gate_decision(result, Severity.ERROR)
    # the leaky project has an active ERROR defect (PY-WL-101), so the gate trips
    assert decision.tripped is True
    assert decision.exit_class == 1
    assert decision.fail_on == "ERROR"


def test_gate_decision_none_threshold_never_trips() -> None:
    result = run_scan(FIXTURE)
    decision = gate_decision(result, None)
    assert decision.tripped is False
    assert decision.exit_class == 0


def test_run_scan_baselined_count_distinguishes_categories(tmp_path: Path) -> None:
    # A genuinely suppressed defect must land in `baselined` and ONLY `baselined`
    # — pins the ScanSummary category labels so a baselined<->waived<->judged
    # mislabel (e.g. swapping the count expressions) would fail this test.
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")

    # First scan: the defect is active; capture its fingerprint.
    first = run_scan(proj)
    assert first.summary.active == 1
    assert first.summary.baselined == 0
    leak = next(f for f in first.findings if f.rule_id == "PY-WL-101")

    # Write a baseline accepting exactly that fingerprint (CLI test YAML shape).
    bl = proj / ".wardline" / "baseline.yaml"
    bl.parent.mkdir(parents=True, exist_ok=True)
    bl.write_text(
        "version: 1\nentries:\n"
        f"  - fingerprint: {leak.fingerprint}\n"
        "    rule_id: PY-WL-101\n    path: svc.py\n    message: m\n",
        encoding="utf-8",
    )

    # Second scan: the defect is now baselined — not waived, not judged, not active.
    result = run_scan(proj)
    assert result.summary.baselined == 1
    assert result.summary.waived == 0
    assert result.summary.judged == 0
    assert result.summary.active == 0
    # And the gate clears now that the only ERROR defect is suppressed.
    assert gate_decision(result, Severity.ERROR).tripped is False
