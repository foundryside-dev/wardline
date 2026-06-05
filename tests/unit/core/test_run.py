from pathlib import Path

import pytest

from wardline.core.errors import ConfigError
from wardline.core.finding import Finding, Kind, Location, Severity, SuppressionState
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
    # sample_project is a clean fixture (src/pkg/__init__.py + src/pkg/mod.py, both
    # mapping to real modules — nothing skipped, unanalyzed == 0): it yields the
    # engine-metrics FACT and no DEFECTs (active == 0). The asserts below pin the
    # invariants (total == len(findings); active == active-defect count), which
    # hold for any fixture regardless of finding count.
    assert result.summary.total == len(result.findings)
    # active is the count of non-suppressed DEFECTs in the emitted findings
    active = sum(1 for f in result.findings if f.kind is Kind.DEFECT and f.suppressed is SuppressionState.ACTIVE)
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


def test_gate_decision_uses_unsuppressed_gate_population() -> None:
    suppressed = Finding(
        rule_id="PY-WL-101",
        message="m",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="svc.py", line_start=1),
        fingerprint="a" * 64,
        suppressed=SuppressionState.BASELINED,
    )
    active_gate_copy = Finding(
        rule_id="PY-WL-101",
        message="m",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="svc.py", line_start=1),
        fingerprint="a" * 64,
    )
    result = ScanResult(
        findings=[suppressed],
        summary=ScanSummary(total=1, active=0, baselined=1, waived=0, judged=0),
        files_scanned=1,
        context=None,
        gate_findings=[active_gate_copy],
    )

    assert gate_decision(result, Severity.ERROR).tripped is True

def test_gate_decision_none_threshold_never_trips() -> None:
    result = run_scan(FIXTURE)
    decision = gate_decision(result, None)
    assert decision.tripped is False
    assert decision.exit_class == 0


def test_run_scan_unknown_rule_enable_is_gate_relevant(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "m.py").write_text("def f(): return 1\n", encoding="utf-8")
    (proj / "wardline.yaml").write_text("rules:\n  enable:\n    - NO_SUCH_RULE\n", encoding="utf-8")

    result = run_scan(proj)
    policy_findings = [f for f in result.findings if f.rule_id == "WLN-ENGINE-POLICY-CONFIG"]
    assert len(policy_findings) == 2
    assert all(f.kind is Kind.DEFECT and f.severity is Severity.ERROR for f in policy_findings)
    assert gate_decision(result, Severity.ERROR).tripped is True


def test_run_scan_none_severity_override_is_gate_relevant(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "m.py").write_text("def f(): return 1\n", encoding="utf-8")
    (proj / "wardline.yaml").write_text("rules:\n  severity:\n    PY-WL-101: NONE\n", encoding="utf-8")

    result = run_scan(proj)
    policy_findings = [f for f in result.findings if f.rule_id == "WLN-ENGINE-POLICY-CONFIG"]
    assert len(policy_findings) == 1
    assert policy_findings[0].kind is Kind.DEFECT
    assert policy_findings[0].severity is Severity.ERROR
    assert gate_decision(result, Severity.ERROR).tripped is True


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
    # The emitted finding is suppressed, but fail-on gates over the unsuppressed
    # population so repository-controlled baselines cannot hide defects in CI.
    assert gate_decision(result, Severity.ERROR).tripped is True


def test_gate_decision_ignores_repo_controlled_waivers(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")

    first = run_scan(proj)
    leak = next(f for f in first.findings if f.rule_id == "PY-WL-101")
    (proj / "wardline.yaml").write_text(
        "waivers:\n"
        f"  - fingerprint: {leak.fingerprint}\n"
        "    reason: attacker-controlled waiver\n",
        encoding="utf-8",
    )

    result = run_scan(proj)
    assert result.summary.waived == 1
    assert result.summary.active == 0
    assert gate_decision(result, Severity.ERROR).tripped is True

def test_run_scan_counts_unanalyzed_parse_error(tmp_path: Path) -> None:
    # (b) A file that cannot be parsed is discovered-but-not-analysed: a
    # Severity.NONE FACT that never trips the severity gate. ScanSummary.unanalyzed
    # must count it so the silent under-scan is surfaced.
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "bad.py").write_text("def f(:\n", encoding="utf-8")
    (proj / "good.py").write_text("def g(): return 1\n", encoding="utf-8")
    result = run_scan(proj)
    assert result.summary.unanalyzed == 1


def test_run_scan_no_module_skip_not_counted_unanalyzed(tmp_path: Path) -> None:
    # (b refinement) A benign no-module-mapping skip (a top-level __init__.py with
    # nothing to analyze) is OBSERVABLE as a WLN-ENGINE-NO-MODULE FACT but is NOT a
    # "tried and failed" signal — it must NOT count toward unanalyzed, so a clean
    # src-layout repo does not unconditionally report "could not be analyzed".
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "__init__.py").write_text("VERSION = 1\n", encoding="utf-8")
    (proj / "mod.py").write_text("def g(): return 1\n", encoding="utf-8")
    result = run_scan(proj)
    # The fact is still emitted (the silent-drop fix stands).
    assert any(f.rule_id == "WLN-ENGINE-NO-MODULE" for f in result.findings)
    # ...but it does not dilute the unanalyzed signal.
    assert result.summary.unanalyzed == 0


def test_run_scan_missing_source_root_yields_finding(tmp_path: Path) -> None:
    # (c) A non-existent source_root used to be only a warnings.warn (invisible to
    # the MCP agent). It must now surface as a finding in result.findings (reaching
    # both the CLI summary and the MCP result) and count toward unanalyzed.
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "wardline.yaml").write_text("source_roots:\n  - does_not_exist\n", encoding="utf-8")
    # discover still warns on a missing root (by design — the CLI keeps the stderr
    # signal); the NEW contract is that it ALSO becomes a structured finding.
    with pytest.warns(UserWarning, match="source root does not exist"):
        result = run_scan(proj)
    missing = [f for f in result.findings if f.rule_id == "WLN-ENGINE-SOURCE-ROOT-MISSING"]
    assert len(missing) == 1
    assert result.summary.unanalyzed >= 1


def test_run_scan_explicit_missing_config_raises(tmp_path: Path) -> None:
    # (d) An EXPLICIT --config path that does not exist must NOT silently fall back
    # to default policy — it raises ConfigError (CLI maps to exit 2).
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "m.py").write_text("def f(): return 1\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        run_scan(proj, config_path=proj / "nope.yaml")


def test_run_scan_implicit_missing_config_uses_defaults(tmp_path: Path) -> None:
    # (d) The IMPLICIT default path (root/wardline.yaml) may legitimately be absent;
    # run_scan returns defaults without raising.
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "m.py").write_text("def f(): return 1\n", encoding="utf-8")
    result = run_scan(proj, config_path=None)
    assert isinstance(result, ScanResult)


def test_run_scan_out_of_root_symlink_yields_finding(tmp_path: Path) -> None:
    # Out-of-root target the symlink points at.
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.py"
    secret.write_text("SECRET = 1\n")

    root = tmp_path / "root"
    src = root / "src"
    src.mkdir(parents=True)
    real = src / "real.py"
    real.write_text("x = 1\n")
    # A *.py symlink inside a legitimate source_root pointing outside the root.
    (src / "evil.py").symlink_to(secret)

    # run_scan with confine_to_root=True should skip evil.py and add a finding.
    result = run_scan(root, confine_to_root=True)
    skipped = [f for f in result.findings if f.rule_id == "WLN-ENGINE-FILE-SKIPPED"]
    assert len(skipped) == 1
    assert skipped[0].location.path == "src/evil.py"
    assert skipped[0].properties.get("reason") == "out_of_root_symlink"
