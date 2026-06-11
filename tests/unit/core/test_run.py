import textwrap
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from wardline.core.errors import ConfigError
from wardline.core.finding import FINGERPRINT_SCHEME, Finding, Kind, Location, Severity, SuppressionState
from wardline.core.judged import JudgedFP, write_judged
from wardline.core.paths import baseline_path, judged_path, waivers_path
from wardline.core.run import (
    GateDecision,
    ScanResult,
    ScanSummary,
    baseline_migration_hint,
    gate_decision,
    run_scan,
)
from wardline.core.waivers import add_waiver

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
    # active is the count of non-suppressed DEFECTs in the emitted findings (the gate
    # evaluates ScanResult.gate_findings, a separate unsuppressed population)
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


def test_gate_decision_none_threshold_never_trips() -> None:
    result = run_scan(FIXTURE)
    decision = gate_decision(result, None)
    assert decision.tripped is False
    assert decision.exit_class == 0


def test_run_scan_unknown_rule_enable_is_gate_relevant(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "m.py").write_text("def f(): return 1\n", encoding="utf-8")
    (proj / "weft.toml").write_text('[wardline.rules]\nenable = ["NO_SUCH_RULE"]\n', encoding="utf-8")

    result = run_scan(proj)
    policy_findings = [f for f in result.findings if f.rule_id == "WLN-ENGINE-POLICY-CONFIG"]
    assert len(policy_findings) == 2
    assert all(f.kind is Kind.DEFECT and f.severity is Severity.ERROR for f in policy_findings)
    assert gate_decision(result, Severity.ERROR).tripped is True


def test_run_scan_none_severity_override_is_gate_relevant(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "m.py").write_text("def f(): return 1\n", encoding="utf-8")
    (proj / "weft.toml").write_text('[wardline.rules]\nseverity = { "PY-WL-101" = "NONE" }\n', encoding="utf-8")

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
    bl = baseline_path(proj)
    bl.parent.mkdir(parents=True, exist_ok=True)
    bl.write_text(
        f"fingerprint_scheme: {FINGERPRINT_SCHEME}\nversion: 1\nentries:\n"
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
    # SECURITY default: a repository-controlled baseline ANNOTATES the defect but does
    # NOT clear the --fail-on gate — the gate evaluates the unsuppressed population.
    assert gate_decision(result, Severity.ERROR).tripped is True
    # ...and --trust-suppressions restores the local ratchet: the baselined defect clears.
    trusted = run_scan(proj, trust_suppressions=True)
    assert trusted.summary.baselined == 1
    assert gate_decision(trusted, Severity.ERROR).tripped is False


def _leaky_proj(tmp_path: Path) -> tuple[Path, str]:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")
    fp = next(f for f in run_scan(proj).findings if f.rule_id == "PY-WL-101").fingerprint
    return proj, fp


def _write_baseline(proj: Path, fp: str) -> None:
    bl = baseline_path(proj)
    bl.parent.mkdir(parents=True, exist_ok=True)
    bl.write_text(
        f"fingerprint_scheme: {FINGERPRINT_SCHEME}\nversion: 1\n"
        f"entries:\n  - fingerprint: {fp}\n    rule_id: PY-WL-101\n    path: svc.py\n    message: m\n",
        encoding="utf-8",
    )


def _write_waiver(proj: Path, fp: str) -> None:
    add_waiver(waivers_path(proj), fingerprint=fp, reason="validated downstream", expires=None, root=proj)


def _write_judged(proj: Path, fp: str) -> None:
    write_judged(
        judged_path(proj),
        [
            JudgedFP(
                fingerprint=fp,
                rule_id="PY-WL-101",
                path="svc.py",
                message="m",
                rationale="model ruled FP",
                model_id="anthropic/claude-opus-4-8",
                confidence=0.95,
                recorded_at=datetime(2026, 5, 30, tzinfo=UTC),
                policy_hash="sha256:abc",
            )
        ],
    )


@pytest.mark.parametrize(
    "writer,state",
    [
        (_write_baseline, SuppressionState.BASELINED),
        (_write_waiver, SuppressionState.WAIVED),
        (_write_judged, SuppressionState.JUDGED),
    ],
)
def test_gate_trips_by_default_on_suppressed_defect(tmp_path: Path, writer, state) -> None:
    # SECURITY: a repository-controlled suppression (baseline / waiver / judged) ANNOTATES
    # the defect but must NOT clear the --fail-on gate by default, so a malicious PR cannot
    # self-suppress its own new defect.
    proj, fp = _leaky_proj(tmp_path)
    writer(proj, fp)
    result = run_scan(proj)
    # Annotated in the emitted findings...
    leak = next(f for f in result.findings if f.rule_id == "PY-WL-101")
    assert leak.suppressed is state
    # ...but the gate still trips on the unsuppressed gate population.
    assert gate_decision(result, Severity.ERROR).tripped is True


@pytest.mark.parametrize("writer", [_write_baseline, _write_waiver, _write_judged])
def test_trust_suppressions_restores_old_gate_clearing(tmp_path: Path, writer) -> None:
    proj, fp = _leaky_proj(tmp_path)
    writer(proj, fp)
    result = run_scan(proj, trust_suppressions=True)
    # gate_findings is the None sentinel -> gate falls back to the suppressed findings.
    assert result.gate_findings is None
    assert gate_decision(result, Severity.ERROR).tripped is False


def test_gate_decision_reason_names_suppressed_population_on_default_trip(tmp_path: Path) -> None:
    # The dogfood #2 confusion: summary.active:0 + gate.tripped:true. The verdict must
    # SAY why — name the suppressed-but-gated count and the escape hatches — and name the
    # population it judged, so the agent does not have to run scan twice to infer it.
    proj, fp = _leaky_proj(tmp_path)
    _write_baseline(proj, fp)
    decision = gate_decision(run_scan(proj), Severity.ERROR)
    assert decision.tripped is True
    assert decision.reason is not None
    assert "1 suppressed" in decision.reason
    assert "--trust-suppressions" in decision.reason and "--new-since" in decision.reason
    assert decision.evaluated is not None and "unsuppressed" in decision.evaluated


def test_gate_decision_reason_names_active_defect_on_genuine_trip(tmp_path: Path) -> None:
    proj, _ = _leaky_proj(tmp_path)  # no suppression -> a genuinely active defect
    decision = gate_decision(run_scan(proj), Severity.ERROR)
    assert decision.tripped is True
    assert decision.reason is not None and "1 active" in decision.reason
    # a genuine active trip should NOT misdirect the agent to the suppression flags
    assert "--trust-suppressions" not in decision.reason


def test_gate_decision_reason_names_both_active_and_suppressed_on_mixed_trip(tmp_path: Path) -> None:
    # The mixed branch of _gate_reason: one genuinely-active defect AND one baselined
    # defect both gate by default. The verdict must name BOTH counts (not collapse to
    # one), so the agent sees the real composition of the trip.
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "a.py").write_text(_LEAKY, encoding="utf-8")
    (proj / "b.py").write_text(_LEAKY, encoding="utf-8")
    # Baseline ONLY a.py's finding (fingerprint match); b.py stays active.
    fp_a = next(
        f.fingerprint for f in run_scan(proj).findings if f.rule_id == "PY-WL-101" and f.location.path == "a.py"
    )
    _write_baseline(proj, fp_a)
    decision = gate_decision(run_scan(proj), Severity.ERROR)
    assert decision.tripped is True
    assert decision.reason is not None
    assert "1 active + 1 suppressed" in decision.reason
    assert "--trust-suppressions" in decision.reason


def test_gate_decision_rejects_contradictory_construction() -> None:
    # The __post_init__ invariant guard: GateDecision must make "tripped gate that reads
    # as passed" (dogfood #2) unconstructible, not merely avoided by the factory. The guards
    # are now verdict-keyed (weft-b937e53854).
    with pytest.raises(ValueError, match="exit_class"):
        GateDecision(tripped=True, fail_on="ERROR", exit_class=0, verdict="FAILED", reason="x", evaluated="y")
    with pytest.raises(ValueError, match="reason"):
        GateDecision(tripped=True, fail_on="ERROR", exit_class=1, verdict="FAILED", reason=None, evaluated="y")
    with pytest.raises(ValueError, match="NOT_EVALUATED"):
        # NOT_EVALUATED but a threshold IS set — the no-gate shape leaking into a gated decision.
        GateDecision(tripped=False, fail_on="ERROR", exit_class=0, verdict="NOT_EVALUATED", reason="x", evaluated="y")
    with pytest.raises(ValueError, match="FAILED"):
        # tripped but verdict says PASSED — the dogfood #2 regression made unconstructible.
        GateDecision(tripped=True, fail_on="ERROR", exit_class=1, verdict="PASSED", reason="x", evaluated="y")
    # The three legitimate shapes the factory produces still construct cleanly.
    GateDecision(tripped=False, fail_on=None, exit_class=0, verdict="NOT_EVALUATED", reason="no threshold")
    GateDecision(
        tripped=False, fail_on="ERROR", exit_class=0, verdict="PASSED", reason="clean", evaluated="unsuppressed"
    )
    GateDecision(
        tripped=True, fail_on="ERROR", exit_class=1, verdict="FAILED", reason="1 active", evaluated="unsuppressed"
    )


def test_gate_decision_evaluated_reflects_trust_suppressions(tmp_path: Path) -> None:
    proj, fp = _leaky_proj(tmp_path)
    _write_baseline(proj, fp)
    decision = gate_decision(run_scan(proj, trust_suppressions=True), Severity.ERROR)
    assert decision.tripped is False
    assert decision.evaluated is not None and "honored" in decision.evaluated


def test_gate_decision_no_threshold_is_not_evaluated() -> None:
    # weft-b937e53854: a bare scan is NOT a clean pass — it never ran the gate.
    result = ScanResult(findings=[], summary=ScanSummary(0, 0, 0, 0, 0), files_scanned=0, context=None)
    decision = gate_decision(result, None)
    assert decision.verdict == "NOT_EVALUATED"
    assert decision.tripped is False and decision.exit_class == 0
    # Empty tree: nothing would trip, but the decision still carries an honest reason + population.
    assert decision.would_trip_at is None
    assert decision.reason is not None and "did not evaluate" in decision.reason
    assert decision.evaluated is not None


def _hint(proj: Path, *, new_since=None, trust=False):
    result = run_scan(proj, new_since=new_since, trust_suppressions=trust)
    decision = gate_decision(result, Severity.ERROR)
    return baseline_migration_hint(result, decision, root=proj, new_since=new_since)


def test_migration_hint_fires_on_baselined_only_trip(tmp_path: Path) -> None:
    # The dogfood #3 'my repo went red with no code change' case: a committed baseline
    # that used to clear the gate now re-enters it. Emit a loud one-liner pointing at
    # the escape hatches and the upgrade note.
    proj, fp = _leaky_proj(tmp_path)
    _write_baseline(proj, fp)
    hint = _hint(proj)
    assert hint is not None
    assert "baseline" in hint
    assert "--trust-suppressions" in hint and "--new-since" in hint
    assert "UPGRADING" in hint


def test_migration_hint_silent_under_trust_suppressions(tmp_path: Path) -> None:
    proj, fp = _leaky_proj(tmp_path)
    _write_baseline(proj, fp)
    assert _hint(proj, trust=True) is None


def test_migration_hint_silent_under_new_since(tmp_path: Path) -> None:
    # new_since scopes the gate (operator-supplied ratchet); the surprise — and the hint —
    # belongs to the unscoped run. Assert the helper short-circuits on a non-None ref
    # (tested directly so it does not require a git repo for the delta walk).
    proj, fp = _leaky_proj(tmp_path)
    _write_baseline(proj, fp)
    result = run_scan(proj)
    decision = gate_decision(result, Severity.ERROR)
    assert baseline_migration_hint(result, decision, root=proj, new_since="origin/main") is None


def test_migration_hint_silent_on_genuine_active_trip(tmp_path: Path) -> None:
    # An active (un-baselined) defect trips for a real reason — not a migration surprise.
    proj, _ = _leaky_proj(tmp_path)
    assert _hint(proj) is None


def test_migration_hint_silent_without_baseline_file(tmp_path: Path) -> None:
    # A waiver-only trip is real debt, not the baseline-rollout surprise this hint is for.
    proj, fp = _leaky_proj(tmp_path)
    _write_waiver(proj, fp)
    assert _hint(proj) is None


def test_gate_findings_is_unsuppressed_population(tmp_path: Path) -> None:
    proj, fp = _leaky_proj(tmp_path)
    _write_baseline(proj, fp)
    result = run_scan(proj)
    assert result.gate_findings is not None
    gate_leak = next(f for f in result.gate_findings if f.rule_id == "PY-WL-101")
    assert gate_leak.suppressed is SuppressionState.ACTIVE  # gate sees it active


def test_directly_constructed_scanresult_falls_back_to_findings() -> None:
    # The None sentinel: a ScanResult built without gate_findings (e.g. in a test) must
    # gate on its findings, never silently pass because gate_findings defaulted empty.
    leak = Finding(
        rule_id="PY-WL-101",
        message="m",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="svc.py", line_start=1),
        fingerprint="a" * 64,
        suppressed=SuppressionState.ACTIVE,
    )
    result = ScanResult(
        findings=[leak],
        summary=ScanSummary(total=1, active=1, baselined=0, waived=0, judged=0),
        files_scanned=1,
        context=None,
    )
    assert result.gate_findings is None
    assert gate_decision(result, Severity.ERROR).tripped is True


def test_lineless_defect_does_not_trip_gate(tmp_path: Path) -> None:
    # Regression guard for the bug PR #25 had (gate_findings = list(raw)): a lineless
    # DEFECT must be downgraded to a non-gating FACT in the gate population, exactly as
    # apply_suppressions does for the emitted findings — so it never trips the gate.
    from wardline.core.baseline import Baseline
    from wardline.core.finding import ENGINE_PATH  # noqa: F401  (documents the carve-out)
    from wardline.core.suppression import apply_suppressions, gate_trips
    from wardline.core.waivers import WaiverSet

    lineless = Finding(
        rule_id="PY-WL-101",
        message="m",
        severity=Severity.ERROR,
        kind=Kind.DEFECT,
        location=Location(path="svc.py", line_start=None),
        fingerprint="b" * 64,
        suppressed=SuppressionState.ACTIVE,
    )
    # This is the EXACT empty-suppression transform run_scan applies to build gate_findings.
    gate_pop = apply_suppressions([lineless], Baseline(frozenset()), WaiverSet([]), today=datetime.now(UTC).date())
    downgraded = next(f for f in gate_pop if f.location.path == "svc.py")
    assert downgraded.kind is Kind.FACT  # DEFECT -> FACT, no longer gating
    assert gate_trips(gate_pop, Severity.ERROR) is False


def test_new_since_scopes_both_populations_and_resists_suppression(tmp_path: Path) -> None:
    # --new-since is the SECURE CI ratchet: it scopes BOTH the emitted findings and the
    # gate population. A pre-existing defect OUTSIDE the delta does not trip; a new one
    # INSIDE the delta does, and a repo suppression cannot clear it.
    callee_src = """
    from wardline.decorators import external_boundary
    @external_boundary
    def read_raw(p):
        return p
    """
    caller_src = """
    from callee import read_raw
    from wardline.decorators import trusted
    @trusted(level='ASSURED')
    def f(p):
        return read_raw(p)
    """
    unrelated_src = """
    from wardline.decorators import external_boundary, trusted
    @external_boundary
    def read_raw_unrelated(p):
        return p
    @trusted(level='ASSURED')
    def h(p):
        return read_raw_unrelated(p)
    """
    (tmp_path / "callee.py").write_text(textwrap.dedent(callee_src), encoding="utf-8")
    (tmp_path / "caller.py").write_text(textwrap.dedent(caller_src), encoding="utf-8")
    (tmp_path / "unrelated.py").write_text(textwrap.dedent(unrelated_src), encoding="utf-8")

    # Try to suppress the NEW (in-delta) defect via a committed baseline — must not help.
    first = run_scan(tmp_path)
    new_fp = next(f for f in first.findings if f.qualname == "caller.f").fingerprint
    bl = baseline_path(tmp_path)
    bl.parent.mkdir(parents=True, exist_ok=True)
    bl.write_text(
        f"fingerprint_scheme: {FINGERPRINT_SCHEME}\nversion: 1\n"
        f"entries:\n  - fingerprint: {new_fp}\n    rule_id: PY-WL-101\n    path: caller.py\n"
        "    message: m\n",
        encoding="utf-8",
    )

    with patch("subprocess.run") as mock_run:

        def run_dispatch(args, **kwargs):
            if "rev-parse" in args and "--show-toplevel" in args:
                m = MagicMock(returncode=0)
                m.stdout = f"{tmp_path.resolve()}\n"
                return m
            if "rev-parse" in args and "--verify" in args:
                m = MagicMock(returncode=0)
                m.stdout = "abc123\n"
                return m
            if "diff" in args and "--name-only" in args:
                m = MagicMock(returncode=0)
                m.stdout = "callee.py\n"
                return m
            if "ls-files" in args:
                m = MagicMock(returncode=0)
                m.stdout = ""
                return m
            raise ValueError(f"Unexpected git command: {args}")

        mock_run.side_effect = run_dispatch
        result = run_scan(tmp_path, new_since="HEAD~1")

    # The in-delta caller.f stays ACTIVE in the gate population despite the baseline entry.
    assert result.gate_findings is not None
    gate_by_qn = {f.qualname: f for f in result.gate_findings if f.kind is Kind.DEFECT}
    assert gate_by_qn["caller.f"].suppressed is SuppressionState.ACTIVE
    # The out-of-delta unrelated.h is scoped OUT of the gate (delta: unchanged).
    assert gate_by_qn["unrelated.h"].suppressed is SuppressionState.BASELINED
    # Net: the gate trips on the new defect, and the repo baseline did not clear it.
    decision = gate_decision(result, Severity.ERROR)
    assert decision.tripped is True
    # The verdict reason counts only what ACTUALLY gates: caller.f (in-delta, repo-baselined
    # -> 1 suppressed). unrelated.h is delta-scoped-out (BASELINED in the gate population),
    # so it must NOT inflate the count — exactly 1, not 2.
    assert decision.reason is not None
    assert "1 suppressed" in decision.reason and "2 suppressed" not in decision.reason


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
    (proj / "weft.toml").write_text('[wardline]\nsource_roots = ["does_not_exist"]\n', encoding="utf-8")
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
        run_scan(proj, config_path=proj / "nope.toml")


def test_gate_decision_rejects_unknown_fail_on() -> None:
    # fail_on is always a Severity value; an arbitrary string is an illegal state the
    # other guards would otherwise let through (it satisfies "reason iff fail_on").
    with pytest.raises(ValueError, match="fail_on"):
        GateDecision(tripped=True, fail_on="banana", exit_class=1, verdict="FAILED", reason="x", evaluated="y")


def test_gate_decision_accepts_valid_severity_value() -> None:
    dec = GateDecision(
        tripped=True, fail_on=Severity.ERROR.value, exit_class=1, verdict="FAILED", reason="x", evaluated="y"
    )
    assert dec.fail_on == "ERROR"


def test_would_trip_at_names_highest_severity_on_bare_scan(tmp_path: Path) -> None:
    # weft-b937e53854: a bare scan reports would_trip_at = the worst active severity, so the
    # agent's first call is not a vacuous green. The leaky proj has a PY-WL-101 ERROR defect.
    proj, _ = _leaky_proj(tmp_path)
    decision = gate_decision(run_scan(proj), None)
    assert decision.verdict == "NOT_EVALUATED"
    assert decision.would_trip_at == "ERROR"
    assert decision.tripped is False and decision.exit_class == 0
    assert decision.reason is not None and "ERROR" in decision.reason


def test_verdict_passed_vs_failed_and_would_trip_at_is_threshold_independent(tmp_path: Path) -> None:
    proj, _ = _leaky_proj(tmp_path)
    result = run_scan(proj)
    failed = gate_decision(result, Severity.ERROR)
    assert failed.verdict == "FAILED" and failed.tripped is True and failed.would_trip_at == "ERROR"
    # A threshold ABOVE the worst active severity passes; would_trip_at still names the worst.
    passed = gate_decision(result, Severity.CRITICAL)
    assert passed.verdict == "PASSED" and passed.tripped is False
    assert passed.would_trip_at == "ERROR"


def test_summary_buckets_sum_to_total(tmp_path: Path) -> None:
    # weft-f506e5f845: active+baselined+waived+judged+informational == total exactly;
    # unanalyzed is an overlay, not a partition member.
    proj, fp = _leaky_proj(tmp_path)
    _write_baseline(proj, fp)
    s = run_scan(proj).summary
    assert s.active + s.baselined + s.waived + s.judged + s.informational == s.total
    assert s.informational >= 1  # the engine metric/fact is a non-defect finding


def test_run_scan_explicit_malformed_config_raises(tmp_path: Path) -> None:
    # (d) An EXPLICIT --config that EXISTS but is malformed must NOT silently fall
    # back to default policy either — that is the same false-green as a missing path.
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "m.py").write_text("def f(): return 1\n", encoding="utf-8")
    bad = proj / "bad.toml"
    bad.write_text("[wardline]\nsource_roots = [\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        run_scan(proj, config_path=bad)


def test_run_scan_implicit_missing_config_uses_defaults(tmp_path: Path) -> None:
    # (d) The IMPLICIT default path (root/weft.toml) may legitimately be absent;
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


# --- N-3 (wardline-8669de3576): nested scan root is surfaced, never silent ---


def test_run_scan_nested_scan_root_yields_fact(tmp_path: Path) -> None:
    # A subdirectory scan of a weft project silently mints scan-relative qualnames,
    # skips the project baseline, and drops output into the subdir. run_scan must
    # surface the nested root as a structured FACT (reaching both the CLI warning
    # and the MCP result).
    proj = tmp_path / "proj"
    (proj / ".weft" / "wardline").mkdir(parents=True)
    sub = proj / "specimen"
    sub.mkdir()
    (sub / "svc.py").write_text(_LEAKY, encoding="utf-8")
    result = run_scan(sub)
    facts = [f for f in result.findings if f.rule_id == "WLN-ENGINE-NESTED-SCAN-ROOT"]
    assert len(facts) == 1
    fact = facts[0]
    assert fact.kind is Kind.FACT and fact.severity is Severity.NONE
    assert fact.properties["project_root"] == str(proj.resolve())
    assert fact.properties["qualname_prefix"] == "specimen"
    # the qualname hazard and the remedy root are named in the message (the
    # agent-actionable signal — the CLI warning reuses this verbatim)
    assert "qualname" in fact.message and str(proj.resolve()) in fact.message
    # a scope hazard, not an under-scan — never counted as unanalyzed
    assert result.summary.unanalyzed == 0
    # the PY-WL-101 defect still fires, with the scan-relative qualname the fact warns about
    leak = next(f for f in result.findings if f.rule_id == "PY-WL-101")
    assert leak.qualname == "svc.leaky"


def test_run_scan_project_root_scan_has_no_nested_fact(tmp_path: Path) -> None:
    proj, _ = _leaky_proj(tmp_path)
    (proj / ".weft" / "wardline").mkdir(parents=True, exist_ok=True)
    result = run_scan(proj)
    assert not [f for f in result.findings if f.rule_id == "WLN-ENGINE-NESTED-SCAN-ROOT"]


def test_run_scan_fresh_tree_subdir_has_no_nested_fact(tmp_path: Path) -> None:
    # No weft markers anywhere above: a fresh unfederated tree must not warn —
    # warning every first-time user would dilute the signal into habitual noise.
    sub = tmp_path / "plain" / "pkg"
    sub.mkdir(parents=True)
    (sub / "m.py").write_text("def f(): return 1\n", encoding="utf-8")
    result = run_scan(sub)
    assert not [f for f in result.findings if f.rule_id == "WLN-ENGINE-NESTED-SCAN-ROOT"]


def test_run_scan_nested_src_root_has_empty_qualname_prefix(tmp_path: Path) -> None:
    # Scanning P/src of a src-layout project mints the SAME qualnames as scanning P
    # (module_dotted_name strips one leading src/ component) — the baseline/output
    # hazards remain so the FACT still fires, but the prefix must be empty so the
    # message never claims a phantom 'src.' qualname prefix.
    proj = tmp_path / "proj"
    (proj / ".weft" / "wardline").mkdir(parents=True)
    src = proj / "src"
    src.mkdir()
    (src / "m.py").write_text("def f(): return 1\n", encoding="utf-8")
    result = run_scan(src)
    fact = next(f for f in result.findings if f.rule_id == "WLN-ENGINE-NESTED-SCAN-ROOT")
    assert fact.properties["qualname_prefix"] == ""
