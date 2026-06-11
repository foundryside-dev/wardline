# tests/unit/scanner/test_analyzer_isolation.py
"""Per-file / per-rule exception isolation (analyzer robustness).

Before this suite existed, any non-RecursionError raised by the L2 walk or by a
single rule aborted the ENTIRE scan (exit 2, zero findings) — one pathological
file lost every other file's findings, asymmetric with the Rust frontend's
WLN-ENGINE-FILE-FAILED per-file fence. The Python contract pinned here:

  * an unexpected exception during one file's analysis becomes a GATE-ELIGIBLE
    WLN-ENGINE-FILE-FAILED ERROR DEFECT naming the file (fail-closed — engine
    bugs surface, never silently skip), and the scan continues;
  * a crashing rule becomes a WLN-ENGINE-RULE-FAILED ERROR DEFECT at ENGINE_PATH
    and every other rule still contributes its findings;
  * parse failures (syntax/encoding/null bytes) are gate-eligible ERROR DEFECTs
    so the default ``--fail-on ERROR`` loop cannot read GREEN over unscanned code.
"""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import ENGINE_PATH, UNANALYZED_RULE_IDS, Kind, Severity
from wardline.core.run import gate_decision, run_scan
from wardline.scanner.analyzer import WardlineAnalyzer
from wardline.scanner.context import RuleRegistry


def _write(root: Path, rel: str, src: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(src), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Per-file isolation: an L2 engine exception fails ONE file, not the scan.
# ---------------------------------------------------------------------------


def _boom_on_marker(monkeypatch, exc: Exception) -> None:
    """Make the L2 stage raise ``exc`` for any function whose body names ``boom``."""
    import wardline.scanner.analyzer as analyzer_mod

    real = analyzer_mod.run_l2_function_stage

    def _boom(stage_input):  # noqa: ANN001, ANN202
        if any(isinstance(n, ast.Name) and n.id == "boom" for n in ast.walk(stage_input.node)):
            raise exc
        return real(stage_input)

    monkeypatch.setattr(analyzer_mod, "run_l2_function_stage", _boom)


def test_l2_engine_exception_fails_file_not_scan(tmp_path, monkeypatch) -> None:
    _boom_on_marker(monkeypatch, ValueError("synthetic engine defect"))
    _write(tmp_path, "broken.py", "def a():\n    boom = 1\n    return boom\n")
    _write(tmp_path, "clean.py", "def ok():\n    return 1\n")
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze([tmp_path / "broken.py", tmp_path / "clean.py"], WardlineConfig(), root=tmp_path)

    failed = [f for f in findings if f.rule_id == "WLN-ENGINE-FILE-FAILED"]
    assert len(failed) == 1
    # Fail-closed contract: gate-eligible ERROR DEFECT naming the file, with a
    # line anchor so the lineless-DEFECT downgrade cannot demote it out of the gate.
    assert failed[0].kind == Kind.DEFECT
    assert failed[0].severity == Severity.ERROR
    assert failed[0].location.path == "broken.py"
    assert failed[0].location.line_start is not None
    assert "ValueError" in failed[0].message
    # Counted toward ScanSummary.unanalyzed (single source of truth in core.finding).
    assert "WLN-ENGINE-FILE-FAILED" in UNANALYZED_RULE_IDS
    # The scan CONTINUED: the clean sibling is fully analysed.
    ctx = analyzer.last_context
    assert ctx is not None
    assert "clean.ok" in ctx.project_taints


def test_l2_engine_exception_emits_one_finding_per_file(tmp_path, monkeypatch) -> None:
    # The fingerprint is keyed on the relpath (the Rust frontend contract), so two
    # failing entities in ONE file must collapse to one finding — never two distinct
    # findings sharing a fingerprint (that would trip the collision guard).
    _boom_on_marker(monkeypatch, ValueError("synthetic engine defect"))
    _write(
        tmp_path,
        "broken.py",
        "def a():\n    boom = 1\n    return boom\ndef b():\n    boom = 2\n    return boom\n",
    )
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze([tmp_path / "broken.py"], WardlineConfig(), root=tmp_path)
    failed = [f for f in findings if f.rule_id == "WLN-ENGINE-FILE-FAILED"]
    assert len(failed) == 1
    assert not any(f.rule_id == "WLN-ENGINE-FINGERPRINT-COLLISION" for f in findings)


def test_recursion_error_still_yields_function_skip_fact(tmp_path, monkeypatch) -> None:
    # The broad fence must NOT swallow the dedicated RecursionError boundary —
    # too-deep functions keep their dedicated WLN-ENGINE-FUNCTION-SKIPPED finding.
    _boom_on_marker(monkeypatch, RecursionError("simulated deep L2"))
    _write(tmp_path, "deep.py", "def a():\n    boom = 1\n    return boom\n")
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze([tmp_path / "deep.py"], WardlineConfig(), root=tmp_path)
    skipped = [f for f in findings if f.rule_id == "WLN-ENGINE-FUNCTION-SKIPPED"]
    assert len(skipped) == 1
    assert skipped[0].kind == Kind.DEFECT
    assert skipped[0].severity == Severity.ERROR
    assert not any(f.rule_id == "WLN-ENGINE-FILE-FAILED" for f in findings)


def test_parse_stage_engine_exception_fails_file_not_scan(tmp_path, monkeypatch) -> None:
    # An unexpected exception while indexing/seeding ONE file (parse stage) is also
    # fenced per-file: WLN-ENGINE-FILE-FAILED for the named file, sibling analysed.
    import wardline.scanner.pipeline as pipeline_mod

    real = pipeline_mod.seed_function_taints

    def _boom(entities, *, ctx, provider):  # noqa: ANN001, ANN202
        if ctx.module == "broken":
            raise KeyError("synthetic seeding defect")
        return real(entities, ctx=ctx, provider=provider)

    monkeypatch.setattr(pipeline_mod, "seed_function_taints", _boom)
    _write(tmp_path, "broken.py", "def a():\n    return 1\n")
    _write(tmp_path, "clean.py", "def ok():\n    return 1\n")
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze([tmp_path / "broken.py", tmp_path / "clean.py"], WardlineConfig(), root=tmp_path)
    failed = [f for f in findings if f.rule_id == "WLN-ENGINE-FILE-FAILED"]
    assert len(failed) == 1
    assert failed[0].location.path == "broken.py"
    assert failed[0].kind == Kind.DEFECT
    assert failed[0].severity == Severity.ERROR
    ctx = analyzer.last_context
    assert ctx is not None
    assert "clean.ok" in ctx.project_taints


# ---------------------------------------------------------------------------
# Per-rule isolation: one crashing rule loses its own findings only.
# ---------------------------------------------------------------------------


class _RaisingRule:
    rule_id = "PY-WL-TEST-BOOM"

    def check(self, context):  # noqa: ANN001, ANN202
        raise RuntimeError("synthetic rule defect")


def test_crashing_rule_is_isolated_and_fails_closed(tmp_path) -> None:
    # Build the default registry PLUS a raising rule: the default rules' findings
    # must survive, and the crash surfaces as a gate-eligible ERROR DEFECT.
    from wardline.scanner.rules import build_default_registry

    registry = build_default_registry(WardlineConfig())
    registry.register(_RaisingRule())
    _write(
        tmp_path,
        "svc.py",
        "import subprocess\n"
        "from wardline.decorators import external_boundary, trusted\n"
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted(level='ASSURED')\n"
        "def run(p):\n    subprocess.run(read_raw(p), shell=True)\n    return 1\n",
    )
    analyzer = WardlineAnalyzer(registry=registry)
    findings = analyzer.analyze([tmp_path / "svc.py"], WardlineConfig(), root=tmp_path)

    rule_failed = [f for f in findings if f.rule_id == "WLN-ENGINE-RULE-FAILED"]
    assert len(rule_failed) == 1
    assert rule_failed[0].kind == Kind.DEFECT
    assert rule_failed[0].severity == Severity.ERROR
    # ENGINE_PATH location: exempt from the lineless-DEFECT downgrade, so it gates.
    assert rule_failed[0].location.path == ENGINE_PATH
    assert rule_failed[0].properties["rule"] == "PY-WL-TEST-BOOM"
    # The other rules still ran — the real sink finding is NOT lost.
    assert any(f.rule_id.startswith("PY-WL-") and f.kind is Kind.DEFECT for f in findings)


def test_duck_typed_registry_seam_still_runs(tmp_path) -> None:
    # A test-seam registry exposing only run() (no .rules) keeps the undelegated call.
    class _Custom:
        def run(self, context):  # noqa: ANN001, ANN202
            return []

    _write(tmp_path, "m.py", "def f():\n    return 1\n")
    analyzer = WardlineAnalyzer(registry=_Custom())
    findings = analyzer.analyze([tmp_path / "m.py"], WardlineConfig(), root=tmp_path)
    assert any(f.rule_id == "WLN-ENGINE-METRICS" for f in findings)


def test_registry_rules_maturity_stamp_survives_per_rule_dispatch(tmp_path) -> None:
    # The per-rule dispatch reuses RuleRegistry.run, so a PREVIEW rule's findings
    # still carry their maturity stamp (the stamping must not be lost to isolation).
    from dataclasses import dataclass

    from wardline.core.finding import Finding, Location, Maturity

    @dataclass(frozen=True)
    class _Meta:
        maturity: Maturity = Maturity.PREVIEW

    class _PreviewRule:
        rule_id = "PY-WL-TEST-PREVIEW"
        metadata = _Meta()

        def check(self, context):  # noqa: ANN001, ANN202
            return [
                Finding(
                    rule_id="PY-WL-TEST-PREVIEW",
                    message="preview finding",
                    severity=Severity.WARN,
                    kind=Kind.DEFECT,
                    location=Location(path="m.py", line_start=1),
                    fingerprint="ab" * 32,
                )
            ]

    registry = RuleRegistry()
    registry.register(_PreviewRule())
    _write(tmp_path, "m.py", "def f():\n    return 1\n")
    analyzer = WardlineAnalyzer(registry=registry)
    findings = analyzer.analyze([tmp_path / "m.py"], WardlineConfig(), root=tmp_path)
    preview = [f for f in findings if f.rule_id == "PY-WL-TEST-PREVIEW"]
    assert len(preview) == 1
    assert preview[0].maturity is Maturity.PREVIEW


# ---------------------------------------------------------------------------
# Gate eligibility: unscanned code must not pass `--fail-on ERROR` (fail-open fix).
# ---------------------------------------------------------------------------


def test_unparseable_file_trips_default_fail_on_error_gate(tmp_path) -> None:
    # The exact fail-open from the robustness review: a syntax error wrapping a real
    # command sink used to read PASSED/exit 0 under the documented agent loop.
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "bad.py").write_text("import subprocess\ndef f(\n    subprocess.run(evil)\n", encoding="utf-8")
    result = run_scan(proj)
    decision = gate_decision(result, Severity.ERROR)
    assert decision.tripped is True
    assert decision.verdict == "FAILED"
    assert result.summary.unanalyzed == 1


def test_runnable_but_undecodable_encoding_trips_gate(tmp_path) -> None:
    # The strengthened repro: a latin-1 coding cookie CPython tokenizes and RUNS,
    # but the scanner's UTF-8 read rejects — live code invisible to analysis must
    # not read GREEN. The encoding error carries no line; the defect must still
    # gate (line_start falls back, dodging the lineless-DEFECT downgrade).
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "enc.py").write_bytes(b'# -*- coding: latin-1 -*-\nimport os\nos.system("ls \xe9")\n')
    result = run_scan(proj)
    parse_errors = [f for f in result.findings if f.rule_id == "WLN-ENGINE-PARSE-ERROR"]
    assert len(parse_errors) == 1
    assert parse_errors[0].kind is Kind.DEFECT
    assert parse_errors[0].location.line_start is not None
    decision = gate_decision(result, Severity.ERROR)
    assert decision.tripped is True


def test_null_byte_file_is_gate_eligible(tmp_path) -> None:
    # Null bytes raise SyntaxError on current CPython and ValueError on some others;
    # either way the file must surface as a gate-eligible under-scan defect.
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "nul.py").write_bytes(b"import os\x00\nos.system('x')\n")
    result = run_scan(proj)
    under_scan = [f for f in result.findings if f.rule_id in {"WLN-ENGINE-PARSE-ERROR", "WLN-ENGINE-FILE-FAILED"}]
    assert len(under_scan) == 1
    assert under_scan[0].kind is Kind.DEFECT
    assert under_scan[0].severity is Severity.ERROR
    assert gate_decision(result, Severity.ERROR).tripped is True


def test_duplicate_project_fqns_trip_default_fail_on_error_gate(tmp_path) -> None:
    # A default repository-root scan maps both pkg/foo.py and src/pkg/foo.py to
    # pkg.foo. Duplicate function qualnames must fail loud before a later module
    # can hide an unsafe summary under the same project-wide key.
    proj = tmp_path / "proj"
    proj.mkdir()
    _write(proj, "pkg/foo.py", "def f(p):\n    return p\n")
    _write(proj, "src/pkg/foo.py", "def f(p):\n    return 'safe'\n")

    result = run_scan(proj)

    duplicates = [f for f in result.findings if f.rule_id == "WLN-ENGINE-DUPLICATE-FQN"]
    assert len(duplicates) == 1
    assert duplicates[0].kind is Kind.DEFECT
    assert duplicates[0].severity is Severity.ERROR
    assert "pkg.foo.f" in duplicates[0].message
    assert gate_decision(result, Severity.ERROR).tripped is True


def test_parse_error_gates_in_secure_population_but_baseline_annotates(tmp_path) -> None:
    # Secure-by-default precedent: a committed baseline ANNOTATES the parse-error
    # defect (suppressed in the emitted findings) but cannot clear the secure gate;
    # --trust-suppressions (trusted checkout) honors it.
    from wardline.core.finding import FINGERPRINT_SCHEME

    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "bad.py").write_text("def f(:\n", encoding="utf-8")
    fp = next(f.fingerprint for f in run_scan(proj).findings if f.rule_id == "WLN-ENGINE-PARSE-ERROR")
    bl = proj / ".weft" / "wardline" / "baseline.yaml"
    bl.parent.mkdir(parents=True, exist_ok=True)
    bl.write_text(
        f"fingerprint_scheme: {FINGERPRINT_SCHEME}\nversion: 1\nentries:\n"
        f"  - fingerprint: {fp}\n    rule_id: WLN-ENGINE-PARSE-ERROR\n    path: bad.py\n    message: m\n",
        encoding="utf-8",
    )
    secure = run_scan(proj)
    assert gate_decision(secure, Severity.ERROR).tripped is True  # baseline cannot clear the gate
    trusted = run_scan(proj, trust_suppressions=True)
    assert gate_decision(trusted, Severity.ERROR).tripped is False  # explicit operator trust
