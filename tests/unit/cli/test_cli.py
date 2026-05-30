import json as _json
from pathlib import Path

import yaml as _yaml
from click.testing import CliRunner

from wardline.cli.main import cli
from wardline.cli.main import cli as _cli
from wardline.cli.scan import scan

FIXTURE = Path(__file__).parents[2] / "fixtures" / "sample_project"


def test_version() -> None:
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "wardline" in result.output


def test_scan_writes_findings_and_exits_zero(tmp_path: Path) -> None:
    out = tmp_path / "findings.jsonl"
    result = CliRunner().invoke(cli, ["scan", str(FIXTURE), "--output", str(out)])
    assert result.exit_code == 0, result.output
    assert out.exists()
    # SP1: analyzer emits at least the engine metrics finding
    lines = [ln for ln in out.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert any(_json.loads(ln)["rule_id"] == "WLN-ENGINE-METRICS" for ln in lines)


def test_scan_format_sarif_writes_sarif_file(tmp_path: Path) -> None:
    out = tmp_path / "out.sarif"
    result = CliRunner().invoke(cli, ["scan", str(FIXTURE), "--format", "sarif", "--output", str(out)])
    assert result.exit_code == 0, result.output
    log = _json.loads(out.read_text(encoding="utf-8"))
    assert log["version"] == "2.1.0"
    assert log["runs"][0]["tool"]["driver"]["name"] == "wardline"


def test_scan_format_sarif_default_output_path(tmp_path: Path) -> None:
    import shutil

    project = tmp_path / "proj"
    shutil.copytree(FIXTURE, project)
    result = CliRunner().invoke(cli, ["scan", str(project), "--format", "sarif"])
    assert result.exit_code == 0, result.output
    assert (project / "findings.sarif").exists()


def test_scan_format_sarif_still_gates(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    _write(proj, "svc.py", _LEAKY)  # PY-WL-101 ERROR defect
    result = CliRunner().invoke(
        cli, ["scan", str(proj), "--format", "sarif", "--output", str(tmp_path / "o.sarif"),
              "--fail-on", "ERROR"]
    )
    assert result.exit_code == 1, result.output


def test_baseline_is_a_group() -> None:
    runner = CliRunner()
    # `baseline` is a command group; invoking it with no subcommand shows help.
    res = runner.invoke(cli, ["baseline"])
    assert res.exit_code == 0
    assert "create" in res.output and "update" in res.output


def test_judge_is_registered() -> None:
    # The SP5 judge command replaced the SP0 stub; --help must describe it.
    res = CliRunner().invoke(cli, ["judge", "--help"])
    assert res.exit_code == 0
    assert "--write" in res.output and "triage" in res.output.lower()


def test_scan_fail_on_clean_fixture_exits_zero(tmp_path: Path) -> None:
    # The sample fixture has no active CRITICAL defect, so --fail-on CRITICAL is clean.
    out = tmp_path / "findings.jsonl"
    result = CliRunner().invoke(
        cli, ["scan", str(FIXTURE), "--output", str(out), "--fail-on", "CRITICAL"]
    )
    assert result.exit_code == 0, result.output


def test_scan_default_output_lands_in_scanned_path(tmp_path: Path) -> None:
    # copy the fixture into tmp so the default output doesn't pollute the repo
    import shutil

    project = tmp_path / "proj"
    shutil.copytree(FIXTURE, project)
    result = CliRunner().invoke(cli, ["scan", str(project)])
    assert result.exit_code == 0, result.output
    assert (project / "findings.jsonl").exists()


def test_scan_config_error_exits_2(tmp_path: Path) -> None:
    import shutil

    project = tmp_path / "proj"
    shutil.copytree(FIXTURE, project)
    (project / "wardline.yaml").write_text("a: [1, 2\n", encoding="utf-8")  # malformed
    out = tmp_path / "f.jsonl"
    result = CliRunner().invoke(cli, ["scan", str(project), "--output", str(out)])
    assert result.exit_code == 2


def test_scan_emits_engine_metrics(tmp_path) -> None:
    (tmp_path / "m.py").write_text("def f(p):\n    return p\n", encoding="utf-8")
    out = tmp_path / "findings.jsonl"
    res = CliRunner().invoke(scan, [str(tmp_path), "--output", str(out)])
    assert res.exit_code == 0, res.output
    lines = [_json.loads(ln) for ln in out.read_text().splitlines() if ln.strip()]
    assert any(f["rule_id"] == "WLN-ENGINE-METRICS" for f in lines)


def test_vocab_emits_descriptor_as_yaml() -> None:
    import yaml as _yaml

    from wardline.core.descriptor import build_vocabulary_descriptor

    result = CliRunner().invoke(cli, ["vocab"])
    assert result.exit_code == 0, result.output
    parsed = _yaml.safe_load(result.output)
    assert parsed == build_vocabulary_descriptor()


def test_scan_cache_dir_persists_warm_taints_equal_cold(tmp_path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "m.py").write_text("def f(p):\n    return p\n", encoding="utf-8")
    cache = tmp_path / "cache"
    out1 = tmp_path / "f1.jsonl"
    out2 = tmp_path / "f2.jsonl"
    runner = CliRunner()
    r1 = runner.invoke(scan, [str(proj), "--cache-dir", str(cache), "--output", str(out1)])
    assert r1.exit_code == 0, r1.output
    assert cache.exists() and any(cache.iterdir())  # cache written to disk
    r2 = runner.invoke(scan, [str(proj), "--cache-dir", str(cache), "--output", str(out2)])
    assert r2.exit_code == 0, r2.output

    def _parse(p: Path) -> list[dict]:
        return [_json.loads(line) for line in p.read_text().splitlines() if line.strip()]

    def _non_metric(fs: list[dict]) -> list[dict]:
        return [f for f in fs if f["rule_id"] != "WLN-ENGINE-METRICS"]

    def _hit_rate(fs: list[dict]) -> float:
        m = next(f for f in fs if f["rule_id"] == "WLN-ENGINE-METRICS")
        return m["properties"]["cache_hit_rate"]

    f1, f2 = _parse(out1), _parse(out2)
    # The invariant SP1e guarantees: taint/structural findings are warm≡cold.
    assert _non_metric(f1) == _non_metric(f2)
    # The cache metric meaningfully varies: cold all-miss, warm served from disk.
    assert _hit_rate(f1) == 0.0
    assert _hit_rate(f2) > 0.0


def _write(project, name, src):
    p = project / name
    p.write_text(src, encoding="utf-8")
    return p


# A @trusted function returning raw data fires PY-WL-101 (a real DEFECT).
_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def test_scan_fail_on_trips_on_unsuppressed_defect(tmp_path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    _write(proj, "svc.py", _LEAKY)
    out = tmp_path / "f.jsonl"
    res = CliRunner().invoke(scan, [str(proj), "--output", str(out), "--fail-on", "ERROR"])
    assert res.exit_code == 1, res.output  # PY-WL-101 is ERROR, unsuppressed


def test_scan_fail_on_inert_without_flag(tmp_path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    _write(proj, "svc.py", _LEAKY)
    out = tmp_path / "f.jsonl"
    res = CliRunner().invoke(scan, [str(proj), "--output", str(out)])
    assert res.exit_code == 0, res.output  # no --fail-on -> never gates


def test_scan_baseline_suppresses_and_clears_gate(tmp_path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    _write(proj, "svc.py", _LEAKY)
    out = tmp_path / "f.jsonl"
    # First scan: capture the PY-WL-101 fingerprint.
    CliRunner().invoke(scan, [str(proj), "--output", str(out)])
    findings = [_json.loads(ln) for ln in out.read_text().splitlines() if ln.strip()]
    fp = next(f["fingerprint"] for f in findings if f["rule_id"] == "PY-WL-101")
    # Write a baseline accepting it.
    bl = proj / ".wardline" / "baseline.yaml"
    bl.parent.mkdir(parents=True, exist_ok=True)
    bl.write_text(
        "version: 1\nentries:\n  - fingerprint: " + fp + "\n    rule_id: PY-WL-101\n    path: svc.py\n    message: m\n",
        encoding="utf-8",
    )
    # Second scan: the defect is baselined -> annotated + gate clears.
    res = CliRunner().invoke(scan, [str(proj), "--output", str(out), "--fail-on", "ERROR"])
    assert res.exit_code == 0, res.output
    findings2 = [_json.loads(ln) for ln in out.read_text().splitlines() if ln.strip()]
    leak = next(f for f in findings2 if f["rule_id"] == "PY-WL-101")
    assert leak["suppressed"] == "baselined"  # annotate-and-keep
    assert "1 suppressed" in res.output


def test_scan_malformed_baseline_exits_2(tmp_path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    _write(proj, "svc.py", "def f(p):\n    return p\n")
    bl = proj / ".wardline" / "baseline.yaml"
    bl.parent.mkdir(parents=True, exist_ok=True)
    bl.write_text("version: 1\nentries: [1, 2\n", encoding="utf-8")  # malformed
    res = CliRunner().invoke(scan, [str(proj), "--output", str(tmp_path / "f.jsonl")])
    assert res.exit_code == 2  # never silently empty -> mass-unsuppress


_LEAKY_FOR_BASELINE = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def test_baseline_create_writes_file_and_suppresses_next_scan(tmp_path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY_FOR_BASELINE, encoding="utf-8")
    runner = CliRunner()
    res = runner.invoke(_cli, ["baseline", "create", str(proj)])
    assert res.exit_code == 0, res.output
    bl = proj / ".wardline" / "baseline.yaml"
    assert bl.exists()
    doc = _yaml.safe_load(bl.read_text())
    assert doc["version"] == 1 and len(doc["entries"]) >= 1
    assert "baselined" in res.output
    # Next scan: the captured defect is now baselined, gate clears.
    out = tmp_path / "f.jsonl"
    res2 = runner.invoke(scan, [str(proj), "--output", str(out), "--fail-on", "ERROR"])
    assert res2.exit_code == 0, res2.output


def test_baseline_create_refuses_if_exists(tmp_path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY_FOR_BASELINE, encoding="utf-8")
    runner = CliRunner()
    runner.invoke(_cli, ["baseline", "create", str(proj)])
    res = runner.invoke(_cli, ["baseline", "create", str(proj)])
    assert res.exit_code == 2  # already exists -> use update


def test_baseline_update_overwrites(tmp_path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY_FOR_BASELINE, encoding="utf-8")
    runner = CliRunner()
    runner.invoke(_cli, ["baseline", "create", str(proj)])
    res = runner.invoke(_cli, ["baseline", "update", str(proj)])
    assert res.exit_code == 0, res.output


def test_baseline_create_excludes_active_waivers(tmp_path) -> None:
    # TWO distinct defects: waive one, leave the other. The baseline must EXCLUDE the
    # waived fingerprint and KEEP the non-waived one (selective exclusion, not "empty").
    two_leaks = (
        "from wardline.decorators import external_boundary, trusted\n"
        "@external_boundary\ndef read_raw(p):\n    return p\n"
        "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
        "@trusted\ndef leaky2(p):\n    return read_raw(p)\n"
    )
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(two_leaks, encoding="utf-8")
    runner = CliRunner()
    out = tmp_path / "f.jsonl"
    runner.invoke(scan, [str(proj), "--output", str(out)])
    leaks = {
        _json.loads(ln)["qualname"]: _json.loads(ln)["fingerprint"]
        for ln in out.read_text().splitlines()
        if ln.strip() and _json.loads(ln)["rule_id"] == "PY-WL-101"
    }
    fp_waived, fp_kept = leaks["svc.leaky"], leaks["svc.leaky2"]
    assert fp_waived != fp_kept  # genuinely distinct findings
    (proj / "wardline.yaml").write_text(
        "waivers:\n  - fingerprint: " + fp_waived + "\n    reason: handled\n", encoding="utf-8"
    )
    res = runner.invoke(_cli, ["baseline", "create", str(proj)])
    assert res.exit_code == 0, res.output
    doc = _yaml.safe_load((proj / ".wardline" / "baseline.yaml").read_text()) or {}
    fps = {e["fingerprint"] for e in (doc.get("entries") or [])}
    assert fp_waived not in fps  # active-waiver fingerprint excluded
    assert fp_kept in fps        # non-waived defect still baselined


def test_scan_relative_root_emits_relative_path_and_qualname(tmp_path) -> None:
    # Regression: a RELATIVE scan-root arg must still yield repo-relative location.path
    # and an uncorrupted qualname. discover() resolves to absolute paths; if the analyzer
    # doesn't resolve root to the same base, is_relative_to fails and findings carry an
    # absolute path -> Filigree 400 + a garbage dotted qualname (broken Clarion reconcile).
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        Path("proj").mkdir()
        Path("proj/svc.py").write_text(_LEAKY, encoding="utf-8")
        result = runner.invoke(scan, ["proj", "--output", "proj/f.jsonl"])  # RELATIVE root
        assert result.exit_code == 0, result.output
        findings = [_json.loads(ln) for ln in Path("proj/f.jsonl").read_text().splitlines() if ln.strip()]
    leak = next(f for f in findings if f["rule_id"] == "PY-WL-101")
    assert leak["location"]["path"] == "svc.py"  # relative, not /abs/.../svc.py
    assert leak["qualname"] == "svc.leaky"        # clean module prefix, not '.tmp....svc.leaky'


def test_scan_filigree_emit_success(tmp_path, monkeypatch) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    _write(proj, "svc.py", _LEAKY)
    captured: dict[str, object] = {}

    class _StubEmitter:
        def __init__(self, url, **kw):
            captured["url"] = url

        def emit(self, findings):
            from wardline.core.filigree_emit import EmitResult

            captured["n"] = len(findings)
            return EmitResult(reachable=True, created=len(findings), warnings=("w1",))

    monkeypatch.setattr("wardline.cli.scan.FiligreeEmitter", _StubEmitter)
    out = tmp_path / "f.jsonl"
    result = CliRunner().invoke(
        scan, [str(proj), "--output", str(out), "--filigree-url", "http://x/api/loom/scan-results"]
    )
    assert result.exit_code == 0, result.output
    assert captured["url"] == "http://x/api/loom/scan-results"
    assert "emitted" in result.output and "w1" in result.output  # stats + warning surfaced


def test_scan_filigree_protocol_error_exits_2(tmp_path, monkeypatch) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    _write(proj, "svc.py", _LEAKY)
    from wardline.core.errors import FiligreeEmitError

    class _BadEmitter:
        def __init__(self, url, **kw):
            pass

        def emit(self, findings):
            raise FiligreeEmitError("Filigree rejected (400): bad path")

    monkeypatch.setattr("wardline.cli.scan.FiligreeEmitter", _BadEmitter)
    out = tmp_path / "f.jsonl"
    result = CliRunner().invoke(scan, [str(proj), "--output", str(out), "--filigree-url", "http://x"])
    assert result.exit_code == 2, result.output
    assert "bad path" in result.output


def test_scan_filigree_absent_continues(tmp_path, monkeypatch) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    _write(proj, "svc.py", _LEAKY)

    class _AbsentEmitter:
        def __init__(self, url, **kw):
            pass

        def emit(self, findings):
            from wardline.core.filigree_emit import EmitResult

            return EmitResult(reachable=False)

    monkeypatch.setattr("wardline.cli.scan.FiligreeEmitter", _AbsentEmitter)
    out = tmp_path / "f.jsonl"
    # absent sibling must NOT change the exit code; with no --fail-on, stays 0
    result = CliRunner().invoke(scan, [str(proj), "--output", str(out), "--filigree-url", "http://x"])
    assert result.exit_code == 0, result.output
    assert "could not reach" in result.output.lower()


def test_baseline_create_honors_custom_config_waivers(tmp_path) -> None:
    # Regression: `baseline create --config X` must read waivers from X (same as `scan`),
    # or the baseline is built from a different waiver set than scans consume.
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY_FOR_BASELINE, encoding="utf-8")
    runner = CliRunner()
    out = tmp_path / "f.jsonl"
    runner.invoke(scan, [str(proj), "--output", str(out)])
    fp = next(
        _json.loads(ln)["fingerprint"]
        for ln in out.read_text().splitlines() if ln.strip() and _json.loads(ln)["rule_id"] == "PY-WL-101"
    )
    custom = tmp_path / "custom.yaml"  # NOT proj/wardline.yaml
    custom.write_text("waivers:\n  - fingerprint: " + fp + "\n    reason: handled\n", encoding="utf-8")
    res = runner.invoke(_cli, ["baseline", "create", str(proj), "--config", str(custom)])
    assert res.exit_code == 0, res.output
    doc = _yaml.safe_load((proj / ".wardline" / "baseline.yaml").read_text()) or {}
    fps = {e["fingerprint"] for e in (doc.get("entries") or [])}
    assert fp not in fps  # waiver from --config was honored, so the fp is excluded


# --- SP5: wardline judge -----------------------------------------------------

_JUDGE_FIXTURE = (
    "from wardline.decorators.trust import trust_boundary\n"
    "from wardline.core.taints import TaintState\n"
    "@trust_boundary(to_level=TaintState.GUARDED)\n"
    "def validate(x):\n    return x\n"
)


def _make_judge_proj(tmp_path):  # type: ignore[no-untyped-def]
    proj = tmp_path / "proj"
    (proj / "svc").mkdir(parents=True)
    (proj / "svc" / "__init__.py").write_text("")
    (proj / "svc" / "v.py").write_text(_JUDGE_FIXTURE)
    return proj


def _fake_fp_response():  # type: ignore[no-untyped-def]
    from datetime import UTC, datetime

    from wardline.core.judge import JudgeResponse, JudgeVerdict
    return JudgeResponse(
        verdict=JudgeVerdict.FALSE_POSITIVE, rationale="over-taint", confidence=0.9,
        model_id="m", recorded_at=datetime.now(UTC), prompt_tokens_total=1,
        prompt_tokens_cached=None, policy_hash="sha256:x")


def test_judge_dry_run_reports_without_writing(monkeypatch, tmp_path) -> None:
    from click.testing import CliRunner

    import wardline.cli.judge as judge_cli
    from wardline.cli.main import cli
    proj = _make_judge_proj(tmp_path)
    monkeypatch.setattr(judge_cli, "call_judge", lambda req, **kw: _fake_fp_response())
    monkeypatch.setenv("WARDLINE_OPENROUTER_API_KEY", "k")
    result = CliRunner().invoke(cli, ["judge", str(proj)])
    assert result.exit_code == 0, result.output
    assert "FP" in result.output
    assert not (proj / ".wardline" / "judged.yaml").exists()


def test_judge_write_persists_false_positives(monkeypatch, tmp_path) -> None:
    from click.testing import CliRunner

    import wardline.cli.judge as judge_cli
    from wardline.cli.main import cli
    from wardline.core.judged import load_judged
    proj = _make_judge_proj(tmp_path)
    monkeypatch.setattr(judge_cli, "call_judge", lambda req, **kw: _fake_fp_response())
    monkeypatch.setenv("WARDLINE_OPENROUTER_API_KEY", "k")
    result = CliRunner().invoke(cli, ["judge", str(proj), "--write"])
    assert result.exit_code == 0, result.output
    assert load_judged(proj / ".wardline" / "judged.yaml").fingerprints()


def test_judge_missing_key_exits_2(monkeypatch, tmp_path) -> None:
    from click.testing import CliRunner

    from wardline.cli.main import cli
    proj = _make_judge_proj(tmp_path)
    monkeypatch.delenv("WARDLINE_OPENROUTER_API_KEY", raising=False)
    result = CliRunner().invoke(cli, ["judge", str(proj)])
    assert result.exit_code == 2


def test_judge_reads_key_from_dotenv(monkeypatch, tmp_path) -> None:
    import os

    from wardline.cli.judge import _load_env_key
    (tmp_path / ".env").write_text("WARDLINE_OPENROUTER_API_KEY=sk-or-fromdotenv\n")
    monkeypatch.delenv("WARDLINE_OPENROUTER_API_KEY", raising=False)
    _load_env_key(tmp_path)
    assert os.environ["WARDLINE_OPENROUTER_API_KEY"] == "sk-or-fromdotenv"


def test_dotenv_does_not_override_existing_env(monkeypatch, tmp_path) -> None:
    import os

    from wardline.cli.judge import _load_env_key
    (tmp_path / ".env").write_text("WARDLINE_OPENROUTER_API_KEY=sk-or-fromdotenv\n")
    monkeypatch.setenv("WARDLINE_OPENROUTER_API_KEY", "sk-or-fromenv")
    _load_env_key(tmp_path)
    assert os.environ["WARDLINE_OPENROUTER_API_KEY"] == "sk-or-fromenv"
