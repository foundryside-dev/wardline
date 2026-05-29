import json as _json
from pathlib import Path

from click.testing import CliRunner

from wardline.cli.main import cli
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


def test_scan_sarif_is_not_yet_implemented(tmp_path: Path) -> None:
    result = CliRunner().invoke(cli, ["scan", str(FIXTURE), "--format", "sarif"])
    assert result.exit_code == 2


def test_baseline_and_judge_stubs_exit_2() -> None:
    runner = CliRunner()
    assert runner.invoke(cli, ["baseline"]).exit_code == 2
    assert runner.invoke(cli, ["judge"]).exit_code == 2


def test_scan_fail_on_is_inert_in_sp0(tmp_path: Path) -> None:
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
