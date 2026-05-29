from pathlib import Path

from click.testing import CliRunner

from wardline.cli.main import cli

FIXTURE = Path(__file__).parents[2] / "fixtures" / "sample_project"


def test_version() -> None:
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "wardline" in result.output


def test_scan_writes_empty_findings_and_exits_zero(tmp_path: Path) -> None:
    out = tmp_path / "findings.jsonl"
    result = CliRunner().invoke(cli, ["scan", str(FIXTURE), "--output", str(out)])
    assert result.exit_code == 0, result.output
    assert out.exists()
    assert out.read_text(encoding="utf-8") == ""


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
