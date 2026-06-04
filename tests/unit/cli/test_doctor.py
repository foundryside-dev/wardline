from pathlib import Path

from click.testing import CliRunner

from wardline.cli.main import cli


def test_doctor_reports_missing_install_artifacts(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: home)
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)

    result = CliRunner().invoke(cli, ["doctor", "--root", str(tmp_path)])

    assert result.exit_code == 1
    assert "CLAUDE.md: missing" in result.output
    assert ".mcp.json: missing wardline server" in result.output
    assert "Codex MCP: missing wardline server" in result.output


def test_doctor_repair_installs_artifacts_and_discovers_bindings(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    monkeypatch.delenv("WARDLINE_CLARION_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: home)
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    (tmp_path / ".filigree.conf").write_text("{}", encoding="utf-8")
    filigree_dir = tmp_path / ".filigree"
    filigree_dir.mkdir()
    (filigree_dir / "ephemeral.port").write_text("8628", encoding="utf-8")

    result = CliRunner().invoke(cli, ["doctor", "--root", str(tmp_path), "--repair"])

    assert result.exit_code == 0, result.output
    assert "CLAUDE.md: repaired" in result.output
    assert ".mcp.json: repaired" in result.output
    assert "Codex MCP: repaired" in result.output
    assert "bindings: repaired" in result.output
    assert (tmp_path / ".mcp.json").is_file()
    assert (home / ".codex" / "config.toml").is_file()
    assert 'filigree:\n  url: "http://localhost:8628/api/loom/scan-results"' in (tmp_path / "wardline.yaml").read_text(
        encoding="utf-8"
    )


def test_doctor_passes_after_repair(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    monkeypatch.delenv("WARDLINE_CLARION_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: home)
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)

    repair = CliRunner().invoke(cli, ["doctor", "--root", str(tmp_path), "--repair"])
    assert repair.exit_code == 0, repair.output

    result = CliRunner().invoke(cli, ["doctor", "--root", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert "wardline doctor: ok" in result.output
