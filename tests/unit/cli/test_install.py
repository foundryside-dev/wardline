from pathlib import Path

from click.testing import CliRunner

from wardline.cli.main import cli


def test_scan_reads_filigree_url_from_config(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "wardline.yaml").write_text('filigree:\n  url: "http://configured-filigree"\n', encoding="utf-8")
    (tmp_path / "m.py").write_text("x = 1\n", encoding="utf-8")
    captured: dict[str, object] = {}

    class _FakeEmitter:
        def __init__(self, url: str) -> None:
            captured["url"] = url

        def emit(self, findings):  # noqa: ANN001
            from wardline.core.filigree_emit import EmitResult

            return EmitResult(reachable=False)

    monkeypatch.setattr("wardline.cli.scan.FiligreeEmitter", _FakeEmitter)
    result = CliRunner().invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert captured["url"] == "http://configured-filigree"


def test_mcp_resolves_clarion_url_from_config(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "wardline.yaml").write_text('clarion:\n  url: "http://configured-clarion"\n', encoding="utf-8")
    captured: dict[str, object] = {}

    class _FakeServer:
        def __init__(self, *, root: Path, clarion_url: str | None = None) -> None:
            captured["clarion_url"] = clarion_url
            self.rpc = self

        def run_stdio(self) -> None:
            captured["ran"] = True

    monkeypatch.setattr("wardline.cli.mcp.WardlineMCPServer", _FakeServer)
    result = CliRunner().invoke(cli, ["mcp", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert captured["clarion_url"] == "http://configured-clarion"


def test_install_writes_all_artifacts(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_CLARION_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    result = CliRunner().invoke(cli, ["install", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "CLAUDE.md").is_file()
    assert (tmp_path / "AGENTS.md").is_file()
    assert (tmp_path / ".claude" / "skills" / "wardline-gate" / "SKILL.md").is_file()
    assert (tmp_path / ".agents" / "skills" / "wardline-gate" / "SKILL.md").is_file()
    assert (tmp_path / ".mcp.json").is_file()
    assert "CLAUDE.md" in result.output


def test_install_is_idempotent(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_CLARION_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    CliRunner().invoke(cli, ["install", "--root", str(tmp_path)])
    result = CliRunner().invoke(cli, ["install", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "CLAUDE.md: unchanged" in result.output
    assert ".mcp.json (wardline entry): unchanged" in result.output


def test_install_opt_outs(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    result = CliRunner().invoke(
        cli,
        ["install", "--root", str(tmp_path), "--no-agents-md", "--no-skill", "--no-mcp", "--no-bindings"],
    )
    assert result.exit_code == 0, result.output
    assert (tmp_path / "CLAUDE.md").is_file()
    assert not (tmp_path / "AGENTS.md").exists()
    assert not (tmp_path / ".claude").exists()
    assert not (tmp_path / ".mcp.json").exists()


def test_install_no_claude_md_still_writes_agents(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_CLARION_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    result = CliRunner().invoke(cli, ["install", "--root", str(tmp_path), "--no-claude-md"])
    assert result.exit_code == 0, result.output
    assert not (tmp_path / "CLAUDE.md").exists()
    assert (tmp_path / "AGENTS.md").is_file()


def test_install_summary_includes_binding_lines(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("WARDLINE_CLARION_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    result = CliRunner().invoke(cli, ["install", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "clarion:" in result.output
    assert "filigree:" in result.output


def test_install_fails_2_on_malformed_mcp_json(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    (tmp_path / ".mcp.json").write_text("{bad", encoding="utf-8")
    result = CliRunner().invoke(cli, ["install", "--root", str(tmp_path)])
    assert result.exit_code == 2
    assert "malformed .mcp.json" in result.output
