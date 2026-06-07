from pathlib import Path

from click.testing import CliRunner

from wardline.cli.main import cli


def test_scan_resolves_filigree_url_from_published_port(tmp_path: Path, monkeypatch) -> None:
    # Sibling-URL config keys were removed: the live URL now resolves from the
    # published .weft/filigree/ephemeral.port rung.
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    port_dir = tmp_path / ".weft" / "filigree"
    port_dir.mkdir(parents=True)
    (port_dir / "ephemeral.port").write_text("8628", encoding="utf-8")
    (tmp_path / "m.py").write_text("x = 1\n", encoding="utf-8")
    captured: dict[str, object] = {}

    class _FakeEmitter:
        def __init__(self, url: str, *, token: str | None = None) -> None:
            captured["url"] = url

        def emit(self, findings, *, scanned_paths=()):  # noqa: ANN001
            from wardline.core.filigree_emit import EmitResult

            captured["scanned_paths"] = tuple(scanned_paths)
            return EmitResult(reachable=False)

    monkeypatch.setattr("wardline.cli.scan.FiligreeEmitter", _FakeEmitter)
    result = CliRunner().invoke(cli, ["scan", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert captured["url"] == "http://localhost:8628/api/weft/scan-results"
    assert captured["scanned_paths"] == ("m.py",)


def test_mcp_resolves_loomweave_url_from_env(tmp_path: Path, monkeypatch) -> None:
    # Sibling-URL config keys were removed: the URL now resolves from the env var
    # (or the published .weft/loomweave/ephemeral.port rung).
    monkeypatch.setenv("WARDLINE_LOOMWEAVE_URL", "http://localhost:9000/configured-loomweave")
    captured: dict[str, object] = {}

    class _FakeServer:
        def __init__(self, *, root: Path, loomweave_url: str | None = None, filigree_url: str | None = None) -> None:
            captured["loomweave_url"] = loomweave_url
            captured["filigree_url"] = filigree_url
            self.rpc = self

        def run_stdio(self) -> None:
            captured["ran"] = True

    monkeypatch.setattr("wardline.cli.mcp.WardlineMCPServer", _FakeServer)
    result = CliRunner().invoke(cli, ["mcp", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert captured["loomweave_url"] == "http://localhost:9000/configured-loomweave"


def test_install_writes_all_artifacts(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: home)
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    result = CliRunner().invoke(cli, ["install", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "CLAUDE.md").is_file()
    assert (tmp_path / "AGENTS.md").is_file()
    assert (tmp_path / ".claude" / "skills" / "wardline-gate" / "SKILL.md").is_file()
    assert (tmp_path / ".agents" / "skills" / "wardline-gate" / "SKILL.md").is_file()
    assert (tmp_path / ".mcp.json").is_file()
    assert (home / ".codex" / "config.toml").is_file()
    assert "CLAUDE.md" in result.output
    assert "runtime markers: install `weft-markers` and import from `weft_markers`" in result.output


def test_install_is_idempotent(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: home)
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    CliRunner().invoke(cli, ["install", "--root", str(tmp_path)])
    result = CliRunner().invoke(cli, ["install", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "CLAUDE.md: unchanged" in result.output
    assert ".mcp.json (wardline entry): unchanged" in result.output
    assert "Codex MCP (wardline entry): unchanged" in result.output


def test_install_opt_outs(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: home)
    result = CliRunner().invoke(
        cli,
        ["install", "--root", str(tmp_path), "--no-agents-md", "--no-skill", "--no-mcp", "--no-bindings"],
    )
    assert result.exit_code == 0, result.output
    assert (tmp_path / "CLAUDE.md").is_file()
    assert not (tmp_path / "AGENTS.md").exists()
    assert not (tmp_path / ".claude").exists()
    assert not (tmp_path / ".mcp.json").exists()
    assert not (home / ".codex" / "config.toml").exists()


def test_install_no_claude_md_still_writes_agents(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: home)
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    result = CliRunner().invoke(cli, ["install", "--root", str(tmp_path), "--no-claude-md"])
    assert result.exit_code == 0, result.output
    assert not (tmp_path / "CLAUDE.md").exists()
    assert (tmp_path / "AGENTS.md").is_file()


def test_install_summary_includes_binding_lines(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: home)
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    result = CliRunner().invoke(cli, ["install", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "loomweave:" in result.output
    assert "filigree:" in result.output


def test_install_detects_filigree_from_ephemeral_port(tmp_path: Path, monkeypatch) -> None:
    # The "wire config" feature was removed: install DETECTS the sibling from its
    # published port and REPORTS it, writing no config file.
    home = tmp_path / "home"
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: home)
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    (tmp_path / ".filigree.conf").write_text("{}", encoding="utf-8")
    filigree_dir = tmp_path / ".filigree"
    filigree_dir.mkdir()
    (filigree_dir / "ephemeral.port").write_text("8628", encoding="utf-8")

    result = CliRunner().invoke(cli, ["install", "--root", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert "filigree: detected (discovered URL)" in result.output
    assert not (tmp_path / "weft.toml").exists()


def test_install_rerun_detects_filigree_when_port_appears_after_initial_install(tmp_path: Path, monkeypatch) -> None:
    # No config is written either before or after the port appears; only the
    # reported detection status changes (no URL → discovered URL).
    home = tmp_path / "home"
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: home)
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    (tmp_path / ".filigree.conf").write_text("{}", encoding="utf-8")

    initial = CliRunner().invoke(cli, ["install", "--root", str(tmp_path)])
    assert initial.exit_code == 0, initial.output
    assert "filigree: detected (no URL" in initial.output
    assert not (tmp_path / "weft.toml").exists()

    filigree_dir = tmp_path / ".filigree"
    filigree_dir.mkdir()
    (filigree_dir / "ephemeral.port").write_text("8628", encoding="utf-8")
    rerun = CliRunner().invoke(cli, ["install", "--root", str(tmp_path)])

    assert rerun.exit_code == 0, rerun.output
    assert "filigree: detected (discovered URL)" in rerun.output
    assert not (tmp_path / "weft.toml").exists()

    captured: dict[str, object] = {}

    class _FakeEmitter:
        def __init__(self, url: str, *, token: str | None = None) -> None:
            captured["url"] = url

        def emit(self, findings, *, scanned_paths=()):  # noqa: ANN001
            from wardline.core.filigree_emit import EmitResult

            captured["scanned_paths"] = tuple(scanned_paths)
            return EmitResult(reachable=True)

    monkeypatch.setattr("wardline.cli.scan.FiligreeEmitter", _FakeEmitter)
    (tmp_path / "m.py").write_text("x = 1\n", encoding="utf-8")
    scan = CliRunner().invoke(cli, ["scan", str(tmp_path)])

    assert scan.exit_code == 0, scan.output
    assert captured["url"] == "http://localhost:8628/api/weft/scan-results"
    assert captured["scanned_paths"] == ("m.py",)


def test_scan_threads_filigree_bearer_token_from_env(tmp_path: Path, monkeypatch) -> None:
    # End-to-end: a set WEFT_FEDERATION_TOKEN reaches the FiligreeEmitter through
    # the scan CLI boundary (item 5 — Wardline actually SENDS the bearer token).
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_TOKEN", raising=False)
    monkeypatch.setenv("WEFT_FEDERATION_TOKEN", "s3cr3t-bearer")
    captured: dict[str, object] = {}

    class _FakeEmitter:
        def __init__(self, url: str, *, token: str | None = None) -> None:
            captured["url"] = url
            captured["token"] = token

        def emit(self, findings, *, scanned_paths=()):  # noqa: ANN001
            from wardline.core.filigree_emit import EmitResult

            return EmitResult(reachable=True)

    monkeypatch.setattr("wardline.cli.scan.FiligreeEmitter", _FakeEmitter)
    (tmp_path / "m.py").write_text("x = 1\n", encoding="utf-8")
    scan = CliRunner().invoke(
        cli, ["scan", str(tmp_path), "--filigree-url", "http://localhost:8628/api/weft/scan-results"]
    )

    assert scan.exit_code == 0, scan.output
    assert captured["token"] == "s3cr3t-bearer"


def test_scan_threads_filigree_bearer_token_from_deprecated_env(tmp_path: Path, monkeypatch) -> None:
    # The deprecated WARDLINE_FILIGREE_TOKEN still threads through when the
    # federation-scoped name is absent — existing deployments keep working.
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    monkeypatch.delenv("WEFT_FEDERATION_TOKEN", raising=False)
    monkeypatch.setenv("WARDLINE_FILIGREE_TOKEN", "legacy-bearer")
    captured: dict[str, object] = {}

    class _FakeEmitter:
        def __init__(self, url: str, *, token: str | None = None) -> None:
            captured["url"] = url
            captured["token"] = token

        def emit(self, findings, *, scanned_paths=()):  # noqa: ANN001
            from wardline.core.filigree_emit import EmitResult

            return EmitResult(reachable=True)

    monkeypatch.setattr("wardline.cli.scan.FiligreeEmitter", _FakeEmitter)
    (tmp_path / "m.py").write_text("x = 1\n", encoding="utf-8")
    scan = CliRunner().invoke(
        cli, ["scan", str(tmp_path), "--filigree-url", "http://localhost:8628/api/weft/scan-results"]
    )

    assert scan.exit_code == 0, scan.output
    assert captured["token"] == "legacy-bearer"


def test_install_fails_2_on_malformed_mcp_json(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: home)
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    (tmp_path / ".mcp.json").write_text("{bad", encoding="utf-8")
    result = CliRunner().invoke(cli, ["install", "--root", str(tmp_path)])
    assert result.exit_code == 2
    assert "malformed .mcp.json" in result.output


def test_install_pre_commit_hook(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: home)
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    # 1. No pre-commit config: should skip
    result = CliRunner().invoke(cli, ["install", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "pre-commit" not in result.output

    # 2. Config exists, accept integration
    config_path = tmp_path / ".pre-commit-config.yaml"
    config_path.write_text("repos:\n", encoding="utf-8")
    result2 = CliRunner().invoke(cli, ["install", "--root", str(tmp_path)], input="y\n")
    assert result2.exit_code == 0, result2.output
    assert "pre-commit hook: added" in result2.output
    config_text = config_path.read_text(encoding="utf-8")
    assert "id: wardline-scan" in config_text
    assert "language: system" in config_text
    assert "pass_filenames: false" in config_text

    # 3. Running again should report already configured
    result3 = CliRunner().invoke(cli, ["install", "--root", str(tmp_path)], input="y\n")
    assert result3.exit_code == 0, result3.output
    assert "pre-commit hook: already configured" in result3.output
