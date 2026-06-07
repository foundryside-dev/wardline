import json
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
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
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
    # Bindings are no longer wired into config — repair only DETECTS siblings and
    # ensures the .weft/wardline/ state dir exists. No config file is written.
    assert "bindings: detected" in result.output
    assert (tmp_path / ".mcp.json").is_file()
    assert (home / ".codex" / "config.toml").is_file()
    assert (tmp_path / ".weft" / "wardline").is_dir()
    assert not (tmp_path / "weft.toml").exists()


def test_doctor_passes_after_repair(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: home)
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)

    repair = CliRunner().invoke(cli, ["doctor", "--root", str(tmp_path), "--repair"])
    assert repair.exit_code == 0, repair.output

    result = CliRunner().invoke(cli, ["doctor", "--root", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert "wardline doctor: ok" in result.output


def test_doctor_fix_emits_shared_machine_readable_shape(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_TOKEN", raising=False)
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: home)
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    (tmp_path / ".filigree.conf").write_text("{}", encoding="utf-8")
    filigree_dir = tmp_path / ".filigree"
    filigree_dir.mkdir()
    (filigree_dir / "ephemeral.port").write_text("8628", encoding="utf-8")

    result = CliRunner().invoke(cli, ["doctor", "--root", str(tmp_path), "--fix"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["ok"] is True
    assert payload["next_actions"] == []
    checks = {check["id"]: check for check in payload["checks"]}
    for check_id in (
        "wardline.config",
        "mcp.registration",
        "marker_package",
        "loomweave.url",
        "filigree.url",
        "decorator_grammar",
        "scan.output_path",
        "auth.token",
    ):
        assert checks[check_id]["status"] == "ok"
        assert isinstance(checks[check_id]["fixed"], bool)
    assert checks["mcp.registration"]["fixed"] is True


def test_doctor_reports_present_but_broken_weft_toml_as_error(tmp_path: Path, monkeypatch) -> None:
    # C-9c makes load() silently fall back to built-in defaults on an unparseable
    # shared weft.toml; doctor is the only compensating operator-visibility signal.
    # A PRESENT-but-broken weft.toml must surface as wardline.config status=="error"
    # (never the silent-default "ok"), else a misconfigured operator gets default
    # behavior with no diagnostic. Guards the _check_config present-but-broken arm.
    home = tmp_path / "home"
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: home)
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    (tmp_path / "weft.toml").write_text("[wardline]\nrules = \n", encoding="utf-8")  # invalid TOML

    result = CliRunner().invoke(cli, ["doctor", "--root", str(tmp_path), "--fix"])

    payload = json.loads(result.output)
    checks = {check["id"]: check for check in payload["checks"]}
    assert checks["wardline.config"]["status"] == "error"
    assert "weft.toml" in checks["wardline.config"]["message"]


def test_doctor_fix_reports_filigree_url_ok_from_env(tmp_path: Path, monkeypatch) -> None:
    # The "upgrade commented binding when a port appears" feature was removed: doctor
    # no longer writes config and the filigree.url check is now ENV-ONLY (a published
    # port is a scan-time discovery concern, not a doctor concern). When the env var
    # is set to a valid URL, the check is ok; doctor writes no config file.
    home = tmp_path / "home"
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_TOKEN", raising=False)
    monkeypatch.setenv("WARDLINE_FILIGREE_URL", "http://localhost:8628/api/weft/scan-results")
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: home)
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    (tmp_path / ".filigree.conf").write_text("{}", encoding="utf-8")

    result = CliRunner().invoke(cli, ["doctor", "--root", str(tmp_path), "--fix"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    checks = {check["id"]: check for check in payload["checks"]}
    assert checks["filigree.url"]["status"] == "ok"
    assert not (tmp_path / "weft.toml").exists()


def test_doctor_accepts_filigree_url_flag_and_reports_not_configured(tmp_path: Path, monkeypatch) -> None:
    # No filigree wiring (no .mcp.json arg, no env, no port) => filigree.auth is ok/not-configured,
    # so doctor does no network and the new flag is accepted.
    home = tmp_path / "home"
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.delenv("WEFT_FEDERATION_TOKEN", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_TOKEN", raising=False)
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: home)
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)

    repair = CliRunner().invoke(cli, ["doctor", "--root", str(tmp_path), "--repair"])
    assert repair.exit_code == 0, repair.output

    result = CliRunner().invoke(cli, ["doctor", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "filigree.auth" in result.output


def test_doctor_fix_json_includes_filigree_auth_check(tmp_path: Path, monkeypatch) -> None:
    import json as _json

    home = tmp_path / "home"
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.delenv("WEFT_FEDERATION_TOKEN", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_TOKEN", raising=False)
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: home)
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)

    result = CliRunner().invoke(cli, ["doctor", "--root", str(tmp_path), "--fix"])
    payload = _json.loads(result.output)
    ids = [c["id"] for c in payload["checks"]]
    assert "filigree.auth" in ids
