import json
from pathlib import Path

import pytest

from wardline.core.errors import WardlineError
from wardline.install.mcp_json import install_codex_mcp, merge_mcp_entry

_WARDLINE_ENTRY = {"type": "stdio", "command": "/bin/wardline", "args": ["mcp", "--root", "."]}


def test_create_when_absent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    assert merge_mcp_entry(tmp_path) == "created"
    data = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))
    assert data["mcpServers"]["wardline"] == _WARDLINE_ENTRY


def test_merge_rejects_symlinked_mcp_json(tmp_path: Path) -> None:
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    (tmp_path / ".mcp.json").symlink_to(outside)

    with pytest.raises(WardlineError, match="symlink"):
        merge_mcp_entry(tmp_path)

    assert outside.read_text(encoding="utf-8") == "{}"


def test_merge_preserves_siblings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"filigree": {"type": "stdio", "command": "filigree-mcp", "args": []}}}),
        encoding="utf-8",
    )
    assert merge_mcp_entry(tmp_path) == "updated"
    data = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))
    assert data["mcpServers"]["filigree"]["command"] == "filigree-mcp"
    assert data["mcpServers"]["wardline"] == _WARDLINE_ENTRY


def test_idempotent_when_entry_matches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    merge_mcp_entry(tmp_path)
    assert merge_mcp_entry(tmp_path) == "unchanged"


def test_malformed_json_raises_without_clobbering(tmp_path: Path) -> None:
    bad = tmp_path / ".mcp.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(WardlineError):
        merge_mcp_entry(tmp_path)
    assert bad.read_text(encoding="utf-8") == "{not json"


def test_mcpservers_non_dict_raises(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": []}), encoding="utf-8")
    with pytest.raises(WardlineError):
        merge_mcp_entry(tmp_path)


def test_mcpservers_null_is_treated_as_absent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": None, "other": 1}), encoding="utf-8")
    assert merge_mcp_entry(tmp_path) == "updated"
    data = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))
    assert data["mcpServers"]["wardline"] == _WARDLINE_ENTRY
    assert data["other"] == 1  # unrelated top-level keys preserved


def test_replaces_stale_wardline_entry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"wardline": {"type": "stdio", "command": "OLD", "args": []}}}),
        encoding="utf-8",
    )
    assert merge_mcp_entry(tmp_path) == "updated"
    data = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))
    assert data["mcpServers"]["wardline"] == _WARDLINE_ENTRY  # stale entry replaced


def test_install_codex_mcp_creates_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: home)
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")

    assert install_codex_mcp(tmp_path) == "created"

    content = (home / ".codex" / "config.toml").read_text(encoding="utf-8")
    assert "[mcp_servers.wardline]" in content
    assert 'command = "/bin/wardline"' in content
    assert 'args = ["mcp"]' in content


def test_install_codex_mcp_preserves_sibling_servers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    config = home / ".codex" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text('[mcp_servers.filigree]\ncommand = "filigree-mcp"\nargs = []\n', encoding="utf-8")
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: home)
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")

    assert install_codex_mcp(tmp_path) == "updated"

    content = config.read_text(encoding="utf-8")
    assert "[mcp_servers.filigree]" in content
    assert "[mcp_servers.wardline]" in content


def test_install_codex_mcp_is_idempotent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: home)
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")

    assert install_codex_mcp(tmp_path) == "created"
    assert install_codex_mcp(tmp_path) == "unchanged"


def test_install_codex_mcp_replaces_stale_wardline_entry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    config = home / ".codex" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text(
        '[mcp_servers.wardline]\ncommand = "wardline"\nargs = ["mcp", "--root", "/tmp/other"]\n',
        encoding="utf-8",
    )
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: home)
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")

    assert install_codex_mcp(tmp_path) == "updated"

    content = config.read_text(encoding="utf-8")
    assert 'command = "/bin/wardline"' in content
    assert 'args = ["mcp"]' in content
    assert "--root" not in content
