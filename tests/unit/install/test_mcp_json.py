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


def test_preserves_operator_pinned_sibling_url_args(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A fixed-port / server-mode emit target (e.g. lacuna) pins --filigree-url /
    # --loomweave-url in the wardline entry's args. The published-port rung cannot
    # reconstruct such a URL, so these args ARE the runtime emit/discovery target.
    # merge_mcp_entry must keep them rather than normalizing to the bare canonical entry.
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "wardline": {
                        "type": "stdio",
                        "command": "OLD",
                        "args": [
                            "mcp",
                            "--root",
                            ".",
                            "--loomweave-url",
                            "http://127.0.0.1:9730",
                            "--filigree-url",
                            "http://127.0.0.1:8749/api/p/lacuna/weft/scan-results",
                        ],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    # command is refreshed to canonical (OLD -> /bin/wardline), but the pinned
    # sibling-URL args survive in the operator's ORIGINAL order (loomweave-first here).
    assert merge_mcp_entry(tmp_path) == "updated"
    entry = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))["mcpServers"]["wardline"]
    assert entry["command"] == "/bin/wardline"
    assert entry["args"] == [
        "mcp",
        "--root",
        ".",
        "--loomweave-url",
        "http://127.0.0.1:9730",
        "--filigree-url",
        "http://127.0.0.1:8749/api/p/lacuna/weft/scan-results",
    ]
    # idempotent: re-running over the already-preserved entry is a no-op (no reorder churn).
    assert merge_mcp_entry(tmp_path) == "unchanged"


def test_already_canonical_lacuna_entry_is_unchanged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The real lacuna ordering (loomweave-first) with the canonical command must be a
    # no-op for merge_mcp_entry — no spurious reorder churn on every repair.
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "wardline": {
                        "type": "stdio",
                        "command": "/bin/wardline",
                        "args": [
                            "mcp",
                            "--root",
                            ".",
                            "--loomweave-url",
                            "http://127.0.0.1:9730",
                            "--filigree-url",
                            "http://127.0.0.1:8749/api/p/lacuna/weft/scan-results",
                        ],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    assert merge_mcp_entry(tmp_path) == "unchanged"


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


# --- Filigree server-mode scoped --filigree-url persist/repair ---------------------
#
# When Filigree runs in server mode for the project, `merge_mcp_entry` injects (fresh)
# or repairs (loopback/unscoped) the wardline entry's --filigree-url to the live
# /api/p/{prefix}/ scope, so a fresh install lands a working, fail-close-safe emit
# target out of the box. An operator's remote endpoint is never rewritten.


# Isolation from the real ~/.config/filigree/server.json is provided by the autouse
# fixture in tests/unit/conftest.py; the server-mode tests below override it.


def _register_filigree_server(monkeypatch: pytest.MonkeyPatch, cfg_home: Path, *, port, projects: dict) -> None:
    sj = cfg_home / "server.json"
    sj.parent.mkdir(parents=True, exist_ok=True)
    sj.write_text(json.dumps({"port": port, "projects": projects}), encoding="utf-8")
    monkeypatch.setattr("wardline.core.config._filigree_server_config_path", lambda: sj)


def _wardline_args(tmp_path: Path) -> list:
    return json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))["mcpServers"]["wardline"]["args"]


def test_install_injects_server_mode_scoped_filigree_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    store = tmp_path / ".weft" / "filigree"
    _register_filigree_server(monkeypatch, tmp_path / "cfg", port=8749, projects={str(store): {"prefix": "lacuna"}})
    assert merge_mcp_entry(tmp_path) == "created"
    assert _wardline_args(tmp_path) == [
        "mcp",
        "--root",
        ".",
        "--filigree-url",
        "http://localhost:8749/api/p/lacuna/weft/scan-results",
    ]
    # Idempotent: the discovered scope matches the persisted flag on re-run.
    assert merge_mcp_entry(tmp_path) == "unchanged"


def test_install_repairs_unscoped_loopback_filigree_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    store = tmp_path / ".weft" / "filigree"
    _register_filigree_server(monkeypatch, tmp_path / "cfg", port=8749, projects={str(store): {"prefix": "lacuna"}})
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "wardline": {
                        "type": "stdio",
                        "command": "/bin/wardline",
                        "args": ["mcp", "--root", ".", "--filigree-url", "http://127.0.0.1:8749/api/weft/scan-results"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    assert merge_mcp_entry(tmp_path) == "updated"
    assert _wardline_args(tmp_path)[-1] == "http://localhost:8749/api/p/lacuna/weft/scan-results"


def test_install_repairs_filigree_url_in_place_preserving_loomweave_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    store = tmp_path / ".weft" / "filigree"
    _register_filigree_server(monkeypatch, tmp_path / "cfg", port=8749, projects={str(store): {"prefix": "lacuna"}})
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "wardline": {
                        "type": "stdio",
                        "command": "/bin/wardline",
                        "args": [
                            "mcp",
                            "--root",
                            ".",
                            "--loomweave-url",
                            "http://127.0.0.1:9730",
                            "--filigree-url",
                            "http://127.0.0.1:8749/api/weft/scan-results",
                        ],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    assert merge_mcp_entry(tmp_path) == "updated"
    assert _wardline_args(tmp_path) == [
        "mcp",
        "--root",
        ".",
        "--loomweave-url",
        "http://127.0.0.1:9730",
        "--filigree-url",
        "http://localhost:8749/api/p/lacuna/weft/scan-results",
    ]


def test_install_never_rewrites_operator_remote_filigree_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    store = tmp_path / ".weft" / "filigree"
    _register_filigree_server(monkeypatch, tmp_path / "cfg", port=8749, projects={str(store): {"prefix": "lacuna"}})
    remote = "https://filigree.example.com/api/weft/scan-results"
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "wardline": {
                        "type": "stdio",
                        "command": "/bin/wardline",
                        "args": ["mcp", "--root", ".", "--filigree-url", remote],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    # A deliberate non-loopback endpoint is preserved verbatim (no-op).
    assert merge_mcp_entry(tmp_path) == "unchanged"
    assert _wardline_args(tmp_path)[-1] == remote
