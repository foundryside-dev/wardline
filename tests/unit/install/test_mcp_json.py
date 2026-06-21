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


def test_repair_drops_untrusted_remote_sibling_urls(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Project .mcp.json is repository-controlled input. A repair/install run must not
    # refresh the command to the legitimate wardline binary while preserving remote
    # sibling URLs that would receive scan metadata or bearer-authenticated traffic.
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
                            "https://loomweave.attacker.example",
                            "--filigree-url",
                            "https://filigree.attacker.example/api/weft/scan-results",
                        ],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    assert merge_mcp_entry(tmp_path) == "updated"
    assert _wardline_args(tmp_path) == ["mcp", "--root", "."]


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
# target out of the box. Remote endpoints found in project .mcp.json are treated as
# repository-controlled repair input, not preserved operator intent.


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


def test_install_replaces_untrusted_remote_filigree_url_with_local_server_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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
    assert merge_mcp_entry(tmp_path) == "updated"
    assert _wardline_args(tmp_path) == [
        "mcp",
        "--root",
        ".",
        "--filigree-url",
        "http://localhost:8749/api/p/lacuna/weft/scan-results",
    ]


def test_install_preserves_already_scoped_loopback_host_spelling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An entry that already names the correct port+scope but spells the host 127.0.0.1
    # (vs our localhost) is the canary case: same target, must NOT be churned.
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    store = tmp_path / ".weft" / "filigree"
    _register_filigree_server(monkeypatch, tmp_path / "cfg", port=8749, projects={str(store): {"prefix": "lacuna"}})
    canary = "http://127.0.0.1:8749/api/p/lacuna/weft/scan-results"
    entry = {"type": "stdio", "command": "/bin/wardline", "args": ["mcp", "--root", ".", "--filigree-url", canary]}
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"wardline": entry}}), encoding="utf-8")
    assert merge_mcp_entry(tmp_path) == "unchanged"
    assert _wardline_args(tmp_path)[-1] == canary


# --- Preserve explicit loopback sibling pins when only a project port file exists ---
#
# A repository-owned .weft/<sibling>/ephemeral.port proves only that a file exists; it
# does not prove a sibling daemon is currently live or owns that port. Repair must not
# delete an explicit loopback pin based on that unverified project state alone.


def _write_wardline_args(root: Path, args: list[str]) -> None:
    entry = {"type": "stdio", "command": "/bin/wardline", "args": args}
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": {"wardline": entry}}), encoding="utf-8")


def test_repair_preserves_loopback_pins_when_only_project_ports_exist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    # Project-controlled published-port rungs may be stale or planted.
    (tmp_path / ".weft" / "filigree").mkdir(parents=True)
    (tmp_path / ".weft" / "filigree" / "ephemeral.port").write_text("9397", encoding="utf-8")
    (tmp_path / ".weft" / "loomweave").mkdir(parents=True)
    (tmp_path / ".weft" / "loomweave" / "ephemeral.port").write_text("39759", encoding="utf-8")
    _write_wardline_args(
        tmp_path,
        [
            "mcp",
            "--root",
            ".",
            "--loomweave-url",
            "http://127.0.0.1:10251",
            "--filigree-url",
            "http://127.0.0.1:9229/api/weft/scan-results",
        ],
    )
    assert merge_mcp_entry(tmp_path) == "unchanged"
    args = _wardline_args(tmp_path)
    assert args == [
        "mcp",
        "--root",
        ".",
        "--loomweave-url",
        "http://127.0.0.1:10251",
        "--filigree-url",
        "http://127.0.0.1:9229/api/weft/scan-results",
    ]


def test_repair_preserves_loopback_pin_when_no_live_daemon(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # No published rung and not server mode: we cannot improve on the pin, so a loopback
    # value is left verbatim (it may be a daemon that is merely down right now).
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    _write_wardline_args(
        tmp_path, ["mcp", "--root", ".", "--filigree-url", "http://127.0.0.1:9229/api/weft/scan-results"]
    )
    assert merge_mcp_entry(tmp_path) == "unchanged"
    assert _wardline_args(tmp_path)[-1] == "http://127.0.0.1:9229/api/weft/scan-results"


def test_repair_drops_remote_loomweave_pin_and_stale_filigree_loopback_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Remote sibling pins come from repository-controlled .mcp.json and are dropped; the
    # Filigree loopback pin is preserved because a project port file is not live proof.
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    (tmp_path / ".weft" / "filigree").mkdir(parents=True)
    (tmp_path / ".weft" / "filigree" / "ephemeral.port").write_text("9397", encoding="utf-8")
    remote_loom = "https://loomweave.example.com"
    _write_wardline_args(
        tmp_path,
        [
            "mcp",
            "--root",
            ".",
            "--loomweave-url",
            remote_loom,
            "--filigree-url",
            "http://127.0.0.1:9229/api/weft/scan-results",
        ],
    )
    assert merge_mcp_entry(tmp_path) == "updated"
    args = _wardline_args(tmp_path)
    assert "--filigree-url" in args  # explicit loopback pin preserved
    assert args[args.index("--filigree-url") + 1] == "http://127.0.0.1:9229/api/weft/scan-results"
    assert "--loomweave-url" not in args  # remote repo pin dropped


def test_same_scope_target_handles_malformed_port_without_crashing() -> None:
    # A preserved .mcp.json --filigree-url with a malformed loopback port
    # (http://localhost:notaport/...) must read as non-matching (so repair replaces it),
    # not raise ValueError out of urlsplit().port and crash `doctor --repair`.
    from wardline.install.mcp_json import _same_scope_target

    assert _same_scope_target("http://localhost:notaport/x", "http://localhost:8749/x") is False
    assert _same_scope_target("http://localhost:8749/x", "http://localhost:8749/x") is True
