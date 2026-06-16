"""A2 (wardline-4c5165e896): the `doctor` MCP twin + server-freshness self-identification.

The CLI `doctor --fix` envelope (machine_readable_doctor) is served read-only over MCP,
plus a `server` self-identification block (package version, pid, start time, source
freshness) so an agent can detect the 2026-06-06 stale-server class — a long-lived
`wardline mcp` process serving code older than the tree it scans — without shelling out.
Repair is behind an explicit `repair: true` (WRITE-gated); the default call writes nothing.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from wardline._version import __version__
from wardline.install.doctor import machine_readable_doctor
from wardline.mcp.server import WardlineMCPServer, _doctor


def _isolate(tmp_path: Path, monkeypatch) -> Path:
    home = tmp_path / "home"
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.setattr("wardline.install.mcp_json.Path.home", lambda: home)
    monkeypatch.setattr("wardline.install.mcp_json._find_wardline_command", lambda: "/bin/wardline")
    monkeypatch.setattr("wardline.install.detect.shutil.which", lambda _: None)
    return home


def test_doctor_matches_cli_machine_readable_envelope(tmp_path: Path, monkeypatch) -> None:
    """CLI==MCP by construction: the MCP doctor's check set IS machine_readable_doctor's
    (fix=False), with exactly one extra MCP-only check appended (server.freshness)."""
    _isolate(tmp_path, monkeypatch)
    cli = machine_readable_doctor(tmp_path, fix=False)
    mcp = _doctor({}, tmp_path, started_at=time.time())
    assert mcp["checks"][:-1] == cli["checks"]
    assert mcp["checks"][-1]["id"] == "server.freshness"
    # A fresh server adds no failure: ok parity holds.
    assert mcp["ok"] == cli["ok"]


def test_doctor_url_checks_report_launch_flags_with_provenance(tmp_path: Path, monkeypatch) -> None:
    """Dogfood-4 B8: doctor said loomweave.url/filigree.url 'not configured' while
    the answering server was launched with both flags and using them. The url
    checks must describe THIS process's effective config and name the source."""
    _isolate(tmp_path, monkeypatch)
    payload = _doctor(
        {},
        tmp_path,
        started_at=time.time(),
        filigree_url="http://127.0.0.1:8749/api/p/lacuna/weft/scan-results",
        loomweave_url="http://127.0.0.1:9730",
    )
    by_id = {c["id"]: c for c in payload["checks"]}
    assert by_id["loomweave.url"]["message"] == "from --loomweave-url launch flag"
    assert by_id["filigree.url"]["message"] == "from --filigree-url launch flag"
    # And honest absence names what was checked, not a bare "not configured".
    bare = _doctor({}, tmp_path, started_at=time.time())
    by_id = {c["id"]: c for c in bare["checks"]}
    assert by_id["loomweave.url"]["message"] == "not configured (no launch flag, no env)"


def test_doctor_reports_server_identity(tmp_path: Path, monkeypatch) -> None:
    _isolate(tmp_path, monkeypatch)
    now = time.time()
    payload = _doctor({}, tmp_path, started_at=now)
    server = payload["server"]
    assert server["package_version"] == __version__
    assert server["pid"] == os.getpid()
    assert server["project_root"] == str(tmp_path)
    assert server["started_at"].startswith("20")  # ISO timestamp
    assert server["fresh"] is True
    assert payload["checks"][-1] == {"id": "server.freshness", "status": "ok", "fixed": False}


def test_doctor_detects_stale_server(tmp_path: Path, monkeypatch) -> None:
    """A server started before the on-disk wardline source last changed is STALE —
    the exact dogfood-2026-06-06 failure class. The verdict must flip ok and land in
    next_actions with the restart instruction."""
    _isolate(tmp_path, monkeypatch)
    payload = _doctor({}, tmp_path, started_at=1.0)  # 1970 — everything on disk is newer
    server = payload["server"]
    assert server["fresh"] is False
    freshness = payload["checks"][-1]
    assert freshness["id"] == "server.freshness"
    assert freshness["status"] == "error"
    assert "restart" in freshness["message"].lower()
    assert payload["ok"] is False
    assert any("server.freshness" in action and "restart" in action.lower() for action in payload["next_actions"])


def test_doctor_default_is_read_only(tmp_path: Path, monkeypatch) -> None:
    home = _isolate(tmp_path, monkeypatch)
    _doctor({}, tmp_path, started_at=time.time())
    assert not (tmp_path / "CLAUDE.md").exists()
    assert not (tmp_path / ".mcp.json").exists()
    assert not (home / ".codex" / "config.toml").exists()


def test_doctor_repair_true_repairs_install_artifacts(tmp_path: Path, monkeypatch) -> None:
    home = _isolate(tmp_path, monkeypatch)
    payload = _doctor({"repair": True}, tmp_path, started_at=time.time())
    assert "wardline:instructions:" in (tmp_path / "CLAUDE.md").read_text(encoding="utf-8")
    assert (tmp_path / ".mcp.json").is_file()
    assert (home / ".codex" / "config.toml").is_file()
    assert (tmp_path / ".weft" / "wardline").is_dir()
    by_id = {c["id"]: c for c in payload["checks"]}
    assert by_id["mcp.registration"]["status"] == "ok"


def _tool_call(server: WardlineMCPServer, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    resp = server.rpc.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }
    )
    assert "error" not in resp, resp
    return resp["result"]


def test_doctor_repair_is_denied_by_no_write_policy(tmp_path: Path, monkeypatch) -> None:
    _isolate(tmp_path, monkeypatch)
    server = WardlineMCPServer(root=tmp_path, allow_write=False)
    result = _tool_call(server, "doctor", {"repair": True})
    assert result["isError"] is True
    assert "write" in result["content"][0]["text"].lower()
    # The read-only probe stays allowed under the same policy.
    ok = _tool_call(server, "doctor")
    assert "isError" not in ok


def test_doctor_with_probe_url_is_denied_by_no_network_policy(tmp_path: Path, monkeypatch) -> None:
    _isolate(tmp_path, monkeypatch)
    server = WardlineMCPServer(root=tmp_path, filigree_url="http://127.0.0.1:9/weft", allow_network=False)
    result = _tool_call(server, "doctor")
    assert result["isError"] is True
    assert "network" in result["content"][0]["text"].lower()


def test_doctor_registered_with_served_schema(tmp_path: Path, monkeypatch) -> None:
    _isolate(tmp_path, monkeypatch)
    server = WardlineMCPServer(root=tmp_path)
    resp = server.rpc.dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    doctor = next(t for t in resp["result"]["tools"] if t["name"] == "doctor")
    props = doctor["inputSchema"]["properties"]
    assert props["repair"]["type"] == "boolean"
    assert props["filigree_url"]["type"] == "string"
    # The anti-stale-server contract is advertised where agents read it.
    assert "stale" in doctor["description"].lower() or "fresh" in doctor["description"].lower()


def test_doctor_over_rpc_serves_identity(tmp_path: Path, monkeypatch) -> None:
    """End-to-end through the dispatch loop: the server's own started_at feeds the
    freshness verdict, and a just-started server is fresh."""
    import json

    _isolate(tmp_path, monkeypatch)
    server = WardlineMCPServer(root=tmp_path)
    result = _tool_call(server, "doctor")
    payload = json.loads(result["content"][0]["text"])
    assert payload["server"]["fresh"] is True
    assert payload["server"]["package_version"] == __version__
