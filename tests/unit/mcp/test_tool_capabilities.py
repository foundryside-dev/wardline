from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import wardline.mcp.server as server_mod
from wardline.mcp.server import WardlineMCPServer
from wardline.mcp.tooling import Tool, ToolCapability


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


def test_tools_list_exposes_tool_capability_classes() -> None:
    server = WardlineMCPServer(root=Path("tests/fixtures/sample_project"))
    resp = server.rpc.dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    tools = {tool["name"]: tool for tool in resp["result"]["tools"]}

    assert "read" in tools["scan"]["capabilities"]
    assert "network" in tools["judge"]["capabilities"]
    assert "write" in tools["baseline"]["capabilities"]
    assert {"network", "write"} <= set(tools["file_finding"]["capabilities"])


def test_scan_tool_annotations_match_possible_integration_side_effects() -> None:
    server = WardlineMCPServer(root=Path("tests/fixtures/sample_project"))
    resp = server.rpc.dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    scan = next(tool for tool in resp["result"]["tools"] if tool["name"] == "scan")

    assert scan["annotations"]["readOnlyHint"] is False
    assert scan["annotations"]["openWorldHint"] is True
    assert {"network", "write"} <= set(scan["capabilities"])


def test_local_scan_without_integrations_is_allowed_under_hardened_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    called = False

    def fake_scan(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal called
        called = True
        return {"ok": True}

    monkeypatch.setattr(server_mod, "_scan", fake_scan)
    server = WardlineMCPServer(root=tmp_path, allow_network=False, allow_write=False)

    result = _tool_call(server, "scan")

    assert result.get("isError") is not True
    assert result["structuredContent"] == {"ok": True}
    assert called is True


def test_no_network_policy_denies_network_tool_before_handler(tmp_path: Path) -> None:
    called = False
    server = WardlineMCPServer(root=tmp_path, allow_network=False)

    def handler(args: dict[str, Any], root: Path) -> dict[str, Any]:
        nonlocal called
        called = True
        return {"ok": True}

    server.add_tool(
        Tool(
            name="net_tool",
            description="network test tool",
            input_schema={"type": "object"},
            handler=handler,
            capabilities=frozenset({ToolCapability.READ, ToolCapability.NETWORK}),
        )
    )

    result = _tool_call(server, "net_tool")

    assert result.get("isError") is True
    assert "network" in result["content"][0]["text"].lower()
    assert called is False


def test_no_write_policy_denies_mutating_tool_before_handler(tmp_path: Path) -> None:
    called = False
    server = WardlineMCPServer(root=tmp_path, allow_write=False)

    def handler(args: dict[str, Any], root: Path) -> dict[str, Any]:
        nonlocal called
        called = True
        return {"ok": True}

    server.add_tool(
        Tool(
            name="write_tool",
            description="write test tool",
            input_schema={"type": "object"},
            handler=handler,
            capabilities=frozenset({ToolCapability.READ, ToolCapability.WRITE}),
        )
    )

    result = _tool_call(server, "write_tool")

    assert result["isError"] is True
    assert "write" in result["content"][0]["text"].lower()
    assert called is False


def test_builtin_judge_is_denied_by_no_network_policy(tmp_path: Path) -> None:
    server = WardlineMCPServer(root=tmp_path, allow_network=False)
    result = _tool_call(server, "judge")

    assert result["isError"] is True
    text = result["content"][0]["text"].lower()
    assert "judge" in text
    assert "network" in text


def test_builtin_baseline_is_denied_by_no_write_policy(tmp_path: Path) -> None:
    server = WardlineMCPServer(root=tmp_path, allow_write=False)
    result = _tool_call(server, "baseline")

    assert result["isError"] is True
    text = result["content"][0]["text"].lower()
    assert "baseline" in text
    assert "write" in text


def test_waiver_add_entity_symbol_is_denied_by_no_network_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WARDLINE_LOOMWEAVE_URL", "http://localhost:9100")
    called = False

    def fake_waiver_add(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal called
        called = True
        return {"ok": True}

    monkeypatch.setattr(server_mod, "_waiver_add", fake_waiver_add)
    server = WardlineMCPServer(root=tmp_path, allow_network=False)
    result = _tool_call(
        server,
        "waiver_add",
        {
            "fingerprint": "a" * 64,
            "reason": "validated upstream",
            "expires": "2026-12-31",
            "entity_symbol": "pkg.mod.leaky",
        },
    )

    assert result["isError"] is True
    assert "network" in result["content"][0]["text"].lower()
    assert called is False


def test_waiver_add_entity_id_is_not_network_gated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WARDLINE_LOOMWEAVE_URL", "http://localhost:9100")
    called = False

    def fake_waiver_add(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal called
        called = True
        return {"ok": True}

    monkeypatch.setattr(server_mod, "_waiver_add", fake_waiver_add)
    server = WardlineMCPServer(root=tmp_path, allow_network=False)
    result = _tool_call(
        server,
        "waiver_add",
        {
            "fingerprint": "a" * 64,
            "reason": "validated upstream",
            "expires": "2026-12-31",
            "entity_id": "loomweave:eid:held",
        },
    )

    assert result.get("isError") is not True
    assert result["structuredContent"] == {"ok": True}
    assert called is True


def test_waiver_add_entity_id_wins_over_symbol_without_network_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WARDLINE_LOOMWEAVE_URL", "http://localhost:9100")
    called = False

    def fake_waiver_add(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal called
        called = True
        return {"ok": True}

    monkeypatch.setattr(server_mod, "_waiver_add", fake_waiver_add)
    server = WardlineMCPServer(root=tmp_path, allow_network=False)
    result = _tool_call(
        server,
        "waiver_add",
        {
            "fingerprint": "a" * 64,
            "reason": "validated upstream",
            "expires": "2026-12-31",
            "entity_id": "loomweave:eid:held",
            "entity_symbol": "pkg.mod.leaky",
        },
    )

    assert result.get("isError") is not True
    assert result["structuredContent"] == {"ok": True}
    assert called is True


# Sibling URL config keys (`[wardline.filigree].url`) were removed: URLs resolve only
# via flag / env var / published `<root>/.weft/<sibling>/ephemeral.port`. The intent —
# a resolved sibling URL is denied by the no-write policy — is preserved via the
# surviving resolution rungs (env var + published port).
@pytest.mark.parametrize("source", ["environment", "published_port"])
def test_scan_with_resolved_filigree_url_is_denied_by_no_write_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source: str
) -> None:
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    args: dict[str, Any] = {}
    if source == "published_port":
        port_file = tmp_path / ".weft" / "filigree" / "ephemeral.port"
        port_file.parent.mkdir(parents=True, exist_ok=True)
        port_file.write_text("8628", encoding="utf-8")
    else:
        monkeypatch.setenv("WARDLINE_FILIGREE_URL", "http://localhost:8628/api/weft/scan-results")

    called = False

    def fake_scan(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal called
        called = True
        return {"ok": True}

    monkeypatch.setattr(server_mod, "_scan", fake_scan)
    server = WardlineMCPServer(root=tmp_path, allow_write=False)
    result = _tool_call(server, "scan", args)

    assert result["isError"] is True
    assert "write" in result["content"][0]["text"].lower()
    assert called is False


def test_doctor_with_project_published_port_is_not_denied_by_no_network_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("WARDLINE_FILIGREE_URL", raising=False)
    port_file = tmp_path / ".weft" / "filigree" / "ephemeral.port"
    port_file.parent.mkdir(parents=True, exist_ok=True)
    port_file.write_text("8628", encoding="utf-8")
    called = False

    def fake_doctor(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal called
        called = True
        return {"ok": True}

    monkeypatch.setattr(server_mod, "_doctor", fake_doctor)
    server = WardlineMCPServer(root=tmp_path, allow_network=False)
    result = _tool_call(server, "doctor", {"repair": False})

    assert result.get("isError") is not True
    assert called is True


@pytest.mark.parametrize("source", ["environment", "published_port"])
def test_dossier_with_resolved_loomweave_url_is_denied_by_no_network_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source: str
) -> None:
    monkeypatch.delenv("WARDLINE_LOOMWEAVE_URL", raising=False)
    args: dict[str, Any] = {"entity": "pkg.mod.func"}
    if source == "published_port":
        port_file = tmp_path / ".weft" / "loomweave" / "ephemeral.port"
        port_file.parent.mkdir(parents=True, exist_ok=True)
        port_file.write_text("9100", encoding="utf-8")
    else:
        monkeypatch.setenv("WARDLINE_LOOMWEAVE_URL", "http://localhost:9100")

    called = False

    def fake_dossier(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal called
        called = True
        return {"ok": True}

    monkeypatch.setattr(server_mod, "_dossier", fake_dossier)
    server = WardlineMCPServer(root=tmp_path, allow_network=False)
    result = _tool_call(server, "dossier", args)

    assert result["isError"] is True
    assert "network" in result["content"][0]["text"].lower()
    assert called is False
