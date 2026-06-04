from __future__ import annotations

import json
from pathlib import Path

from wardline.mcp.server import WardlineMCPServer

_SRC = "from wardline.decorators import trusted\n@trusted\ndef f():\n    return 1\n"


def _mcp_call(server: WardlineMCPServer, name: str, arguments: dict[str, object]) -> dict[str, object]:
    resp = server.rpc.dispatch(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
    )
    assert "error" not in resp, resp
    return json.loads(resp["result"]["content"][0]["text"])


def test_mcp_advertises_decorator_coverage_tool(tmp_path: Path) -> None:
    server = WardlineMCPServer(root=tmp_path)
    resp = server.rpc.dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    names = {tool["name"] for tool in resp["result"]["tools"]}
    assert "decorator_coverage" in names


def test_mcp_decorator_coverage_returns_core_shape(tmp_path: Path) -> None:
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")

    out = _mcp_call(WardlineMCPServer(root=tmp_path), "decorator_coverage", {})

    assert out["summary"]["total"] == 1
    assert out["rows"][0]["qualname"] == "svc.f"
    assert out["rows"][0]["work"]["reason"] == "filigree not configured"
