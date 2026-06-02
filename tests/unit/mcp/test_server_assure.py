"""MCP `assure` tool: the pre-trust-decision trust-surface COVERAGE read.

CLI and MCP are identical by construction (CLAUDE.md tenet), and the MCP tool
result must EQUAL the core posture (== the CLI JSON). A bad path/config surfaces
as a tool-EXECUTION isError result, never a raw crash.
"""

import json
from pathlib import Path

from wardline.core.assure import build_posture
from wardline.mcp.server import WardlineMCPServer

_TRUSTED = "from wardline.decorators import trusted\n@trusted\ndef produce(p):\n    return p\n"


def _proj(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_TRUSTED, encoding="utf-8")
    return proj


def _mcp_call(server, name, arguments):
    resp = server.rpc.dispatch(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
    )
    assert "error" not in resp, resp
    return json.loads(resp["result"]["content"][0]["text"])


def test_mcp_advertises_the_assure_tool() -> None:
    server = WardlineMCPServer(root=Path("tests/fixtures/sample_project"))
    resp = server.rpc.dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    names = {t["name"] for t in resp["result"]["tools"]}
    assert "assure" in names


def test_mcp_assure_result_equals_core_posture(tmp_path: Path) -> None:
    # MCP-result == core posture (== CLI JSON): identical by construction.
    proj = _proj(tmp_path)
    out = _mcp_call(WardlineMCPServer(root=proj), "assure", {"path": str(proj)})
    expected = build_posture(proj, confine_to_root=True).to_dict()
    assert out == expected


def test_mcp_assure_no_path_defaults_to_root(tmp_path: Path) -> None:
    # No `path` arg → posture of the whole root, still == core.
    proj = _proj(tmp_path)
    out = _mcp_call(WardlineMCPServer(root=proj), "assure", {})
    expected = build_posture(proj, confine_to_root=True).to_dict()
    assert out == expected


def test_mcp_assure_missing_config_is_iserror(tmp_path: Path) -> None:
    # A config that doesn't exist is a tool-EXECUTION error → isError RESULT, not a
    # JSON-RPC error and not a raw crash.
    proj = _proj(tmp_path)
    resp = WardlineMCPServer(root=proj).rpc.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "assure", "arguments": {"config": "nope.yaml"}},
        }
    )
    assert "error" not in resp
    assert resp["result"].get("isError") is True


def test_mcp_assure_escaping_path_is_iserror(tmp_path: Path) -> None:
    # A path that escapes root must be refused as an isError RESULT (confinement),
    # never read outside the project.
    proj = _proj(tmp_path)
    resp = WardlineMCPServer(root=proj).rpc.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "assure", "arguments": {"path": "../../etc"}},
        }
    )
    assert "error" not in resp
    assert resp["result"].get("isError") is True
