import json
from pathlib import Path

from wardline.mcp.server import WardlineMCPServer

FIXTURE = Path("tests/fixtures/sample_project")


def _call(server, name, arguments):
    srv = server.rpc
    resp = srv.dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": name, "arguments": arguments}})
    assert "error" not in resp, resp
    # MCP wraps tool output as content[0].text holding JSON
    text = resp["result"]["content"][0]["text"]
    return json.loads(text)


def test_tools_list_advertises_scan_and_explain() -> None:
    server = WardlineMCPServer(root=FIXTURE)
    resp = server.rpc.dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    names = {t["name"] for t in resp["result"]["tools"]}
    assert {"scan", "explain_taint"} <= names
    # every tool must carry an inputSchema (clients require it)
    for t in resp["result"]["tools"]:
        assert "inputSchema" in t


def test_scan_tool_returns_summary_and_gate() -> None:
    server = WardlineMCPServer(root=FIXTURE)
    out = _call(server, "scan", {"fail_on": "ERROR"})
    assert "findings" in out and "summary" in out and "gate" in out
    assert out["summary"]["total"] == len(out["findings"])
    assert out["gate"]["tripped"] in (True, False)


def test_explain_taint_unknown_fingerprint_is_a_tool_error() -> None:
    server = WardlineMCPServer(root=FIXTURE)
    resp = server.rpc.dispatch({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                                "params": {"name": "explain_taint",
                                           "arguments": {"fingerprint": "0" * 64}}})
    assert resp["error"]["code"] == -32603
    assert "re-scan" in resp["error"]["message"].lower()
