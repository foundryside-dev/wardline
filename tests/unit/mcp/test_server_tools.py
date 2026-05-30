import json
from pathlib import Path

from wardline.mcp.server import WardlineMCPServer

FIXTURE = Path("tests/fixtures/sample_project")

# A @trusted boundary returning an @external_boundary-tainted value: PY-WL-101
# ERROR defect. sample_project itself is clean, so we build a leaky tmp project.
_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def _leaky_project(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")
    return proj


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


def test_scan_tool_returns_summary_and_gate(tmp_path: Path) -> None:
    # Exercise the MCP _scan gate wiring + Finding.to_jsonl() serialization through
    # the envelope on a project that actually trips the gate (the prior assertion,
    # `tripped in (True, False)`, was tautologically true).
    root = _leaky_project(tmp_path)
    server = WardlineMCPServer(root=root)
    out = _call(server, "scan", {"fail_on": "ERROR"})
    assert "findings" in out and "summary" in out and "gate" in out
    assert out["summary"]["total"] == len(out["findings"])
    assert out["summary"]["active"] >= 1
    assert out["gate"]["tripped"] is True
    assert any(f["rule_id"] == "PY-WL-101" for f in out["findings"])


def test_explain_taint_success_through_mcp(tmp_path: Path) -> None:
    # scan to get a real PY-WL-101 fingerprint, then explain it through the MCP
    # layer: NOT isError, and the projected provenance fields are populated.
    root = _leaky_project(tmp_path)
    server = WardlineMCPServer(root=root)
    scan_out = _call(server, "scan", {})
    leak = next(f for f in scan_out["findings"] if f["rule_id"] == "PY-WL-101")
    fp = leak["fingerprint"]

    resp = server.rpc.dispatch({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                                "params": {"name": "explain_taint",
                                           "arguments": {"fingerprint": fp}}})
    assert "error" not in resp, resp
    assert resp["result"].get("isError") is not True, resp["result"]
    out = json.loads(resp["result"]["content"][0]["text"])
    assert out["immediate_tainted_callee"] == "read_raw"
    assert out["source_boundary_qualname"] == "svc.read_raw"
    assert "tier_in" in out and "tier_out" in out

    # path+line success case: the path is a MATCH KEY (relative posix), confined
    # for escape-rejection but passed through unmodified to match the finding.
    out2 = _call(server, "explain_taint",
                 {"path": out["location"]["path"], "line": out["location"]["line"]})
    assert out2["fingerprint"] == fp


def test_explain_taint_unknown_fingerprint_is_an_iserror_result() -> None:
    # A stale/unknown fingerprint is a tool-EXECUTION error the agent must act on:
    # it returns as an isError RESULT (content the client reliably surfaces), NOT a
    # JSON-RPC error that clients may swallow as a transport fault.
    server = WardlineMCPServer(root=FIXTURE)
    resp = server.rpc.dispatch({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                                "params": {"name": "explain_taint",
                                           "arguments": {"fingerprint": "0" * 64}}})
    assert "error" not in resp, resp
    assert resp["result"]["isError"] is True
    assert "re-scan" in resp["result"]["content"][0]["text"].lower()


def test_unknown_tool_name_is_a_jsonrpc_error() -> None:
    # A genuinely-unknown tool name is a PROTOCOL fault (caller bug), so it stays a
    # JSON-RPC error — not an isError result.
    server = WardlineMCPServer(root=FIXTURE)
    resp = server.rpc.dispatch({"jsonrpc": "2.0", "id": 11, "method": "tools/call",
                                "params": {"name": "does_not_exist", "arguments": {}}})
    assert "result" not in resp, resp
    assert resp["error"]["code"] == -32603
    assert "does_not_exist" in resp["error"]["message"]
