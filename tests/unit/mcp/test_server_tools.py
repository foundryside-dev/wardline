import json
from pathlib import Path
from typing import Any

from wardline.mcp.protocol import McpError
from wardline.mcp.server import Tool, WardlineMCPServer

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
    resp = srv.dispatch(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
    )
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


def test_scan_tool_summary_includes_unanalyzed(tmp_path: Path) -> None:
    # (b) The MCP scan result must expose the unanalyzed count so a silently-skipped
    # file reaches the agent, not just stderr. An unparseable file makes it >= 1.
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "bad.py").write_text("def f(:\n", encoding="utf-8")
    server = WardlineMCPServer(root=proj)
    out = _call(server, "scan", {})
    assert "unanalyzed" in out["summary"]
    assert out["summary"]["unanalyzed"] >= 1


def test_explain_taint_success_through_mcp(tmp_path: Path) -> None:
    # scan to get a real PY-WL-101 fingerprint, then explain it through the MCP
    # layer: NOT isError, and the projected provenance fields are populated.
    root = _leaky_project(tmp_path)
    server = WardlineMCPServer(root=root)
    scan_out = _call(server, "scan", {})
    leak = next(f for f in scan_out["findings"] if f["rule_id"] == "PY-WL-101")
    fp = leak["fingerprint"]

    resp = server.rpc.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "explain_taint", "arguments": {"fingerprint": fp}},
        }
    )
    assert "error" not in resp, resp
    assert resp["result"].get("isError") is not True, resp["result"]
    out = json.loads(resp["result"]["content"][0]["text"])
    assert out["immediate_tainted_callee"] == "read_raw"
    assert out["source_boundary_qualname"] == "svc.read_raw"
    assert "tier_in" in out and "tier_out" in out

    # path+line success case: the path is a MATCH KEY (relative posix), confined
    # for escape-rejection but passed through unmodified to match the finding.
    out2 = _call(server, "explain_taint", {"path": out["location"]["path"], "line": out["location"]["line"]})
    assert out2["fingerprint"] == fp


def test_explain_taint_unknown_fingerprint_is_an_iserror_result() -> None:
    # A stale/unknown fingerprint is a tool-EXECUTION error the agent must act on:
    # it returns as an isError RESULT (content the client reliably surfaces), NOT a
    # JSON-RPC error that clients may swallow as a transport fault.
    server = WardlineMCPServer(root=FIXTURE)
    resp = server.rpc.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {"name": "explain_taint", "arguments": {"fingerprint": "0" * 64}},
        }
    )
    assert "error" not in resp, resp
    assert resp["result"]["isError"] is True
    assert "re-scan" in resp["result"]["content"][0]["text"].lower()


def test_unexpected_handler_exception_is_an_iserror_result() -> None:
    # An UNEXPECTED exception raised deep in a tool handler (e.g. a KeyError/ValueError
    # from the taint engine mid-scan) is a tool-EXECUTION crash. It must surface as an
    # isError RESULT — carrying the actionable detail in content the client reliably
    # relays — NOT as a top-level JSON-RPC -32603 error whose message clients may drop.
    server = WardlineMCPServer(root=FIXTURE)

    def boom(args: dict[str, Any], root: Path) -> Any:
        raise ValueError("taint engine exploded")

    server.add_tool(Tool(name="boom", description="", input_schema={"type": "object"}, handler=boom))
    resp = server.rpc.dispatch(
        {"jsonrpc": "2.0", "id": 13, "method": "tools/call", "params": {"name": "boom", "arguments": {}}}
    )
    assert "error" not in resp, resp
    assert resp["result"]["isError"] is True
    text = resp["result"]["content"][0]["text"]
    assert "taint engine exploded" in text
    assert "wardline internal error" in text


def test_handler_raising_mcperror_stays_a_jsonrpc_error() -> None:
    # A handler that DELIBERATELY raises McpError is signalling a protocol fault from
    # within the tool — that must still propagate as a JSON-RPC error, NOT be swallowed
    # into an isError result by the broad crash-fallback.
    server = WardlineMCPServer(root=FIXTURE)

    def proto_fault(args: dict[str, Any], root: Path) -> Any:
        raise McpError("deliberate protocol fault")

    server.add_tool(Tool(name="pf", description="", input_schema={"type": "object"}, handler=proto_fault))
    resp = server.rpc.dispatch(
        {"jsonrpc": "2.0", "id": 14, "method": "tools/call", "params": {"name": "pf", "arguments": {}}}
    )
    assert "result" not in resp, resp
    assert resp["error"]["code"] == -32603
    assert "deliberate protocol fault" in resp["error"]["message"]


def test_unknown_tool_name_is_a_jsonrpc_error() -> None:
    # A genuinely-unknown tool name is a PROTOCOL fault (caller bug), so it stays a
    # JSON-RPC error — not an isError result.
    server = WardlineMCPServer(root=FIXTURE)
    resp = server.rpc.dispatch(
        {"jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": {"name": "does_not_exist", "arguments": {}}}
    )
    assert "result" not in resp, resp
    assert resp["error"]["code"] == -32603
    assert "does_not_exist" in resp["error"]["message"]
