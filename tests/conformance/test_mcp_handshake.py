"""Conformance: a client driving the documented MCP envelope must connect and
exercise every surface. Guards the hand-rolled transport — 'passes our handlers'
is not 'a client can talk to it'."""

import io
import json
from pathlib import Path

from wardline.mcp.protocol import PROTOCOL_VERSION
from wardline.mcp.server import WardlineMCPServer

FIXTURE = Path("tests/fixtures/sample_project")


def _drive(messages: list[dict], root: Path = FIXTURE) -> list[dict]:
    server = WardlineMCPServer(root=root)
    stdin = io.StringIO("".join(json.dumps(m) + "\n" for m in messages))
    stdout = io.StringIO()
    server.rpc.run_stdio(stdin=stdin, stdout=stdout)
    return [json.loads(ln) for ln in stdout.getvalue().splitlines() if ln.strip()]


def test_full_client_handshake_and_every_surface() -> None:
    responses = _drive(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "test-client", "version": "1.0"},
                },
            },
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "resources/list", "params": {}},
            {"jsonrpc": "2.0", "id": 4, "method": "prompts/list", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "scan", "arguments": {"fail_on": "ERROR"}},
            },
            {"jsonrpc": "2.0", "id": 6, "method": "resources/read", "params": {"uri": "wardline://vocab"}},
            {"jsonrpc": "2.0", "id": 7, "method": "prompts/get", "params": {"name": "wardline:loop"}},
        ]
    )
    by_id = {r["id"]: r for r in responses}
    # initialize: protocolVersion echoed, serverInfo present, capabilities advertise all three
    init = by_id[1]["result"]
    assert init["protocolVersion"] == PROTOCOL_VERSION
    assert init["serverInfo"]["name"] == "wardline"
    assert {"tools", "resources", "prompts"} <= set(init["capabilities"])
    # tools/list: the eleven documented tools, no more no less
    tool_names = {t["name"] for t in by_id[2]["result"]["tools"]}
    assert tool_names == {
        "scan",
        "explain_taint",
        "dossier",
        "assure",
        "attest",
        "verify_attestation",
        "file_finding",
        "scan_file_findings",
        "judge",
        "baseline",
        "fix",
        "waiver_add",
    }
    # resources/list: the four stable URIs
    resource_uris = {r["uri"] for r in by_id[3]["result"]["resources"]}
    assert resource_uris == {"wardline://vocab", "wardline://rules", "wardline://config", "wardline://config-schema"}
    # prompts/list: the one loop prompt
    prompt_names = {p["name"] for p in by_id[4]["result"]["prompts"]}
    assert prompt_names == {"wardline:loop"}
    # tools/call result MUST be content-wrapped, not bare JSON
    call = by_id[5]["result"]
    assert call["content"][0]["type"] == "text"
    payload = json.loads(call["content"][0]["text"])
    assert {"findings", "summary", "gate"} <= set(payload)
    # resources/read: the vocab resource round-trips non-empty text through the loop
    read = by_id[6]["result"]
    assert read["contents"][0]["uri"] == "wardline://vocab"
    assert read["contents"][0]["text"].strip()
    # prompts/get: the loop prompt body comes back as a user message
    got = by_id[7]["result"]
    assert "scan" in got["messages"][0]["content"]["text"].lower()
    # the initialized NOTIFICATION produced no response line: 7 request ids were
    # issued and all 7 answered; the notification between them carried no id.
    assert set(by_id) == {1, 2, 3, 4, 5, 6, 7}
    assert len(responses) == 7


def test_capabilities_match_actually_registered_methods() -> None:
    responses = _drive(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}},
            },
            {"jsonrpc": "2.0", "id": 2, "method": "resources/list", "params": {}},
        ]
    )
    # advertising resources capability obliges resources/list to work
    assert "error" not in responses[1]


def test_tool_execution_error_is_iserror_result_not_jsonrpc_error() -> None:
    # A stale/unknown fingerprint is a tool-EXECUTION error: it must come back as a
    # result with isError:true (so an MCP client relays the guidance to the model),
    # NOT as a JSON-RPC error (which clients often swallow).
    responses = _drive(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}},
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "explain_taint", "arguments": {"fingerprint": "0" * 64}},
            },
        ]
    )
    by_id = {r["id"]: r for r in responses}
    resp = by_id[2]
    assert "error" not in resp  # NOT a JSON-RPC error
    assert resp["result"]["isError"] is True  # IS an isError result
    assert "re-scan" in resp["result"]["content"][0]["text"].lower()


def test_unknown_method_is_a_jsonrpc_error() -> None:
    # A protocol fault (unknown method) IS a JSON-RPC error — the other half of the split.
    responses = _drive(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}},
            },
            {"jsonrpc": "2.0", "id": 2, "method": "no/such/method", "params": {}},
        ]
    )
    by_id = {r["id"]: r for r in responses}
    assert by_id[2]["error"]["code"] == -32601


def test_reject_before_initialize() -> None:
    server = WardlineMCPServer(root=FIXTURE)
    server.rpc._initialized = False
    server.rpc._initializing = False
    messages = [{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}]
    stdin = io.StringIO("".join(json.dumps(m) + "\n" for m in messages))
    stdout = io.StringIO()
    server.rpc.run_stdio(stdin=stdin, stdout=stdout)
    responses = [json.loads(ln) for ln in stdout.getvalue().splitlines() if ln.strip()]
    assert len(responses) == 1
    assert responses[0]["error"]["code"] == -32600
    assert "server not initialized" in responses[0]["error"]["message"]


def test_line_too_long() -> None:
    server = WardlineMCPServer(root=FIXTURE)
    stdin = io.StringIO("a" * (10 * 1024 * 1024 + 1) + "\n")
    stdout = io.StringIO()
    server.rpc.run_stdio(stdin=stdin, stdout=stdout)
    responses = [json.loads(ln) for ln in stdout.getvalue().splitlines() if ln.strip()]
    assert len(responses) == 1
    assert responses[0]["error"]["code"] == -32700
    assert "line too long" in responses[0]["error"]["message"]
