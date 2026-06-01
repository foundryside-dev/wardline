import io
import json

from wardline.mcp.protocol import PROTOCOL_VERSION, JsonRpcServer, McpError


def _server() -> JsonRpcServer:
    srv = JsonRpcServer(server_name="wardline", server_version="0.1.0")
    srv.register("ping", lambda params: {"pong": params.get("n", 0) + 1})
    return srv


def test_initialize_returns_capabilities_and_protocol_version() -> None:
    srv = _server()
    resp = srv.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}},
        }
    )
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == 1
    assert resp["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert "capabilities" in resp["result"]
    assert resp["result"]["serverInfo"]["name"] == "wardline"


def test_notification_initialized_returns_none() -> None:
    srv = _server()
    # notifications (no id) must not produce a response
    assert srv.dispatch({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_dispatch_routes_to_handler() -> None:
    srv = _server()
    resp = srv.dispatch({"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {"n": 41}})
    assert resp["result"] == {"pong": 42}


def test_unknown_method_returns_method_not_found() -> None:
    srv = _server()
    resp = srv.dispatch({"jsonrpc": "2.0", "id": 3, "method": "nope", "params": {}})
    assert resp["error"]["code"] == -32601  # JSON-RPC "Method not found"


def test_handler_exception_becomes_internal_error() -> None:
    srv = _server()
    srv.register("boom", lambda params: (_ for _ in ()).throw(RuntimeError("kaboom")))
    resp = srv.dispatch({"jsonrpc": "2.0", "id": 4, "method": "boom", "params": {}})
    assert resp["error"]["code"] == -32603  # Internal error
    assert "kaboom" in resp["error"]["message"]


def test_run_stdio_loop_frames_and_skips_notifications() -> None:
    srv = _server()
    stdin = io.StringIO(
        "this is not json\n"  # -> parse error, one response
        "\n"  # blank line, skipped entirely
        '{"jsonrpc": "2.0", "method": "notifications/initialized"}\n'  # notification, no response
        '{"jsonrpc": "2.0", "id": 7, "method": "ping", "params": {"n": 1}}\n'  # -> ping result
    )
    stdout = io.StringIO()
    srv.run_stdio(stdin=stdin, stdout=stdout)
    lines = [json.loads(line) for line in stdout.getvalue().splitlines() if line]
    # Exactly two responses: the parse error and the ping result. The blank line
    # and the notification produce no output.
    assert len(lines) == 2
    assert lines[0]["error"]["code"] == -32700  # parse error
    assert lines[0]["id"] is None
    assert lines[1]["id"] == 7
    assert lines[1]["result"] == {"pong": 2}


def test_run_stdio_rejects_non_jsonrpc_message() -> None:
    srv = _server()
    stdin = io.StringIO('{"id": 9, "method": "ping"}\n')  # missing jsonrpc: "2.0"
    stdout = io.StringIO()
    srv.run_stdio(stdin=stdin, stdout=stdout)
    resp = json.loads(stdout.getvalue())
    assert resp["error"]["code"] == -32600  # invalid request
    assert resp["id"] == 9


def test_mcp_error_custom_code_propagates() -> None:
    # Tasks 7-9 rely on McpError carrying explicit codes (e.g. explain_taint
    # staleness, judge missing-key). This branch must NOT collapse into -32603.
    srv = _server()
    srv.register("stale_tool", lambda params: (_ for _ in ()).throw(McpError("stale", code=-32042)))
    resp = srv.dispatch({"jsonrpc": "2.0", "id": 5, "method": "stale_tool", "params": {}})
    assert resp["error"]["code"] == -32042
    assert resp["error"]["message"] == "stale"


def test_id_null_is_a_request_not_a_notification() -> None:
    # Detection is presence-keyed ("id" not in message), not truthiness:
    # id:null is still a request and MUST get a response.
    srv = _server()
    resp = srv.dispatch({"jsonrpc": "2.0", "id": None, "method": "ping", "params": {"n": 1}})
    assert resp is not None
    assert resp["id"] is None
    assert resp["result"] == {"pong": 2}
    # Contrast: a message with NO id key is a notification -> no response.
    assert srv.dispatch({"jsonrpc": "2.0", "method": "ping", "params": {"n": 1}}) is None


def test_run_stdio_rejects_non_object_json() -> None:
    # Valid JSON but not an object: the `not isinstance(message, dict)` branch
    # plus the id fallback (id: null since there is no dict to read id from).
    srv = _server()
    stdin = io.StringIO("[1, 2, 3]\n")
    stdout = io.StringIO()
    srv.run_stdio(stdin=stdin, stdout=stdout)
    lines = [json.loads(line) for line in stdout.getvalue().splitlines() if line]
    assert len(lines) == 1
    assert lines[0]["error"]["code"] == -32600  # invalid request
    assert lines[0]["id"] is None
