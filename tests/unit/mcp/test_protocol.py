import io
import json

from wardline.mcp.protocol import PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS, JsonRpcServer, McpError


def _server() -> JsonRpcServer:
    # Explicit opt-out of the initialize gate: these tests exercise dispatch
    # semantics, not handshake sequencing (pinned by the gate tests below).
    srv = JsonRpcServer(server_name="wardline", server_version="0.1.0", require_handshake=False)
    srv.register("ping", lambda params: {"pong": params.get("n", 0) + 1})
    return srv


def _gated_server() -> JsonRpcServer:
    # require_handshake=True passed EXPLICITLY (not relying on the default) so the
    # tests/unit/mcp/conftest.py opt-out fixture cannot pre-open the gate here.
    srv = JsonRpcServer(server_name="wardline", server_version="0.1.0", require_handshake=True)
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


def test_initialize_negotiates_each_supported_protocol_version() -> None:
    # Spec negotiation: a supported requested revision is echoed VERBATIM, so an
    # older client (e.g. pinned to 2024-11-05) keeps its own revision.
    srv = _server()
    for requested in SUPPORTED_PROTOCOL_VERSIONS:
        resp = srv.dispatch(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": requested, "capabilities": {}},
            }
        )
        assert resp["result"]["protocolVersion"] == requested


def test_initialize_unknown_protocol_version_answers_latest() -> None:
    # An unsupported revision gets the newest revision this server speaks.
    srv = _server()
    resp = srv.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "1999-01-01", "capabilities": {}},
        }
    )
    assert resp["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert SUPPORTED_PROTOCOL_VERSIONS[0] == PROTOCOL_VERSION  # newest first


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


def test_id_null_is_rejected_by_mcp_request_contract() -> None:
    # MCP tightens JSON-RPC: request IDs must be string/integer and MUST NOT be null.
    srv = _server()
    resp = srv.dispatch({"jsonrpc": "2.0", "id": None, "method": "ping", "params": {"n": 1}})
    assert resp is not None
    assert resp["id"] is None
    assert resp["error"]["code"] == -32600
    assert "id" in resp["error"]["message"]
    # Contrast: a message with NO id key is a notification -> no response.
    assert srv.dispatch({"jsonrpc": "2.0", "method": "ping", "params": {"n": 1}}) is None


def test_non_string_integer_request_ids_are_rejected() -> None:
    srv = _server()
    for bad_id in (1.5, True, ["abc"]):
        resp = srv.dispatch({"jsonrpc": "2.0", "id": bad_id, "method": "ping", "params": {"n": 1}})
        assert resp is not None
        assert resp["id"] is None
        assert resp["error"]["code"] == -32600
        assert "id" in resp["error"]["message"]


def test_initialize_without_id_is_a_notification() -> None:
    srv = _server()
    resp = srv.dispatch(
        {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}},
        }
    )
    assert resp is None


def test_non_object_params_are_invalid_params_not_internal_error() -> None:
    srv = _server()
    resp = srv.dispatch({"jsonrpc": "2.0", "id": 8, "method": "ping", "params": ["not", "an", "object"]})
    assert resp["id"] == 8
    assert resp["error"]["code"] == -32602
    assert "params" in resp["error"]["message"]


def test_notifications_do_not_invoke_registered_handlers() -> None:
    srv = _server()
    calls: list[dict] = []

    def _mutate(params: dict) -> dict[str, bool]:
        calls.append(params)
        return {"ok": True}

    srv.register("mutate", _mutate)

    assert srv.dispatch({"jsonrpc": "2.0", "method": "mutate", "params": {"x": 1}}) is None

    assert calls == []


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


def test_initialization_gate() -> None:
    # wardline-5e4a4ee246: gate state comes from the constructor, never from
    # environment sniffing — no private-attribute forcing needed to test it.
    srv = _gated_server()
    resp = srv.dispatch({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"n": 1}})
    assert resp["error"]["code"] == -32600
    assert "not initialized" in resp["error"]["message"]


def test_handshake_sequence_opens_gate() -> None:
    """The real client sequence — initialize -> notifications/initialized -> call —
    must open the gate, and each earlier step must still reject method calls."""
    srv = _gated_server()
    # before initialize: rejected
    resp = srv.dispatch({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"n": 1}})
    assert resp["error"]["code"] == -32600
    assert "not initialized" in resp["error"]["message"]
    # initialize succeeds
    resp = srv.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "initialize",
            "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}},
        }
    )
    assert resp["result"]["serverInfo"]["name"] == "wardline"
    # after initialize but BEFORE notifications/initialized: still rejected
    resp = srv.dispatch({"jsonrpc": "2.0", "id": 3, "method": "ping", "params": {"n": 1}})
    assert resp["error"]["code"] == -32600
    # the initialized notification completes the handshake
    assert srv.dispatch({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    resp = srv.dispatch({"jsonrpc": "2.0", "id": 4, "method": "ping", "params": {"n": 41}})
    assert resp["result"] == {"pong": 42}


def test_initialized_notification_before_initialize_does_not_open_gate() -> None:
    srv = _gated_server()
    assert srv.dispatch({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    resp = srv.dispatch({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"n": 1}})
    assert resp["error"]["code"] == -32600
    assert "not initialized" in resp["error"]["message"]


def test_oversized_complete_line_does_not_swallow_next_message() -> None:
    """A line whose total length (INCLUDING the trailing newline) is exactly
    limit+1 is returned complete by readline(limit+1). The too-long recovery must
    not drain — that would eat and drop the next legitimate message."""
    limit = 10 * 1024 * 1024
    srv = _server()
    stdin = io.StringIO(
        "a" * limit + "\n"  # limit content chars + '\n' -> len(raw) == limit+1, complete line
        '{"jsonrpc": "2.0", "id": 7, "method": "ping", "params": {"n": 1}}\n'
    )
    stdout = io.StringIO()
    srv.run_stdio(stdin=stdin, stdout=stdout)
    lines = [json.loads(line) for line in stdout.getvalue().splitlines() if line]
    assert len(lines) == 2
    assert lines[0]["error"]["code"] == -32700  # line too long
    assert lines[0]["id"] is None
    assert lines[1]["id"] == 7  # the following message was answered, not swallowed
    assert lines[1]["result"] == {"pong": 2}


def test_oversized_truncated_line_drains_remainder_then_answers_next_message() -> None:
    """When the oversized line IS truncated mid-line, the drain must consume the
    remainder of that line only — the next message still gets its response."""
    limit = 10 * 1024 * 1024
    srv = _server()
    stdin = io.StringIO(
        "a" * (limit + 5) + "\n"  # readline returns limit+1 chars WITHOUT newline -> drain
        '{"jsonrpc": "2.0", "id": 8, "method": "ping", "params": {"n": 2}}\n'
    )
    stdout = io.StringIO()
    srv.run_stdio(stdin=stdin, stdout=stdout)
    lines = [json.loads(line) for line in stdout.getvalue().splitlines() if line]
    assert len(lines) == 2
    assert lines[0]["error"]["code"] == -32700
    assert lines[1]["id"] == 8
    assert lines[1]["result"] == {"pong": 3}
