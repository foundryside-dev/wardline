import json
from pathlib import Path
from typing import Any

import jsonschema

import wardline.mcp.server as server_mod
from wardline.mcp.server import WardlineMCPServer


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
    result = resp["result"]
    if result.get("isError"):
        return result
    return json.loads(result["content"][0]["text"])


def _status(job_id: str = "a" * 32, status: str = "running") -> dict[str, Any]:
    return {
        "job_id": job_id,
        "status": status,
        "phase": "scanning",
        "progress": {"steps_completed": 1, "steps_total": 4},
        "heartbeat": "2026-06-13T00:00:00Z",
        "request": {},
        "artifacts": {},
        "failure_kind": None,
        "error": None,
    }


def test_scan_job_tools_are_advertised_with_capabilities(tmp_path: Path) -> None:
    server = WardlineMCPServer(root=tmp_path)
    resp = server.rpc.dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    tools = {tool["name"]: tool for tool in resp["result"]["tools"]}

    assert {"scan_job_start", "scan_job_status", "scan_job_cancel"} <= set(tools)
    assert {"read", "write"} <= set(tools["scan_job_start"]["capabilities"])
    assert tools["scan_job_status"]["capabilities"] == ["read"]
    assert {"read", "write"} <= set(tools["scan_job_cancel"]["capabilities"])
    assert tools["scan_job_start"]["outputSchema"]["type"] == "object"


def test_scan_job_start_threads_request_to_core(tmp_path: Path, monkeypatch) -> None:
    calls: list[tuple[Path, dict[str, Any], bool]] = []

    def fake_start(root: Path, request: dict[str, Any], *, foreground: bool = False) -> dict[str, Any]:
        calls.append((root, request, foreground))
        return _status()

    monkeypatch.setattr(server_mod, "start_scan_job", fake_start)
    server = WardlineMCPServer(root=tmp_path, filigree_url="http://filigree.local/api/weft/scan-results")

    out = _tool_call(
        server,
        "scan_job_start",
        {
            "format": "agent-summary",
            "fail_on": "ERROR",
            "fail_on_unanalyzed": True,
            "timeout_seconds": 12.5,
            "lang": "python",
            "trust_packs": ["org.pack"],
        },
    )

    assert out["job_id"] == "a" * 32
    assert calls == [
        (
            tmp_path,
            {
                "config": None,
                "format": "agent-summary",
                "output": None,
                "fail_on": "ERROR",
                "fail_on_unanalyzed": True,
                "cache_dir": None,
                "filigree_url": "http://filigree.local/api/weft/scan-results",
                "local_only": False,
                "filigree_max_findings_per_request": None,
                "timeout_seconds": 12.5,
                "lang": "python",
                "new_since": None,
                "trusted_packs": ["org.pack"],
                "trust_local_packs": False,
                "strict_defaults": False,
                "trust_suppressions": False,
            },
            False,
        )
    ]


def test_scan_job_start_schema_and_runtime_accept_case_insensitive_fail_on(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls: list[dict[str, Any]] = []

    def fake_start(root: Path, request: dict[str, Any], *, foreground: bool = False) -> dict[str, Any]:
        calls.append(request)
        return _status()

    monkeypatch.setattr(server_mod, "start_scan_job", fake_start)
    server = WardlineMCPServer(root=tmp_path)
    tools = server.rpc.dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    schema = next(t for t in tools["result"]["tools"] if t["name"] == "scan_job_start")["inputSchema"]

    jsonschema.validate({"fail_on": "error"}, schema)
    assert "enum" not in schema["properties"]["fail_on"]
    out = _tool_call(server, "scan_job_start", {"fail_on": "error"})

    assert out["job_id"] == "a" * 32
    assert calls[0]["fail_on"] == "ERROR"


def test_scan_job_status_and_cancel_call_core(tmp_path: Path, monkeypatch) -> None:
    seen: list[tuple[str, Path, str]] = []

    def fake_status(root: Path, job_id: str) -> dict[str, Any]:
        seen.append(("status", root, job_id))
        return _status(job_id=job_id)

    def fake_cancel(root: Path, job_id: str) -> dict[str, Any]:
        seen.append(("cancel", root, job_id))
        return _status(job_id=job_id, status="cancelled")

    monkeypatch.setattr(server_mod, "read_scan_job_status", fake_status)
    monkeypatch.setattr(server_mod, "cancel_scan_job", fake_cancel)
    server = WardlineMCPServer(root=tmp_path)

    status = _tool_call(server, "scan_job_status", {"job_id": "b" * 32})
    cancel = _tool_call(server, "scan_job_cancel", {"job_id": "b" * 32})

    assert status["status"] == "running"
    assert cancel["status"] == "cancelled"
    assert seen == [("status", tmp_path, "b" * 32), ("cancel", tmp_path, "b" * 32)]


def test_scan_job_start_respects_write_and_network_policy(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WARDLINE_FILIGREE_URL", "http://filigree.local/api/weft/scan-results")
    called = False

    def fake_start(root: Path, request: dict[str, Any], *, foreground: bool = False) -> dict[str, Any]:
        nonlocal called
        called = True
        return _status()

    monkeypatch.setattr(server_mod, "start_scan_job", fake_start)

    no_write = WardlineMCPServer(root=tmp_path, allow_write=False)
    write_denied = _tool_call(no_write, "scan_job_start")
    assert write_denied["isError"] is True
    assert "write" in write_denied["content"][0]["text"].lower()

    no_network = WardlineMCPServer(root=tmp_path, allow_network=False)
    network_denied = _tool_call(no_network, "scan_job_start")
    assert network_denied["isError"] is True
    assert "network" in network_denied["content"][0]["text"].lower()

    local_only = _tool_call(no_network, "scan_job_start", {"local_only": True})
    assert local_only["status"] == "running"
    assert called is True
