"""A1 (wardline-2ee1bbda82): the MCP ``scan`` tool's ``lang`` arg.

CLI ``wardline scan --lang rust`` selects the Rust frontend; the MCP scan tool
must expose the same selector or the Rust line is unreachable over the primary
surface. The schema declares the enum, the handler plumbs it to ``run_scan``,
and a bad value surfaces as the agent-actionable ``ConfigError`` (isError
result), never a silent python-default scan.
"""

from __future__ import annotations

import pytest

from wardline.core.errors import ConfigError
from wardline.mcp.server import WardlineMCPServer, _scan

_TRUSTED = "/// @trusted(level=ASSURED)\n"
_INJECTION = _TRUSTED + 'fn run() {\n    let t = std::env::var("X").unwrap();\n    Command::new(t).output();\n}\n'


def test_scan_lang_rust_finds_injection_and_trips_gate(tmp_path) -> None:
    pytest.importorskip("tree_sitter", reason="wardline[rust] extra not installed")
    (tmp_path / "m.rs").write_text(_INJECTION, encoding="utf-8")
    response = _scan({"lang": "rust", "fail_on": "ERROR", "full": True}, root=tmp_path)
    rule_ids = {e["rule_id"] for e in response["agent_summary"]["active_defects"]}
    assert "RS-WL-108" in rule_ids
    assert response["gate"]["tripped"] is True
    assert response["gate"]["verdict"] == "FAILED"


def test_scan_default_lang_is_python_and_ignores_rs(tmp_path) -> None:
    # Absent lang must stay byte-identical to the released behaviour: .rs files
    # are not swept, the gate stays green.
    (tmp_path / "m.rs").write_text(_INJECTION, encoding="utf-8")
    response = _scan({"fail_on": "ERROR"}, root=tmp_path)
    assert response["files_scanned"] == 0
    assert response["gate"]["tripped"] is False


def test_scan_unknown_lang_is_agent_actionable_config_error(tmp_path) -> None:
    # ConfigError is a WardlineError -> the MCP loop maps it to an isError result
    # the agent can read; the message names the valid set.
    with pytest.raises(ConfigError, match="unknown language 'go'.*'python'.*'rust'"):
        _scan({"lang": "go"}, root=tmp_path)


def test_scan_tool_schema_declares_lang_enum(tmp_path) -> None:
    server = WardlineMCPServer(root=tmp_path)
    tools = server.rpc.dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    scan_tool = next(t for t in tools["result"]["tools"] if t["name"] == "scan")
    lang_schema = scan_tool["inputSchema"]["properties"]["lang"]
    assert lang_schema["enum"] == ["python", "rust"]
    assert lang_schema["type"] == "string"
    # The description must carry the preview posture the CLI banner carries
    # (slice coverage; no severity-override parity) — MCP agents read tool docs,
    # not stderr.
    assert "RS-WL-108" in lang_schema["description"]
