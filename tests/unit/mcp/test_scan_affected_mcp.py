"""Phase 8: the MCP ``scan`` tool's ``affected`` (delta-scope) parameter.

CLI ``wardline scan --affected <file|->`` scopes a scan to a warpline reverify-worklist
or bare entity list; the MCP scan tool must expose the same selector or the delta-scope
path is unreachable over the primary surface. The handler:

- accepts an inline object/array worklist|entity-list, OR a string path under root;
- rejects ``affected`` + ``new_since`` together with a ``ToolError`` (mutual exclusion,
  matching the CLI);
- maps a malformed inline payload (``ScopeParseError``) to a ``ToolError`` / isError result;
- emits ``result.scope.to_dict()`` as a top-level ``scope`` block that VALIDATES against
  ``_SCAN_OUTPUT_SCHEMA`` (the only end-to-end pin of the scope shape with scope present).

The scope block is OPTIONAL (absent on a full scan, INV-1) — so it must be exercised by a
real delta invocation, not just left untested.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from wardline.mcp.server import _SCAN_OUTPUT_SCHEMA, WardlineMCPServer, _scan
from wardline.mcp.tooling import ToolError

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)
_OTHER = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef rr(p):\n    return p\n"
    "@trusted\ndef otherleak(p):\n    return rr(p)\n"
)


def _two_file_project(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")
    (proj / "other.py").write_text(_OTHER, encoding="utf-8")
    return proj


# Two CO-LOCATED ERROR sinks (``alpha``, ``beta``) in ONE module — a worklist naming only
# ``alpha`` surgically excludes ``beta`` from the displayed findings while still analyzing
# the file, the in-analyzed-file THREAT-001 shape (INV-4).
_TWO_ENTITY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef alpha(p):\n    return read_raw(p)\n"
    "@trusted\ndef beta(p):\n    return read_raw(p)\n"
)


def _co_located_project(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_TWO_ENTITY, encoding="utf-8")
    return proj


def test_inline_entity_list_scopes_analysis(tmp_path: Path) -> None:
    proj = _two_file_project(tmp_path)
    out = _scan({"full": True, "affected": [{"locator": "python:function:svc.leaky"}]}, root=proj)
    scope = out["scope"]
    assert scope["mode"] == "delta"
    assert scope["gate_authority"] == "advisory"
    assert scope["files_discovered"] == 2
    assert scope["files_analyzed"] == 1
    # Only the affected entity's finding is displayed; the co-located other.py one is dropped.
    shown = {e["qualname"] for e in out["agent_summary"]["active_defects"]}
    assert shown == {"svc.leaky"}


def test_inline_worklist_envelope_scopes_analysis(tmp_path: Path) -> None:
    proj = _two_file_project(tmp_path)
    worklist = {"data": {"items": [{"entity": {"locator": "python:function:svc.leaky"}}]}}
    out = _scan({"full": True, "affected": worklist}, root=proj)
    assert out["scope"]["mode"] == "delta"
    assert out["scope"]["files_analyzed"] == 1
    shown = {e["qualname"] for e in out["agent_summary"]["active_defects"]}
    assert shown == {"svc.leaky"}


def test_affected_path_string_under_root(tmp_path: Path) -> None:
    proj = _two_file_project(tmp_path)
    worklist_path = proj / "worklist.json"
    worklist_path.write_text(json.dumps([{"locator": "python:function:svc.leaky"}]), encoding="utf-8")
    out = _scan({"full": True, "affected": "worklist.json"}, root=proj)
    assert out["scope"]["mode"] == "delta"
    assert out["scope"]["files_analyzed"] == 1


def test_empty_affected_falls_back_to_full_scan(tmp_path: Path) -> None:
    proj = _two_file_project(tmp_path)
    out = _scan({"full": True, "affected": []}, root=proj)
    scope = out["scope"]
    assert scope["mode"] == "full-fallback"
    assert scope["gate_authority"] == "gate-of-record"
    assert scope["files_analyzed"] == scope["files_discovered"] == 2


def test_malformed_inline_affected_is_tool_error(tmp_path: Path) -> None:
    proj = _two_file_project(tmp_path)
    # A non-object entity-list item is structurally malformed -> ScopeParseError -> ToolError.
    with pytest.raises(ToolError):
        _scan({"affected": ["not-an-object"]}, root=proj)


def test_affected_plus_new_since_is_tool_error(tmp_path: Path) -> None:
    proj = _two_file_project(tmp_path)
    with pytest.raises(ToolError, match="mutually exclusive"):
        _scan({"affected": [{"locator": "python:function:svc.leaky"}], "new_since": "HEAD~1"}, root=proj)


def test_full_scan_emits_no_scope_block(tmp_path: Path) -> None:
    # INV-1: a scan with no `affected` carries no scope block.
    proj = _two_file_project(tmp_path)
    out = _scan({"full": True}, root=proj)
    assert "scope" not in out


def test_delta_structured_content_validates_with_scope_present(tmp_path: Path) -> None:
    # The end-to-end pin: a delta invocation's structuredContent (scope NON-NULL) must
    # validate against the tool's declared outputSchema, and the scope block must round-trip
    # the dual-emission text block.
    proj = _two_file_project(tmp_path)
    server = WardlineMCPServer(root=proj)
    resp = server.rpc.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "scan",
                "arguments": {"full": True, "affected": [{"locator": "python:function:svc.leaky"}]},
            },
        }
    )
    assert "error" not in resp, resp
    result = resp["result"]
    assert result.get("isError") is not True, result
    structured = result["structuredContent"]
    assert "scope" in structured and structured["scope"]["mode"] == "delta"
    jsonschema.validate(structured, _SCAN_OUTPUT_SCHEMA)
    assert json.loads(result["content"][0]["text"]) == structured


def test_affected_with_fail_on_is_rejected(tmp_path: Path) -> None:
    """``affected`` (advisory delta) cannot drive ``fail_on`` (the gate of record).

    A delta scan analyzes only the scoped subset, so a green gate would be unearned (an
    ERROR in an unanalyzed file would never be seen). The MCP handler refuses the
    combination with a ToolError — symmetric with the CLI's exit-2 rejection. The
    engine-level INV-4 guarantee (the gate population is never narrowed, even under
    ``trust_suppressions``) is covered by the ``run_scan`` / ``gate_decision`` unit tests
    (tests/unit/core/test_run_affected.py, test_affected_invariants.py); here the surface
    simply refuses to gate an advisory scope at all."""
    proj = _co_located_project(tmp_path)

    with pytest.raises(ToolError, match="fail_on"):
        _scan(
            {
                "fail_on": "ERROR",
                "affected": [{"locator": "python:function:svc.alpha"}],
            },
            root=proj,
        )


def test_affected_schema_declared_on_scan_tool(tmp_path: Path) -> None:
    server = WardlineMCPServer(root=tmp_path)
    tools = server.rpc.dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    scan_tool = next(t for t in tools["result"]["tools"] if t["name"] == "scan")
    affected = scan_tool["inputSchema"]["properties"]["affected"]
    assert affected["type"] == ["object", "array", "string"]
    assert "reverify_worklist" in affected["description"]
    # The scope output property is declared and optional (absent on a full scan).
    scope_prop = scan_tool["outputSchema"]["properties"]["scope"]
    assert scope_prop["type"] == "object"
    assert "scope" not in scan_tool["outputSchema"]["required"]
