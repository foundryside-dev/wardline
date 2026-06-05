"""SP8 Task 9: MCP suppression tools (baseline/waiver), the network-fenced judge
tool, and the wardline:loop prompt. No network: the judge success path injects a
fake caller by monkeypatching the caller the default path imports."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import pytest
import yaml

from wardline.core.judge import JudgeResponse, JudgeVerdict
from wardline.mcp.server import WardlineMCPServer

FIXTURE = Path("tests/fixtures/sample_project")

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


def _call(server: WardlineMCPServer, name: str, arguments: dict) -> dict:
    resp = server.rpc.dispatch(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
    )
    assert "error" not in resp, resp
    assert not resp["result"].get("isError"), resp  # tool-execution error
    return json.loads(resp["result"]["content"][0]["text"])


def test_mcp_scan_gate_trips_on_baselined_defect_by_default(tmp_path: Path) -> None:
    # SECURITY parity with the CLI: a repository-controlled baseline annotates the defect
    # but the MCP scan gate evaluates the unsuppressed population by default.
    proj = _leaky_project(tmp_path)
    server = WardlineMCPServer(root=proj)
    first = _call(server, "scan", {})
    fp = next(f["fingerprint"] for f in first["findings"] if f["rule_id"] == "PY-WL-101")
    bl = proj / ".wardline" / "baseline.yaml"
    bl.parent.mkdir(parents=True, exist_ok=True)
    bl.write_text(
        f"version: 1\nentries:\n  - fingerprint: {fp}\n    rule_id: PY-WL-101\n    path: svc.py\n    message: m\n",
        encoding="utf-8",
    )
    # Default: annotated baselined, but the gate trips.
    default = _call(server, "scan", {"fail_on": "ERROR"})
    leak = next(f for f in default["findings"] if f["rule_id"] == "PY-WL-101")
    assert leak["suppressed"] == "baselined"
    assert default["gate"]["tripped"] is True
    # trust_suppressions restores the trusted-local behaviour: the gate clears.
    trusted = _call(server, "scan", {"fail_on": "ERROR", "trust_suppressions": True})
    assert trusted["gate"]["tripped"] is False


def test_baseline_optional_reason(tmp_path: Path) -> None:
    proj = _leaky_project(tmp_path)
    server = WardlineMCPServer(root=proj)
    resp = server.rpc.dispatch(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "baseline", "arguments": {}}}
    )
    assert "error" not in resp, resp
    assert not resp["result"].get("isError"), resp
    out = json.loads(resp["result"]["content"][0]["text"])
    assert out["baselined_count"] >= 1
    assert out["reason"] is None


def test_baseline_create_then_overwrite(tmp_path: Path) -> None:
    proj = _leaky_project(tmp_path)
    server = WardlineMCPServer(root=proj)
    out = _call(server, "baseline", {"reason": "accept current debt"})
    assert out["baselined_count"] >= 1
    out2 = _call(server, "baseline", {"reason": "re-derive", "overwrite": True})
    assert out2["baselined_count"] >= 1


def test_baseline_create_trusted_pack_matches_scan_mcp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project_root = Path(__file__).resolve().parents[3]
    monkeypatch.syspath_prepend(str(project_root))
    from tests.unit.install.mock_pack import grammar as mock_grammar

    fake_pack = ModuleType("baseline_mcp_pack")
    fake_pack.grammar = mock_grammar  # type: ignore[attr-defined]
    sys.modules["baseline_mcp_pack"] = fake_pack

    try:
        proj = tmp_path / "proj"
        proj.mkdir()
        (proj / "wardline.yaml").write_text("packs:\n  - baseline_mcp_pack\n", encoding="utf-8")
        (proj / "m.py").write_text("def violator():\n    pass\n", encoding="utf-8")
        server = WardlineMCPServer(root=proj)

        scan = _call(server, "scan", {"trust_packs": ["baseline_mcp_pack"], "trust_local_packs": True})
        assert any(f["rule_id"] == "PY-WL-901" for f in scan["findings"])

        baseline = _call(
            server,
            "baseline",
            {
                "reason": "accept custom rule debt",
                "trust_packs": ["baseline_mcp_pack"],
                "trust_local_packs": True,
                "cache_dir": ".wardline/cache",
            },
        )
        assert baseline["baselined_count"] >= 1
        baseline_doc = yaml.safe_load((proj / ".wardline" / "baseline.yaml").read_text(encoding="utf-8"))
        assert any(entry["rule_id"] == "PY-WL-901" for entry in baseline_doc["entries"])
    finally:
        sys.modules.pop("baseline_mcp_pack", None)


def test_baseline_retry_is_idempotent(tmp_path: Path) -> None:
    proj = _leaky_project(tmp_path)
    server = WardlineMCPServer(root=proj)
    first = _call(server, "baseline", {"reason": "accept current debt"})
    resp = server.rpc.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "baseline", "arguments": {"reason": "again"}},
        }
    )
    assert "error" not in resp, resp
    assert not resp["result"].get("isError"), resp
    out = json.loads(resp["result"]["content"][0]["text"])
    assert out["already_exists"] is True
    assert out["baselined_count"] == first["baselined_count"]


def test_waiver_add_requires_reason_and_expires(tmp_path: Path) -> None:
    proj = _leaky_project(tmp_path)
    server = WardlineMCPServer(root=proj)
    fp = "b" * 64
    resp = server.rpc.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "waiver_add", "arguments": {"fingerprint": fp, "reason": "ok"}},
        }
    )
    # expires is mandatory at the tool boundary -> isError result
    assert resp["result"]["isError"] is True
    out = _call(server, "waiver_add", {"fingerprint": fp, "reason": "validated upstream", "expires": "2026-12-31"})
    assert out["fingerprint"] == fp


def test_waiver_add_retry_is_idempotent(tmp_path: Path) -> None:
    proj = _leaky_project(tmp_path)
    server = WardlineMCPServer(root=proj)
    fp = "d" * 64
    args = {"fingerprint": fp, "reason": "validated upstream", "expires": "2026-12-31"}
    first = _call(server, "waiver_add", args)
    second = _call(server, "waiver_add", args)
    assert first["fingerprint"] == second["fingerprint"] == fp
    assert second["already_exists"] is True


def test_waiver_add_bad_date_is_iserror(tmp_path: Path) -> None:
    proj = _leaky_project(tmp_path)
    server = WardlineMCPServer(root=proj)
    fp = "c" * 64
    resp = server.rpc.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "waiver_add", "arguments": {"fingerprint": fp, "reason": "ok", "expires": "not-a-date"}},
        }
    )
    # A malformed date is agent-actionable -> isError with YYYY-MM-DD guidance.
    assert resp["result"]["isError"] is True
    assert "yyyy-mm-dd" in resp["result"]["content"][0]["text"].lower()


def test_judge_tool_is_advertised_with_network_flag() -> None:
    server = WardlineMCPServer(root=FIXTURE)
    resp = server.rpc.dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    judge = next(t for t in resp["result"]["tools"] if t["name"] == "judge")
    assert "network" in judge["description"].lower()


def test_prompts_list_has_loop() -> None:
    server = WardlineMCPServer(root=FIXTURE)
    resp = server.rpc.dispatch({"jsonrpc": "2.0", "id": 1, "method": "prompts/list", "params": {}})
    assert any(p["name"] == "wardline:loop" for p in resp["result"]["prompts"])


def test_prompts_get_loop_returns_message() -> None:
    server = WardlineMCPServer(root=FIXTURE)
    resp = server.rpc.dispatch(
        {"jsonrpc": "2.0", "id": 1, "method": "prompts/get", "params": {"name": "wardline:loop"}}
    )
    assert "error" not in resp, resp
    msg = resp["result"]["messages"][0]
    assert msg["role"] == "user"
    assert "scan" in msg["content"]["text"].lower()


def test_prompts_get_unknown_is_jsonrpc_error() -> None:
    server = WardlineMCPServer(root=FIXTURE)
    resp = server.rpc.dispatch({"jsonrpc": "2.0", "id": 1, "method": "prompts/get", "params": {"name": "nope"}})
    # An unknown prompt name is a caller bug -> JSON-RPC error, not an isError result.
    assert "error" in resp


def _fake_response() -> JudgeResponse:
    return JudgeResponse(
        verdict=JudgeVerdict.TRUE_POSITIVE,
        rationale="genuinely reaches a trusted sink",
        confidence=0.91,
        model_id="fake/model",
        recorded_at=datetime.now(UTC),
        prompt_tokens_total=128,
        prompt_tokens_cached=None,
        policy_hash="deadbeef",
    )


def test_judge_tool_success_via_monkeypatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # run_judge builds its default caller from call_judge imported INTO the
    # judge_run namespace; patch it there so the network is never touched.
    monkeypatch.setattr("wardline.core.judge_run.call_judge", lambda *a, **k: _fake_response())
    # call_judge is patched out, and the env-key check lives inside it — so no key is
    # actually read and no network is hit. The setenv just keeps the default-caller
    # construction path representative; it is not load-bearing for this test.
    monkeypatch.setenv("WARDLINE_OPENROUTER_API_KEY", "sk-or-test")
    proj = _leaky_project(tmp_path)
    server = WardlineMCPServer(root=proj)
    out = _call(server, "judge", {})
    assert isinstance(out["verdicts"], list)
    assert out["verdicts"], out
    v = out["verdicts"][0]
    assert v["label"] in {"TRUE_POSITIVE", "FALSE_POSITIVE"}
    assert 0.0 <= v["confidence"] <= 1.0
    assert v["fingerprint"]


def test_judge_tool_missing_key_is_iserror_with_guidance(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WARDLINE_OPENROUTER_API_KEY", raising=False)
    proj = _leaky_project(tmp_path)  # no .env in this bare project
    server = WardlineMCPServer(root=proj)
    resp = server.rpc.dispatch(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "judge", "arguments": {}}}
    )
    # Missing key reaches the agent as readable guidance, not a swallowed JSON-RPC error.
    assert "error" not in resp, resp
    assert resp["result"]["isError"] is True
    text = resp["result"]["content"][0]["text"]
    assert "WARDLINE_OPENROUTER_API_KEY" in text
