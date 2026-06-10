"""T4.3 — the dossier surface: MCP `dossier` tool + CLI≡MCP parity (dossier spec §11).

The dossier verb must be REACHABLE (an agent calls it through MCP; a user through the
CLI), and CLI and MCP must be identical by construction (CLAUDE.md tenet).
"""

import json
from pathlib import Path

from click.testing import CliRunner

from wardline.cli.main import cli
from wardline.mcp.server import WardlineMCPServer

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def _proj(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")
    return proj


def _mcp_call(server, name, arguments):
    resp = server.rpc.dispatch(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
    )
    assert "error" not in resp, resp
    return json.loads(resp["result"]["content"][0]["text"])


def test_mcp_advertises_the_dossier_tool() -> None:
    server = WardlineMCPServer(root=Path("tests/fixtures/sample_project"))
    resp = server.rpc.dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    names = {t["name"] for t in resp["result"]["tools"]}
    assert "dossier" in names


def test_mcp_dossier_tool_returns_real_trust_posture(tmp_path: Path) -> None:
    proj = _proj(tmp_path)
    out = _mcp_call(WardlineMCPServer(root=proj), "dossier", {"entity": "svc.leaky"})
    assert out["identity"]["qualname"] == "svc.leaky"
    assert out["trust"]["gate_verdict"] == "defect"
    # self-only (no loomweave/filigree configured) → honest unavailable sources
    assert out["linkages"]["available"] is False
    assert out["work"]["available"] is False


def test_mcp_dossier_unknown_entity_is_iserror(tmp_path: Path) -> None:
    proj = _proj(tmp_path)
    resp = WardlineMCPServer(root=proj).rpc.dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "dossier", "arguments": {"entity": "svc.nope"}},
        }
    )
    # a tool-execution fault surfaces as an isError RESULT, not a JSON-RPC error
    assert "error" not in resp
    assert resp["result"].get("isError") is True


def test_cli_dossier_emits_json(tmp_path: Path) -> None:
    proj = _proj(tmp_path)
    res = CliRunner().invoke(cli, ["dossier", "svc.leaky", str(proj)])
    assert res.exit_code == 0, res.output
    payload = json.loads(res.output)
    assert payload["identity"]["qualname"] == "svc.leaky"
    assert payload["trust"]["gate_verdict"] == "defect"


def test_cli_dossier_unknown_entity_exits_2(tmp_path: Path) -> None:
    proj = _proj(tmp_path)
    res = CliRunner().invoke(cli, ["dossier", "svc.nope", str(proj)])
    assert res.exit_code == 2
    assert "error:" in res.output


def test_cli_dossier_with_loomweave_url_degrades_soft(tmp_path: Path, monkeypatch) -> None:
    # exercise the --loomweave-url wiring branch without a live Loomweave: a fake client
    # whose capability probe returns None → honest self-only degrade, no crash.
    proj = _proj(tmp_path)

    class _FakeClient:
        def __init__(self, *a, **k):
            pass

        def capabilities(self):
            return None

        def resolve(self, qualnames, *, plugin=None):
            return None

    monkeypatch.setattr("wardline.loomweave.client.LoomweaveClient", _FakeClient)
    monkeypatch.setattr("wardline.loomweave.config.load_loomweave_token", lambda p: None)
    monkeypatch.setattr("wardline.loomweave.config.resolve_project_name", lambda p: "proj")
    res = CliRunner().invoke(cli, ["dossier", "svc.leaky", str(proj), "--loomweave-url", "http://x"])
    assert res.exit_code == 0, res.output
    payload = json.loads(res.output)
    assert payload["identity"]["identity_status"] == "unavailable"
    assert payload["trust"]["gate_verdict"] == "defect"


def test_cli_and_mcp_dossier_are_identical(tmp_path: Path) -> None:
    # The tenet: CLI and MCP are identical by construction (both delegate to
    # build_weft_dossier). Same input → byte-identical envelope.
    proj = _proj(tmp_path)
    cli_res = CliRunner().invoke(cli, ["dossier", "svc.leaky", str(proj)])
    assert cli_res.exit_code == 0, cli_res.output
    cli_payload = json.loads(cli_res.output)
    mcp_payload = _mcp_call(WardlineMCPServer(root=proj), "dossier", {"entity": "svc.leaky"})
    assert cli_payload == mcp_payload
