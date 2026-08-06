# tests/unit/mcp/test_server_trust_grants.py
"""Server-level trust-pack grant residency (Gap A, wardline-7a76f6c5a0).

``wardline mcp`` launch flags are the human-controlled home for pack grants
(the .mcp.json args array), mirroring the CLI scan's --trust-pack /
--allow-custom-packs. The server unions those launch grants into every tool
call's ``trust_packs`` / ``trust_local_packs`` arguments at dispatch, so a
pack-declaring project is scannable over MCP without every caller re-supplying
the grants — while per-call grants keep working and malformed per-call values
are still rejected by the handlers' strict guards.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from wardline.mcp.server import WardlineMCPServer

PACK_NAME = "scripts.grantpack"


def _pack_project(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    (proj / "scripts").mkdir(parents=True)
    (proj / "scripts" / "grantpack.py").write_text(
        'config = {"exclude": ["skipped_by_pack.py"]}\n', encoding="utf-8"
    )
    (proj / "weft.toml").write_text(f'[wardline]\npacks = ["{PACK_NAME}"]\n', encoding="utf-8")
    (proj / "kept.py").write_text("def kept():\n    return 1\n", encoding="utf-8")
    (proj / "skipped_by_pack.py").write_text("def skipped():\n    return 1\n", encoding="utf-8")
    return proj


def _forget_pack_modules() -> None:
    sys.modules.pop(PACK_NAME, None)
    sys.modules.pop("scripts", None)


def _dispatch(server: WardlineMCPServer, name: str, arguments: dict) -> dict:
    resp = server.rpc.dispatch(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
    )
    assert resp is not None
    return resp


def _text(resp: dict) -> str:
    return resp["result"]["content"][0]["text"]


def test_scan_fails_closed_without_any_grant(tmp_path) -> None:
    # Pin the fail-closed baseline: a declared-but-ungranted pack is a loud error,
    # never a silently packless (inert-green) scan.
    server = WardlineMCPServer(root=_pack_project(tmp_path))
    try:
        resp = _dispatch(server, "scan", {})
    finally:
        _forget_pack_modules()
    assert resp["result"]["isError"] is True
    assert "not trusted" in _text(resp)


def test_server_launch_grants_authorize_scan(tmp_path) -> None:
    server = WardlineMCPServer(
        root=_pack_project(tmp_path),
        trusted_packs=(PACK_NAME,),
        trust_local_packs=True,
    )
    try:
        resp = _dispatch(server, "scan", {})
    finally:
        _forget_pack_modules()
    assert resp["result"].get("isError") is not True, _text(resp)
    payload = json.loads(_text(resp))
    # The pack's config actually applied: skipped_by_pack.py was excluded,
    # leaving kept.py and scripts/grantpack.py.
    assert payload["files_scanned"] == 2


def test_per_call_args_union_with_launch_grants(tmp_path) -> None:
    # Launch flags grant the pack name; the caller supplies only the local-pack
    # grant. The union authorizes the scan — grants merge, they don't replace.
    server = WardlineMCPServer(root=_pack_project(tmp_path), trusted_packs=(PACK_NAME,))
    try:
        resp = _dispatch(server, "scan", {"trust_local_packs": True})
    finally:
        _forget_pack_modules()
    assert resp["result"].get("isError") is not True, _text(resp)
    assert json.loads(_text(resp))["files_scanned"] == 2


def test_launch_grants_do_not_mask_malformed_per_call_values(tmp_path, monkeypatch) -> None:
    # Degraded no-jsonschema mode: the handlers' strict guards must still reject
    # string booleans / non-list packs — grant injection never overwrites a
    # malformed caller value into a valid-looking one.
    monkeypatch.setitem(sys.modules, "jsonschema", None)
    server = WardlineMCPServer(
        root=_pack_project(tmp_path),
        trusted_packs=(PACK_NAME,),
        trust_local_packs=True,
    )
    try:
        resp = _dispatch(server, "scan", {"trust_local_packs": "false"})
        assert resp["result"]["isError"] is True
        assert "trust_local_packs must be a boolean" in _text(resp)

        resp = _dispatch(server, "scan", {"trust_packs": "not-a-list"})
        assert resp["result"]["isError"] is True
        assert "trust_packs must be an array of strings" in _text(resp)
    finally:
        _forget_pack_modules()
