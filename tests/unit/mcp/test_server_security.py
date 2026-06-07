"""THREAT-001 regression: the MCP server is rooted, and every caller-supplied
``path``/``config`` arg plus the effective ``source_roots`` is confined to the
project root. An escape is refused as an isError result — a tool can never read
or write outside the root. These tests reproduce the live attacks the security
reviewer confirmed.
"""

from pathlib import Path

import pytest

from wardline.core.errors import ConfigError
from wardline.core.run import run_scan
from wardline.mcp.server import WardlineMCPServer

# A @trusted boundary returning an @external_boundary-tainted value: PY-WL-101.
_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def _dispatch(server, name, arguments):
    return server.rpc.dispatch(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
    )


def _assert_iserror(resp, needle: str) -> None:
    assert "error" not in resp, resp
    assert resp["result"].get("isError") is True, resp["result"]
    assert needle in resp["result"]["content"][0]["text"]


def test_scan_absolute_path_out_of_root_is_iserror(tmp_path: Path) -> None:
    # The confirmed attack: scan {"path":"/etc"} walked /etc. Now refused — and the
    # result is an error, NOT a successful scan of /etc.
    server = WardlineMCPServer(root=tmp_path)
    resp = _dispatch(server, "scan", {"path": "/etc"})
    _assert_iserror(resp, "within the project root")
    assert "findings" not in resp["result"]


def test_scan_config_traversal_escape_is_iserror(tmp_path: Path) -> None:
    server = WardlineMCPServer(root=tmp_path)
    resp = _dispatch(server, "scan", {"config": "../../etc/passwd"})
    _assert_iserror(resp, "within the project root")


def test_explain_taint_out_of_root_path_is_iserror(tmp_path: Path) -> None:
    server = WardlineMCPServer(root=tmp_path)
    resp = _dispatch(server, "explain_taint", {"path": "/etc/x.py", "line": 1})
    _assert_iserror(resp, "within the project root")


def test_baseline_create_config_escape_is_iserror(tmp_path: Path) -> None:
    server = WardlineMCPServer(root=tmp_path)
    resp = _dispatch(server, "baseline", {"reason": "x", "config": "../../outside.yaml"})
    _assert_iserror(resp, "within the project root")


def test_waiver_add_default_config_symlink_escape_is_iserror(tmp_path: Path) -> None:
    # waiver_add now writes the member-owned waivers state at
    # <root>/.weft/wardline/waivers.yaml (NOT config). add_waiver still confines that
    # write via safe_project_file(root, ...), so a final-component symlink escaping the
    # root is refused as an isError — the same confinement vector, on the new path.
    from wardline.core.paths import waivers_path

    outside = tmp_path / "outside.yaml"
    outside.write_text("", encoding="utf-8")
    waivers = waivers_path(tmp_path)
    waivers.parent.mkdir(parents=True, exist_ok=True)
    waivers.symlink_to(outside)
    server = WardlineMCPServer(root=tmp_path)

    resp = _dispatch(
        server,
        "waiver_add",
        {
            "fingerprint": "a" * 64,
            "reason": "validated upstream",
            "expires": "2026-12-31",
        },
    )

    _assert_iserror(resp, "symlink")
    assert outside.read_text(encoding="utf-8") == ""


def test_scan_bad_fail_on_enum_is_actionable_iserror(tmp_path: Path) -> None:
    # A bad fail_on used to surface as an opaque -32603; now it is an actionable
    # isError naming the valid set.
    server = WardlineMCPServer(root=tmp_path)
    resp = _dispatch(server, "scan", {"fail_on": "BOGUS"})
    _assert_iserror(resp, "")
    text = resp["result"]["content"][0]["text"]
    for w in ["CRITICAL", "ERROR", "WARN", "INFO"]:
        assert w in text


def test_poisoned_source_roots_refused_by_mcp_and_core_by_default(tmp_path: Path) -> None:
    # The deeper exfil vector: an IN-ROOT weft.toml [wardline] whose source_roots escape
    # the root. config is confined, but the config itself points out. discover()
    # behind confine_to_root=True refuses it. The shared core default is now
    # confined too; legacy escape requires an explicit opt-out.
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("SECRET = 'do not exfiltrate'\n", encoding="utf-8")
    (proj / "weft.toml").write_text('[wardline]\nsource_roots = ["../outside"]\n', encoding="utf-8")

    # MCP scan tool → confine_to_root=True → ConfigError → isError, no scan of outside.
    server = WardlineMCPServer(root=proj)
    resp = _dispatch(server, "scan", {})
    _assert_iserror(resp, "outside the project root")
    assert "findings" not in resp["result"]

    with pytest.raises(ConfigError, match="outside the project root"):
        run_scan(proj)

    # Discriminator (advisor trap #4): prove the config can still be accepted by
    # an explicit unconfined opt-out, so the raising condition is confinement.
    result = run_scan(proj, confine_to_root=False)
    assert result.files_scanned >= 1  # the out-of-root file is scanned, as before
    with pytest.raises(ConfigError, match="outside the project root"):
        run_scan(proj, confine_to_root=True)
