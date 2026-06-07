"""MCP `attest` + `verify_attestation` tools: the signed evidence bundle, surfaced
over MCP identically to the CLI/core by construction.

The MCP `attest` result's canonical payload bytes must EQUAL the core
`build_attestation` for the same tree+key (CLAUDE.md tenet: CLI and MCP identical).
An agent must not silently attest a dirty tree, so the MCP handler DEFAULTS to strict
(`allow_dirty=False`) even though core defaults `allow_dirty=True`. A missing key or a
refused dirty tree surfaces as a tool-EXECUTION isError result, never a raw crash.

`monkeypatch.delenv(WARDLINE_ATTEST_KEY)` in EVERY test: an ambient env key wins over
`.env` in `load_attest_key`, which would both bypass the minted-into-.env key (1/2/4)
and break the no-key path (3). The annotated tree is NON-git → `dirty=False`, so the
default-strict path still builds; it is waiver-free → date-independent.
"""

from __future__ import annotations

import json
import subprocess
from datetime import date
from pathlib import Path

from wardline.core.attest import _canonical_bytes, build_attestation
from wardline.core.attest_key import WARDLINE_ATTEST_KEY_ENV, mint_attest_key
from wardline.mcp.server import WardlineMCPServer

# Real trust boundaries (mirrors test_attest.py): `src` is an @external_boundary,
# `clean` conforms, `leak` declares INTEGRAL but returns the EXTERNAL_RAW value.
_MODULE = (
    "from wardline.decorators.trust import trusted, external_boundary\n"
    "\n"
    "@external_boundary\n"
    "def src():\n"
    "    return _read()\n"
    "\n"
    "def _read():\n"
    "    return object()\n"
    "\n"
    "@trusted(level='INTEGRAL')\n"
    "def clean():\n"
    "    return 1\n"
    "\n"
    "@trusted(level='INTEGRAL')\n"
    "def leak():\n"
    "    return src()\n"
)


def _annotated_tree(tmp_path: Path) -> Path:
    """A clean, NON-git annotated tree (waiver-free → payload is date-independent)."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "m.py").write_text(_MODULE, encoding="utf-8")
    return proj


def _call(server: WardlineMCPServer, name: str, arguments: dict) -> dict:
    resp = server.rpc.dispatch(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
    )
    assert "error" not in resp, resp
    return resp["result"]


def _payload(result: dict) -> dict:
    return json.loads(result["content"][0]["text"])


def test_mcp_advertises_both_attest_tools(monkeypatch) -> None:
    monkeypatch.delenv(WARDLINE_ATTEST_KEY_ENV, raising=False)
    server = WardlineMCPServer(root=Path("tests/fixtures/sample_project"))
    resp = server.rpc.dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    names = {t["name"] for t in resp["result"]["tools"]}
    assert {"attest", "verify_attestation"} <= names


class _FixedDate(date):
    """A ``date`` whose ``today()`` is pinned but ``fromisoformat`` still delegates.

    The MCP `attest` handler takes no ``today`` and defaults to ``date.today()``, as does
    the core ``build_attestation`` comparison call below. With the new ``attested_at``
    field, two independent ``date.today()`` reads that straddle midnight would record
    different dates and break byte-equality. Freezing the symbol both builds observe makes
    the parity deterministic. ``verify_attestation`` reads the recorded date via
    ``fromisoformat``, which a ``date`` subclass inherits unchanged."""

    @classmethod
    def today(cls) -> date:
        return date(2026, 6, 3)


def test_mcp_attest_payload_equals_core(monkeypatch, tmp_path: Path) -> None:
    # Parity: MCP `attest`'s canonical payload bytes == core build_attestation for the
    # same tree+key. Both default today=date.today(); freezing that symbol for the duration
    # of both builds makes the new `attested_at` field deterministic across midnight.
    monkeypatch.delenv(WARDLINE_ATTEST_KEY_ENV, raising=False)
    monkeypatch.setattr("wardline.core.attest.date", _FixedDate)
    proj = _annotated_tree(tmp_path)
    key, _ = mint_attest_key(proj)  # minted into proj/.env (env unset → .env is the source)

    result = _call(WardlineMCPServer(root=proj), "attest", {})
    bundle = _payload(result)
    expected = build_attestation(proj, key, confine_to_root=True)

    assert _canonical_bytes(bundle["payload"]) == _canonical_bytes(expected["payload"])
    # The bundle carries only the non-secret key_id, never the key itself.
    assert key not in json.dumps(bundle)
    assert bundle["signature"]["key_id"]


def test_mcp_attest_then_verify_round_trips(monkeypatch, tmp_path: Path) -> None:
    # Round-trip: feed the returned bundle into verify_attestation → signature_valid.
    monkeypatch.delenv(WARDLINE_ATTEST_KEY_ENV, raising=False)
    proj = _annotated_tree(tmp_path)
    mint_attest_key(proj)
    server = WardlineMCPServer(root=proj)

    bundle = _payload(_call(server, "attest", {}))
    verified = _payload(_call(server, "verify_attestation", {"bundle": bundle}))
    assert verified["signature_valid"] is True
    assert verified["reproduced"] is None  # reproduce defaults False


def test_mcp_attest_reproduce_with_trusted_pack(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv(WARDLINE_ATTEST_KEY_ENV, raising=False)
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[3]))
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "weft.toml").write_text('[wardline]\npacks = ["tests.unit.install.mock_pack"]\n', encoding="utf-8")
    (proj / "m.py").write_text(
        "from tests.unit.install.mock_pack import mock_boundary\n\n@mock_boundary\ndef violator():\n    pass\n",
        encoding="utf-8",
    )
    mint_attest_key(proj)
    server = WardlineMCPServer(root=proj)
    trust_args = {"trust_packs": ["tests.unit.install.mock_pack"], "trust_local_packs": True}

    bundle = _payload(_call(server, "attest", trust_args))
    assert bundle["payload"]["posture"]["defect_total"] >= 1

    verified = _payload(_call(server, "verify_attestation", {"bundle": bundle, "reproduce": True, **trust_args}))
    assert verified["signature_valid"] is True
    assert verified["reproduced"] is True


def test_mcp_attest_no_key_is_iserror(monkeypatch, tmp_path: Path) -> None:
    # No key (env unset, no .env) → tool-EXECUTION isError result, NOT a crash.
    monkeypatch.delenv(WARDLINE_ATTEST_KEY_ENV, raising=False)
    proj = _annotated_tree(tmp_path)  # no mint → no key

    result = _call(WardlineMCPServer(root=proj), "attest", {})
    assert result.get("isError") is True
    assert "attest key" in result["content"][0]["text"].lower()


def test_mcp_verify_no_key_is_iserror(monkeypatch, tmp_path: Path) -> None:
    # verify_attestation also needs the key; absent → isError, same hint.
    monkeypatch.delenv(WARDLINE_ATTEST_KEY_ENV, raising=False)
    proj = _annotated_tree(tmp_path)

    result = _call(WardlineMCPServer(root=proj), "verify_attestation", {"bundle": {"payload": {}, "signature": {}}})
    assert result.get("isError") is True
    assert "attest key" in result["content"][0]["text"].lower()


def test_mcp_verify_malformed_bundle_is_iserror(monkeypatch, tmp_path: Path) -> None:
    """A bundle missing ``payload``/``signature`` is agent-actionable: the handler rejects
    it as a tool-EXECUTION isError naming the missing keys — NOT a raw KeyError surfaced as
    an internal error."""
    monkeypatch.delenv(WARDLINE_ATTEST_KEY_ENV, raising=False)
    proj = _annotated_tree(tmp_path)
    mint_attest_key(proj)

    result = _call(WardlineMCPServer(root=proj), "verify_attestation", {"bundle": {"foo": 1}})
    assert result.get("isError") is True
    text = result["content"][0]["text"].lower()
    assert "payload" in text and "signature" in text
    assert "internal" not in text


def _git(args: list[str], cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True)


def test_mcp_attest_dirty_strict_default_then_allow(monkeypatch, tmp_path: Path) -> None:
    # Default-strict on a dirty tree: an agent must not silently attest uncommitted changes.
    # A THROWAWAY tmp git repo (the feature under test on a tmp repo — NOT this repo's VCS).
    monkeypatch.delenv(WARDLINE_ATTEST_KEY_ENV, raising=False)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "m.py").write_text(_MODULE, encoding="utf-8")
    _git(["init"], repo)
    _git(["add", "-A"], repo)
    _git(["-c", "user.email=t@example.com", "-c", "user.name=Test", "commit", "-m", "init"], repo)
    mint_attest_key(repo)
    # An uncommitted change flips the tree dirty.
    (repo / "m.py").write_text(_MODULE + "\nx = 2\n", encoding="utf-8")

    server = WardlineMCPServer(root=repo)
    # No allow_dirty arg → refused as isError.
    refused = _call(server, "attest", {})
    assert refused.get("isError") is True
    assert "dirty" in refused["content"][0]["text"].lower()

    # allow_dirty=true → builds, records dirty: true.
    built = _payload(_call(server, "attest", {"allow_dirty": True}))
    assert built["payload"]["dirty"] is True
