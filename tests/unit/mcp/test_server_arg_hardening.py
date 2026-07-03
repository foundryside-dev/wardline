"""MCP argument hardening for the degraded no-jsonschema mode, plus the legis
artifact's config provenance.

Two pinned invariants:

1. Without jsonschema, ``_tools_call`` skips schema validation (stderr warning only),
   so handlers run on raw JSON. Every gate-relevant boolean must go through the strict
   ``_bool_arg`` guard — ``bool("false")`` is ``True``, so truthy coercion would let a
   client's string ``"false"`` silently INVERT gate-relevant intent (trust repo-local
   packs, sign a dirty tree, mass-promote every defect). Likewise ``fail_on`` must
   reject ``"none"`` with the documented enum error: ``Severity.NONE`` is absent from
   the gate's rank order, so accepting it surfaced as a KeyError-shaped
   "wardline internal error" deep in ``gate_trips``.

2. ``_attach_legis_artifact`` must build the artifact from the config the scan
   ACTUALLY ran with (``config`` resolves against the SERVER root, per the input
   schema) — never re-resolve the arg against the scan sub-path, which either loads a
   DIFFERENT policy into the signed artifact (rule_set_version/scan_scope provenance
   lie on the legis wire) or raises after a successful scan, violating the block's
   fail-soft contract.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from wardline.core import config as config_mod
from wardline.core.attest_key import WARDLINE_ATTEST_KEY_ENV
from wardline.core.legis import LEGIS_ARTIFACT_KEY_ENV
from wardline.core.ruleset import ruleset_hash
from wardline.mcp.server import WardlineMCPServer, _scan

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


def _dispatch(server: WardlineMCPServer, name: str, arguments: dict) -> dict:
    resp = server.rpc.dispatch(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
    )
    assert resp is not None  # dispatch returns None only for id-less notifications; this carries id=1
    return resp


def _block_jsonschema(monkeypatch) -> None:
    """Simulate the partial install: ``import jsonschema`` raises ImportError, so
    ``_tools_call`` runs the handler UNVALIDATED (the degraded mode under test)."""
    monkeypatch.setitem(sys.modules, "jsonschema", None)


# ---------------------------------------------------------------------------
# 1. Strict booleans in the degraded no-jsonschema mode
# ---------------------------------------------------------------------------


def test_scan_rejects_string_trust_local_packs_without_jsonschema(tmp_path, monkeypatch) -> None:
    # bool("false") is True: coercion would TRUST repo-checkout-controlled rule packs,
    # which can rewrite severities/vocab and flip the gate green.
    _block_jsonschema(monkeypatch)
    server = WardlineMCPServer(root=_leaky_project(tmp_path))
    resp = _dispatch(server, "scan", {"trust_local_packs": "false"})
    assert resp["result"]["isError"] is True
    assert "trust_local_packs must be a boolean" in resp["result"]["content"][0]["text"]


def test_scan_rejects_string_strict_defaults_without_jsonschema(tmp_path, monkeypatch) -> None:
    _block_jsonschema(monkeypatch)
    server = WardlineMCPServer(root=_leaky_project(tmp_path))
    resp = _dispatch(server, "scan", {"strict_defaults": "false"})
    assert resp["result"]["isError"] is True
    assert "strict_defaults must be a boolean" in resp["result"]["content"][0]["text"]


def test_scan_real_booleans_still_work_without_jsonschema(tmp_path, monkeypatch) -> None:
    # The strict guard must reject only NON-booleans: genuine JSON booleans pass through
    # unchanged in the degraded mode.
    _block_jsonschema(monkeypatch)
    server = WardlineMCPServer(root=_leaky_project(tmp_path))
    resp = _dispatch(server, "scan", {"trust_local_packs": False, "strict_defaults": False, "summary_only": True})
    assert not resp["result"].get("isError"), resp
    out = json.loads(resp["result"]["content"][0]["text"])
    assert out["summary"]["total"] >= 1


def test_attest_rejects_string_allow_dirty_without_jsonschema(tmp_path, monkeypatch) -> None:
    # allow_dirty="false" coerced truthy would sign a dirty tree the caller explicitly
    # asked not to attest.
    _block_jsonschema(monkeypatch)
    monkeypatch.setenv(WARDLINE_ATTEST_KEY_ENV, "testsecret")
    server = WardlineMCPServer(root=_leaky_project(tmp_path))
    resp = _dispatch(server, "attest", {"allow_dirty": "false"})
    assert resp["result"]["isError"] is True
    assert "allow_dirty must be a boolean" in resp["result"]["content"][0]["text"]


def test_verify_attestation_rejects_string_reproduce_without_jsonschema(tmp_path, monkeypatch) -> None:
    _block_jsonschema(monkeypatch)
    monkeypatch.setenv(WARDLINE_ATTEST_KEY_ENV, "testsecret")
    server = WardlineMCPServer(root=_leaky_project(tmp_path))
    resp = _dispatch(
        server,
        "verify_attestation",
        {"bundle": {"payload": {}, "signature": "hmac-sha256:00"}, "reproduce": "false"},
    )
    assert resp["result"]["isError"] is True
    assert "reproduce must be a boolean" in resp["result"]["content"][0]["text"]


def test_scan_file_findings_rejects_string_all_active_without_jsonschema(tmp_path, monkeypatch) -> None:
    # all_active="false" coerced truthy selects EVERY active defect AND flips the
    # dry_run default off — a mass-promotion into real Filigree issues.
    _block_jsonschema(monkeypatch)
    server = WardlineMCPServer(root=_leaky_project(tmp_path))
    resp = _dispatch(server, "scan_file_findings", {"all_active": "false"})
    assert resp["result"]["isError"] is True
    assert "all_active must be a boolean" in resp["result"]["content"][0]["text"]


def test_scan_file_findings_rejects_string_dry_run_without_jsonschema(tmp_path, monkeypatch) -> None:
    _block_jsonschema(monkeypatch)
    server = WardlineMCPServer(root=_leaky_project(tmp_path))
    resp = _dispatch(server, "scan_file_findings", {"dry_run": "false"})
    assert resp["result"]["isError"] is True
    assert "dry_run must be a boolean" in resp["result"]["content"][0]["text"]


def test_scan_fail_on_none_is_documented_enum_error_not_internal_crash(tmp_path, monkeypatch) -> None:
    # Severity.NONE exists (facts/metrics) but is absent from the gate's rank order;
    # pre-guard it fell through to a KeyError in gate_trips -> "wardline internal error".
    # The degraded mode must produce the SAME documented enum error jsonschema gives.
    _block_jsonschema(monkeypatch)
    server = WardlineMCPServer(root=_leaky_project(tmp_path))
    resp = _dispatch(server, "scan", {"fail_on": "none"})
    assert resp["result"]["isError"] is True
    text = resp["result"]["content"][0]["text"]
    assert "fail_on must be one of CRITICAL/ERROR/WARN/INFO" in text
    assert "internal error" not in text


# ---------------------------------------------------------------------------
# 2. Legis artifact config provenance (root-resolved, same policy as the scan)
# ---------------------------------------------------------------------------


def _subpath_project(tmp_path: Path) -> Path:
    """Server root with a scannable ``sub/`` and a root-level explicit config."""
    root = tmp_path / "proj"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "svc.py").write_text(_LEAKY, encoding="utf-8")
    (root / "weft.toml").write_text('[wardline]\nexclude = ["zzz_root_marker/**"]\n', encoding="utf-8")
    return root


def test_legis_artifact_subpath_scan_with_root_relative_config_stays_fail_soft(tmp_path, monkeypatch) -> None:
    # scan(path:"sub", config:"weft.toml"): run_scan resolves the config against the
    # SERVER root (input-schema contract). The artifact block used to RE-resolve it
    # against the sub-path, where the file does not exist -> ConfigError AFTER a
    # successful scan, discarding the whole response. It must reuse the scan's config.
    monkeypatch.delenv(LEGIS_ARTIFACT_KEY_ENV, raising=False)
    root = _subpath_project(tmp_path)
    out = _scan({"path": "sub", "config": "weft.toml", "legis_artifact": True}, root, None, None)
    assert "legis_artifact" in out
    expected = ruleset_hash(config_mod.load(root / "weft.toml", explicit=True))
    assert out["legis_artifact"]["rule_set_version"] == expected


def test_legis_artifact_uses_scan_config_not_subpath_config(tmp_path, monkeypatch) -> None:
    # A DIFFERENT weft.toml under the sub-path must never leak into the artifact:
    # rule_set_version/scan_scope attest the policy that produced the findings, and a
    # sub-path re-resolve would sign provenance from a config the scan never used.
    monkeypatch.delenv(LEGIS_ARTIFACT_KEY_ENV, raising=False)
    root = _subpath_project(tmp_path)
    (root / "sub" / "weft.toml").write_text('[wardline]\nexclude = ["zzz_sub_marker/**"]\n', encoding="utf-8")
    out = _scan({"path": "sub", "config": "weft.toml", "legis_artifact": True}, root, None, None)
    assert "legis_artifact" in out
    scan_cfg_hash = ruleset_hash(config_mod.load(root / "weft.toml", explicit=True))
    sub_cfg_hash = ruleset_hash(config_mod.load(root / "sub" / "weft.toml", explicit=True))
    assert scan_cfg_hash != sub_cfg_hash  # the divergence the test relies on is real
    assert out["legis_artifact"]["rule_set_version"] == scan_cfg_hash


def test_legis_artifact_implicit_config_still_resolves_at_scan_path(tmp_path, monkeypatch) -> None:
    # No explicit config: run_scan defaults to weft_config_path(<scan path>) and the
    # artifact block must keep matching THAT (the sub-path's own weft.toml), not the
    # server root's.
    monkeypatch.delenv(LEGIS_ARTIFACT_KEY_ENV, raising=False)
    root = _subpath_project(tmp_path)
    (root / "sub" / "weft.toml").write_text('[wardline]\nexclude = ["zzz_sub_marker/**"]\n', encoding="utf-8")
    out = _scan({"path": "sub", "legis_artifact": True}, root, None, None)
    assert "legis_artifact" in out
    sub_cfg_hash = ruleset_hash(config_mod.load(root / "sub" / "weft.toml", explicit=True))
    assert out["legis_artifact"]["rule_set_version"] == sub_cfg_hash
