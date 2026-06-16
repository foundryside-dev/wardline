"""WS-A1: MCP `scan` emits to Filigree when an emitter is injected.

Mirrors test_server_loomweave_write.py: inject a duck-typed emitter into `_scan`
and assert on the `filigree` block. Sibling-unreachable responses remain
fail-soft, but Filigree protocol/client rejections (FiligreeEmitError) are loud:
the MCP scan must not return a successful payload that hides tracker drift.
"""

import pytest

from wardline.core.errors import FiligreeEmitError
from wardline.core.filigree_emit import EmitResult, FailedFinding
from wardline.mcp.server import WardlineMCPServer, _scan

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


class FakeEmitter:
    """Duck-typed FiligreeEmitter: records the findings it was handed, returns a
    canned EmitResult."""

    def __init__(self, result):
        self._result = result
        self.seen = None
        self.scanned_paths = None

    def emit(self, findings, *, scanned_paths=()):
        self.seen = list(findings)
        self.scanned_paths = tuple(scanned_paths)
        return self._result


class RaisingEmitter:
    def emit(self, findings, *, scanned_paths=()):
        raise FiligreeEmitError("Filigree rejected scan-results (400) at http://x: bad payload")


class FakeLoomweave:
    def write_taint_facts(self, facts):
        from wardline.loomweave.client import WriteResult

        return WriteResult(reachable=True, written=len(facts))


def test_scan_emits_to_filigree_when_emitter_present(tmp_path):
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    emitter = FakeEmitter(EmitResult(reachable=True, created=2, updated=1))
    out = _scan({}, tmp_path, None, emitter)
    assert out["filigree"]["reachable"] is True
    assert out["filigree"]["created"] == 2
    assert out["filigree"]["updated"] == 1
    assert out["filigree"]["failed"] == 0
    assert out["filigree_emit"] == {
        "configured": True,
        "reachable": True,
        "created": 2,
        "updated": 1,
        "failed": 0,
        "failures": [],
        "warnings": [],
        "status": None,
        "auth_rejected": False,
        "token_sent": False,
        "url": None,
        "disabled_reason": None,
        "destination": {"url": None, "project": None, "project_pinned": False},
    }
    assert emitter.scanned_paths == ("svc.py",)


def test_scan_reports_both_integrations_successful(tmp_path):
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    out = _scan({}, tmp_path, FakeLoomweave(), FakeEmitter(EmitResult(reachable=True, created=2, updated=1)))
    assert out["loomweave_write"]["configured"] is True
    assert out["loomweave_write"]["reachable"] is True
    assert out["loomweave_write"]["written"] >= 2
    assert out["filigree_emit"] == {
        "configured": True,
        "reachable": True,
        "created": 2,
        "updated": 1,
        "failed": 0,
        "failures": [],
        "warnings": [],
        "status": None,
        "auth_rejected": False,
        "token_sent": False,
        "url": None,
        "disabled_reason": None,
        "destination": {"url": None, "project": None, "project_pinned": False},
    }


def test_scan_filigree_block_null_when_no_emitter(tmp_path):
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    out = _scan({}, tmp_path, None, None)
    assert out["filigree"] is None
    assert out["filigree_emit"] == {
        "configured": False,
        "reachable": None,
        "created": 0,
        "updated": 0,
        "failed": 0,
        "failures": [],
        "warnings": [],
        "disabled_reason": "not configured",
        "destination": {"url": None, "project": None, "project_pinned": False},
    }


def test_scan_propagates_filigree_emit_error(tmp_path):
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    with pytest.raises(FiligreeEmitError, match="rejected scan-results"):
        _scan({}, tmp_path, None, RaisingEmitter())


def test_mcp_scan_filigree_emit_error_is_not_a_success_payload(tmp_path, monkeypatch):
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    server = WardlineMCPServer(root=tmp_path)
    monkeypatch.setattr(server, "_filigree_emitter", lambda *args, **kwargs: RaisingEmitter())

    resp = server.rpc.dispatch(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "scan", "arguments": {}}}
    )

    assert "error" not in resp, resp
    assert resp["result"]["isError"] is True
    assert "Filigree rejected scan-results" in resp["result"]["content"][0]["text"]


def test_scan_unreachable_filigree_is_soft(tmp_path):
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    out = _scan({}, tmp_path, None, FakeEmitter(EmitResult(reachable=False)))
    assert out["filigree"]["reachable"] is False
    assert out["filigree_emit"]["configured"] is True
    assert out["filigree_emit"]["reachable"] is False
    assert out["filigree_emit"]["disabled_reason"] == "filigree unreachable"
    assert out["summary"]["total"] >= 1


def test_scan_filigree_401_surfaces_auth_reason_to_agent(tmp_path):
    # Dogfood #5 (MCP parity): a 401 stays soft but the agent must read an actionable
    # disabled_reason naming the token, not a flat "unreachable".
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    out = _scan({}, tmp_path, None, FakeEmitter(EmitResult(reachable=False, status=401)))
    assert out["filigree"]["reachable"] is False  # still soft
    reason = out["filigree_emit"]["disabled_reason"]
    assert "401" in reason and "WEFT_FEDERATION_TOKEN" in reason
    assert "unreachable" not in reason


def test_scan_filigree_403_says_forbidden_not_set_a_token(tmp_path):
    # A 403 is auth-rejected too, but "set WEFT_FEDERATION_TOKEN" is the wrong remedy
    # (the token is present and lacks access / is blocked). The reason must say forbidden,
    # not point at the env var.
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    out = _scan({}, tmp_path, None, FakeEmitter(EmitResult(reachable=False, status=403)))
    assert out["filigree"]["reachable"] is False  # still soft
    reason = out["filigree_emit"]["disabled_reason"]
    assert "403" in reason and "forbidden" in reason
    assert "WEFT_FEDERATION_TOKEN" not in reason
    assert "unreachable" not in reason


def test_scan_partial_ingest_surfaces_failures_to_agent(tmp_path):
    # PDR-0023: a partial ingest (some findings rejected) must NOT read as a clean emit on
    # the agent-facing MCP surface. The `failures` array names which findings failed and why,
    # so an agent can distinguish "all emitted" from "M of N emitted, K failed because R".
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    result = EmitResult(
        reachable=True,
        created=1,
        failures=(FailedFinding(reason="scheme_mismatch", detail="expected wlfp3", fingerprint="wlfp2:bad"),),
    )
    out = _scan({}, tmp_path, None, FakeEmitter(result))
    # weft-reason (G1): each failure wire carries the shipped domain fields AND the canonical
    # carrier triple {reason_class, cause, fix} additively (scheme_mismatch -> scheme_mismatch).
    expected_failure = {
        "reason": "scheme_mismatch",
        "detail": "expected wlfp3",
        "reason_class": "scheme_mismatch",
        "cause": "expected wlfp3",
        "fix": (
            "align the wardline fingerprint scheme to the scheme Filigree expects, then re-emit (a drift join-misses)"
        ),
        "fingerprint": "wlfp2:bad",
    }
    assert out["filigree"]["failed"] == 1
    assert out["filigree"]["failures"] == [expected_failure]
    assert out["filigree_emit"]["failed"] == 1
    assert out["filigree_emit"]["failures"] == [expected_failure]


def test_scan_filigree_5xx_says_server_error_not_unreachable(tmp_path):
    # A 5xx outage reached us (the sibling is degraded, not absent). The disabled_reason
    # must say "server error (503)", distinct from both the 401 auth case and the genuine
    # transport-unreachable case (dogfood #5, the untested sibling of the 401 path).
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    out = _scan({}, tmp_path, None, FakeEmitter(EmitResult(reachable=False, status=503)))
    assert out["filigree"]["reachable"] is False  # still soft
    reason = out["filigree_emit"]["disabled_reason"]
    assert "503" in reason and "server error" in reason
    assert "unreachable" not in reason
    assert "WEFT_FEDERATION_TOKEN" not in reason
