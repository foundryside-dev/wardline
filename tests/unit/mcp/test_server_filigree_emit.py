"""WS-A1: MCP `scan` emits to Filigree when an emitter is injected.

Mirrors test_server_loomweave_write.py: inject a duck-typed emitter into `_scan`
and assert on the `filigree` block. Sibling-unreachable responses remain
fail-soft, but Filigree protocol/client rejections (FiligreeEmitError) are loud:
the MCP scan must not return a successful payload that hides tracker drift.
"""

import pytest

from wardline.core.errors import FiligreeEmitError
from wardline.core.filigree_emit import EmitResult
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
        "warnings": [],
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
        "warnings": [],
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
        "warnings": [],
        "disabled_reason": "not configured",
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
    assert out["summary"]["total"] >= 1
