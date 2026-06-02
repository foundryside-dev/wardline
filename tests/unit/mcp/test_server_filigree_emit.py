"""WS-A1: MCP `scan` emits to Filigree when an emitter is injected, fail-soft.

Mirrors test_server_clarion_write.py: inject a duck-typed emitter into `_scan`
and assert on the `filigree` block. The MCP surface is fail-soft — a rejected
payload (FiligreeEmitError) or an unreachable sibling is REPORTED in the block,
never allowed to discard the scan payload (the deliberate asymmetry from the
Clarion block at server.py:91-95).
"""

from wardline.core.errors import FiligreeEmitError
from wardline.core.filigree_emit import EmitResult
from wardline.mcp.server import _scan

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

    def emit(self, findings):
        self.seen = list(findings)
        return self._result


class RaisingEmitter:
    def emit(self, findings):
        raise FiligreeEmitError("Filigree rejected scan-results (400) at http://x: bad payload")


def test_scan_emits_to_filigree_when_emitter_present(tmp_path):
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    out = _scan({}, tmp_path, None, FakeEmitter(EmitResult(reachable=True, created=2, updated=1)))
    assert out["filigree"]["reachable"] is True
    assert out["filigree"]["created"] == 2
    assert out["filigree"]["updated"] == 1
    assert out["filigree"]["failed"] == 0


def test_scan_filigree_block_null_when_no_emitter(tmp_path):
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    out = _scan({}, tmp_path, None, None)
    assert out["filigree"] is None


def test_scan_survives_filigree_emit_error(tmp_path):
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    out = _scan({}, tmp_path, None, RaisingEmitter())
    assert out["filigree"]["reachable"] is False
    assert out["filigree"]["warnings"]  # carries the rejection text
    # The scan payload is intact, NOT discarded — assert keys _scan always returns.
    assert "summary" in out and "findings" in out and "gate" in out
    assert out["summary"]["total"] >= 1  # PY-WL-101 fires on _LEAKY


def test_scan_unreachable_filigree_is_soft(tmp_path):
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    out = _scan({}, tmp_path, None, FakeEmitter(EmitResult(reachable=False)))
    assert out["filigree"]["reachable"] is False
    assert out["summary"]["total"] >= 1
