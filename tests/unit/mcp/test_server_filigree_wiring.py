"""WS-A1: the server builds a FiligreeEmitter from its URL and threads it into
the scan handler — mirroring _clarion_client()."""

from wardline.core.filigree_emit import EmitResult, FiligreeEmitter
from wardline.mcp.server import WardlineMCPServer

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


class CapturingEmitter:
    def __init__(self):
        self.seen = None

    def emit(self, findings):
        self.seen = list(findings)
        return EmitResult(reachable=True, created=len(self.seen))


def test_filigree_emitter_none_without_url(tmp_path):
    srv = WardlineMCPServer(root=tmp_path)
    assert srv._filigree_emitter() is None


def test_filigree_emitter_built_with_url(tmp_path):
    srv = WardlineMCPServer(root=tmp_path, filigree_url="http://filigree.local/api/loom/scan-results")
    assert isinstance(srv._filigree_emitter(), FiligreeEmitter)


def test_scan_handler_threads_filigree_emitter(tmp_path, monkeypatch):
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    srv = WardlineMCPServer(root=tmp_path, filigree_url="http://filigree.local/api")
    cap = CapturingEmitter()
    # The scan handler calls self._filigree_emitter() at call time, so patching the
    # bound method on the instance redirects it to our capturing fake.
    monkeypatch.setattr(srv, "_filigree_emitter", lambda: cap)
    out = srv._tools["scan"].handler({}, tmp_path)
    assert out["filigree"]["reachable"] is True
    assert cap.seen is not None and len(cap.seen) >= 1
