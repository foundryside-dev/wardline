from wardline.clarion.client import WriteResult
from wardline.mcp.server import _scan

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


class FakeClient:
    def write_taint_facts(self, facts):
        return WriteResult(reachable=True, written=len(facts))


class RaisingClient:
    def write_taint_facts(self, facts):
        from wardline.core.errors import ClarionError

        raise ClarionError("INVALID_PATH 400")


def test_scan_tool_writes_facts_when_client_present(tmp_path):
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    out = _scan({}, tmp_path, FakeClient())
    assert out["clarion"]["reachable"] is True
    assert out["clarion"]["written"] >= 2


def test_scan_tool_clarion_block_is_null_when_no_client(tmp_path):
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    out = _scan({}, tmp_path, None)
    assert out["clarion"] is None


def test_scan_tool_survives_clarion_write_error(tmp_path):
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    out = _scan({}, tmp_path, RaisingClient())
    assert out["clarion"]["reachable"] is False
    assert out["clarion"]["disabled_reason"]  # carries the error text
    # The scan payload itself is intact, NOT discarded — assert on real scan keys
    # that _scan always returns.
    assert "summary" in out
    assert "findings" in out
    assert "gate" in out
    # PY-WL-101 fires on _LEAKY, so the scan found real findings.
    assert out["summary"]["total"] >= 1
