import blake3

from wardline.clarion.client import TaintFactView, WriteResult
from wardline.mcp.server import _explain_taint, _scan

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


def _fresh_view(proj, qualname, callee_qualname):
    h = blake3.blake3((proj / "svc.py").read_bytes()).hexdigest()
    blob = {
        "schema_version": "wardline-taint-1", "qualname": qualname,
        "content_hash_at_compute": h,
        "taint": {"declared_return": "INTEGRAL", "actual_return": "EXTERNAL_RAW",
                  "source": "anchored", "contributing_callee_qualname": callee_qualname,
                  "resolved_call_count": 1, "unresolved_call_count": 0},
        "findings": [],
    }
    return TaintFactView(qualname=qualname, exists=True, wardline_json=blob,
                         current_content_hash=h)


class MapClient:
    def __init__(self, by_qualname):
        self._by = by_qualname

    def batch_get(self, qualnames):
        return [self._by.get(q, TaintFactView(qualname=q, exists=False)) for q in qualnames]


def test_explain_taint_chain_block_with_store(tmp_path):
    # chain:true + a configured store walks the full taint chain (leaky -> read_raw
    # boundary leaf) and surfaces it as a `chain` block alongside the single-hop fields.
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    client = MapClient({
        "svc.leaky": _fresh_view(tmp_path, "svc.leaky", "svc.read_raw"),
        "svc.read_raw": _fresh_view(tmp_path, "svc.read_raw", None),
    })
    out = _explain_taint(
        {"sink_qualname": "svc.leaky", "chain": True}, tmp_path, client
    )
    assert "chain" in out
    assert [h["qualname"] for h in out["chain"]["hops"]] == ["svc.leaky", "svc.read_raw"]
    assert out["chain"]["truncated_at"] is None
