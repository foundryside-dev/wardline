from wardline.core.run import run_scan
from wardline.loomweave.client import WriteResult
from wardline.loomweave.write import write_facts_to_loomweave

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


class FakeClient:
    def __init__(self, result):
        self._result = result
        self.written_payloads = None

    def write_taint_facts(self, facts):
        self.written_payloads = facts
        return self._result


def _proj(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")
    return proj


def test_write_reports_written_and_unresolved(tmp_path):
    proj = _proj(tmp_path)
    result = run_scan(proj)
    client = FakeClient(WriteResult(reachable=True, written=2, unresolved_qualnames=("x.y",)))
    outcome = write_facts_to_loomweave(result, proj, client)
    assert outcome.reachable is True
    assert outcome.written == 2
    assert outcome.unresolved_qualnames == ("x.y",)
    assert client.written_payloads is not None


def test_write_crlf_file_sends_fresh_facts(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    raw = _LEAKY.replace("\n", "\r\n").encode("utf-8")
    (proj / "svc.py").write_bytes(raw)
    result = run_scan(proj)
    client = FakeClient(WriteResult(reachable=True, written=2))

    import blake3

    outcome = write_facts_to_loomweave(result, proj, client)
    facts = {f["qualname"]: f for f in client.written_payloads or []}

    assert outcome.written == 2
    assert "svc.leaky" in facts
    assert facts["svc.leaky"]["content_hash_at_compute"] == blake3.blake3(raw).hexdigest()


def test_write_disabled_is_soft(tmp_path):
    proj = _proj(tmp_path)
    result = run_scan(proj)
    client = FakeClient(WriteResult(reachable=False, disabled_reason="WRITE_DISABLED"))
    outcome = write_facts_to_loomweave(result, proj, client)
    assert outcome.reachable is False
    assert outcome.disabled_reason == "WRITE_DISABLED"


def test_outage_is_soft(tmp_path):
    proj = _proj(tmp_path)
    result = run_scan(proj)
    client = FakeClient(WriteResult(reachable=False))
    outcome = write_facts_to_loomweave(result, proj, client)
    assert outcome.reachable is False
    assert outcome.disabled_reason is None
