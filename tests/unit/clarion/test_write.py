from wardline.clarion.client import WriteResult
from wardline.clarion.write import write_facts_to_clarion
from wardline.core.run import run_scan

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
    outcome = write_facts_to_clarion(result, proj, client)
    assert outcome.reachable is True
    assert outcome.written == 2
    assert outcome.unresolved_qualnames == ("x.y",)
    assert client.written_payloads is not None


def test_write_disabled_is_soft(tmp_path):
    proj = _proj(tmp_path)
    result = run_scan(proj)
    client = FakeClient(WriteResult(reachable=False, disabled_reason="WRITE_DISABLED"))
    outcome = write_facts_to_clarion(result, proj, client)
    assert outcome.reachable is False
    assert outcome.disabled_reason == "WRITE_DISABLED"


def test_outage_is_soft(tmp_path):
    proj = _proj(tmp_path)
    result = run_scan(proj)
    client = FakeClient(WriteResult(reachable=False))
    outcome = write_facts_to_clarion(result, proj, client)
    assert outcome.reachable is False
    assert outcome.disabled_reason is None
