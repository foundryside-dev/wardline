import dataclasses

from wardline.core.delta_scope import DeltaScopeReport
from wardline.core.run import run_scan
from wardline.loomweave.client import WriteResult
from wardline.loomweave.facts import build_taint_facts
from wardline.loomweave.write import DELTA_SKIP_REASON, NO_FACTS_REASON, write_facts_to_loomweave

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


def _scope(mode: str) -> DeltaScopeReport:
    return DeltaScopeReport(
        mode=mode,
        gate_authority="advisory" if mode == "delta" else "gate-of-record",
        scope_source="entity_list",
        entities_requested=1,
        files_discovered=1,
        files_analyzed=1,
        in_scope_findings=0,
        fell_back_count=0,
        stale_sei_count=0,
        unresolved_entities=(),
        loomweave_used=False,
    )


def test_delta_scan_skips_write_with_signal(tmp_path):
    # The Loomweave analog of the Filigree INV-5 guard: a delta scan's findings are
    # display-filtered to the affected entities while the context carries EVERY entity
    # in every analyzed file, so a write would overwrite correct store facts with
    # hollow findings:[] blobs stamped fresh (false-green telemetry). The write is
    # skipped — and the skip is SIGNALLED via disabled_reason, never silent.
    proj = _proj(tmp_path)
    result = dataclasses.replace(run_scan(proj), scope=_scope("delta"))
    client = FakeClient(WriteResult(reachable=True, written=2))
    outcome = write_facts_to_loomweave(result, proj, client)
    assert client.written_payloads is None  # no write attempted
    assert outcome.reachable is False  # never a fabricated positive
    assert outcome.written == 0
    assert outcome.disabled_reason == DELTA_SKIP_REASON


def test_delta_scan_builds_no_facts_even_when_called_directly(tmp_path):
    # Defense in depth: the projection itself refuses delta results, so a future
    # direct caller of build_taint_facts cannot hollow the store either.
    proj = _proj(tmp_path)
    result = dataclasses.replace(run_scan(proj), scope=_scope("delta"))
    assert build_taint_facts(result, proj) == []


def test_full_fallback_scope_still_writes(tmp_path):
    # mode="full-fallback" means the FULL tree was analyzed (INV-3 fail-closed
    # honesty) — facts are complete and the write proceeds normally.
    proj = _proj(tmp_path)
    result = dataclasses.replace(run_scan(proj), scope=_scope("full-fallback"))
    client = FakeClient(WriteResult(reachable=True, written=2))
    outcome = write_facts_to_loomweave(result, proj, client)
    assert client.written_payloads is not None
    assert outcome.reachable is True
    assert outcome.written == 2


def test_no_facts_is_reported_as_no_attempt_not_reachable(tmp_path):
    # Zero facts means the server was never contacted — reachable must not be a
    # fabricated positive reachability claim (the store could be down); the skip is
    # signalled via disabled_reason.
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "README.md").write_text("docs only\n", encoding="utf-8")
    result = run_scan(proj)
    client = FakeClient(WriteResult(reachable=True, written=99))
    outcome = write_facts_to_loomweave(result, proj, client)
    assert client.written_payloads is None  # no network attempt
    assert outcome.reachable is False
    assert outcome.written == 0
    assert outcome.disabled_reason == NO_FACTS_REASON
