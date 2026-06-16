import blake3

from wardline.core.explain import explain_finding
from wardline.core.finding import Kind, SuppressionState
from wardline.core.run import run_scan
from wardline.loomweave.client import TaintFactView

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_raw(p):\n    return p\n"
    "@trusted\ndef leaky(p):\n    return read_raw(p)\n"
)


def _proj(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "svc.py").write_text(_LEAKY, encoding="utf-8")
    return proj


class SpyClient:
    """Returns queued batch_get views; records whether it was consulted."""

    def __init__(self, views):
        self._views = views
        self.batch_get_calls = 0

    def batch_get(self, qualnames):
        self.batch_get_calls += 1
        return self._views


def _fresh_blob(proj, qualname):
    h = blake3.blake3((proj / "svc.py").read_bytes()).hexdigest()
    return {
        "schema_version": "wardline-taint-1",
        "qualname": qualname,
        "content_hash_at_compute": h,
        "taint": {
            "declared_return": "INTEGRAL",
            "actual_return": "EXTERNAL_RAW",
            "source": "anchored",
            "contributing_callee_qualname": "svc.read_raw",
            "resolved_call_count": 1,
            "unresolved_call_count": 0,
        },
        "findings": [{"rule_id": "PY-WL-101", "fingerprint": "fp-leaky-1", "path": "svc.py", "line_start": 6}],
    }, h


def test_fresh_fact_is_served_without_reanalysis(tmp_path, monkeypatch):
    proj = _proj(tmp_path)
    blob, h = _fresh_blob(proj, "svc.leaky")
    view = TaintFactView(qualname="svc.leaky", exists=True, wardline_json=blob, current_content_hash=h)
    client = SpyClient([view])

    import wardline.core.explain as explain_mod

    calls = {"n": 0}
    real = explain_mod.run_scan

    def counting(*a, **k):
        calls["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(explain_mod, "run_scan", counting)

    exp = explain_finding(proj, path="svc.py", line=6, loomweave=client, sink_qualname="svc.leaky")
    assert exp is not None
    assert exp.sink_qualname == "svc.leaky"
    assert exp.tier_in == "EXTERNAL_RAW"
    assert exp.immediate_tainted_callee == "read_raw"
    assert exp.path == "svc.py"
    assert exp.rule_id == "PY-WL-101"
    assert exp.fingerprint == "fp-leaky-1"  # served from the blob (no fingerprint passed by caller)
    assert calls["n"] == 0
    assert client.batch_get_calls == 1


def test_fresh_fact_selects_requested_fingerprint_from_multiple_blob_findings(tmp_path, monkeypatch):
    proj = _proj(tmp_path)
    blob, h = _fresh_blob(proj, "svc.leaky")
    blob["findings"] = [
        {"rule_id": "PY-WL-999", "fingerprint": "fp-other", "path": "svc.py", "line_start": 2},
        {"rule_id": "PY-WL-101", "fingerprint": "fp-target", "path": "svc.py", "line_start": 6},
    ]
    view = TaintFactView(qualname="svc.leaky", exists=True, wardline_json=blob, current_content_hash=h)

    import wardline.core.explain as explain_mod

    monkeypatch.setattr(explain_mod, "run_scan", lambda *a, **k: (_ for _ in ()).throw(AssertionError("reanalyzed")))

    exp = explain_finding(proj, fingerprint="fp-target", loomweave=SpyClient([view]), sink_qualname="svc.leaky")

    assert exp is not None
    assert exp.fingerprint == "fp-target"
    assert exp.rule_id == "PY-WL-101"
    assert exp.path == "svc.py"
    assert exp.line == 6


def test_fresh_fact_missing_requested_fingerprint_falls_back_to_reanalysis(tmp_path, monkeypatch):
    proj = _proj(tmp_path)
    local_finding = next(
        f
        for f in run_scan(proj).findings
        if f.kind is Kind.DEFECT and f.suppressed is SuppressionState.ACTIVE and f.rule_id == "PY-WL-101"
    )
    blob, h = _fresh_blob(proj, "svc.leaky")
    blob["findings"] = [{"rule_id": "PY-WL-999", "fingerprint": "fp-other", "path": "svc.py", "line_start": 2}]
    view = TaintFactView(qualname="svc.leaky", exists=True, wardline_json=blob, current_content_hash=h)

    import wardline.core.explain as explain_mod

    calls = {"n": 0}
    real = explain_mod.run_scan

    def counting(*a, **k):
        calls["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(explain_mod, "run_scan", counting)

    exp = explain_finding(
        proj,
        fingerprint=local_finding.fingerprint,
        loomweave=SpyClient([view]),
        sink_qualname="svc.leaky",
    )

    assert exp is not None
    assert exp.fingerprint == local_finding.fingerprint
    assert calls["n"] == 1


def test_spoofed_remote_hash_falls_back_to_reanalysis(tmp_path, monkeypatch):
    proj = _proj(tmp_path)
    local_finding = next(
        f
        for f in run_scan(proj).findings
        if f.kind is Kind.DEFECT and f.suppressed is SuppressionState.ACTIVE and f.rule_id == "PY-WL-101"
    )
    blob, _h = _fresh_blob(proj, "svc.leaky")
    spoofed = "f" * 64
    blob["content_hash_at_compute"] = spoofed
    blob["findings"] = [{"rule_id": "PY-WL-101", "fingerprint": "fp-forged", "path": "svc.py", "line_start": 6}]
    view = TaintFactView(qualname="svc.leaky", exists=True, wardline_json=blob, current_content_hash=spoofed)

    import wardline.core.explain as explain_mod

    calls = {"n": 0}
    real = explain_mod.run_scan

    def counting(*a, **k):
        calls["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(explain_mod, "run_scan", counting)

    exp = explain_finding(proj, path="svc.py", line=6, loomweave=SpyClient([view]), sink_qualname="svc.leaky")

    assert exp is not None
    assert exp.fingerprint == local_finding.fingerprint
    assert exp.fingerprint != "fp-forged"
    assert calls["n"] == 1


def test_blob_qualname_mismatch_falls_back_to_reanalysis(tmp_path, monkeypatch):
    proj = _proj(tmp_path)
    blob, h = _fresh_blob(proj, "svc.other")
    view = TaintFactView(qualname="svc.leaky", exists=True, wardline_json=blob, current_content_hash=h)

    import wardline.core.explain as explain_mod

    calls = {"n": 0}
    real = explain_mod.run_scan

    def counting(*a, **k):
        calls["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(explain_mod, "run_scan", counting)

    exp = explain_finding(proj, path="svc.py", line=6, loomweave=SpyClient([view]), sink_qualname="svc.leaky")

    assert exp is not None
    assert exp.sink_qualname == "svc.leaky"
    assert calls["n"] == 1


def test_malformed_blob_counts_fall_back_to_reanalysis(tmp_path, monkeypatch):
    proj = _proj(tmp_path)
    blob, h = _fresh_blob(proj, "svc.leaky")
    blob["taint"]["resolved_call_count"] = "not-an-int"
    view = TaintFactView(qualname="svc.leaky", exists=True, wardline_json=blob, current_content_hash=h)

    import wardline.core.explain as explain_mod

    calls = {"n": 0}
    real = explain_mod.run_scan

    def counting(*a, **k):
        calls["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(explain_mod, "run_scan", counting)

    exp = explain_finding(proj, path="svc.py", line=6, loomweave=SpyClient([view]), sink_qualname="svc.leaky")

    assert exp is not None
    assert exp.resolved_call_count == 1
    assert calls["n"] == 1


def test_stale_hash_falls_back_to_reanalysis(tmp_path):
    proj = _proj(tmp_path)
    blob, h = _fresh_blob(proj, "svc.leaky")
    blob["content_hash_at_compute"] = "0" * 64
    view = TaintFactView(qualname="svc.leaky", exists=True, wardline_json=blob, current_content_hash=h)
    exp = explain_finding(proj, path="svc.py", line=6, loomweave=SpyClient([view]), sink_qualname="svc.leaky")
    assert exp is not None
    assert exp.sink_qualname == "svc.leaky"


def test_missing_current_hash_is_stale(tmp_path):
    proj = _proj(tmp_path)
    blob, h = _fresh_blob(proj, "svc.leaky")
    view = TaintFactView(qualname="svc.leaky", exists=True, wardline_json=blob, current_content_hash=None)
    exp = explain_finding(proj, path="svc.py", line=6, loomweave=SpyClient([view]), sink_qualname="svc.leaky")
    assert exp is not None


def test_exists_false_falls_back(tmp_path):
    proj = _proj(tmp_path)
    view = TaintFactView(qualname="svc.leaky", exists=False)
    exp = explain_finding(proj, path="svc.py", line=6, loomweave=SpyClient([view]), sink_qualname="svc.leaky")
    assert exp is not None


def test_no_client_is_identical_to_sp8(tmp_path):
    proj = _proj(tmp_path)
    a = explain_finding(proj, path="svc.py", line=6)
    b = explain_finding(proj, path="svc.py", line=6, loomweave=None)
    assert a == b


def test_malformed_blob_falls_back_to_reanalysis(tmp_path):
    proj = _proj(tmp_path)
    h = blake3.blake3((proj / "svc.py").read_bytes()).hexdigest()
    # fresh hash but a structurally broken blob (taint is not a dict, findings not a list)
    bad = {
        "schema_version": "wardline-taint-1",
        "qualname": "svc.leaky",
        "content_hash_at_compute": h,
        "taint": "oops",
        "findings": "nope",
    }
    view = TaintFactView(qualname="svc.leaky", exists=True, wardline_json=bad, current_content_hash=h)
    exp = explain_finding(proj, path="svc.py", line=6, loomweave=SpyClient([view]), sink_qualname="svc.leaky")
    assert exp is not None
    assert exp.sink_qualname == "svc.leaky"  # came from the real re-scan, not the bad blob
    assert exp.tier_in == "EXTERNAL_RAW"  # only the real re-scan produces this


def test_raising_client_falls_back_to_reanalysis(tmp_path):
    # A loud read error (bad token → 401, route-skew → 404) surfaces from the client
    # as LoomweaveError. explain must NOT propagate it — it degrades to the SP8 re-run,
    # so the agent still gets a correct explanation (never worse than no store).
    from wardline.core.errors import LoomweaveError

    proj = _proj(tmp_path)

    class RaisingClient:
        def batch_get(self, qualnames):
            raise LoomweaveError("Loomweave rejected batch-get (401; code=PERMISSION)")

    exp = explain_finding(proj, path="svc.py", line=6, loomweave=RaisingClient(), sink_qualname="svc.leaky")
    assert exp is not None
    assert exp.sink_qualname == "svc.leaky"  # from the real re-scan, not raised
    assert exp.tier_in == "EXTERNAL_RAW"  # only the real re-scan produces this
