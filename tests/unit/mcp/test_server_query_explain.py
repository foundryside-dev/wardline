"""WS-B1/B2: MCP `scan` server-side `where` filter and `explain` inliner."""

import pytest

from wardline.mcp.server import ToolError, _scan


def _many_leaks(n: int) -> str:
    head = "from wardline.decorators import external_boundary, trusted\n@external_boundary\ndef raw(p):\n    return p\n"
    body = "".join(f"@trusted\ndef leak_{i}(p):\n    return raw(p)\n" for i in range(n))
    return head + body


def _baseline_all(tmp_path) -> None:
    # Baseline every PY-WL-101 finding so they all become suppressed=baselined.
    from wardline.core.baseline import write_baseline
    from wardline.core.run import run_scan

    scan = run_scan(tmp_path)
    defects = [f for f in scan.findings if f.rule_id == "PY-WL-101"]
    bl = tmp_path / ".wardline" / "baseline.yaml"
    bl.parent.mkdir(parents=True, exist_ok=True)
    write_baseline(bl, defects)

# Two boundaries + two trusted leaks → PY-WL-101 fires on both leaks.
_SRC = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\ndef read_a(p):\n    return p\n"
    "@external_boundary\ndef read_b(p):\n    return p\n"
    "@trusted\ndef leak_a(p):\n    return read_a(p)\n"
    "@trusted\ndef leak_b(p):\n    return read_b(p)\n"
)


def test_where_filters_findings_by_qualname(tmp_path):
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    full = _scan({}, tmp_path)
    qualnames = {f["qualname"] for f in full["findings"] if f["rule_id"] == "PY-WL-101"}
    assert "svc.leak_a" in qualnames and "svc.leak_b" in qualnames

    filtered = _scan({"where": {"qualname": "svc.leak_a"}}, tmp_path)
    got = [f for f in filtered["findings"] if f["rule_id"] == "PY-WL-101"]
    assert {f["qualname"] for f in got} == {"svc.leak_a"}


def test_where_summary_and_gate_describe_whole_project(tmp_path):
    # The filter is a read-lens on `findings`; summary/gate stay whole-project.
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    full = _scan({}, tmp_path)
    filtered = _scan({"where": {"qualname": "svc.leak_a"}}, tmp_path)
    assert filtered["summary"] == full["summary"]
    assert filtered["gate"] == full["gate"]


def test_where_unknown_key_is_toolerror(tmp_path):
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    with pytest.raises(ToolError, match="unknown filter key"):
        _scan({"where": {"bogus": "x"}}, tmp_path)


def test_explain_inlines_provenance_on_active_defects(tmp_path):
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    out = _scan({"explain": True}, tmp_path)
    by_q = {f["qualname"]: f for f in out["findings"] if f["rule_id"] == "PY-WL-101"}
    exp = by_q["svc.leak_a"]["explanation"]
    assert exp["immediate_tainted_callee"] == "read_a"
    assert exp["source_boundary_qualname"] == "svc.read_a"
    assert "tier_in" in exp and "tier_out" in exp


def test_explain_absent_by_default(tmp_path):
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    out = _scan({}, tmp_path)
    assert all("explanation" not in f for f in out["findings"])


def test_explain_matches_single_finding_explain(tmp_path):
    # The inlined slice must equal what explain_taint returns for the same finding.
    from wardline.mcp.server import _explain_taint

    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    out = _scan({"explain": True}, tmp_path)
    f = next(f for f in out["findings"] if f["qualname"] == "svc.leak_a" and f["rule_id"] == "PY-WL-101")
    single = _explain_taint({"fingerprint": f["fingerprint"]}, tmp_path)
    # All six explanation keys must match the single-finding explain projection.
    assert f["explanation"] == {k: single[k] for k in f["explanation"]}


# --- dogfood #4: payload shrinking ------------------------------------------


def test_where_filters_agent_summary_arrays(tmp_path):
    # Symptom (a): where matching 0 findings still returned all 34 suppressed inline.
    # The agent_summary finding arrays must respect `where`; summary counts stay whole.
    (tmp_path / "svc.py").write_text(_many_leaks(5), encoding="utf-8")
    _baseline_all(tmp_path)
    out = _scan({"where": {"suppression": "active", "severity": "CRITICAL"}}, tmp_path)
    assert out["findings"] == []  # 0 active CRITICAL
    summ = out["agent_summary"]
    assert summ["suppressed_findings"] == []
    assert summ["active_defects"] == []
    # but the whole-project counts are preserved
    assert summ["summary"]["suppressed_findings"] == 5
    assert out["summary"]["baselined"] == 5


def test_explain_true_has_default_cap(tmp_path):
    # Blocker (c): bare explain:true over a many-defect repo must NOT inline every
    # provenance (the 56KB-on-one-line symptom). A DEFAULT ceiling bounds it, and the
    # truncation is announced — never silent.
    (tmp_path / "svc.py").write_text(_many_leaks(40), encoding="utf-8")
    out = _scan({"explain": True}, tmp_path)
    explained = [f for f in out["findings"] if "explanation" in f]
    assert 0 < len(explained) <= 25  # default cap
    assert out["truncation"]["explanations_truncated"] is True
    # the true total is still reported, so nothing is silently hidden
    assert out["summary"]["active"] == 40


def test_summary_only_omits_finding_arrays(tmp_path):
    # (d): the "did the gate pass?" payload — counts + gate, no finding bodies.
    (tmp_path / "svc.py").write_text(_many_leaks(5), encoding="utf-8")
    out = _scan({"summary_only": True, "fail_on": "ERROR"}, tmp_path)
    assert out["findings"] == []
    summ = out["agent_summary"]
    assert summ["active_defects"] == [] and summ["suppressed_findings"] == [] and summ["engine_facts"] == []
    # counts + gate intact
    assert out["summary"]["active"] == 5
    assert out["gate"]["tripped"] is True
    assert out["truncation"]["summary_only"] is True


def test_include_suppressed_false_drops_suppressed(tmp_path):
    # (b): drop the suppressed bodies from both surfaces; keep the counts.
    (tmp_path / "svc.py").write_text(_many_leaks(5), encoding="utf-8")
    _baseline_all(tmp_path)
    out = _scan({"include_suppressed": False}, tmp_path)
    assert all(f["suppressed"] == "active" for f in out["findings"])
    assert out["agent_summary"]["suppressed_findings"] == []
    # whole-project count still visible
    assert out["summary"]["baselined"] == 5


def test_max_findings_caps_and_marks(tmp_path):
    # (b): bound the returned list and announce the cut.
    (tmp_path / "svc.py").write_text(_many_leaks(10), encoding="utf-8")
    out = _scan({"max_findings": 3}, tmp_path)
    assert len(out["findings"]) == 3
    assert out["truncation"]["findings_truncated"] is True
    assert out["truncation"]["findings_returned"] == 3
    assert out["truncation"]["findings_total"] >= 10
