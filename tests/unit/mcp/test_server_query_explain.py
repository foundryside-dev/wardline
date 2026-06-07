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
    from wardline.core.paths import baseline_path
    from wardline.core.run import run_scan

    scan = run_scan(tmp_path)
    defects = [f for f in scan.findings if f.rule_id == "PY-WL-101"]
    bl = baseline_path(tmp_path)
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
    full = _scan({"full": True}, tmp_path)
    qualnames = {e["qualname"] for e in full["agent_summary"]["active_defects"] if e["rule_id"] == "PY-WL-101"}
    assert "svc.leak_a" in qualnames and "svc.leak_b" in qualnames

    filtered = _scan({"where": {"qualname": "svc.leak_a"}, "full": True}, tmp_path)
    got = [e for e in filtered["agent_summary"]["active_defects"] if e["rule_id"] == "PY-WL-101"]
    assert {e["qualname"] for e in got} == {"svc.leak_a"}


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
    by_q = {e["qualname"]: e for e in out["agent_summary"]["active_defects"] if e["rule_id"] == "PY-WL-101"}
    exp = by_q["svc.leak_a"]["explanation"]
    assert exp["immediate_tainted_callee"] == "read_a"
    assert exp["source_boundary_qualname"] == "svc.read_a"
    assert "tier_in" in exp and "tier_out" in exp


def test_explain_absent_by_default(tmp_path):
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    out = _scan({}, tmp_path)
    assert all("explanation" not in e for e in out["agent_summary"]["active_defects"])


def test_explain_matches_single_finding_explain(tmp_path):
    # The inlined slice must equal what explain_taint returns for the same finding.
    from wardline.mcp.server import _explain_taint

    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    out = _scan({"explain": True}, tmp_path)
    f = next(
        e
        for e in out["agent_summary"]["active_defects"]
        if e["qualname"] == "svc.leak_a" and e["rule_id"] == "PY-WL-101"
    )
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
    summ = out["agent_summary"]
    assert summ["suppressed_findings"] == []  # 0 active CRITICAL
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
    explained = [e for e in out["agent_summary"]["active_defects"] if "explanation" in e]
    assert 0 < len(explained) <= 10  # default explanation cap (independent of the body page size)
    assert out["agent_summary"]["truncation"]["explanations_truncated"] is True
    # the true total is still reported, so nothing is silently hidden
    assert out["summary"]["active"] == 40


def test_max_findings_can_raise_explain_cap_above_default(tmp_path):
    # max_findings is the explicit knob: it can RAISE the inlined-explanation count above
    # the conservative default (10) when the agent accepts the larger payload.
    (tmp_path / "svc.py").write_text(_many_leaks(20), encoding="utf-8")
    out = _scan({"explain": True, "max_findings": 20}, tmp_path)
    explained = [e for e in out["agent_summary"]["active_defects"] if "explanation" in e]
    assert len(explained) > 10  # exceeded the default cap
    assert out["agent_summary"]["truncation"]["explanations_truncated"] is False


def test_summary_only_omits_finding_arrays(tmp_path):
    # (d): the "did the gate pass?" payload — counts + gate, no finding bodies.
    (tmp_path / "svc.py").write_text(_many_leaks(5), encoding="utf-8")
    out = _scan({"summary_only": True, "fail_on": "ERROR"}, tmp_path)
    summ = out["agent_summary"]
    assert summ["active_defects"] == [] and summ["suppressed_findings"] == [] and summ["engine_facts"] == []
    # counts + gate intact
    assert out["summary"]["active"] == 5
    assert out["gate"]["tripped"] is True
    assert summ["truncation"]["summary_only"] is True


def test_include_suppressed_false_drops_suppressed(tmp_path):
    # (b): drop the suppressed bodies from both surfaces; keep the counts.
    (tmp_path / "svc.py").write_text(_many_leaks(5), encoding="utf-8")
    _baseline_all(tmp_path)
    out = _scan({"include_suppressed": False}, tmp_path)
    # suppressed bodies are dropped from the page; any shown defect body is active.
    assert all(e["suppression_state"] == "active" for e in out["agent_summary"]["active_defects"])
    assert out["agent_summary"]["suppressed_findings"] == []
    # whole-project count still visible
    assert out["summary"]["baselined"] == 5


def test_max_findings_caps_and_marks(tmp_path):
    # (b): bound the returned list and announce the cut.
    (tmp_path / "svc.py").write_text(_many_leaks(10), encoding="utf-8")
    out = _scan({"max_findings": 3}, tmp_path)
    ag = out["agent_summary"]
    shown = len(ag["active_defects"]) + len(ag["suppressed_findings"]) + len(ag["engine_facts"])
    assert shown == 3
    assert ag["truncation"]["findings_truncated"] is True
    assert ag["truncation"]["findings_returned"] == 3
    assert ag["truncation"]["findings_total"] >= 10


@pytest.mark.parametrize("bad", [-1, 1.5, "3", True])
def test_max_findings_rejects_non_negative_integer(tmp_path, bad):
    # Agent-actionable validation: a negative / non-int / bool max_findings is a loud
    # ToolError, never a silent negative-slice that drops the last finding.
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    with pytest.raises(ToolError, match="max_findings"):
        _scan({"max_findings": bad}, tmp_path)


@pytest.mark.parametrize("name", ["summary_only", "include_suppressed"])
def test_boolean_payload_controls_reject_non_bool(tmp_path, name):
    # The string "false" must NOT silently coerce to True (the bug the strict _bool_arg
    # closes) — a non-bool is rejected loudly, matching max_findings' strictness.
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    with pytest.raises(ToolError, match=name):
        _scan({name: "false"}, tmp_path)


# --- W1: bounded default + offset pagination (weft-439d09fc8d) ---------------


def _shown(ag) -> int:
    return len(ag["active_defects"]) + len(ag["suppressed_findings"]) + len(ag["engine_facts"])


def test_default_scan_is_bounded_to_25(tmp_path):
    # A bare scan over 30 active defects returns at most the bounded page (25), so the
    # agent's first natural call cannot overflow its context — the ~123KB dump is gone.
    (tmp_path / "svc.py").write_text(_many_leaks(30), encoding="utf-8")
    out = _scan({}, tmp_path)
    ag = out["agent_summary"]
    assert _shown(ag) == 25
    t = ag["truncation"]
    assert t["findings_returned"] == 25 and t["findings_truncated"] is True and t["next_offset"] == 25
    # whole-project count stays honest regardless of the page bound
    assert out["summary"]["active"] == 30


def test_offset_pages_are_disjoint_and_full_is_uncapped(tmp_path):
    (tmp_path / "svc.py").write_text(_many_leaks(30), encoding="utf-8")
    page1 = _scan({}, tmp_path)["agent_summary"]
    nxt = page1["truncation"]["next_offset"]
    assert nxt == 25
    page2 = _scan({"offset": nxt}, tmp_path)["agent_summary"]
    fp1 = {e["fingerprint"] for e in page1["active_defects"]}
    fp2 = {e["fingerprint"] for e in page2["active_defects"]}
    assert fp1 and fp2 and fp1.isdisjoint(fp2)  # no finding appears on both pages
    assert page2["truncation"]["offset"] == 25
    assert page2["truncation"]["next_offset"] is None  # 30 actives → page 2 is the last
    # full=true returns every body in one call, untruncated.
    full = _scan({"full": True}, tmp_path)["agent_summary"]
    assert len(full["active_defects"]) == 30
    assert full["truncation"]["findings_truncated"] is False and full["truncation"]["next_offset"] is None


def test_offset_rejects_non_negative_integer(tmp_path):
    (tmp_path / "svc.py").write_text(_SRC, encoding="utf-8")
    with pytest.raises(ToolError, match="offset"):
        _scan({"offset": -1}, tmp_path)
