"""WS-B1/B2: MCP `scan` server-side `where` filter and `explain` inliner."""

import pytest

from wardline.mcp.server import ToolError, _scan

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
