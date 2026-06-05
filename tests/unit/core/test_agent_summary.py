from __future__ import annotations

from pathlib import Path

from wardline.core.agent_summary import build_agent_summary
from wardline.core.baseline import write_baseline
from wardline.core.finding import Severity
from wardline.core.run import gate_decision, run_scan

_LEAKY = (
    "from wardline.decorators import external_boundary, trusted\n"
    "@external_boundary\n"
    "def raw(p):\n"
    "    return p\n"
    "@trusted\n"
    "def leaky(p):\n"
    "    return raw(p)\n"
)


def test_agent_summary_active_defects_first_and_stable(tmp_path: Path) -> None:
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    scan = run_scan(tmp_path)

    first = build_agent_summary(scan, gate_decision(scan, Severity.ERROR)).to_dict()
    again = build_agent_summary(scan, gate_decision(scan, Severity.ERROR)).to_dict()

    assert first == again
    assert first["schema"] == "wardline-agent-summary-1"
    assert first["summary"]["active_defects"] == 1
    assert first["summary"]["suppressed_findings"] == 0
    assert first["summary"]["engine_facts"] >= 0
    defect = first["active_defects"][0]
    assert {
        "fingerprint",
        "rule_id",
        "severity",
        "qualname",
        "location",
        "message",
        "suppression_state",
        "explain",
        "next_tool_calls",
    } <= set(defect)
    assert defect["rule_id"] == "PY-WL-101"
    assert defect["suppression_state"] == "active"
    assert defect["explain"]["available"] is True
    assert defect["next_tool_calls"][0]["tool"] == "explain_taint"


def test_agent_summary_no_active_defects_still_has_next_actions(tmp_path: Path) -> None:
    (tmp_path / "svc.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    scan = run_scan(tmp_path)
    out = build_agent_summary(scan, gate_decision(scan, None)).to_dict()

    assert out["active_defects"] == []
    assert out["next_actions"] == [{"tool": "scan", "reason": "no active defects; rescan after edits"}]


def test_agent_summary_surfaces_suppressed_findings(tmp_path: Path) -> None:
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    leak = next(f for f in run_scan(tmp_path).findings if f.rule_id == "PY-WL-101")
    write_baseline(tmp_path / ".wardline" / "baseline.yaml", [leak])
    scan = run_scan(tmp_path)

    out = build_agent_summary(scan, gate_decision(scan, None)).to_dict()

    assert out["active_defects"] == []
    assert out["summary"]["suppressed_findings"] == 1
    assert out["suppressed_findings"][0]["fingerprint"] == leak.fingerprint
    assert out["suppressed_findings"][0]["suppression_state"] == "baselined"


def test_agent_summary_includes_integration_status_blocks(tmp_path: Path) -> None:
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    scan = run_scan(tmp_path)
    out = build_agent_summary(
        scan,
        gate_decision(scan, None),
        filigree_emit={
            "configured": True,
            "reachable": False,
            "created": 0,
            "updated": 0,
            "failed": 0,
            "warnings": [],
            "disabled_reason": "filigree unreachable",
        },
        clarion_write={
            "configured": True,
            "reachable": False,
            "written": 0,
            "unresolved_qualnames": [],
            "disabled_reason": "403",
        },
    ).to_dict()

    assert out["integrations"]["filigree_emit"]["reachable"] is False
    assert out["integrations"]["clarion_write"]["disabled_reason"] == "403"
