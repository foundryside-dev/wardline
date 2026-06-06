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


def test_agent_summary_gate_block_carries_reason_and_evaluated(tmp_path: Path) -> None:
    # The dogfood #2 fix must reach the agent_summary gate block, not just the MCP scan
    # top-level: a baselined-only scan that trips must SAY why and which population.
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    scan = run_scan(tmp_path)
    fp = next(f.fingerprint for f in scan.findings if f.rule_id == "PY-WL-101")
    bl = tmp_path / ".wardline" / "baseline.yaml"
    bl.parent.mkdir(parents=True, exist_ok=True)
    write_baseline(bl, [next(f for f in scan.findings if f.fingerprint == fp)])
    rescan = run_scan(tmp_path)
    out = build_agent_summary(rescan, gate_decision(rescan, Severity.ERROR)).to_dict()
    assert out["gate"]["tripped"] is True
    assert "suppressed" in out["gate"]["reason"]
    assert "unsuppressed" in out["gate"]["evaluated"]


def test_agent_summary_gate_block_carries_migration_hint(tmp_path: Path) -> None:
    # The "see gate.migration_hint" pointer in next_actions must resolve on THIS surface:
    # the agent_summary gate block carries the rollout hint too, not only the MCP scan
    # top-level gate block (the dangling-pointer fix).
    from wardline.core.run import baseline_migration_hint

    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    scan = run_scan(tmp_path)
    bl = tmp_path / ".wardline" / "baseline.yaml"
    bl.parent.mkdir(parents=True, exist_ok=True)
    write_baseline(bl, [next(f for f in scan.findings if f.rule_id == "PY-WL-101")])
    rescan = run_scan(tmp_path)
    decision = gate_decision(rescan, Severity.ERROR)
    hint = baseline_migration_hint(rescan, decision, root=tmp_path, new_since=None)
    assert hint is not None  # baselined-only trip with a committed baseline -> a hint
    out = build_agent_summary(rescan, decision, migration_hint=hint).to_dict()
    assert out["gate"]["migration_hint"] == hint
    # The field is present (and None) when no hint is threaded — the key never disappears.
    out_default = build_agent_summary(rescan, decision).to_dict()
    assert out_default["gate"]["migration_hint"] is None


def test_agent_summary_no_active_defects_still_has_next_actions(tmp_path: Path) -> None:
    (tmp_path / "svc.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    scan = run_scan(tmp_path)
    out = build_agent_summary(scan, gate_decision(scan, None)).to_dict()

    assert out["active_defects"] == []
    assert out["next_actions"] == [{"tool": "scan", "reason": "no active defects; rescan after edits"}]


def test_agent_summary_next_actions_do_not_say_passed_when_gate_tripped(tmp_path: Path) -> None:
    # Dogfood #2 (the "Worse" half): with the gate tripped solely on baselined findings,
    # summary.active is 0 — but next_actions must NOT say "no active defects; rescan after
    # edits" (which reads as PASSED). It must reflect the gate failure and the escape hatches.
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    scan = run_scan(tmp_path)
    fp = next(f.fingerprint for f in scan.findings if f.rule_id == "PY-WL-101")
    bl = tmp_path / ".wardline" / "baseline.yaml"
    bl.parent.mkdir(parents=True, exist_ok=True)
    write_baseline(bl, [next(f for f in scan.findings if f.fingerprint == fp)])
    rescan = run_scan(tmp_path)
    out = build_agent_summary(rescan, gate_decision(rescan, Severity.ERROR)).to_dict()

    assert out["gate"]["tripped"] is True
    assert out["summary"]["active_defects"] == 0
    reasons = " ".join(a["reason"].lower() for a in out["next_actions"])
    assert "no active defects; rescan after edits" not in reasons  # must not imply pass
    assert "gate" in reasons
    assert "trust_suppressions" in reasons or "new_since" in reasons


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
        loomweave_write={
            "configured": True,
            "reachable": False,
            "written": 0,
            "unresolved_qualnames": [],
            "disabled_reason": "403",
        },
    ).to_dict()

    assert out["integrations"]["filigree_emit"]["reachable"] is False
    assert out["integrations"]["loomweave_write"]["disabled_reason"] == "403"
