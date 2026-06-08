from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from wardline.core.agent_summary import build_agent_summary
from wardline.core.baseline import write_baseline
from wardline.core.finding import Finding, Kind, Location, Severity
from wardline.core.paths import baseline_path
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


def test_agent_summary_rejects_negative_max_findings(tmp_path: Path) -> None:
    # max_findings slices the inline arrays; a negative value would silently DROP
    # findings (e.g. [:-1]). Match the rigor of the sibling GateDecision/EmitResult
    # guards and refuse the illegal value at construction.
    import pytest

    from wardline.core.agent_summary import AgentSummary

    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    scan = run_scan(tmp_path)
    gate = gate_decision(scan, Severity.ERROR)
    with pytest.raises(ValueError, match="max_findings"):
        AgentSummary(result=scan, gate=gate, max_findings=-1)


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
    bl = baseline_path(tmp_path)
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
    bl = baseline_path(tmp_path)
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
    # A bare scan is NOT_EVALUATED (weft-b937e53854): next_actions point at enforcing a
    # threshold, never the bland "rescan after edits" that reads as a pass.
    assert len(out["next_actions"]) == 1
    reason = out["next_actions"][0]["reason"].lower()
    assert "not_evaluated" in reason and "--fail-on" in reason


def test_agent_summary_next_actions_do_not_say_passed_when_gate_tripped(tmp_path: Path) -> None:
    # Dogfood #2 (the "Worse" half): with the gate tripped solely on baselined findings,
    # summary.active is 0 — but next_actions must NOT say "no active defects; rescan after
    # edits" (which reads as PASSED). It must reflect the gate failure and the escape hatches.
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    scan = run_scan(tmp_path)
    fp = next(f.fingerprint for f in scan.findings if f.rule_id == "PY-WL-101")
    bl = baseline_path(tmp_path)
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
    write_baseline(baseline_path(tmp_path), [leak])
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


def test_agent_summary_nondefects_included_in_union_and_pagination(tmp_path: Path) -> None:
    """W3 residual: non-defect findings beyond engine facts must appear in the union
    and pagination, not just in the summary count.

    Three assertions:
    (1) truncation.findings_total == summary.total_findings (union == whole scan).
    (2) Each synthetic non-defect finding's fingerprint appears in exactly one
        display array (metric → informational; non-engine FACT → informational).
    (3) len(active_defects) + len(suppressed_findings) + len(engine_facts)
        + len(informational) == truncation.findings_total.
    """
    (tmp_path / "svc.py").write_text(_LEAKY, encoding="utf-8")
    real_scan = run_scan(tmp_path)

    # Synthetic non-defect findings that must NOT be silently dropped:
    # – a Kind.METRIC with a "WLN-ENGINE-METRICS" rule_id  (engine prefix, but METRIC
    #   kind → _is_engine_fact is False → goes to informational display array)
    # – a non-engine Kind.FACT with a "WLN-L3-*" rule_id (non-engine → informational)
    metric_fp = "metric-fingerprint-test-01"
    l3fact_fp = "l3fact-fingerprint-test-01"
    metric = Finding(
        rule_id="WLN-ENGINE-METRICS",
        message="L3 resolver run metrics",
        severity=Severity.NONE,
        kind=Kind.METRIC,
        location=Location(path="<engine>"),
        fingerprint=metric_fp,
    )
    # A Kind.FACT whose rule_id does NOT start with "WLN-ENGINE-" → _is_engine_fact
    # returns False → must appear in the informational display array, not engine_facts.
    l3_fact = Finding(
        rule_id="WLN-CUSTOM-NON-ENGINE-FACT",
        message="a non-engine fact finding for test coverage",
        severity=Severity.INFO,
        kind=Kind.FACT,
        location=Location(path="<engine>"),
        fingerprint=l3fact_fp,
    )

    augmented_findings = real_scan.findings + [metric, l3_fact]
    orig_summary = real_scan.summary
    augmented_summary = replace(
        orig_summary,
        total=orig_summary.total + 2,
        informational=orig_summary.informational + 2,
    )
    augmented_scan = replace(
        real_scan,
        findings=augmented_findings,
        summary=augmented_summary,
    )

    out = build_agent_summary(augmented_scan, gate_decision(augmented_scan, None)).to_dict()

    # (1) union length == total_findings
    assert out["truncation"]["findings_total"] == out["summary"]["total_findings"], (
        "findings_total (union) must equal total_findings (summary)"
    )

    # (2) each synthetic finding appears in exactly one display array
    all_fps_by_array: dict[str, list[str]] = {
        "active_defects": [e["fingerprint"] for e in out["active_defects"]],
        "suppressed_findings": [e["fingerprint"] for e in out["suppressed_findings"]],
        "engine_facts": [e["fingerprint"] for e in out["engine_facts"]],
        "informational": [e["fingerprint"] for e in out["informational"]],
    }
    for synthetic_fp in (metric_fp, l3fact_fp):
        found_in = [name for name, fps in all_fps_by_array.items() if synthetic_fp in fps]
        assert found_in == ["informational"], (
            f"fingerprint {synthetic_fp!r} should be in exactly [informational], got {found_in}"
        )

    # (3) four-array partition == findings_total
    total_shown = (
        len(out["active_defects"])
        + len(out["suppressed_findings"])
        + len(out["engine_facts"])
        + len(out["informational"])
    )
    assert total_shown == out["truncation"]["findings_total"], (
        f"display array sum {total_shown} != findings_total {out['truncation']['findings_total']}"
    )
