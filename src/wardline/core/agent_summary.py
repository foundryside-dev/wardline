"""Stable agent-oriented scan summary.

The JSONL and SARIF outputs are complete streams. This module builds the compact
handoff shape agents need at the end of a scan: active defects first, suppressed
debt visible, integration status explicit, and suggested next tool calls.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from wardline.core.finding import Finding, Kind, SuppressionState
from wardline.core.run import GateDecision, ScanResult

SCHEMA = "wardline-agent-summary-1"

_SEVERITY_ORDER = {"CRITICAL": 0, "ERROR": 1, "WARN": 2, "INFO": 3, "NONE": 4}


def _default_filigree_status() -> dict[str, Any]:
    return {
        "configured": False,
        "reachable": None,
        "created": 0,
        "updated": 0,
        "failed": 0,
        "warnings": [],
        "disabled_reason": "not configured",
    }


def _default_loomweave_status() -> dict[str, Any]:
    return {
        "configured": False,
        "reachable": None,
        "written": 0,
        "unresolved_qualnames": [],
        "disabled_reason": "not configured",
    }


@dataclass(frozen=True, slots=True)
class AgentSummary:
    result: ScanResult
    gate: GateDecision
    filigree_emit: dict[str, Any] = field(default_factory=_default_filigree_status)
    loomweave_write: dict[str, Any] = field(default_factory=_default_loomweave_status)
    # Payload-shrinking controls (dogfood #4). The summary COUNTS always describe the
    # whole project; these govern only the inline finding ARRAYS. ``display_findings``
    # is the (already ``where``-filtered) view the arrays are built from — None means the
    # whole result, the back-compat default used by the CLI ``--format agent-summary``.
    display_findings: list[Finding] | None = None
    summary_only: bool = False
    max_findings: int | None = None
    include_suppressed: bool = True

    def to_dict(self) -> dict[str, Any]:
        # Counts are whole-project (summary describes the whole project, per the `where`
        # contract); arrays come from the displayed/filtered view, then bounded.
        count_active = len(_active_defects(self.result.findings))
        count_suppressed = len(_suppressed_defects(self.result.findings))
        count_facts = len(_engine_facts(self.result.findings))

        base = self.result.findings if self.display_findings is None else self.display_findings
        if self.summary_only:
            shown_active: list[Finding] = []
            shown_suppressed: list[Finding] = []
            shown_facts: list[Finding] = []
        else:
            shown_active = _active_defects(base)
            shown_suppressed = _suppressed_defects(base) if self.include_suppressed else []
            shown_facts = _engine_facts(base)
            if self.max_findings is not None:
                shown_active = shown_active[: self.max_findings]
                shown_suppressed = shown_suppressed[: self.max_findings]
                shown_facts = shown_facts[: self.max_findings]
        active_defects = [_finding_entry(f, include_next=True) for f in shown_active]
        suppressed = [_finding_entry(f, include_next=False) for f in shown_suppressed]
        engine_facts = [_finding_entry(f, include_next=False) for f in shown_facts]
        return {
            "schema": SCHEMA,
            "summary": {
                "files_scanned": self.result.files_scanned,
                "total_findings": self.result.summary.total,
                "active_defects": count_active,
                "suppressed_findings": count_suppressed,
                "engine_facts": count_facts,
                "baselined": self.result.summary.baselined,
                "waived": self.result.summary.waived,
                "judged": self.result.summary.judged,
                "unanalyzed": self.result.summary.unanalyzed,
            },
            "gate": {
                "tripped": self.gate.tripped,
                "fail_on": self.gate.fail_on,
                "exit_class": self.gate.exit_class,
                "reason": self.gate.reason,
                "evaluated": self.gate.evaluated,
            },
            "integrations": {
                "filigree_emit": dict(self.filigree_emit),
                "loomweave_write": dict(self.loomweave_write),
            },
            "active_defects": active_defects,
            "suppressed_findings": suppressed,
            "engine_facts": engine_facts,
            # next_actions follow the whole-project active count, not the displayed slice,
            # so a summary_only/filtered view does not falsely say "no active defects" — and
            # they are GATE-AWARE so a baselined-only trip (0 active + gate FAILED) never
            # reads as "rescan after edits" / passed (dogfood #2, the "Worse" half).
            "next_actions": _next_actions_for(count_active, self.gate),
        }


def _sort_key(finding: Finding) -> tuple[int, str, int, str, str]:
    return (
        _SEVERITY_ORDER.get(finding.severity.value, 99),
        finding.location.path,
        finding.location.line_start or 0,
        finding.rule_id,
        finding.fingerprint,
    )


def _active_defects(findings: list[Finding]) -> list[Finding]:
    return sorted(
        (f for f in findings if f.kind is Kind.DEFECT and f.suppressed is SuppressionState.ACTIVE),
        key=_sort_key,
    )


def _suppressed_defects(findings: list[Finding]) -> list[Finding]:
    return sorted(
        (f for f in findings if f.kind is Kind.DEFECT and f.suppressed is not SuppressionState.ACTIVE),
        key=_sort_key,
    )


def _engine_facts(findings: list[Finding]) -> list[Finding]:
    return sorted(
        (f for f in findings if f.kind is Kind.FACT and f.rule_id.startswith("WLN-ENGINE-")),
        key=_sort_key,
    )


def _finding_entry(finding: Finding, *, include_next: bool) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "fingerprint": finding.fingerprint,
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "kind": finding.kind.value,
        "qualname": finding.qualname,
        "location": {
            "path": finding.location.path,
            "line_start": finding.location.line_start,
            "line_end": finding.location.line_end,
        },
        "message": finding.message,
        "suppression_state": finding.suppressed.value,
        "suppression_reason": finding.suppression_reason,
    }
    if include_next:
        explain_available = finding.qualname is not None
        entry["explain"] = {
            "available": explain_available,
            "reason": None if explain_available else "finding has no qualname",
            "suggested_call": {
                "tool": "explain_taint",
                "arguments": {"fingerprint": finding.fingerprint},
            }
            if explain_available
            else None,
        }
        entry["next_tool_calls"] = [
            {"tool": "explain_taint", "arguments": {"fingerprint": finding.fingerprint}},
            {"tool": "file_finding", "arguments": {"fingerprint": finding.fingerprint}},
        ]
    return entry


def _next_actions_for(active_count: int, gate: GateDecision) -> list[dict[str, Any]]:
    if active_count > 0:
        return [
            {"tool": "explain_taint", "reason": "inspect each active defect before editing"},
            {"tool": "file_finding", "reason": "promote confirmed true positives after Filigree emission"},
            {"tool": "scan", "reason": "rescan after fixes to verify closure"},
        ]
    if gate.tripped:
        # 0 active defects but the gate FAILED — it tripped on suppressed/baselined findings.
        # Do NOT say "rescan after edits" (which reads as passed); point at the gate verdict.
        detail = gate.reason or "the gate tripped on suppressed (baselined/waived/judged) findings"
        return [
            {
                "tool": "scan",
                "reason": (
                    f"gate FAILED with 0 active defects — {detail}. To clear: pass "
                    "trust_suppressions (trusted checkout) or new_since <ref> (PR), or remove the "
                    "baseline/waiver/judged entries; see gate.reason / gate.migration_hint."
                ),
            }
        ]
    return [{"tool": "scan", "reason": "no active defects; rescan after edits"}]


def build_agent_summary(
    result: ScanResult,
    gate: GateDecision,
    *,
    filigree_emit: dict[str, Any] | None = None,
    loomweave_write: dict[str, Any] | None = None,
    display_findings: list[Finding] | None = None,
    summary_only: bool = False,
    max_findings: int | None = None,
    include_suppressed: bool = True,
) -> AgentSummary:
    return AgentSummary(
        result=result,
        gate=gate,
        filigree_emit=filigree_emit or _default_filigree_status(),
        loomweave_write=loomweave_write or _default_loomweave_status(),
        display_findings=display_findings,
        summary_only=summary_only,
        max_findings=max_findings,
        include_suppressed=include_suppressed,
    )
