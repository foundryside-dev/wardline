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


def _default_clarion_status() -> dict[str, Any]:
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
    clarion_write: dict[str, Any] = field(default_factory=_default_clarion_status)

    def to_dict(self) -> dict[str, Any]:
        active_defects = [_finding_entry(f, include_next=True) for f in _active_defects(self.result.findings)]
        suppressed = [_finding_entry(f, include_next=False) for f in _suppressed_defects(self.result.findings)]
        engine_facts = [_finding_entry(f, include_next=False) for f in _engine_facts(self.result.findings)]
        return {
            "schema": SCHEMA,
            "summary": {
                "files_scanned": self.result.files_scanned,
                "total_findings": self.result.summary.total,
                "active_defects": len(active_defects),
                "suppressed_findings": len(suppressed),
                "engine_facts": len(engine_facts),
                "baselined": self.result.summary.baselined,
                "waived": self.result.summary.waived,
                "judged": self.result.summary.judged,
                "unanalyzed": self.result.summary.unanalyzed,
            },
            "gate": {
                "tripped": self.gate.tripped,
                "fail_on": self.gate.fail_on,
                "exit_class": self.gate.exit_class,
            },
            "integrations": {
                "filigree_emit": dict(self.filigree_emit),
                "clarion_write": dict(self.clarion_write),
            },
            "active_defects": active_defects,
            "suppressed_findings": suppressed,
            "engine_facts": engine_facts,
            "next_actions": _next_actions(active_defects),
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


def _next_actions(active_defects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not active_defects:
        return [{"tool": "scan", "reason": "no active defects; rescan after edits"}]
    return [
        {"tool": "explain_taint", "reason": "inspect each active defect before editing"},
        {"tool": "file_finding", "reason": "promote confirmed true positives after Filigree emission"},
        {"tool": "scan", "reason": "rescan after fixes to verify closure"},
    ]


def build_agent_summary(
    result: ScanResult,
    gate: GateDecision,
    *,
    filigree_emit: dict[str, Any] | None = None,
    clarion_write: dict[str, Any] | None = None,
) -> AgentSummary:
    return AgentSummary(
        result=result,
        gate=gate,
        filigree_emit=filigree_emit or _default_filigree_status(),
        clarion_write=clarion_write or _default_clarion_status(),
    )
