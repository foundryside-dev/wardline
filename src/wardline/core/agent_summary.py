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


def _is_engine_fact(f: Finding) -> bool:
    """Engine diagnostic facts: Kind.FACT with a WLN-ENGINE-* rule_id.

    Used as the shared predicate for both ``_engine_facts`` and the re-split so
    the two can never drift from each other.  The display array ``engine_facts``
    covers exactly this population; ``informational`` (display) covers everything
    else that is not a defect.
    """
    return f.kind is Kind.FACT and f.rule_id.startswith("WLN-ENGINE-")


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
    # Offset into the flattened ordered union (active → suppressed → engine_facts →
    # informational) for pagination. The default scan returns a bounded first page; the
    # agent walks the rest with offset = truncation.next_offset (weft-439d09fc8d).
    offset: int = 0
    include_suppressed: bool = True
    # The secure-gate-default rollout hint (or None), surfaced in the gate block so the
    # "see gate.migration_hint" pointer in next_actions resolves on this surface too — the
    # MCP scan response carries the same value at its top-level gate block.
    migration_hint: str | None = None

    def __post_init__(self) -> None:
        # max_findings bounds the inline arrays via a slice; a negative value would
        # silently DROP findings ([:-1]). Refuse it at construction, matching the
        # GateDecision/EmitResult guards. ``display_findings ⊆ result.findings`` remains
        # a documented caller precondition (a full fingerprint subset-check every build
        # is too costly for the hot scan path).
        if self.max_findings is not None and self.max_findings < 0:
            raise ValueError(f"max_findings must be >= 0, got {self.max_findings}")
        if self.offset < 0:
            raise ValueError(f"offset must be >= 0, got {self.offset}")

    def to_dict(self) -> dict[str, Any]:
        # Counts are whole-project (summary describes the whole project, per the `where`
        # contract); arrays come from the displayed/filtered view, then paginated.
        count_active = len(_active_defects(self.result.findings))
        count_suppressed = len(_suppressed_defects(self.result.findings))
        count_facts = len(_engine_facts(self.result.findings))

        base = self.result.findings if self.display_findings is None else self.display_findings
        # ONE ordered sequence is the pagination unit (weft-439d09fc8d): active defects first
        # (most urgent), then suppressed debt, then engine facts, then the remaining
        # informational findings (metrics, classifications, suggestions, non-engine facts) —
        # each bucket internally sorted by _sort_key.  A single offset+max_findings window
        # slices this union so one truncation block describes the whole page, not four
        # independently-sliced arrays.  The union covers EVERY finding exactly once, so
        # len(union) == summary.total_findings within the display_findings contract.
        union = _active_defects(base)
        if self.include_suppressed:
            union = union + _suppressed_defects(base)
        union = union + _engine_facts(base) + _informational(base)
        findings_total = len(union)
        if self.summary_only:
            window: list[Finding] = []
        elif self.max_findings is not None:
            window = union[self.offset : self.offset + self.max_findings]
        else:
            window = union[self.offset :]
        findings_returned = len(window)
        end = self.offset + findings_returned
        findings_truncated = (not self.summary_only) and end < findings_total
        next_offset = end if findings_truncated else None
        # Re-split the window back into the four display arrays by category (the union was
        # built in category order, so this preserves both order and the page boundary).
        # NOTE: shown_facts must mirror _is_engine_fact exactly — a non-engine FACT
        # (e.g. WLN-L3-*) must NOT land in both shown_facts and shown_informational.
        shown_active = [f for f in window if f.kind is Kind.DEFECT and f.suppressed is SuppressionState.ACTIVE]
        shown_suppressed = [f for f in window if f.kind is Kind.DEFECT and f.suppressed is not SuppressionState.ACTIVE]
        shown_facts = [f for f in window if _is_engine_fact(f)]
        shown_informational = [f for f in window if f.kind is not Kind.DEFECT and not _is_engine_fact(f)]
        active_defects = [_finding_entry(f, include_next=True) for f in shown_active]
        suppressed = [_finding_entry(f, include_next=False) for f in shown_suppressed]
        engine_facts = [_finding_entry(f, include_next=False) for f in shown_facts]
        informational = [_finding_entry(f, include_next=False) for f in shown_informational]
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
                # summary.informational counts ALL non-defect findings (engine facts included);
                # the display array ``informational`` below covers only non-engine non-defects.
                # engine_facts has its own display array, so the display split is:
                #   active_defects + suppressed_findings + engine_facts + informational(display)
                #   == total_findings (within the display_findings contract).
                "informational": self.result.summary.informational,
                "unanalyzed": self.result.summary.unanalyzed,
            },
            "gate": {
                "tripped": self.gate.tripped,
                "fail_on": self.gate.fail_on,
                "exit_class": self.gate.exit_class,
                "verdict": self.gate.verdict,
                "would_trip_at": self.gate.would_trip_at,
                "reason": self.gate.reason,
                "evaluated": self.gate.evaluated,
                "migration_hint": self.migration_hint,
            },
            "integrations": {
                "filigree_emit": dict(self.filigree_emit),
                "loomweave_write": dict(self.loomweave_write),
            },
            "active_defects": active_defects,
            "suppressed_findings": suppressed,
            "engine_facts": engine_facts,
            # Non-defect findings beyond engine facts: metrics, classifications, suggestions,
            # and non-engine facts.  Parallel to summary.informational (which also includes
            # engine_facts; see comment above), but scoped to the display window.  This is the
            # W3 residual fix: these findings were counted in summary.total_findings but had no
            # display array, making pagination falsely appear complete.
            "informational": informational,
            # Every cut is explicit so a bounded page never reads as "covered all". This is the
            # single pagination descriptor for the union above; ``explanations_truncated`` is
            # set by the MCP server when explain=true inlines provenance (core never explains).
            "truncation": {
                "summary_only": self.summary_only,
                "include_suppressed": self.include_suppressed,
                "max_findings": self.max_findings,
                "offset": self.offset,
                "findings_total": findings_total,
                "findings_returned": findings_returned,
                "next_offset": next_offset,
                "findings_truncated": findings_truncated,
                "explanations_truncated": False,
            },
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
        (f for f in findings if _is_engine_fact(f)),
        key=_sort_key,
    )


def _informational(findings: list[Finding]) -> list[Finding]:
    """Non-defect findings that are NOT engine facts.

    Covers Kind.METRIC, Kind.CLASSIFICATION, Kind.SUGGESTION, and Kind.FACT
    findings whose rule_id does NOT start with "WLN-ENGINE-".  Together with
    _engine_facts this partitions all non-defect findings, so the four display
    arrays (active_defects, suppressed_findings, engine_facts, informational)
    partition the full finding set exactly once — closing the W3 pagination
    residual where these findings were counted in summary.total_findings but
    occupied no display slot.

    Note: summary.informational (in ScanSummary) counts ALL non-defect findings
    including engine facts, so summary.informational >= len(informational display).
    The display split here is finer; both are correct for their purpose.
    """
    return sorted(
        (f for f in findings if f.kind is not Kind.DEFECT and not _is_engine_fact(f)),
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


def _unanalyzed_trip_action(gate: GateDecision) -> dict[str, Any]:
    # An unanalyzed trip is an under-scan, not a finding — suppression escape hatches
    # (trust_suppressions / new_since / baseline edits) cannot clear it; only fixing what
    # blocked analysis (or dropping the knob) can.
    return {
        "tool": "scan",
        "reason": (
            f"gate FAILED on unanalyzed files — {gate.reason}. Fix what blocked analysis "
            "(parse errors / too-deep skips / missing source roots — see the WLN-ENGINE-* "
            "facts), or drop fail_on_unanalyzed; suppressions cannot clear this trip."
        ),
    }


def _next_actions_for(active_count: int, gate: GateDecision) -> list[dict[str, Any]]:
    if active_count > 0:
        actions = [
            {"tool": "explain_taint", "reason": "inspect each active defect before editing"},
            {"tool": "file_finding", "reason": "promote confirmed true positives after Filigree emission"},
            {"tool": "scan", "reason": "rescan after fixes to verify closure"},
        ]
        if gate.fail_on is None:
            # Active defects AND no severity threshold ran (the gate may still have evaluated
            # via fail_on_unanalyzed) — name the enforcement step so a green-looking exit is
            # not mistaken for a pass (weft-b937e53854).
            actions.append(
                {
                    "tool": "scan",
                    "reason": (
                        f"severity gate did not run (no --fail-on); pass --fail-on "
                        f"{gate.would_trip_at or 'ERROR'} to enforce"
                    ),
                }
            )
        if gate.unanalyzed_tripped:
            actions.append(_unanalyzed_trip_action(gate))
        return actions
    if gate.tripped:
        # 0 active defects but the gate FAILED. Attribute each tripping sub-gate — and never
        # point an unanalyzed trip at the suppression escape hatches (they cannot clear it).
        actions = []
        if gate.unanalyzed_tripped:
            actions.append(_unanalyzed_trip_action(gate))
        if gate.severity_tripped:
            # The severity gate tripped on suppressed/baselined findings. Do NOT say
            # "rescan after edits" (which reads as passed); point at the gate verdict.
            detail = gate.reason or "the gate tripped on suppressed (baselined/waived/judged) findings"
            actions.append(
                {
                    "tool": "scan",
                    "reason": (
                        f"gate FAILED with 0 active defects — {detail}. To clear: pass "
                        "trust_suppressions (trusted checkout) or new_since <ref> (PR), or remove the "
                        "baseline/waiver/judged entries; see gate.reason / gate.migration_hint."
                    ),
                }
            )
        return actions
    if gate.fail_on is None:
        # 0 active defects but the severity gate never ran (NOT_EVALUATED, or PASSED on the
        # unanalyzed knob alone). If would_trip_at is set, suppressed/baselined defects would
        # re-enter an unsuppressed gate (the dogfood-#2 "worse" case); never let this read as
        # a clean pass.
        label = (
            "gate NOT_EVALUATED (no --fail-on ran)"
            if gate.verdict == "NOT_EVALUATED"
            else "severity gate did not run (no --fail-on)"
        )
        if gate.would_trip_at is not None:
            return [
                {
                    "tool": "scan",
                    "reason": (
                        f"{label}; 0 active defects but suppressed/baselined "
                        f"{gate.would_trip_at}+ finding(s) would trip an unsuppressed gate — pass --fail-on "
                        f"{gate.would_trip_at} to enforce, or trust_suppressions / new_since <ref> to scope"
                    ),
                }
            ]
        return [
            {
                "tool": "scan",
                "reason": f"{label}; no defect would trip at any threshold — pass --fail-on ERROR to lock it in",
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
    offset: int = 0,
    include_suppressed: bool = True,
    migration_hint: str | None = None,
) -> AgentSummary:
    return AgentSummary(
        result=result,
        gate=gate,
        filigree_emit=filigree_emit or _default_filigree_status(),
        loomweave_write=loomweave_write or _default_loomweave_status(),
        display_findings=display_findings,
        summary_only=summary_only,
        max_findings=max_findings,
        offset=offset,
        include_suppressed=include_suppressed,
        migration_hint=migration_hint,
    )
