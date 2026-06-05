"""One-shot scan -> emit -> file workflow for agents."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from wardline.core.errors import WardlineError
from wardline.core.explain import TaintExplanation, explanation_from_context
from wardline.core.filigree_emit import EmitResult
from wardline.core.filigree_issue import (
    FileResult,
    IdentityAttachResult,
    attach_clarion_identity_for_qualname,
    identity_attach_result_to_json,
)
from wardline.core.finding import Finding, Kind, Severity, SuppressionState
from wardline.core.run import gate_decision, run_scan


def _explanation_to_dict(exp: TaintExplanation) -> dict[str, Any]:
    return {
        "tier_in": exp.tier_in,
        "tier_out": exp.tier_out,
        "immediate_tainted_callee": exp.immediate_tainted_callee,
        "source_boundary_qualname": exp.source_boundary_qualname,
        "resolved_call_count": exp.resolved_call_count,
        "unresolved_call_count": exp.unresolved_call_count,
    }


def _finding_base(finding: Finding, explanation: TaintExplanation | None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "fingerprint": finding.fingerprint,
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "message": finding.message,
        "qualname": finding.qualname,
        "path": finding.location.path,
        "line": finding.location.line_start,
    }
    if explanation is not None:
        payload["explanation"] = _explanation_to_dict(explanation)
    return payload


def _emit_to_dict(result: EmitResult | None, *, configured: bool) -> dict[str, Any]:
    if result is None:
        return {
            "configured": configured,
            "reachable": None,
            "created": 0,
            "updated": 0,
            "failed": 0,
            "warnings": [],
            "disabled_reason": None if configured else "not configured",
        }
    return {
        "configured": configured,
        "reachable": result.reachable,
        "created": result.created,
        "updated": result.updated,
        "failed": result.failed,
        "warnings": list(result.warnings),
        "disabled_reason": None if result.reachable else "filigree unreachable",
    }


def _file_to_dict(result: FileResult | None, *, selected: bool, configured: bool) -> dict[str, Any]:
    if result is None:
        return {
            "selected": selected,
            "attempted": False,
            "reachable": None,
            "issue_id": None,
            "created": False,
            "not_found": False,
            "disabled_reason": None if configured else "no Filigree URL configured",
        }
    return {
        "selected": selected,
        "attempted": True,
        "reachable": result.reachable,
        "issue_id": result.issue_id,
        "created": result.created,
        "not_found": result.not_found,
        "disabled_reason": result.disabled_reason,
    }


def _selected_fingerprints(
    active_defects: list[Finding],
    *,
    fingerprints: tuple[str, ...],
    all_active: bool,
    dry_run: bool,
) -> tuple[set[str], str]:
    if dry_run or (not fingerprints and not all_active):
        return set(), "dry_run"
    if fingerprints and all_active:
        raise WardlineError("choose explicit fingerprints or all_active, not both")
    if all_active:
        return {finding.fingerprint for finding in active_defects}, "all_active"
    return set(fingerprints), "fingerprints"


def scan_file_findings(
    root: Path,
    *,
    config_path: Path | None = None,
    cache_dir: Path | None = None,
    fail_on: str | None = None,
    trust_local_packs: bool = False,
    trusted_packs: tuple[str, ...] = (),
    strict_defaults: bool = False,
    fingerprints: tuple[str, ...] = (),
    all_active: bool = False,
    dry_run: bool = True,
    priority: str | None = None,
    labels: tuple[str, ...] = (),
    filigree_emitter: Any = None,
    filigree_filer: Any = None,
    clarion_client: Any = None,
) -> dict[str, Any]:
    threshold = Severity(fail_on) if fail_on else None
    result = run_scan(
        root,
        config_path=config_path,
        cache_dir=cache_dir,
        confine_to_root=True,
        trust_local_packs=trust_local_packs,
        trusted_packs=trusted_packs,
        strict_defaults=strict_defaults,
    )
    decision = gate_decision(result, threshold)
    active_defects = [
        finding
        for finding in result.findings
        if finding.kind is Kind.DEFECT and finding.suppressed is SuppressionState.ACTIVE
    ]
    selected, mode = _selected_fingerprints(
        active_defects,
        fingerprints=fingerprints,
        all_active=all_active,
        dry_run=dry_run,
    )
    known_active = {finding.fingerprint for finding in active_defects}
    unknown_fingerprints = [fingerprint for fingerprint in fingerprints if fingerprint not in known_active]

    emit_result: EmitResult | None = None
    if selected and filigree_emitter is not None:
        emit_result = filigree_emitter.emit(result.findings, scanned_paths=result.scanned_paths)

    active_out: list[dict[str, Any]] = []
    for finding in active_defects:
        explanation = (
            explanation_from_context(finding, result.context)
            if finding.qualname is not None and result.context is not None
            else None
        )
        selected_here = finding.fingerprint in selected
        file_result: FileResult | None = None
        identity_result: IdentityAttachResult = IdentityAttachResult.not_attempted("finding was not selected")
        if selected_here:
            if filigree_filer is not None:
                file_result = filigree_filer.file(
                    finding.fingerprint,
                    priority=priority,
                    labels=list(labels) or None,
                )
                if finding.qualname:
                    identity_result = attach_clarion_identity_for_qualname(
                        qualname=finding.qualname,
                        issue_id=file_result.issue_id,
                        filer=filigree_filer,
                        clarion_client=clarion_client,
                    )
                else:
                    identity_result = IdentityAttachResult.skipped("finding has no qualname")
            else:
                identity_result = IdentityAttachResult.not_attempted("no issue_id from Filigree promote")
        item = _finding_base(finding, explanation)
        item["promotion"] = _file_to_dict(file_result, selected=selected_here, configured=filigree_filer is not None)
        item["identity_attach"] = identity_attach_result_to_json(identity_result)
        active_out.append(item)

    return {
        "mode": mode,
        "files_scanned": result.files_scanned,
        "summary": {
            "total": result.summary.total,
            "active": result.summary.active,
            "baselined": result.summary.baselined,
            "waived": result.summary.waived,
            "judged": result.summary.judged,
            "unanalyzed": result.summary.unanalyzed,
        },
        "gate": {"tripped": decision.tripped, "fail_on": decision.fail_on, "exit_class": decision.exit_class},
        "filigree_emit": _emit_to_dict(emit_result, configured=filigree_emitter is not None),
        "active_defects": active_out,
        "selected_count": len(selected & known_active),
        "unknown_fingerprints": unknown_fingerprints,
    }
