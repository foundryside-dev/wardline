# src/wardline/core/explain.py
"""SP8: project the taint provenance the engine computes but otherwise discards.

``explain_finding`` re-runs the analysis (via run_scan, which retains the
analysis context in-process) and projects the cheap provenance slice for one
finding: the immediate tainted callee (the call that introduced the untrusted
return), the originating boundary resolved one hop (NOT the full N-hop chain,
which is deferred to SP9), the trust tiers at the sink, and the resolution
counts.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from wardline.core.run import run_scan

if TYPE_CHECKING:
    from wardline.core.finding import Finding


@dataclass(frozen=True, slots=True)
class TaintExplanation:
    fingerprint: str
    rule_id: str
    sink_qualname: str | None
    path: str
    line: int | None
    tier_in: str | None              # actual (untrusted) tier arriving at the sink
    tier_out: str | None             # tier the sink declares it returns
    immediate_tainted_callee: str | None
    source_boundary_qualname: str | None
    resolved_call_count: int
    unresolved_call_count: int


def _match(
    result_findings: list[Finding],
    *,
    fingerprint: str | None,
    path: str | None,
    line: int | None,
) -> Finding | None:
    if fingerprint is not None:
        for f in result_findings:
            if f.fingerprint == fingerprint:
                return f
        return None
    for f in result_findings:
        if f.location.path == path and f.location.line_start == line:
            return f
    return None


def explain_finding(
    root: Path,
    *,
    fingerprint: str | None = None,
    path: str | None = None,
    line: int | None = None,
    config_path: Path | None = None,
    confine_to_root: bool = False,
) -> TaintExplanation | None:
    """Return the taint explanation for one finding, or None if it is not in the
    current scan (the caller's code changed since the scan that produced the
    fingerprint — re-scan)."""
    if fingerprint is None and (path is None or line is None):
        raise ValueError("explain_finding requires either fingerprint or (path, line)")
    result = run_scan(root, config_path=config_path, confine_to_root=confine_to_root)
    finding = _match(result.findings, fingerprint=fingerprint, path=path, line=line)
    if finding is None:
        return None
    # A matched finding means analyze() ran to completion, which always sets
    # last_context; ScanResult.context is typed Optional only for the empty-scan
    # case that produces no findings to match here.
    assert result.context is not None
    context = result.context

    qualname = finding.qualname
    immediate_tainted_callee = (
        context.function_return_callee.get(qualname) if qualname is not None else None
    )

    # Resolve the source boundary ONE hop, honestly. If the immediate callee is a
    # simple (non-dotted) name, form the same-module candidate qualname and report
    # it ONLY when it is a known entity that is itself a leaf source (its own return
    # callee is None — it does not get its taint from a further call). Never report a
    # non-leaf intermediate, a dotted callee, or a cross-module/deep chain (SP9).
    source_boundary_qualname: str | None = None
    if (
        immediate_tainted_callee is not None
        and "." not in immediate_tainted_callee
        and qualname is not None
        and "." in qualname
    ):
        module = qualname.rsplit(".", 1)[0]
        candidate = f"{module}.{immediate_tainted_callee}"
        if (
            candidate in context.entities
            and context.function_return_callee.get(candidate) is None
        ):
            source_boundary_qualname = candidate

    prov = context.taint_provenance.get(qualname) if qualname is not None else None

    return TaintExplanation(
        fingerprint=finding.fingerprint,
        rule_id=finding.rule_id,
        sink_qualname=qualname,
        path=finding.location.path,
        line=finding.location.line_start,
        tier_in=finding.properties.get("actual_return"),
        tier_out=finding.properties.get("declared_return"),
        immediate_tainted_callee=immediate_tainted_callee,
        source_boundary_qualname=source_boundary_qualname,
        resolved_call_count=prov.resolved_call_count if prov is not None else 0,
        unresolved_call_count=prov.unresolved_call_count if prov is not None else 0,
    )
