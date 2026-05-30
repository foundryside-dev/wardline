# src/wardline/core/explain.py
"""SP8: project the taint provenance the engine computes but otherwise discards.

``explain_finding`` re-runs the analysis (via run_scan, which retains the
analysis context in-process) and projects the cheap provenance slice for one
finding: the immediate tainted callee, the originating boundary (a bounded walk
of the via_callee chain — NOT the full N-hop chain, which is deferred), the
trust tiers at the sink, and the resolution counts.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from wardline.core.run import run_scan

if TYPE_CHECKING:
    from collections.abc import Mapping

    from wardline.core.finding import Finding
    from wardline.scanner.taint.propagation import TaintProvenance


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


def _walk_to_origin(
    provenance: Mapping[str, TaintProvenance], start: str | None
) -> str | None:
    """Follow via_callee from ``start`` to the anchored origin. Bounded by chain
    length; guards against cycles. Returns the last qualname whose via_callee is
    None (the source boundary), or None if no chain exists."""
    seen: set[str] = set()
    cur = start
    origin = start
    while cur is not None and cur not in seen:
        seen.add(cur)
        prov = provenance.get(cur)
        if prov is None:
            break
        origin = cur
        if prov.via_callee is None:
            break
        cur = prov.via_callee
    return origin


def explain_finding(
    root: Path,
    *,
    fingerprint: str | None = None,
    path: str | None = None,
    line: int | None = None,
    config_path: Path | None = None,
) -> TaintExplanation | None:
    """Return the taint explanation for one finding, or None if it is not in the
    current scan (the caller's code changed since the scan that produced the
    fingerprint — re-scan)."""
    if fingerprint is None and (path is None or line is None):
        raise ValueError("explain_finding requires either fingerprint or (path, line)")
    result = run_scan(root, config_path=config_path)
    finding = _match(result.findings, fingerprint=fingerprint, path=path, line=line)
    if finding is None:
        return None

    provenance: Mapping[str, TaintProvenance] = {}
    if result.context is not None:
        provenance = getattr(result.context, "taint_provenance", {}) or {}
    prov = provenance.get(finding.qualname) if finding.qualname is not None else None
    immediate = prov.via_callee if prov is not None else None
    origin = _walk_to_origin(provenance, finding.qualname) if finding.qualname else None

    return TaintExplanation(
        fingerprint=finding.fingerprint,
        rule_id=finding.rule_id,
        sink_qualname=finding.qualname,
        path=finding.location.path,
        line=finding.location.line_start,
        tier_in=finding.properties.get("actual_return"),
        tier_out=finding.properties.get("declared_return"),
        immediate_tainted_callee=immediate,
        source_boundary_qualname=origin,
        resolved_call_count=prov.resolved_call_count if prov is not None else 0,
        unresolved_call_count=prov.unresolved_call_count if prov is not None else 0,
    )
