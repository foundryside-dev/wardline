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

import dataclasses
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from wardline.core.errors import ClarionError
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


def _explain_local(
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


def _is_fresh(view: Any) -> bool:
    """Fresh iff: exists, a live current_content_hash is present, the blob is a
    structurally sound dict (with a dict ``taint``), and the in-blob
    content_hash_at_compute equals that live hash. Wardline decides freshness by
    comparing the stamp IT wrote against the hash Clarion read live; Clarion never
    asserts a verdict. Missing hash (file deleted/unreadable), exists:false, or a
    malformed/skewed blob (wrong types after the HTTP round-trip) ⇒ stale, so the
    caller falls through to the SP8 re-run rather than serving a broken fact."""
    if not view.exists or view.current_content_hash is None:
        return False
    blob = view.wardline_json
    if not isinstance(blob, dict) or not isinstance(blob.get("taint"), dict):
        return False
    stamped = blob.get("content_hash_at_compute")
    return stamped is not None and stamped == view.current_content_hash


def _callee_leaf(callee_qualname: str | None) -> str | None:
    """The blob stores the resolved callee QUALNAME; SP8's immediate_tainted_callee is
    the bare trailing name. Project back for surface parity with the SP8 shape."""
    return None if callee_qualname is None else callee_qualname.rsplit(".", 1)[-1]


def _explanation_from_blob(view: Any) -> TaintExplanation:
    """Project a fresh stored blob into the SP8 TaintExplanation shape (no analysis).
    The store is entity-scoped, so per-finding location comes from the blob's findings[]
    when present (else blank/None — the entity is known, the specific finding is not)."""
    blob = view.wardline_json if isinstance(view.wardline_json, dict) else {}
    taint = blob.get("taint")
    if not isinstance(taint, dict):
        taint = {}
    findings = blob.get("findings")
    if not isinstance(findings, list):
        findings = []
    first = findings[0] if findings and isinstance(findings[0], dict) else {}
    callee_q = taint.get("contributing_callee_qualname")
    return TaintExplanation(
        fingerprint=str(first.get("fingerprint", "")),
        rule_id=str(first.get("rule_id", "")),
        sink_qualname=blob.get("qualname"),
        path="",
        line=first.get("line_start"),
        tier_in=taint.get("actual_return"),
        tier_out=taint.get("declared_return"),
        immediate_tainted_callee=_callee_leaf(callee_q),
        source_boundary_qualname=callee_q,
        resolved_call_count=int(taint.get("resolved_call_count", 0) or 0),
        unresolved_call_count=int(taint.get("unresolved_call_count", 0) or 0),
    )


@dataclass(frozen=True, slots=True)
class ChainHop:
    qualname: str
    tier_in: str | None
    tier_out: str | None
    contributing_callee_qualname: str | None


@dataclass(frozen=True, slots=True)
class TaintChain:
    hops: list[ChainHop]
    truncated_at: str | None  # the next qualname we could NOT walk (stale/absent/max_hops), or None


def explain_chain(
    root: Path,
    *,
    sink_qualname: str,
    clarion: Any,
    max_hops: int = 20,
) -> TaintChain:
    """Walk contributing_callee_qualname from the sink to the boundary, batch_getting
    each hop's fresh fact. Truncate EXPLICITLY (never silently) on a stale/absent hop,
    a loud read error, an unresolvable callee, or max_hops. Entirely client-side;
    Clarion never parses."""
    hops: list[ChainHop] = []
    current: str | None = sink_qualname
    seen: set[str] = set()
    while current is not None:
        if len(hops) >= max_hops:
            return TaintChain(hops=hops, truncated_at=current)
        if current in seen:  # cycle guard
            return TaintChain(hops=hops, truncated_at=current)
        seen.add(current)
        try:
            views = clarion.batch_get([current])
        except ClarionError:
            views = None  # loud read error (bad token/route-skew) → explicit truncation
        if not views:
            return TaintChain(hops=hops, truncated_at=current)  # outage/read-error
        view = views[0]
        if view.qualname != current or not _is_fresh(view):
            # wrong-entity echo (contract violation) or stale/absent → explicit stop
            return TaintChain(hops=hops, truncated_at=current)
        blob = view.wardline_json or {}
        taint = blob.get("taint", {})
        next_q = taint.get("contributing_callee_qualname")
        hops.append(ChainHop(
            qualname=current,
            tier_in=taint.get("actual_return"),
            tier_out=taint.get("declared_return"),
            contributing_callee_qualname=next_q,
        ))
        current = next_q  # None at the boundary leaf → clean finish
    return TaintChain(hops=hops, truncated_at=None)


def explain_finding(
    root: Path,
    *,
    fingerprint: str | None = None,
    path: str | None = None,
    line: int | None = None,
    config_path: Path | None = None,
    confine_to_root: bool = False,
    clarion: Any | None = None,
    sink_qualname: str | None = None,
) -> TaintExplanation | None:
    """Explain ONE finding's taint. Standalone (clarion=None) ⇒ identical to SP8.

    Fast path: when ``clarion`` and ``sink_qualname`` are both given (the MCP loop just
    scanned, so it knows the sink's qualname), consult the store FIRST — a FRESH fact
    is served from the blob with NO re-analysis. On a miss/stale/outage, or when no
    ``sink_qualname`` is available, fall back to the SP8 re-run (``_explain_local``)."""
    if clarion is not None and sink_qualname is not None:
        try:
            views = clarion.batch_get([sink_qualname])
        except ClarionError:
            # A loud read-side error (bad token → 401, 400, route-skew → 404) is NOT
            # load-bearing for explain: degrade to the SP8 re-run, never raise. (The
            # store read is optional enrichment; only the WRITE path surfaces a 4xx.)
            views = None
        if views and views[0].qualname == sink_qualname and _is_fresh(views[0]):
            served = _explanation_from_blob(views[0])
            return dataclasses.replace(
                served,
                fingerprint=fingerprint or served.fingerprint,
                path=path or served.path,
                line=line if line is not None else served.line,
            )
        # miss/stale/outage → fall through to the re-run
    return _explain_local(
        root, fingerprint=fingerprint, path=path, line=line,
        config_path=config_path, confine_to_root=confine_to_root,
    )
