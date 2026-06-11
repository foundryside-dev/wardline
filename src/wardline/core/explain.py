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
from typing import TYPE_CHECKING, Any

from wardline.core.errors import LoomweaveError
from wardline.core.run import run_scan

if TYPE_CHECKING:
    from wardline.core.finding import Finding
    from wardline.scanner.context import AnalysisContext


@dataclass(frozen=True, slots=True)
class TaintExplanation:
    fingerprint: str
    rule_id: str
    sink_qualname: str | None
    path: str
    line: int | None
    tier_in: str | None  # actual (untrusted) tier arriving at the sink
    tier_out: str | None  # tier the sink declares it returns
    immediate_tainted_callee: str | None
    source_boundary_qualname: str | None
    resolved_call_count: int
    unresolved_call_count: int


def explanation_from_context(finding: Finding, context: AnalysisContext) -> TaintExplanation:
    """Project the cheap provenance slice for one finding from an ALREADY-COMPUTED
    analysis context (no re-analysis). Shared by `_explain_local` (single-finding
    re-run) and the MCP `scan(explain=true)` inliner, so both produce identical
    provenance. Resolves the source boundary ONE hop only (full N-hop chain is the
    Loomweave-backed `explain_chain`)."""
    qualname = finding.qualname
    immediate_tainted_callee = context.function_return_callee.get(qualname) if qualname is not None else None
    source_boundary_qualname: str | None = None
    if (
        immediate_tainted_callee is not None
        and "." not in immediate_tainted_callee
        and qualname is not None
        and "." in qualname
    ):
        module = qualname.rsplit(".", 1)[0]
        candidate = f"{module}.{immediate_tainted_callee}"
        if candidate in context.entities and context.function_return_callee.get(candidate) is None:
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
    confine_to_root: bool = True,
) -> TaintExplanation | None:
    """Return the taint explanation for one finding, or None if it is not in the
    current scan (the caller's code changed since the scan that produced the
    fingerprint — re-scan)."""
    if fingerprint is None and (path is None or line is None):
        raise ValueError("explain_finding requires either fingerprint or (path, line)")
    if path is not None:
        try:
            p = Path(path)
            if p.is_absolute():
                path = p.relative_to(root.resolve()).as_posix()
            else:
                path = (root / p).resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            pass
    result = run_scan(root, config_path=config_path, confine_to_root=confine_to_root)
    finding = _match(result.findings, fingerprint=fingerprint, path=path, line=line)
    if finding is None:
        return None
    # A matched finding means analyze() ran to completion, which always sets
    # last_context; ScanResult.context is typed Optional only for the empty-scan
    # case that produces no findings to match here.
    assert result.context is not None
    return explanation_from_context(finding, result.context)


def _is_fresh(view: Any) -> bool:
    """Fresh iff: exists, a live current_content_hash is present, the blob is a
    structurally sound dict (with a dict ``taint``), and the in-blob
    content_hash_at_compute equals that live hash. Wardline decides freshness by
    comparing the stamp IT wrote against the hash Loomweave read live; Loomweave never
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


def _opt_str(value: Any) -> str | None:
    """Type-narrow an untrusted store-blob field to string-or-None.

    The blob is external input (hand-editable, version-skewable); the adjacent
    fingerprint/rule_id/path/line fields are already isinstance-guarded — taint tiers
    and callee qualnames get the same treatment so a type-skewed blob cannot put a
    non-string into a payload published as string|null in the MCP outputSchema."""
    return value if isinstance(value, str) else None


def _callee_leaf(callee_qualname: str | None) -> str | None:
    """The blob stores the resolved callee QUALNAME; SP8's immediate_tainted_callee is
    the bare trailing name. Project back for surface parity with the SP8 shape."""
    return None if callee_qualname is None else callee_qualname.rsplit(".", 1)[-1]


def _blob_finding_matches(
    finding: dict[str, Any],
    *,
    fingerprint: str | None,
    path: str | None,
    line: int | None,
    rule_id: str | None,
) -> bool:
    if fingerprint is not None and finding.get("fingerprint") != fingerprint:
        return False
    if rule_id is not None and finding.get("rule_id") != rule_id:
        return False
    if path is not None and finding.get("path") != path:
        return False
    return not (line is not None and finding.get("line_start") != line)


def _select_blob_finding(
    findings: list[dict[str, Any]],
    *,
    fingerprint: str | None,
    path: str | None,
    line: int | None,
    rule_id: str | None,
) -> dict[str, Any] | None:
    requested_specific = fingerprint is not None or path is not None or line is not None or rule_id is not None
    if requested_specific:
        return next(
            (
                finding
                for finding in findings
                if _blob_finding_matches(finding, fingerprint=fingerprint, path=path, line=line, rule_id=rule_id)
            ),
            None,
        )
    return findings[0] if findings else {}


def _explanation_from_blob(
    view: Any,
    *,
    fingerprint: str | None = None,
    path: str | None = None,
    line: int | None = None,
    rule_id: str | None = None,
) -> TaintExplanation | None:
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
    finding_rows = [f for f in findings if isinstance(f, dict)]
    first = _select_blob_finding(finding_rows, fingerprint=fingerprint, path=path, line=line, rule_id=rule_id)
    if first is None:
        return None
    callee_q = _opt_str(taint.get("contributing_callee_qualname"))
    stored_fingerprint = first.get("fingerprint")
    stored_rule_id = first.get("rule_id")
    stored_path = first.get("path")
    stored_line = first.get("line_start")
    qualname = blob.get("qualname")
    return TaintExplanation(
        fingerprint=stored_fingerprint if isinstance(stored_fingerprint, str) else "",
        rule_id=stored_rule_id if isinstance(stored_rule_id, str) else "",
        sink_qualname=qualname if isinstance(qualname, str) else None,
        path=stored_path if isinstance(stored_path, str) else "",
        line=stored_line if isinstance(stored_line, int) else None,
        tier_in=_opt_str(taint.get("actual_return")),
        tier_out=_opt_str(taint.get("declared_return")),
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
    loomweave: Any,
    max_hops: int = 20,
) -> TaintChain:
    """Walk contributing_callee_qualname from the sink to the boundary, batch_getting
    each hop's fresh fact. Truncate EXPLICITLY (never silently) on a stale/absent hop,
    a loud read error, an unresolvable callee, or max_hops. Entirely client-side;
    Loomweave never parses."""
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
            views = loomweave.batch_get([current])
        except LoomweaveError:
            views = None  # loud read error (bad token/route-skew) → explicit truncation
        if not views:
            return TaintChain(hops=hops, truncated_at=current)  # outage/read-error
        view = views[0]
        if view.qualname != current or not _is_fresh(view):
            # wrong-entity echo (contract violation) or stale/absent → explicit stop
            return TaintChain(hops=hops, truncated_at=current)
        blob = view.wardline_json or {}
        taint = blob.get("taint", {})
        next_q = _opt_str(taint.get("contributing_callee_qualname"))
        hops.append(
            ChainHop(
                qualname=current,
                tier_in=_opt_str(taint.get("actual_return")),
                tier_out=_opt_str(taint.get("declared_return")),
                contributing_callee_qualname=next_q,
            )
        )
        current = next_q  # None at the boundary leaf → clean finish
    return TaintChain(hops=hops, truncated_at=None)


def explain_finding(
    root: Path,
    *,
    fingerprint: str | None = None,
    path: str | None = None,
    line: int | None = None,
    config_path: Path | None = None,
    confine_to_root: bool = True,
    loomweave: Any | None = None,
    sink_qualname: str | None = None,
) -> TaintExplanation | None:
    """Explain ONE finding's taint. Standalone (loomweave=None) ⇒ identical to SP8.

    Fast path: when ``loomweave`` and ``sink_qualname`` are both given (the MCP loop just
    scanned, so it knows the sink's qualname), consult the store FIRST — a FRESH fact
    is served from the blob with NO re-analysis. On a miss/stale/outage, or when no
    ``sink_qualname`` is available, fall back to the SP8 re-run (``_explain_local``)."""
    if path is not None:
        try:
            p = Path(path)
            if p.is_absolute():
                path = p.relative_to(root.resolve()).as_posix()
            else:
                path = (root / p).resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            pass
    if loomweave is not None and sink_qualname is not None:
        try:
            views = loomweave.batch_get([sink_qualname])
        except LoomweaveError:
            # A loud read-side error (bad token → 401, 400, route-skew → 404) is NOT
            # load-bearing for explain: degrade to the SP8 re-run, never raise. (The
            # store read is optional enrichment; only the WRITE path surfaces a 4xx.)
            views = None
        if views and views[0].qualname == sink_qualname and _is_fresh(views[0]):
            served = _explanation_from_blob(views[0], fingerprint=fingerprint, path=path, line=line)
            if served is not None:
                return served
        # miss/stale/outage → fall through to the re-run
    return _explain_local(
        root,
        fingerprint=fingerprint,
        path=path,
        line=line,
        config_path=config_path,
        confine_to_root=confine_to_root,
    )


def explanation_to_dict(exp: TaintExplanation) -> dict[str, Any]:
    """The serialized explanation slice + remediation hint. Single source for the
    MCP ``explain_taint`` result and the CLI ``wardline explain-taint`` output
    (identical by construction — the N-2 dead-end was the CLI lacking this)."""
    return {
        "tier_in": exp.tier_in,
        "tier_out": exp.tier_out,
        "immediate_tainted_callee": exp.immediate_tainted_callee,
        "source_boundary_qualname": exp.source_boundary_qualname,
        "resolved_call_count": exp.resolved_call_count,
        "unresolved_call_count": exp.unresolved_call_count,
        "remediation": remediation_to_dict(exp),
    }


def remediation_to_dict(exp: TaintExplanation) -> dict[str, Any]:
    if exp.rule_id != "PY-WL-101":
        return {
            "kind": "review_required",
            "rule_id": exp.rule_id,
            "summary": (
                "Review the finding and apply the rule-specific fix; no automated remediation hint is available."
            ),
            "sink_qualname": exp.sink_qualname,
            "source_qualname": exp.source_boundary_qualname,
            "caveat": "This hint is advisory and does not replace the factual taint explanation.",
        }

    source = exp.source_boundary_qualname or exp.immediate_tainted_callee
    sink = exp.sink_qualname
    if source and sink:
        summary = (
            f"Validate or normalize data from {source} before it reaches trusted producer {sink}. "
            "Add or repair a @trust_boundary only on the function that actually rejects invalid data."
        )
    elif sink:
        summary = (
            f"Validate or normalize the raw input before it reaches trusted producer {sink}; "
            "the taint source is unresolved in this explanation. Add or repair a @trust_boundary only where "
            "the code actually rejects invalid data."
        )
    else:
        summary = (
            "Validate or normalize the raw input before it reaches the trusted producer; the taint source is "
            "unresolved in this explanation. Add or repair a @trust_boundary only where the code actually "
            "rejects invalid data."
        )
    return {
        "kind": "boundary_placement",
        "rule_id": exp.rule_id,
        "summary": summary,
        "sink_qualname": sink,
        "source_qualname": source,
        "caveat": (
            "Do not use blind decorator insertion; mark a trust boundary only on code that validates "
            "and rejects invalid data."
        ),
    }


def explain_taint_result(
    root: Path,
    *,
    fingerprint: str | None = None,
    path: str | None = None,
    line: int | None = None,
    config_path: Path | None = None,
    confine_to_root: bool = True,
    loomweave: Any | None = None,
    sink_qualname: str | None = None,
    chain: bool = False,
    max_hops: int = 20,
) -> dict[str, Any] | None:
    """The full ``explain_taint`` result dict shared by the MCP handler and the
    CLI command. None means the fingerprint/location is not in the current scan
    (the caller maps that to its own error channel — ToolError or exit 2).

    ``chain=True`` additionally walks the full taint chain when a Loomweave
    store is configured; without one it degrades silently to the single-hop
    explanation (no ``chain`` block), exactly as the MCP tool documents.
    """
    exp = explain_finding(
        root,
        fingerprint=fingerprint,
        path=path,
        line=line,
        config_path=config_path,
        confine_to_root=confine_to_root,
        loomweave=loomweave,
        sink_qualname=sink_qualname,
    )
    if exp is None:
        return None
    result: dict[str, Any] = {
        "fingerprint": exp.fingerprint,
        "rule_id": exp.rule_id,
        "sink_qualname": exp.sink_qualname,
        "location": {"path": exp.path, "line": exp.line},
        **explanation_to_dict(exp),
    }
    if chain and loomweave is not None and exp.sink_qualname:
        ch = explain_chain(root, sink_qualname=exp.sink_qualname, loomweave=loomweave, max_hops=max_hops)
        result["chain"] = {
            "hops": [
                {
                    "qualname": h.qualname,
                    "tier_in": h.tier_in,
                    "tier_out": h.tier_out,
                    "contributing_callee_qualname": h.contributing_callee_qualname,
                }
                for h in ch.hops
            ],
            "truncated_at": ch.truncated_at,
        }
    return result
