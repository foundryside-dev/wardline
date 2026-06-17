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

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from wardline.core.errors import LoomweaveError
from wardline.core.run import run_scan
from wardline.core.taints import RAW_ZONE

if TYPE_CHECKING:
    from wardline.core.finding import Finding
    from wardline.scanner.context import AnalysisContext

# The C-10(c) honest-degrade marker: when the taint source is not derivable from
# wardline's own single-scan analysis, the response names the capability that could
# resolve it further and how to enable it — never nulls that read as a
# complete-but-empty answer (dogfood-5 B7, weft-0d24cf9152).
LOOMWEAVE_CAPABILITY = "loomweave_taint_store"
LOOMWEAVE_ENABLEMENT = (
    "configure a Loomweave store (--loomweave-url / WARDLINE_LOOMWEAVE_URL / "
    "weft.toml [loomweave].url) and call explain_taint with chain=true to walk "
    "the stored cross-entity taint chain"
)


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
    # Dotted name of the dangerous sink CALLABLE for call-site-anchored sink findings
    # (properties["sink"], e.g. "logging.getLogger.info"); None for return-tier rules
    # and on the store-served path (the blob carries no sink property).
    sink: str | None = None


def _untrusted_project_callee(call: ast.Call, context: AnalysisContext) -> str | None:
    """The resolved in-project callee of *call* when its RETURN taint is in the raw
    zone (an untrusted source), else None."""
    callee = context.call_site_callees.get(id(call))
    if callee is None:
        return None
    taint = context.function_return_taints.get(callee, context.project_return_taints.get(callee))
    return callee if taint in RAW_ZONE else None


def _sink_arg_exprs(call: ast.Call) -> list[ast.expr]:
    return [*call.args, *[kw.value for kw in call.keywords]]


def _call_matches_finding_span(call: ast.Call, finding: Finding, line: int) -> bool:
    if getattr(call, "lineno", None) != line:
        return False
    if finding.location.col_start is not None and getattr(call, "col_offset", None) != finding.location.col_start:
        return False
    return not (
        finding.location.col_end is not None and getattr(call, "end_col_offset", None) != finding.location.col_end
    )


def _sink_taint_source(finding: Finding, context: AnalysisContext) -> str | None:
    """For a call-site-anchored sink finding, the in-project call that introduced the
    untrusted value into the sink's arguments — derived from wardline's OWN analysis
    (no store needed): either a raw-returning call INLINE in the sink's argument list
    (``logger.info(read_raw(p))``) or the LAST raw-returning call assigned to a name
    the sink's arguments use (``msg = read_raw(p); logger.info(msg)``). Returns the
    callee's qualname, or None when the source is genuinely not derivable from the
    single scan (imported/dynamic sources — the Loomweave chain walk's territory)."""
    qualname, line = finding.qualname, finding.location.line_start
    if qualname is None or line is None:
        return None
    entity = context.entities.get(qualname)
    if entity is None:
        return None
    sink_calls = [
        n for n in ast.walk(entity.node) if isinstance(n, ast.Call) and _call_matches_finding_span(n, finding, line)
    ]
    if not sink_calls:
        return None
    # (a) a raw-returning call nested directly in the sink's own arguments.
    for sink in sink_calls:
        for arg in _sink_arg_exprs(sink):
            for sub in ast.walk(arg):
                if isinstance(sub, ast.Call):
                    callee = _untrusted_project_callee(sub, context)
                    if callee is not None:
                        return callee
    # (b) a Name argument assigned from a raw-returning call earlier in the function;
    # the LAST such assignment before the sink line wins (mirrors L2's forward walk).
    arg_names = {
        sub.id
        for sink in sink_calls
        for arg in _sink_arg_exprs(sink)
        for sub in ast.walk(arg)
        if isinstance(sub, ast.Name)
    }
    if not arg_names:
        return None
    best: tuple[int, str] | None = None
    for node in ast.walk(entity.node):
        targets: list[ast.expr]
        value: ast.expr | None
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = list(node.targets) if isinstance(node, ast.Assign) else [node.target]
            value = node.value
        elif isinstance(node, ast.NamedExpr):
            targets, value = [node.target], node.value
        else:
            continue
        if value is None or not isinstance(value, ast.Call) or node.lineno > line:
            continue
        if not any(isinstance(t, ast.Name) and t.id in arg_names for t in targets):
            continue
        callee = _untrusted_project_callee(value, context)
        if callee is not None and (best is None or node.lineno > best[0]):
            best = (node.lineno, callee)
    return best[1] if best else None


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
    sink = finding.properties.get("sink")
    if immediate_tainted_callee is None and isinstance(sink, str):
        # A sink finding's tainted value reaches the sink ARGUMENT, never the return,
        # so the return-callee map cannot explain it (B7, weft-0d24cf9152): derive the
        # source from the sink's argument flow instead.
        source = _sink_taint_source(finding, context)
        if source is not None:
            immediate_tainted_callee = source.rsplit(".", 1)[-1]
            if source in context.entities and context.function_return_callee.get(source) is None:
                source_boundary_qualname = source  # a leaf source — the 1-hop boundary
    tier_in = finding.properties.get("actual_return")
    tier_out = finding.properties.get("declared_return")
    if isinstance(sink, str):
        # Sink findings carry their tier facts as arg_taint (what arrives at the sink)
        # and tier (the enclosing declared tier) — project them, not nulls.
        tier_in = tier_in or finding.properties.get("arg_taint")
        tier_out = tier_out or finding.properties.get("tier")
    prov = context.taint_provenance.get(qualname) if qualname is not None else None
    return TaintExplanation(
        fingerprint=finding.fingerprint,
        rule_id=finding.rule_id,
        sink_qualname=qualname,
        path=finding.location.path,
        line=finding.location.line_start,
        tier_in=tier_in,
        tier_out=tier_out,
        immediate_tainted_callee=immediate_tainted_callee,
        source_boundary_qualname=source_boundary_qualname,
        resolved_call_count=prov.resolved_call_count if prov is not None else 0,
        unresolved_call_count=prov.unresolved_call_count if prov is not None else 0,
        sink=sink if isinstance(sink, str) else None,
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


def _local_content_hash(root: Path, path: str) -> str | None:
    """Return the local whole-file blake3 for an in-project relative path."""
    try:
        from wardline.loomweave import require_blake3

        blake3 = require_blake3()
        root_resolved = root.resolve()
        candidate = Path(path)
        local = candidate if candidate.is_absolute() else root / candidate
        resolved = local.resolve(strict=True)
        if not resolved.is_file() or not resolved.is_relative_to(root_resolved):
            return None
        return str(blake3.blake3(resolved.read_bytes()).hexdigest())
    except (OSError, ValueError, LoomweaveError):
        return None


def _is_fresh(view: Any, *, root: Path | None = None, path: str | None = None) -> bool:
    """Fresh iff the stored Wardline stamp matches current file bytes.

    When a local ``root`` and selected finding ``path`` are available, freshness is
    checked against the local file hash. The remote ``current_content_hash`` is kept
    only for legacy chain reads that lack a path; it is not authoritative for
    ``explain_finding`` blob serving.
    """
    if not view.exists:
        return False
    blob = view.wardline_json
    if not isinstance(blob, dict) or not isinstance(blob.get("taint"), dict):
        return False
    stamped = blob.get("content_hash_at_compute")
    if root is not None and path is not None:
        local_hash = _local_content_hash(root, path)
        return isinstance(stamped, str) and local_hash is not None and stamped == local_hash
    if view.current_content_hash is None:
        return False
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


def _opt_count(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


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
    return findings[0] if findings else None


def _explanation_from_blob(
    view: Any,
    *,
    root: Path | None = None,
    sink_qualname: str | None = None,
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
    resolved_call_count = _opt_count(taint.get("resolved_call_count", 0))
    unresolved_call_count = _opt_count(taint.get("unresolved_call_count", 0))
    if resolved_call_count is None or unresolved_call_count is None:
        return None
    stored_fingerprint = first.get("fingerprint")
    stored_rule_id = first.get("rule_id")
    stored_path = first.get("path")
    stored_line = first.get("line_start")
    qualname = blob.get("qualname")
    if sink_qualname is not None and qualname != sink_qualname:
        return None
    if root is not None and (not isinstance(stored_path, str) or not _is_fresh(view, root=root, path=stored_path)):
        return None
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
        resolved_call_count=resolved_call_count,
        unresolved_call_count=unresolved_call_count,
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
        if views and views[0].qualname == sink_qualname:
            served = _explanation_from_blob(
                views[0],
                root=root,
                sink_qualname=sink_qualname,
                fingerprint=fingerprint,
                path=path,
                line=line,
            )
            # Serve the cached fact only when it actually NAMES a source, OR when no
            # re-run is possible (a pure-store read keyed on sink_qualname alone has
            # no local match key). A blob whose contributing callee is null answers
            # nothing for a sink-argument finding (the store records return-taint
            # facts), while the SP8 re-run can derive the source from the sink's
            # argument flow (B7, weft-0d24cf9152) — correctness over the cached read.
            can_rerun = fingerprint is not None or (path is not None and line is not None)
            if served is not None and (
                served.immediate_tainted_callee is not None
                or served.source_boundary_qualname is not None
                or not can_rerun
            ):
                return served
        # miss/stale/outage/sourceless → fall through to the re-run
    if fingerprint is None and path is None and line is None:
        return None
    return _explain_local(
        root,
        fingerprint=fingerprint,
        path=path,
        line=line,
        config_path=config_path,
        confine_to_root=confine_to_root,
    )


def source_resolution_to_dict(exp: TaintExplanation, *, loomweave_configured: bool = False) -> dict[str, Any]:
    """The C-10(c) honesty block: is the taint source named, and if not, WHY and what
    capability would resolve it further. Fixed key set so an unresolved source is an
    explicit degrade marker, never nulls that read as a complete-but-empty answer
    (B7, weft-0d24cf9152)."""
    if exp.immediate_tainted_callee is not None or exp.source_boundary_qualname is not None:
        return {"status": "resolved", "reason": None, "missing_capability": None, "enablement": None}
    where = f" in {exp.sink_qualname}" if exp.sink_qualname else ""
    reason = (
        "wardline's single-scan analysis could not attribute the tainted value"
        f"{where} to a resolvable in-project call (imported or dynamic sources are "
        "beyond its single-scan reach)"
    )
    if loomweave_configured:
        return {
            "status": "unresolved",
            "reason": reason + "; the configured Loomweave store's facts also carried no contributing callee",
            "missing_capability": None,
            "enablement": None,
        }
    return {
        "status": "unresolved",
        "reason": reason,
        "missing_capability": LOOMWEAVE_CAPABILITY,
        "enablement": LOOMWEAVE_ENABLEMENT,
    }


def explanation_to_dict(exp: TaintExplanation, *, loomweave_configured: bool = False) -> dict[str, Any]:
    """The serialized explanation slice + remediation hint. Single source for the
    MCP ``explain_taint`` result and the CLI ``wardline explain-taint`` output
    (identical by construction — the N-2 dead-end was the CLI lacking this)."""
    return {
        "tier_in": exp.tier_in,
        "tier_out": exp.tier_out,
        "immediate_tainted_callee": exp.immediate_tainted_callee,
        "source_boundary_qualname": exp.source_boundary_qualname,
        "source_resolution": source_resolution_to_dict(exp, loomweave_configured=loomweave_configured),
        "resolved_call_count": exp.resolved_call_count,
        "unresolved_call_count": exp.unresolved_call_count,
        "remediation": remediation_to_dict(exp),
    }


# Rule-specific fix guidance for the call-site-anchored sink family — generic "review
# the finding" text on a SPECIFIC finding is part of the B7 defect. One sentence per
# rule, composed with the named source/sink below.
_SINK_FIX_HINTS: dict[str, str] = {
    "PY-WL-106": (
        "Deserialize only trusted bytes: verify provenance or switch to a "
        "schema-validated format (e.g. json.loads + validation) before the sink."
    ),
    "PY-WL-107": (
        "Never pass untrusted text to dynamic execution; replace it with an explicit "
        "dispatch table or parser, or strictly allowlist the input first."
    ),
    "PY-WL-108": (
        "Run a fixed program path and pass untrusted values only as list-form "
        "arguments (never through a shell); validate or allowlist them first."
    ),
    "PY-WL-112": (
        "Avoid shell=True with untrusted input: use list-form arguments without a "
        "shell, or quote via shlex.quote after validating."
    ),
    "PY-WL-115": (
        "Do not import modules named by untrusted input; resolve the name through an "
        "explicit allowlist of importable modules."
    ),
    "PY-WL-116": (
        "Resolve untrusted paths against a fixed base directory and reject escapes "
        "(e.g. Path.resolve() + is_relative_to) before opening."
    ),
    "PY-WL-118": ("Use parameterized queries (placeholders) — never interpolate untrusted values into SQL text."),
    "PY-WL-117": (
        "Validate the URL against an allowlist of schemes and hosts before fetching; never fetch a raw caller URL."
    ),
    "PY-WL-121": ("Parse untrusted XML with entity resolution disabled (e.g. defusedxml) instead of the raw parser."),
    "PY-WL-122": (
        "Never compile untrusted text as a template; render untrusted values only as template DATA (context variables)."
    ),
    "PY-WL-123": (
        "Do not let untrusted input choose attribute names; map allowed names "
        "explicitly instead of reflecting raw input."
    ),
    "PY-WL-124": (
        "Load native libraries only from fixed, vetted paths — never from a path derived from untrusted input."
    ),
    "PY-WL-125": (
        "Do not use untrusted data as the log message format string: use logging's "
        "lazy parameterization (logger.info('value=%s', value)) or strip "
        "newline/control characters first."
    ),
    "PY-WL-126": ("Validate and normalize recipient addresses and message bodies (reject CR/LF) before the mail API."),
}


def remediation_to_dict(exp: TaintExplanation) -> dict[str, Any]:
    source = exp.source_boundary_qualname or exp.immediate_tainted_callee
    hint = _SINK_FIX_HINTS.get(exp.rule_id)
    if exp.rule_id != "PY-WL-101" and hint is not None:
        sink_call = f"the {exp.sink} sink" if exp.sink else "the sink"
        where = f" in {exp.sink_qualname}" if exp.sink_qualname else ""
        origin = f"from {source} " if source else ""
        return {
            "kind": "sink_hygiene",
            "rule_id": exp.rule_id,
            "summary": f"Untrusted data {origin}reaches {sink_call}{where}. {hint}",
            "sink_qualname": exp.sink_qualname,
            "source_qualname": source,
            "caveat": "This hint is advisory and does not replace the factual taint explanation.",
        }
    if exp.rule_id != "PY-WL-101":
        return {
            "kind": "review_required",
            "rule_id": exp.rule_id,
            "summary": (
                "Review the finding and apply the rule-specific fix; no automated remediation hint is available."
            ),
            "sink_qualname": exp.sink_qualname,
            "source_qualname": source,
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
        **explanation_to_dict(exp, loomweave_configured=loomweave is not None),
    }
    if chain and loomweave is not None and exp.sink_qualname:
        ch = explain_chain(root, sink_qualname=exp.sink_qualname, loomweave=loomweave, max_hops=max_hops)
        result["chain"] = {
            "status": "walked",
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
            "missing_capability": None,
            "enablement": None,
        }
    elif chain:
        # chain=true but the walk cannot run: say so EXPLICITLY (C-10(c)) — an absent
        # block was a silent degrade an agent read as "no chain exists".
        missing = LOOMWEAVE_CAPABILITY if loomweave is None else "sink_qualname"
        enablement = (
            LOOMWEAVE_ENABLEMENT
            if loomweave is None
            else "this finding carries no qualname for the engine to anchor the walk on; re-scan and use a finding with one"  # noqa: E501
        )
        result["chain"] = {
            "status": "unavailable",
            "hops": [],
            "truncated_at": None,
            "missing_capability": missing,
            "enablement": enablement,
        }
    return result
