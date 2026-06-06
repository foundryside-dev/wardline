"""SP8: the Wardline MCP server — tools/resources/prompts wired to core/.

Stateless (no server-side session carried between calls). The read-only tools
(scan, explain_taint) are pure functions of (disk + config); fix, the suppression
tools (baseline, waiver_add), and judge --write mutate
project files on disk. Rooted at a project path (launch cwd by default)."""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import replace
from datetime import date
from pathlib import Path
from typing import Any

from wardline._version import __version__
from wardline.core import config as config_mod
from wardline.core.assure import build_posture
from wardline.core.attest import build_attestation, verify_attestation
from wardline.core.attest_key import load_attest_key
from wardline.core.baseline import generate_baseline, load_baseline
from wardline.core.errors import WardlineError
from wardline.core.explain import explain_chain, explain_finding, explanation_from_context
from wardline.core.filigree_emit import FiligreeEmitter, filigree_disabled_reason
from wardline.core.finding import Finding, Kind, Severity, SuppressionState
from wardline.core.finding_query import filter_findings
from wardline.core.judge_run import run_judge
from wardline.core.run import baseline_migration_hint, gate_decision, run_scan
from wardline.core.safe_paths import safe_project_file
from wardline.core.sei_resolution import resolve_query_filters
from wardline.core.waivers import add_waiver, parse_waivers
from wardline.mcp.prompts import get_prompt, list_prompts
from wardline.mcp.protocol import _INVALID_PARAMS, JsonRpcServer, McpError
from wardline.mcp.resources import list_resources, read_resource
from wardline.mcp.tooling import Tool, ToolCapability, ToolError, ToolPolicy
from wardline.mcp.tooling import cfg as _cfg
from wardline.mcp.tooling import explanation_to_dict as _explanation_to_dict
from wardline.mcp.tooling import finding_to_dict as _finding_to_dict
from wardline.mcp.tooling import require as _require
from wardline.mcp.tooling import resolve_under_root as _resolve_under_root


def _emit_filigree(
    findings: list[Finding], filigree: Any, *, scanned_paths: tuple[str, ...] = ()
) -> dict[str, Any] | None:
    """Emit to Filigree for the MCP `scan`, returning None when no emitter is injected.

    Sibling-unreachable / 5xx results are already soft in FiligreeEmitter as
    ``reachable=False``. Protocol/client rejections stay loud by letting
    ``FiligreeEmitError`` propagate into the tool's isError result.
    """
    if filigree is None:
        return None
    er = filigree.emit(findings, scanned_paths=scanned_paths)
    return {
        "reachable": er.reachable,
        "created": er.created,
        "updated": er.updated,
        "failed": er.failed,
        "warnings": list(er.warnings),
        # Distinguish auth-rejected (401/403) from transport-unreachable so the agent reads
        # an actionable reason, not a flat "unreachable" (dogfood #5).
        "status": er.status,
        "auth_rejected": er.auth_rejected,
    }


def _filigree_emit_status(block: dict[str, Any] | None) -> dict[str, Any]:
    if block is None:
        return {
            "configured": False,
            "reachable": None,
            "created": 0,
            "updated": 0,
            "failed": 0,
            "warnings": [],
            "disabled_reason": "not configured",
        }
    disabled_reason = filigree_disabled_reason(
        reachable=bool(block.get("reachable")),
        auth_rejected=bool(block.get("auth_rejected")),
        status=block.get("status"),
    )
    return {"configured": True, "disabled_reason": disabled_reason, **block}


def _loomweave_write_status(block: dict[str, Any] | None) -> dict[str, Any]:
    if block is None:
        return {
            "configured": False,
            "reachable": None,
            "written": 0,
            "unresolved_qualnames": [],
            "disabled_reason": "not configured",
        }
    return {"configured": True, **block}


def _file_finding(args: dict[str, Any], root: Path, filer: Any, loomweave: Any = None) -> dict[str, Any]:
    """File ONE finding (by fingerprint) into a tracked Filigree issue, returning its
    id. Fail-soft on reachability; a 404 (unknown fingerprint) surfaces as not_found."""
    if filer is None:
        raise ToolError("no Filigree URL configured; launch `wardline mcp --filigree-url ...`")
    fp = _require(args, "fingerprint")
    labels = args.get("labels")
    if labels is not None and not isinstance(labels, list):
        raise ToolError("labels must be an array of strings")
    res = filer.file(fp, priority=args.get("priority"), labels=labels)
    payload = {
        "reachable": res.reachable,
        "issue_id": res.issue_id,
        "created": res.created,
        "not_found": res.not_found,
        "fingerprint": fp,
        "disabled_reason": res.disabled_reason,
    }
    if bool(args.get("attach_loomweave_identity") or False):
        from wardline.core.filigree_issue import attach_loomweave_identity_for_finding, identity_attach_result_to_json

        payload["identity_attach"] = identity_attach_result_to_json(
            attach_loomweave_identity_for_finding(
                fingerprint=fp,
                issue_id=res.issue_id,
                root=root,
                filer=filer,
                loomweave_client=loomweave,
                config_path=_cfg(args, root),
            )
        )
    return payload


def _scan_file_findings(
    args: dict[str, Any],
    root: Path,
    filigree_emitter: Any = None,
    filigree_filer: Any = None,
    loomweave: Any = None,
) -> dict[str, Any]:
    fingerprints_raw = args.get("fingerprints") or []
    if not isinstance(fingerprints_raw, list) or not all(isinstance(fp, str) for fp in fingerprints_raw):
        raise ToolError("fingerprints must be an array of strings")
    labels_raw = args.get("labels") or []
    if not isinstance(labels_raw, list) or not all(isinstance(label, str) for label in labels_raw):
        raise ToolError("labels must be an array of strings")
    dry_run = bool(args.get("dry_run", not (bool(args.get("all_active")) or bool(fingerprints_raw))))
    path = _resolve_under_root(root, args["path"]) if args.get("path") else root
    from wardline.core.scan_file_workflow import scan_file_findings

    return scan_file_findings(
        root=path,
        config_path=_cfg(args, root),
        cache_dir=_cache_dir_arg(args, root),
        fail_on=args.get("fail_on"),
        trust_local_packs=bool(args.get("trust_local_packs", False)),
        trusted_packs=_trusted_packs_arg(args),
        strict_defaults=bool(args.get("strict_defaults", False)),
        fingerprints=tuple(fingerprints_raw),
        all_active=bool(args.get("all_active", False)),
        dry_run=dry_run,
        priority=args.get("priority"),
        labels=tuple(labels_raw),
        filigree_emitter=filigree_emitter,
        filigree_filer=filigree_filer,
        loomweave_client=loomweave,
    )


def _trusted_packs_arg(args: dict[str, Any]) -> tuple[str, ...]:
    trusted_packs_raw = args.get("trust_packs") or []
    if not isinstance(trusted_packs_raw, list) or not all(isinstance(p, str) for p in trusted_packs_raw):
        raise ToolError("trust_packs must be an array of strings")
    return tuple(trusted_packs_raw)


def _cache_dir_arg(args: dict[str, Any], root: Path) -> Path | None:
    return _resolve_under_root(root, args["cache_dir"]) if args.get("cache_dir") else None


def _bool_arg(args: dict[str, Any], name: str, default: bool) -> bool:
    # Reject non-bool values loudly rather than ``bool(...)``-coercing them: a JSON string
    # like "false" would otherwise coerce to True, silently inverting intent. Matches the
    # strict (agent-actionable) validation max_findings already gets.
    val = args.get(name)
    if val is None:
        return default
    if not isinstance(val, bool):
        raise ToolError(f"{name} must be a boolean")
    return val


def _scan(
    args: dict[str, Any],
    root: Path,
    loomweave: Any = None,
    filigree: Any = None,
    *,
    trust_local_packs: bool = False,
    strict_defaults: bool = False,
) -> dict[str, Any]:
    path = _resolve_under_root(root, args["path"]) if args.get("path") else root
    fail_on = args.get("fail_on")
    try:
        threshold = Severity(fail_on) if fail_on else None
    except ValueError as exc:
        # A bad enum value is agent-actionable — give it the valid set rather than
        # letting it surface as an opaque generic JSON-RPC -32603.
        raise ToolError("fail_on must be one of CRITICAL/ERROR/WARN/INFO") from exc
    new_since = args.get("new_since")
    trusted_packs = _trusted_packs_arg(args)
    cache_dir = _cache_dir_arg(args, root)
    trust_suppressions = bool(args.get("trust_suppressions") or False)
    result = run_scan(
        path,
        config_path=_cfg(args, root),
        cache_dir=cache_dir,
        confine_to_root=True,
        new_since=new_since,
        trust_local_packs=trust_local_packs,
        trusted_packs=trusted_packs,
        strict_defaults=strict_defaults,
        trust_suppressions=trust_suppressions,
    )
    # Fail-soft Loomweave write: only when a client was injected (server has a URL).
    # An outage/403 yields a not-reachable WriteResult; never raises here.
    loomweave_block: dict[str, Any] | None = None
    if loomweave is not None:
        from wardline.core.errors import LoomweaveError
        from wardline.loomweave.client import WriteResult
        from wardline.loomweave.write import write_facts_to_loomweave

        try:
            wr = write_facts_to_loomweave(result, path, loomweave)
        except LoomweaveError as exc:
            # Non-load-bearing enrichment: the MCP loop's scan payload must survive
            # an optional-write failure (bad config / missing extra / 4xx). Report,
            # don't discard the scan.
            wr = WriteResult(reachable=False, disabled_reason=str(exc))
        loomweave_block = {
            "reachable": wr.reachable,
            "written": wr.written,
            "unresolved_qualnames": list(wr.unresolved_qualnames),
            "disabled_reason": wr.disabled_reason,
        }
    decision = gate_decision(result, threshold)
    migration_hint = baseline_migration_hint(result, decision, root=path, new_since=new_since)
    filigree_block = _emit_filigree(result.findings, filigree, scanned_paths=result.scanned_paths)
    filigree_status = _filigree_emit_status(filigree_block)
    loomweave_status = _loomweave_write_status(loomweave_block)
    where = args.get("where")
    try:
        resolved_where = resolve_query_filters(where, root, _cfg(args, root), loomweave)
        selected = filter_findings(result.findings, resolved_where)
    except (ValueError, WardlineError) as exc:
        # An unknown filter key or SEI resolution failure is agent-actionable -> isError result.
        raise ToolError(str(exc)) from exc

    # Payload-shrinking controls (dogfood #4). The `summary`/`gate` blocks always
    # describe the WHOLE project; these only bound the returned finding bodies.
    summary_only = _bool_arg(args, "summary_only", False)
    include_suppressed = _bool_arg(args, "include_suppressed", True)
    max_findings = args.get("max_findings")
    if max_findings is not None and (
        not isinstance(max_findings, int) or isinstance(max_findings, bool) or max_findings < 0
    ):
        raise ToolError("max_findings must be a non-negative integer")
    explain = _bool_arg(args, "explain", False)

    # include_suppressed:false drops the suppressed DEFECT bodies (counts stay whole).
    if not include_suppressed:
        selected = [f for f in selected if not (f.kind is Kind.DEFECT and f.suppressed is not SuppressionState.ACTIVE)]
    findings_total = len(selected)

    # summary_only returns no finding bodies at all (the smallest "did the gate pass?"
    # payload); otherwise an explicit max_findings bounds the list (default: uncapped).
    display = [] if summary_only else selected
    findings_truncated = False
    if max_findings is not None and len(display) > max_findings:
        display = display[:max_findings]
        findings_truncated = True

    # explain has a DEFAULT ceiling: inlining EVERY active defect's provenance is the
    # 56KB-on-one-line blowup the dogfood report hit. Cap the number of explanations (an
    # explicit max_findings tightens it further); findings past the cap are still
    # returned, just without inline provenance. The cut is announced, never silent.
    explain_cap = max_findings if max_findings is not None else _EXPLAIN_DEFAULT_CAP
    explanations_attached = 0
    explanations_truncated = False
    findings_out: list[dict[str, Any]] = []
    for f in display:
        d = _finding_to_dict(f)
        if (
            explain
            and f.kind is Kind.DEFECT
            and f.suppressed is SuppressionState.ACTIVE
            and f.qualname is not None
            and result.context is not None
        ):
            if explanations_attached < explain_cap:
                exp = explanation_from_context(f, result.context)
                d["explanation"] = _explanation_to_dict(exp)
                explanations_attached += 1
            else:
                explanations_truncated = True
        findings_out.append(d)
    from wardline.core.agent_summary import build_agent_summary

    response: dict[str, Any] = {
        "files_scanned": result.files_scanned,
        "findings": findings_out,
        "summary": {
            "total": result.summary.total,
            "active": result.summary.active,
            "baselined": result.summary.baselined,
            "waived": result.summary.waived,
            "judged": result.summary.judged,
            # Files discovered but NOT analysed (parse error / too-deep / missing
            # source root — benign no-module skips are excluded). Surfaced so the
            # silent under-scan reaches the agent, not just the human-facing stderr.
            "unanalyzed": result.summary.unanalyzed,
        },
        # Make every cut explicit so a bounded payload never reads as "covered all".
        "truncation": {
            "summary_only": summary_only,
            "include_suppressed": include_suppressed,
            "max_findings": max_findings,
            "findings_total": findings_total,
            "findings_returned": len(findings_out),
            "findings_truncated": findings_truncated,
            "explanations_truncated": explanations_truncated,
        },
        "gate": {
            "tripped": decision.tripped,
            "fail_on": decision.fail_on,
            "exit_class": decision.exit_class,
            "reason": decision.reason,
            "evaluated": decision.evaluated,
            "migration_hint": migration_hint,
        },
        "loomweave": loomweave_block,
        "filigree": filigree_block,
        "loomweave_write": loomweave_status,
        "filigree_emit": filigree_status,
        "agent_summary": build_agent_summary(
            result,
            decision,
            filigree_emit=filigree_status,
            loomweave_write=loomweave_status,
            display_findings=selected,
            summary_only=summary_only,
            max_findings=max_findings,
            include_suppressed=include_suppressed,
            migration_hint=migration_hint,
        ).to_dict(),
    }
    _attach_legis_artifact(
        response,
        result,
        path,
        args,
        trust_local_packs=trust_local_packs,
        trusted_packs=trusted_packs,
        strict_defaults=strict_defaults,
    )
    return response


def _attach_legis_artifact(
    response: dict[str, Any],
    result: Any,
    path: Path,
    args: dict[str, Any],
    *,
    trust_local_packs: bool,
    trusted_packs: tuple[str, ...],
    strict_defaults: bool,
) -> None:
    """Opt-in: attach the signed, verbatim-postable legis scan-artifact.

    Activated only when a shared HMAC secret is provisioned
    (``WARDLINE_LEGIS_ARTIFACT_KEY`` env or ``.env``) OR the caller passes
    ``legis_artifact: true`` (unsigned, for legis's optional-verify posture). When
    neither is requested the response is byte-unchanged from the released shape.

    Fail-soft like the Loomweave/Filigree blocks: a signing refusal (dirty tree /
    non-repo) reports ``signed: false`` with the reason and omits the postable
    artifact — it never fails the scan itself. The agent posts ``legis_artifact``
    verbatim as the ``scan`` field of ``POST /wardline/scan-results``.
    """
    from wardline.core.errors import LegisArtifactError
    from wardline.core.legis import build_legis_artifact, key_id, load_legis_artifact_key

    key_str = load_legis_artifact_key(path)
    if key_str is None and not bool(args.get("legis_artifact")):
        return  # not requested — default response unchanged

    cfg = config_mod.load(
        _cfg(args, path) or (path / "wardline.yaml"),
        trust_local_packs=trust_local_packs,
        trusted_packs=trusted_packs,
        strict_defaults=strict_defaults,
    )
    key_bytes = key_str.encode("utf-8") if key_str else None
    allow_dirty = _bool_arg(args, "allow_dirty", False)
    status: dict[str, Any] = {
        "configured": True,
        "signed": False,
        "key_id": key_id(key_str) if key_str else None,
        "reason": None,
    }
    try:
        artifact = build_legis_artifact(result, root=path, config=cfg, key=key_bytes, allow_dirty=allow_dirty)
    except LegisArtifactError as exc:
        status["reason"] = str(exc)
        response["legis_artifact_status"] = status
        return
    # A dirty tree under allow_dirty falls through to the unsigned dev artifact: it is
    # never signed even with a key present (false-provenance guard), and legis records
    # it `unverified`. Report signed honestly from the artifact, not from key presence.
    dirty = bool(artifact.get("dirty"))
    status["signed"] = key_bytes is not None and not dirty
    status["dirty"] = dirty
    if dirty:
        # Match the CLI's loudness on the agent surface: the artifact is UNSIGNED and legis
        # records it unverified — say so and say "never gate CI on it" rather than leaving
        # the agent to infer it from signed:false / dirty:true alone (agent-first).
        status["reason"] = (
            "dirty working tree — emitted an UNSIGNED legis dev artifact (legis records it "
            "unverified); never gate CI on it. Commit for a signed artifact."
        )
    response["legis_artifact"] = artifact
    response["legis_artifact_status"] = status


def _explain_taint(args: dict[str, Any], root: Path, loomweave: Any = None) -> dict[str, Any]:
    # The store-backed read path: when a Loomweave store is configured and the caller
    # passes the finding's qualname as `sink_qualname`, explain_finding serves a FRESH
    # fact straight from the store with no re-scan; otherwise it falls back to the SP8
    # re-run. loomweave=None reproduces SP8 behavior exactly. With chain=true it also walks
    # the full taint chain to the originating boundary.
    # path+line identify a source location of an existing finding (not a scan
    # subdir): pass path through only when a line is also given. The path is a
    # MATCH KEY (compared against a finding's relative posix location), not a file
    # to open — so confine it for escape-rejection but pass the ORIGINAL string.
    match_path = args.get("path") if args.get("line") is not None else None
    if match_path is not None:
        _resolve_under_root(root, match_path)  # reject escapes; result discarded
    exp = explain_finding(
        root,
        fingerprint=args.get("fingerprint"),
        path=match_path,
        line=args.get("line"),
        config_path=_cfg(args, root),
        confine_to_root=True,
        loomweave=loomweave,
        sink_qualname=args.get("sink_qualname"),
    )
    if exp is None:
        raise ToolError(
            "fingerprint not in current scan; your code changed since the scan that produced it — re-scan.",
        )
    result_dict: dict[str, Any] = {
        "fingerprint": exp.fingerprint,
        "rule_id": exp.rule_id,
        "sink_qualname": exp.sink_qualname,
        "location": {"path": exp.path, "line": exp.line},
        **_explanation_to_dict(exp),
    }
    if args.get("chain") and loomweave is not None and exp.sink_qualname:
        max_hops_raw = args.get("max_hops")
        max_hops = int(max_hops_raw) if max_hops_raw is not None else 20
        ch = explain_chain(root, sink_qualname=exp.sink_qualname, loomweave=loomweave, max_hops=max_hops)
        result_dict["chain"] = {
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
    return result_dict


def _dossier(
    args: dict[str, Any], root: Path, loomweave: Any = None, filigree_url: str | None = None
) -> dict[str, Any]:
    """Assemble the one-call entity dossier. The SEI-keyed, freshness-honest read:
    Wardline's own trust posture (always real) + Loomweave linkages + Filigree open work,
    each section degrading to an honest `unavailable` when its source is absent."""
    from wardline.weft_dossier import build_weft_dossier

    entity = _require(args, "entity")
    dossier = build_weft_dossier(
        entity,
        root=root,
        loomweave_client=loomweave,
        filigree_url=filigree_url,
        config_path=_cfg(args, root),
        confine_to_root=True,
    )
    return dossier.to_dict()


def _assure(args: dict[str, Any], root: Path) -> dict[str, Any]:
    """Trust-surface COVERAGE posture — the pre-trust-decision read. How many declared
    trust boundaries the engine reached a definite verdict on vs. how many are honestly
    unknown, plus waiver-debt. Identical to the CLI `assure` JSON by construction (both
    call ``build_posture``). Path/config confined under root like every rooted tool."""
    path = _resolve_under_root(root, args["path"]) if args.get("path") else root
    posture = build_posture(path, config_path=_cfg(args, root), confine_to_root=True)
    return posture.to_dict()


def _decorator_coverage(
    args: dict[str, Any],
    root: Path,
    loomweave: Any = None,
    filigree_url: str | None = None,
) -> dict[str, Any]:
    """Row-level inventory of every trust-decorated entity under the project."""
    from wardline.weft_decorator_coverage import build_weft_decorator_coverage

    path = _resolve_under_root(root, args["path"]) if args.get("path") else root
    report = build_weft_decorator_coverage(
        path,
        loomweave_client=loomweave,
        filigree_url=filigree_url,
        config_path=_cfg(args, root),
        confine_to_root=True,
    )
    return report.to_dict()


def _attest(args: dict[str, Any], root: Path, loomweave: Any = None) -> dict[str, Any]:
    """Build a SIGNED, reproducible evidence bundle for the project — identical to the
    CLI `attest` by construction (both call ``build_attestation``). Path/config confined
    under root. DEFAULTS to strict on a dirty tree (`allow_dirty=False`): an agent must
    not silently attest uncommitted changes — core defaults the other way, so the MCP
    boundary INVERTS it. A dirty refusal raises ``AttestError`` (a ``WardlineError``) →
    the existing isError mapping, not a crash."""
    resolved_root = _resolve_under_root(root, args["path"]) if args.get("path") else root
    key = load_attest_key(resolved_root)
    if key is None:
        raise ToolError("no attest key — run `wardline install` to mint one (or set WARDLINE_ATTEST_KEY)")
    allow_dirty = bool(args.get("allow_dirty", False))
    return build_attestation(
        resolved_root,
        key,
        config_path=_cfg(args, root),
        cache_dir=_cache_dir_arg(args, root),
        confine_to_root=True,
        trust_local_packs=bool(args.get("trust_local_packs", False)),
        trusted_packs=_trusted_packs_arg(args),
        strict_defaults=bool(args.get("strict_defaults", False)),
        loomweave_client=loomweave,
        allow_dirty=allow_dirty,
    )


def _verify_attestation(args: dict[str, Any], root: Path, loomweave: Any = None) -> dict[str, Any]:
    """Verify an attestation bundle's signature (offline, needs the project key) and
    optionally re-derive it at the current tree (`reproduce=true`). Identical to the CLI
    `attest --verify` by construction."""
    bundle = _require(args, "bundle")
    if not isinstance(bundle, dict) or "payload" not in bundle or "signature" not in bundle:
        raise ToolError("bundle must contain 'payload' and 'signature'")
    resolved_root = _resolve_under_root(root, args["path"]) if args.get("path") else root
    key = load_attest_key(resolved_root)
    if key is None:
        raise ToolError("no attest key — run `wardline install` to mint one (or set WARDLINE_ATTEST_KEY)")
    reproduce = bool(args.get("reproduce", False))
    return verify_attestation(
        bundle,
        key,
        root=resolved_root,
        reproduce=reproduce,
        config_path=_cfg(args, root),
        cache_dir=_cache_dir_arg(args, root),
        loomweave_client=loomweave,
        confine_to_root=True,
        trust_local_packs=bool(args.get("trust_local_packs", False)),
        trusted_packs=_trusted_packs_arg(args),
        strict_defaults=bool(args.get("strict_defaults", False)),
    )


def _judge(args: dict[str, Any], root: Path) -> dict[str, Any]:
    # No key/.env → run_judge's default caller raises JudgeConfigurationError (a
    # WardlineError) naming WARDLINE_OPENROUTER_API_KEY; _tools_call turns that into
    # an isError result the agent can read. The network is touched only here, only
    # when a finding is actually triaged.
    context_lines = args.get("context_lines")
    outcome = run_judge(
        root,
        config_path=_cfg(args, root),
        model=args.get("model"),
        max_findings=args.get("max_findings"),
        write=bool(args.get("write", False)),
        confine_to_root=True,
        trust_local_packs=bool(args.get("trust_local_packs", False)),
        trusted_packs=tuple(args.get("trust_packs") or []),
        trust_judge_config=bool(args.get("trust_judge_config", False)),
        trust_judge_policy=bool(args.get("trust_judge_policy", False)),
        strict_defaults=bool(args.get("strict_defaults", False)),
        context_lines=int(context_lines) if context_lines is not None else None,
    )
    return {
        "verdicts": [
            {
                "fingerprint": v.fingerprint,
                "rule_id": v.rule_id,
                "path": v.path,
                "line": v.line,
                "label": v.label,
                "confidence": v.confidence,
                "rationale": v.rationale,
            }
            for v in outcome.verdicts
        ],
        "wrote": outcome.wrote,
        "held_back": outcome.held_back,
    }


def _baseline(args: dict[str, Any], root: Path) -> dict[str, Any]:
    reason = args.get("reason")
    baseline_path = root / ".wardline" / "baseline.yaml"
    overwrite = bool(args.get("overwrite", False))
    try:
        count = generate_baseline(
            root,
            overwrite=overwrite,
            config_path=_cfg(args, root),
            cache_dir=_cache_dir_arg(args, root),
            confine_to_root=True,
            trust_local_packs=bool(args.get("trust_local_packs", False)),
            trusted_packs=_trusted_packs_arg(args),
            strict_defaults=bool(args.get("strict_defaults", False)),
        )
    except FileExistsError:
        if overwrite:
            raise
        existing = load_baseline(baseline_path)
        return {
            "baselined_count": len(existing.fingerprints),
            "path": str(baseline_path),
            "reason": reason,
            "already_exists": True,
        }
    payload = {"baselined_count": count, "path": str(baseline_path), "reason": reason}
    if not overwrite:
        payload["already_exists"] = False
    return payload


def _waiver_add(args: dict[str, Any], root: Path) -> dict[str, Any]:
    fp = _require(args, "fingerprint")
    reason = _require(args, "reason")
    expires_str = _require(args, "expires")  # mandatory at the tool boundary
    if not isinstance(expires_str, str):
        raise ToolError("expires must be a string in YYYY-MM-DD format")
    try:
        expires = date.fromisoformat(expires_str)
    except ValueError as exc:
        # A malformed date is something the agent can fix and should see.
        raise ToolError("expires must be an ISO date (YYYY-MM-DD)") from exc
    cfg_path = _cfg(args, root) or (root / "wardline.yaml")
    safe_cfg_path = safe_project_file(root, cfg_path, label=cfg_path.name)
    if safe_cfg_path.exists():
        for existing in parse_waivers(config_mod.load(safe_cfg_path).waivers):
            if existing.fingerprint == fp:
                return {
                    "fingerprint": existing.fingerprint,
                    "reason": existing.reason,
                    "expires": existing.expires.isoformat() if existing.expires else None,
                    "already_exists": True,
                }
    waiver = add_waiver(cfg_path, fingerprint=fp, reason=reason, expires=expires, root=root)
    return {
        "fingerprint": waiver.fingerprint,
        "reason": waiver.reason,
        "expires": waiver.expires.isoformat() if waiver.expires else None,
        "already_exists": False,
    }


def _fix(args: dict[str, Any], root: Path) -> dict[str, Any]:
    """Scan the path and apply mechanical autofixes to findings in-place."""
    path = _resolve_under_root(root, args["path"]) if args.get("path") else root
    cfg_path = _cfg(args, root)
    try:
        from wardline.core.config import load

        cfg = load(cfg_path or (path / "wardline.yaml"))
        result = run_scan(path, config_path=cfg_path, confine_to_root=True)
    except WardlineError as exc:
        raise ToolError(str(exc)) from exc

    findings = [f for f in result.findings if f.rule_id == "PY-WL-111"]
    if not findings:
        return {"fixed": {}, "message": "No fixable findings found."}

    from wardline.core.autofix import run_autofix

    dry_run = not bool(args.get("apply", False)) or bool(args.get("dry_run", False))
    applied = run_autofix(findings, cfg, path, dry_run=dry_run)
    action = "Previewed" if dry_run else "Applied"
    return {
        "fixed": applied,
        "applied": not dry_run,
        "message": f"{action} fixes for {len(applied)} files." if applied else "No fixes applied.",
    }


# Gate thresholds are the four defect severities. Severity also defines NONE
# (the "facts carry no defect severity" sentinel), deliberately excluded here:
# fail_on=NONE is not a meaningful gate threshold.
_SEVERITY_ENUM = ["CRITICAL", "ERROR", "WARN", "INFO"]

# Default ceiling on the number of active-defect provenances inlined by `explain: true`
# on the MCP `scan`. Bounds the one-shot payload (the dogfood report hit 56,820 chars on
# one line over a whole repo); an explicit `max_findings` tightens it further.
_EXPLAIN_DEFAULT_CAP = 10


class WardlineMCPServer:
    def __init__(
        self,
        *,
        root: Path,
        loomweave_url: str | None = None,
        filigree_url: str | None = None,
        allow_write: bool = True,
        allow_network: bool = True,
    ) -> None:
        self.root = Path(root)
        self.loomweave_url = loomweave_url
        self.filigree_url = filigree_url
        self._tool_policy = ToolPolicy(allow_write=allow_write, allow_network=allow_network)
        self.rpc = JsonRpcServer(server_name="wardline", server_version=__version__)
        self._tools: dict[str, Tool] = {}
        self._register_tools()
        self._wire()

    def _loomweave_client(
        self,
        config_path: Path | None = None,
        *,
        trust_local_packs: bool = False,
        trusted_packs: Iterable[str] = (),
        strict_defaults: bool = False,
    ) -> Any:
        """Build a LoomweaveClient for this server's root, or None when no URL is set."""
        url = config_mod.resolve_loomweave_url(
            self.loomweave_url,
            self.root,
            config_path,
            trust_local_packs=trust_local_packs,
            trusted_packs=trusted_packs,
            strict_defaults=strict_defaults,
        )
        if url is None:
            return None
        from wardline.loomweave.client import LoomweaveClient
        from wardline.loomweave.config import load_loomweave_token, resolve_project_name

        return LoomweaveClient(
            url,
            secret=load_loomweave_token(self.root),
            project=resolve_project_name(self.root),
        )

    def _filigree_emitter(
        self,
        config_path: Path | None = None,
        *,
        trust_local_packs: bool = False,
        trusted_packs: Iterable[str] = (),
        strict_defaults: bool = False,
    ) -> Any:
        """Build a FiligreeEmitter for this server's URL, or None when no URL is set."""
        url = config_mod.resolve_filigree_url(
            self.filigree_url,
            self.root,
            config_path,
            trust_local_packs=trust_local_packs,
            trusted_packs=trusted_packs,
            strict_defaults=strict_defaults,
        )
        if url is None:
            return None
        from wardline.filigree.config import load_filigree_token

        return FiligreeEmitter(url, token=load_filigree_token(self.root))

    def _filigree_filer(
        self,
        config_path: Path | None = None,
        *,
        trust_local_packs: bool = False,
        trusted_packs: Iterable[str] = (),
        strict_defaults: bool = False,
    ) -> Any:
        """Build a FiligreeIssueFiler from this server's Weft URL, or None when unset."""
        url = config_mod.resolve_filigree_url(
            self.filigree_url,
            self.root,
            config_path,
            trust_local_packs=trust_local_packs,
            trusted_packs=trusted_packs,
            strict_defaults=strict_defaults,
        )
        if url is None:
            return None
        from wardline.core.filigree_issue import FiligreeIssueFiler
        from wardline.filigree.config import load_filigree_token

        return FiligreeIssueFiler(url, token=load_filigree_token(self.root))

    def _register_tools(self) -> None:
        self.add_tool(
            Tool(
                name="scan",
                description="Whole-program taint scan of the project. Returns structured "
                "findings, the suppression summary (active = unsuppressed defects; "
                "by default the --fail-on gate evaluates the UNSUPPRESSED population so "
                "repo-controlled baseline/waiver/judged annotate but do not clear it — "
                "pass `trust_suppressions: true` for the trusted-local behaviour), "
                "and the gate verdict. Pass `where` to filter the returned findings "
                "(conjunctive; summary/gate stay whole-project) and `explain: true` to inline "
                "each active defect's taint provenance — one call, no per-finding explain_taint. "
                "When a Filigree URL is configured, also POSTs the "
                "findings to Filigree (fail-soft: an unreachable sibling or rejected payload "
                "is reported in the `filigree` block, never fails the scan).",
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "subdir relative to project root"},
                        "fail_on": {"type": "string", "enum": _SEVERITY_ENUM},
                        "config": {"type": "string"},
                        "where": {
                            "type": "object",
                            "description": "Filter the returned findings (conjunctive). Keys: "
                            "rule_id, qualname, severity, suppression, kind, path_glob, sink, tier. "
                            "summary/gate still describe the whole project.",
                            "properties": {
                                "rule_id": {"type": "string"},
                                "qualname": {"type": "string"},
                                "severity": {"type": "string", "enum": _SEVERITY_ENUM},
                                "suppression": {"type": "string", "enum": ["active", "baselined", "waived", "judged"]},
                                "kind": {
                                    "type": "string",
                                    "enum": ["defect", "fact", "classification", "metric", "suggestion"],
                                },
                                "path_glob": {"type": "string"},
                                "sink": {"type": "string"},
                                "tier": {"type": "string"},
                            },
                        },
                        "explain": {
                            "type": "boolean",
                            "description": "Inline each active defect's taint provenance "
                            "(immediate tainted callee, source boundary, trust tiers, resolution "
                            "counts) — one call instead of an explain_taint per finding. Inlining is "
                            "capped at 10 provenances by default (raise/lower with max_findings); the cut "
                            "is reported at truncation.explanations_truncated.",
                        },
                        "summary_only": {
                            "type": "boolean",
                            "description": "Return counts + gate only, no finding bodies — the smallest "
                            "'did the gate pass?' payload. summary/gate still describe the whole project.",
                        },
                        "max_findings": {
                            "type": "integer",
                            "minimum": 0,
                            "description": "Cap the number of returned finding bodies (and inlined "
                            "explanations). Must be a non-negative integer. The cut is reported in the "
                            "truncation block; summary counts stay whole-project.",
                        },
                        "include_suppressed": {
                            "type": "boolean",
                            "description": "Default true. Set false to drop suppressed (baselined/waived/"
                            "judged) finding bodies from the response; the suppression counts stay in "
                            "summary.",
                        },
                        "new_since": {
                            "type": "string",
                            "description": "PR-scoped 'new findings only' gate: only gate on findings in "
                            "files/entities changed since this git ref",
                        },
                        "cache_dir": {
                            "type": "string",
                            "description": "subdir relative to project root for summary cache",
                        },
                        "trust_packs": {"type": "array", "items": {"type": "string"}},
                        "trust_local_packs": {
                            "type": "boolean",
                            "description": "Allow loading custom trust-grammar packs from the local project directory",
                        },
                        "strict_defaults": {
                            "type": "boolean",
                            "description": "Ignore repository-supplied custom configuration overrides (wardline.yaml)",
                        },
                        "trust_suppressions": {
                            "type": "boolean",
                            "description": "Let repository-controlled baseline/waiver/judged clear the gate "
                            "(they always annotate findings regardless). Default false — the gate "
                            "evaluates the unsuppressed population so a PR cannot self-suppress its "
                            "own defect. Use only on a trusted checkout; in CI prefer new_since.",
                        },
                        "legis_artifact": {
                            "type": "boolean",
                            "description": "Attach the verbatim-postable legis scan-artifact "
                            "(`legis_artifact` block) even when no signing key is provisioned "
                            "(unsigned, for legis's optional-verify posture).",
                        },
                        "allow_dirty": {
                            "type": "boolean",
                            "description": "For the legis artifact only: on a dirty tree emit an UNSIGNED, "
                            "clearly-marked (dirty: true) dev artifact instead of refusing to sign. "
                            "Signing stays clean-tree-only; legis records it unverified.",
                        },
                    },
                },
                handler=lambda args, root: _scan(
                    args,
                    root,
                    self._loomweave_client(
                        _cfg(args, root),
                        trust_local_packs=bool(args.get("trust_local_packs") or False),
                        trusted_packs=tuple(args.get("trust_packs") or []),
                        strict_defaults=bool(args.get("strict_defaults") or False),
                    ),
                    self._filigree_emitter(
                        _cfg(args, root),
                        trust_local_packs=bool(args.get("trust_local_packs") or False),
                        trusted_packs=tuple(args.get("trust_packs") or []),
                        strict_defaults=bool(args.get("strict_defaults") or False),
                    ),
                    trust_local_packs=bool(args.get("trust_local_packs") or False),
                    strict_defaults=bool(args.get("strict_defaults") or False),
                ),
            )
        )
        self.add_tool(
            Tool(
                name="explain_taint",
                description="Explain ONE finding's taint: the immediate tainted callee, the "
                "originating boundary, and the trust tiers at the sink. Call right "
                "after scan and before editing — a stale fingerprint returns an error. "
                "Pass the finding's `qualname` as `sink_qualname`: when a Loomweave store "
                "is configured this serves the explanation from the store instead of "
                "re-scanning. Pass `chain: true` (needs a configured Loomweave store) to "
                "also walk the full taint chain from the sink to the originating boundary; "
                "without a store it degrades to the single-hop explanation (no `chain` block).",
                input_schema={
                    "type": "object",
                    "properties": {
                        "fingerprint": {"type": "string"},
                        "path": {"type": "string"},
                        "line": {"type": "integer"},
                        "sink_qualname": {"type": "string"},
                        "chain": {"type": "boolean"},
                        "max_hops": {"type": "integer"},
                        "config": {"type": "string"},
                    },
                },
                handler=lambda args, root: _explain_taint(args, root, self._loomweave_client(_cfg(args, root))),
            )
        )
        self.add_tool(
            Tool(
                name="dossier",
                description="One-call entity dossier for a function `entity` (a qualname): its "
                "trust posture (declared vs actual taint, gate verdict, active findings — always "
                "computed fresh), plus Loomweave call-graph linkages and Filigree open work joined on "
                "the entity's opaque SEI. Every cross-tool section is freshness-stamped on BOTH axes "
                "(identity alive/orphaned/unavailable + content fresh/stale/unknown) and degrades to "
                "an honest `unavailable` when its source is absent. Token-bounded (~2k) with an "
                "explicit truncation marker. Read the whole context without opening the source.",
                input_schema={
                    "type": "object",
                    "required": ["entity"],
                    "properties": {
                        "entity": {"type": "string", "description": "the function qualname, e.g. pkg.mod.func"},
                        "config": {"type": "string"},
                    },
                },
                handler=lambda args, root: _dossier(
                    args,
                    root,
                    self._loomweave_client(_cfg(args, root)),
                    config_mod.resolve_filigree_url(self.filigree_url, root, _cfg(args, root)),
                ),
            )
        )
        self.add_tool(
            Tool(
                name="assure",
                description="Trust-surface COVERAGE posture: how many declared trust boundaries the "
                "engine reached a definite verdict on vs. how many are honestly unknown, plus "
                "waiver-debt. Consult before deciding to trust a module.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "config": {"type": "string"},
                    },
                },
                handler=lambda args, root: _assure(args, root),
            )
        )
        self.add_tool(
            Tool(
                name="decorator_coverage",
                capabilities=frozenset({ToolCapability.READ, ToolCapability.NETWORK}),
                description="Stable JSON inventory of every Wardline trust-decorated entity: "
                "qualname, path/line, decorators, declared/actual tier, gate verdict, "
                "active/suppressed finding fingerprints, optional SEI/content status, and "
                "optional Filigree linked work status. Optional sources degrade explicitly.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "config": {"type": "string"},
                    },
                },
                handler=lambda args, root: _decorator_coverage(
                    args,
                    root,
                    self._loomweave_client(_cfg(args, root)),
                    config_mod.resolve_filigree_url(self.filigree_url, root, _cfg(args, root)),
                ),
            )
        )
        self.add_tool(
            Tool(
                name="attest",
                description="Build a SIGNED, reproducible evidence bundle (commit, ruleset hash, "
                "trust-surface posture, boundaries) for the project. HMAC-signed with the "
                "install-minted project key. Refuses a dirty working tree unless allow_dirty=true. "
                "SEI-keyed when a Loomweave store is configured.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "config": {"type": "string"},
                        "allow_dirty": {"type": "boolean"},
                        "cache_dir": {
                            "type": "string",
                            "description": "subdir relative to project root for summary cache",
                        },
                        "trust_packs": {"type": "array", "items": {"type": "string"}},
                        "trust_local_packs": {"type": "boolean"},
                        "strict_defaults": {"type": "boolean"},
                    },
                },
                handler=lambda args, root: _attest(
                    args,
                    root,
                    self._loomweave_client(
                        _cfg(args, root),
                        trust_local_packs=bool(args.get("trust_local_packs") or False),
                        trusted_packs=_trusted_packs_arg(args),
                        strict_defaults=bool(args.get("strict_defaults") or False),
                    ),
                ),
            )
        )
        self.add_tool(
            Tool(
                name="verify_attestation",
                description="Verify an attestation bundle's signature (offline, needs the project "
                "key) and optionally its reproducibility (reproduce=true re-derives at the current "
                "tree). Returns {signature_valid, reproduced, mismatches, note}.",
                input_schema={
                    "type": "object",
                    "required": ["bundle"],
                    "properties": {
                        "bundle": {"type": "object"},
                        "reproduce": {"type": "boolean"},
                        "config": {"type": "string"},
                        "path": {"type": "string"},
                        "cache_dir": {
                            "type": "string",
                            "description": "subdir relative to project root for summary cache",
                        },
                        "trust_packs": {"type": "array", "items": {"type": "string"}},
                        "trust_local_packs": {"type": "boolean"},
                        "strict_defaults": {"type": "boolean"},
                    },
                },
                handler=lambda args, root: _verify_attestation(
                    args,
                    root,
                    self._loomweave_client(
                        _cfg(args, root),
                        trust_local_packs=bool(args.get("trust_local_packs") or False),
                        trusted_packs=_trusted_packs_arg(args),
                        strict_defaults=bool(args.get("strict_defaults") or False),
                    ),
                ),
            )
        )
        self.add_tool(
            Tool(
                name="file_finding",
                capabilities=frozenset({ToolCapability.READ, ToolCapability.WRITE, ToolCapability.NETWORK}),
                description="File ONE finding (by `fingerprint`) into a tracked Filigree issue and "
                "return its `issue_id`. Idempotent (re-filing returns the same issue). Emit findings "
                "to Filigree first (scan with a configured Filigree URL) so the fingerprint is known; "
                "a `not_found: true` result means it isn't. Reconciliation (close-on-fixed / "
                "reopen-on-regress) happens automatically on later scans. Fail-soft.",
                input_schema={
                    "type": "object",
                    "required": ["fingerprint"],
                    "properties": {
                        "fingerprint": {"type": "string"},
                        "priority": {"type": "string", "description": "Filigree priority, e.g. P2"},
                        "labels": {"type": "array", "items": {"type": "string"}},
                        "attach_loomweave_identity": {
                            "type": "boolean",
                            "description": (
                                "Opt in to resolving the finding qualname through Loomweave and attaching "
                                "a Filigree entity association."
                            ),
                        },
                        "config": {"type": "string"},
                    },
                },
                handler=lambda args, root: _file_finding(
                    args,
                    root,
                    self._filigree_filer(_cfg(args, root)),
                    self._loomweave_client(_cfg(args, root))
                    if bool(args.get("attach_loomweave_identity") or False)
                    else None,
                ),
            )
        )
        self.add_tool(
            Tool(
                name="scan_file_findings",
                capabilities=frozenset({ToolCapability.READ, ToolCapability.WRITE, ToolCapability.NETWORK}),
                description="One-shot agent workflow: run a scan, list active defects first with "
                "inline explanation summaries, optionally emit to Filigree, promote selected "
                "fingerprints or all active defects, and attach Loomweave identity when available. "
                "Defaults to dry-run unless fingerprints or all_active are supplied.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "subdir relative to project root"},
                        "fail_on": {"type": "string", "enum": _SEVERITY_ENUM},
                        "config": {"type": "string"},
                        "cache_dir": {
                            "type": "string",
                            "description": "subdir relative to project root for summary cache",
                        },
                        "fingerprints": {"type": "array", "items": {"type": "string"}},
                        "all_active": {"type": "boolean"},
                        "dry_run": {"type": "boolean"},
                        "priority": {"type": "string", "description": "Filigree priority, e.g. P2"},
                        "labels": {"type": "array", "items": {"type": "string"}},
                        "trust_packs": {"type": "array", "items": {"type": "string"}},
                        "trust_local_packs": {"type": "boolean"},
                        "strict_defaults": {"type": "boolean"},
                    },
                },
                handler=lambda args, root: _scan_file_findings(
                    args,
                    root,
                    self._filigree_emitter(
                        _cfg(args, root),
                        trust_local_packs=bool(args.get("trust_local_packs") or False),
                        trusted_packs=tuple(args.get("trust_packs") or []),
                        strict_defaults=bool(args.get("strict_defaults") or False),
                    ),
                    self._filigree_filer(
                        _cfg(args, root),
                        trust_local_packs=bool(args.get("trust_local_packs") or False),
                        trusted_packs=tuple(args.get("trust_packs") or []),
                        strict_defaults=bool(args.get("strict_defaults") or False),
                    ),
                    self._loomweave_client(
                        _cfg(args, root),
                        trust_local_packs=bool(args.get("trust_local_packs") or False),
                        trusted_packs=tuple(args.get("trust_packs") or []),
                        strict_defaults=bool(args.get("strict_defaults") or False),
                    ),
                ),
            )
        )
        self.add_tool(
            Tool(
                name="judge",
                capabilities=frozenset({ToolCapability.READ, ToolCapability.NETWORK}),
                description="NETWORK: opt-in LLM triage of active defects via OpenRouter "
                "(needs WARDLINE_OPENROUTER_API_KEY). Labels each TRUE/FALSE positive. "
                "Never run automatically; never folded into scan.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "config": {"type": "string"},
                        "model": {"type": "string"},
                        "max_findings": {"type": "integer"},
                        "write": {"type": "boolean", "description": "append above-floor FPs to judged.yaml"},
                        "trust_judge_config": {"type": "boolean"},
                        "trust_judge_policy": {"type": "boolean"},
                        "trust_packs": {"type": "array", "items": {"type": "string"}},
                        "trust_local_packs": {"type": "boolean"},
                        "strict_defaults": {"type": "boolean"},
                        "context_lines": {"type": "integer"},
                    },
                },
                handler=_judge,
            )
        )
        self.add_tool(
            Tool(
                name="baseline",
                capabilities=frozenset({ToolCapability.READ, ToolCapability.WRITE}),
                description="Snapshot current defects as the baseline so only NEW findings surface. "
                "Default overwrite=false refuses to clobber and returns already_exists=true. "
                "Set overwrite=true to re-derive and overwrite the baseline. "
                "Prefer FIXING a finding over baselining it. Optional reason.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "reason": {"type": "string"},
                        "overwrite": {"type": "boolean"},
                        "config": {"type": "string"},
                        "cache_dir": {
                            "type": "string",
                            "description": "subdir relative to project root for summary cache",
                        },
                        "trust_packs": {"type": "array", "items": {"type": "string"}},
                        "trust_local_packs": {"type": "boolean"},
                        "strict_defaults": {"type": "boolean"},
                    },
                },
                handler=_baseline,
            )
        )
        self.add_tool(
            Tool(
                name="waiver_add",
                capabilities=frozenset({ToolCapability.READ, ToolCapability.WRITE}),
                description="Waive ONE finding by fingerprint with a mandatory reason and expiry. "
                "Prefer fixing; a waiver is an audited, time-boxed exception.",
                input_schema={
                    "type": "object",
                    "required": ["fingerprint", "reason", "expires"],
                    "properties": {
                        "fingerprint": {"type": "string"},
                        "reason": {"type": "string"},
                        "expires": {"type": "string", "description": "YYYY-MM-DD"},
                        "config": {"type": "string"},
                    },
                },
                handler=_waiver_add,
            )
        )
        self.add_tool(
            Tool(
                name="fix",
                capabilities=frozenset({ToolCapability.READ, ToolCapability.WRITE}),
                description="Scan and apply mechanical autofixes to findings (currently only PY-WL-111 is supported).",
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "subdir relative to project root to scan and fix"},
                        "config": {"type": "string"},
                        "dry_run": {"type": "boolean", "description": "preview changes without modifying files"},
                        "apply": {"type": "boolean", "description": "must be true to modify files"},
                    },
                },
                handler=_fix,
            )
        )

    def add_tool(self, tool: Tool) -> None:
        schema = dict(tool.input_schema)
        if schema.get("type") == "object":
            schema.setdefault("additionalProperties", False)
            tool = replace(tool, input_schema=schema)
        self._tools[tool.name] = tool

    def _wire(self) -> None:
        self.rpc.capabilities["tools"] = {"listChanged": False}
        self.rpc.register("tools/list", self._tools_list)
        self.rpc.register("tools/call", self._tools_call)
        self.rpc.capabilities["resources"] = {"listChanged": False}
        self.rpc.register("resources/list", self._resources_list)
        self.rpc.register("resources/read", self._resources_read)
        self.rpc.capabilities["prompts"] = {"listChanged": False}
        self.rpc.register("prompts/list", self._prompts_list)
        self.rpc.register("prompts/get", self._prompts_get)

    def _tools_list(self, params: dict[str, Any]) -> dict[str, Any]:
        return {
            "tools": [
                {
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": t.input_schema,
                    "capabilities": [cap.value for cap in sorted(t.capabilities, key=lambda c: c.value)],
                }
                for t in self._tools.values()
            ]
        }

    def _resolved_loomweave_url_for_policy(self, arguments: dict[str, Any]) -> str | None:
        return config_mod.resolve_loomweave_url(
            self.loomweave_url,
            self.root,
            _cfg(arguments, self.root),
            trust_local_packs=bool(arguments.get("trust_local_packs") or False),
            trusted_packs=_trusted_packs_arg(arguments),
            strict_defaults=bool(arguments.get("strict_defaults") or False),
        )

    def _resolved_filigree_url_for_policy(self, arguments: dict[str, Any]) -> str | None:
        return config_mod.resolve_filigree_url(
            self.filigree_url,
            self.root,
            _cfg(arguments, self.root),
            trust_local_packs=bool(arguments.get("trust_local_packs") or False),
            trusted_packs=_trusted_packs_arg(arguments),
            strict_defaults=bool(arguments.get("strict_defaults") or False),
        )

    def _effective_tool_capabilities(self, tool: Tool, arguments: dict[str, Any]) -> frozenset[ToolCapability]:
        capabilities = set(tool.capabilities)
        if tool.name == "scan" and (
            self._resolved_loomweave_url_for_policy(arguments) is not None
            or self._resolved_filigree_url_for_policy(arguments) is not None
        ):
            capabilities.update({ToolCapability.NETWORK, ToolCapability.WRITE})
        if (
            tool.name in {"explain_taint", "attest", "verify_attestation"}
            and self._resolved_loomweave_url_for_policy(arguments) is not None
        ):
            capabilities.add(ToolCapability.NETWORK)
        if tool.name == "dossier" and (
            self._resolved_loomweave_url_for_policy(arguments) is not None
            or self._resolved_filigree_url_for_policy(arguments) is not None
        ):
            capabilities.add(ToolCapability.NETWORK)
        if tool.name == "judge" and bool(arguments.get("write", False)):
            capabilities.add(ToolCapability.WRITE)
        return frozenset(capabilities)

    def _tools_call(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        if not isinstance(name, str):
            raise McpError("tools/call params.name must be a string", code=_INVALID_PARAMS)
        raw_arguments = params.get("arguments", {})
        arguments: dict[str, Any]
        if raw_arguments is None:
            arguments = {}
        elif isinstance(raw_arguments, dict):
            arguments = raw_arguments
        else:
            raise McpError("tools/call params.arguments must be an object", code=_INVALID_PARAMS)
        tool = self._tools.get(name)
        if tool is None:
            # Protocol fault (caller bug) → JSON-RPC error, not an agent-actionable
            # tool-execution outcome.
            raise McpError(f"unknown tool: {name}", code=_INVALID_PARAMS)

        if tool.input_schema:
            try:
                import jsonschema

                jsonschema.validate(arguments, tool.input_schema)
            except ImportError:
                import sys

                print("Warning: jsonschema is missing; skipping MCP tool argument validation.", file=sys.stderr)
            except jsonschema.ValidationError as exc:
                return self._is_error(f"invalid arguments: {exc.message}")

        try:
            effective_capabilities = self._effective_tool_capabilities(tool, arguments)
        except ToolError as exc:
            return self._is_error(exc.message)
        except WardlineError as exc:
            return self._is_error(str(exc))

        denial = self._tool_policy.denial(name, effective_capabilities)
        if denial is not None:
            return self._is_error(denial)

        try:
            payload = tool.handler(arguments, self.root)
        except ToolError as exc:
            return self._is_error(exc.message)
        except WardlineError as exc:
            # Bad config / unreadable path during a tool call: a tool-execution
            # error the agent must read and act on → isError result.
            return self._is_error(str(exc))
        except McpError:
            # A handler may DELIBERATELY raise McpError to signal a protocol fault;
            # that stays a JSON-RPC error (dispatch maps it), so let it propagate.
            raise
        except Exception as exc:  # noqa: BLE001
            # An UNEXPECTED crash deep in a handler (e.g. a KeyError/RecursionError from
            # the taint engine mid-scan) is a tool-EXECUTION error, not a protocol fault.
            # Surface it as an isError RESULT so the detail lands in the channel MCP
            # clients reliably relay, rather than a -32603 whose message they may drop.
            import sys
            import traceback

            traceback.print_exc(file=sys.stderr)
            return self._is_error(f"wardline internal error: {exc}")
        return {"content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}]}

    def _resources_list(self, params: dict[str, Any]) -> dict[str, Any]:
        return {"resources": list_resources()}

    def _resources_read(self, params: dict[str, Any]) -> dict[str, Any]:
        uri = params.get("uri")
        text, mime = read_resource(self.root, uri)
        return {"contents": [{"uri": uri, "mimeType": mime, "text": text}]}

    def _prompts_list(self, params: dict[str, Any]) -> dict[str, Any]:
        return {"prompts": list_prompts()}

    def _prompts_get(self, params: dict[str, Any]) -> dict[str, Any]:
        return get_prompt(params.get("name"))

    @staticmethod
    def _is_error(text: str) -> dict[str, Any]:
        return {"content": [{"type": "text", "text": text}], "isError": True}
