"""SP8: the Wardline MCP server — tools/resources/prompts wired to core/.

Stateless (no server-side session carried between calls). The read-only tools
(scan, explain_taint) are pure functions of (disk + config); fix, the suppression
tools (baseline, waiver_add), and judge --write mutate
project files on disk. Rooted at a project path (launch cwd by default)."""

from __future__ import annotations

import json
import time
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
from wardline.core.explain import explain_taint_result, explanation_from_context, explanation_to_dict
from wardline.core.filigree_emit import FiligreeEmitter, filigree_destination, filigree_disabled_reason
from wardline.core.finding import Finding, Severity
from wardline.core.finding_query import filter_findings
from wardline.core.judge_run import run_judge
from wardline.core.paths import baseline_path as baseline_file
from wardline.core.paths import waivers_path, weft_config_path
from wardline.core.run import baseline_migration_hint, gate_decision, run_scan
from wardline.core.scan_jobs import cancel_scan_job, read_scan_job_status, start_scan_job
from wardline.core.sei_resolution import resolve_query_filters
from wardline.core.waivers import add_waiver, load_project_waivers
from wardline.mcp.prompts import get_prompt, list_prompts
from wardline.mcp.protocol import _INVALID_PARAMS, JsonRpcServer, McpError
from wardline.mcp.resources import list_resources, read_resource
from wardline.mcp.tooling import Tool, ToolCapability, ToolError, ToolPolicy
from wardline.mcp.tooling import cfg as _cfg
from wardline.mcp.tooling import require as _require
from wardline.mcp.tooling import resolve_under_root as _resolve_under_root

# Gate thresholds are the four defect severities. Severity also defines NONE
# (the "facts carry no defect severity" sentinel), deliberately excluded here:
# fail_on=NONE is not a meaningful gate threshold.
_SEVERITY_ENUM = ["CRITICAL", "ERROR", "WARN", "INFO"]

# Default ceiling on the number of active-defect provenances inlined by `explain: true`
# on the MCP `scan`. Bounds the one-shot payload (the dogfood report hit 56,820 chars on
# one line over a whole repo); an explicit `max_findings` tightens it further.
_EXPLAIN_DEFAULT_CAP = 10
# The bounded-default page size for `scan` (weft-439d09fc8d). A bare scan returns at most
# this many finding bodies so an agent's first natural call cannot overflow its context;
# full=true lifts the cap and offset pages through the rest.
_DEFAULT_MAX_FINDINGS = 25


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
        # an actionable reason, not a flat "unreachable" (dogfood #5). token_sent + url further
        # split a 401 into no-token vs token-rejected, naming where it tried (C-7).
        "status": er.status,
        "auth_rejected": er.auth_rejected,
        "token_sent": er.token_sent,
        "url": er.url,
        # N1 / C-10(a): name where findings went so a wrong-project write is visible.
        "destination": filigree_destination(er.url),
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
            "destination": filigree_destination(None),
        }
    disabled_reason = filigree_disabled_reason(
        reachable=bool(block.get("reachable")),
        status=block.get("status"),
        token_sent=bool(block.get("token_sent")),
        url=block.get("url"),
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


_FILE_FINDING_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": "Success payload of the file_finding tool: the outcome of promoting ONE finding (by fingerprint) "
    "into a tracked Filigree issue, fail-soft on reachability.",
    "properties": {
        "reachable": {
            "type": "boolean",
            "description": "Whether Filigree's promote route was reachable. False on transport failure, 5xx outage, "
            "or 401/403 auth refusal (all soft).",
        },
        "issue_id": {
            "type": ["string", "null"],
            "description": "The Filigree issue id the fingerprint was promoted into; null when unreachable or the "
            "fingerprint was not found.",
        },
        "created": {
            "type": "boolean",
            "description": "True when the promote created a NEW issue (vs returning an existing one).",
        },
        "not_found": {
            "type": "boolean",
            "description": "True when Filigree was reachable but the fingerprint is unknown to it (404 — emit "
            "findings to Filigree first).",
        },
        "fingerprint": {"type": "string", "description": "The fingerprint that was filed (echoed from the request)."},
        "disabled_reason": {
            "type": ["string", "null"],
            "description": "Why enrichment was unavailable (e.g. 'filigree unreachable', 'filigree 503'); null on "
            "success.",
        },
        "identity_attach": {
            "type": "object",
            "description": "Present only when attach_loomweave_identity=true was requested: the outcome of binding "
            "the finding's Loomweave entity identity to the filed issue.",
            "properties": {
                "attempted": {
                    "type": "boolean",
                    "description": "Whether an identity attach was attempted at all (false when there is no issue_id "
                    "or no Loomweave URL configured).",
                },
                "attached": {
                    "type": "boolean",
                    "description": "Whether the entity association was successfully attached to the Filigree issue.",
                },
                "entity_id": {
                    "type": ["string", "null"],
                    "description": "The entity identifier used for the binding — a 'loomweave:eid:...' SEI or a "
                    "legacy '{plugin}:function:{qualname}' locator.",
                },
                "content_hash": {
                    "type": ["string", "null"],
                    "description": "The entity content hash captured at attach time (drift-detection anchor); null "
                    "when unresolved.",
                },
                "binding_kind": {
                    "type": ["string", "null"],
                    "enum": ["sei", "locator", None],
                    "description": "Whether the binding used a rename-stable SEI or a legacy locator; null when no "
                    "binding was attempted.",
                },
                "reason": {
                    "type": ["string", "null"],
                    "description": "Human-readable reason when not attempted or skipped; null on success.",
                },
            },
            "required": ["attempted", "attached", "entity_id", "content_hash", "binding_kind", "reason"],
            "additionalProperties": False,
        },
    },
    "required": ["reachable", "issue_id", "created", "not_found", "fingerprint", "disabled_reason"],
    "additionalProperties": False,
}


_FILE_FINDING_TOOL: dict[str, Any] = {
    "name": "file_finding",
    "title": "File finding as Filigree issue",
    "description": "File ONE finding (by `fingerprint`) into a tracked Filigree issue and "
    "return its `issue_id`. Idempotent (re-filing returns the same issue). Emit findings "
    "to Filigree first (scan with a configured Filigree URL) so the fingerprint is known; "
    "a `not_found: true` result means it isn't. Reconciliation (close-on-fixed / "
    "reopen-on-regress) happens automatically on later scans. Fail-soft.",
    "input_schema": {
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
    "output_schema": _FILE_FINDING_OUTPUT_SCHEMA,
    "annotations": {
        "title": "File finding as Filigree issue",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
    "capabilities": frozenset({ToolCapability.READ, ToolCapability.WRITE, ToolCapability.NETWORK}),
}


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


_SCAN_FILE_FINDINGS_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": "Success payload of the scan_file_findings tool: one-shot scan -> (optionally) emit findings to "
    "Filigree -> (optionally) promote selected active defects into tracked issues.",
    "properties": {
        "mode": {
            "type": "string",
            "enum": ["dry_run", "all_active", "fingerprints"],
            "description": "Selection mode that ran: dry_run (nothing promoted), all_active (every active defect "
            "selected), or fingerprints (explicit selection).",
        },
        "files_scanned": {"type": "integer", "description": "Number of files the scan analyzed."},
        "summary": {
            "type": "object",
            "description": "Finding counts by suppression class for the whole scan.",
            "properties": {
                "total": {"type": "integer", "description": "Every finding (defects + facts/metrics)."},
                "active": {"type": "integer", "description": "Non-suppressed defects."},
                "baselined": {"type": "integer", "description": "Defects suppressed by the baseline."},
                "waived": {"type": "integer", "description": "Defects suppressed by waivers."},
                "judged": {"type": "integer", "description": "Defects suppressed by judge FALSE_POSITIVE records."},
                "informational": {"type": "integer", "description": "Informational (non-gating) findings."},
                "unanalyzed": {
                    "type": "integer",
                    "description": "Files discovered but never analyzed (benign no-module skips excluded).",
                },
            },
            "required": ["total", "active", "baselined", "waived", "judged", "informational", "unanalyzed"],
            "additionalProperties": False,
        },
        "gate": {
            "type": "object",
            "description": "The pass/fail gate decision for this scan (a trip is data, not an error).",
            "properties": {
                "tripped": {"type": "boolean", "description": "Whether the gate tripped."},
                "fail_on": {
                    "type": ["string", "null"],
                    "description": "The severity threshold the gate evaluated (e.g. 'ERROR'); null when no threshold "
                    "was given.",
                },
                "exit_class": {
                    "type": "integer",
                    "description": "CLI-equivalent exit class: 0 clean, 1 gate tripped (2 is reserved for tool errors "
                    "and never appears here).",
                },
                "verdict": {
                    "type": "string",
                    "enum": ["NOT_EVALUATED", "PASSED", "FAILED"],
                    "description": "NOT_EVALUATED = no threshold ran; PASSED/FAILED = a threshold ran. Never reads a "
                    "bare scan as a clean pass.",
                },
                "would_trip_at": {
                    "type": ["string", "null"],
                    "description": "Highest severity at which the gate WOULD trip on the evaluated population; null "
                    "when nothing would trip.",
                },
            },
            "required": ["tripped", "fail_on", "exit_class", "verdict", "would_trip_at"],
            "additionalProperties": False,
        },
        "filigree_emit": {
            "type": "object",
            "description": "Outcome of bulk-emitting scan findings to Filigree (runs only when findings were selected "
            "and an emitter is configured).",
            "properties": {
                "configured": {
                    "type": "boolean",
                    "description": "Whether a Filigree emitter is configured for this server.",
                },
                "reachable": {
                    "type": ["boolean", "null"],
                    "description": "Whether Filigree was reachable for the emit; null when no emit was attempted.",
                },
                "created": {"type": "integer", "description": "Findings newly created in Filigree."},
                "updated": {"type": "integer", "description": "Findings updated in Filigree."},
                "failed": {"type": "integer", "description": "Findings Filigree rejected."},
                "warnings": {"type": "array", "items": {"type": "string"}, "description": "Non-fatal emit warnings."},
                "disabled_reason": {
                    "type": ["string", "null"],
                    "description": "Why the emit failed soft — the discriminated 401/403-vs-5xx-vs-transport "
                    "ladder ('not configured', 'filigree rejected the token (401)...', 'filigree unreachable'). "
                    "null means success OR no emit was attempted (dry-run / nothing selected) — read `reachable` "
                    "to tell them apart (null = no attempt).",
                },
            },
            "required": ["configured", "reachable", "created", "updated", "failed", "warnings", "disabled_reason"],
            "additionalProperties": False,
        },
        "active_defects": {
            "type": "array",
            "description": "Every active (non-suppressed) defect in the scan, each with its per-finding promotion and "
            "identity-attach outcome.",
            "items": {
                "type": "object",
                "properties": {
                    "fingerprint": {
                        "type": "string",
                        "description": "Stable finding fingerprint (the promotion join key).",
                    },
                    "rule_id": {"type": "string", "description": "Rule that produced the finding (e.g. PY-WL-101)."},
                    "severity": {
                        "type": "string",
                        "enum": ["CRITICAL", "ERROR", "WARN", "INFO", "NONE"],
                        "description": "Finding severity.",
                    },
                    "message": {"type": "string", "description": "Human-readable finding message."},
                    "qualname": {
                        "type": ["string", "null"],
                        "description": "Dotted module-qualified name of the enclosing callable; null when the finding "
                        "has no callable anchor.",
                    },
                    "path": {"type": "string", "description": "Repo-relative file path of the finding."},
                    "line": {"type": ["integer", "null"], "description": "1-based start line; null when unknown."},
                    "explanation": {
                        "type": "object",
                        "description": "One-hop taint provenance slice. Present only when the finding has a qualname "
                        "AND the scan produced an analysis context.",
                        "properties": {
                            "tier_in": {
                                "type": ["string", "null"],
                                "description": "Actual (untrusted) trust tier arriving at the sink.",
                            },
                            "tier_out": {
                                "type": ["string", "null"],
                                "description": "Trust tier the sink declares it returns.",
                            },
                            "immediate_tainted_callee": {
                                "type": ["string", "null"],
                                "description": "The directly-called function that contributed the taint, if resolved.",
                            },
                            "source_boundary_qualname": {
                                "type": ["string", "null"],
                                "description": "Qualname of the boundary function the taint originated from (one hop "
                                "only).",
                            },
                            "resolved_call_count": {
                                "type": "integer",
                                "description": "Calls inside the function the analyzer resolved.",
                            },
                            "unresolved_call_count": {
                                "type": "integer",
                                "description": "Calls the analyzer could not resolve.",
                            },
                        },
                        "required": [
                            "tier_in",
                            "tier_out",
                            "immediate_tainted_callee",
                            "source_boundary_qualname",
                            "resolved_call_count",
                            "unresolved_call_count",
                        ],
                        "additionalProperties": False,
                    },
                    "promotion": {
                        "type": "object",
                        "description": "Per-finding Filigree promote outcome for this defect.",
                        "properties": {
                            "selected": {
                                "type": "boolean",
                                "description": "Whether this finding was in the selection set.",
                            },
                            "attempted": {
                                "type": "boolean",
                                "description": "Whether a promote was actually attempted (false in dry_run, when "
                                "unselected, or when no filer is configured).",
                            },
                            "reachable": {
                                "type": ["boolean", "null"],
                                "description": "Whether Filigree was reachable for the promote; null when not "
                                "attempted.",
                            },
                            "issue_id": {
                                "type": ["string", "null"],
                                "description": "The Filigree issue id; null when not attempted, unreachable, or not "
                                "found.",
                            },
                            "created": {"type": "boolean", "description": "True when the promote created a NEW issue."},
                            "not_found": {
                                "type": "boolean",
                                "description": "True when Filigree was reachable but the fingerprint is unknown to it "
                                "(404).",
                            },
                            "disabled_reason": {
                                "type": ["string", "null"],
                                "description": "Why the promote did not happen or failed soft; null on success.",
                            },
                        },
                        "required": [
                            "selected",
                            "attempted",
                            "reachable",
                            "issue_id",
                            "created",
                            "not_found",
                            "disabled_reason",
                        ],
                        "additionalProperties": False,
                    },
                    "identity_attach": {
                        "type": "object",
                        "description": "Outcome of binding the finding's Loomweave entity identity to the promoted "
                        "issue.",
                        "properties": {
                            "attempted": {
                                "type": "boolean",
                                "description": "Whether an identity attach was attempted at all.",
                            },
                            "attached": {
                                "type": "boolean",
                                "description": "Whether the entity association was successfully attached.",
                            },
                            "entity_id": {
                                "type": ["string", "null"],
                                "description": "The entity identifier used — a 'loomweave:eid:...' SEI or a legacy "
                                "locator.",
                            },
                            "content_hash": {
                                "type": ["string", "null"],
                                "description": "Entity content hash captured at attach time; null when unresolved.",
                            },
                            "binding_kind": {
                                "type": ["string", "null"],
                                "enum": ["sei", "locator", None],
                                "description": "Whether the binding used a rename-stable SEI or a legacy locator; "
                                "null when no binding was attempted.",
                            },
                            "reason": {
                                "type": ["string", "null"],
                                "description": "Why the attach was not attempted or was skipped; null on success.",
                            },
                        },
                        "required": ["attempted", "attached", "entity_id", "content_hash", "binding_kind", "reason"],
                        "additionalProperties": False,
                    },
                },
                "required": [
                    "fingerprint",
                    "rule_id",
                    "severity",
                    "message",
                    "qualname",
                    "path",
                    "line",
                    "promotion",
                    "identity_attach",
                ],
                "additionalProperties": False,
            },
        },
        "selected_count": {
            "type": "integer",
            "description": "How many selected fingerprints matched known active defects.",
        },
        "unknown_fingerprints": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Explicitly-requested fingerprints that are not among the scan's active defects.",
        },
    },
    "required": [
        "mode",
        "files_scanned",
        "summary",
        "gate",
        "filigree_emit",
        "active_defects",
        "selected_count",
        "unknown_fingerprints",
    ],
    "additionalProperties": False,
}


_SCAN_FILE_FINDINGS_TOOL: dict[str, Any] = {
    "name": "scan_file_findings",
    "title": "Scan and file findings",
    "description": "One-shot agent workflow: run a scan, list active defects first with "
    "inline explanation summaries, optionally emit to Filigree, promote selected "
    "fingerprints or all active defects, and attach Loomweave identity when available. "
    "Defaults to dry-run unless fingerprints or all_active are supplied.",
    "input_schema": {
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
    "output_schema": _SCAN_FILE_FINDINGS_OUTPUT_SCHEMA,
    "annotations": {
        "title": "Scan and file findings",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
    "capabilities": frozenset({ToolCapability.READ, ToolCapability.WRITE, ToolCapability.NETWORK}),
}


def _trusted_packs_arg(args: dict[str, Any]) -> tuple[str, ...]:
    trusted_packs_raw = args.get("trust_packs") or []
    if not isinstance(trusted_packs_raw, list) or not all(isinstance(p, str) for p in trusted_packs_raw):
        raise ToolError("trust_packs must be an array of strings")
    return tuple(trusted_packs_raw)


def _cache_dir_arg(args: dict[str, Any], root: Path) -> Path | None:
    return _resolve_under_root(root, args["cache_dir"]) if args.get("cache_dir") else None


def _path_arg(args: dict[str, Any], root: Path) -> Path:
    return _resolve_under_root(root, args["path"]) if args.get("path") else root


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


def _scan_job_request(args: dict[str, Any], root: Path, filigree_url: str | None) -> dict[str, Any]:
    fail_on = args.get("fail_on")
    if fail_on is not None:
        try:
            Severity(str(fail_on))
        except ValueError as exc:
            raise ToolError("fail_on must be one of CRITICAL/ERROR/WARN/INFO") from exc
    lang = str(args.get("lang") or "python")
    if lang not in {"python", "rust"}:
        raise ToolError("lang must be one of python/rust")
    fmt = str(args.get("format") or "jsonl")
    if fmt not in {"jsonl", "sarif", "agent-summary"}:
        raise ToolError("format must be one of jsonl/sarif/agent-summary")
    local_only = _bool_arg(args, "local_only", False)
    trusted_packs = _trusted_packs_arg(args)
    output = _resolve_under_root(root, args["output"]) if args.get("output") else None
    config = _cfg(args, root)
    cache_dir = _cache_dir_arg(args, root)
    return {
        "config": str(config) if config is not None else None,
        "format": fmt,
        "output": str(output) if output is not None else None,
        "fail_on": str(fail_on).upper() if fail_on else None,
        "fail_on_unanalyzed": _bool_arg(args, "fail_on_unanalyzed", False),
        "cache_dir": str(cache_dir) if cache_dir is not None else None,
        "filigree_url": None if local_only else filigree_url,
        "local_only": local_only,
        "filigree_max_findings_per_request": args.get("filigree_max_findings_per_request"),
        "timeout_seconds": args.get("timeout_seconds"),
        "lang": lang,
        "new_since": args.get("new_since"),
        "trusted_packs": list(trusted_packs),
        "trust_local_packs": _bool_arg(args, "trust_local_packs", False),
        "strict_defaults": _bool_arg(args, "strict_defaults", False),
        "trust_suppressions": _bool_arg(args, "trust_suppressions", False),
    }


def _scan_job_start(args: dict[str, Any], root: Path, filigree_url: str | None = None) -> dict[str, Any]:
    path = _path_arg(args, root)
    request = _scan_job_request(args, root, filigree_url)
    return start_scan_job(path, request)


def _scan_job_status(args: dict[str, Any], root: Path) -> dict[str, Any]:
    job_id = str(_require(args, "job_id"))
    return read_scan_job_status(_path_arg(args, root), job_id)


def _scan_job_cancel(args: dict[str, Any], root: Path) -> dict[str, Any]:
    job_id = str(_require(args, "job_id"))
    return cancel_scan_job(_path_arg(args, root), job_id)


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
    # A4 (wardline-7fd0f3a82c): the CLI's --fail-on-unanalyzed knob, same default (off).
    fail_on_unanalyzed = _bool_arg(args, "fail_on_unanalyzed", False)
    new_since = args.get("new_since")
    trusted_packs = _trusted_packs_arg(args)
    cache_dir = _cache_dir_arg(args, root)
    trust_suppressions = bool(args.get("trust_suppressions") or False)
    # A1 (wardline-2ee1bbda82): the same frontend selector the CLI's --lang exposes.
    # A bad value is run_scan's ConfigError (names the valid set) -> isError result.
    lang = args.get("lang") or "python"
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
        lang=lang,
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
    decision = gate_decision(result, threshold, fail_on_unanalyzed=fail_on_unanalyzed)
    migration_hint = baseline_migration_hint(result, decision, root=path, new_since=new_since)
    filigree_block = _emit_filigree(result.findings, filigree, scanned_paths=result.scanned_paths)
    filigree_status = _filigree_emit_status(filigree_block)
    loomweave_status = _loomweave_write_status(loomweave_block)
    where = args.get("where")
    try:
        resolved_where = resolve_query_filters(
            where,
            root,
            _cfg(args, root),
            loomweave,
            strict_defaults=strict_defaults,
        )
        selected = filter_findings(result.findings, resolved_where)
    except (ValueError, WardlineError) as exc:
        # An unknown filter key or SEI resolution failure is agent-actionable -> isError result.
        raise ToolError(str(exc)) from exc

    # Payload-shrinking controls. The `summary`/`gate` blocks always describe the WHOLE
    # project; these only bound the returned finding BODIES (which live solely in
    # agent_summary now — there is no separate top-level findings array). The DEFAULT scan is
    # BOUNDED (weft-439d09fc8d): a bare call returns at most _DEFAULT_MAX_FINDINGS bodies so
    # an agent's first natural call cannot overflow its own context. full=true lifts the cap;
    # offset pages through the rest via truncation.next_offset.
    summary_only = _bool_arg(args, "summary_only", False)
    include_suppressed = _bool_arg(args, "include_suppressed", True)
    full = _bool_arg(args, "full", False)
    max_findings = args.get("max_findings")
    if max_findings is not None and (
        not isinstance(max_findings, int) or isinstance(max_findings, bool) or max_findings < 0
    ):
        raise ToolError("max_findings must be a non-negative integer")
    offset = args.get("offset", 0)
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise ToolError("offset must be a non-negative integer")
    explain = _bool_arg(args, "explain", False)

    # Effective page size: full=true → uncapped; explicit max_findings → that; else the
    # bounded default. summary_only short-circuits to no bodies inside agent_summary.
    if full:
        limit: int | None = None
    elif max_findings is not None:
        limit = max_findings
    else:
        limit = _DEFAULT_MAX_FINDINGS

    from wardline.core.agent_summary import build_agent_summary

    agent_summary = build_agent_summary(
        result,
        decision,
        filigree_emit=filigree_status,
        loomweave_write=loomweave_status,
        display_findings=selected,
        summary_only=summary_only,
        max_findings=limit,
        offset=offset,
        include_suppressed=include_suppressed,
        migration_hint=migration_hint,
    ).to_dict()

    # explain inlines each SHOWN active defect's provenance into its agent_summary entry (one
    # call instead of an explain_taint per finding). Capped — inlining EVERY provenance is the
    # 56KB-on-one-line blowup the dogfood report hit; the cut is announced in truncation.
    if explain and result.context is not None:
        explain_cap = max_findings if max_findings is not None else _EXPLAIN_DEFAULT_CAP
        by_fp = {f.fingerprint: f for f in selected}
        attached = 0
        explanations_truncated = False
        for entry in agent_summary["active_defects"]:
            f = by_fp.get(entry["fingerprint"])
            if f is None or f.qualname is None:
                continue
            if attached < explain_cap:
                entry["explanation"] = explanation_to_dict(
                    explanation_from_context(f, result.context), loomweave_configured=loomweave is not None
                )
                attached += 1
            else:
                explanations_truncated = True
        agent_summary["truncation"]["explanations_truncated"] = explanations_truncated

    response: dict[str, Any] = {
        "files_scanned": result.files_scanned,
        "summary": {
            "total": result.summary.total,
            "active": result.summary.active,
            "baselined": result.summary.baselined,
            "waived": result.summary.waived,
            "judged": result.summary.judged,
            # Non-defect findings (facts/metrics/classifications). active+baselined+
            # waived+judged+informational == total (the buckets-sum-to-total invariant,
            # weft-f506e5f845); unanalyzed is an overlay (subset of informational), not a
            # partition member.
            "informational": result.summary.informational,
            # Files discovered but NOT analysed (parse error / too-deep / missing
            # source root — benign no-module skips are excluded). Surfaced so the
            # silent under-scan reaches the agent, not just the human-facing stderr.
            "unanalyzed": result.summary.unanalyzed,
        },
        "gate": {
            "tripped": decision.tripped,
            "fail_on": decision.fail_on,
            "fail_on_unanalyzed": decision.fail_on_unanalyzed,
            "exit_class": decision.exit_class,
            "verdict": decision.verdict,
            # Sub-gate attribution: which knob(s) the overall trip came from, so an agent
            # never has to parse `reason` to tell a severity trip from an unanalyzed one.
            "severity_tripped": decision.severity_tripped,
            "unanalyzed_tripped": decision.unanalyzed_tripped,
            "would_trip_at": decision.would_trip_at,
            "reason": decision.reason,
            "evaluated": decision.evaluated,
            "migration_hint": migration_hint,
        },
        "loomweave": loomweave_block,
        "filigree": filigree_block,
        "loomweave_write": loomweave_status,
        "filigree_emit": filigree_status,
        "agent_summary": agent_summary,
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


_SCAN_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": "Success payload of the wardline MCP `scan` tool (the dict _scan returns, served verbatim as "
    "structuredContent).",
    "properties": {
        "files_scanned": {"type": "integer", "description": "Number of files discovered and handed to the analyzer."},
        "summary": {
            "type": "object",
            "description": "Whole-project finding counts. active+baselined+waived+judged+informational == total; "
            "unanalyzed is an overlay, not a partition member.",
            "properties": {
                "total": {"type": "integer", "description": "Every finding (defects + facts/metrics)."},
                "active": {"type": "integer", "description": "Non-suppressed defects."},
                "baselined": {"type": "integer"},
                "waived": {"type": "integer"},
                "judged": {"type": "integer"},
                "informational": {
                    "type": "integer",
                    "description": "All non-defect findings (facts, metrics, classifications).",
                },
                "unanalyzed": {
                    "type": "integer",
                    "description": "Files discovered but never analysed (parse errors / too-deep / missing source "
                    "roots); overlay count.",
                },
            },
            "required": ["total", "active", "baselined", "waived", "judged", "informational", "unanalyzed"],
            "additionalProperties": False,
        },
        "gate": {
            "type": "object",
            "description": "The pass/fail gate decision (a trip is data, not an error).",
            "properties": {
                "tripped": {"type": "boolean"},
                "fail_on": {
                    "description": "The severity threshold evaluated, or null when no --fail-on ran.",
                    "enum": ["CRITICAL", "ERROR", "WARN", "INFO", "NONE", None],
                },
                "fail_on_unanalyzed": {
                    "type": "boolean",
                    "description": "Whether the unanalyzed sub-gate knob was set.",
                },
                "exit_class": {
                    "type": "integer",
                    "enum": [0, 1],
                    "description": "0 clean, 1 gate tripped (mirrors tripped).",
                },
                "verdict": {
                    "type": "string",
                    "enum": ["NOT_EVALUATED", "PASSED", "FAILED"],
                    "description": "NOT_EVALUATED when neither sub-gate was configured; FAILED iff tripped.",
                },
                "severity_tripped": {
                    "type": "boolean",
                    "description": "Sub-gate attribution: the severity threshold tripped.",
                },
                "unanalyzed_tripped": {
                    "type": "boolean",
                    "description": "Sub-gate attribution: the unanalyzed gate tripped.",
                },
                "would_trip_at": {
                    "description": "Highest severity at which the gate WOULD trip on the evaluated population, or "
                    "null if nothing would.",
                    "enum": ["CRITICAL", "ERROR", "WARN", "INFO", None],
                },
                "reason": {
                    "type": "string",
                    "description": "Human-readable verdict naming the count/class of defects that decided it.",
                },
                "evaluated": {
                    "type": ["string", "null"],
                    "description": "Which population the gate judged (unsuppressed default vs suppression-honoring).",
                },
                "migration_hint": {
                    "type": ["string", "null"],
                    "description": "Secure-gate-default rollout hint, or null.",
                },
            },
            "required": [
                "tripped",
                "fail_on",
                "fail_on_unanalyzed",
                "exit_class",
                "verdict",
                "severity_tripped",
                "unanalyzed_tripped",
                "would_trip_at",
                "reason",
                "evaluated",
                "migration_hint",
            ],
            "additionalProperties": False,
        },
        "loomweave": {
            "description": "Raw Loomweave taint-fact write result; null when no Loomweave client is configured.",
            "oneOf": [
                {"type": "null"},
                {
                    "type": "object",
                    "properties": {
                        "reachable": {"type": "boolean"},
                        "written": {"type": "integer", "description": "Entity taint blobs written."},
                        "unresolved_qualnames": {"type": "array", "items": {"type": "string"}},
                        "disabled_reason": {"type": ["string", "null"]},
                    },
                    "required": ["reachable", "written", "unresolved_qualnames", "disabled_reason"],
                    "additionalProperties": False,
                },
            ],
        },
        "filigree": {
            "description": "Raw Filigree emit result; null when no emitter is configured.",
            "oneOf": [
                {"type": "null"},
                {
                    "type": "object",
                    "properties": {
                        "reachable": {"type": "boolean"},
                        "created": {"type": "integer"},
                        "updated": {"type": "integer"},
                        "failed": {"type": "integer"},
                        "warnings": {"type": "array", "items": {"type": "string"}},
                        "status": {
                            "type": ["integer", "null"],
                            "description": "HTTP error status (401/403/5xx) for soft failures; null on success or "
                            "transport failure.",
                        },
                        "auth_rejected": {
                            "type": "boolean",
                            "description": "True when the emit was refused with 401/403.",
                        },
                        "token_sent": {
                            "type": "boolean",
                            "description": "Whether a bearer token was actually sent (splits a 401 into absent vs "
                            "rejected).",
                        },
                        "url": {"type": ["string", "null"], "description": "The endpoint attempted."},
                        "destination": {"$ref": "#/$defs/filigree_destination"},
                    },
                    "required": [
                        "reachable",
                        "created",
                        "updated",
                        "failed",
                        "warnings",
                        "status",
                        "auth_rejected",
                        "token_sent",
                        "url",
                        "destination",
                    ],
                    "additionalProperties": False,
                },
            ],
        },
        "loomweave_write": {"$ref": "#/$defs/loomweave_write_status"},
        "filigree_emit": {"$ref": "#/$defs/filigree_emit_status"},
        "agent_summary": {
            "type": "object",
            "description": "The stable agent-oriented handoff block (schema wardline-agent-summary-1): active defects "
            "first, suppressed debt visible, integration status explicit, suggested next tool calls.",
            "properties": {
                "schema": {"type": "string", "enum": ["wardline-agent-summary-1"]},
                "summary": {
                    "type": "object",
                    "description": "Whole-project counts (never affected by where/pagination filters).",
                    "properties": {
                        "files_scanned": {"type": "integer"},
                        "total_findings": {"type": "integer"},
                        "active_defects": {"type": "integer"},
                        "suppressed_findings": {"type": "integer"},
                        "engine_facts": {
                            "type": "integer",
                            "description": "Kind.FACT findings with a WLN-ENGINE-* rule_id.",
                        },
                        "baselined": {"type": "integer"},
                        "waived": {"type": "integer"},
                        "judged": {"type": "integer"},
                        "informational": {
                            "type": "integer",
                            "description": "ALL non-defect findings (engine facts included; the display array below "
                            "excludes them).",
                        },
                        "unanalyzed": {"type": "integer"},
                    },
                    "required": [
                        "files_scanned",
                        "total_findings",
                        "active_defects",
                        "suppressed_findings",
                        "engine_facts",
                        "baselined",
                        "waived",
                        "judged",
                        "informational",
                        "unanalyzed",
                    ],
                    "additionalProperties": False,
                },
                "gate": {
                    "type": "object",
                    "description": "Gate echo inside the agent summary (no sub-gate attribution flags here; see the "
                    "top-level gate block for those).",
                    "properties": {
                        "tripped": {"type": "boolean"},
                        "fail_on": {"enum": ["CRITICAL", "ERROR", "WARN", "INFO", "NONE", None]},
                        "exit_class": {"type": "integer", "enum": [0, 1]},
                        "verdict": {"type": "string", "enum": ["NOT_EVALUATED", "PASSED", "FAILED"]},
                        "would_trip_at": {"enum": ["CRITICAL", "ERROR", "WARN", "INFO", None]},
                        "reason": {"type": "string"},
                        "evaluated": {"type": ["string", "null"]},
                        "migration_hint": {"type": ["string", "null"]},
                    },
                    "required": [
                        "tripped",
                        "fail_on",
                        "exit_class",
                        "verdict",
                        "would_trip_at",
                        "reason",
                        "evaluated",
                        "migration_hint",
                    ],
                    "additionalProperties": False,
                },
                "integrations": {
                    "type": "object",
                    "properties": {
                        "filigree_emit": {"$ref": "#/$defs/filigree_emit_status"},
                        "loomweave_write": {"$ref": "#/$defs/loomweave_write_status"},
                    },
                    "required": ["filigree_emit", "loomweave_write"],
                    "additionalProperties": False,
                },
                "active_defects": {
                    "type": "array",
                    "description": "Non-suppressed defects in the displayed page (severity-sorted). Each entry "
                    "carries explain/next_tool_calls hints; with explain:true an inlined explanation (capped — see "
                    "truncation.explanations_truncated).",
                    "items": {"$ref": "#/$defs/active_defect_entry"},
                },
                "suppressed_findings": {
                    "type": "array",
                    "description": "Suppressed (baselined/waived/judged) defects in the displayed page.",
                    "items": {"$ref": "#/$defs/finding_entry"},
                },
                "engine_facts": {
                    "type": "array",
                    "description": "Engine diagnostic facts (WLN-ENGINE-*) in the displayed page.",
                    "items": {"$ref": "#/$defs/finding_entry"},
                },
                "informational": {
                    "type": "array",
                    "description": "Non-defect, non-engine-fact findings (metrics, classifications, suggestions) in "
                    "the displayed page.",
                    "items": {"$ref": "#/$defs/finding_entry"},
                },
                "truncation": {
                    "type": "object",
                    "description": "Single pagination descriptor for the four display arrays (one ordered union: "
                    "active, suppressed, engine facts, informational).",
                    "properties": {
                        "summary_only": {"type": "boolean"},
                        "include_suppressed": {"type": "boolean"},
                        "max_findings": {
                            "type": ["integer", "null"],
                            "description": "Effective page size; null means uncapped (full:true).",
                        },
                        "offset": {"type": "integer"},
                        "findings_total": {
                            "type": "integer",
                            "description": "Size of the displayed union before paging.",
                        },
                        "findings_returned": {"type": "integer"},
                        "next_offset": {
                            "type": ["integer", "null"],
                            "description": "Pass as offset to fetch the next page; null when complete.",
                        },
                        "findings_truncated": {"type": "boolean"},
                        "explanations_truncated": {
                            "type": "boolean",
                            "description": "True when explain:true hit the inlining cap before covering every shown "
                            "active defect.",
                        },
                    },
                    "required": [
                        "summary_only",
                        "include_suppressed",
                        "max_findings",
                        "offset",
                        "findings_total",
                        "findings_returned",
                        "next_offset",
                        "findings_truncated",
                        "explanations_truncated",
                    ],
                    "additionalProperties": False,
                },
                "next_actions": {
                    "type": "array",
                    "description": "Gate-aware suggested next tool calls, driven by the whole-project active count "
                    "(not the displayed slice).",
                    "items": {
                        "type": "object",
                        "properties": {
                            "tool": {"type": "string", "enum": ["explain_taint", "file_finding", "scan"]},
                            "reason": {"type": "string"},
                        },
                        "required": ["tool", "reason"],
                        "additionalProperties": False,
                    },
                },
            },
            "required": [
                "schema",
                "summary",
                "gate",
                "integrations",
                "active_defects",
                "suppressed_findings",
                "engine_facts",
                "informational",
                "truncation",
                "next_actions",
            ],
            "additionalProperties": False,
        },
        "legis_artifact": {
            "type": "object",
            "description": "OPTIONAL: the verbatim-postable signed scan object for legis POST /wardline/scan-results. "
            "Present only when a WARDLINE_LEGIS_ARTIFACT_KEY is provisioned or legis_artifact:true was passed, AND "
            "building it did not fail (a signing refusal omits it). Suppressed under summary_only:true unless "
            "legis_artifact:true is passed explicitly — summary_only promises the smallest gate payload.",
            "properties": {
                "scanner_identity": {"type": "string", "description": "wardline@<version>."},
                "rule_set_version": {"type": "string", "description": "Hash of the effective ruleset."},
                "fingerprint_scheme": {"type": "string"},
                "findings": {
                    "type": "array",
                    "description": "The gate population projected onto legis's accepted vocabulary.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "rule_id": {"type": "string"},
                            "message": {"type": "string"},
                            "severity": {"type": "string", "enum": ["CRITICAL", "ERROR", "WARN", "INFO", "NONE"]},
                            "kind": {
                                "type": "string",
                                "enum": ["defect", "fact", "classification", "metric", "suggestion"],
                            },
                            "fingerprint": {"type": "string"},
                            "qualname": {"type": ["string", "null"]},
                            "properties": {
                                "type": "object",
                                "description": "Trust-tier-valued properties only (plus suppression_reason proof on "
                                "non-active defects); diagnostics dropped.",
                                "additionalProperties": {"type": "string"},
                            },
                            "suppression_state": {"type": "string", "enum": ["active", "waived", "suppressed"]},
                        },
                        "required": [
                            "rule_id",
                            "message",
                            "severity",
                            "kind",
                            "fingerprint",
                            "qualname",
                            "properties",
                            "suppression_state",
                        ],
                        "additionalProperties": False,
                    },
                },
                "scan_scope": {
                    "type": "object",
                    "description": (
                        "Signed scope binding: scan root, configured/resolved source roots, and realized files."
                    ),
                    "properties": {
                        "schema": {"type": "string", "enum": ["wardline-legis-scan-scope-1"]},
                        "scan_root": {
                            "type": "string",
                            "description": "Scan root relative to the git repository root when in git; otherwise '.'.",
                        },
                        "is_git_root": {
                            "type": "boolean",
                            "description": "True only when the scan root is the containing git repository root.",
                        },
                        "source_roots": {"type": "array", "items": {"type": "string"}},
                        "resolved_source_roots": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Configured source roots resolved relative to the signed scope base.",
                        },
                        "scanned_paths": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Files actually discovered and analyzed, relative to the scan root.",
                        },
                    },
                    "required": [
                        "schema",
                        "scan_root",
                        "is_git_root",
                        "source_roots",
                        "resolved_source_roots",
                        "scanned_paths",
                    ],
                    "additionalProperties": False,
                },
                "commit_sha": {
                    "type": "string",
                    "description": "Present when provenance was readable (always on the signed path).",
                },
                "tree_sha": {
                    "type": "string",
                    "description": "Committed tree SHA; present on the signed path and best-effort otherwise.",
                },
                "artifact_signature": {
                    "type": "string",
                    "description": "hmac-sha256:v2:<hex> over the canonical scan-minus-signature; present only on the "
                    "signed (key + clean tree) path.",
                },
                "dirty": {
                    "type": "boolean",
                    "description": "Present (true) only when the working tree was dirty (unsigned dev artifact).",
                },
            },
            "required": ["scanner_identity", "rule_set_version", "fingerprint_scheme", "findings", "scan_scope"],
            "additionalProperties": False,
        },
        "legis_artifact_status": {
            "type": "object",
            "description": "OPTIONAL: signed/dirty status of the legis artifact attempt. Present whenever the legis "
            "block was activated (key provisioned or legis_artifact:true), including when signing was refused and "
            "legis_artifact itself is absent.",
            "properties": {
                "configured": {"type": "boolean", "enum": [True]},
                "signed": {"type": "boolean"},
                "key_id": {
                    "type": ["string", "null"],
                    "description": "Non-secret short id of the HMAC key (first 8 hex of sha256), or null when unkeyed.",
                },
                "reason": {
                    "type": ["string", "null"],
                    "description": "Refusal/unverified reason (e.g. dirty-tree refusal), or null.",
                },
                "dirty": {
                    "type": "boolean",
                    "description": "Present only when the artifact was actually built (absent on a build refusal).",
                },
            },
            "required": ["configured", "signed", "key_id", "reason"],
            "additionalProperties": False,
        },
    },
    "required": [
        "files_scanned",
        "summary",
        "gate",
        "loomweave",
        "filigree",
        "loomweave_write",
        "filigree_emit",
        "agent_summary",
    ],
    "additionalProperties": False,
    "$defs": {
        "filigree_destination": {
            "type": "object",
            "description": "Where findings were (or would be) sent, so a wrong-project write is visible.",
            "properties": {
                "url": {"type": ["string", "null"]},
                "project": {
                    "type": ["string", "null"],
                    "description": "The project pinned in the URL, or null when Filigree resolves it server-side.",
                },
                "project_pinned": {"type": "boolean"},
            },
            "required": ["url", "project", "project_pinned"],
            "additionalProperties": False,
        },
        "filigree_emit_status": {
            "type": "object",
            "description": "Normalized Filigree emit status (always an object; configured:false when no emitter).",
            "properties": {
                "configured": {"type": "boolean"},
                "reachable": {"type": ["boolean", "null"], "description": "null when not configured."},
                "created": {"type": "integer"},
                "updated": {"type": "integer"},
                "failed": {"type": "integer"},
                "warnings": {"type": "array", "items": {"type": "string"}},
                "disabled_reason": {
                    "type": ["string", "null"],
                    "description": "Actionable reason (auth-rejected vs server error vs unreachable vs not "
                    "configured), or null when reached.",
                },
                "destination": {"$ref": "#/$defs/filigree_destination"},
                "status": {
                    "type": ["integer", "null"],
                    "description": "HTTP error status for soft failures; absent when not configured.",
                },
                "auth_rejected": {"type": "boolean", "description": "Absent when not configured."},
                "token_sent": {"type": "boolean", "description": "Absent when not configured."},
                "url": {"type": ["string", "null"], "description": "Absent when not configured."},
            },
            "required": [
                "configured",
                "reachable",
                "created",
                "updated",
                "failed",
                "warnings",
                "disabled_reason",
                "destination",
            ],
            "additionalProperties": False,
        },
        "loomweave_write_status": {
            "type": "object",
            "description": "Normalized Loomweave taint-fact write status (always an object; configured:false when no "
            "client).",
            "properties": {
                "configured": {"type": "boolean"},
                "reachable": {"type": ["boolean", "null"], "description": "null when not configured."},
                "written": {"type": "integer"},
                "unresolved_qualnames": {"type": "array", "items": {"type": "string"}},
                "disabled_reason": {"type": ["string", "null"]},
            },
            "required": ["configured", "reachable", "written", "unresolved_qualnames", "disabled_reason"],
            "additionalProperties": False,
        },
        "location": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Repo-relative POSIX path."},
                "line_start": {"type": ["integer", "null"]},
                "line_end": {"type": ["integer", "null"]},
            },
            "required": ["path", "line_start", "line_end"],
            "additionalProperties": False,
        },
        "finding_entry": {
            "type": "object",
            "description": "One finding (suppressed / engine-fact / informational display arrays).",
            "properties": {
                "fingerprint": {"type": "string"},
                "rule_id": {"type": "string"},
                "severity": {"type": "string", "enum": ["CRITICAL", "ERROR", "WARN", "INFO", "NONE"]},
                "kind": {"type": "string", "enum": ["defect", "fact", "classification", "metric", "suggestion"]},
                "qualname": {"type": ["string", "null"]},
                "location": {"$ref": "#/$defs/location"},
                "message": {"type": "string"},
                "suppression_state": {"type": "string", "enum": ["active", "baselined", "waived", "judged"]},
                "suppression_reason": {"type": ["string", "null"]},
            },
            "required": [
                "fingerprint",
                "rule_id",
                "severity",
                "kind",
                "qualname",
                "location",
                "message",
                "suppression_state",
                "suppression_reason",
            ],
            "additionalProperties": False,
        },
        "active_defect_entry": {
            "type": "object",
            "description": "One active defect, with explain availability and suggested next tool calls; explanation "
            "is inlined only under scan(explain:true) for findings with a qualname, up to the cap.",
            "properties": {
                "fingerprint": {"type": "string"},
                "rule_id": {"type": "string"},
                "severity": {"type": "string", "enum": ["CRITICAL", "ERROR", "WARN", "INFO", "NONE"]},
                "kind": {"type": "string", "enum": ["defect", "fact", "classification", "metric", "suggestion"]},
                "qualname": {"type": ["string", "null"]},
                "location": {"$ref": "#/$defs/location"},
                "message": {"type": "string"},
                "suppression_state": {"type": "string", "enum": ["active", "baselined", "waived", "judged"]},
                "suppression_reason": {"type": ["string", "null"]},
                "explain": {
                    "type": "object",
                    "properties": {
                        "available": {"type": "boolean"},
                        "reason": {
                            "type": ["string", "null"],
                            "description": "Why explain is unavailable (no qualname), or null.",
                        },
                        "suggested_call": {
                            "oneOf": [
                                {"type": "null"},
                                {
                                    "type": "object",
                                    "properties": {
                                        "tool": {"type": "string", "enum": ["explain_taint"]},
                                        "arguments": {
                                            "type": "object",
                                            "properties": {"fingerprint": {"type": "string"}},
                                            "required": ["fingerprint"],
                                            "additionalProperties": False,
                                        },
                                    },
                                    "required": ["tool", "arguments"],
                                    "additionalProperties": False,
                                },
                            ],
                        },
                    },
                    "required": ["available", "reason", "suggested_call"],
                    "additionalProperties": False,
                },
                "next_tool_calls": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "tool": {"type": "string", "enum": ["explain_taint", "file_finding"]},
                            "arguments": {
                                "type": "object",
                                "properties": {"fingerprint": {"type": "string"}},
                                "required": ["fingerprint"],
                                "additionalProperties": False,
                            },
                        },
                        "required": ["tool", "arguments"],
                        "additionalProperties": False,
                    },
                },
                "explanation": {"$ref": "#/$defs/explanation"},
            },
            "required": [
                "fingerprint",
                "rule_id",
                "severity",
                "kind",
                "qualname",
                "location",
                "message",
                "suppression_state",
                "suppression_reason",
                "explain",
                "next_tool_calls",
            ],
            "additionalProperties": False,
        },
        "explanation": {
            "type": "object",
            "description": "Inlined taint provenance (same shape as the explanation slice of explain_taint).",
            "properties": {
                "tier_in": {"type": ["string", "null"], "description": "Actual (untrusted) tier arriving at the sink."},
                "tier_out": {"type": ["string", "null"], "description": "Tier the sink declares it returns."},
                "immediate_tainted_callee": {"type": ["string", "null"]},
                "source_boundary_qualname": {"type": ["string", "null"]},
                "source_resolution": {
                    "type": "object",
                    "description": "C-10(c) honesty block: explicit resolved/unresolved verdict on the taint source, "
                    "with reason + missing capability + enablement when unresolved.",
                    "properties": {
                        "status": {"type": "string", "enum": ["resolved", "unresolved"]},
                        "reason": {"type": ["string", "null"]},
                        "missing_capability": {"type": ["string", "null"]},
                        "enablement": {"type": ["string", "null"]},
                    },
                    "required": ["status", "reason", "missing_capability", "enablement"],
                    "additionalProperties": False,
                },
                "resolved_call_count": {"type": "integer"},
                "unresolved_call_count": {"type": "integer"},
                "remediation": {
                    "type": "object",
                    "properties": {
                        "kind": {"type": "string", "enum": ["boundary_placement", "sink_hygiene", "review_required"]},
                        "rule_id": {"type": "string"},
                        "summary": {"type": "string"},
                        "sink_qualname": {"type": ["string", "null"]},
                        "source_qualname": {"type": ["string", "null"]},
                        "caveat": {"type": "string"},
                    },
                    "required": ["kind", "rule_id", "summary", "sink_qualname", "source_qualname", "caveat"],
                    "additionalProperties": False,
                },
            },
            "required": [
                "tier_in",
                "tier_out",
                "immediate_tainted_callee",
                "source_boundary_qualname",
                "source_resolution",
                "resolved_call_count",
                "unresolved_call_count",
                "remediation",
            ],
            "additionalProperties": False,
        },
    },
}


_SCAN_TOOL: dict[str, Any] = {
    "name": "scan",
    "title": "Trust-boundary scan",
    "description": "Whole-program taint scan of the project. Returns structured "
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
    "input_schema": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "subdir relative to project root"},
            "fail_on": {"type": "string", "enum": _SEVERITY_ENUM},
            "fail_on_unanalyzed": {
                "type": "boolean",
                "description": "Also trip the gate when any file was discovered but could "
                "not be analyzed (parse error / too-deep skip / missing source root; benign "
                "no-module skips excluded). Default false — same default as the CLI's "
                "--fail-on-unanalyzed; summary.unanalyzed always reports the count either "
                "way, and gate.unanalyzed_tripped attributes a trip to this knob.",
            },
            "config": {"type": "string"},
            "lang": {
                "type": "string",
                "enum": ["python", "rust"],
                "description": "Language frontend (default python). 'rust' sweeps .rs files "
                "for the command-injection slice (RS-WL-108 program injection / RS-WL-112 "
                "shell injection; frozen identity, baseline-eligible). Preview posture: "
                "weft.toml severity overrides do not yet apply to Rust findings, and a tree "
                "with no /// @trusted markers is vacuously green — read the WLN-RUST-COVERAGE "
                "fact before trusting '0 active'. Requires the wardline[rust] extra.",
            },
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
                "is reported at agent_summary.truncation.explanations_truncated.",
            },
            "summary_only": {
                "type": "boolean",
                "description": "Return counts + gate only, no finding bodies — the smallest "
                "'did the gate pass?' payload. summary/gate still describe the whole project.",
            },
            "full": {
                "type": "boolean",
                "description": "Default false. The default scan is BOUNDED (≤25 finding bodies) so "
                "it cannot overflow your context; set full=true to return ALL bodies in one call "
                "(or page with offset). summary/gate counts are always whole-project.",
            },
            "max_findings": {
                "type": "integer",
                "minimum": 0,
                "description": "Override the page size for returned finding bodies (and the inlined-"
                "explanation cap). Default 25; full=true ignores it. Must be a non-negative integer. "
                "The cut + next page are reported in agent_summary.truncation; counts stay whole.",
            },
            "offset": {
                "type": "integer",
                "minimum": 0,
                "description": "Pagination cursor into the ordered finding union (active → suppressed "
                "→ engine_facts → informational). Pass agent_summary.truncation.next_offset from "
                "the previous call to fetch the next page. Default 0.",
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
                "description": "Ignore repository-supplied custom configuration overrides (weft.toml)",
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
    "output_schema": _SCAN_OUTPUT_SCHEMA,
    "annotations": {
        "title": "Trust-boundary scan",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
}


_SCAN_JOB_STATUS_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": "File-backed scan-job status. Non-terminal jobs include heartbeat/pid/progress; terminal jobs "
    "include summary/gate/artifacts when the worker reached them.",
    "properties": {
        "job_id": {"type": "string"},
        "status": {
            "type": "string",
            "enum": [
                "queued",
                "running",
                "running_stale",
                "completed",
                "completed_with_enrichment_failure",
                "failed",
                "cancelled",
            ],
        },
        "phase": {"type": "string"},
        "progress": {"type": "object"},
        "heartbeat": {"type": "string"},
        "pid": {"type": "integer"},
        "artifacts": {"type": "object"},
        "failure_kind": {"type": ["string", "null"]},
        "error": {"type": ["string", "null"]},
        "request": {"type": "object"},
    },
    "required": ["job_id", "status", "phase", "progress", "heartbeat", "artifacts", "failure_kind", "error", "request"],
    "additionalProperties": True,
}


_SCAN_JOB_START_INPUT_PROPERTIES: dict[str, Any] = {
    "path": {"type": "string", "description": "scan root subdir relative to the MCP server project root"},
    "config": {"type": "string", "description": "config file relative to project root"},
    "format": {"type": "string", "enum": ["jsonl", "sarif", "agent-summary"], "description": "artifact format"},
    "output": {"type": "string", "description": "artifact output path relative to project root"},
    "fail_on": {"type": "string", "enum": _SEVERITY_ENUM},
    "fail_on_unanalyzed": {
        "type": "boolean",
        "description": "Trip the gate when any file was discovered but could not be analyzed.",
    },
    "cache_dir": {"type": "string", "description": "summary-cache directory relative to project root"},
    "local_only": {
        "type": "boolean",
        "description": "Disable sibling emission even when a Filigree URL resolves from launch/env/install state.",
    },
    "filigree_max_findings_per_request": {"type": "integer", "minimum": 1},
    "timeout_seconds": {
        "type": "number",
        "minimum": 0,
        "description": "Fail the background scan job after this many seconds. Defaults to 1800; use 0 to disable.",
    },
    "lang": {"type": "string", "enum": ["python", "rust"]},
    "new_since": {
        "type": "string",
        "description": "PR-scoped 'new findings only' gate: only gate on findings in files/entities changed "
        "since this git ref.",
    },
    "trust_packs": {"type": "array", "items": {"type": "string"}},
    "trust_local_packs": {
        "type": "boolean",
        "description": "Allow loading custom trust-grammar packs from the local project directory.",
    },
    "strict_defaults": {
        "type": "boolean",
        "description": "Ignore repository-supplied custom configuration overrides (weft.toml).",
    },
    "trust_suppressions": {
        "type": "boolean",
        "description": "Let repository-controlled baseline/waiver/judged files clear the gate.",
    },
}


_SCAN_JOB_START_TOOL: dict[str, Any] = {
    "name": "scan_job_start",
    "title": "Start scan job",
    "description": "Start a file-backed Wardline scan job and return its stable job id plus initial status. "
    "Use scan_job_status to poll heartbeat/progress and scan_job_cancel to stop it. This is the MCP-safe "
    "surface for long scans; prefer it over synchronous scan when the project may take more than a short call.",
    "input_schema": {
        "type": "object",
        "properties": _SCAN_JOB_START_INPUT_PROPERTIES,
    },
    "output_schema": _SCAN_JOB_STATUS_OUTPUT_SCHEMA,
    "annotations": {
        "title": "Start scan job",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
    "capabilities": frozenset({ToolCapability.READ, ToolCapability.WRITE}),
}


_SCAN_JOB_STATUS_TOOL: dict[str, Any] = {
    "name": "scan_job_status",
    "title": "Read scan-job status",
    "description": "Read the current status JSON for a file-backed Wardline scan job. Reports stale heartbeat "
    "or dead-worker terminal failure instead of leaving an apparently hung job ambiguous.",
    "input_schema": {
        "type": "object",
        "required": ["job_id"],
        "properties": {
            "job_id": {"type": "string", "pattern": "^[0-9a-f]{32}$"},
            "path": {"type": "string", "description": "scan root subdir relative to the MCP server project root"},
        },
    },
    "output_schema": _SCAN_JOB_STATUS_OUTPUT_SCHEMA,
    "annotations": {
        "title": "Read scan-job status",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
    "capabilities": frozenset({ToolCapability.READ}),
}


_SCAN_JOB_CANCEL_TOOL: dict[str, Any] = {
    "name": "scan_job_cancel",
    "title": "Cancel scan job",
    "description": "Cancel a non-terminal file-backed Wardline scan job and return the persisted terminal status.",
    "input_schema": {
        "type": "object",
        "required": ["job_id"],
        "properties": {
            "job_id": {"type": "string", "pattern": "^[0-9a-f]{32}$"},
            "path": {"type": "string", "description": "scan root subdir relative to the MCP server project root"},
        },
    },
    "output_schema": _SCAN_JOB_STATUS_OUTPUT_SCHEMA,
    "annotations": {
        "title": "Cancel scan job",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": True,
        "openWorldHint": False,
    },
    "capabilities": frozenset({ToolCapability.READ, ToolCapability.WRITE}),
}


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
    from wardline.core.legis import (
        build_legis_artifact,
        key_id,
        legis_artifact_outcome,
        load_legis_artifact_key,
    )

    key_str = load_legis_artifact_key(path)
    explicit = bool(args.get("legis_artifact"))
    if key_str is None and not explicit:
        return  # not requested — default response unchanged
    if _bool_arg(args, "summary_only", False) and not explicit:
        # summary_only promises the smallest "did the gate pass?" payload; a
        # provisioned key must not auto-attach a ~56KB verbatim artifact into it
        # (dogfood-4 B6 blew the MCP token cap exactly this way). An explicit
        # legis_artifact:true still wins when the caller asks for both.
        return

    cfg = config_mod.load(
        _cfg(args, path) or weft_config_path(path),
        explicit=_cfg(args, path) is not None,
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
    # it `unverified`. Read signed/dirty/reason from the single authority over what the
    # producer emitted (legis_artifact_outcome), not by re-deriving from key presence.
    outcome = legis_artifact_outcome(artifact)
    status["signed"] = outcome.signed
    status["dirty"] = outcome.dirty
    if outcome.unverified_reason is not None:
        # Match the CLI's loudness on the agent surface (agent-first): the artifact is
        # UNSIGNED and legis records it unverified — say so rather than leaving the agent
        # to infer it from signed:false / dirty:true alone.
        status["reason"] = outcome.unverified_reason
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
    max_hops_raw = args.get("max_hops")
    result_dict = explain_taint_result(
        root,
        fingerprint=args.get("fingerprint"),
        path=match_path,
        line=args.get("line"),
        config_path=_cfg(args, root),
        confine_to_root=True,
        loomweave=loomweave,
        sink_qualname=args.get("sink_qualname"),
        chain=bool(args.get("chain")),
        max_hops=int(max_hops_raw) if max_hops_raw is not None else 20,
    )
    if result_dict is None:
        raise ToolError(
            "fingerprint not in current scan; your code changed since the scan that produced it — re-scan.",
        )
    return result_dict


_EXPLAIN_TAINT_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": "Success payload of the explain_taint tool: the taint provenance slice for one finding (single "
    "source: core/explain.explain_taint_result, shared with the CLI `wardline explain-taint`). Served either from a "
    "fresh Loomweave store fact (no re-scan) or from an SP8 re-run; both paths produce this same key set. With "
    "chain=true and a configured Loomweave store, a `chain` block is additionally attached.",
    "properties": {
        "fingerprint": {
            "type": "string",
            "description": "Stable finding fingerprint. May be the empty string on the store-served path when the "
            "entity blob carries no per-finding rows (the entity is known, the specific finding is not).",
        },
        "rule_id": {
            "type": "string",
            "description": "Rule that produced the finding (e.g. PY-WL-101). May be the empty string on the "
            "store-served path when no per-finding row matched.",
        },
        "sink_qualname": {
            "type": ["string", "null"],
            "description": "Qualified name of the sink function the tainted value reaches (null when the engine has "
            "no qualname for the finding).",
        },
        "location": {
            "type": "object",
            "description": "Source location of the finding. path may be empty and line null on the store-served path "
            "when the blob has no per-finding rows.",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Root-relative posix path of the finding's file (empty string when unknown on the "
                    "store-served path).",
                },
                "line": {
                    "type": ["integer", "null"],
                    "description": "1-based start line of the finding (null when unknown).",
                },
            },
            "required": ["path", "line"],
            "additionalProperties": False,
        },
        "tier_in": {
            "type": ["string", "null"],
            "description": "Actual (untrusted) trust tier arriving at the sink, e.g. EXTERNAL_RAW (null when the "
            "engine recorded none).",
        },
        "tier_out": {
            "type": ["string", "null"],
            "description": "Trust tier the sink declares it returns, e.g. INTEGRAL (null when the engine recorded "
            "none).",
        },
        "immediate_tainted_callee": {
            "type": ["string", "null"],
            "description": "Bare trailing name of the call that introduced the untrusted return into the sink (null "
            "when unresolved).",
        },
        "source_boundary_qualname": {
            "type": ["string", "null"],
            "description": "Originating boundary resolved one hop from the sink: qualified name of the boundary "
            "function the taint came from (null when not resolvable in one hop). On the store-served path this is the "
            "blob's contributing_callee_qualname.",
        },
        "source_resolution": {
            "type": "object",
            "description": "C-10(c) honesty block: whether the taint source is named above, and when it is NOT, why "
            "and what capability would resolve it further — an explicit degrade marker, never nulls that read as a "
            "complete-but-empty answer.",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["resolved", "unresolved"],
                    "description": "resolved when immediate_tainted_callee or source_boundary_qualname is named; "
                    "unresolved otherwise.",
                },
                "reason": {
                    "type": ["string", "null"],
                    "description": "unresolved only: why wardline's own single-scan analysis could not name the "
                    "source; null when resolved.",
                },
                "missing_capability": {
                    "type": ["string", "null"],
                    "description": "unresolved only: capability that could resolve further — 'loomweave_taint_store' "
                    "when no store is configured; null when resolved or when nothing more would help.",
                },
                "enablement": {
                    "type": ["string", "null"],
                    "description": "unresolved only: how to enable the missing capability; null otherwise.",
                },
            },
            "required": ["status", "reason", "missing_capability", "enablement"],
            "additionalProperties": False,
        },
        "resolved_call_count": {
            "type": "integer",
            "description": "Number of calls inside the sink the engine resolved during taint computation.",
        },
        "unresolved_call_count": {
            "type": "integer",
            "description": "Number of calls inside the sink the engine could NOT resolve (residual uncertainty in the "
            "explanation).",
        },
        "remediation": {
            "type": "object",
            "description": "Advisory fix-at-the-boundary hint derived from the explanation; never replaces the "
            "factual taint fields above.",
            "properties": {
                "kind": {
                    "type": "string",
                    "enum": ["boundary_placement", "sink_hygiene", "review_required"],
                    "description": "boundary_placement for PY-WL-101 (place/repair a @trust_boundary at the "
                    "validating function); sink_hygiene for the dangerous-sink family (rule-specific fix guidance "
                    "naming the source and sink); review_required for rules with no automated hint.",
                },
                "rule_id": {
                    "type": "string",
                    "description": "Rule the hint applies to (echoes the top-level rule_id).",
                },
                "summary": {"type": "string", "description": "Human/agent-readable remediation guidance sentence."},
                "sink_qualname": {
                    "type": ["string", "null"],
                    "description": "Sink the hint refers to (null when the finding has no qualname).",
                },
                "source_qualname": {
                    "type": ["string", "null"],
                    "description": "Taint source the hint refers to: the resolved boundary, else the immediate "
                    "tainted callee, else null when unresolved.",
                },
                "caveat": {
                    "type": "string",
                    "description": "Standing warning against blind decorator insertion / over-trusting the hint.",
                },
            },
            "required": ["kind", "rule_id", "summary", "sink_qualname", "source_qualname", "caveat"],
            "additionalProperties": False,
        },
        "chain": {
            "type": "object",
            "description": "Full N-hop taint chain from the sink to the originating boundary, walked from the "
            "Loomweave store. Present whenever the call passed chain=true: status 'walked' carries the hops; status "
            "'unavailable' is the explicit C-10(c) degrade marker (no Loomweave store configured, or no sink "
            "qualname to anchor on) naming the missing capability and its enablement path — the walk never degrades "
            "silently.",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["walked", "unavailable"],
                    "description": "walked: the store walk ran (hops below). unavailable: the walk could not run; "
                    "see missing_capability/enablement.",
                },
                "missing_capability": {
                    "type": ["string", "null"],
                    "description": "unavailable only: what the walk lacked ('loomweave_taint_store' or "
                    "'sink_qualname'); null when walked.",
                },
                "enablement": {
                    "type": ["string", "null"],
                    "description": "unavailable only: how to enable the missing capability; null when walked.",
                },
                "hops": {
                    "type": "array",
                    "description": "Ordered hops from the sink toward the boundary leaf. The walk stops cleanly at a "
                    "boundary (contributing_callee_qualname null on the last hop) or truncates explicitly (see "
                    "truncated_at).",
                    "items": {
                        "type": "object",
                        "properties": {
                            "qualname": {
                                "type": "string",
                                "description": "Qualified name of the function at this hop.",
                            },
                            "tier_in": {
                                "type": ["string", "null"],
                                "description": "Actual trust tier arriving at this hop (from the stored fact; null "
                                "when absent).",
                            },
                            "tier_out": {
                                "type": ["string", "null"],
                                "description": "Trust tier this hop declares it returns (from the stored fact; null "
                                "when absent).",
                            },
                            "contributing_callee_qualname": {
                                "type": ["string", "null"],
                                "description": "Next hop toward the boundary; null at the boundary leaf (clean "
                                "finish).",
                            },
                        },
                        "required": ["qualname", "tier_in", "tier_out", "contributing_callee_qualname"],
                        "additionalProperties": False,
                    },
                },
                "truncated_at": {
                    "type": ["string", "null"],
                    "description": "Qualified name of the next hop the walk could NOT take (stale/absent fact, read "
                    "error, cycle, or max_hops reached) — truncation is always explicit; null means the chain reached "
                    "the boundary cleanly.",
                },
            },
            "required": ["status", "hops", "truncated_at", "missing_capability", "enablement"],
            "additionalProperties": False,
        },
    },
    "required": [
        "fingerprint",
        "rule_id",
        "sink_qualname",
        "location",
        "tier_in",
        "tier_out",
        "immediate_tainted_callee",
        "source_boundary_qualname",
        "source_resolution",
        "resolved_call_count",
        "unresolved_call_count",
        "remediation",
    ],
    "additionalProperties": False,
}


_EXPLAIN_TAINT_TOOL: dict[str, Any] = {
    "name": "explain_taint",
    "title": "Explain finding taint",
    "description": "Explain ONE finding's taint: the immediate tainted callee, the "
    "originating boundary, and the trust tiers at the sink. Call right "
    "after scan and before editing — a stale fingerprint returns an error. "
    "Pass the finding's `qualname` as `sink_qualname`: when a Loomweave store "
    "is configured this serves the explanation from the store instead of "
    "re-scanning. Pass `chain: true` (needs a configured Loomweave store) to "
    "also walk the full taint chain from the sink to the originating boundary; "
    "without a store the `chain` block is an explicit `status: unavailable` marker "
    "naming the missing capability and its enablement path.",
    "input_schema": {
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
    "output_schema": _EXPLAIN_TAINT_OUTPUT_SCHEMA,
    "annotations": {
        "title": "Explain finding taint",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
}


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


_DOSSIER_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": "One-call entity dossier envelope: Wardline's own trust posture (always re-derived fresh) plus "
    "Loomweave linkages and Filigree open work, each cross-tool section degrading to an honest unavailable shape "
    "(available=false + reason) when its source is absent. Token-bounded with an explicit truncation marker.",
    "properties": {
        "identity": {
            "type": "object",
            "description": "Who the entity is plus its two-axis freshness (identity axis / content axis). Never "
            "trimmed by the budgeter.",
            "properties": {
                "qualname": {
                    "type": "string",
                    "description": "The entity's qualified name, minted relative to the scan root.",
                },
                "kind": {"type": ["string", "null"], "description": "Entity kind (e.g. function); null when unknown."},
                "path": {"type": ["string", "null"], "description": "Source file path of the entity."},
                "line_start": {"type": ["integer", "null"]},
                "line_end": {"type": ["integer", "null"]},
                "sei": {
                    "type": ["string", "null"],
                    "description": "Opaque stable entity identifier (the cross-tool binding key); null when no "
                    "Loomweave binding was resolved.",
                },
                "keyed_on_sei": {
                    "type": "boolean",
                    "description": "True when the cross-tool sections were keyed on the SEI rather than a locator.",
                },
                "identity_status": {
                    "type": "string",
                    "enum": ["alive", "orphaned", "unavailable"],
                    "description": "Identity axis: is this the same entity? Never inferred from content.",
                },
                "content_status": {
                    "type": "string",
                    "enum": ["fresh", "stale", "unknown"],
                    "description": "Content axis: has the entity's code changed? Never inferred from identity.",
                },
                "content_hash": {
                    "type": ["string", "null"],
                    "description": "Current content hash from the binding, when available.",
                },
            },
            "required": [
                "qualname",
                "kind",
                "path",
                "line_start",
                "line_end",
                "sei",
                "keyed_on_sei",
                "identity_status",
                "content_status",
                "content_hash",
            ],
            "additionalProperties": False,
        },
        "shape": {
            "type": "object",
            "description": "Signature and decorators as declared in source.",
            "properties": {
                "signature": {"type": ["string", "null"], "description": 'Rendered signature, e.g. "(p) -> str".'},
                "decorators": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Decorators as declared, each prefixed with '@'.",
                },
            },
            "required": ["signature", "decorators"],
            "additionalProperties": False,
        },
        "trust": {
            "type": "object",
            "description": "Wardline's OWN trust posture, re-derived from a live scan (fresh by construction).",
            "properties": {
                "declared_return": {
                    "type": ["string", "null"],
                    "description": "Declared return trust tier; null when undeclared.",
                },
                "actual_return": {
                    "type": ["string", "null"],
                    "description": "Engine-computed actual return taint; null when not computed.",
                },
                "gate_verdict": {
                    "type": "string",
                    "enum": ["defect", "clean", "unknown"],
                    "description": "Three-valued, fail-closed verdict: defect (active findings), clean (declared "
                    "posture that conforms), unknown (undeclared/unprovable/under-scanned).",
                },
                "active_findings": {
                    "type": "array",
                    "description": "Active (non-suppressed) defect findings on the entity. May be trimmed by the "
                    "token budgeter (see truncation.elided).",
                    "items": {
                        "type": "object",
                        "properties": {
                            "rule_id": {"type": "string"},
                            "severity": {"type": "string", "enum": ["CRITICAL", "ERROR", "WARN", "INFO", "NONE"]},
                            "message": {"type": "string"},
                            "line": {"type": ["integer", "null"]},
                        },
                        "required": ["rule_id", "severity", "message", "line"],
                        "additionalProperties": False,
                    },
                },
                "suppressed_findings": {
                    "type": "integer",
                    "description": "Count of accepted (baselined/waived/judged) defects — known debt a clean verdict "
                    "must not hide.",
                },
                "unanalyzed_reason": {
                    "type": ["string", "null"],
                    "description": "Engine under-scan fact (parse error / recursion skip) when the body was not "
                    "analysed; else null.",
                },
                "freshness": {
                    "type": "string",
                    "enum": ["fresh_by_construction"],
                    "description": "Constant: the trust section is re-derived on demand, never stale.",
                },
            },
            "required": [
                "declared_return",
                "actual_return",
                "gate_verdict",
                "active_findings",
                "suppressed_findings",
                "unanalyzed_reason",
                "freshness",
            ],
            "additionalProperties": False,
        },
        "linkages": {
            "type": "object",
            "description": "Call-graph neighbourhood from Loomweave. available=false with a reason when Loomweave is "
            "not configured / unreachable / serves no HTTP linkages.",
            "properties": {
                "available": {"type": "boolean"},
                "callers": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Caller entity locators; empty when unavailable. May be trimmed by the token "
                    "budgeter.",
                },
                "callees": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Callee entity locators; empty when unavailable. May be trimmed by the token "
                    "budgeter.",
                },
                "scc_peers": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Strongly-connected-component peers (currently always empty: SCC membership is not "
                    "served over HTTP).",
                },
                "identity_status": {"type": "string", "enum": ["alive", "orphaned", "unavailable"]},
                "content_status": {"type": "string", "enum": ["fresh", "stale", "unknown"]},
                "reason": {
                    "type": ["string", "null"],
                    "description": "Why the section is unavailable or degraded (e.g. one-sided linkage failure); null "
                    "when fully available.",
                },
            },
            "required": ["available", "callers", "callees", "scc_peers", "identity_status", "content_status", "reason"],
            "additionalProperties": False,
        },
        "work": {
            "type": "object",
            "description": "Open work from Filigree, keyed on the SEI. available=false with a reason when Filigree is "
            "not configured / unreachable / there is no binding.",
            "properties": {
                "available": {"type": "boolean"},
                "tickets": {
                    "type": "array",
                    "description": "Filigree issues bound to the entity. May be trimmed by the token budgeter.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "issue_id": {"type": "string"},
                            "status": {"type": ["string", "null"]},
                            "priority": {"type": ["string", "null"]},
                            "title": {"type": ["string", "null"]},
                            "drift": {
                                "type": "boolean",
                                "description": "True when the issue was bound to a PRIOR version of the entity "
                                "(content hash at attach no longer matches).",
                            },
                        },
                        "required": ["issue_id", "status", "priority", "title", "drift"],
                        "additionalProperties": False,
                    },
                },
                "identity_status": {"type": "string", "enum": ["alive", "orphaned", "unavailable"]},
                "content_status": {
                    "type": "string",
                    "enum": ["fresh", "stale", "unknown"],
                    "description": "stale when any ticket binding drifted; unknown when a compare was impossible.",
                },
                "reason": {
                    "type": ["string", "null"],
                    "description": "Why the section is unavailable; null when available.",
                },
            },
            "required": ["available", "tickets", "identity_status", "content_status", "reason"],
            "additionalProperties": False,
        },
        "synthesis": {
            "type": ["string", "null"],
            "description": "Best-effort one-paragraph actionable join of all sections; null when dropped to fit the "
            "token budget.",
        },
        "truncation": {
            "type": "object",
            "description": "Elision-honest truncation marker: truncated=false on a complete envelope; when true, "
            "elided names every trimmed list with shown-of-total counts.",
            "properties": {
                "truncated": {"type": "boolean"},
                "elided": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "section": {
                                "type": "string",
                                "description": 'Dotted list path that was trimmed, e.g. "linkages.callers" or '
                                '"trust.active_findings".',
                            },
                            "shown": {"type": "integer"},
                            "total": {"type": "integer"},
                        },
                        "required": ["section", "shown", "total"],
                        "additionalProperties": False,
                    },
                },
                "note": {
                    "type": ["string", "null"],
                    "description": "Human-readable trim summary; null when not truncated.",
                },
            },
            "required": ["truncated", "elided", "note"],
            "additionalProperties": False,
        },
    },
    "required": ["identity", "shape", "trust", "linkages", "work", "synthesis", "truncation"],
    "additionalProperties": False,
}


_DOSSIER_TOOL: dict[str, Any] = {
    "name": "dossier",
    "title": "Entity trust dossier",
    "description": "One-call entity dossier for a function `entity` (a qualname): its "
    "trust posture (declared vs actual taint, gate verdict, active findings — always "
    "computed fresh), plus Loomweave call-graph linkages and Filigree open work joined on "
    "the entity's opaque SEI. Every cross-tool section is freshness-stamped on BOTH axes "
    "(identity alive/orphaned/unavailable + content fresh/stale/unknown) and degrades to "
    "an honest `unavailable` when its source is absent. Token-bounded (~2k) with an "
    "explicit truncation marker. Read the whole context without opening the source.",
    "input_schema": {
        "type": "object",
        "required": ["entity"],
        "properties": {
            "entity": {"type": "string", "description": "the function qualname, e.g. pkg.mod.func"},
            "config": {"type": "string"},
        },
    },
    "output_schema": _DOSSIER_OUTPUT_SCHEMA,
    "annotations": {
        "title": "Entity trust dossier",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
}


def _assure(args: dict[str, Any], root: Path) -> dict[str, Any]:
    """Trust-surface COVERAGE posture — the pre-trust-decision read. How many declared
    trust boundaries the engine reached a definite verdict on vs. how many are honestly
    unknown, plus waiver-debt. Identical to the CLI `assure` JSON by construction (both
    call ``build_posture``). Path/config confined under root like every rooted tool."""
    path = _resolve_under_root(root, args["path"]) if args.get("path") else root
    posture = build_posture(path, config_path=_cfg(args, root), confine_to_root=True)
    return posture.to_dict()


_ASSURE_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": "Trust-surface coverage posture: how many declared trust boundaries got a definite verdict vs. how "
    "many are honestly unknown, plus waiver debt. Identical to the CLI `assure` JSON.",
    "properties": {
        "boundaries_total": {
            "type": "integer",
            "description": "Denominator: count of anchored (trust-declared) entities. proven + defect_total + "
            "len(unknown) == boundaries_total.",
        },
        "proven": {"type": "integer", "description": "Boundaries with a definite clean verdict."},
        "defect_total": {
            "type": "integer",
            "description": "Boundaries with a definite defect verdict (a defect counts as COVERED — the engine "
            "reached a verdict).",
        },
        "unknown": {
            "type": "array",
            "description": "The honesty gap: anchored entities whose trust could not be proven either way, sorted by "
            "qualname.",
            "items": {
                "type": "object",
                "properties": {
                    "qualname": {"type": "string", "description": "Qualified name of the anchored entity."},
                    "tier": {"type": ["string", "null"], "description": "Declared trust tier, or null if undeclared."},
                    "location": {
                        "type": "object",
                        "description": "Where the entity is declared; both fields null when no location is known.",
                        "properties": {"path": {"type": ["string", "null"]}, "line": {"type": ["integer", "null"]}},
                        "required": ["path", "line"],
                        "additionalProperties": False,
                    },
                    "reason": {
                        "type": ["string", "null"],
                        "description": "Engine under-scan FACT message when the body was not analysed "
                        "(parse/recursion skip), else null (undeclared / unprovable).",
                    },
                },
                "required": ["qualname", "tier", "location", "reason"],
                "additionalProperties": False,
            },
        },
        "engine_limited": {
            "type": "integer",
            "description": "Under-scan pressure: entity-level unknowns with an engine reason plus unanalyzed files.",
        },
        "coverage_pct": {
            "type": ["number", "null"],
            "description": "Share of known boundaries with a definite verdict over known boundaries plus "
            "unanalyzed files, rounded to 1 decimal. null when there are no boundaries and no unanalyzed files.",
        },
        "unanalyzed_total": {
            "type": "integer",
            "description": "Files discovered but never analyzed. Each counts as at least one uncovered surface "
            "item in coverage_pct.",
        },
        "unanalyzed_rule_ids": {
            "type": "array",
            "description": "Distinct under-scan rule ids present in the scan findings, sorted lexicographically.",
            "items": {"type": "string"},
        },
        "waiver_debt": {
            "type": "array",
            "description": "Configured waivers with days-to-expiry, sorted by fingerprint. Populated even when "
            "nothing was analysable.",
            "items": {
                "type": "object",
                "properties": {
                    "fingerprint": {"type": "string", "description": "Finding fingerprint the waiver covers."},
                    "expires": {
                        "type": ["string", "null"],
                        "description": "ISO date the waiver expires, or null for no expiry.",
                    },
                    "days_left": {
                        "type": ["integer", "null"],
                        "description": "Days until expiry; may be NEGATIVE for a lapsed waiver; null for no expiry.",
                    },
                    "reason": {"type": "string", "description": "The waiver's recorded justification."},
                },
                "required": ["fingerprint", "expires", "days_left", "reason"],
                "additionalProperties": False,
            },
        },
        "baselined_total": {"type": "integer", "description": "Findings suppressed by the baseline in this scan."},
        "judged_total": {"type": "integer", "description": "Findings suppressed by judge verdicts in this scan."},
    },
    "required": [
        "boundaries_total",
        "proven",
        "defect_total",
        "unknown",
        "engine_limited",
        "coverage_pct",
        "unanalyzed_total",
        "unanalyzed_rule_ids",
        "waiver_debt",
        "baselined_total",
        "judged_total",
    ],
    "additionalProperties": False,
}


_ASSURE_TOOL: dict[str, Any] = {
    "name": "assure",
    "title": "Trust-surface coverage posture",
    "description": "Trust-surface COVERAGE posture: how many declared trust boundaries the "
    "engine reached a definite verdict on vs. how many are honestly unknown, plus "
    "waiver-debt. Consult before deciding to trust a module.",
    "input_schema": {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "config": {"type": "string"},
        },
    },
    "output_schema": _ASSURE_OUTPUT_SCHEMA,
    "annotations": {
        "title": "Trust-surface coverage posture",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
}


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


_DECORATOR_COVERAGE_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": "Row-level inventory of every trust-decorated entity under the project (the row-level sibling of "
    "assure): each declared trust-surface entity with its current verdict, findings, identity binding, and open-work "
    "state, plus a rollup summary.",
    "properties": {
        "summary": {
            "type": "object",
            "description": "Rollup counts over rows by finding_state.",
            "properties": {
                "total": {"type": "integer", "description": "Total declared trust-surface entities."},
                "clean": {"type": "integer", "description": "Rows with finding_state == clean."},
                "defect": {"type": "integer", "description": "Rows with finding_state == defect."},
                "unknown": {"type": "integer", "description": "Rows with finding_state == unknown."},
                "suppressed": {"type": "integer", "description": "Rows with finding_state == suppressed."},
            },
            "required": ["total", "clean", "defect", "unknown", "suppressed"],
            "additionalProperties": False,
        },
        "rows": {
            "type": "array",
            "description": "One row per declared trust-decorated entity, sorted by qualname. Empty when the scan "
            "produced no analysis context.",
            "items": {
                "type": "object",
                "properties": {
                    "qualname": {
                        "type": "string",
                        "description": "The entity's qualified name, minted relative to the scan root.",
                    },
                    "path": {
                        "type": ["string", "null"],
                        "description": "Source file path; null when the declared qualname has no scanned entity.",
                    },
                    "line": {
                        "type": ["integer", "null"],
                        "description": "Entity start line; null when the declared qualname has no scanned entity.",
                    },
                    "decorators": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Decorators as declared, each prefixed with '@'.",
                    },
                    "declared_tier": {
                        "type": ["string", "null"],
                        "description": "Declared return trust tier; null when undeclared.",
                    },
                    "actual_tier": {
                        "type": ["string", "null"],
                        "description": "Engine-computed actual return taint; null when not computed.",
                    },
                    "verdict": {
                        "type": "string",
                        "enum": ["defect", "clean", "unknown"],
                        "description": "Three-valued, fail-closed trust verdict for the entity.",
                    },
                    "finding_state": {
                        "type": "string",
                        "enum": ["defect", "suppressed", "unknown", "clean"],
                        "description": "defect when active findings exist; suppressed when only accepted findings "
                        "exist; unknown when the verdict is unknown; else clean.",
                    },
                    "active_finding_fingerprints": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Sorted fingerprints of active (non-suppressed) defect findings on the entity.",
                    },
                    "suppressed_finding_fingerprints": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Sorted fingerprints of accepted (baselined/waived/judged) defect findings.",
                    },
                    "identity": {
                        "type": "object",
                        "description": "Cross-tool identity binding for the row. Degrades to available=false with a "
                        "reason when Loomweave is not configured / unreachable / resolved no SEI.",
                        "properties": {
                            "available": {
                                "type": "boolean",
                                "description": "True only when an SEI was resolved for the entity.",
                            },
                            "locator": {
                                "type": "string",
                                "description": "The Loomweave-style locator, e.g. python:function:pkg.mod.func.",
                            },
                            "sei": {
                                "type": ["string", "null"],
                                "description": "Opaque stable entity identifier; null when not resolved.",
                            },
                            "identity_status": {
                                "type": "string",
                                "enum": ["alive", "orphaned", "unavailable"],
                                "description": "Identity axis: is this the same entity?",
                            },
                            "content_status": {
                                "type": "string",
                                "enum": ["fresh", "stale", "unknown"],
                                "description": "Content axis: has the entity's code changed?",
                            },
                            "content_hash": {
                                "type": ["string", "null"],
                                "description": "Current content hash from the binding, when available.",
                            },
                            "reason": {
                                "type": ["string", "null"],
                                "description": "Why identity is unavailable (e.g. 'loomweave not configured', 'no SEI "
                                "resolved'); null when an SEI was resolved.",
                            },
                        },
                        "required": [
                            "available",
                            "locator",
                            "sei",
                            "identity_status",
                            "content_status",
                            "content_hash",
                            "reason",
                        ],
                        "additionalProperties": False,
                    },
                    "work": {
                        "type": "object",
                        "description": "Open work from Filigree, keyed on the SEI. available=false with a reason when "
                        "Filigree is not configured / unreachable / there is no SEI binding.",
                        "properties": {
                            "available": {"type": "boolean"},
                            "tickets": {
                                "type": "array",
                                "description": "Filigree issues bound to the entity.",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "issue_id": {"type": "string"},
                                        "status": {"type": ["string", "null"]},
                                        "priority": {"type": ["string", "null"]},
                                        "title": {"type": ["string", "null"]},
                                        "drift": {
                                            "type": "boolean",
                                            "description": "True when the issue was bound to a PRIOR version of the "
                                            "entity (content hash at attach no longer matches).",
                                        },
                                    },
                                    "required": ["issue_id", "status", "priority", "title", "drift"],
                                    "additionalProperties": False,
                                },
                            },
                            "identity_status": {"type": "string", "enum": ["alive", "orphaned", "unavailable"]},
                            "content_status": {
                                "type": "string",
                                "enum": ["fresh", "stale", "unknown"],
                                "description": "stale when any ticket binding drifted; unknown when a compare was "
                                "impossible.",
                            },
                            "reason": {
                                "type": ["string", "null"],
                                "description": "Why the section is unavailable; null when available.",
                            },
                        },
                        "required": ["available", "tickets", "identity_status", "content_status", "reason"],
                        "additionalProperties": False,
                    },
                },
                "required": [
                    "qualname",
                    "path",
                    "line",
                    "decorators",
                    "declared_tier",
                    "actual_tier",
                    "verdict",
                    "finding_state",
                    "active_finding_fingerprints",
                    "suppressed_finding_fingerprints",
                    "identity",
                    "work",
                ],
                "additionalProperties": False,
            },
        },
    },
    "required": ["summary", "rows"],
    "additionalProperties": False,
}


_DECORATOR_COVERAGE_TOOL: dict[str, Any] = {
    "name": "decorator_coverage",
    "title": "Trust-decorator inventory",
    "description": "Stable JSON inventory of every Wardline trust-decorated entity: "
    "qualname, path/line, decorators, declared/actual tier, gate verdict, "
    "active/suppressed finding fingerprints, optional SEI/content status, and "
    "optional Filigree linked work status. Optional sources degrade explicitly.",
    "input_schema": {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "config": {"type": "string"},
        },
    },
    "output_schema": _DECORATOR_COVERAGE_OUTPUT_SCHEMA,
    "annotations": {
        "title": "Trust-decorator inventory",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
    "capabilities": frozenset({ToolCapability.READ, ToolCapability.NETWORK}),
}


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


_ATTEST_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": "Signed, reproducible evidence bundle: a deterministic payload plus an HMAC-SHA256 signature under "
    "the shared project key (tamper-evidence within the key-holding trust domain, not asymmetric proof).",
    "properties": {
        "schema": {
            "type": "string",
            "enum": ["wardline-attest-1"],
            "description": "Wire-contract tag; bound into the HMAC so a relabel cannot verify.",
        },
        "payload": {
            "type": "object",
            "description": "The signed, deterministic attestation payload (canonical compact key-sorted JSON is the "
            "reproducibility target).",
            "properties": {
                "wardline_version": {"type": "string", "description": "Wardline version that produced the bundle."},
                "attested_at": {
                    "type": "string",
                    "description": "ISO date the bundle was built; re-derivation on verify uses this as `today`.",
                },
                "commit": {
                    "type": ["string", "null"],
                    "description": "`git rev-parse HEAD` of the tree, or null for a non-git tree / missing git.",
                },
                "dirty": {
                    "type": "boolean",
                    "description": "True iff the working tree had uncommitted changes (MCP refuses dirty trees unless "
                    "allow_dirty=true).",
                },
                "ruleset_hash": {
                    "type": "string",
                    "description": "Deterministic 'sha256:<hex>' over the effective scan policy.",
                },
                "posture": {
                    "type": "object",
                    "description": "The trust-surface coverage posture at attestation time (same shape as the "
                    "`assure` tool result).",
                    "properties": {
                        "boundaries_total": {"type": "integer"},
                        "proven": {"type": "integer"},
                        "defect_total": {"type": "integer"},
                        "unknown": {
                            "type": "array",
                            "description": "Anchored entities with no definite verdict, sorted by qualname.",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "qualname": {"type": "string"},
                                    "tier": {"type": ["string", "null"]},
                                    "location": {
                                        "type": "object",
                                        "properties": {
                                            "path": {"type": ["string", "null"]},
                                            "line": {"type": ["integer", "null"]},
                                        },
                                        "required": ["path", "line"],
                                        "additionalProperties": False,
                                    },
                                    "reason": {"type": ["string", "null"]},
                                },
                                "required": ["qualname", "tier", "location", "reason"],
                                "additionalProperties": False,
                            },
                        },
                        "engine_limited": {"type": "integer"},
                        "coverage_pct": {
                            "type": ["number", "null"],
                            "description": "null when there are no boundaries and no unanalyzed files.",
                        },
                        "unanalyzed_total": {"type": "integer"},
                        "unanalyzed_rule_ids": {"type": "array", "items": {"type": "string"}},
                        "waiver_debt": {
                            "type": "array",
                            "description": "Configured waivers with days-to-expiry (the only date-sensitive payload "
                            "field), sorted by fingerprint.",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "fingerprint": {"type": "string"},
                                    "expires": {"type": ["string", "null"]},
                                    "days_left": {"type": ["integer", "null"]},
                                    "reason": {"type": "string"},
                                },
                                "required": ["fingerprint", "expires", "days_left", "reason"],
                                "additionalProperties": False,
                            },
                        },
                        "baselined_total": {"type": "integer"},
                        "judged_total": {"type": "integer"},
                    },
                    "required": [
                        "boundaries_total",
                        "proven",
                        "defect_total",
                        "unknown",
                        "engine_limited",
                        "coverage_pct",
                        "unanalyzed_total",
                        "unanalyzed_rule_ids",
                        "waiver_debt",
                        "baselined_total",
                        "judged_total",
                    ],
                    "additionalProperties": False,
                },
                "boundaries": {
                    "type": "array",
                    "description": "Per-boundary trust verdicts, sorted by qualname; empty when nothing was "
                    "analysable.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "qualname": {"type": "string", "description": "Qualified name of the anchored entity."},
                            "sei": {
                                "type": ["string", "null"],
                                "description": "Loomweave SEI resolved at build time; null without a Loomweave client "
                                "or when unresolvable.",
                            },
                            "verdict": {
                                "type": "string",
                                "enum": ["clean", "defect", "unknown"],
                                "description": "The entity's trust verdict from the single source of truth "
                                "(classify_entity_trust).",
                            },
                            "tier": {
                                "type": ["string", "null"],
                                "description": "Declared trust tier, or null if undeclared.",
                            },
                        },
                        "required": ["qualname", "sei", "verdict", "tier"],
                        "additionalProperties": False,
                    },
                },
                "sei_source": {
                    "type": "string",
                    "enum": ["loomweave", "unavailable"],
                    "description": "'loomweave' iff a client was supplied AND at least one SEI resolved; else "
                    "'unavailable'.",
                },
            },
            "required": [
                "wardline_version",
                "attested_at",
                "commit",
                "dirty",
                "ruleset_hash",
                "posture",
                "boundaries",
                "sei_source",
            ],
            "additionalProperties": False,
        },
        "signature": {
            "type": "object",
            "description": "HMAC-SHA256 over the canonical {schema, payload} envelope bytes.",
            "properties": {
                "alg": {"type": "string", "enum": ["HMAC-SHA256"]},
                "value": {"type": "string", "description": "Hex HMAC digest."},
                "key_id": {
                    "type": "string",
                    "description": "Non-secret 8-hex short id of the signing key (distinguishes keys without "
                    "revealing them).",
                },
            },
            "required": ["alg", "value", "key_id"],
            "additionalProperties": False,
        },
    },
    "required": ["schema", "payload", "signature"],
    "additionalProperties": False,
}


_ATTEST_TOOL: dict[str, Any] = {
    "name": "attest",
    "title": "Build signed attestation",
    "description": "Build a SIGNED, reproducible evidence bundle (commit, ruleset hash, "
    "trust-surface posture, boundaries) for the project. HMAC-signed with the "
    "install-minted project key. Refuses a dirty working tree unless allow_dirty=true. "
    "SEI-keyed when a Loomweave store is configured.",
    "input_schema": {
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
    "output_schema": _ATTEST_OUTPUT_SCHEMA,
    "annotations": {
        "title": "Build signed attestation",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
}


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


_VERIFY_ATTESTATION_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": "Result of verifying an attestation bundle: signature check (always, offline) plus optional "
    "reproducibility re-derivation against the current tree.",
    "properties": {
        "signature_valid": {
            "type": "boolean",
            "description": "True iff the recomputed HMAC over the recorded payload matches the stored signature "
            "(schema tag, alg, and key_id must all match too).",
        },
        "reproduced": {
            "type": ["boolean", "null"],
            "description": "null when reproduce was not requested (or no root); true when the re-derived payload's "
            "canonical bytes equal the recorded payload's; false otherwise. A false may mean the tree moved on, not "
            "tamper.",
        },
        "mismatches": {
            "type": "array",
            "description": "Top-level payload keys that differ between the recorded and re-derived payloads. Empty "
            "unless reproduced is false.",
            "items": {"type": "string"},
        },
        "note": {
            "type": "string",
            "description": "Fixed caveat: reproducibility holds against the RECORDED commit; a mismatch may mean the "
            "tree moved, not tamper.",
        },
    },
    "required": ["signature_valid", "reproduced", "mismatches", "note"],
    "additionalProperties": False,
}


_VERIFY_ATTESTATION_TOOL: dict[str, Any] = {
    "name": "verify_attestation",
    "title": "Verify attestation bundle",
    "description": "Verify an attestation bundle's signature (offline, needs the project "
    "key) and optionally its reproducibility (reproduce=true re-derives at the current "
    "tree). Returns {signature_valid, reproduced, mismatches, note}.",
    "input_schema": {
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
    "output_schema": _VERIFY_ATTESTATION_OUTPUT_SCHEMA,
    "annotations": {
        "title": "Verify attestation bundle",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
}


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


_JUDGE_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": "Success payload of the judge tool: per-finding LLM triage verdicts plus the persistence outcome "
    "of FALSE_POSITIVE records.",
    "properties": {
        "verdicts": {
            "type": "array",
            "description": "One flattened verdict per triaged finding.",
            "items": {
                "type": "object",
                "properties": {
                    "fingerprint": {"type": "string", "description": "Stable fingerprint of the judged finding."},
                    "rule_id": {"type": "string", "description": "Rule that produced the finding."},
                    "path": {"type": "string", "description": "Repo-relative file path of the finding."},
                    "line": {"type": ["integer", "null"], "description": "1-based start line; null when unknown."},
                    "label": {
                        "type": "string",
                        "enum": ["TRUE_POSITIVE", "FALSE_POSITIVE"],
                        "description": "The judge's verdict: a real defect vs an analyzer over-approximation.",
                    },
                    "confidence": {
                        "type": "number",
                        "description": "The judge's calibrated confidence in the verdict, 0.0 to 1.0.",
                    },
                    "rationale": {
                        "type": "string",
                        "description": "The model's verbatim reasoning (the audit primitive); always a non-empty "
                        "string.",
                    },
                },
                "required": ["fingerprint", "rule_id", "path", "line", "label", "confidence", "rationale"],
                "additionalProperties": False,
            },
        },
        "wrote": {
            "type": "integer",
            "description": "FALSE_POSITIVE verdicts persisted to .wardline/judged.yaml (0 unless write=true).",
        },
        "held_back": {
            "type": "integer",
            "description": "FALSE_POSITIVE verdicts NOT persisted because their confidence fell below the write floor.",
        },
    },
    "required": ["verdicts", "wrote", "held_back"],
    "additionalProperties": False,
}


_JUDGE_TOOL: dict[str, Any] = {
    "name": "judge",
    "title": "LLM triage of findings",
    "description": "NETWORK: opt-in LLM triage of active defects via OpenRouter "
    "(needs WARDLINE_OPENROUTER_API_KEY). Labels each TRUE/FALSE positive. "
    "Never run automatically; never folded into scan.",
    "input_schema": {
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
    "output_schema": _JUDGE_OUTPUT_SCHEMA,
    "annotations": {
        "title": "LLM triage of findings",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
    "capabilities": frozenset({ToolCapability.READ, ToolCapability.NETWORK}),
}


def _baseline(args: dict[str, Any], root: Path) -> dict[str, Any]:
    reason = args.get("reason")
    baseline_path = baseline_file(root)
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


_BASELINE_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": "Success payload of the wardline MCP `baseline` tool: records the result of generating (or finding "
    "an existing) suppression baseline for the project.",
    "properties": {
        "baselined_count": {
            "type": "integer",
            "description": "Number of finding fingerprints in the baseline. On a fresh generation this is the count "
            "just written; when the baseline already existed (already_exists=true) it is the count in the existing "
            "file.",
        },
        "path": {"type": "string", "description": "Absolute path of the baseline file."},
        "reason": {
            "type": ["string", "null"],
            "description": "Caller-supplied reason for creating the baseline; null when not provided.",
        },
        "already_exists": {
            "type": "boolean",
            "description": "Only present when overwrite was not requested: true if a baseline file already existed "
            "(nothing was written; counts reflect the existing file), false if a new baseline was created. Absent "
            "when overwrite=true succeeds.",
        },
    },
    "required": ["baselined_count", "path", "reason"],
    "additionalProperties": False,
}


_BASELINE_TOOL: dict[str, Any] = {
    "name": "baseline",
    "title": "Snapshot findings baseline",
    "description": "Snapshot current defects as the baseline so only NEW findings surface. "
    "Default overwrite=false refuses to clobber and returns already_exists=true. "
    "Set overwrite=true to re-derive and overwrite the baseline. "
    "Prefer FIXING a finding over baselining it. Optional reason.",
    "input_schema": {
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
    "output_schema": _BASELINE_OUTPUT_SCHEMA,
    "annotations": {
        "title": "Snapshot findings baseline",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
    "capabilities": frozenset({ToolCapability.READ, ToolCapability.WRITE}),
}


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
    for existing in load_project_waivers(root):
        if existing.fingerprint == fp:
            return {
                "fingerprint": existing.fingerprint,
                "reason": existing.reason,
                "expires": existing.expires.isoformat() if existing.expires else None,
                "already_exists": True,
            }
    waiver = add_waiver(waivers_path(root), fingerprint=fp, reason=reason, expires=expires, root=root)
    return {
        "fingerprint": waiver.fingerprint,
        "reason": waiver.reason,
        "expires": waiver.expires.isoformat() if waiver.expires else None,
        "already_exists": False,
    }


_WAIVER_ADD_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": "Success payload of the wardline MCP `waiver_add` tool: the waiver that now covers the fingerprint "
    "(newly added, or the pre-existing one when a waiver for the fingerprint was already present).",
    "properties": {
        "fingerprint": {"type": "string", "description": "The finding fingerprint the waiver covers."},
        "reason": {
            "type": "string",
            "description": "The waiver's reason. When already_exists=true this is the EXISTING waiver's reason, which "
            "may differ from the one passed in this call.",
        },
        "expires": {
            "type": ["string", "null"],
            "description": "Waiver expiry as an ISO date (YYYY-MM-DD). Null only when a pre-existing waiver loaded "
            "from the waivers file carries no expiry (the tool itself requires expires on new waivers).",
        },
        "already_exists": {
            "type": "boolean",
            "description": "True when a waiver for this fingerprint already existed and the returned fields describe "
            "that existing waiver; false when this call added a new waiver.",
        },
    },
    "required": ["fingerprint", "reason", "expires", "already_exists"],
    "additionalProperties": False,
}


_WAIVER_ADD_TOOL: dict[str, Any] = {
    "name": "waiver_add",
    "title": "Add time-boxed waiver",
    "description": "Waive ONE finding by fingerprint with a mandatory reason and expiry. "
    "Prefer fixing; a waiver is an audited, time-boxed exception.",
    "input_schema": {
        "type": "object",
        "required": ["fingerprint", "reason", "expires"],
        "properties": {
            "fingerprint": {"type": "string"},
            "reason": {"type": "string"},
            "expires": {"type": "string", "description": "YYYY-MM-DD"},
        },
    },
    "output_schema": _WAIVER_ADD_OUTPUT_SCHEMA,
    "annotations": {
        "title": "Add time-boxed waiver",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
    "capabilities": frozenset({ToolCapability.READ, ToolCapability.WRITE}),
}


def _doctor(
    args: dict[str, Any],
    root: Path,
    *,
    started_at: float,
    filigree_url: str | None = None,
    loomweave_url: str | None = None,
) -> dict[str, Any]:
    """The CLI `doctor --fix` envelope over MCP (A2, wardline-2ee1bbda82's sibling):
    install/federation health checks via the SAME machine_readable_doctor builder,
    plus the running server's self-identification + source-freshness verdict so an
    agent can detect a stale long-lived server without shelling out. Read-only by
    default; `repair: true` is the explicit WRITE opt-in (mirrors CLI --fix).

    Both launch-flag URLs are threaded in so the url checks describe the EFFECTIVE
    config of THIS server process, with provenance — not just env (dogfood-4 B8)."""
    from wardline.install.doctor import machine_readable_doctor
    from wardline.mcp.freshness import attach_server_identity

    repair = _bool_arg(args, "repair", False)
    flag = args.get("filigree_url")
    if flag is not None and not isinstance(flag, str):
        raise ToolError("filigree_url must be a string")
    payload = machine_readable_doctor(root, fix=repair, filigree_url=flag or filigree_url, loomweave_url=loomweave_url)
    return attach_server_identity(payload, root=root, started_at=started_at)


_DOCTOR_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": "Doctor success payload: the CLI `doctor --fix` machine-readable envelope (install/federation "
    "health checks) plus the running MCP server's self-identification block and a `server.freshness` check appended "
    "to the check list.",
    "properties": {
        "ok": {
            "type": "boolean",
            "description": "True only when every check (including the appended server.freshness check) passed.",
        },
        "checks": {
            "type": "array",
            "description": "Uniform health-check verdicts: wardline.config, mcp.registration, marker_package, "
            "loomweave.url, filigree.url, decorator_grammar, scan.output_path, auth.token, filigree.auth, then "
            "server.freshness last.",
            "items": {
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "description": "Stable check identifier, e.g. 'wardline.config' or 'server.freshness'.",
                    },
                    "status": {"type": "string", "enum": ["ok", "error"], "description": "Check verdict."},
                    "fixed": {
                        "type": "boolean",
                        "description": "True when this run's repair (repair: true) corrected the underlying condition.",
                    },
                    "message": {
                        "type": "string",
                        "description": "Human/agent-readable detail. Present only when the check produced a non-empty "
                        "message (always on errors; sometimes on informational ok results).",
                    },
                },
                "required": ["id", "status", "fixed"],
                "additionalProperties": False,
            },
        },
        "next_actions": {
            "type": "array",
            "description": "One '<check id>: <message>' action line per failed check that carries a message; empty "
            "when everything is healthy.",
            "items": {"type": "string"},
        },
        "server": {
            "type": "object",
            "description": "The running MCP server's self-identification: detects a stale long-lived server (source "
            "on disk newer than process start).",
            "properties": {
                "package_version": {"type": "string", "description": "Installed wardline package version."},
                "pid": {"type": "integer", "description": "Server process id."},
                "project_root": {"type": "string", "description": "Absolute project root this server is confined to."},
                "started_at": {"type": "string", "description": "ISO-8601 UTC timestamp of server process start."},
                "source_latest_mtime": {
                    "type": ["string", "null"],
                    "description": "ISO-8601 UTC mtime of the newest *.py file under the imported wardline package, "
                    "or null when nothing was statable.",
                },
                "source_latest_path": {
                    "type": ["string", "null"],
                    "description": "Package-relative path of that newest source file, or null.",
                },
                "fresh": {
                    "type": "boolean",
                    "description": "False when on-disk package source changed after this process started — the server "
                    "is serving OLD code and must be restarted.",
                },
            },
            "required": [
                "package_version",
                "pid",
                "project_root",
                "started_at",
                "source_latest_mtime",
                "source_latest_path",
                "fresh",
            ],
            "additionalProperties": False,
        },
    },
    "required": ["ok", "checks", "next_actions", "server"],
    "additionalProperties": False,
}


_DOCTOR_TOOL: dict[str, Any] = {
    "name": "doctor",
    "title": "Install and federation health check",
    "description": "Health-check the wardline install and federation wiring "
    "(same checks as CLI `doctor --fix`: instruction blocks, skills, MCP "
    "registration, config parseability, sibling URLs, Filigree emit auth) "
    "PLUS this server's self-identification: package version, pid, start "
    "time, and a source-FRESHNESS verdict. If `server.fresh` is false this "
    "long-lived server predates the on-disk wardline code — its results are "
    "stale; restart the MCP server. Read-only by default; `repair: true` "
    "(write-gated) repairs install artifacts and re-pins a rejected "
    "federation token.",
    "input_schema": {
        "type": "object",
        "properties": {
            "repair": {
                "type": "boolean",
                "description": "Default false (pure probe, writes nothing). true repairs "
                "install artifacts (CLAUDE.md/AGENTS.md blocks, .claude/.agents skills, "
                ".mcp.json + Codex registration, .weft state dir) and, when Filigree "
                "rejected the emit token, re-pins the accepted local mint in .env.",
            },
            "filigree_url": {
                "type": "string",
                "description": "Filigree URL to probe for emit auth (default: the server's "
                "configured URL, then WARDLINE_FILIGREE_URL, then the .mcp.json arg). "
                "Only loopback origins are ever probed with a token.",
            },
        },
    },
    "output_schema": _DOCTOR_OUTPUT_SCHEMA,
    "annotations": {
        "title": "Install and federation health check",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
}


def _rekey(args: dict[str, Any], root: Path, filigree: Any = None) -> dict[str, Any]:
    """Fingerprint-scheme migration over MCP (A3): the same core.rekey the CLI drives —
    no second migration path. Probe-by-default (read-only: report match/orphans/
    collisions, write NOTHING); `apply`/`resume`/`rollback` are explicit, mutually
    exclusive, WRITE-gated. The injected Filigree emitter (apply only) re-emits under
    the new fingerprints, best-effort like the CLI's --filigree-url leg."""
    from wardline.core.rekey import (
        ORPHAN_CAUSE,
        ORPHAN_SAMPLE_LIMIT,
        STALE_CAUSE,
        Journal,
        probe,
        resume_rekey,
        rollback,
        run_rekey,
    )

    apply_ = _bool_arg(args, "apply", False)
    do_resume = _bool_arg(args, "resume", False)
    do_rollback = _bool_arg(args, "rollback", False)
    if sum((apply_, do_resume, do_rollback)) > 1:
        raise ToolError("apply, resume and rollback are mutually exclusive")
    path = _resolve_under_root(root, args["path"]) if args.get("path") else root

    def journal_block(journal: Journal) -> dict[str, Any]:
        # Lean payload: carried as a COUNT (can be the whole store), orphans as a count
        # plus a BOUNDED sample (bounded-by-default; never silent — the FULL list is
        # recorded verbatim in the migration journal on disk).
        block: dict[str, Any] = {
            "complete": journal.complete,
            "fingerprint_scheme_from": journal.fingerprint_scheme_from,
            "fingerprint_scheme_to": journal.fingerprint_scheme_to,
            "snapshot_prescheme": journal.snapshot_prescheme,
            "orphan_cause": ORPHAN_CAUSE,
            "collisions": [
                {"new_fp": c.new_fp, "old_fps": list(c.old_fps), "message": c.message} for c in journal.collisions
            ],
            "legs": [
                {
                    "name": leg.name,
                    "done": leg.done,
                    "carried_count": len(leg.carried),
                    "orphaned_count": len(leg.orphaned),
                    "orphaned_sample": list(leg.orphaned[:ORPHAN_SAMPLE_LIMIT]),
                    "debt": leg.debt,
                }
                for leg in journal.legs
            ],
            "next_pending_leg": journal.next_pending_leg(),
        }
        if not journal.complete:
            block["next_action"] = "re-run the rekey tool to finish pending leg(s)"
        return block

    if do_rollback:
        rolled = rollback(path)
        return {
            "mode": "rollback",
            "restored": list(rolled.restored),
            "note": "Filigree associations from the forward run are NOT reversed "
            "(no remap endpoint); reconcile manually if needed.",
        }
    if do_resume:
        # Resume NEVER re-scans — YAML legs re-carry from the snapshot; a pending
        # Filigree leg is deferred as debt (re-run with apply to retry it).
        return {"mode": "resume", **journal_block(resume_rekey(path))}

    # Probe (the default) and apply both need the suppression-free scan: migration
    # scans WITHOUT loading the stores it is about to rekey (they are still
    # old-scheme and would SCHEME_MISMATCH). EVERY frontend participates — the
    # stores hold RS-WL verdicts too, and a python-only scan misreads each healthy
    # Rust verdict as orphaned/stale (A7, weft-dda1a6d8dd).
    findings: list[Any] = []
    for lang in ("python", "rust"):
        result = run_scan(
            path,
            config_path=_cfg(args, root),
            cache_dir=_cache_dir_arg(args, root),
            confine_to_root=True,
            trust_local_packs=bool(args.get("trust_local_packs", False)),
            trusted_packs=_trusted_packs_arg(args),
            strict_defaults=bool(args.get("strict_defaults", False)),
            skip_suppression=True,
            lang=lang,
        )
        findings.extend(result.findings)
    if not apply_:
        report = probe(path, findings)
        return {
            "mode": "probe",
            "scanned_findings": report.scanned_findings,
            "matched": report.matched,
            # Counts + a bounded sample (A7, weft-dda1a6d8dd): never the full
            # fingerprint dump — the cut is explicit via the count.
            "orphaned_count": len(report.orphaned),
            "orphaned_sample": list(report.orphaned[:ORPHAN_SAMPLE_LIMIT]),
            "orphan_cause": ORPHAN_CAUSE,
            "stale_count": len(report.stale),
            "stale_sample": list(report.stale[:ORPHAN_SAMPLE_LIMIT]),
            "stale_cause": STALE_CAUSE,
            "collisions": [
                {"new_fp": c.new_fp, "old_fps": list(c.old_fps), "message": c.message} for c in report.collisions
            ],
            "per_store": dict(report.per_store),
            "prescheme": report.prescheme,
            "current_scheme_stores": list(report.current_scheme_stores),
            "no_op": report.no_op,
            "clean": report.clean,
        }
    return {"mode": "apply", **journal_block(run_rekey(path, findings, filigree=filigree))}


_REKEY_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": "Rekey success payload. Four shapes share the 'mode' discriminator: 'probe' (default, read-only "
    "dry run), 'apply' and 'resume' (journal block reporting the migration's per-leg state), and 'rollback' ({mode, "
    "restored, note}). All non-'mode' fields are mode-specific.",
    "properties": {
        "mode": {
            "type": "string",
            "enum": ["probe", "apply", "resume", "rollback"],
            "description": "Which rekey operation ran. 'probe' is the read-only default; 'apply'/'resume'/'rollback' "
            "are explicit, mutually exclusive write modes.",
        },
        "scanned_findings": {
            "type": "integer",
            "description": "probe only: number of findings the suppression-free scan produced (each carries an "
            "old/new fingerprint pair).",
        },
        "matched": {
            "type": "integer",
            "description": "probe only: count of distinct stored fingerprints that map to a current finding — each "
            "store is judged against ITS OWN scheme (a wlfp1 store via the migration remap, a store already at the "
            "live scheme via the current fingerprints).",
        },
        "orphaned_count": {
            "type": "integer",
            "description": "probe only: number of stored OLD-SCHEME fingerprints with no current finding — these "
            "verdicts would be dropped by an apply. Stores already at the live scheme never orphan (see stale_*).",
        },
        "orphaned_sample": {
            "type": "array",
            "items": {"type": "string"},
            "description": "probe only: bounded sorted sample of the orphaned fingerprints (counts are authoritative; "
            "an apply records the full list verbatim in the migration journal).",
        },
        "orphan_cause": {
            "type": "string",
            "description": "probe/apply/resume: fixed explanation string for why a stored fingerprint can orphan "
            "(source moved/deleted, or a custom multi-emit rule not surfacing taint_path_v0).",
        },
        "stale_count": {
            "type": "integer",
            "description": "probe only: number of CURRENT-scheme store entries matching no current finding — baseline "
            "drift, NOT migration orphans; a rekey would not touch them and they do not dirty the probe.",
        },
        "stale_sample": {
            "type": "array",
            "items": {"type": "string"},
            "description": "probe only: bounded sorted sample of the stale fingerprints.",
        },
        "stale_cause": {
            "type": "string",
            "description": "probe only: fixed explanation string for why a current-scheme entry can be stale.",
        },
        "collisions": {
            "type": "array",
            "description": "probe/apply/resume: pre-rekey fingerprints that collapse to the same new fingerprint "
            "under the new scheme; all involved old fingerprints are orphaned, not carried.",
            "items": {
                "type": "object",
                "properties": {
                    "new_fp": {
                        "type": "string",
                        "description": "The new-scheme fingerprint that more than one old fingerprint maps onto.",
                    },
                    "old_fps": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "The colliding pre-rekey fingerprints (sorted).",
                    },
                    "message": {
                        "type": "string",
                        "description": "WLN-ENGINE-FINGERPRINT-COLLISION diagnostic explaining that the colliding "
                        "verdicts are orphaned.",
                    },
                },
                "required": ["new_fp", "old_fps", "message"],
                "additionalProperties": False,
            },
        },
        "per_store": {
            "type": "object",
            "description": "probe only: open map of store file name (e.g. 'baseline.yaml') -> count of its stored "
            "fingerprints with no current finding. Only stores with orphans appear.",
            "additionalProperties": {"type": "integer"},
        },
        "prescheme": {
            "type": "boolean",
            "description": "probe only: true when a live store predates the fingerprint-scheme stamp, so orphans MAY "
            "be a fingerprint-formula change rather than source churn.",
        },
        "current_scheme_stores": {
            "type": "array",
            "items": {"type": "string"},
            "description": "probe only: store file names ALREADY at the live fingerprint scheme — a rekey is a no-op "
            "for them; their entries were matched against the current scan's fingerprints.",
        },
        "no_op": {
            "type": "boolean",
            "description": "probe only: true when every populated store already carries the live scheme — no "
            "fingerprint migration is pending and an apply would be refused.",
        },
        "clean": {
            "type": "boolean",
            "description": "probe only: true when there are no orphans and no collisions — an apply would carry every "
            "stored verdict (or, when no_op, there is simply nothing to migrate).",
        },
        "complete": {"type": "boolean", "description": "apply/resume: true when every migration leg is done."},
        "fingerprint_scheme_from": {
            "type": "string",
            "description": "apply/resume: the fingerprint scheme being migrated from (e.g. 'wlfp1').",
        },
        "fingerprint_scheme_to": {
            "type": "string",
            "description": "apply/resume: the fingerprint scheme being migrated to (e.g. 'wlfp2').",
        },
        "snapshot_prescheme": {
            "type": "boolean",
            "description": "apply/resume: true when the snapshotted stores carried no scheme stamp (pre-scheme), so "
            "orphans may be a formula change — surfaced as a caution.",
        },
        "legs": {
            "type": "array",
            "description": "apply/resume: per-leg migration state, in application order (baseline, judged, waivers, "
            "filigree).",
            "items": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Leg name: one of 'baseline', 'judged', 'waivers', 'filigree' in a journal "
                        "this code wrote.",
                    },
                    "done": {"type": "boolean", "description": "True when this leg has been applied and persisted."},
                    "carried_count": {
                        "type": "integer",
                        "description": "Number of stored verdicts re-keyed and carried forward by this leg (count "
                        "only; can be the whole store).",
                    },
                    "orphaned_count": {
                        "type": "integer",
                        "description": "Number of stored verdicts this leg dropped — never silent; the full verbatim "
                        "list is recorded in the on-disk migration journal.",
                    },
                    "orphaned_sample": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Bounded sample of the old fingerprints this leg dropped (counts are "
                        "authoritative; full list in the migration journal).",
                    },
                    "debt": {
                        "type": ["string", "null"],
                        "description": "Filigree leg only: recorded reconciliation debt when the leg soft-failed "
                        "(re-run with apply to retry); null otherwise.",
                    },
                },
                "required": ["name", "done", "carried_count", "orphaned_count", "orphaned_sample", "debt"],
                "additionalProperties": False,
            },
        },
        "next_pending_leg": {
            "type": ["string", "null"],
            "description": "apply/resume: name of the first not-done leg, or null when the migration is complete.",
        },
        "next_action": {
            "type": "string",
            "description": "apply/resume, only when the migration is INCOMPLETE: instruction to re-run the rekey tool "
            "to finish pending leg(s).",
        },
        "restored": {
            "type": "array",
            "items": {"type": "string"},
            "description": "rollback only: store file names restored from the pre-migration snapshot.",
        },
        "note": {
            "type": "string",
            "description": "rollback only: caveat that Filigree associations from the forward run are NOT reversed "
            "(no remap endpoint); reconcile manually if needed.",
        },
    },
    "required": ["mode"],
    "additionalProperties": False,
}


_REKEY_TOOL: dict[str, Any] = {
    "name": "rekey",
    "title": "Migrate fingerprint scheme",
    "description": "Re-key baseline/waiver/judged verdicts across a fingerprint-scheme "
    "change (after the engine's fingerprint formula migrates, NOT after ordinary "
    "refactors — fingerprints are line-insensitive). DEFAULT is a read-only PROBE: "
    "reports how many stored verdicts will carry, which orphan and why, and any "
    "collisions — writes nothing. Pass `apply: true` to migrate (snapshots first, "
    "resumable journal), `resume: true` to finish an interrupted migration without "
    "re-scanning, `rollback: true` to restore the pre-migration stores. The three "
    "are mutually exclusive and write-gated.",
    "input_schema": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "subdir relative to project root"},
            "config": {"type": "string"},
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
                "description": "Ignore repository-supplied custom configuration overrides (weft.toml)",
            },
            "apply": {
                "type": "boolean",
                "description": "Default false (read-only probe). true RUNS the migration: "
                "snapshot stores, write the resumable journal, carry verdicts to the "
                "new fingerprints, best-effort re-emit to a configured Filigree.",
            },
            "resume": {
                "type": "boolean",
                "description": "Finish an interrupted migration from the journal WITHOUT "
                "re-scanning (YAML legs re-carry from the snapshot).",
            },
            "rollback": {
                "type": "boolean",
                "description": "Restore the pre-migration stores byte-identical from the "
                "snapshot and remove the journal. Filigree associations are NOT reversed.",
            },
        },
    },
    "output_schema": _REKEY_OUTPUT_SCHEMA,
    "annotations": {
        "title": "Migrate fingerprint scheme",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
    },
}


def _fix(args: dict[str, Any], root: Path) -> dict[str, Any]:
    """Scan the path and apply mechanical autofixes to findings in-place."""
    path = _resolve_under_root(root, args["path"]) if args.get("path") else root
    cfg_path = _cfg(args, root)
    try:
        from wardline.core.config import load

        cfg = load(cfg_path or weft_config_path(path), explicit=cfg_path is not None)
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


_FIX_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": "Success payload of the wardline MCP `fix` tool: mechanical autofix results (PY-WL-111 "
    "assert-at-boundary rewrites), either previewed (default / dry_run) or applied in-place (apply=true).",
    "properties": {
        "fixed": {
            "type": "object",
            "description": "Open map of file path (relative to the scanned `path` argument, NOT the project root) "
            "-> list of human-readable descriptions of the fixes previewed/applied in that file. Empty object when "
            "no fixable findings were found or no fixes could be produced.",
            "additionalProperties": {
                "type": "array",
                "items": {"type": "string", "description": "Description of one fix in this file."},
            },
        },
        "applied": {
            "type": "boolean",
            "description": "True when fixes were written to disk (apply=true and not dry_run), false when this was a "
            "preview. Absent on the early-return path where the scan found no fixable findings.",
        },
        "message": {
            "type": "string",
            "description": "Human-readable summary, e.g. 'No fixable findings found.', 'Previewed fixes for N files.' "
            "or 'Applied fixes for N files.'",
        },
    },
    "required": ["fixed", "message"],
    "additionalProperties": False,
}


_FIX_TOOL: dict[str, Any] = {
    "name": "fix",
    "title": "Apply mechanical autofixes",
    "description": "Scan and apply mechanical autofixes to findings (currently only PY-WL-111 is supported).",
    "input_schema": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "subdir relative to project root to scan and fix"},
            "config": {"type": "string"},
            "dry_run": {"type": "boolean", "description": "preview changes without modifying files"},
            "apply": {"type": "boolean", "description": "must be true to modify files"},
        },
    },
    "output_schema": _FIX_OUTPUT_SCHEMA,
    "annotations": {
        "title": "Apply mechanical autofixes",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": True,
        "openWorldHint": False,
    },
    "capabilities": frozenset({ToolCapability.READ, ToolCapability.WRITE}),
}


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
        # Recorded once at construction: the doctor tool's freshness verdict compares
        # on-disk source mtimes against this to expose a stale long-lived server.
        self.started_at = time.time()
        self._tool_policy = ToolPolicy(allow_write=allow_write, allow_network=allow_network)
        self.rpc = JsonRpcServer(server_name="wardline", server_version=__version__)
        self._tools: dict[str, Tool] = {}
        self._register_tools()
        self._wire()

    def _loomweave_client(
        self,
        config_path: Path | None = None,
        *,
        strict_defaults: bool = False,
    ) -> Any:
        """Build a LoomweaveClient for this server's root, or None when no URL is set."""
        url = config_mod.resolve_loomweave_url(
            self.loomweave_url,
            self.root,
            config_path,
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
        strict_defaults: bool = False,
    ) -> Any:
        """Build a FiligreeEmitter for this server's URL, or None when no URL is set."""
        url = config_mod.resolve_filigree_url(
            self.filigree_url,
            self.root,
            config_path,
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
        strict_defaults: bool = False,
    ) -> Any:
        """Build a FiligreeIssueFiler from this server's Weft URL, or None when unset."""
        url = config_mod.resolve_filigree_url(
            self.filigree_url,
            self.root,
            config_path,
            strict_defaults=strict_defaults,
        )
        if url is None:
            return None
        from wardline.core.filigree_issue import FiligreeIssueFiler
        from wardline.filigree.config import load_filigree_token

        return FiligreeIssueFiler(url, token=load_filigree_token(self.root))

    def _register_tools(self) -> None:
        # Each tool's full declaration (schemas, annotations, capabilities) lives
        # module-level next to its handler; registration just binds it to the
        # injected-client lambda. Order is the published surface order.
        self.add_tool(
            Tool(
                **_SCAN_TOOL,
                handler=lambda args, root: _scan(
                    args,
                    root,
                    self._loomweave_client(
                        _cfg(args, root), strict_defaults=bool(args.get("strict_defaults") or False)
                    ),
                    self._filigree_emitter(
                        _cfg(args, root), strict_defaults=bool(args.get("strict_defaults") or False)
                    ),
                    trust_local_packs=bool(args.get("trust_local_packs") or False),
                    strict_defaults=bool(args.get("strict_defaults") or False),
                ),
            )
        )
        self.add_tool(
            Tool(
                **_SCAN_JOB_START_TOOL,
                handler=lambda args, root: _scan_job_start(
                    args,
                    root,
                    None if bool(args.get("local_only") or False) else self._resolved_filigree_url_for_policy(args),
                ),
            )
        )
        self.add_tool(
            Tool(
                **_SCAN_JOB_STATUS_TOOL,
                handler=_scan_job_status,
            )
        )
        self.add_tool(
            Tool(
                **_SCAN_JOB_CANCEL_TOOL,
                handler=_scan_job_cancel,
            )
        )
        self.add_tool(
            Tool(
                **_EXPLAIN_TAINT_TOOL,
                handler=lambda args, root: _explain_taint(args, root, self._loomweave_client(_cfg(args, root))),
            )
        )
        self.add_tool(
            Tool(
                **_DOSSIER_TOOL,
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
                **_ASSURE_TOOL,
                handler=lambda args, root: _assure(args, root),
            )
        )
        self.add_tool(
            Tool(
                **_DECORATOR_COVERAGE_TOOL,
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
                **_ATTEST_TOOL,
                handler=lambda args, root: _attest(
                    args,
                    root,
                    self._loomweave_client(
                        _cfg(args, root), strict_defaults=bool(args.get("strict_defaults") or False)
                    ),
                ),
            )
        )
        self.add_tool(
            Tool(
                **_VERIFY_ATTESTATION_TOOL,
                handler=lambda args, root: _verify_attestation(
                    args,
                    root,
                    self._loomweave_client(
                        _cfg(args, root), strict_defaults=bool(args.get("strict_defaults") or False)
                    ),
                ),
            )
        )
        self.add_tool(
            Tool(
                **_FILE_FINDING_TOOL,
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
                **_SCAN_FILE_FINDINGS_TOOL,
                handler=lambda args, root: _scan_file_findings(
                    args,
                    root,
                    self._filigree_emitter(
                        _cfg(args, root), strict_defaults=bool(args.get("strict_defaults") or False)
                    ),
                    self._filigree_filer(_cfg(args, root), strict_defaults=bool(args.get("strict_defaults") or False)),
                    self._loomweave_client(
                        _cfg(args, root), strict_defaults=bool(args.get("strict_defaults") or False)
                    ),
                ),
            )
        )
        self.add_tool(
            Tool(
                **_JUDGE_TOOL,
                handler=_judge,
            )
        )
        self.add_tool(
            Tool(
                **_BASELINE_TOOL,
                handler=_baseline,
            )
        )
        self.add_tool(
            Tool(
                **_WAIVER_ADD_TOOL,
                handler=_waiver_add,
            )
        )
        self.add_tool(
            Tool(
                **_FIX_TOOL,
                handler=_fix,
            )
        )
        self.add_tool(
            Tool(
                **_DOCTOR_TOOL,
                handler=lambda args, root: _doctor(
                    args,
                    root,
                    started_at=self.started_at,
                    filigree_url=self.filigree_url,
                    loomweave_url=self.loomweave_url,
                ),
            )
        )
        self.add_tool(
            Tool(
                **_REKEY_TOOL,
                handler=lambda args, root: _rekey(
                    args,
                    root,
                    # The Filigree leg only runs under apply; building the emitter is
                    # cheap and returns None when no URL resolves.
                    self._filigree_emitter(_cfg(args, root), strict_defaults=bool(args.get("strict_defaults") or False))
                    if args.get("apply")
                    else None,
                ),
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
        # B1/B2: standard MCP metadata (title / outputSchema / annotations, with
        # annotations.title for 2025-03-26 clients) ALONGSIDE the homegrown
        # "capabilities" key — mapped, not replaced, so existing consumers keep working.
        tools: list[dict[str, Any]] = []
        for t in self._tools.values():
            entry: dict[str, Any] = {"name": t.name}
            if t.title is not None:
                entry["title"] = t.title
            entry["description"] = t.description
            entry["inputSchema"] = t.input_schema
            if t.output_schema is not None:
                entry["outputSchema"] = t.output_schema
            if t.annotations is not None:
                entry["annotations"] = t.annotations
            entry["capabilities"] = [cap.value for cap in sorted(t.capabilities, key=lambda c: c.value)]
            tools.append(entry)
        return {"tools": tools}

    def _resolved_loomweave_url_for_policy(self, arguments: dict[str, Any]) -> str | None:
        return config_mod.resolve_loomweave_url(
            self.loomweave_url,
            self.root,
            _cfg(arguments, self.root),
            strict_defaults=bool(arguments.get("strict_defaults") or False),
        )

    def _resolved_filigree_url_for_policy(self, arguments: dict[str, Any]) -> str | None:
        return config_mod.resolve_filigree_url(
            self.filigree_url,
            self.root,
            _cfg(arguments, self.root),
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
            tool.name == "scan_job_start"
            and not bool(arguments.get("local_only", False))
            and self._resolved_filigree_url_for_policy(arguments) is not None
        ):
            capabilities.add(ToolCapability.NETWORK)
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
        if tool.name == "doctor":
            if bool(arguments.get("repair", False)):
                capabilities.add(ToolCapability.WRITE)
            from wardline.install.doctor import _resolve_probe_url

            flag = arguments.get("filigree_url")
            probe_url = flag if isinstance(flag, str) and flag else None
            if _resolve_probe_url(self.root, probe_url or self.filigree_url) is not None:
                # The filigree-auth probe will touch the (loopback-only) network.
                capabilities.add(ToolCapability.NETWORK)
        if tool.name == "rekey":
            if any(bool(arguments.get(k, False)) for k in ("apply", "resume", "rollback")):
                capabilities.add(ToolCapability.WRITE)
            if bool(arguments.get("apply", False)) and self._resolved_filigree_url_for_policy(arguments) is not None:
                # apply's last leg re-emits the rekeyed findings to Filigree.
                capabilities.add(ToolCapability.NETWORK)
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
        # Dual emission (B1): the text block stays byte-identical to the pre-B1 shape so
        # existing clients parsing it keep working; structuredContent carries the same
        # payload for 2025-06-18 clients. isError results never carry structuredContent.
        return {
            "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}],
            "structuredContent": payload,
        }

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
