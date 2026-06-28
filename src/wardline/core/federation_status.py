"""Canonical federation-status envelope: ONE builder + ONE schema source.

Every Wardline surface that reports the outcome of the optional sibling-tool
writes — the Filigree finding emit and the Loomweave taint-fact write — emits the
same ``{"filigree_emit": <status>, "loomweave_write": <status>}`` shapes. Before
this module those status dicts (and their JSON-schema ``$defs``) were hand-copied
across cli/scan, core/scan_jobs, core/scan_file_workflow, core/agent_summary, and
mcp/server — six near-identical inline copies that could (and did) drift.

This module is the single source of truth. The builders below reproduce each
surface's CURRENT bytes exactly — same keys, same key order, same null/absent
semantics — so the consolidation is behavior-preserving. The surfaces legitimately
DIFFER in context (the MCP scan response carries the discriminated transport detail
``status/auth_rejected/token_sent/url`` and orders ``disabled_reason`` second; the
CLI/scan-job blocks omit those keys; the scan_file_findings block omits
``destination`` entirely and has no loomweave_write). Those differences are
preserved via explicit flags, not collapsed — collapsing would change emitted bytes.

The JSON ``$defs`` for the MCP output schema live here too, so the schema and the
runtime builder can never drift: the schema is what the builder's bytes validate
against, and tests/conformance/test_federation_status_envelope_parity.py pins it.
"""

from __future__ import annotations

from typing import Any

from wardline.core.filigree_emit import EmitResult, filigree_destination, filigree_disabled_reason

# ---------------------------------------------------------------------------
# Filigree emit status builders
# ---------------------------------------------------------------------------


def filigree_emit_status(
    result: EmitResult | None,
    *,
    configured: bool,
    include_destination: bool = True,
) -> dict[str, Any]:
    """The result/None-based ``filigree_emit`` status block.

    Covers the CLI (``cli/scan``), the scan-job artifact (``core/scan_jobs``), and
    the one-shot scan_file_findings workflow (``core/scan_file_workflow``).

    ``configured`` is passed explicitly so the configured-true-but-no-result case
    (a dry-run where an emitter IS configured but nothing was emitted) renders
    ``disabled_reason: null`` instead of ``"not configured"`` — the scan_file
    workflow's existing None-semantics, which a result-is-None test cannot express.

    ``include_destination`` toggles the trailing ``destination`` echo: True for the
    CLI/scan-job blocks; False for scan_file_findings, whose schema has never carried
    it. The block never carries the discriminated transport detail
    (``status/auth_rejected/token_sent/url``) — that lives only on the MCP block;
    see :func:`filigree_emit_status_from_block`.
    """
    if result is None:
        block: dict[str, Any] = {
            "configured": configured,
            "reachable": None,
            "created": 0,
            "updated": 0,
            "failed": 0,
            "failures": [],
            "warnings": [],
            "disabled_reason": None if configured else "not configured",
        }
        if include_destination:
            block["destination"] = filigree_destination(None)
        return block
    block = {
        "configured": configured,
        "reachable": result.reachable,
        "created": result.created,
        "updated": result.updated,
        "failed": result.failed,
        # PDR-0023: per-finding reject reasons so a partial ingest is distinguishable from clean.
        "failures": [f.to_wire() for f in result.failures],
        "warnings": list(result.warnings),
        # The shared 401/403-vs-5xx-vs-transport ladder (dogfood #5) instead of flattening
        # every soft failure to "filigree unreachable".
        "disabled_reason": filigree_disabled_reason(
            reachable=result.reachable,
            status=result.status,
            token_sent=result.token_sent,
            url=result.url,
        ),
    }
    if include_destination:
        # N1 / C-10(a): name where findings went so a wrong-project write is visible.
        block["destination"] = filigree_destination(result.url)
    return block


def filigree_emit_status_from_block(block: dict[str, Any] | None) -> dict[str, Any]:
    """The MCP ``filigree_emit`` status block (built from a pre-computed raw block).

    The MCP scan response carries the WIDER shape: the discriminated transport detail
    (``status/auth_rejected/token_sent/url``) AND a ``disabled_reason`` at position
    two (right after ``configured``). The raw ``block`` is the dict produced by the
    MCP ``_emit_filigree`` helper (an emit attempt) or None (no emitter injected).
    The configured-false (block is None) bytes match the CLI/scan-job not-configured
    block exactly; the configured-true bytes keep MCP's distinct key set and order.
    """
    if block is None:
        return filigree_emit_status(None, configured=False, include_destination=True)
    disabled_reason = filigree_disabled_reason(
        reachable=bool(block.get("reachable")),
        status=block.get("status"),
        token_sent=bool(block.get("token_sent")),
        url=block.get("url"),
    )
    return {"configured": True, "disabled_reason": disabled_reason, **block}


def default_filigree_emit_status(*, include_destination: bool = False) -> dict[str, Any]:
    """The not-configured ``filigree_emit`` default (no emit attempted).

    ``include_destination`` defaults to False to preserve the agent_summary default,
    which has never carried ``destination`` on its bare default path. Surfaces that
    DO carry it (CLI/scan-job/MCP not-configured blocks) pass include_destination=True,
    or equivalently call ``filigree_emit_status(None, configured=False)``.
    """
    return filigree_emit_status(None, configured=False, include_destination=include_destination)


# ---------------------------------------------------------------------------
# Loomweave write status builders
# ---------------------------------------------------------------------------


def loomweave_write_status(result: Any | None) -> dict[str, Any]:
    """The result/None-based ``loomweave_write`` status block (CLI surface).

    ``result`` is a ``loomweave.client.WriteResult`` (duck-typed via getattr so the
    optional ``[clarion]`` extra need not be importable here) or None when no
    Loomweave client is configured.
    """
    if result is None:
        return default_loomweave_write_status()
    return {
        "configured": True,
        "reachable": getattr(result, "reachable", False),
        "written": getattr(result, "written", 0),
        "unresolved_qualnames": list(getattr(result, "unresolved_qualnames", ())),
        "disabled_reason": getattr(result, "disabled_reason", None),
    }


def loomweave_write_status_from_block(block: dict[str, Any] | None) -> dict[str, Any]:
    """The MCP ``loomweave_write`` status block (built from a pre-computed raw block).

    ``block`` is the dict the MCP scan path builds from a ``WriteResult`` (the
    reachable/written/unresolved_qualnames/disabled_reason fields) or None when no
    Loomweave client is injected. Byte-identical to :func:`loomweave_write_status`
    for the configured cases; both share the not-configured default.
    """
    if block is None:
        return default_loomweave_write_status()
    return {"configured": True, **block}


def default_loomweave_write_status() -> dict[str, Any]:
    """The not-configured ``loomweave_write`` default (no write attempted)."""
    return {
        "configured": False,
        "reachable": None,
        "written": 0,
        "unresolved_qualnames": [],
        "disabled_reason": "not configured",
    }


# ---------------------------------------------------------------------------
# JSON-schema $defs — ONE schema source for the MCP output schema
# ---------------------------------------------------------------------------


def filigree_emit_status_schema(*, include_transport_detail: bool = True) -> dict[str, Any]:
    """The JSON-schema for a ``filigree_emit`` status block.

    ``include_transport_detail=True`` is the canonical ``$defs/filigree_emit_status``
    used by the MCP ``scan`` output schema (carries destination + the discriminated
    transport detail). ``include_transport_detail=False`` is the narrower variant the
    scan_file_findings output schema declares inline (no destination, no transport
    detail) — matching what :func:`filigree_emit_status` emits with
    ``include_destination=False``.
    """
    properties: dict[str, Any] = {
        "configured": {"type": "boolean"},
        "reachable": {"type": ["boolean", "null"], "description": "null when not configured."},
        "created": {"type": "integer"},
        "updated": {"type": "integer"},
        "failed": {
            "type": "integer",
            "description": "Count of un-ingested findings (derived from `failures`); 0 is earned, not assumed.",
        },
        "failures": {"$ref": "#/$defs/filigree_emit_failures"},
        "warnings": {"type": "array", "items": {"type": "string"}},
        "disabled_reason": {
            "type": ["string", "null"],
            "description": "Actionable reason (auth-rejected vs server error vs unreachable vs not "
            "configured), or null when reached.",
        },
    }
    required = [
        "configured",
        "reachable",
        "created",
        "updated",
        "failed",
        "failures",
        "warnings",
        "disabled_reason",
    ]
    if include_transport_detail:
        properties["destination"] = {"$ref": "#/$defs/filigree_destination"}
        properties["status"] = {
            "type": ["integer", "null"],
            "description": "HTTP error status for soft failures; absent when not configured.",
        }
        properties["auth_rejected"] = {"type": "boolean", "description": "Absent when not configured."}
        properties["token_sent"] = {"type": "boolean", "description": "Absent when not configured."}
        properties["url"] = {"type": ["string", "null"], "description": "Absent when not configured."}
        required.append("destination")
    return {
        "type": "object",
        "description": "Normalized Filigree emit status (always an object; configured:false when no emitter).",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


# The scan_file_findings output schema is self-contained (it declares no ``$defs``),
# so its ``filigree_emit`` cannot use the ``$ref``-based canonical schema above. This
# verbatim constant — moved here from mcp/server.py — is the ONE source for that
# surface's block schema: the no-destination, no-transport-detail variant with the
# tool's own richer descriptions and an INLINE failures array. Structurally it is the
# include_transport_detail=False shape; the runtime block is built by
# ``filigree_emit_status(result, configured=..., include_destination=False)``.
SCAN_FILE_FINDINGS_FILIGREE_EMIT_SCHEMA: dict[str, Any] = {
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
        "failed": {
            "type": "integer",
            "description": "Count of findings that did NOT land in Filigree (derived from `failures`). "
            "0 here is earned from real per-finding records, not assumed — see `failures` for which and why.",
        },
        "failures": {
            "type": "array",
            "description": "PDR-0023 honesty surface: one record per finding that failed to land, so a "
            "PARTIAL ingest ('M of N emitted, K rejected because R') is distinguishable from a clean emit "
            "('all N emitted'). Empty on a clean run — but earned, not hardwired.",
            "items": {
                "type": "object",
                "properties": {
                    "reason": {
                        "type": "string",
                        "enum": ["rejected", "validation_error", "scheme_mismatch", "partial"],
                        "description": "Machine-readable failure case: rejected (Filigree refused this "
                        "finding), validation_error (malformed body), scheme_mismatch (fingerprint-scheme "
                        "drift — a join-miss, not a true-negative), partial (the whole chunk was rejected at "
                        "the protocol layer, so the cause is the request not the body).",
                    },
                    "detail": {"type": "string", "description": "Filigree's per-finding reject explanation."},
                    "reason_class": {
                        "type": "string",
                        "enum": ["rejected", "scheme_mismatch", "partial"],
                        "description": "weft-reason (G1): the canonical reason_class this failure maps to "
                        "(one of the closed 11 in contracts/weft-reason-vocab.json). validation_error maps to "
                        "rejected; the domain term stays in `reason`/`cause`.",
                    },
                    "cause": {
                        "type": "string",
                        "description": "weft-reason carrier `cause`: the why (Filigree's detail, else the "
                        "domain reason). Always present on a failure (a failure is never clean).",
                    },
                    "fix": {
                        "type": "string",
                        "description": "weft-reason carrier `fix` (MANDATORY on a non-clean carrier): the "
                        "remedial action.",
                    },
                    "fingerprint": {
                        "type": "string",
                        "description": "The wardline join key for the failed finding (absent when the "
                        "failure is chunk-wide and not attributable to one finding).",
                    },
                },
                "required": ["reason", "detail", "reason_class", "cause", "fix"],
                "additionalProperties": False,
            },
        },
        "warnings": {"type": "array", "items": {"type": "string"}, "description": "Non-fatal emit warnings."},
        "disabled_reason": {
            "type": ["string", "null"],
            "description": "Why the emit failed soft — the discriminated 401/403-vs-5xx-vs-transport "
            "ladder ('not configured', 'filigree rejected the token (401)...', 'filigree unreachable'). "
            "null means success OR no emit was attempted (dry-run / nothing selected) — read `reachable` "
            "to tell them apart (null = no attempt).",
        },
    },
    "required": [
        "configured",
        "reachable",
        "created",
        "updated",
        "failed",
        "failures",
        "warnings",
        "disabled_reason",
    ],
    "additionalProperties": False,
}


def loomweave_write_status_schema() -> dict[str, Any]:
    """The JSON-schema for a ``loomweave_write`` status block (``$defs/loomweave_write_status``)."""
    return {
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
    }
