# src/wardline/clarion/facts.py
"""SP9: project the engine's AnalysisContext into Wardline-owned taint-fact blobs.

`build_taint_facts` is a pure function of (ScanResult + root). It produces one
fact per function entity. Each fact carries:
  - `qualname`: the composed dotted form (Entity.qualname — already Clarion-conformant),
  - `wardline_json`: the opaque `wardline-taint-1` blob (Clarion stores it verbatim),
  - top-level `content_hash_at_compute` (Clarion's queryable column) — REPEATED inside
    the blob because Clarion's read never returns the column, only the blob (the
    freshness gate reads the in-blob copy).
  - `dead_code_root`: a Wardline-owned reachability-root hint for Clarion dead-code
    analysis. Wardline emits the signal in its taint facts; it never writes Clarion's
    `entity_tags` table directly.

`content_hash_at_compute` = blake3 of the entity's containing file, WHOLE FILE, RAW
BYTES (binary read — no LF translation), lowercase hex. This matches Clarion's
`current_content_hash` (clarion_storage::current_file_hash); it is NOT sha256, NOT
LF-normalized, NOT span-scoped. blake3 is imported lazily via require_blake3, so the
base package stays zero-dependency.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from wardline.clarion import require_blake3

if TYPE_CHECKING:
    from wardline.core.run import ScanResult
    from wardline.scanner.context import AnalysisContext

SCHEMA_VERSION = "wardline-taint-1"
_ROOT_REASON = "Wardline trust-decorated entity is externally reachable or trust-significant."


def _read_bytes(path: Path) -> bytes:
    """Whole file, raw bytes. Indirected so tests can spy on read frequency."""
    return path.read_bytes()


def _resolve_callee_qualname(context: AnalysisContext, qualname: str, callee: str | None) -> str | None:
    """Resolve the bare contributing-callee name to a same-module entity qualname for
    the chain walk, mirroring explain_finding's honest 1-hop rule: only when the callee
    is a simple (non-dotted) name AND `<module>.<callee>` is a known entity. Otherwise
    None — the chain can't follow this hop and will truncate explicitly."""
    if callee is None or "." in callee or "." not in qualname:
        return None
    module = qualname.rsplit(".", 1)[0]
    candidate = f"{module}.{callee}"
    return candidate if candidate in context.entities else None


def build_taint_facts(result: ScanResult, root: Path) -> list[dict[str, Any]]:
    """Build the write payloads (one per function entity). Empty list if the scan
    produced no context (no entities)."""
    context = result.context
    if context is None:
        return []
    blake3 = require_blake3()
    hash_cache: dict[str, str] = {}

    findings_by_qualname: dict[str, list[dict[str, Any]]] = {}
    for f in result.findings:
        if f.qualname is None:
            continue
        findings_by_qualname.setdefault(f.qualname, []).append(
            {
                "rule_id": f.rule_id,
                "fingerprint": f.fingerprint,
                "path": f.location.path,
                "line_start": f.location.line_start,
            }
        )

    facts: list[dict[str, Any]] = []
    for qualname, entity in context.entities.items():
        rel_path = entity.location.path
        if rel_path not in hash_cache:
            hash_cache[rel_path] = blake3.blake3(_read_bytes(root / rel_path)).hexdigest()
        # RESIDUAL (builtin-marker shadow false-green): ``content_hash_at_compute``
        # is whole-file raw-byte blake3 ONLY — it cannot observe the shadow state of
        # a builtin marker root. So identical file bytes scanned once UNSHADOWED then
        # under a project that shadows ``wardline``/``loom_markers`` could serve a
        # stale TRUSTED fact via the MCP explain_taint / Clarion read path. We do NOT
        # fold the shadow bit / provider fingerprint into this hash: it is a
        # CROSS-TOOL contract value — Clarion's read path INDEPENDENTLY recomputes
        # the whole-file blake3 (clarion_storage::current_file_hash) and compares it
        # against the in-blob copy. Mixing in a Wardline-private bit would make every
        # comparison mismatch and break fact reconciliation entirely; there is no
        # separate Wardline-owned compute-key the freshness gate consults. Closing
        # this fully needs a Clarion read-path contract change. Lower impact: this
        # path is opt-in (--clarion-url) and not the scan gate. See CHANGELOG.
        content_hash = hash_cache[rel_path]

        declared = context.project_return_taints.get(qualname)
        actual = context.function_return_taints.get(qualname)
        prov = context.taint_provenance.get(qualname)
        callee = context.function_return_callee.get(qualname)

        blob: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "qualname": qualname,
            "content_hash_at_compute": content_hash,
            "dead_code_root": _dead_code_root_blob(qualname in context.declared_qualnames),
            "taint": {
                "declared_return": declared.value if declared is not None else None,
                "actual_return": actual.value if actual is not None else None,
                "source": prov.source if prov is not None else None,
                "contributing_callee_qualname": _resolve_callee_qualname(context, qualname, callee),
                "resolved_call_count": prov.resolved_call_count if prov is not None else 0,
                "unresolved_call_count": prov.unresolved_call_count if prov is not None else 0,
            },
            "findings": findings_by_qualname.get(qualname, []),
        }
        facts.append(
            {
                "qualname": qualname,
                "wardline_json": blob,
                "content_hash_at_compute": content_hash,
            }
        )
    return facts


def _dead_code_root_blob(is_declared: bool) -> dict[str, Any]:
    if not is_declared:
        return {"is_root": False, "source": None, "tags": [], "reason": None}
    return {
        "is_root": True,
        "source": "wardline_trust_decorator",
        "tags": ["entry-point"],
        "reason": _ROOT_REASON,
    }
