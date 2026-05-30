# src/wardline/clarion/facts.py
"""SP9: project the engine's AnalysisContext into Wardline-owned taint-fact blobs.

`build_taint_facts` is a pure function of (ScanResult + root). It produces one
fact per function entity. Each fact carries:
  - `qualname`: the composed dotted form (Entity.qualname — already Clarion-conformant),
  - `wardline_json`: the opaque `wardline-taint-1` blob (Clarion stores it verbatim),
  - top-level `content_hash_at_compute` (Clarion's queryable column) — REPEATED inside
    the blob because Clarion's read never returns the column, only the blob (the
    freshness gate reads the in-blob copy).

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
from wardline.core.run import ScanResult

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext

SCHEMA_VERSION = "wardline-taint-1"


def _read_bytes(path: Path) -> bytes:
    """Whole file, raw bytes. Indirected so tests can spy on read frequency."""
    return path.read_bytes()


def _resolve_callee_qualname(
    context: AnalysisContext, qualname: str, callee: str | None
) -> str | None:
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
            {"rule_id": f.rule_id, "fingerprint": f.fingerprint,
             "line_start": f.location.line_start}
        )

    facts: list[dict[str, Any]] = []
    for qualname, entity in context.entities.items():
        rel_path = entity.location.path
        if rel_path not in hash_cache:
            hash_cache[rel_path] = blake3.blake3(_read_bytes(root / rel_path)).hexdigest()
        content_hash = hash_cache[rel_path]

        declared = context.project_return_taints.get(qualname)
        actual = context.function_return_taints.get(qualname)
        prov = context.taint_provenance.get(qualname)
        callee = context.function_return_callee.get(qualname)

        blob: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "qualname": qualname,
            "content_hash_at_compute": content_hash,
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
        facts.append({
            "qualname": qualname,
            "wardline_json": blob,
            "content_hash_at_compute": content_hash,
        })
    return facts
