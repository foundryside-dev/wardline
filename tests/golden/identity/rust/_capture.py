"""Deterministic Rust identity-capture harness (the SP2 completion gate).

The Rust sibling of ``golden.identity._capture`` — same canonical-JSON discipline
(stable named-array sorts, ``sort_keys``, relative paths only, no timestamps/host
data), reusing its ``to_json`` serializer and finding sort key.

**A PARTIAL mirror by necessity:** ``RustAnalyzer.last_context`` is ``None`` —
``RustAnalysisContext`` is not the Python ``AnalysisContext`` — so the Python
oracle's SARIF code-flows, taint facts, and explain surfaces are NOT capturable
here. The Rust identity surface is:

- **findings** — the real wire format (``Finding.to_jsonl()``) for the
  identity-bearing population (``RS-WL-* ∧ Kind.DEFECT``), produced by the REAL
  analyzer path (``run_scan(root, lang="rust")`` — discovery, crate roots, module
  routes, per-file pipeline, suppression — exactly what a scan emits).
- **entities** — qualname, ADR-049 id-kind (via the ``entity_id`` mapping, so the
  semantic ``method`` freezes as ``function``), parent, and full span of EVERY
  emitted entity across the fixture crate.
- **edges** — every anchored ``imports``/``implements`` edge
  (``discover_rust_edges`` over the same whole-tree parse products).

Engine diagnostics (``WLN-ENGINE-*`` / ``WLN-RUST-COVERAGE`` / ``Kind.METRIC`` /
``Kind.FACT``) are deliberately excluded, mirroring the Python oracle's rationale.

Imported by both ``regen.py`` (freeze) and ``test_rust_identity_parity.py`` (gate)
via ``from golden.identity.rust import _capture`` (``tests/`` is on ``sys.path``).
"""

from __future__ import annotations

import dataclasses
import json
from typing import TYPE_CHECKING, Any

from golden.identity._capture import _finding_sort_key, to_json  # type: ignore[import-not-found]
from wardline.core import config as config_mod
from wardline.core.discovery import discover
from wardline.core.finding import Finding, Kind
from wardline.core.paths import weft_config_path
from wardline.core.run import run_scan
from wardline.rust import qualname as q
from wardline.rust.analyzer import _build_overlays, _module_for
from wardline.rust.crate_roots import discover_crate_roots
from wardline.rust.edges import RustParsedFile, discover_rust_edges, index_rust_file

if TYPE_CHECKING:
    from pathlib import Path

__all__ = ["capture", "is_identity_bearing", "to_json"]


def is_identity_bearing(f: Finding) -> bool:
    """The Rust analogue of the Python oracle's predicate: ``RS-WL-* ∧ Kind.DEFECT``.

    A positive allowlist so engine diagnostics (``WLN-ENGINE-*`` FACTs, the
    ``WLN-RUST-COVERAGE`` METRIC) can never silently enter the frozen corpus.
    """
    return f.rule_id.startswith("RS-WL-") and f.kind is Kind.DEFECT


def _capture_findings(result: Any) -> list[dict[str, Any]]:
    # The REAL wire format (Finding.to_jsonl), re-parsed for canonical
    # re-serialization — identical discipline to the Python oracle.
    recs = [json.loads(f.to_jsonl()) for f in result.findings if is_identity_bearing(f)]
    return sorted(recs, key=_finding_sort_key)


def _parsed_files(root: Path) -> list[RustParsedFile]:
    """Parse + index every discovered ``.rs`` file exactly the way the analyzer
    does: same ``discover`` sweep (suffix ``.rs``, ``target/`` skipped), same
    crate-root pass, same ``_module_for`` route, relative ``path`` labels only."""
    resolved_root = root.resolve()
    cfg = config_mod.load(weft_config_path(resolved_root), explicit=False)
    files = discover(resolved_root, cfg, confine_to_root=True, suffixes=frozenset({".rs"}))
    crate_roots = discover_crate_roots(resolved_root)
    sources = {file: file.read_text(encoding="utf-8") for file in files}
    # Same Amendment-8 pre-pass as the analyzer: per-crate #[path] mount overlays.
    overlays = _build_overlays(sources, resolved_root, crate_roots)
    parsed: list[RustParsedFile] = []
    for file in files:
        module = _module_for(file, resolved_root, crate_roots, overlays)
        relpath = file.resolve().relative_to(resolved_root).as_posix()
        parsed.append(index_rust_file(source=sources[file], module=module, path=relpath))
    return parsed


def _capture_entities(parsed: list[RustParsedFile]) -> list[dict[str, Any]]:
    # EVERY emitted entity: qualname, id-kind (entity_id maps method -> function),
    # parent, full span. (path, qualname, kind) is a total key — within one file a
    # (kind, qualname) pair is unique (the per-kind twin counter guarantees it) —
    # but keep the canonical-JSON tiebreaker anyway, mirroring the Python oracle.
    rows: list[dict[str, Any]] = []
    for f in parsed:
        for e in f.entities:
            id_kind = q.entity_id(e.kind, e.qualname).split(":", 2)[1]
            loc = e.location
            rows.append(
                {
                    "qualname": e.qualname,
                    "kind": id_kind,
                    "parent": e.parent,
                    "location": {
                        "path": loc.path,
                        "line_start": loc.line_start,
                        "line_end": loc.line_end,
                        "col_start": loc.col_start,
                        "col_end": loc.col_end,
                    },
                }
            )
    return sorted(
        rows,
        key=lambda r: (
            r["location"]["path"],
            r["qualname"],
            r["kind"],
            json.dumps(r, sort_keys=True, ensure_ascii=False),
        ),
    )


def _capture_edges(parsed: list[RustParsedFile]) -> list[dict[str, Any]]:
    # The full RustEdge field set, totally ordered by its own content (the dataclass
    # fields are the whole record, so the tuple key is total).
    rows = [dataclasses.asdict(e) for e in discover_rust_edges(parsed)]
    return sorted(
        rows,
        key=lambda r: (
            r["kind"],
            r["from_id"],
            r["to_id"],
            r["source_byte_start"],
            r["source_byte_end"],
            r["confidence"],
        ),
    )


def capture(root: Path) -> dict[str, Any]:
    """Capture the full Rust identity surface for one fixture crate root."""
    result = run_scan(root, lang="rust")
    parsed = _parsed_files(root)
    return {
        "findings": _capture_findings(result),
        "entities": _capture_entities(parsed),
        "edges": _capture_edges(parsed),
    }
