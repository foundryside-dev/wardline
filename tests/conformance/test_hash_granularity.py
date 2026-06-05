"""T5.3 — content-hash granularity discipline (the two-granularity invariant).

Weft uses two content-hash granularities for two purposes and NEVER compares
across them (see `docs/decisions/2026-06-02-wardline-hash-granularity-two-model.md`):

  - whole-file   — taint-store freshness (`content_hash_at_compute` <-> Loomweave
                   `current_file_hash`);
  - entity-body  — identity / association drift (Loomweave resolve `content_hash`
                   <-> Filigree `content_hash_at_attach`).

The behavioral pieces are pinned elsewhere (the whole-file taint hash in
`tests/unit/loomweave/test_facts.py`; the entity-body drift compare in
`tests/unit/filigree/test_dossier_client.py`; the FRESH/STALE/UNKNOWN truth table
in `tests/unit/loomweave/test_sei_identity.py`). This module locks the two
cross-cutting INVARIANTS that keep them honest:

  1. `content_status` never fabricates a verdict — a missing hash is UNKNOWN, never
     a false-STALE (the failure mode a cross-granularity compare would cause);
  2. `content_status` is only *called* from the sanctioned entity-body surface, so
     a whole-file hash can never be wired into it by a future change.
"""

from __future__ import annotations

from pathlib import Path

from wardline.loomweave.identity import ContentStatus, content_status

_SRC = Path(__file__).resolve().parents[2] / "src" / "wardline"


def test_content_status_never_false_stale_on_missing() -> None:
    # Property: with either side absent, the verdict is UNKNOWN — never STALE and
    # never a guessed FRESH. This is the guard that makes a granularity mismatch
    # (one side simply not obtainable) honest rather than a fabricated drift.
    for stored in (None, "h"):
        for current in (None, "h"):
            result = content_status(stored, current)
            if stored is None or current is None:
                assert result is ContentStatus.UNKNOWN
            else:
                assert result is ContentStatus.FRESH  # same-granularity, equal
    # different same-granularity hashes are the ONLY way to get STALE
    assert content_status("a", "b") is ContentStatus.STALE


def test_content_status_is_only_called_from_the_entity_body_surface() -> None:
    # Discipline guard: `content_status` is granularity-agnostic, so nothing at the
    # type level stops a caller passing a WHOLE-FILE hash where an entity-body hash
    # is expected. The only sanctioned live call site is the Filigree drift compare
    # (entity-body vs entity-body). If a new caller appears — especially in a
    # whole-file context like loomweave/facts.py — this reds, forcing a granularity
    # review (per the T5.3 ADR).
    sanctioned = {"dossier_client.py"}
    offenders: list[str] = []
    for path in _SRC.rglob("*.py"):
        if path.name == "identity.py":
            continue  # the definition module (def + a docstring usage example)
        text = path.read_text(encoding="utf-8")
        if "content_status(" in text and path.name not in sanctioned:
            offenders.append(str(path.relative_to(_SRC)))
    assert offenders == [], (
        f"content_status called outside the sanctioned entity-body surface {sanctioned}: "
        f"{offenders} — verify the hashes are entity-body, then add to the allowlist "
        f"(see docs/decisions/2026-06-02-wardline-hash-granularity-two-model.md)"
    )
