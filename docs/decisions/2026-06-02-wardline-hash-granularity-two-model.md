# ADR: Two content-hash granularities (whole-file vs entity-body), never cross-compared

- **Status:** Accepted
- **Date:** 2026-06-02
- **Resolves:** Track 5 T5.3 (content-axis hash-granularity harmonisation; SEI
  conformance standard §2 granularity note)

## Context

Loom computes content freshness on the **content axis** — "has this entity's code
changed since we recorded a fact / a binding about it?" Across the suite, two
*different* hashes answer two *different* questions, and they are computed over
different spans:

- **Whole-file** — Wardline's taint-fact `content_hash_at_compute` is a blake3 of
  the entity's *entire containing file*, raw bytes (`clarion/facts.py`). It is
  defined to byte-equal Clarion's `current_file_hash`
  (`clarion_storage::current_file_hash`), because the taint-store freshness gate
  must decide "is this stored fact still fresh?" against the live file Clarion
  serves. This is the **taint-store freshness** granularity.
- **Entity-body** — Clarion's identity-resolve `content_hash` is the hash of *the
  entity's body span* only, and Filigree's `content_hash_at_attach` (ADR-029
  entity associations) stores that same entity-body hash at attach time. This is
  the **identity / association drift** granularity: "did *this function's body*
  change?", independent of unrelated edits elsewhere in the file.

These are not interchangeable. A whole-file hash changes when *anything* in the
file changes; an entity-body hash changes only when *that entity* changes. The
SEI conformance standard §2 explicitly flags that the two must not be conflated.

The risk is a silent **false-`STALE`**: comparing Wardline's whole-file
`content_hash_at_compute` against Clarion's entity-body `content_hash` would
almost always differ (different spans), reporting a fresh entity as stale forever.

## Decision

**Wardline maintains two granularities for two purposes and never compares across
them.** Specifically:

1. **Whole-file** is used *only* for taint-store freshness — the
   `content_hash_at_compute` Wardline writes and the freshness gate Clarion
   applies. It is paired only with `current_file_hash` (same granularity, by
   construction).
2. **Entity-body** is used *only* for identity/association drift — the dossier
   compares Clarion's resolve `content_hash` against Filigree's
   `content_hash_at_attach` (both entity-body), never against
   `content_hash_at_compute`.
3. **`content_status` is the single chokepoint** and is granularity-agnostic by
   contract: it compares two hashes *the caller guarantees are the same
   granularity* and returns `FRESH`/`STALE`; if either side is absent it returns
   `UNKNOWN` — **never a guessed `FRESH` and never a cross-granularity
   `STALE`**. Its docstring states the same-granularity precondition explicitly.

We do **not** add an entity-body hash to Wardline's taint facts, and we do **not**
change the shipped whole-file freshness gate. Unifying to a single granularity was
considered and rejected: it would either break the SP9 store's byte-for-byte
freshness contract with Clarion (if we dropped whole-file) or require reaching
into Clarion/Filigree (out of Wardline's lane), and nothing today consumes a
unified value. "Resolved + suite-consistent" therefore means **formalised and
tested**, not collapsed to one value.

## Consequences

- **Honest, never false-green.** A granularity mismatch surfaces as `UNKNOWN`, not
  a fabricated verdict. The dossier's content axis stays honest.
- **No breaking change.** The taint-store fingerprint/freshness contract is
  untouched; baselines/waivers and warm/cold byte-identity are unaffected.
- **A discipline to uphold.** Because the two hashes are both opaque hex strings,
  nothing at the type level prevents a future caller from passing one where the
  other is expected. This ADR + the T5.3 discipline tests
  (`tests/conformance/test_hash_granularity.py`) encode the invariant: each
  surface uses the correct granularity, and `content_status` is only ever called
  with same-granularity inputs.
- **If a unified freshness verdict is ever needed** across the whole-file ↔
  entity-body boundary, the additive path (compute an entity-body hash in Wardline
  *alongside* the whole-file one, leaving the store gate unchanged) remains open as
  a future, separately-justified change — not taken now (YAGNI).

## References

- `src/wardline/clarion/identity.py` — `content_status`, `ContentStatus`, the
  same-granularity precondition.
- `src/wardline/clarion/facts.py` — `content_hash_at_compute` (whole-file).
- `src/wardline/filigree/dossier_client.py` — entity-body drift compare.
- SEI conformance standard §2 (granularity note).
