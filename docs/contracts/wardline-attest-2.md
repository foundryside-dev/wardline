# Contract: `wardline-attest-2` (producer: wardline · consumer: warpline)

Wardline publishes a signed, full-scan, commit-pinned attest bundle. Warpline's
risk-as-verification ("Rung 2") consumes it to decide whether an entity was *proven
clean at a commit*. **Wardline is the trust authority; warpline never declares clean.**

## Bundle shape (verbatim)

`payload.boundaries[]`: `{qualname, sei, content_hash, verdict, tier}`
- `verdict` ∈ `{clean, defect, unknown}` — fail-closed 3-valued. `unknown` (undeclared /
  under-scanned / unprovable) is **never** `clean`.
- `sei`: opaque Loomweave SEI, or `null` when no Loomweave client resolved it.
- `content_hash`: entity-body span blake3 from the resolved Loomweave `EntityBinding`
  (the same granularity as Filigree's `content_hash_at_attach`), or `null` when unresolved.
  **Entity-precise** — a change to this function's body changes the hash; sibling entities
  in the same file are unaffected. A consumer MUST compare this value only against another
  entity-body hash for the same SEI, never against a whole-file hash (cross-granularity
  compare would produce permanent false-STALE; see the two-granularity ADR
  `docs/decisions/2026-06-02-wardline-hash-granularity-two-model.md`).
- `payload.commit`: the git HEAD the full scan ran against (`dirty` refused at build).
- `payload.attested_at`: the BUILD date (analysis freshness) — **NOT** a resolution time.

## Consumer rules (warpline)

1. **Temporal pin is `commit`** (+ `content_hash`), never `attested_at`. To claim
   "proven clean at commit X", match `payload.commit == X` AND the entity's current
   `content_hash` byte-equals the boundary's. This is a mechanical equality check, not a
   trust judgement.
2. **Only `verdict == "clean"` AND a matched `(commit, content_hash)` → proven-good.**
   Anything else → `risk=unavailable`. Note: `verdict == "defect"` is a distinct
   *proven-bad* signal — the engine reached a definite bad verdict — and a consumer
   MAY surface it as known-risk (not absence-of-proof). The `enrichment_reasons` triple
   below enumerates only the NOT-proven-clean-and-NOT-defect cases; it is not exhaustive
   of all non-clean outcomes.
3. **`enrichment_reasons` triple** — the three codes warpline reports when it cannot
   assert proven-good:
   - `not_attested` — no bundle for this commit (absent / commit mismatch).
   - `sei_unkeyed` — bundle present but `sei_source == "unavailable"`, so no boundary
     matches this SEI.
   - `verdict_unknown` — entity SEI-matched but `verdict == "unknown"`.
4. **Signature caveat:** HMAC-SHA256 with a shared project key is tamper-evidence within
   a key-holding domain, NOT non-repudiable proof of *who* produced the bundle.

## Versioning

A change to the boundary key set or `verdict` vocabulary is a schema bump (e.g.
`wardline-attest-3`) and must update this doc, `test_attest_contract_freeze.py`, and
warpline's consumer. Tracked under `wardline-c0563eee74`.
