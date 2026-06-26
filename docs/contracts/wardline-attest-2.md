# Contract: `wardline-attest-2` (producer: wardline · consumer: warpline)

Wardline publishes a signed, full-scan, commit-pinned attest bundle. Warpline's
risk-as-verification ("Rung 2") consumes it to decide whether an entity was *proven
clean at a commit*. **Wardline is the trust authority; warpline never declares clean.**

## Bundle shape (verbatim)

`payload.boundaries[]`: `{qualname, sei, content_hash, verdict, tier}`
- `verdict` ∈ `{clean, defect, unknown}` — fail-closed 3-valued. `unknown` (undeclared /
  under-scanned / unprovable) is **never** `clean`.
- `sei`: opaque Loomweave SEI, or `null` when no Loomweave client resolved it.
- `content_hash`: whole-file blake3 binding key, or `null` when unresolved. **File
  granularity, not entity-span** — do not key on it as entity-precise.
- `payload.commit`: the git HEAD the full scan ran against (`dirty` refused at build).
- `payload.attested_at`: the BUILD date (analysis freshness) — **NOT** a resolution time.

## Consumer rules (warpline)

1. **Temporal pin is `commit`** (+ `content_hash`), never `attested_at`. To claim
   "proven clean at commit X", match `payload.commit == X` AND the entity's current
   `content_hash` byte-equals the boundary's. This is a mechanical equality check, not a
   trust judgement.
2. **Only `verdict == "clean"` AND a matched `(commit, content_hash)` → proven-good.**
   Anything else → `risk=unavailable`.
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
