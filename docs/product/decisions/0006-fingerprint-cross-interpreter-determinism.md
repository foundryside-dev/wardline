# PDR 0006 — Fingerprint join-key made cross-interpreter deterministic (match-3.13, no scheme bump)

`Date: 2026-06-28` · `Status: Accepted` · `Decider: product-owner agent (within grant —
soundness bugfix; no fingerprint-scheme bump, no release)`

## Context

While dispatching crit-3, the open PR #69's **Python 3.12 CI matrix leg was red** — 5 golden
tests (`test_identity_corpus_is_byte_identical` ×3, `test_golden_matches_live_producer`,
`test_builtin_findings_match_golden`) — and had been red since before this session
(unrelated to crit-3). Root cause: CPython 3.13's `ast.dump` changed its default to
`show_empty=False`, which **omits empty-list fields** (`posonlyargs=[]`, `decorator_list=[]`,
`type_params=[]`, …) that 3.12 still emits. `entity_source_fingerprint` hashed `ast.dump`
output, so the **cross-tool fingerprint JOIN KEY** (baseline / waiver / judged stores + the
Filigree wire) was **interpreter-dependent** — wardline under 3.12 vs 3.13 minted different
fingerprints for identical source, and the 3.13-frozen identity corpus drifted on 3.12.

This is a real soundness hole, not cosmetic: an interpreter-dependent join key can silently
**drop a finding on a join** (the collision/instability class the identity corpus exists to
guard) — the same blast-radius family as a confident-empty seam.

## Options

- **(a) Re-freeze the corpus on 3.12.** *Rejected:* breaks 3.13; just moves the drift.
- **(b) Version-independent custom serializer + re-freeze + scheme bump `wlfp2`→`wlfp3`.**
  *Rejected:* breaking — orphans **all** users' baselines/waivers/Filigree joins, needs a
  rekey migration, and changes the working 3.13 reference values. A sledgehammer for a
  one-interpreter bug.
- **(c) Structural canonical dumper reproducing 3.13's `show_empty=False` form on every
  interpreter, byte-identical to 3.13's `ast.dump`.** *Chosen.*

## The call

Ship option (c). `_canonical_ast_dump` structurally omits empty-list fields (and
None-default optionals, matching `ast.dump`), **verified node-for-node equal to 3.13's
`ast.dump`** across the fixtures (corpus hash identical 3.12 == 3.13). 3.13 values are
**byte-unchanged** → **no corpus re-freeze, no scheme bump**; only the broken 3.12 values
converge to the 3.13 reference. Done **structurally, not by regex** on the dump string,
because a string literal `"x=[]"` renders as `Constant(value='x=[]')` and a text strip would
corrupt the key.

Commit `b6704c00`. **Verified:** full suite 3.12 **4478 passed** (was 5 failed), 3.13
unchanged; the 5 goldens green on both interpreters; ruff/mypy clean; **PR #69 CI overall
green**.

## Rationale

Keeping the 3.13 reference values stable means **zero blast radius for the canonical
interpreter** — no migration, no orphaned joins — while closing the latent silent-drop
hazard on 3.12. Within grant: internal bugfix, no scheme/contract bump, no release.

## Reversal trigger

Metric-bound, tied to `metrics.md` **G2** (soundness / join-key integrity):
1. **Future `ast.dump` divergence.** If a later CPython changes `ast.dump` in a way the
   empty-list normalization doesn't cover, the CI matrix parity test reds → extend
   `_canonical_ast_dump` (the matrix is the standing guard).
2. **Observed collision/instability.** A real fingerprint collision or a soundness-lock
   failure on a join is a **P0**.
3. **`ast.unparse` display drift** (obs `wardline-obs-db89aac030`) — promote to a fix if any
   `ast.unparse` site (dossier/decorator_coverage/autofix) ever feeds a frozen golden or a
   `content_hash`.

## Release consideration (owner gate)

This changes 3.12 fingerprint **values** (they were never stable, so this is a correction,
not a contract change — no scheme bump). When the consolidation branch is released, any user
on 3.12 with existing baselines/waivers will re-key once (their old 3.12 values were not the
3.13 reference). Flag this as a one-line **release note**; it is not actioned by this
checkpoint.
