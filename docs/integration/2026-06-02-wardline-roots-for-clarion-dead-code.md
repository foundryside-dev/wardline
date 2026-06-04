# Wardline → Clarion: trust boundaries as reachability roots (dead-code enrichment)

**From:** Wardline maintainer (John, with Claude)
**To:** Clarion maintainers
**Date:** 2026-06-02
**Status:** Wardline signal shipped; Clarion consumption remains additive / non-blocking
**Relates to:** Clarion `find_dead_code` plan (Part B), the "Root categorisation
tag-emission pipeline" follow-up WP, the shipped SP9 Wardline→Clarion taint-store
channel (`docs/integration/2026-05-30-wardline-clarion-taint-store-requirements.md`,
`docs/guides/clarion-taint-store.md`), ADR-028 (fail-toward-live), ADR-038 (SEI).

---

## 1. Context

Original verification against Clarion `main` on 2026-06-02 found the root-tag
pipeline absent. Re-checking Clarion on 2026-06-04 showed the generic dependency
has moved: plugin-emitted `tags` are now a typed field, normalized and persisted
into `entity_tags`, and `find_dead_code` consumes the root tag set
(`entry-point`, `http-route`, `test`, `data-model`, `cli-command`,
`exported-api`).

Clarion's `find_dead_code` (forward reachability over `calls`/`imports`
edges; candidates = `all_entities − reachable`, intersected with scope) is
**technically sound and idiomatic** — it mirrors `find_circular_imports`
(`crates/clarion-mcp/src/catalogue/shortcuts.rs:59`), reuses the honest-empty
`missing_signal` guard (`catalogue/mod.rs:134`), is bounded by `EDGE_SCAN_CAP`
(`shortcuts.rs:29`), fails toward live across confidence tiers (ADR-028), and —
critically — guards the catastrophic empty-root-set case so it can never flag a
whole repo as dead.

Wardline still does **not** write Clarion's `entity_tags` table. Its shipped
contribution is an opaque `dead_code_root` block inside each
`wardline-taint-1` fact written through the existing Wardline taint-store
channel. Clarion can either consult this store directly when assembling roots or
ingest the hint through its own tag pipeline.

## 2. The Wardline angle: trust boundaries are high-confidence roots

Reachability roots must include entities called from *outside* the static call
graph — exactly the entities that otherwise look dead because Clarion can't see
their in-edge (HTTP handlers, CLI entries, deserialization boundaries, framework
callbacks).

Wardline already knows a high-quality subset of these, **by developer
annotation, not heuristic**:

- `@external_boundary` — "external/untrusted data enters here." A function so
  annotated is, almost by definition, invoked by external/framework code Clarion
  cannot resolve statically. It is an excellent `entry-point` root.
- `@trusted` producers — declared trusted API surface; plausibly externally
  called. Maps to an `exported-api`-style root.

Because a human wrote the annotation, this is a **higher-confidence** root signal
than a structural plugin heuristic — and it directly reduces *false-dead*
findings (the costly error mode for a reachability tool).

## 3. What Wardline would contribute — and what it would NOT

**Would contribute (opt-in, additive, off the critical path):**

- A per-entity `dead_code_root` signal inside the existing `wardline-taint-1`
  blob. Trust-decorated entities carry:
  `{"is_root": true, "source": "wardline_trust_decorator", "tags":
  ["entry-point"], ...}`. Undecorated entities carry an explicit false/empty
  block.

**Explicitly out of scope (non-goals — guard against mission creep):**

- **Trust axis only.** Wardline does not know what an `http-route`, `test`,
  `data-model`, or `cli-command` is. It exposes what it already proves (trust
  boundaries) and nothing more. It will not grow a general entity classifier —
  that is Clarion's plugin-detector job.
- **Roots, not barriers.** The reflection / dynamic-dispatch barrier (flagged
  entities stay live) is Clarion's own dynamic-dispatch detection. Wardline
  contributes nothing there.
- **No unilateral writes to `entity_tags`.** Wardline does not own that table or
  the categorisation vocabulary.

## 4. Integration mechanism (Clarion's design call)

A channel already exists: SP9 has `wardline scan --clarion-url` writing
per-entity, HMAC-signed, blake3-freshness-gated facts into Clarion's
**`wardline_taint`** store (`crates/clarion-storage/src/wardline_taint.rs`) —
a table **distinct from `entity_tags`**. Wardline now emits the root hint over
that channel. Two Clarion-side consumption paths remain possible:

1. **`find_dead_code` also consults `wardline_taint`** when assembling roots —
   treat entities with a boundary fact as roots. No new Wardline write surface;
   reuses the shipped, freshness-gated channel. Lowest coupling.
2. **Clarion's tag pipeline ingests a Wardline-derived `entry-point` tag** into
   `entity_tags` (a Wardline fact → host validation → tag write), unifying it
   with the other categorisation roots.

Either way the SEI/freshness discipline already in the SP9 channel applies — a
stale boundary fact must not resurrect a since-deleted entity as a root.

## 5. Sequencing / dependency

- **Critical path = Clarion's tag-emission pipeline.** It stands alone and must
  not wait for any Wardline work.
- This enhancement is **strictly downstream**: it is inert until Clarion can
  ingest the signal (§4), and even then it only sharpens the `entry-point` /
  `exported-api` root classes. Treat it as a dependent follow-up on the Clarion
  WP, never as a blocker.
- A second precondition Clarion should name explicitly (independent of Wardline):
  the **reflection/dynamic-dispatch barrier** signals must themselves be emitted,
  or the barrier is vacuous and `find_dead_code` will produce false-dead once
  roots exist.

## 6. Ask of Clarion

Consume the shipped Wardline `dead_code_root` hint as a root source if wanted,
either directly from `wardline_taint` (§4.1) or by validated ingestion into
`entity_tags` (§4.2). Wardline's side remains additive and freshness-gated.
