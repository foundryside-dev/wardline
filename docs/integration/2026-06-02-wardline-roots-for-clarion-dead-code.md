# Wardline → Clarion: trust boundaries as reachability roots (dead-code enrichment)

**From:** Wardline maintainer (John, with Claude)
**To:** Clarion maintainers
**Date:** 2026-06-02
**Status:** Proposal / dependent enhancement — **must not block** Clarion's dead-code WP
**Relates to:** Clarion `find_dead_code` plan (Part B), the "Root categorisation
tag-emission pipeline" follow-up WP, the shipped SP9 Wardline→Clarion taint-store
channel (`docs/integration/2026-05-30-wardline-clarion-taint-store-requirements.md`,
`docs/guides/clarion-taint-store.md`), ADR-028 (fail-toward-live), ADR-038 (SEI).

---

## 1. Context (verified against Clarion `main`, 2026-06-02)

Clarion's planned `find_dead_code` (forward reachability over `calls`/`imports`
edges; candidates = `all_entities − reachable`, intersected with scope) is
**technically sound and idiomatic** — it mirrors `find_circular_imports`
(`crates/clarion-mcp/src/catalogue/shortcuts.rs:59`), reuses the honest-empty
`missing_signal` guard (`catalogue/mod.rs:134`), is bounded by `EDGE_SCAN_CAP`
(`shortcuts.rs:29`), fails toward live across confidence tiers (ADR-028), and —
critically — guards the catastrophic empty-root-set case so it can never flag a
whole repo as dead.

But the tool is **born inert**: its root set comes entirely from `entity_tags`,
and **no production code emits any categorisation tag today**. There is no
`INSERT INTO entity_tags` outside the test fixtures
(`crates/clarion-mcp/tests/catalogue_tools.rs:98`), and no `tags` field on the
plugin/scanner entity protocol record. The entire catalogue-shortcuts family
(`find_entry_points`, `find_http_routes`, `find_data_models`, `find_tests`, …)
is already born-inert for the same reason (each carries a "…not emitted by the
active plugins" honest-empty note, `shortcuts.rs:249–330`).

So the real unlock is Clarion's **root/barrier tag-emission pipeline**
(plugin detectors → protocol `tags` field → host validation → `entity_tags`
write), not `find_dead_code` itself. **That pipeline is wholly Clarion's
engineering work; Wardline has no role in building it.** This document is about
one *additive* signal Wardline can contribute once that pipeline exists.

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

- A per-entity signal that an entity is a Wardline trust boundary
  (`external_boundary` / `trusted`), suitable for inclusion in Clarion's
  reachability **root** set.

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
a table **distinct from `entity_tags`**. Two plausible paths, both Clarion-side
decisions:

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

Confirm whether the Wardline boundary signal is wanted as a root source, and if
so which mechanism (§4.1 vs §4.2). No Wardline-side work begins until that's
confirmed — this doc is the standing offer, tracked on the Wardline side as a
dependent issue.
