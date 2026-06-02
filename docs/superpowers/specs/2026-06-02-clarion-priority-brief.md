# Clarion — priority brief ("what to get on with first")

**Date:** 2026-06-02
**Status:** Directive / suite-coordination brief (companion to Clarion's own
`2026-06-01-clarion-roadmap-to-first-class.md`, the SEI standard, and the goal-state
case study). High-level — *what* and *in what order*, not *how*; Clarion owns the
implementation plan.
**Audience:** the agent(s) building Clarion.

> **One-line ask:** Clarion is the critical path to "core paradise" (the one-call
> mastery read that survives a rename). Three of its items are **un-gated,
> paradise-critical, and start today**: **HTTP linkages**, **prior-index
> retention**, and **deciding REQ-C-01 / REQ-C-02 so SEI can lock**. Do these
> first — they unblock three sibling tools that are otherwise ready and waiting.

---

## 1. Why this brief exists

The suite-wide assessment is blunt: **Filigree and Wardline are essentially done
waiting** — their halves of every cross-tool binding are already built. **legis is
a parallel greenfield track** that the *core* loop does not depend on. The core
paradise loop is **Wardline + Clarion + Filigree**, and it gates almost entirely on
**Clarion**.

The striking part: Clarion's blockers are **its own autonomous work**, not
cross-tool negotiation. Nothing is waiting on an unmade decision or an unsettled
contract (the four-way SEI reconciliation is done — see SEI spec §0.5). The suite
moves as fast as Clarion executes these specific items.

This brief does **not** replace Clarion's roadmap; it **reorders** it from the
suite's point of view. One honest tension to name up front: Clarion's roadmap ranks
**MCP-catalogue completion (its M1)** as its highest-leverage autonomous item, and
for Clarion *as a standalone consult tool* that is correct. But for **suite
paradise**, the identity + linkage + lock items dominate, because each unblocks
work three other tools have already finished their half of. This brief asks Clarion
to prioritise the **suite-unlocking** items ahead of the standalone-polish ones.
M1/M2/M7 remain important — they are not cancelled, just sequenced behind the
critical path.

---

## 2. The priority stack

### P0 — start now (autonomous, un-gated, paradise-critical)

| Item | Clarion roadmap ref | Why it's P0 | Unblocks |
|---|---|---|---|
| **HTTP linkages** — `callers`/`callees` (+ batch) over the HTTP read API, with pagination + confidence-tier filtering and a `linkages: { http: true }` capability flag | M4 | Linkages are MCP-only today; the dossier's structural half needs them over HTTP. Gated on nothing. | The dossier (with SEI); any HTTP linkage consumer |
| **Prior-index retention** — a lightweight keyed side table (SEI↔locator + body-hash + signature), persisted across re-index, cleared only on `--force` | M3 | Prerequisite for the SEI matcher **and** file-level incremental analysis. Its **durability is the real protection against cold-rebuild orphaning** (more than the token scheme). Shape-independent — safe before lock. | SEI matcher; incremental `analyze` |
| **Decide REQ-C-01 and REQ-C-02** (§3 below) | App. A | These are *decisions*, not large builds — and they are the last thing between "all four reported" and **SEI lock**. Cheap, high-leverage. | SEI lock → all SEI work |

### P1 — after SEI lock

| Item | Ref | Gate |
|---|---|---|
| **SEI authority** — minting, deterministic fail-closed matcher, append-only lineage, wire contract (`resolve` / `resolve_sei` / `lineage` / `_capabilities`) | M5 | SEI lock (which P0's decisions unblock) |
| **Hard cutover migration** — coordinated Clarion + Filigree + Wardline release; mint SEIs, run the backfill, flag unresolvable orphans | M5 | SEI authority shipped; one scheduled release (we own all four release cycles) |

### P2 — closes the core loop

| Item | Ref | Gate |
|---|---|---|
| **Dossier participation** — structural + identity contribution to the one-call read (Clarion contributes its slice; it is **not** the assembler) | M6 | HTTP linkages (P0) **+** SEI (P1) — both internal |

### Parallel / later (valuable, but not on the core critical path)

- **MCP-catalogue completion + guidance maturity** (M1, M2) — Clarion's standalone
  first-class bar. Do in parallel as capacity allows; high value for consult-mode
  agents, but the suite loop does not gate on it.
- **Multi-language plugin** (M7) — autonomous; North-Star generality.
- **Governance consumption** (M8) — gated on legis; thin on Clarion's side.

---

## 3. The two decisions to make now

Both are recorded **OPEN, owned by Clarion** in SEI spec §0.5 — the spec
deliberately did not pre-empt them. They need Clarion's ruling before lock.

### REQ-C-01 — formalise "signature"

The matcher's *move* case ("identical body hash and identical signature at a new
module") depends on a "signature" Clarion does not yet store as a discrete field.
**Decide:** a versioned, plugin-supplied signature schema (the property is fixed —
*versioned, discrete, plugin-declared*; the exact fields are Clarion + plugin's
call). Until defined, the move case is under-specified and implementations diverge.

### REQ-C-02 — the SEI token scheme

The property the token must satisfy: **opaque + stable + collision-free under
locator reuse + preserves Clarion's byte-identical-run determinism.** A finding to
weigh before you pick:

- `clarion:eid:<ulid>` embeds a timestamp → **breaks Clarion's determinism
  guarantee.**
- `blake3(locator-at-birth)` (Clarion's stated preference) has **two flaws**: it
  **collides on locator reuse** (delete `m:func:f`, a new one is later born → same
  token, new entity inherits the dead one's identity); and it **does not survive a
  cold `--force` rebuild after a rename** (re-mints from current state → a different
  token → orphans the renamed entity *regardless of scheme*).
- The real cold-rebuild protection is **side-table durability (REQ-C-03)**, not the
  token construction. So pick the token for *determinism + collision-freedom* (e.g.
  content-address over locator **plus a birth-uniqueness component** like
  `first_seen_commit`), and rely on the side table for robustness.

The §8 oracle stays **token-format-agnostic** — it tests behaviour and opacity, not
the token's internal form — so this choice is genuinely Clarion's, with the one
constraint that the oracle must not have to assume a time-ordered token.

---

## 4. Invariants to hold while building

- **Opacity.** SEI is opaque; consumers never parse it. The token's internal form
  is Clarion's business.
- **No binding keyed on a locator, on *any* surface [REQ-C-04].** Every surface
  that returns an identity for use as a binding key — HTTP read API **and** the MCP
  tool surface — carries the **SEI**. A locator may also appear, labelled as the
  (mutable) address. No "MCP locator exception" — that is a false-green.
- **Fail-closed / no-false-green.** When the matcher cannot *prove* sameness, mint a
  new SEI and mark the old `orphaned` — never silently re-point. Honest `UNKNOWN`
  over a confident guess.
- **Typed git-rename interface [REQ-C-05].** Source git-rename in Clarion for v1,
  but **behind a typed `git-rename signal` interface** (`{old_locator, new_locator,
  commit, …}`) so legis can later supply it without touching the SEI model. Shape
  the seam now; legis has claimed it as the planned first provider.
- **Lineage tamper-evidence is consumer-side in v1 [REQ-L-01].** Serve `lineage`
  from an append-only store with **no backfill path**; do **not** build a
  Clarion-side hash-chain/signature in v1 (legis re-establishes integrity at its own
  boundary — custody axiom). Signed lineage is North Star, not now.

---

## 5. Scope boundaries (what *not* to do)

- **Clarion is not the dossier assembler.** It contributes its slice (structure +
  identity + linkages); the consumer (Wardline) composes the envelope. Do not
  aggregate Wardline taint facts or Filigree issues.
- **Clarion is not the trust-vocabulary lead.** Carry `declared_tier` /
  `wardline_groups` verbatim; Wardline owns the grammar, legis governs it. Clarion
  does not adjudicate trust.
- **Do not over-build the migration.** Single hard cutover; no mixed-format
  tolerance, no migration window, no generation marker — we control all four release
  cycles, so it is a scheduling problem (SEI §7.1).
- **Do not build a lineage push/event surface.** Pull-only polling for v1; a push
  surface is Loom-URI-class apparatus, explicitly out of scope (SEI §9).
- **Prior-index is a side table, not a snapshot.** Not a retained prior
  `clarion.db`; do not let the requirement inflate into "keep the whole prior DB."

---

## 6. Definition of done / unlock map

- **P0 done →** the dossier's structural half is reachable over HTTP, the matcher
  has its prior state, and **SEI can lock**.
- **SEI lock + P1 done →** identity is refactor-stable; the hard cutover re-keys
  every existing binding; Filigree's backfill and Wardline's SEI-client (both thin,
  both ready) light up immediately after.
- **P2 done →** `dossier(entity)` returns a complete, freshness-stamped, SEI-keyed
  envelope. **Core paradise reached.**
- legis's governance layer then lands in parallel for *complete* (governed)
  paradise; it does not gate the above.

The headline for Clarion: **you are the long pole, but nothing is blocking you.**
Every P0 item is yours to start today, with no dependency on another tool and no
unmade decision in your way except the two that are explicitly yours to make.
