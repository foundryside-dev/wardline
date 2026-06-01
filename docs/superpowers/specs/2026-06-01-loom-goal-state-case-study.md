# Loom — goal state & design case study

**Date:** 2026-06-01  
**Status:** Living reference (umbrella over the SEI, dossier, and trust-declaration specs)  
**Scope:** The target architecture for the **Loom** suite — Wardline (analysis),
Clarion (code intelligence), Filigree (issue tracking), and the planned `legis`
(governance + git interface) — and the design reasoning that produced it. Both a
north star to converge on and a case study of the decisions behind it.

---

## 1. What Loom is converging on (the goal state)

Four subsystems, one author, **one shared substrate**: a codebase modelled as
**entities**, each carrying typed facts produced by different tools, all keyed on
a single durable identity, all freshness-honest, all consumable in one call.

```
                    ┌──────────────── the entity (one durable identity: SEI) ───────────────┐
   Wardline ──taint facts──►                                                                  │
   Clarion  ──structure/linkages/lineage──►   [ Clarion: identity authority + fact store ]    │
   legis    ──governance attestations──►                                                      │
   Filigree ──issue associations──►                                                           │
                    └──────────────────────────────────────────────────────────────────────┘
                                              ▲
                          one freshness-honest read: dossier(entity) / traverse(...)
                                              ▲
                                          a coding agent
```

At goal state:

- **Identity is stable across refactors.** A function keeps its identity through
  rename/move/edit (**SEI** — Stable Entity Identity), so every cross-tool binding
  survives the operations developers actually perform instead of silently
  orphaning. Clarion mints and carries it; everyone else keys on it.
- **Every fact is freshness-honest.** Two orthogonal axes — *is this the same
  entity?* (SEI alive/orphan) and *has its code changed?* (content hash
  fresh/stale) — are always explicit. Nothing stale is served unlabelled
  ("no false-green").
- **An agent reaches mastery in one call.** The **dossier** returns a function's
  trust posture, decorators, linkages, recent history, and open work as one typed,
  token-bounded, freshness-stamped envelope — no reading a hundred lines across
  three tools.
- **Governance is an opt-in layer, not a tax.** `legis` adds IRAP-grade governance
  (attestations, sign-offs, custody, audit lineage) and owns the git interface —
  invisible until switched on, so a solo "vibe coder" pays nothing and a regulated
  team gets everything.
- **Conformance is proven, not assumed.** Each subsystem demonstrates conformance
  to the shared standards via a shared **oracle**; no subsystem is grandfathered,
  including ones that "feel done."

The test of "done": a coding agent can ask *"what is true of this function, and
what should I do about it?"* and get a complete, current, cited answer — and that
answer stays correct when the function is renamed tomorrow.

---

## 2. The unifying axiom

One principle underlies every standard in this suite. It is worth stating once,
plainly, because both major standards (SEI for identity, the trust model for
data) are instances of it:

> **A property follows the *author* of a value — not the container, the format,
> or the database it passed through. Persistence interrupts custody; you
> re-establish the property at each handoff; only the *response* to a broken seal
> differs.**

- **Trust** (Wardline's lattice; elspeth's tiers; `legis`'s governance): trust
  attaches to whoever *authored* the data. A trusted courier (our own plugin, our
  own DB) does not launder external-origin data into trust. Re-reading persisted
  external data is a fresh boundary. Broken seal → crash if it's *our* data
  (corruption of our evidence), quarantine if it's *external* (a dented parcel).
- **Identity** (SEI): identity attaches to the *authored entity*, not to its
  qualname, file path, or storage row. A rename changes the address, never the
  identity. Storage interrupts custody; Clarion re-establishes identity via a
  matcher at each re-index; broken seal → orphan (our-authored facts) handled
  honestly, never silently re-pointed.

Identity custody and trust custody are the same idea twice. Designing each new
Loom standard as an instance of this axiom is what keeps the suite coherent.

---

## 3. The case study — how we got here

A worked example of the reasoning, preserved because the *method* generalises.

**Symptom.** Each subsystem was running on a different version of "the federation
spec." A planned cross-tool standard (the **Loom URI** scheme — `loom://` +
registry + multi-fetch) had been specified but **never implemented**, superseded
in practice by a simpler shipped binding (ADR-029 entity-associations). Result:
divergence, and bindings that broke on ordinary refactors.

**Verification before design.** Rather than trust the docs, we read the actual
source of all three tools. Findings that changed the design:
1. Clarion's entity id is **derived from name + module path** and **not
   refactor-stable** — a rename/move *orphans* every fact and association on it.
   (ADR-003 had even named a deferred `EntityAlias` seam for exactly this.)
2. Clarion **linkages are MCP-only, not HTTP** — a real build gap, not a thin read.
3. Filigree is **done/frozen** and stores the id as an **opaque string**, computing
   no drift (the consumer does).
4. Two different freshness granularities already existed (Wardline whole-file vs
   Filigree entity-body).

**The diagnosis.** Loom **conflated identity with address.** The qualname is a fine
address and a terrible identity, because rename/move change it.

**The decision.** Introduce **SEI**: a durable, opaque surrogate identity, with the
qualname demoted to a resolvable *locator*. This is the **minimal salvage** of the
abandoned Loom-URI effort — keep the stable identity it was reaching for, drop the
registry/multi-fetch apparatus that made it too heavy to ship. Crucially, because
Filigree treats the id as opaque, **the standard is adoptable across a frozen
member with zero code change** (only the stored *value* changes).

**The governance choices.** Fail-closed re-binding (never silently carry an
identity across an unproven match — essential for a substrate governance will
attest against). Deterministic-only matcher in v1 (fuzzy is North Star).
Conformance proven via a shared oracle, no grandfathering.

**The discipline that made it land.** A hard reset on the *track* ("this is the
interface, it supersedes your divergent versions") but an open *shape* — SEI is
**not yet locked**; each subsystem contributes its still-emerging requirements
before a defined lock gate. Mandate the direction; ratify the details.

**What this produced** (this session's artifacts):
- `2026-06-01-loom-stable-entity-identity-conformance.md` — the SEI standard.
- `2026-06-01-wardline-loom-entity-dossier-design.md` — the one-call mastery read.
- `2026-06-01-wardline-explicit-trusted-body-return-design.md` +
  `2026-06-01-wardline-config-trust-declarations-design.md` — Wardline's trust
  vocabulary work (the seed of the *next* conformance domain — §5).

---

## 4. Reusable principles (the lessons)

These are the transferable takeaways, independent of Loom:

1. **Verify ground truth before designing.** Read the source, not the docs;
   aspiration and implementation had diverged on every load-bearing point.
2. **Separate the concerns that drift.** Identity / address / freshness were one
   thing; splitting them dissolved the bug. (So too trust / type / value.)
3. **Minimal salvage beats grand rebuild.** The abandoned standard was right about
   *what* (stable identity) and wrong about *how much* (registry, URIs). Take the
   kernel, drop the apparatus.
4. **Opt-in layering, not tax.** Heavy capability (governance, judging) is a layer
   you add, never weight in the base — the only way one tool serves both the
   vibe-coder and the regulated team.
5. **Mandate the direction, ratify the details.** A reset ends divergence; an input
   window honours real emerging requirements. Lock only when conformance is
   testable.
6. **Conformance is proven, not assumed.** Structural compatibility is necessary,
   never sufficient; a shared oracle makes "conformant" a fact, not a claim.
7. **Fail-closed, observably.** When you can't prove something (a match, a trust
   level, a freshness), say so honestly (orphan / unknown / stale) — never
   silently guess. No false-greens.
8. **Borrow effects, not vocabulary.** When a sibling design has the right
   *guarantees* (e.g. elspeth's custody/fabrication/fail-closed-boundary rules),
   adopt the **guarantees** in Loom's *own* terms — do not import its naming
   (`tier1/tier2/tier3`, `tier=3`). Loom already has a richer trust vocabulary
   (the 8-state lattice; `@external_boundary` / `@trust_boundary(to_level=…)` /
   `@trusted`); the goal is the same *effect*, expressed natively — not a second
   naming scheme bolted on beside the first.

---

## 5. Current status & path to lock

- **Drafted, not locked.** SEI is the agreed single track; its precise shape is in
  the ratification window. Lock gate: all four subsystems sign off / record
  requirements, and the oracle encodes them.
- **Wardline's position:** its SEI half is a thin *client-layer* change (carry SEI
  as the explain/dossier handle; handle orphan/lineage/capability), **zero engine
  change**, gated on Clarion shipping SEI first. Its ratification inputs: SEI as a
  carryable handle, and settling the content-axis hash granularity.
- **Safe to build now:** only shape-independent groundwork — Clarion prior-index
  retention (the matcher's prerequisite).
- **The next conformance domain after identity is the *trust vocabulary*.**
  elspeth's `@trust_boundary(tier=3)` and Wardline's `@trust_boundary(to_level=…)`
  collide in name but not in intent. The resolution is **not** to import elspeth's
  `tier` naming — it is to converge the suite on **one** trust vocabulary in Loom's
  own terms (the lattice + the three decorators) that *delivers elspeth's
  guarantees* (custody, the fabrication test, fail-closed boundaries) — borrow the
  effects, not the words (principle 8). And `legis` should *govern* trust while
  Wardline *analyses* it (one judge, not two). Identity first; trust vocabulary
  next; same reset-then-ratify method.

---

## 6. Goal-state checklist

Loom has reached its goal state when:

- [ ] SEI is locked and all four subsystems pass the SEI conformance oracle.
- [ ] A rename/move of a function preserves every Wardline fact, Filigree
      association, and `legis` attestation on it (or surfaces an honest orphan).
- [ ] `dossier(entity)` returns a complete, freshness-stamped envelope; `traverse`
      pivots across linkages — both keyed on SEI.
- [ ] Clarion serves linkages over HTTP (closing the dossier's `linkages` gap).
- [ ] The trust vocabulary is reconciled to one `@trust_boundary` across the suite.
- [ ] `legis` ships as opt-in: invisible to a solo project, complete for a
      regulated one, governing (not re-analysing) trust.
- [ ] Every standard is demonstrably an instance of the §2 custody axiom.
