# Loom — goal state & design case study

**Date:** 2026-06-01  
**Status:** Living reference (umbrella over the SEI, dossier, and trust-declaration specs)  
**Scope:** The target architecture for the **Loom** suite — Wardline (analysis),
Clarion (code intelligence), Filigree (issue tracking), and the planned `legis`
(governance + git interface) — and the design reasoning that produced it. Both a
north star to converge on and a case study of the decisions behind it.

> **Guiding stance: build the best, most powerful, most general version of the
> idea.** The goal state is always the *fullest* form of each idea — identity,
> dossier, governance, the custody axiom — at maximum generality (any entity, any
> language, any artifact, any fact-producer), not a constrained first cut. Scope
> decisions (a deterministic v1 matcher, deferred verbs) are **sequencing toward
> that**, never the ceiling. "Minimal" applies only to *dead apparatus and
> accidental complexity* — never to the ambition, power, or generality of the
> idea. Under-reach is a failure mode too: a well-crafted system no one reaches
> for is not being used. This composes with the product thesis, not against it —
> the most powerful capability, delivered as **opt-in layers**, so the base stays
> weightless for anyone who doesn't switch it on.
>
> **We design from a position of strength, not scarcity.** Loom is a **real
> product now** — a robust shipped baseline (Wardline on PyPI, Clarion 1.x,
> Filigree 2.3.0), not a pile of ideas to be salvaged. "Salvage" was the posture
> of building from nothing; we are past it. We build the fullest version *forward*
> on that foundation, with product-maturity confidence — keeping what ships,
> shedding dead apparatus, and reaching for the most general form.

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

- **Identity is stable across refactors.** Any entity — function, class, module,
  and onward to any addressable artifact in any language a plugin can describe —
  keeps its identity through rename/move/edit (**SEI** — Stable Entity Identity),
  so every cross-tool binding survives the operations developers actually perform
  instead of silently orphaning. Clarion mints and carries it; everyone else keys
  on it. (The general form: identity is a property of the *authored thing*, not of
  any one language's qualname — §2.)
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

> **On elspeth.** `/home/john/elspeth` is a **standalone** project — the *initial
> version* of these trust ideas, which Loom builds on. It is **not** a Loom
> federation member and **not** a conformer to Loom's standards (the four
> subsystems are Wardline, Clarion, Filigree, `legis`). Loom and `legis` borrow
> elspeth's **concepts and effects**, re-expressed in Loom's own vocabulary
> (§4, principle 8) — not its naming, and not its scope. References to elspeth in
> this document are to a design ancestor, never to a peer in the suite. (We are
> still figuring the suite out; elspeth is the proven prior art, not a fifth tool.)

---

## 1.5 The operating model & the combination matrix

One root invariant generates the entire stack:

> **Agent-first: humans on the loop, not in the loop.** The agent *operates and
> extends* the environment; the human *supervises, approves, and governs* from
> outside the operating cycle.

Everything else is a consequence of it:

- **Zero *human* config.** Each tool stands itself up (`filigree init`,
  `wardline install`) preloaded with **agent-calibrated instructions** — the
  instruction layer *is* the configuration mechanism. If a human had to configure
  a step to operate the tool, the human would be *in* the loop. (Enterprise
  *feature set*, plug-and-play *setup*.)
- **Agent-programmable extension.** The agent does not merely toggle presets; it
  can **define new boundary types and the rules enforced at them**, expressed in a
  shared grammar with the builtins as preloaded defaults. Zero *human* config ≠
  zero config — the config surface is agent-facing and **generative**. (One
  grammar, open instance set — the same seam shape as `TaintSourceProvider`,
  Clarion `Transport`, the dossier `HistoryProvider`, and elspeth's plugin
  architecture.) Extensions still inherit the soundness invariants: a boundary the
  engine can't prove emits an honest `UNKNOWN_*`, never a false-green.
- **legis graded enforcement.** When a policy fires, its *mode* decides who
  answers and how: **block + escalate** (the human operator signs off — *in* the
  loop by exception) or **surface + override** (the agent must **recordably
  override** — self-honesty; the human reviews the trail asynchronously). The
  recorded override — an attributable audit event — is what makes "humans *not in*
  the loop" safe: it is the §2 custody axiom applied to agent *behaviour* (a broken
  seal handled honestly, never silently passed). The human sets the dial while on
  the loop; the agent operates under it.

**The combination matrix.** Loom's value is the *matrix* of its tools'
combinations, not their sum. Each pair is an opt-in layer that lights up a
capability neither tool has alone:

| Combination | Capability it unlocks | Status |
|---|---|---|
| **Wardline + Clarion** | Understand the codebase *and* how taint flows through it — structure + trust posture in one view (this is the **dossier**) | **Live** — `scan --clarion-url` writes per-entity taint facts; Clarion serves them |
| **Wardline + legis** | Agent-*defined* policy, *enforced* at the CI/git boundary — analysis becomes a governed gate | **Future** — Wardline has the gate (`--fail-on`, exit codes); legis adds the governed policy + git interface |
| **Wardline + Filigree** | Findings become tracked work — a taint finding files/links an issue | **Live** — native Filigree emitter + entity-associations |
| **Clarion + Filigree** | Issues bound to the live code entity, surviving refactors | **Partial** — bindings exist but *orphan* on rename/move (the SEI gap) |
| **Clarion + legis** | Governance attestations keyed to stable code identity — custody/lineage of the code itself | **Future** |
| **Filigree + legis** | Governed issue lifecycle — sign-offs, RTM, verification states on tracked work | **Future** — Filigree has the verification state machine; legis governs it |

Higher-order combos are where it becomes the operating model rather than a feature:

- **W + C + F** — the mastery read: *"what's true of this function (taint +
  structure), and what work is open on it,"* in one call. The dossier, complete.
- **All four** — the closed "humans on the loop" loop: the agent *understands* the
  code (C) and its *trust* (W), legis *governs* what it may do and *records* the
  overrides (L), and every decision and unit of work is *tracked against stable
  identity* (F + C).

**SEI is the connective tissue of the whole matrix.** Every cell is a cross-tool
**binding**, and a binding needs a shared, durable identity to bind *on*. That is
why three pairs ship today, one (C+F) is only *partial* — it orphans on refactor —
and the governance row waits on legis. **A combination is only as strong as its
weakest binding**: one tool keying on a fragile id silently orphans every combo it
participates in. The combination matrix is therefore the business case for SEI,
and the reason no subsystem is grandfathered (SEI spec §0.1, §0.4).

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
qualname demoted to a resolvable *locator*. The abandoned Loom-URI effort is
**prior art we learned from, not scrap we salvaged** — it was right about *what*
(stable identity) and over-built in its *mechanism* (registry, multi-fetch, URIs),
which is why it never shipped. SEI is the deliberate, product-grade design for a
mature suite: the stable-identity idea at full generality, on the robust baseline
we already have, without the dead apparatus. Crucially, because Filigree treats
the id as opaque, **the standard is adoptable across a frozen member with zero
code change** (only the stored *value* changes).

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
- `archive/2026-06-01-wardline-loom-entity-dossier-design.md` — the one-call mastery read.
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
3. **Build forward on the baseline; maximal idea, minimal apparatus.** We are a
   real product, not salvaging from nothing — design with that confidence. Prior
   efforts (the abandoned Loom-URI) are *lessons*, not scrap: it was right about
   *what* (stable identity — keep this at maximum generality) and over-built in
   its *mechanism* (registry, URIs, multi-fetch), which is why it never shipped.
   Keep the fullest form of the idea on the shipped foundation; drop only dead
   apparatus. Minimality is about mechanism and accidental complexity, **never**
   about the power or generality of the idea (guiding stance, top of doc).
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
