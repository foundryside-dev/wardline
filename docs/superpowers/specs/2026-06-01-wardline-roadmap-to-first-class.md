# Wardline — the road to first-class (roadmap & final form)

**Date:** 2026-06-01
**Status:** Living reference (roadmap; companion to the Loom goal-state case study)
**Scope:** Wardline's **final form** as a first-class, enterprise-capable analyzer
— and the staged path to it — given the Loom operating model and invariants
settled across the 2026-06-01 design sessions. Sibling to
`2026-06-01-loom-goal-state-case-study.md` (the suite umbrella) and
`2026-06-01-loom-stable-entity-identity-conformance.md` (the SEI keystone).

> **The thesis filter governs every line of this roadmap.** "Bring it to
> enterprise level" means enterprise *capability* delivered as **opt-in layers** —
> **never** enterprise *weight* in the base. The zero-dependency base stays
> zero-dependency; governance, V&V, and audit live in `legis`, not in Wardline. A
> solo "vibe coder" gets a sound, precise analyzer that installs itself and the
> agent drives, and never pays for any layer they don't switch on.

---

## 0. The final form, in one sentence

> Wardline becomes the **best Python trust-taint analyzer in existence** — sound,
> precise, broad-ruled, agent-programmable — **and** a first-class Loom citizen:
> an SEI-keyed, freshness-honest, fail-closed engine whose trust grammar is
> extensible, whose facts survive refactors and read in one call, and which is
> **governed** (never re-judged) by `legis`.

"First-class" has **two co-equal halves**. The analyzer-quality bar comes *first*;
the suite-integration bar comes *second*. A tool that is a perfect Loom citizen but
a mediocre analyzer is not first-class — and most of what the design sessions
discussed is the second half, so this roadmap deliberately leads with the first.

---

## 1. Half 1 — the analyzer itself (the foundation; mostly Wardline-autonomous)

This is where "first-class" actually starts, and the tracker says so: the
highest-priority open issue, `wardline-2b138b3662`, is literally titled
**"Taint-combination engine — *first-class* hardening."** That is the spine of the
near-term work, not a footnote. None of this half is gated on a sibling tool.

- **Soundness (the non-negotiable floor).** Continue closing fail-open holes (the
  lineage of the soundness-hardening scrub): no silent laundering of
  untrusted→trusted; every gap the engine cannot prove is an observable
  `WLN-ENGINE-*` FACT, never a false-green.
- **Precision & FP economics.** A low, *budgeted* false-positive rate with
  disciplined waivers. A first-class analyzer is one teams do not reflexively
  suppress.
- **Lattice & engine precision.** The taint-combination hardening epic
  (`wardline-2b138b3662`).
- **Callgraph completeness.** Close the known false-negative / indirection gaps:
  star-import resolution (`wardline-2b427a9579`), return-indirection in
  `compute_return_callee` (`wardline-82f49ec3c3`), and L3 fixed-point coverage.
- **Rule-set breadth.** Wardline ships **four** rules today (PY-WL-101–104).
  First-class means a **broad, curated, growing** builtin set. The extensible
  grammar (§2) *enables* authoring more rules; it does **not** *substitute* for a
  curated builtin library — that library is itself a deliverable.

---

## 2. Half 2 — first-class Loom citizen (the layers; mostly gated)

### 2.1 Extensible trust grammar *(Wardline-autonomous; highest-leverage)*

Turn today's fixed 8-state lattice / three decorators / four rules into a
**grammar**: agents define new boundary types and the rules enforced at them, with
the builtins as preloaded defaults. This is the most-powerful-version of the trust
model (the agent-programmable extension plane), and it is the **substrate** for
both rule breadth (§1) and suite vocabulary convergence (§2.4).

- **One grammar, open instance set.** The grammar (what a boundary *is*, how trust
  composes, what fail-closed means) is singular and shared; the boundary types and
  rules expressed in it are an open, agent-authored set. Same seam shape as
  `TaintSourceProvider`, Clarion `Transport`, the dossier `HistoryProvider`, and
  elspeth's plugin architecture.
- **Soundness is inherited, not waived.** An agent-defined boundary the engine
  cannot prove emits an honest `UNKNOWN_*` and a `WLN-ENGINE-*` FACT. Agent-authored
  ≠ trusted-by-fiat; the no-false-green tenet applies to custom rules exactly as to
  the builtins.
- **Zero *human* config.** The agent authors the extension; no human fills in a
  form. This is the agent-first operating model (humans on the loop, not in it)
  applied to Wardline's configuration surface.

### 2.2 SEI client conformance *(thin & ready — gated on Clarion shipping SEI)*

Key taint facts (and dossier reads) on **SEI** instead of the qualname locator, so
they survive the renames and moves developers actually perform instead of silently
orphaning. Treat SEI opaque; **degrade gracefully** when Clarion lacks the `sei`
capability. Wardline's half is a client-layer change with **zero engine impact**;
the gate is Clarion *implementing* SEI (see the SEI conformance standard).

### 2.3 The dossier — one-call mastery read *(gated on Clarion SEI + HTTP linkages)*

`dossier(entity)` returns a function's trust posture, decorators, linkages, recent
history, and open work as **one** typed, token-bounded, freshness-stamped,
SEI-keyed envelope — no reading a hundred lines across three tools. Wardline's
contribution (the trust posture) is ready; the gates are Clarion serving linkages
over HTTP (today they are MCP-only) **and** SEI.

### 2.4 Trust-vocabulary convergence *(gated on legis)*

The suite converges on **one** trust vocabulary — Wardline's grammar, delivering
elspeth's *effects* (custody, the fabrication test, fail-closed boundaries) in
Loom's *own* terms, not its `tier1/2/3` naming. **Wardline analyses trust; `legis`
governs it — one judge, not two.** Related to the grammar (§2.1 makes the
vocabulary extensible) but not strictly gated by it: convergence is about which
vocabulary the suite *adopts*.

### 2.5 Wardline + legis enforcement at CI *(gated on legis existing)*

Agent-defined policy enforced at the git/CI boundary with **graded modes**:
*block + escalate* (human operator signs off — in the loop by exception) or
*surface + override* (the agent must recordably override — self-honesty; the human
reviews the trail asynchronously). Wardline already has the gate primitive
(`--fail-on`, exit codes); `legis` adds the governed policy layer around it.

---

## 3. Staging — by capability milestone and dependency gate

SP0–SP9 were real and shipped. The milestones below are **proposed**, framed by
what unblocks each — not a manufactured SP10/11/12 sequence with the committed
weight of the shipped work.

| # | Milestone | Gate | Wardline's position |
|---|---|---|---|
| 1 | **Engine-quality floor** — hardening epic + FN/indirection issues + FP/precision discipline + first wave of rule breadth | none (autonomous) | owns it end-to-end |
| 2 | **Extensible trust grammar** — grammar + builtins-as-defaults | none (autonomous) | owns it end-to-end; **highest-leverage un-gated item** |
| 3 | **SEI client** — facts keyed on SEI, graceful degrade | Clarion ships SEI | thin & ready; waiting on sibling |
| 4 | **Dossier** — the one-call mastery read | Clarion SEI **+** HTTP linkages | half ready; waiting on sibling |
| 5 | **Governance & convergence** — suite vocabulary + CI graded enforcement | `legis` exists | half ready; waiting on sibling |

**Honest gating picture.** Milestones 1–2 are Wardline's to finish alone, and #2
sequences right behind #1 — it is the hinge between "best analyzer" and "Loom
citizen." For milestones 3–5, Wardline's half is *thin and ready*; the wait is on
the sibling (Clarion SEI, Clarion HTTP linkages, `legis` existing), not on Wardline.

---

## 4. North Star — multi-language, done honestly

The *contracts* go language-agnostic — the fact format, the trust vocabulary, and
SEI — so **other producers** can feed the same store and the suite can grow across
languages. The Python AST analyzer **stays Python**: other languages are *other
producers*, not a rewrite of this engine. This keeps "the most general version of
the idea" honest without committing to a rewrite Wardline will not do.

---

## 5. The throughline

Every item above is an **opt-in layer**. The base stays zero-dependency and
weightless; the agent drives; the human supervises from the loop's edge. A solo
project gets a sound, precise, self-installing Python analyzer and nothing it did
not ask for. A team that needs identity-durable facts, the one-call dossier, or
governed CI enforcement switches on the layer — capability without tax. That is
enterprise/first-class on this product's terms.
