# Loom — subsystem alignment prompt

**Date:** 2026-06-01
**Status:** Operational reference (a reusable agent prompt)
**Scope:** A drop-in prompt to point an agent working in **Clarion**, **Filigree**,
or **legis** at the authoritative 2026-06-01 Loom design pass — telling it to shelve
divergent prior guidance, converge on SEI + the operating model, and produce its own
"final form" roadmap. Companion to the three canonical docs it references.

## How to use

1. Copy the prompt below into an agent running in the target subsystem's repo.
2. Replace the `[SUBSYSTEM]` line with the matching role line from the table below,
   so the agent leads with its own authority.
3. Ensure the agent can read the three canonical docs (see **Access** at the end).

---

## The prompt

```
You are working on [SUBSYSTEM], one of the four Loom subsystems (Wardline,
Clarion, Filigree, legis).

A suite-wide design pass has produced the AUTHORITATIVE direction for Loom. It
supersedes any earlier "federation spec", cross-tool addressing scheme (e.g. the
abandoned Loom-URI), or divergent identity agreement you currently hold on the
identity question. Shelve that prior guidance and converge on the following.

Read these three canonical documents (they live in the Wardline repo):

1. /home/john/wardline/docs/superpowers/specs/2026-06-01-loom-goal-state-case-study.md
   — the suite goal state, the operating model (agent-first: "humans on the loop,
   not in the loop"; zero-HUMAN-config; agent-programmable extension; legis graded
   enforcement), the combination matrix, and the custody axiom.

2. /home/john/wardline/docs/superpowers/specs/2026-06-01-loom-stable-entity-identity-conformance.md
   — SEI, the single canonical entity-identity interface. Every subsystem keys its
   cross-tool bindings on SEI. Read §5 (your conformance obligations) and §0.3
   (the lock gate) closely.

3. /home/john/wardline/docs/superpowers/specs/2026-06-01-wardline-roadmap-to-first-class.md
   — Wardline's "final form" roadmap. This is the TEMPLATE for your deliverable.

Two things are true at once, and both matter:
- The TRACK is closed. There is one canonical identity interface, it is SEI, and
  it supersedes the divergent prior specs. This is settled — start converging.
- The SHAPE is open. SEI is NOT yet locked. You influence it before lock by
  bringing CONCRETE, EMERGING requirements — not by re-litigating settled
  trade-offs or staying on your old spec. "We already agreed something different"
  is not grounds to diverge; it is legitimate input only if it reflects a real
  emerging requirement.

Your deliverables:

A. A "final form" roadmap for [SUBSYSTEM], modelled on doc 3. State your endstate
   as BOTH a first-class Loom citizen AND a first-class tool in your own right;
   the intermediate milestones; and an honest dependency-gate picture (what you
   can finish alone vs. what waits on a sibling). Save it to your repo as
   docs/superpowers/specs/2026-06-01-[subsystem]-roadmap-to-first-class.md.

B. Your SEI conformance position: confirm the §5 obligations the SEI spec sets
   for you, and record any concrete emerging requirement you need reflected
   before lock (extend your existing federation/SEI notes if you have them).

Operate under the suite invariants throughout: agent-first; opt-in layers (never
weight in the base); fail-closed / no false-green; conformance PROVEN by the
shared oracle, never assumed (no grandfathering — structural compatibility is
necessary, not sufficient).

Do NOT start implementation that pins a specific SEI shape before lock;
shape-independent groundwork is fine. Surface your roadmap and requirements for
review when ready.
```

---

## Per-subsystem role line (paste in for `[SUBSYSTEM]`)

| Subsystem | Role line |
|---|---|
| **Clarion** | …**Clarion**, the suite's code-intelligence engine and the SEI **authority/implementer** (you mint, persist, re-bind, and resolve identity; everyone else consumes it). Your roadmap's heaviest item is the SEI matcher + prior-index retention (SEI spec §3, §3.1). |
| **Filigree** | …**Filigree**, the suite's issue/workflow authority — `done`/frozen (v2.3.0). Note the trap in SEI spec §0.1: you need no code change to store SEIs, but that makes you *able* to conform, not conformant. Your roadmap centres on the locator→SEI backfill + oracle pass + the governed-lifecycle (Filigree + legis) combo, within your frozen-surface constraints. |
| **legis** | …**legis**, the git/CI operating picture + governance authority (design-ready, not implemented). You already have a charter, SEI-conformance notes, and a bootstrap plan — extend those into the full roadmap shape; your endstate is the chill→protected-systems dial working end-to-end. |

---

## Access

The three canonical docs live in the **Wardline repo** (`/home/john/wardline/docs/superpowers/specs/`).
If you launch an agent sandboxed to its own repo and it cannot read that path, copy
those three files into the target repo first. (legis already vendors references to
them in its README and `docs/federation/`.)

## The canonical set

- `2026-06-01-loom-goal-state-case-study.md` — suite goal state, operating model, combination matrix, custody axiom.
- `2026-06-01-loom-stable-entity-identity-conformance.md` — the SEI standard (canonical identity interface; track closed, shape open until lock).
- `2026-06-01-wardline-roadmap-to-first-class.md` — Wardline's final-form roadmap (the template for each subsystem's roadmap deliverable).
