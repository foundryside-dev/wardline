# PDR 0002 — Rotate the Now bet Later→Now: weft-seam-conformance

`Date: 2026-06-27` · `Status: Accepted` · `Decider: product-owner agent
(within authority grant; rotation confirmed with john@foundryside.dev this
session)`

> Recorded as crash-recovery. A prior session on 2026-06-27 made this decision,
> wrote `PRD-0002-weft-seam-conformance.md`, and added the **G2-seam** guardrail
> to `metrics.md` — then crashed before `/product-checkpoint`. This PDR makes the
> already-depended-on decision durable; the next RESUME finds provenance, not a
> contradiction.

## Context

The previous Now bet — the Codex security-review hardening close-out (PDR-0001 /
PRD-0001 scope) — **paid off**. Both P1s are closed with red/green regressions
(`wardline-c797baf28b` DoS bound, 2026-06-22; `wardline-d96b94d4e9` doctor
token-leak, 2026-06-23); the `codex-security-2026-06-20` batch is **0 open** and
`codex-security` overall is **0 open**; guardrail **G2 is at target** ahead of the
2026-07-31 backstop. The single formerly-in-progress item (`wardline-14359d070b`)
is also closed (`cbd287d2`). The outward-facing B7 site-kit pin
(`wardline-c852f6d8b5`) — escalated at triage — is closed (`42e2bab9`).

Meanwhile reality pulled the next front forward. On
`release/consolidation-2026-06-26`, Wardline already landed the P0 **enforceable
seam registry + fail-closed gate** and **6 seams reaching `at_bar`**, plus
attest-2 per-boundary `content_hash`, delta-scope v1 + `producer_completeness`,
and the federation-status / WeftHttp refactors. The federation *is* the product
(PDR-0023, hub spec `~/weft/pm/2026-06-15-seam-health-map.md`); the seams are the
crown jewels, and the class of defect they carry — **a silent join-miss that
returns a confident answer byte-indistinguishable from a true-negative** — is the
same blast radius as a fail-open taint hole.

## Options

- **(a) Keep Codex as Now** until a formal clean re-review closes the residual
  class. *Rejected:* the batch is already 0 open and the verified work has already
  moved on to seams; holding Now here would be status-theatre.
- **(b) Run weft-seam-conformance as a co-Now**, concurrent with Codex wind-down.
  *Rejected:* single-bet focus is the discipline; the seam front is unambiguously
  the active one, and the Codex bet needs only an ACCEPT pass, not Now attention.
- **(c) Promote weft-seam-conformance Later→Now; accept the Codex bet as
  paid-off.** *Chosen.*

## The call

**weft-seam-conformance (wardline residency, PRD-0002) is the Now bet.** The Codex
hardening close-out is paid off and moves to a formal ACCEPT pass (next DECIDE).
The Now bet's success metric is **G2-seam — cross-repo seam honesty**
(`metrics.md`, added 2026-06-27): no Wardline-owned seam surface can return an
answer indistinguishable from a true-negative; every empty/stale result carries a
machine-readable `reason`, and every consumer read is round-trip-verified, never
by trusting a self-reported status field. Program home: `wardline-c66f62894b`
(children `c0563eee74`, `79ba05f464`, `23c8e4bef4`, `da883a2d07`). Top
dispatchable: PRD-0002 criteria 1 + 2 → `/axiom-planning`.

## Rationale

This is a **within-grant reprioritization** ("prioritize and reprioritize the
backlog"), not a strategy change: the vision, anti-goals, and the 2026-06-01
thesis are unchanged — weft-seam-conformance is squarely the existing
enrich-only, agent-first Weft-composition vision, and the work is internal
hardening (no release, no deprecation, no external-party action). Closing the
silent-seam class is what makes the federation moat real; the dead
loomweave→filigree seam that ran dead for weeks (caught once by luck) is the
proof this is a live class, not a hypothetical.

## Reversal trigger

Metric-bound, tied to `metrics.md` **G2-seam**:

1. **Scope-breach reopen.** If at the 2026-07-31 window close the G2-seam target
   (0 of 6 surfaces able to return a true-negative-indistinguishable answer) is
   **not reachable by Wardline alone** — i.e. acceptance proves contingent on
   unshipped warpline/loomweave/legis work (that is scope C, a different bet) —
   reopen and re-scope to wardline-only criteria, or demote seam back to Next and
   re-promote the MCP-primary program.
2. **G2-core preemption.** A **new** default-gate fail-open or policy-bypass hole
   (G2 core, not the seam axis) is a **P0** and preempts seam as Now until closed
   — the same rule that made the Codex bet Now in the first place.
