# PRD-0003 — Return G2 to zero known false-green holes            Status: ready-for-planning
Decision: PDR-0012 (S0 bet) + PDR-0017 (scope expansion, pending — see Open questions)   Bet (roadmap.md): Now   Target metric (metrics.md): G2 — Soundness / surface integrity

## Problem

The **coding agent**, and the 1–2 developer team that arms it, annotate a trust
boundary and rely on Wardline's gate to tell them whether untrusted data reaches
it. Their pain is that an annotation can be **silently discarded**: the marker is
written, the engine cannot read it, the function falls out of the declared set,
every tier-modulated rule goes quiet, and the gate exits 0. The agent's
edit-verify loop reports success on a boundary that is checked by nothing, and
nothing in the output says so. This directly contradicts the promise the product
is built on — that uncertainty is made *explicit* rather than converted into a
green gate.

The desired outcome, in the user's terms: **a trust annotation either takes
effect or is loudly rejected — it is never silently ignored.** Whatever the
author writes, the gate's colour reflects reality.

Why now: G2 was held continuously at 0 known holes from 2026-06-30 until
2026-08-09, when one hole reopened it (PDR-0012). Inspecting that hole under
review surfaced two more of the same class. The count is **3**, not 1, and the
bet currently in Now closes only the first — so the bet as scoped can complete
without the metric recovering.

## Success metric (the signal the bet paid off)

**G2 — zero known fail-open taint holes, held continuously.**

- `BASELINE: 3 known false-green holes` (reading 2026-08-10, this PRD: the
  builtin call-shape hole `wardline-4928b75782`; the Rust marker-shape channel
  `wardline-b857b50b54`; the unreadable level-value hole `wardline-2b2a6cddfa`)
- `TARGET: 0 known false-green holes`, read at the bet's close receipt and
  re-read 30 days later.

This is the falsification condition: if any of the three still reproduces a
green gate at close, the bet did not pay off.

## Acceptance criteria (falsifiable)

1. **SUCCESS — all three holes closed, each by its own before/after repro.** At
   the close receipt, each of the three named repros exits **1** at
   `--fail-on ERROR` where it exits **0** today, and each is pinned by a
   committed regression test.
   *Reject branch:* any of the three still exits 0 → bet rejected; the residual
   hole is re-filed with a new reading and G2 stays off target.

2. **SUCCESS — no fourth hole of the same class is open at the read.** G2 is a
   *continuously held* target, so the count, not the delta, is what is read. At
   close and at +30 days, the count of open known false-green/fail-open holes
   is **0**.
   *Reject branch:* a newly discovered hole is open at either read → G2 is not
   at target; record the reading and reopen rather than claiming the bet paid.

3. **GUARDRAIL — G1 false-positive rate stays ≤ 0.05 of active findings** over
   the corpus at close (current corpus reading: 0/29).
   *Reject branch:* breached → bet rejected **even if criteria 1 and 2 pass**. A
   soundness win bought with noise is not a win; an analyzer that cries wolf
   gets turned off.

4. **GUARDRAIL — zero scan-golden regeneration.** The byte-identity corpus and
   the builtin-findings oracle are unchanged at close, with at most the reviewed
   re-freezes already sanctioned by the delivery plan.
   *Reject branch:* a scan golden requires regeneration → the change is wrong;
   stop and fix the change, never the golden.

5. **GUARDRAIL — G3 zero-config activation holds.** Closing these holes adds no
   required human configuration step and no runtime dependency to the base
   package.
   *Reject branch:* any fix requires the human to configure something → it
   violates the hard guardrail in `vision.md` and must be redesigned.

6. **SCOPE — the fix reaches every affected surface, not a subset.** Both
   language frontends are covered: the Python builtin marker path *and* the Rust
   doc-comment marker path.
   *Reject branch:* Rust left unfixed → this criterion is unmet regardless of
   the Python result, and G2 cannot be read as 0.

## Non-goals (this bet)

- **The `UNKNOWN_RAW` lattice conflation** (`wardline-e88c098f91`). Measured and
  recorded, and it will matter to S3's restoration work, but it is a *demotion*
  question and no fix in this bet demotes a seed. Separable by construction.
- **PY-WL-130's config-defeatability** (`wardline-c32e5d1420`). Disabling the
  rule returns behaviour to today's rather than something worse, so it does not
  block G2 reaching 0. It needs its own spec change.
- **The S1–S4 declaration kinds** — contracts, facets, restoration, sensitivity,
  dependency taint. This bet closes holes in the *existing* surface; it ships no
  new marker vocabulary.
- **Published `generic-3` / `attest-3` emission.** Stays `published_emission_ready=false`;
  it is a separate release gate and an owner decision.
- **Broadening the readable value grammar beyond module-level constants.** A
  value that is a call, an f-string, or a runtime config lookup stays unreadable
  by design; it gets a diagnostic, not a resolution.

## Constraints & guardrails

- **G1 (FP ≤ 0.05) and G3 (zero-config) must not degrade** — criteria 3 and 5.
- **G4 weight discipline:** base package stays at 0 runtime dependencies.
- **Spec rev 6 is a prerequisite for one hole.** Resolving module-level constants
  in level-value positions contradicts spec §P3 form 2 as written
  (*"Bare names are rejected in value positions"*). The spec's own form-4
  rationale argues for it — a module-level reference resolves through the import
  system, so a typo is a `NameError` and a rename is refactorable — but the
  grammar rule must change before the reader can. The plan's governing blob pin
  moves with it.
- **Fail-closed on anything still unreadable.** Widening the reader must not
  introduce a guess: a value the widened reader still cannot resolve fails closed
  and takes a diagnostic channel.
- **No new human-facing configuration surface** (the hard guardrail in
  `vision.md`).

## Open questions / assumptions

- **No PDR yet records the scope expansion.** PDR-0012 decided the S0 bet at one
  hole; the expansion to three was decided in-session on 2026-08-10 and is
  pending as PDR-0017 at the next `/product-checkpoint`. Until it lands, this
  PRD's provenance is partial.
- **No calendar backstop is set.** Criteria are bounded by the close receipt and
  a +30-day re-read, both observable events. A dated forecast is
  `/program-management`'s output, not this spec's — if the owner wants a calendar
  backstop on G2 (the metric has used one before: *"0 open by 2026-07-31"*), it
  needs a capacity model this PRD does not have.
- **Assumption that changes the bet if wrong:** that these three are *all* the
  holes of this class. The count went 1 → 3 under one session's inspection, and
  criterion 2 exists precisely because the metric is a continuously-held count
  rather than a burn-down. A deliberate hunt may find a fourth, which would
  re-baseline this PRD rather than fail it.
- **The Rust fix's blast radius is measured, not assumed:** all 21 markers in the
  frozen Rust fixtures use the canonical form, so a widened recogniser flags no
  frozen fixture. This was verified, but only against the fixtures in-tree.
- **Agent-fix success (north star) stays unmeasured**, so this bet is judged on a
  guardrail rather than on the north star. That instrumentation gap is standing
  measurement debt, not introduced here.

## Handoff

- **Top item → `/axiom-planning`:** the **module-level constant reader for
  level-value positions** (`wardline-2b2a6cddfa`). It is the most reachable of
  the three in real code — an ordinary DRY refactor to a module constant triggers
  it — and the only one needing both a spec amendment and new engine reading
  behaviour. It is the item that genuinely needs a plan.
- **Already planned, no new planning needed:** `wardline-4928b75782` is covered
  by the S0 plan at rev 3.4, reviewed green.
- **Small, near-plan-free:** `wardline-b857b50b54` — a two-stage
  recognise-then-parse split reusing the existing failure path.
- **→ `/axiom-solution-architect`:** the solution shape for the widened reader —
  how far resolution follows a binding, and what the residual unreadable channel
  looks like. This PRD names the constraints the design lives inside; it does not
  choose the design.
- **→ `/program-management`:** sequencing across the three holes and any dated
  forecast. No date originates here.
- **Tracker:** `wardline-4928b75782`, `wardline-b857b50b54`,
  `wardline-2b2a6cddfa`. Related, out of scope: `wardline-e88c098f91`,
  `wardline-c32e5d1420`. Epic: `wardline-aee6ae068b`.
