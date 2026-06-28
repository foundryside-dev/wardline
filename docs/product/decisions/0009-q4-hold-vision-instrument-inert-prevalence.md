# PDR 0009 — Q4: hold the "silent until opted in" vision; instrument inert-gate prevalence (A+C)

`Date: 2026-06-29` · `Status: Accepted` · `Decider: owner (AskUserQuestion →
"Instrument first, hold vision") — the decision is to NOT make the vision change;
the instrumentation is within grant (measurement, not a vision change)`

## Context

PDR-0008 parked and escalated option (c) — framework-boundary auto-inference for
truly-unannotated apps — as a standing owner question (Q4 in `current-state.md`):
*should an unannotated FastAPI/Flask app get implicit `@external_boundary`
inference, revising the "silent until opted in / not noisy" anti-goal?* The owner
asked for it to be examined. The examination was pressure-tested by two
independent perspectives (`product-decision-critic`, static-analysis
`false-positive-analyst`) and the advisor. Full write-up:
`q4-framework-auto-inference-examination.md`.

Two findings reshaped the decision:
1. **It is a vision change AND an engine-model change, not a pack.** A FastAPI
   handler-boundary pack is **not buildable soundly** on today's engine (three
   demonstrated structural blockers: `@app.get` is not FQN-matchable; the
   single-handler idiom collapses source and sink so any param-taint *suppresses*
   the in-handler injection; Pydantic validation is a runtime property a
   per-function seed cannot carry → mass anchored-rule FPs on every idiomatic
   endpoint). Real enforcement for unannotated apps needs per-parameter seed
   granularity in the abstract domain — a large engine change.
2. **The cheap, in-thesis floor is already done.** Part C (commit `b5170e22`,
   `_REQUEST_SOURCE_TYPES`) ships type-aware raw-`Request.*` source seeding — the
   FP-analyst's "smallest sound step," soundly built. So the only remaining lever
   for the *fully-disengaged* team is the sink-side engine change (option B).

## Options

- **(A) Hold the line + cheap activation.** Keep "silent until opted in"; rely on
  PDR-0007's reliance-gated banner for honesty; make opting-in trivial. In-thesis,
  precision-safe. Cost: the disengaged team that ignores the banner stays
  unprotected.
- **(B) Revise the anti-goal + fund the engine-model change.** Per-parameter seed
  granularity + framework boundary inference behind activation — the "most
  powerful version." Major engine investment, hard precision bar, genuine vision
  change. Worth it only if the disengaged-team segment is real and valuable —
  currently **unmeasured**.
- **(C) Smallest sound step + instrument.** Ship the raw-`Request.*` source floor
  (already done, Part C) + instrument inert-gate prevalence so B-vs-A can be
  decided on data.

## The call

**A+C, chosen by the owner.** Hold the "silent until opted in" anti-goal
(no vision change). Run the within-grant instrumentation (done — baseline below).
B stays parked and escalated; it reopens only on the metric-bound trigger.

**Measured baseline (2026-06-29, local Weft corpus — the *harm surface*, not raw
inertness):** of **9** repos with a wardline gate plausibly armed, **5** are
framework-shaped, and **5 of 5 scan inert** (`recognized_boundaries=0`) — the
inert false-green is the *common case* for framework apps. But **realized
reliance-gated harm = 1** (only elspeth armed an explicit `--fail-on`; the
pre-commit hook arms no threshold → others are advisory / `NOT_EVALUATED`).
Controls confirm the metric is harm-specific: non-framework libraries (warpline,
murk) scan inert *correctly* and are excluded; the annotated library lacuna
enforces (`recognized=33`). Honest cap: N=5, all Weft siblings — cannot size
*external* demand. Reading recorded in `metrics.md` G3.

## Rationale

Realized reliance-gated demand = 1; you do not fund a per-parameter abstract-
domain rebuild on N=1. The latent surface (≈100% of framework apps inert) means
the gap is *structural*, so the right lever is the cheap in-thesis path — which is
already largely pulled (Part C source floor + PDR-0007 honesty) — not a vision
change. The genuine security-tool tension (a silent false-green is arguably worse
than an FP for a trust gate) is real and was surfaced honestly to the owner, who
chose to hold pending data. The earlier "reframe to a pack" instinct was withdrawn
— both the product critic (it dodges the disengaged-team question) and the FP
analyst (it is unbuildable) refuted it.

## Reversal trigger

Metric-bound and **non-self-sealing** (tied to `metrics.md` G3):

> **Reopen the engine+vision change (option B) if the count of *reliance-gated
> inert* framework apps — armed `--fail-on` AND framework-shaped AND
> `recognized_boundaries=0` — reaches ≥ 5 across measured corpora (local + any
> external apps), re-measured each release by re-running this instrumentation.**
> Baseline 2026-06-29 = **1** (elspeth).

Non-self-sealing because shipping the A-path (banner + easier opt-in) does not
artificially zero this signal — the banner makes inert *honest*, it does not make
framework apps *recognized*. Only teams actually declaring boundaries (the intended
A outcome) drops the count; a *rising* count means teams arm gates on framework
apps faster than they opt in — i.e. A is insufficient and B is earned.

## Owner-gate / outward-facing note

Nothing outward-facing was enacted. The decision is to *hold* the vision (status
quo). Standing owner gates are unchanged (PR #69 merge / PyPI release; install the
pack + relay corrected guidance in elspeth). Option B, if ever taken, is a vision
change requiring explicit owner sign-off — it is not pre-authorized by this PDR.
