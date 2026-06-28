# Examination — Q4: framework-boundary auto-inference for truly-unannotated apps

> **Status: OPEN — owner-reserved vision question. This note EXAMINES; it does
> not decide.** Owner-directed examination (2026-06-28) of `current-state.md`
> Q4 / PDR-0008 option (c). The decision is a vision change (revises the "silent
> until opted in" anti-goal) and — per the technical finding below — also an
> engine-model change; both are the owner's call. Pressure-tested by two
> independent perspectives (`product-decision-critic`, static-analysis
> `false-positive-analyst`). A `/product-checkpoint` may promote a resolved
> version to a PDR once the owner decides.

## The question (verbatim)

> Should truly-unannotated apps get framework-boundary auto-inference? (treat
> FastAPI/Flask route handlers as implicit `@external_boundary`.) That revises
> the "silent until opted in" anti-goal — a vision change.

## Why it was raised

The elspeth dogfood: a sibling agent armed `wardline scan . --fail-on ERROR` as
a pre-commit gate on a FastAPI app, it passed **green**, and the agent believed
it was protected. wardline is annotation-driven, so an app with no declared
trust boundary is **inert** (gate passes checking nothing). PDR-0007 made that
*honest* (the inert banner = visibility); PDR-0008 gave elspeth a
zero-hand-annotation path *because it had 25 boundaries in its own vocab*. The
open question is the harder case: the team that declares **nothing**.

## The honest status quo (state it plainly)

A truly-unannotated, disengaged team gets, today, **only PDR-0007's banner —
visibility, not enforcement.** That is the real gap. Nothing currently closes
it; the pack mechanism only helps a team that *adds a pack line*, which is a
more-engaged segment than the one the question names.

## Finding 1 (technical, decisive) — "unannotated app → enforcement" is an engine-model change, not a pack

Static-analysis investigation (verified from engine source + live scans) found
**three structural blockers** to a sound, low-FP FastAPI auto-enforcement pack:

1. **Recognition.** `@app.get(...)` resolves to the runtime instance var
   `app.get`, never an import FQN, so the FQN-keyed pack matcher cannot match it
   (only a brittle/unsound var-name match works). Constructor-binding resolution
   exists on the *sink* side but is not wired into the seed/decorator provider.
2. **Source/sink collapse (lattice imprecision).** FastAPI's single-handler
   idiom puts source and sink in *one* function. Wardline's 2-field per-function
   `FunctionTaint` seed forces a binary: seed params `EXTERNAL_RAW` → handler
   enters the freedom zone → **every in-handler sink is suppressed** (the SQLi is
   missed); or don't → **inert**. You cannot express "params raw AND
   sink-context trusted" — they are the same field. Demonstrated: validating
   seed → PY-WL-102 FP + missed SQLi; external seed → inert; the *split*
   control (untrusted handler → `@trusted` query layer) fires 118+105+101+120
   perfectly. The sink is modeled; the collapse suppresses it.
3. **Pydantic discharge (runtime-property-as-static).** `async def h(item:
   Model)` validates out-of-band before the handler runs. A per-function seed
   can't carry "this `BaseModel` param is validated, that `str` param isn't."
   Honest `UNKNOWN` keeps FP low but leaves the gate silent exactly where
   Pydantic does the work (hollow gate); seeding handlers as boundaries unleashes
   the anchored rules (PY-WL-102/119/101) at base severity on **every idiomatic
   endpoint** → mass FP → the cry-wolf death the G1 guardrail forbids.

**Consequence:** a naive always-on inference either *misses* the injection
(sound but inert — no better than today) or *floods* FPs (anti-goal death).
Doing it right needs **per-parameter seed granularity in the abstract domain** —
a real engine investment with a hard precision bar — not a curated pack. So the
question is bigger than "flip a switch": it is *vision change* **+** *engine-model
change*.

## Finding 2 (the genuine tension — do NOT resolve it circularly)

For a **security** gate whose core promise is "no false green" (G2; a fail-open
hole is a P0), a **silent false-green on every unannotated app is arguably the
worse failure** than the FP fatigue the "cry wolf" anti-goal optimizes against.
The anti-goal was written to stop the tool getting turned off from *noise*; the
dogfood exhibited the *opposite* failure — silence read as safety. It is
illegitimate to use the anti-goal to refuse to reopen the anti-goal. The owner
is probing a real asymmetry (G1 FP-cost vs G2 false-green-cost) that is specific
to this tool class. That asymmetry is the heart of the decision and belongs to
the owner.

## The smallest sound, in-thesis step — ALREADY SHIPPED (Part C, `b5170e22`)

Static-analysis identified the floor the current model permits: model the raw
`Request.*` accessors (`request.json()`, `.body()`, `.form()`, `.query_params`,
`.headers`, `.cookies`) as untrusted sources — explicitly **not** seeding typed
Pydantic params. **This already shipped on this branch as Part C** (commit
`b5170e22`, `scanner/taint/variable_level.py::_REQUEST_SOURCE_TYPES`) — via a
*better* mechanism than the FP-analyst proposed: a **type-aware curated table**
keyed on `fastapi.Request` / `starlette.requests.Request` receivers (so
`req.query_params.get(x)` → sink fires, but `req.app.state.db` → sink does **not**
— the discriminator the `config.untrusted_sources` seam couldn't make). The
analyst, grepping for the `untrusted_sources` seam, did not find Part C; it is
the same idea, soundly done. **So there is no cheap within-grant code step left
to take — the source-side floor is done.** It fires when raw request data reaches
a team-annotated `@trusted` core, and stays silent on a zero-annotation app
(verified: framework apps with no declared trusted core still scan inert post-Part-
C). It is in-thesis (the team still declares its trusted core) and so **does not
serve the fully-disengaged team** — that gap is purely the *sink-side* recognition
+ in-handler source/sink collapse, i.e. option B's engine-model change.

## Options for the owner

- **(A) Hold the line + make opting-in trivial (recommended default).** Keep
  "silent until opted in"; rely on PDR-0007's banner for honesty; invest in
  *cheap activation* (framework source-modeling above, generalize the pack
  mechanism). In-thesis, cheap, precision-safe. **Cost:** the disengaged team
  that ignores the banner stays unprotected. Justified on the anti-goal's merits
  + the engine cost — **not** on a false invariant-1 hook.
- **(B) Revise the anti-goal AND fund the engine-model change.** Per-parameter
  seed granularity + framework boundary inference behind activation — the
  "most powerful version" (invariant 2). Major engine investment, hard precision
  bar (Finding 1), genuine vision change. Worth it only if the disengaged-team
  segment is real and valuable enough — which is currently **unmeasured**.
- **(C) Smallest sound step now, decide the vision later.** Ship the opt-in
  `Request.*` source modeling (Finding's floor) + **instrument inert-gate
  prevalence** on a dogfood corpus, so (B) can later be decided on data. Does
  not serve the fully-disengaged team but lays the empirical groundwork.

## The real blocker to deciding well

Both perspectives independently flag: the **north-star is uninstrumented**, so
"how prevalent is the inert-gate false-green / do disengaged teams exist / will
they flip a switch" is unmeasurable. The highest-value next move *regardless of
A/B/C* — and **within grant** (measurement, not a vision change) — is to
instrument inert-gate prevalence on a dogfood corpus. That converts this from an
opinion to a decision.

## Measured baseline — inert-gate prevalence, local Weft corpus (2026-06-29)

Owner-authorized within-grant instrumentation (A+C; measurement, not a vision
change). Measures the *harm surface*, not raw inertness — a pure-logic library
scanning inert is correct behavior, not harm.

- **Denominator — gate plausibly armed** (wardline wired via `weft.toml
  [wardline]`, a pre-commit hook, CI, or a dep): **9 repos** — plainweave,
  warpline, elspeth, lacuna, esper-lite, loomweave, murk, filigree, tabard.
- **Framework-shaped subset** (genuine web surface): **5** — elspeth (FastAPI, 64
  files), filigree (FastAPI/Starlette/Bottle, 88 route handlers), loomweave (15
  routes), plainweave (Starlette, `Route()`-list style → not even decorator-
  matchable, reinforcing Finding-1 blocker 1), esper-lite (1 route, marginal).
- **Latent harm surface — framework-shaped AND `resolution.inert=True`
  (`recognized_boundaries=0`): 5 of 5.** Every framework-shaped armed repo scans
  inert. The inert false-green is the **common case** for framework apps in this
  corpus, not a one-off.
- **Realized reliance-gated harm — armed `--fail-on` AND inert (the actual
  false-green): 1 of 5 (elspeth only).** The wardline pre-commit hook arms **no**
  `--fail-on`, so filigree/plainweave/loomweave invoke wardline *advisorily*
  (`gate: NOT_EVALUATED`; PDR-0007's banner does not even fire). elspeth is the
  sole repo that armed an explicit threshold over an inert tree.
- **Controls confirm the metric is harm-specific, not noise:** non-framework
  libraries warpline & murk also scan inert — but correctly (no web input
  surface); excluded from the harm count. The annotated library lacuna *enforces*
  (`recognized_boundaries=33`, `inert=False`) — opting in works.

**Honest caveat (denominator integrity):** N is tiny (5 framework apps) and all
are Weft-ecosystem siblings — **not** a representative sample of framework apps
in the wild. This sizes the *local dogfood* harm (latent surface broad, realized
harm N=1); it **cannot** size *external* demand for option B. To ever decide B on
data you would need external real framework apps in the corpus — which the local
tree cannot supply. That denominator cap is itself decision-relevant: **you do
not fund a major engine-model change on N=1 of realized demand.**

**What it confirms:** the A+C call. Realized reliance-gated harm = 1 → B is not
justified on demand. Latent surface ≈ 100% of framework apps → the gap is
*structural*, so the cheap in-thesis A-path (make opting-in trivial + PDR-0007's
honest banner) is the right lever, and B stays parked pending external evidence.

## If this becomes a PDR — provenance fix + concrete trigger

The prior framing leaned on PDR-0008 reversal-trigger 2 (about *hand-written
per-team* packs — the opposite of a curated one — and self-sealing). Replaced by
this **metric-bound, non-self-sealing** trigger, keyed to the baseline above:

> **Reopen the engine+vision change (option B) if the count of *reliance-gated
> inert* framework apps — armed `--fail-on` AND framework-shaped AND
> `recognized_boundaries=0` — reaches ≥ 5 across measured corpora (local + any
> external apps), re-measured each release by re-running this instrumentation.**
> Baseline 2026-06-29 = **1** (elspeth).

Non-self-sealing by construction: shipping the A-path (banner + easier opt-in)
does **not** artificially zero this signal — the banner makes inert *honest*, it
does not make framework apps *recognized*; only teams actually declaring
boundaries (the intended A outcome) drops the count, and that drop **is** A
succeeding. A *rising* count means teams are arming gates on framework apps faster
than they opt in — i.e. A is insufficient and B is earned.

## Recommendation

**Return the question to the owner as the vision + engine decision it is — do not
dispose of it as a pack.** Owner chose **A+C (2026-06-29): hold the vision,
instrument first.** Status after this pass:
- **(C) is effectively complete.** The source-side floor (Part C `b5170e22`) was
  already shipped, and the instrumentation is now done (baseline above). There is
  **no cheap within-grant code step remaining** — the easy lever is already pulled.
- **(A) holds.** "Silent until opted in" stands; PDR-0007's banner keeps the gap
  honest; opting-in is now cheaper (source-side free for FastAPI/Starlette).
- **(B) stays parked and escalated.** The only remaining lever for the
  *fully-disengaged* team is sink-side recognition + the in-handler source/sink
  collapse — the engine-model change. Realized reliance-gated demand = **1**;
  reopen only when the metric-bound trigger above (≥ 5) fires on measured corpora.

The disengaged-team gap is real and named honestly; the evidence says the cheap
in-thesis work is done, and the expensive remainder is not justified on N=1.
