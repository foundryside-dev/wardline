# PDR-0021 — Spend sixteen rounds on the provider fingerprint, then park it on a construction argument

`Date: 2026-08-11` · `Status: ACCEPTED` · `Decided by: Claude, under the owner's standing
directive to keep pushing while rounds do real work` · `Bet: Now (roadmap.md)` ·
`Metric: G2 — soundness / surface integrity`

## Context

S0's Task 13 was budgeted as one QE prerequisite: *pin the provider fingerprint's mutation
table*. The fingerprint is the cache key over a project's **custom trust grammar** — if two
behaviourally different grammars share it, a warm cache serves verdicts computed under the wrong
rules.

It consumed **sixteen fix rounds, an eleven-agent parallel audit, and two independent
assessments** — by a wide margin the largest single overrun in the programme.

What justified continuing was that every round found a live defect in **previously shipped**
code, measured rather than argued:

- the `builtin` flag was absent from the cache key entirely;
- the digest embedded **memory addresses**, so it differed every process — a permanent cold cache;
- referenced helper bodies were keyed by name, so editing a helper did not move the key;
- the digest **mutated the object graph it hashed**, so two calls in one process disagreed;
- an unbounded-cost path (143 MiB / 30 s at depth 20, with the node budget reading zero);
- an outright **hang**; and three crash paths that would take an entire scan down.

The owner's directive governed the stopping rule: *"as long as the rounds are doing real work I'm
happy to keep pushing — the capability is important."* Precision here is a capability question,
not hygiene: this path is how an **agent-authored trust vocabulary** would be cached, and
agent-defined boundary types are `vision.md`'s invariant-2 ceiling.

## Decision

**Park the fingerprint on a construction argument rather than an enumeration**, with a durable
residual document, after round 16.

The park basis is checkable in one place: *every function on which the guard is consulted has, in
that same function and immediately before, already had its root offered to the surface.* That
replaced an earlier enumeration argument ("three producer namespaces, no fourth") which was
**true and whose inference was false** — the producer grew the surface at three enumerated sites
while the consumer was consulted at every visited function, so an enumeration of producer sites
could always be one site short.

Three components were **deleted rather than extended** across the task: `_surface_roots`, an inert
closure-cell growth, and finally all three producer call sites. The design got smaller.

## Alternatives considered

- **Stop at round 5**, as the first independent assessor recommended on a defensible reading of
  the finding pattern. Rejected by evidence within hours: a parallel multi-agent audit attacking
  from angles the serial loop had never used found **four confirmed collisions**, one of which the
  serial loop had itself created and then **pinned as correct with a test**.
- **Stop at round 12**, per the second assessor's bounded "12 plus one scoped 13". Extended
  because each subsequent round still met the owner's bar — a live defect on an ordinary Python
  shape, measured.
- **Fix the remaining residuals.** Rejected on measurement, per residual: the general fix for the
  opaque-reach family is a namespace walk measured at 207 MB; the aliasing axis needs dataflow the
  component does not have; the provenance axis rests on packaging metadata that is unreliable in
  both directions.

## Reversal trigger

Reopen if a **collision on an ordinary shape** is found with a cheap fix — the bar that governed
every round. An over-invalidation (cold cache, never a wrong verdict), an exotic shape, or a
restatement of a documented residual does **not** reopen it. The residual document's own contract
is the standing test: *anything not on that list is not claimed closed.*

## Consequences

- The durable deliverable is **`src/wardline/scanner/taint/PROVIDER_FINGERPRINT_RESIDUALS.md`**,
  beside the code it describes, with every entry carrying failure direction
  (under-discrimination = a false green; over-invalidation = only a cost), measured reachability,
  fix-versus-defect cost, do-not-fix markers, and fresh-versus-inherited marks. It supersedes the
  residual lists in all sixteen report appendices, which are deleted when the plan's workspace is
  cleaned up.
- Blast radius of every remaining under-discrimination is bounded and stated once: the
  stale-verdict hop needs `--cache-dir` **and** `WARDLINE_SUMMARY_CACHE_KEY`, so summary caching
  is opt-in and none is a live default-path false green.
- **The honest limit, recorded rather than smoothed:** the *fixture* class is not exhausted. Five
  of the sixteen rounds found a defect hiding behind an assumption every fixture shared. The
  durable defence is the document's contract and its standing re-measure instruction, not any
  enumeration.
- **Estimation evidence for S1–S4:** the plan under-estimated this task roughly sixteen-fold, and
  not because the work was mis-specified — because the code underneath was in worse shape than
  anyone had measured. S1–S4 assume they build on a sound base; that assumption should be priced
  accordingly.

Related: [PDR-0019], [PDR-0022], `wardline-5a795253f1`,
`src/wardline/scanner/taint/PROVIDER_FINGERPRINT_RESIDUALS.md`.
