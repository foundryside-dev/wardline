# Bit bucket — parking lot for ideas we might consider

This folder is **not** `archive/`. The distinction:

- **`…/archive/`** — implementation material for work that **shipped**. Done,
  kept for the historical record. Nothing here is expected to come back.
- **`bitbucket/` (this folder)** — designs, proposals, and notes that are
  **undecided**: drafted but never acted on, deferred, or superseded by a
  different direction. Parked here so they're not lost, not because they're
  finished. Anything here is a candidate to revisit — or to delete once it's
  clearly dead.

**Status of anything in here is "not active."** Don't treat a doc in this
folder as a current plan or a committed decision. If you pick one up, move it
back out (to `specs/` as an active spec, or wherever it belongs) and update its
status header. If you conclude it's dead, delete it.

Excluded from the mkdocs site build (see `exclude_docs` in `mkdocs.yml`).

## Current contents

- `2026-06-01-wardline-explicit-trusted-body-return-design.md` — adds an explicit
  `@trusted(body=..., returns=...)` form alongside the `level=` shorthand, so a
  function with a pristine `INTEGRAL` body but an honestly-`ASSURED` return can be
  declared without tripping PY-WL-101 (reads the return tier) against PY-WL-103/104
  (modulate off the body tier). Never implemented; the motivating tension is still
  real in the engine, but with only two declarable tiers the feature buys exactly
  one new expressible pair `(INTEGRAL, ASSURED)` against real surface churn
  (registry version bump, marker-attr change, vocab regen, ~10 doc edits). **Parked,
  demand-gated:** revive only on a concrete 101-vs-103/104 false positive hit, not
  speculatively.

  Its sibling, the config-backed `wardline.yaml` `trust:` block design, was
  **retired 2026-06-02**: superseded by the portable trust-grammar-packs direction
  (`filigree wardline-6e4ac6c148`), and its hand-authored qualname→taint config ran
  against the product's "activation, not configuration" invariant. Two ideas worth
  salvaging into pack work if a pack ever ships a `wardline.yaml` trust surface — the
  explicit precedence ladder (entity > decorator > path-default > fallback) and
  folding parsed trust-config into the provider fingerprint for cache invalidation.
