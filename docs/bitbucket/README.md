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

- `2026-06-01-wardline-explicit-trusted-body-return-design.md` +
  `2026-06-01-wardline-config-trust-declarations-design.md` — a sibling pair of
  Wardline trust-declaration designs ("ready for implementation planning",
  2026-06-01). Never implemented; the first-class program (Tracks 1–5) took a
  different direction (extensible trust grammar). Parked pending a decision on
  whether explicit `body=/returns=` declarations + a `wardline.yaml` trust
  surface are still wanted.
