# PDR 0008 — Pack-bridge elspeth's `@trust_boundary` vocabulary (not blake3, not auto-inference)

`Date: 2026-06-28` · `Status: Accepted` · `Decider: owner-directed (AskUserQuestion → "Pack-bridge")
within grant — agent-extension via the packs mechanism; no engine primitive, no release`

## Context

Given wardline is annotation-driven (PDR-0007), making the elspeth gate non-inert requires
wardline to recognize trust boundaries *in elspeth*. Key finding: elspeth is **not unannotated
by neglect** — it annotates ~25 external-data boundaries with its **own** vocabulary,
`elspeth.contracts.trust_boundary.trust_boundary(tier=3, source_param="…", …)`, which wardline
simply does not read. That vocabulary is a clean semantic match to wardline's validating-boundary
seed (`_seed_boundary`: untrusted args in → validated return). blake3 is a confirmed red herring;
FastAPI source coverage is **moot** without declared boundaries.

## Options

- **(a) Make `blake3` a core dependency** (the sibling agent's instinct, from the owner's "if it's
  needed it shouldn't be optional"). *Rejected:* blake3 is write-side federation only; it does not
  gate rule firing. Making it core breaches **G4 weight discipline** for zero analysis benefit. The
  thing actually "needed" was boundary recognition, not blake3.
- **(b) Re-annotate elspeth in wardline's vocabulary.** *Rejected:* double-annotation friction;
  elspeth already has 25 boundaries in its own vocab.
- **(c) Auto-infer framework boundaries** (treat FastAPI/Flask route handlers as implicit
  `@external_boundary`). *Rejected for now and ESCALATED:* large engine feature **and a vision
  change** — it revises the "silent until opted in / not noisy" anti-goal. Parked as Later; flagged
  for the owner as a standing strategic question (see reversal trigger 2).
- **(d) Pack-bridge: a wardline pack maps elspeth's vocabulary → a `BoundaryType`.** *Chosen by the
  owner.*

## The call

Build the pack-bridge (commit `72bc9eb9`). The pack
(`tests/grammar/fixtures/elspeth_trust_boundary_pack.py`) declares a non-builtin `BoundaryType`
(`canonical_name="trust_boundary"`, `module_prefix="elspeth.contracts.trust_boundary"`,
`level_args=()` so elspeth's tier/source_param kwargs are ignored, seed = `FunctionTaint(EXTERNAL_RAW,
ASSURED)`). Validated end-to-end on an elspeth-shaped target: **WITH** the pack → both boundaries
recognized (scan non-inert), a boundary returning its untrusted `source_param` unvalidated fires
**PY-WL-119 ERROR**; **WITHOUT** → zero recognized, no defect (the inert state). The pack is the
copy-ready deliverable: elspeth places it on the import path + references it under `[wardline] packs`
in `weft.toml` (or `--trust-pack`).

## Rationale

The smallest fix that **uses elspeth's existing annotation investment**, via the **as-designed
packs mechanism** (the invariant-2 agent-extension plane in `vision.md`). Honors G4 (no core dep)
and the zero-config thesis: the human flips one switch (a pack reference), the agent does not fill a
form. Auto-inference deferred precisely because it would cross the "silent until opted in" anti-goal
— a vision change the owner must sanction, not a checkpoint action.

## Reversal trigger

Metric-bound, tied to `metrics.md` **G1 (precision)**:
1. **FP rate.** If full elspeth-repo calibration over the 25 real boundaries shows the
   validating-boundary seed produces an FP rate **> 0.05 of active findings** (G1 breach), reopen
   toward a refined seed / boundary mapping before recommending the pack for the gate of record.
2. **Pattern friction (vision tension).** If hand-written per-team packs prove too high-friction to
   scale, the auto-inference option (c) reopens — that is a **vision change** ("silent until opted
   in"), escalated to the owner, never enacted from a checkpoint.

## Owner-gate / outward-facing note

The pack only takes effect once **installed in the elspeth repo** (a cross-repo / sibling action) —
**not actioned by this checkpoint.** The corrected guidance for the elspeth agent ("blake3 will not
fix the gate; install the pack") is for the owner to relay.
