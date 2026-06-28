# Current State — Wardline

> The resume brief: the fastest path back to the running picture. Read this
> first next session. Refreshed 2026-06-28 at `/product-checkpoint`.

## The bet right now

**Close out the Wardline residency of the weft-seam-conformance program** (Now;
`roadmap.md` → Now) — **UNCHANGED**. The open frontier remains the **seam-health probe** —
PRD-0002 criteria 1 + 2 (Layer-1 `doctor --seams` self-check with a mandatory
machine-readable `reason`; Layer-2 consumer round-trip that never trusts a self-reported
status field). *This session did NOT advance the seam bet* — it was an **owner-directed
dogfood detour** (the `~/elspeth/` report), now mostly resolved (below). The seam probe is
still the highest-blast-radius core unbuilt.

- *Metric it moves:* **G2-seam** (`metrics.md`): `BASELINE (2026-06-15): 3 of 6 surfaces
  lie or can't self-report → TARGET: 0 of 6 by 2026-07-31`. crit-3 closed the
  producer-artifact axis; criteria 1/2 (the probe) remain.
- *Spec:* `PRD-0002-weft-seam-conformance.md`.

## In flight (by tracker ID)

- **`wardline-c66f62894b`** (P1, open) — weft-seam-conformance program tracker (the Now bet).
  Children `23c8e4bef4` / `da883a2d07` (P4, cross-repo, non-gating).
- **`wardline-bd9d1e65cb`** (P1, open) — **NEW this session**: elspeth dogfood — inert-gate
  visibility + FastAPI/usefulness. Part A + pack-bridge **DONE** (below); follow-ons open
  (elspeth FP calibration, Part B doctor self-test, Part C FastAPI source coverage).
- **`wardline-bf004e2aea`** (P1, open) — holistic-risk-review parent; children `80e457bc41` /
  `18499aaa2d` code-landed, awaiting a separate ACCEPT pass (not the seam bet).

## Landed this session (the dogfood detour)

- **Diagnosis corrected (twice).** The sibling agent's "blake3 is why the gate is inert" is
  **wrong** (blake3 is write-side only; corpus fires 23 ERROR defects with blake3 blocked).
  Real cause: **wardline is annotation-driven** — no declared trust boundary = inert gate
  (passes green checking nothing). elspeth declares 0 *wardline* boundaries (its 25
  `@trust_boundary` annotations are its own vocab). See `[[project_wardline_annotation_driven]]`.
- **Part A — inert-gate visibility** (PDR-0007, commit `b3d0a81e`): always-on
  `resolution.inert` in agent-summary + MCP (schema golden re-frozen) + reliance-gated stderr
  banner (Python counterpart of the Rust empty-trust-surface warning). 4449 tests green.
- **Pack-bridge** for elspeth's vocab (PDR-0008, commit `72bc9eb9`): maps
  `elspeth.contracts.trust_boundary` → a wardline `BoundaryType`; validated WITH→fires
  PY-WL-119 / WITHOUT→inert. Deliverable: `tests/grammar/fixtures/elspeth_trust_boundary_pack.py`.
- *(Also on the branch: the concurrent layering refactor `cfe546ed` — not a product-owner
  decision; landed between checkpoints.)*

## Open questions / blocked-on-owner

1. **PR #69 merge + release (owner gate) — SCOPE GREW.** PR #69
   (`release/consolidation-2026-06-26` → main) now also carries this session's Part A +
   pack-bridge **and** the layering refactor `cfe546ed`. Merging to main / any PyPI release are
   outward-facing — your call, not actioned here.
2. **Install the pack in elspeth (cross-repo / owner).** The pack-bridge only takes effect once
   placed on elspeth's import path + referenced in elspeth's `weft.toml`. Not actioned here.
3. **Relay corrected guidance to the elspeth agent (owner).** "blake3 will NOT fix the gate;
   install the pack." The sibling agent is operating on the wrong model.
4. **Strategic question (owner): framework-boundary auto-inference?** Whether truly-unannotated
   apps should get enforcement via auto-inferred boundaries — a **vision change** (revises the
   "silent until opted in" anti-goal). Parked as Later (PDR-0008 option c); flagged, not enacted.
5. **3.12 fingerprint release note (owner).** Carry-over from PDR-0006 — one-line note on release.
6. **warpline incoming push (heads-up).** ~34 unpushed commits will red the `source-drift` job →
   wardline re-vendors per procedure (the bet working as designed).
7. **North-star instrumentation still unmeasured.** Agent-fix success rate has no baseline corpus.

## What this checkpoint did

- **PDR-0007** — ship inert-gate visibility (Part A); dated G3 + G1 readings.
- **PDR-0008** — pack-bridge for elspeth's vocab (blake3 stays optional / G4 upheld;
  auto-inference parked + escalated); dated G1 reading (pack FP UNMEASURED — calibration
  follow-on, reversal trigger > 0.05 FP).
- Tracker `wardline-bd9d1e65cb` reconciled (Part A + pack-bridge commented done; ticket open).
- Roadmap **untouched** — no existing bet changed horizon; the dogfood thread is owner-directed
  detour work now in follow-on. The next DECIDE may choose to promote it (the
  annotation-driven/zero-config tension is thesis-level).

## Where the next session starts

1. Confirm the grant still holds (re-confirmed 2026-06-27; next due ~2026-09-25).
2. **The Now bet is still the seam-health probe** — PRD-0002 criteria 1 + 2: probe-protocol
   design → `/axiom-solution-architect`, then `/axiom-planning`.
3. **DECIDE call:** whether the elspeth dogfood thread (Part B/C + the auto-inference strategic
   question) should be promoted onto the roadmap vs. left as `wardline-bd9d1e65cb` follow-ons.

## Provenance

Decisions: `0001` bootstrap, `0002` Now rotation, `0003` doctor seam, `0004` ACCEPT PRD-0001,
`0005` ACCEPT crit-3 + source-drift CI, `0006` fingerprint determinism, `0007` inert-gate
visibility, `0008` elspeth pack-bridge. Tactical truth is the tracker; intent lives here and in
`roadmap.md`.
