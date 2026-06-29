# Current State — Wardline

> The resume brief: the fastest path back to the running picture. Read this
> first next session. Refreshed 2026-06-29 at `/product-checkpoint`.

## The bet right now

**Close out the Wardline residency of the weft-seam-conformance program** (Now;
`roadmap.md` → Now) — **UNCHANGED**. The open frontier remains the **seam-health probe** —
PRD-0002 criteria 1 + 2 (Layer-1 `doctor --seams` self-check with a mandatory
machine-readable `reason`; Layer-2 consumer round-trip that never trusts a self-reported
status field). *The last two sessions did NOT advance the seam bet* — the Q4 examination
(resolved, below) and this session's reactive **install-friction fix** (PDR-0010) were both
detours. The seam probe is still the highest-blast-radius core unbuilt.

- *Metric it moves:* **G2-seam** (`metrics.md`): `BASELINE (2026-06-15): 3 of 6 surfaces
  lie or can't self-report → TARGET: 0 of 6 by 2026-07-31`. crit-3 closed the
  producer-artifact axis; criteria 1/2 (the probe) remain.
- *Spec:* `PRD-0002-weft-seam-conformance.md`.

## In flight (by tracker ID)

- **`wardline-c66f62894b`** (P1, open) — weft-seam-conformance program tracker (the Now bet).
  Children `23c8e4bef4` / `da883a2d07` (P4, cross-repo, non-gating).
- **`wardline-bf004e2aea`** (P1, open) — holistic-risk-review parent; children `80e457bc41` /
  `18499aaa2d` code-landed, awaiting a separate ACCEPT pass (not the seam bet).
- **`wardline-bd9d1e65cb`** — **CLOSED this session** (concurrent session). Dogfood program:
  Part A inert visibility + pack-bridge + **Part B doctor self-test (`652d3bf3`) + Part C
  FastAPI/Starlette request-source coverage (`b5170e22`)** all DONE+committed. Q4 examination
  + baseline recorded on it (comments 199/200). Residual = cross-repo/owner (install pack in
  elspeth; FP calibration on the real elspeth tree).

## Resolved this session — Q4 (framework auto-inference)

**Owner decision (PDR-0009): A+C — hold the "silent until opted in" vision; instrument first.**
No vision change (anti-goal unchanged); the instrumentation was within grant.

- *Examined + pressure-tested* (product-decision-critic + static-analysis FP-analyst + advisor):
  "unannotated app → enforcement" is a **vision change AND an engine-model change** (per-parameter
  seed granularity), **not a pack** — a FastAPI handler-boundary pack is unbuildable soundly
  (3 structural blockers). The "reframe to a pack" instinct was withdrawn.
- *Instrumented baseline (2026-06-29, local Weft corpus, in `metrics.md` G3):* of 9 armed-gate
  repos, 5 framework-shaped, **5/5 scan inert** (the false-green is the common case for framework
  apps) — but **realized reliance-gated harm = 1** (only elspeth armed `--fail-on`). Honest cap:
  N=5, all Weft siblings — cannot size external demand for option B.
- *Cheap in-thesis floor already shipped:* Part C (`b5170e22`) is the raw-`Request.*` source
  seeding the FP-analyst proposed — done, soundly. No cheap within-grant code step remains.
- *Option B* → Later, PARKED+gated (`roadmap.md`); reopens only if reliance-gated-inert framework
  apps reach **≥ 5** across measured corpora (baseline = 1). Full write-up:
  `q4-framework-auto-inference-examination.md`.

## Open questions / blocked-on-owner

1. **PR #69 merge + release (owner gate) — SCOPE GREW AGAIN.** PR #69
   (`release/consolidation-2026-06-26` → main, HEAD now `8c950e02`) carries the prior detour
   (Part A + pack-bridge + layering `cfe546ed`), the concurrent session's Part B
   (`652d3bf3`), Part C (`b5170e22`), de-elspeth refactor (`9886280c`), glossary re-sync
   (`53a1424d`), the **v1.1.0 release prep** (`adb42a0e` version bump + CHANGELOG, `35401454`),
   **plus this session's install-friction fix** (`87f13b0d`/`8c950e02`, PDR-0010). The
   install fix is **unpublished** — it reaches users only via the owner-gated release.
   Merging to main / any PyPI publish are outward-facing — your call.
2. **Install the pack in elspeth + relay corrected guidance (cross-repo / owner).** "blake3 will
   NOT fix the gate; install the pack." Pack-bridge + Part C both shipped generically wardline-side.
3. **3.12 fingerprint release note (owner).** Carry-over from PDR-0006 — one-line note on release.
4. **warpline incoming push (heads-up).** ~34 unpushed commits will red the `source-drift` job →
   wardline re-vendors per procedure (the bet working as designed).
5. **North-star: partially instrumented.** Inert-gate prevalence now has a baseline (PDR-0009);
   the agent-fix-success-rate corpus is still unmeasured (separate from this — see `metrics.md`).
6. **Option B trigger is now live** — re-run the inert-prevalence instrumentation each release;
   ≥ 5 reliance-gated-inert framework apps reopens the engine+vision change (escalates).

## What this checkpoint did

- **PDR-0010** — install-friction fix: scan-pipeline extras self-include scanner (the
  `loomweave` whack-a-mole under `uv tool install`) + a shared install-hint helper naming
  both installers + a regression guard. Commits `87f13b0d`/`8c950e02` (pushed); also
  installed the fixed build into the local uv tool (single `[loomweave]` install now keeps
  scanner — verified).
- **metrics.md** — dated G4 reading (per-release extras re-check; base stays 0-dep; no
  trigger crossed).
- **Tracker** — filed + closed `wardline-c8d7e020e8` (the dogfood install defect).
- **Cross-repo (not wardline's to own):** this session was primarily the plainweave↔warpline
  requirements-enrichment federation gate + an exit-code investigation; those product records
  live in the sibling workspaces (plainweave PDR-017, warpline PDR-0008), not here.
- The **Now bet was not advanced** (reactive install-fix detour). `roadmap.md` untouched;
  grant unchanged (re-confirmed 2026-06-29 by the prior session).

## Where the next session starts

1. Confirm the grant still holds (re-confirmed 2026-06-29; next due ~2026-09-27).
2. **The Now bet is still the seam-health probe** — PRD-0002 criteria 1 + 2: probe-protocol
   design → `/axiom-solution-architect`, then `/axiom-planning`.
3. Q4 is RESOLVED — do not relitigate; the only live thread is the ≥5 reversal-trigger watch.

## Provenance

Decisions: `0001` bootstrap, `0002` Now rotation, `0003` doctor seam, `0004` ACCEPT PRD-0001,
`0005` ACCEPT crit-3 + source-drift CI, `0006` fingerprint determinism, `0007` inert-gate
visibility, `0008` elspeth pack-bridge, `0009` Q4 hold-vision+instrument, `0010` extras
self-include scanner (install-friction fix). Tactical truth is the tracker; intent lives here
and in `roadmap.md`.
