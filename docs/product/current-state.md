# Current State — Wardline

> The resume brief: the fastest path back to the running picture. Read this
> first next session. Refreshed 2026-06-30 at `/product-checkpoint`.

## The bet right now

**Close out the Wardline residency of the weft-seam-conformance program** (Now;
`roadmap.md` → Now) — **UNCHANGED, and NOT advanced this session (3rd consecutive detour).**
The open frontier remains the **seam-health probe** — PRD-0002 criteria 1 + 2 (Layer-1
`doctor --seams` self-check with a mandatory machine-readable `reason`; Layer-2 consumer
round-trip that never trusts a self-reported status field). The last three sessions were all
reactive-P1 detours (Q4 examination → install-friction PDR-0010 → this session's
preview-gate soundness fix PDR-0011). See open question #1 — the pattern is now the signal.

- *Metric it moves:* **G2-seam** (`metrics.md`): `BASELINE (2026-06-15): 3 of 6 surfaces
  lie or can't self-report → TARGET: 0 of 6 by 2026-07-31`. crit-3 closed the
  producer-artifact axis; criteria 1/2 (the probe) remain the open work.
- *Spec:* `PRD-0002-weft-seam-conformance.md`.

## In flight (by tracker ID)

- **`wardline-c66f62894b`** (P1, open) — weft-seam-conformance program tracker (the Now bet).
  Children `23c8e4bef4` / `da883a2d07` (P4, cross-repo, non-gating).
- **`wardline-bf004e2aea`** (P1, open) — holistic-risk-review parent; children code-landed,
  awaiting a separate ACCEPT pass (not the seam bet).
- **`wardline-5dc82dd22a`** (P3, open) — NEW this session. Surface rule `maturity` in the
  agent-summary `active_defects` projection (deferred polish from the v1.2.0 fix; a
  schema/golden change, orthogonal to gate correctness).
- **`wardline-4ada23bb09`** — **CLOSED this session.** The preview-gate false-green (below).

## Resolved this session — preview-maturity false-green + v1.2.0 shipped

**Owner decision (PDR-0011): preview rules gate exactly like stable; `maturity` is
informational-only.** Closed a **G2 false-green**: the `--fail-on` gate silently skipped
`maturity: preview` findings, so six ERROR rules (118 SQLi, 119 no-op boundary, 120
stored-taint, 121 XXE, 122 SSTI, 124 native-load) fired as active ERROR defects but the gate
passed green. Blast radius was **wider than the bug filed** (the axis was maturity, not rule
119). Fixed at all 5 gate/suppression sites; universal registry-wide regression pin
(`test_preview_gating.py`) blocks recurrence. A 3-reviewer panel caught + fixed a CHANGELOG
regression and wrong CI remediation guidance before publish.

- **Shipped v1.2.0** (minor bump — deliberate build-behavior change): merged PR #83 (main CI
  green), tagged `v1.2.0`, **published to PyPI**, installed to the local uv tool — all under
  the owner's **explicit live direction**, which also **resolved the standing release gate**
  (prior open-question #1). Published binary verified gating on the SQLi repro.
- *Metrics:* G2 reading (false-green class closed; held at 0 known holes). G1 reading (~11
  preview rules now gate → new FP-surface; PDR-0011's reversal trigger lives here: preview FP
  rate > 0.05 reopens the call — answered by severity downgrade, never a non-gating tier).

## Open questions / blocked-on-owner

1. **The Now bet keeps being deferred by reactive P1 work — 3rd consecutive session.**
   Seam-probe (PRD-0002 crit 1/2) has not moved since the 2026-06-27 rotation; Q4, PDR-0010,
   and PDR-0011 all pre-empted it. Not a crisis (each detour was a real P1), but the owner may
   want to decide: protect seam-probe capacity, or acknowledge wardline's Now is effectively
   "reactive soundness + the seam probe when clear." No PDR — it's a prioritization question,
   not a decision made.
2. **Inert-prevalence re-measurement is DUE.** Carry-over #6 said re-run the inert-gate
   instrumentation *each release*; v1.2.0 shipped this session **without** it. The Option-B
   reversal trigger (≥ 5 reliance-gated-inert framework apps; baseline = 1) is therefore
   un-refreshed against this release. Cheap to run; do it next session.
3. **Preview-gating FP watch is now live but UNMEASURED** (G1, PDR-0011). Same instrumentation
   gap as the G1 baseline — no labeled corpus yet. Watch preview-rule waiver/baseline growth.
4. **Install the pack in elspeth + relay corrected guidance (cross-repo / owner).** "blake3
   will NOT fix the gate; install the pack." Pack-bridge + Part C shipped generically.
5. **3.12 fingerprint release note (owner).** Carry-over from PDR-0006 — a one-line note; it
   was NOT explicitly included in the v1.2.0 CHANGELOG.
6. **North-star (agent-fix success rate) still unmeasured** — needs a labeled dogfood corpus.

## What this checkpoint did

- **PDR-0011** — preview rules gate like stable (`maturity` informational-only); closed the
  G2 false-green; shipped v1.2.0. Status: accepted (fix within grant; release owner-directed).
- **metrics.md** — G2 reading (false-green closed) + G1 reading (preview-gating FP-surface +
  the reversal-trigger watch). No trigger crossed.
- **Tracker** — closed `wardline-4ada23bb09`; filed `wardline-5dc82dd22a` (P3 maturity-display
  follow-up).
- **roadmap.md** — untouched (no bet changed horizon; the Now bet did not advance).
- **Grant** — unchanged; the outward-facing merge + `v1.2.0` tag + PyPI publish were all done
  under the owner's explicit direction this session (not autonomous).

## Where the next session starts

1. Confirm the grant still holds (re-confirmed 2026-06-29; next due ~2026-09-27).
2. **Run the inert-prevalence re-measurement** (open-question #2 — owed for the v1.2.0 release;
   refreshes the Option-B ≥5 trigger).
3. **The Now bet is still the seam-health probe** — PRD-0002 criteria 1 + 2: probe-protocol
   design → `/axiom-solution-architect`, then `/axiom-planning`. First decide open-question #1
   (protect its capacity vs. accept the reactive cadence).
4. Do NOT relitigate the preview-gating decision (PDR-0011) — the only live thread is its G1
   FP reversal-trigger watch.

## Provenance

Decisions: `0001` bootstrap, `0002` Now rotation, `0003` doctor seam, `0004` ACCEPT PRD-0001,
`0005` ACCEPT crit-3 + source-drift CI, `0006` fingerprint determinism, `0007` inert-gate
visibility, `0008` elspeth pack-bridge, `0009` Q4 hold-vision+instrument, `0010` extras
self-include scanner, `0011` preview rules gate like stable (+ v1.2.0 ship). Tactical truth
is the tracker; intent lives here and in `roadmap.md`.
