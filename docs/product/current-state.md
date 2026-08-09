# Current State — Wardline

> Resume brief. Checkpointed 2026-08-09 from source head `5252e3f5`; the
> checkpoint commit itself is the durable audit record. Read this first next session.

## The bet right now

**Close S0's declaration-surface false green and prove consumer-first local
readiness without emitting new vocabulary** (PDR-0012; `roadmap.md` → Now).

- *Metric it moves:* **G2** back to 0 known false-green/fail-open holes while
  holding **G1** at FP rate ≤ 0.05; **G2-seam** must remain honest across the staged
  consumer contracts.
- *Product contract:* `docs/superpowers/specs/2026-08-09-declaration-surface-v2-design.md`
  at commit `ed7bfe86`, paired with the mandatory Task-1 correction and refreshed
  blob receipt in the plan.
- *Delivery plan:* `docs/superpowers/plans/2026-08-09-s0-hardening-and-consumer-prep.md`
  rev 3 at commit `5252e3f5` — 21 tasks, local S0 GO after preflight, published
  generic-3/attest-3 emission NO-GO.

## In flight (tracker is tactical truth)

- **`wardline-4928b75782`** (P1 bug, triage, ready) — the live malformed-marker
  false green. It must be atomically claimed first and closes only after plan Tasks 2–6
  plus the before/after gate repro.
- **`wardline-5a795253f1`** (P1 task, open, blocked by the bug) — the remaining S0
  hardening/QE/consumer-prep receipt. Claim only after the bug closes; accept only after
  the plan's four-repository local-install proof.
- **`wardline-c66f62894b`** (P1 program tracker, in progress; stale `codex` claim) —
  the prior seam-conformance bet. Its six core seams are at-bar; two P4 non-gating
  follow-ons remain. It moves to Next as residual closeout rather than competing with S0.

## Open questions / blocked-on-owner

- **Cross-repository preflight stop:** `/home/john/legis` contains the unrelated
  untracked plan `docs/superpowers/plans/2026-07-14-plainweave-preflight-v2-conformance.md`.
  Preserve it; S0 cross-repository execution stops until its owner resolves it.
- **Stale tracker custody:** `wardline-c66f62894b` remains assigned to `codex` with an
  expired claim. Reconcile or hand off that residual program claim separately; it does
  not authorize taking S0 work out of order.
- **Published release boundary:** no immediate release approval is requested.
  Publishing consumer releases or enabling generic-3/attest-3 producer emission must
  return to the owner after the published-release gate; S0 records
  `published_emission_ready=false`.
- **Standing measurement debt:** agent-fix success and the preview-rule FP rate remain
  unmeasured; reliance-gated inert-framework prevalence is still due for a per-release
  reread. S0's corpus gates improve evidence but do not manufacture those product-value
  readings.

## What this checkpoint did

- Appended **PDR-0012**, accepting the declaration-surface spec and S0 rev-3 plan as
  a paired contract and rotating S0 to Now.
- Reconciled the active tracker chain: `wardline-4928b75782` →
  `wardline-5a795253f1`; retained the seam program only as a residual Next bet.
- Refreshed G1/G2/G2-seam readings: one known G2 false green is live, waiver usage is
  zero against a fixed ceiling of 5, and no v3 producer surface exists in S0.
- Preserved the authority boundary: local implementation is dispatched; public release
  and producer emission are not authorized.

## Next session, start here

1. Re-read PDR-0012 and the rev-3 plan; do not substitute the older 18-task plan.
2. Resolve the unrelated Legis clean-target stop through its owner.
3. Run the plan preflight and atomically start `wardline-4928b75782` with the bug
   lifecycle's required `--advance`; do not claim `wardline-5a795253f1` first.
4. Execute Task 1 and record the corrected spec commit/blob before any consumer-vector
   work. Keep `published_emission_ready=false` throughout S0.

## Provenance

Latest decision: PDR-0012. Prior decisions 0001–0011 remain append-only under
`docs/product/decisions/`. Tactical backlog detail remains in Filigree; this file records
intent, contract anchors, gates, and the next resume seam.
