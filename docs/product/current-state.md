# Current State — Wardline

> Resume brief. Checkpointed 2026-08-09 from source head `23ce09c4` (main) /
> `release/2.0.0` primary checkout; the checkpoint commit itself is the durable
> audit record. Read this first next session.

## The bet right now

**Close S0's declaration-surface false green and prove consumer-first local
readiness without emitting new vocabulary** (PDR-0012; `roadmap.md` → Now).
This program is **Wardline 2**; its residency is **`release/2.0.0`** (PDR-0015).

- *Metric it moves:* **G2** back to 0 known false-green/fail-open holes while
  holding **G1** at FP rate ≤ 0.05; **G2-seam** must remain honest across the staged
  consumer contracts.
- *Product contract:* declaration-surface-v2 spec **rev 3** at `1244f627`
  (blob `4956ba3b33ad3c594f0ad47db98ee6d636ad3051` — the static preflight pin;
  supersedes the `ed7bfe86` anchor in PDR-0012 via PDR-0013).
- *Delivery plan:* S0 plan **rev 3.1** at `894b6d39` — 21 tasks, Task 1
  code-only, local S0 GO after preflight, published generic-3/attest-3
  emission NO-GO. Wardline work lands on `release/2.0.0`; loomweave stays
  `release/1.5.0`; warpline/legis stay `main`.

## In flight (tracker is tactical truth)

- **`wardline-4928b75782`** (P1 bug, ready, unclaimed) — the live malformed-marker
  false green. Atomically claim first (executing session's actor); closes only after
  plan Tasks 2–6 plus the before/after gate repro.
- **`wardline-5a795253f1`** (P1 task, open, blocked by the bug) — the S0
  hardening/QE/consumer-prep receipt. Comment 269 records execution readiness.
- **`wardline-3baba7e42f`** (P0 spec, reviewing) — the pending re-review now reads
  spec rev 3; comment 268 carries provenance plus two adjudication items (the §13.2
  S2-vs-S3 evidence-marker stage tension; the arg-kind naming duality).
- **`wardline-c66f62894b`** (P1 program tracker, in progress; stale `codex` claim) —
  residual seam-conformance closeout, Next band; unchanged this session.

## Open questions / blocked-on-owner

- **S0 execution go (owner):** subagent-driven (recommended) or inline? Everything
  else is ready — the four-repo clean-target preflight was verified green 2026-08-09
  (all plan-named branches, zero dirty lines, spec pin OK).
- **P0 re-review verdict (owner-run):** against spec rev 3; includes the two
  comment-268 adjudication items.
- **Stale tracker custody:** `wardline-c66f62894b` remains assigned to `codex` with
  an expired claim; reconcile separately.
- **Standing measurement debt:** agent-fix success and the preview-rule FP rate
  remain unmeasured; reliance-gated inert-framework prevalence is due a per-release
  reread — 2.0.0 planning should schedule it.

## What this checkpoint did

- Appended **PDR-0013** (spec rev 3 pre-landed for the P0 re-review; plan rev 3.1
  execution-ready; Legis preflight stop resolved via legis `a117a21`).
- Appended **PDR-0014** (owner-directed merge of release/1.5.0 → main as
  `23ce09c4`, suite-gated 5815-green, no tag/publication) and **PDR-0015**
  (wardline-2 residency `release/2.0.0`).
- Reconciled the tracker live during the session (comments 268/269); no horizon
  change, so `roadmap.md` untouched; no new metric readings, so `metrics.md`
  untouched (G2 still shows exactly one known false green, closed by executing S0).
- **Post-checkpoint addendum (same day):** the owner authorized v1.5.0
  publication — **PDR-0016**: tag `v1.5.0` at `23ce09c4`, Release workflow
  `31296246189` green, `wardline 1.5.0` live on PyPI (wheel + sdist, attested).
  The PDR-0014 publication escalation is closed. Also noted: spec revision 4
  (S0-contract reconciliation, §17) is in flight in the working tree — once it
  commits, plan rev 3.1's static blob pin `4956ba3b…` must be refreshed to the
  rev-4 blob (the pin's own drift rule makes this a hard preflight stop, by design).

## Next session, start here

1. If the owner has given the execution go: run the plan preflight from rev 3.1,
   atomically `start-work wardline-4928b75782` under the executing actor, and begin
   Task 1 on `release/2.0.0` — the plan header names the required sub-skill.
2. If the P0 re-review verdict is in: on GO, close `wardline-3baba7e42f`; on
   changes-requested, S0 STOPS pre-engine-commit per PDR-0013's reversal trigger.
3. Keep `published_emission_ready=false` throughout S0; the v1.5.0 publication
   question is independent and owner-gated.

## Provenance

Latest decisions: PDR-0013..0015. Prior decisions 0001–0012 remain append-only
under `docs/product/decisions/`. Tactical backlog detail remains in Filigree; this
file records intent, contract anchors, gates, and the next resume seam.
