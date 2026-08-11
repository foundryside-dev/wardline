# Current State — Wardline

> Resume brief. Checkpointed 2026-08-11 from `release/2.0.0` @ `ffe890d5` (Tasks 1–17 of S0).
> The checkpoint commit is the durable audit record. Read this first next session.

## The bet right now

**Return G2 to zero known false-green holes, and prove consumer-first local readiness
without emitting new vocabulary** (PRD-0003; `roadmap.md` → Now). Programme is Wardline 2,
resident on `release/2.0.0`.

- *Metric:* **G2** to 0 known false-green/fail-open holes, holding **G1** FP ≤ 0.05.
- *Contracts:* spec **rev 10** (`aa10dd3d`, blob `f4ba87c4…`), S0 plan **rev 3.8** (`0308b4e9`).
- **G2 is NOT at target and the bet cannot be banked** — see PDR-0020.

## In flight (tracker is tactical truth)

- **`wardline-5a795253f1`** — the S0 receipt, `in_progress`, carries Tasks 9–23. Closes only on
  its own five conditions (i)–(v).
- **`wardline-b857b50b54`** (P1, open) — Rust marker shape. From the original three; **owns
  PRD-0003 criterion 6**. Not fixed by S0 by owner ruling.
- **`wardline-69a58cb05f`** (P1, open, NEW) — a cross-module re-export of a builtin marker drops
  the seed with **zero channels**; `PY-WL-101` lost, function in `RAW_ZONE`. The fourth hole.
- **`wardline-70a8bb3875`** (P1, open, NEW) — `--fail-on-inert` silently no-ops on Rust scans.
- **`wardline-74c9a455c5`** (P2, open, NEW) — corpus FP measurement covers 16 of 27 rules.
- **`wardline-1da8b93a73`** (P2, open, NEW) — a memoising pack never warms the cache under `mcp`.
- **`wardline-c66f62894b`** (Next band) — seam-conformance closeout; stale `codex` claim, unchanged.

## Open questions / blocked-on-owner

1. **41 commits are unpushed.** Tasks 1–17 exist only locally. Durability risk — push?
2. **Branch protection is off**, so Task 17's CODEOWNERS is pure routing and the identity-corpus
   review gate does not gate. Verified live (`branches/main/protection` → 404, `rulesets` → `[]`).
   Enable "require review from Code Owners"?
3. **Cross-repo readiness audit was still running at checkpoint** (`wf_b8fb2102-3ab`) — five
   lenses verifying every anchor Tasks 19–23 cite across loomweave/warpline/legis, the last
   re-freeze budget, and whether the five close conditions are checkable. Read its verdict before
   dispatching any implementer into a sibling repo.
4. **Standing measurement debt**, unchanged: agent-fix success (north star) unmeasured; preview-rule
   FP rate unmeasured and now known to be a 16-of-27 gap; reliance-gated inert prevalence due a
   per-release re-read.

## What this checkpoint did

- **PDR-0019** accepted the engine core: two of three holes closed, each verified on the real CLI
  rather than from a report. **PDR-0020** executed PDR-0017's reversal trigger — a fourth hole
  re-baselines PRD-0003 rather than failing it.
- **PDR-0021** recorded Task 13's sixteen-round overrun and its park on a *construction* argument,
  with a durable residual document beside the code. **PDR-0022** adopted the owner's three standing
  review directives and the `reviewing-for-vacuity` catalogue.
- Applied PDR-0017's declared-but-never-written roadmap refresh and G2 reading; added the G1
  16-of-27 qualification; reconciled the tracker (2 closed with evidence, 4 filed, 1 amended twice).

## Next session, start here

1. Read the cross-repo audit verdict (item 3), then **Task 18** (changelog, in-repo) and
   **Tasks 19–23** (cross-repo). The four-repo preflight **passes** as of this checkpoint —
   all four clean, spec pin OK — but re-run it, it is cheap and it failed once already today.
2. Task 20 holds the **last** sanctioned MCP-golden re-freeze; Task 9 spent the first.
3. Answer items 1 and 2 above — both are owner actions, neither blocks execution.

## Provenance

Latest decisions PDR-0019..0022; 0001–0018 remain append-only under `docs/product/decisions/`.
Engine-level residuals live in `src/wardline/scanner/taint/PROVIDER_FINGERPRINT_RESIDUALS.md`,
which is the durable artifact and outlives the plan workspace. Review heuristics live in
`.claude/skills/reviewing-for-vacuity/`.
