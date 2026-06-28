# PDR 0005 — ACCEPT PRD-0002 crit-3; ship the source-drift CI fail-closed leg (path A)

`Date: 2026-06-28` · `Status: Accepted` · `Decider: product-owner agent (within grant —
dispatch + accept; the cross-repo CI read credential was provisioned by the human owner
this session via AskUserQuestion)`

## Context

DISPATCH of the Now bet's **crit-3** (PRD-0002 "producer artifacts peers can verify
against" — the two ready P2s `c0563eee74` warpline contract + `79ba05f464` SEI-oracle CI)
to `/axiom-planning`. The implementation-planning reality pass found crit-3 **~90% already
shipped** against stale ticket text:

- crit-3a — the `wardline.delta_scope.v1` producer artifact + its **unconditional** in-CI
  drift check (`test_wardline_delta_scope_contract.py`) — was already in place; the consumer
  Layer-1 byte-pins already run on every PR.
- The genuine remaining gap: the producer-**SOURCE** byte-drift checks (`sei_drift`,
  `worklist_drift`) ran in **no CI job** — `pyproject` deselects them and the `live-oracles`
  matrix provisions sibling *binaries*, not *source*. So a silent divergence between
  wardline's vendored copy and the upstream HEAD was caught only at a manual release gate.
- The peers had since **published** their artifacts to origin/main (warpline reverify wire;
  loomweave SEI oracle), lifting what would have been a scope-C blocker.

## Options

- **(a) Plan crit-3 as a large build.** *Rejected:* it was 90% done; a big plan would be
  theatre.
- **(b) Path B — producer-published-artifact fetch.** *Rejected:* peers publish to repo
  *paths*, not fetchable URLs; a fetch endpoint is unshipped peer work = partial scope C.
- **(c) Path A — provision sibling source checkout in CI + arm the drift markers
  fail-closed.** *Chosen.* Wardline-side, uses the existing fail-closed mechanism.

## The call

**ACCEPT crit-3.** Shipped the source-drift fail-closed CI leg (path A):
- **Taxonomy change (`src` semantic):** `sei_drift` + `worklist_drift` added to
  `wardline._live_oracle.LIVE_ORACLE_MARKERS`, so an armed `WARDLINE_LIVE_ORACLE_REQUIRED=1`
  run turns a missing-source SKIP into a FAILURE. They were the skip-clean release-gate tier;
  they now fail closed because a CI job provisions their source.
- New weekly/dispatch **`source-drift` job** checks out loomweave + warpline origin/main via
  the owner-provisioned read-only `WARDLINE_SIBLING_SOURCE_TOKEN` and runs the markers
  fail-closed. Off PRs, so a sibling change never blocks a wardline PR.
- T2 env-var normalize: the published-schema check read a dead `WARPLINE_REPO`; fixed to the
  standard `WARDLINE_WARPLINE_REPO`.
- Tickets `79ba05f464` + `c0563eee74` **closed** (anchored to `8fe09d6f`).

Commits `8fe09d6f`, `a1f121f1`. **Verified:** dispatched run 28301178826 GREEN (2 passed vs
loomweave + warpline origin/main); full suite 4475 passed; ruff/mypy clean.

**Deferred (peer-gated, NOT blocking):** the formal published-SCHEMA validation
(`reverify_worklist.v1.schema.json`) stays out of the fail-closed job until warpline pushes
that schema to origin/main (today only in ~34 local commits); arms by marking the schema
test `worklist_drift` then.

## Rationale

Within-grant dispatch + accept. The producer artifacts exist, so this is not contingent on
unshipped peer code (not scope C). The source-byte drift these crown-jewel seams could
silently carry is now caught in CI, strengthening **G2-seam**. The cross-repo read
credential is first-party CI infra the owner provisioned — not a grant escalation.

## Reversal trigger

Metric-bound, tied to `metrics.md` **G2-seam**:
1. **Flaky/over-broad reds.** If `source-drift` reds on benign sibling churn rather than
   genuine contract drift, revisit cadence/scope (it is weekly/dispatch, not per-PR,
   precisely to bound this) — do not weaken it to skip-clean.
2. **Honesty-invariant breach (standing).** A new Wardline-owned seam returning
   confident-empty with no machine-readable reason is a **P0**, same class as a fail-open
   taint hole.
3. **Scope-C creep.** If closing the remaining crit (criteria 1/2 — the seam-health probe)
   proves contingent on unshipped peer work, re-scope to wardline-only; do not fail the bet.
