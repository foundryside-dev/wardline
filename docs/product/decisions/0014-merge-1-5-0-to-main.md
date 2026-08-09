# PDR-0014: Merge release/1.5.0 to main; close the 1.5.0 train boundary without publication

Date: 2026-08-09
Status: accepted
Author: Claude product-owner checkpoint
Owner sign-off: directed by the owner in-session ("create/update a PR to merge
1.5.0 to main"). The merge itself is therefore owner-authorized; the still
outstanding **tag / GitHub release / PyPI publication of v1.5.0 remains
outward-facing and un-actioned** — it is escalated separately, not implied by
this merge.
Related: PR #126, merge commit `23ce09c4`, prior origin tip `7e975982`,
PDR-0012, PDR-0015.

## Context

PR #126 ("release: Wardline 1.5.0") had been open since 2026-07-29 for the
2026-07-31 release train, with an explicit train boundary: keep open, do not
tag or publish. The train date passed without a call. Meanwhile release/1.5.0
accumulated 74 further commits: the sealed Codex CLI judge transport program,
MCP trust-pack grants + the `--fail-on-inert` gate, the declaration-surface-v2
spec/plan custody chain (docs only), and product workspace updates. The owner
called the merge to open the wardline-2 line (PDR-0015).

## Options considered

1. **Hold the PR for a future re-called train.** Rejected by the owner's
   explicit instruction; holding also left ~74 commits of reviewed work
   unlanded on trunk with no consuming release path.
2. **Merge and immediately tag/publish v1.5.0.** Rejected: publication is
   outward-facing and gated; the PR body itself promises the merge publishes
   nothing.
3. **Merge to main with a merge commit, no tag, no publication; update the PR
   body first so the merged record describes its true content.** Chosen.

## The call

Pushed the 74 pending commits, appended a dated content summary to the PR #126
body (superseding the stale train note), ran the full wardline suite as the
merge gate (**5815 passed, 1 skipped, exit 0**), and merged with merge commit
`23ce09c4`. No tag, no GitHub release, no PyPI publication was created.
`release/1.5.0` was left in place (loomweave's own `release/1.5.0` remains a
live consumer target).

## Rationale

Trunk now carries everything 1.5.0 accumulated, the merged PR body is an
honest release record, and the publication decision is cleanly separated from
the merge — exactly the local-vs-published distinction the S0 plan's rollout
fence institutionalizes.

## Reversal trigger

If main's release-gate battery (full suite, `wardline scan . --fail-on ERROR`,
wheel build + smoke) goes red on the merged trunk before any v1.5.0 tag
exists, the 1.5.0 train re-opens and no tag may be cut from `23ce09c4`;
the fix lands on trunk and the release record moves forward, never by
rewriting the merge.
