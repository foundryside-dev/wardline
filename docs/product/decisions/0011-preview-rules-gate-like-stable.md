# PDR-0011: Preview-maturity rules gate exactly like stable (close the G2 false-green); ship v1.2.0

Date: 2026-06-30
Status: accepted
Author: agent:claude (systematic-debugging session; recorded at /product-checkpoint)
Owner sign-off: **Fix approach** — autonomous within grant (a reversible, repo-local
soundness fix + regression pins; the grant authorizes accept/dispatch of reversible
repo-local work). **Release** — the merge to `main`, the `v1.2.0` tag, and the PyPI publish
are outward-facing and were performed under the owner's **EXPLICIT live direction this
session** ("merge it" / "publish it"), which also resolved the standing release gate carried
in `current-state.md` open-question #1. No outward-facing action was taken autonomously.
Related: `vision.md` thesis invariant #2 (soundness — an agent-defined boundary the engine
cannot prove yields an honest `UNKNOWN`, **never a false green**); G2 soundness + G1
false-positive in `metrics.md`; tracker `wardline-4ada23bb09` (closed); bundled delivery of
the concurrent `analyzed_paths` feature (forced by a shared working tree — see rationale).

## Context

`wardline-4ada23bb09` (P1): the `--fail-on` gate predicate silently **skipped**
`maturity: preview` findings. Six ERROR-severity rules — PY-WL-118 (SQL injection), 119
(degenerate/no-op trust boundary), 120 (stored taint → trusted), 121 (XXE), 122 (SSTI), 124
(native-library load) — fired as active ERROR defects but `wardline scan --fail-on ERROR`
passed **green** (`would_trip_at: null`). A G2 false-green: an armed gate certifying clean
over real ERROR defects, present in the shipped 1.1.0. The skip contradicted the
long-documented contract (`docs/concepts/rules.md`: preview rules "participate in the gate,
baseline, waivers, and judge exactly like stable rules") and had been introduced by an
unrelated "audit remediation" commit with no rationale. The blast radius was **wider than
the bug filed**: it scoped 119 as narrow; the real axis was maturity, so SQLi/XXE/SSTI were
also silently non-gating.

## Options considered

1. **Preview gates exactly like stable; `maturity` becomes purely informational** (CHOSEN).
   Remove the preview-exclusion at all five gate/suppression sites; preview findings gate
   AND become baselineable. Makes the docs true; closes the whole class in one move.
2. **Keep an advisory (non-gating) preview tier; rewrite the docs to match; promote the six
   dangerous ERROR rules to stable individually.** Rejected: keeps a two-tier gate the docs
   would have to newly explain, needs per-rule promotion judgement, and preserves a maturity
   knob that silently changes enforcement — the exact surprise that caused the bug.
3. **Literal filed scope — promote only PY-WL-119 to stable.** Rejected: knowingly leaves
   SQLi/XXE/SSTI as false-greens; indefensible for a security gate.

## The call

**Option 1.** Confirmed with the owner (AskUserQuestion). `maturity` is now an informational
"predicates may still sharpen" label only; it never affects gating, counting, or baselining.
A universal regression pin (`test_preview_gating.py`) asserts every preview rule in the
registry gates at its base severity, so the class cannot silently reopen. Shipped as
**v1.2.0** — a deliberate minor (not patch) bump because it changes build outcomes for
existing users. Merged (PR #83, main CI green), tagged `v1.2.0`, PyPI-published, installed
into the local uv tool — all under the owner's explicit direction. A 3-reviewer panel gated
the release and caught two real defects fixed before publish: a CHANGELOG regression (a
swallowed `[1.1.0]` section) and wrong CI remediation guidance (under the secure default,
baseline/waive clears the gate only with `--trust-suppressions`; CI must scope with
`--new-since`).

## Rationale

Serves thesis invariant #2 directly: "an agent-defined boundary the engine cannot prove
yields an honest `UNKNOWN`, **never a false green**." An armed `--fail-on ERROR` gate that
passes over an active SQL-injection finding is the exact failure the product exists to
prevent, and the doc contract already promised the fixed behavior. Choosing the simplest
maturity model (informational-only) *removes* the enforcement-changing knob rather than
documenting it — one mental model, fewer surprises. The `analyzed_paths` delta-coverage work
from a concurrent session rode along in the same commit because `run.py` was co-modified and
non-interactive staging could not split it; it was independently reviewed (sound) rather than
vouched-for by bundling.

## Reversal trigger

Reopen the "preview gates like stable" call if the newly-gating preview rules drive a
false-positive-driven build-break problem — concretely, if the **G1** (`metrics.md`) FP rate
on the preview-rule population exceeds **0.05 of active findings**, or preview-rule
waiver/baseline growth outpaces preview-rule additions (the lattice-mis-design proxy). The
in-thesis response is per-rule severity downgrade or rule refinement — **not** reintroducing
a non-gating preview tier (that restores the false-green). Watched under G1 + G2's
per-release soundness posture.
