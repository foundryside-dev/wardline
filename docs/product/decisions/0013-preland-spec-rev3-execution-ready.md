# PDR-0013: Pre-land the Task-1 spec correction as spec rev 3; S0 plan rev 3.1 is execution-ready

Date: 2026-08-09
Status: accepted
Author: Claude product-owner checkpoint
Owner sign-off: resolution explicitly delegated by the owner in-session
("task subagents to investigate and resolve these and get the plan ready to
execute"). Inward-facing, reversible custody work within the standing grant.
Related: PDR-0012 (the governing bet), `wardline-3baba7e42f` (P0, comment 268),
`wardline-5a795253f1` (comment 269), spec rev 3 commit `1244f627`
(blob `4956ba3b33ad3c594f0ad47db98ee6d636ad3051`), plan rev 3.1 commit
`894b6d39`, legis rescue commit `a117a21`.

## Context

PDR-0012 adopted the spec + rev-3 plan as a paired contract, with the plan's
Task 1 amending spec §4.2/P11 *during execution* — while the P0 spec re-review
(`wardline-3baba7e42f`, status reviewing) still read the rev-2 text. The
independent re-review of the rev-3 plan concurred GO but flagged that
mid-review mutation as a sequencing hazard. Separately, the clean-target
preflight was stopped by an unrelated untracked plan in the Legis checkout,
and two smaller defects stood: the preflight claim named the wrong actor, and
the shared `read_level`'s declared-sibling widening was un-pinned.

## Options considered

1. **Execute as written; let the P0 re-review absorb the Task-1 amendment
   after the fact.** Rejected: the re-review would render a verdict on text
   that S0 immediately rewrites, forcing a second review pass or leaving the
   verdict ambiguous.
2. **Hold S0 until the P0 re-review lands, then amend.** Rejected: serializes
   two independent activities and leaves the known P1 false green open longer
   for no evidence gain.
3. **Pre-land the exact Task-1 correction as spec rev 3 now, make Task 1
   code-only, and pin the corrected blob statically in the plan.** Chosen: the
   re-review reads final text once, the executable plan loses a moving part,
   and the consumer-vector pin becomes a constant instead of a receipt chain.

## The call

- Spec rev 3 (`1244f627`): §4.2 gains the registry-owned `MarkerCallForm` +
  literal/dynamic splat grammar with truthful diagnostics; §4.3's PY-WL-130
  charter and §13.2's S0 row align to it; P11 splits into P11a (S0) / P11b
  (Phase 3 release gate); arg-kind naming bridged.
- Plan rev 3.1 (`894b6d39`): Task 1 is code-only; the preflight verifies the
  static blob `4956ba3b…`; the claim uses the executing session's actor; the
  `read_level` declared-sibling widening is a named contract with its own
  agreement test.
- The Legis preflight stop is resolved by preserving the untracked plainweave
  plan byte-for-byte as a commit on legis `main` (`a117a21`) — its content is
  the implementation plan for an already-committed legis design.
- Verified post-resolution: all four repos on plan-named branches, zero dirty
  lines, spec pin green.

## Rationale

Every change moves paper, not engine behaviour; the P0 re-review gains a
stable object; the plan sheds its only self-referential dependency. The two
review-flagged adjudication items that could NOT be resolved autonomously
(the §13.2 S2-vs-S3 evidence-marker stage tension; the arg-kind naming
duality) were routed to the P0 re-review via ticket comment 268 rather than
decided here.

## Reversal trigger

If the P0 re-review returns changes-requested against the rev-3 corrections
(the call-form grammar or the P11a/P11b split), S0 execution stops before any
engine commit and the spec/plan pair re-aligns under a new review — the
static pin makes any such drift a hard preflight failure, not a silent skew.
