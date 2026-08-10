# PDR-0018 — `wardline-2b2a6cddfa` resolves via a widened reader, with the FACT as residual

`Date: 2026-08-10` · `Status: ACCEPTED` · `Decided by: John (owner), in session`
· `Bet: Now (roadmap.md)` · `Metric: G2 — soundness / surface integrity`

## Context

`wardline-2b2a6cddfa`'s recorded fix direction was
`WLN-ENGINE-UNREADABLE-MARKER-VALUE` — a `Severity.NONE` / `Kind.FACT` channel,
explicitly non-gating. PRD-0003 criterion 1 requires each of the three repros to
exit **1** at `--fail-on ERROR` where it exits **0** today. A non-gating FACT can
never make a gate exit 1, so the recorded fix could not satisfy the criterion it was
filed under. PRD-0003's own constraints described a different fix — resolving
module-level constants in level-value positions — which would restore the seed.
Two documents, two fixes, one of which fails the acceptance criterion.

## Decision

**Widened reader, FACT as residual — both ship. They are not alternatives.**

1. The reader resolves module-level constants in level-value positions so the seed
   **survives** and the repro exits 1. This is what satisfies criterion 1.
2. `WLN-ENGINE-UNREADABLE-MARKER-VALUE` (`Severity.NONE` / `Kind.FACT`) remains the
   fail-closed channel for values the widened reader still cannot resolve — calls,
   f-strings, runtime config lookups — which PRD-0003 :92-94 names as non-goals.

No acceptance criterion is relaxed.

## Prerequisite

**Spec revision 6 is a hard prerequisite.** §P3 form 2 rejects bare names in value
positions, so the reader cannot legally widen until the grammar does. The plan's
governing blob pin moves with the spec, which re-invalidates the preflight: the
order is **rev 6 → plan re-pin → preflight → execute**.

## Alternatives considered

- **FACT-only, relaxing criterion 1 for this hole.** Cheaper, needs no spec change,
  closes the builtin-vs-custom observability asymmetry — but the gate still exits 0,
  so criterion 1 would have to be amended to say so. Rejected: the bet is a
  soundness recovery, and a hole you can see but not gate on is still a hole.
- **Routing the solution shape to `/axiom-solution-architect` first.** Considered;
  the constraints were already sufficiently determined by PRD-0003 to decide the
  route here and send only the residual design questions onward.

## Reversal trigger

If the widened reader cannot make the repro exit 1 without either breaching G1
(FP rate > 0.05) or requiring a scan-golden regeneration (PRD-0003 criterion 4's
reject branch), the widening is wrong — stop and re-scope rather than re-freeze a
golden.

## Open proposal — NOT decided here, requires owner ratification

Design work under this decision surfaced a question the owner has **not** ruled on,
and it must not be treated as settled:

> **Does a value that remains unreadable after the widening — dropping its seed but
> emitting a non-suppressible, counted, fingerprinted FACT — count as an open
> false-green hole for PRD-0003 criterion 2?**

The case *for* narrowing G2 to *silent* fail-open: PRD-0003 :92-94 commits the PRD
to a permanent residual unreadable population by design, so criterion 2 read
literally would be unsatisfiable by the PRD's own scope; and PRD-0003 :107-109 asks
precisely that such values "fail closed and take a diagnostic channel", which the
residual FACT does.

The case *against*: the metric's own history cuts the other way. `metrics.md` :85-95
(PDR-0011) counted as a G2 false green a defect whose findings were **fully
observable** — six ERROR rules fired as active defects while the gate passed green.
G2's operative test there was whether the gate's colour matched reality, not whether
anything appeared in the output.

**Status: UNRATIFIED PROPOSAL.** Spec rev 6 may record it as a proposal, clearly
marked, but must not assert it as settled or attribute it to this PDR. Narrowing a
continuously-held soundness metric mid-bet is an owner call; if ratified it needs a
matching amendment to PRD-0003 :28 / :48-53 and a dated reading in `metrics.md`.

Related: [PDR-0017] (three-hole scope), [PDR-0012] (original S0 bet), PRD-0003,
`wardline-2b2a6cddfa`.
