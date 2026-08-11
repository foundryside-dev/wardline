# PDR-0020 — PDR-0017's reversal trigger fires: re-baseline PRD-0003 on a fourth hole

`Date: 2026-08-11` · `Status: ACCEPTED` · `Decided by: Claude (executing PDR-0017's
pre-committed response)` · `Bet: Now (roadmap.md)` · `Metric: G2 — soundness / surface integrity`

## Context

PDR-0017 set PRD-0003's baseline at **three** known false-green holes and pre-committed the
response to a fourth:

> *A fourth hole of the same class open at the close receipt or at the +30-day re-read
> **re-baselines PRD-0003 rather than failing it** — criterion 2 reads the count, not the delta.*

PRD-0003 itself named the assumption this guards: *"that these three are all the holes of this
class. The count went 1 → 3 under one session's inspection."*

A fourth was found on 2026-08-11 and filed as **`wardline-69a58cb05f`** (P1), by adversarial
review of Task 14's drop-coverage matrix. An ordinary cross-module re-export of a builtin
marker — `from pkg.al import T`, then `@T(level="ASSURED")` — drops the seed with **zero
diagnostic channels**, across all four marker shapes. Measured on identical code:

```
direct import  →  ['PY-WL-101', 'WLN-L3-LOW-RESOLUTION']   declared
via re-export  →  ['WLN-L3-LOW-RESOLUTION']                NOT declared
```

`PY-WL-101` is lost and the function sits in `RAW_ZONE`, where every tier-modulated leak rule
goes quiet. Re-exporting a decorator through a package's own namespace is an ordinary Python
idiom, not an exotic shape.

A fifth item was also filed — `wardline-70a8bb3875` (P1): `--fail-on-inert` silently no-ops on
Rust scans, reporting `PASSED` while reciting the condition that should have tripped it. That is
G2's *policy-bypass* axis rather than its taint axis, but G2's definition covers both.

## Decision

**Execute PDR-0017's pre-committed response: re-baseline PRD-0003 rather than fail it.** The
bet's criterion 2 is read against the current count, and the count is not zero.

The re-baselined G2 position is recorded in `metrics.md` with this date. PRD-0003's success
metric moves from `BASELINE: 3 → TARGET: 0` to a corrected baseline reflecting what is actually
open, and its criterion 6 remains owned by `wardline-b857b50b54`.

## Alternatives considered

- **Declare the bet paid on the two closed holes.** Two holes genuinely closed and verified is
  real progress. Rejected outright: criterion 2 reads the **count**, precisely so that a partial
  win cannot be banked as a whole one, and G2 is a *continuously held* target.
- **Fail the bet.** Defensible on a literal reading of criterion 2, but PDR-0017 anticipated this
  exact case and pre-committed to re-baselining — the discovery of a further hole by deliberate
  hunting is the mechanism working, not the bet failing.
- **Treat the re-export hole as out of class.** Rejected on measurement: same fail-open
  direction, same lost rule, same lattice mechanism as the two just closed.

## Reversal trigger

If a **fifth** hole of this class is found before the S0 close receipt, do not re-baseline a
third time — that pattern would indicate the class is not enumerable by inspection, and the bet
should be re-scoped around a systematic search (or killed) rather than chased hole by hole.
Re-read the count at the S0 close and at +30 days either way.

## Consequences

- **G2 is not at target and the Now bet cannot be banked.** Open at this checkpoint:
  `wardline-b857b50b54` (Rust marker shape, from the original three),
  `wardline-69a58cb05f` (re-export), and `wardline-70a8bb3875` (inert gate no-op).
- PRD-0003's own stated assumption — that three was all of them — is now falsified twice over
  (1 → 3 → 4+). That is evidence about the *method*, not just the count: both expansions came
  from adversarial review of work already believed complete.
- No sequencing or dated forecast originates here; that remains `/program-management`'s.

Related: [PDR-0017] (the trigger this executes), [PDR-0019], PRD-0003 criteria 2 and 6,
`wardline-69a58cb05f`, `wardline-70a8bb3875`, `wardline-b857b50b54`.
