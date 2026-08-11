# PDR-0019 — S0's engine core is delivered; two of the three G2 holes are closed and verified

`Date: 2026-08-11` · `Status: ACCEPTED` · `Decided by: Claude (within grant: accept work against
stated criteria)` · `Bet: Now (roadmap.md)` · `Metric: G2 — soundness / surface integrity`

## Context

The owner gave the S0 execution go on 2026-08-11 against plan rev 3.8 (`0308b4e9`), governing
spec rev 10 (`aa10dd3d`, blob `f4ba87c4…`). The four-repo preflight passed and
`wardline-4928b75782` was claimed atomically.

Tasks 1–17 of 23 are complete and committed on `release/2.0.0`, executed under
`superpowers:subagent-driven-development`: a fresh implementer per task, a task review after
each, and a fix loop where review found defects.

## Decision

**Accept the engine core as delivered against PRD-0003 criterion 1 for the two holes in S0's
scope**, and record the acceptance evidence.

Both were verified by the orchestrator on the real CLI, not taken from an implementer's report:

| hole | specimen | before | after |
|---|---|---|---|
| `wardline-4928b75782` | `@trusted(level="INTEGRAL", audit=True)` | exit 0, gate PASSED | exit **1**, `PY-WL-130` ERROR |
| `wardline-2b2a6cddfa` | `@trusted(level=_SVC_LEVEL)` | exit 0, 0 active | exit **1**, 2 active ERRORs |

Both tickets are closed with `close_commit` anchors and before/after repros in their close
comments. `wardline-4928b75782` was closed as *the call-shape half*, per its own scope note —
not as "the false green is fixed".

Hole 3 closed the way PDR-0018 required: form 5 resolves the constant so the **seed survives**
and the real leak rules fire, rather than a non-gating FACT standing in for a gate.

## Alternatives considered

- **Accept on the implementers' reports.** Faster. Rejected: this programme has repeatedly found
  sincere reports that were wrong, and a gate's colour is exactly the claim that must be
  observed rather than believed.
- **Defer acceptance until all 23 tasks land.** Cleaner bookkeeping, but it would leave verified
  closure unrecorded for the rest of a long execution and lose the evidence while it is fresh.

## Reversal trigger

If either closed hole's committed repro stops exiting 1 at `--fail-on ERROR` — at the S0 close
receipt or at PRD-0003's +30-day re-read — the acceptance is void and the hole is re-filed with a
new reading. Both repros live in `tests/unit/cli/test_false_green_exit_code_repros.py` in
`tmp_path`, deliberately in none of the frozen fixture trees, so a re-freeze cannot absorb them.

## Consequences

- Suite is at **6856 passed / 1 skipped / 1 xfailed**, from a 6093 baseline, with zero
  scan-golden regeneration throughout and the third-party pack bridge held at exactly two
  recognised boundaries every round.
- `wardline-5a795253f1` (the S0 receipt) is claimed and carries Tasks 9–23; it closes only on its
  own five conditions.
- **This does not close PRD-0003.** Criterion 6 (Rust) is owned by `wardline-b857b50b54`, still
  open; and criterion 2 is addressed by [PDR-0020].

Related: [PDR-0012], [PDR-0017], [PDR-0018], PRD-0003.
