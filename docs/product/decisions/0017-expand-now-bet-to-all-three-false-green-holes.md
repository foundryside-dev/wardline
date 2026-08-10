# PDR-0017 — Expand the Now bet to all three known false-green holes

`Date: 2026-08-10` · `Status: ACCEPTED` · `Decided by: John (owner), in session`
· `Bet: Now (roadmap.md)` · `Metric: G2 — soundness / surface integrity`

## Context

PDR-0012 adopted the S0 declaration-surface bet when exactly **one** known
false-green hole was open (`wardline-4928b75782`). On 2026-08-09 that ticket was
re-scoped to the **Python builtin call shape only**, and two siblings of the same
class, in the same fail-open direction, were split out:

- `wardline-b857b50b54` — Rust: a non-canonical `/// @trusted(...)` marker shape
  silently fails to match and suppresses every finding on the function.
- `wardline-2b2a6cddfa` — a statically unreadable level *value* drops the seed with
  no diagnostic on any channel.

The count is **3**, not 1. `roadmap.md`'s Now entry claims the bet moves "G2 back to
0", but S0 as scoped closes only the first — so the bet could complete fully green
and leave G2 at 2. A bet that cannot reach its own stated metric is not a bet.

## Decision

The Now bet is **re-scoped to the full three-hole G2 recovery**, as specified in
PRD-0003. S0 executes as-is against plan rev 3.4 for `wardline-4928b75782`;
`wardline-b857b50b54` and `wardline-2b2a6cddfa` close before G2 is read.

## Alternatives considered

- **Execute S0 as-is and read G2 later.** Fastest to a green S0 receipt, but leaves
  G2 off target at 2 with no bet pointed at it — the failure mode this PDR exists to
  prevent.
- **Hold S0 until the spec rev 6 amendment lands.** Cleanest single pass, but delays
  work already reviewed green by three panels for no soundness gain.

## Reversal trigger

A fourth hole of the same class open at the close receipt or at the +30-day re-read
**re-baselines PRD-0003 rather than failing it** — criterion 2 reads the count, not
the delta. If the count cannot reach 0 within the bet, kill the bet and record the
residual as a standing G2 reading rather than banking a partial win.

## Consequences

- `roadmap.md`'s Now entry and contract anchors are refreshed to PRD-0003, spec
  rev 6, and plan rev 3.4.
- `metrics.md` G2 takes a dated reading moving 1 → 3 open holes (2026-08-10), which
  is a **reversal-trigger crossing** on a continuously-held target and is recorded
  as such.
- Sequencing across the three holes and any dated forecast belong to
  `/program-management`; no date originates here.

Related: [PDR-0012] (original S0 bet), [PDR-0018] (the `wardline-2b2a6cddfa` fix
route), PRD-0003.
