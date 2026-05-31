# ADR: Retain the 8-state taint lattice and `taint_join` as a documented contrast operator

- **Status:** Accepted
- **Date:** 2026-05-31
- **Resolves:** taint-combination audit findings F1, F3, F4, F5
  (`docs/audits/2026-05-31-taint-combination-audit.md`)

## Context

Wardline's taint engine combines, merges, and aggregates per-value and
per-function trust levels at many sites (expression operands, control-flow merge
points, call-graph callee sets). Historically several of these sites used
`taint_join` — a *provenance-clash* operator that maps any pair of
different-family clean states to the absorbing top `MIXED_RAW`. Three migrations
(`wardline-4d94577013` L2 expression combiners, `wardline-4d9f840c24` L2
control-flow merges, `wardline-17b9ce2c70` L3 callee combinations) replaced every
combination site with `least_trusted` — the rank-meet (weakest-link) operator —
because two clean callees/branches of *different* families combining to
`MIXED_RAW` (rank 7, in the firing raw zone) was a `PY-WL-101` false positive.

The 2026-05-31 audit confirmed the engine is correct after these migrations:
**zero live false positives, zero live false negatives**, every combination site
on `least_trusted`. It also established the linchpin result: the only taint
states any source can introduce into the live pipeline are
`{INTEGRAL, ASSURED, GUARDED, EXTERNAL_RAW, UNKNOWN_RAW}`. `least_trusted` returns
one of its inputs, so its closure over that set *is* that set — the trio
`{MIXED_RAW, UNKNOWN_GUARDED, UNKNOWN_ASSURED}` is **never produced** anywhere in
production.

That left a disposition question (audit F3): `taint_join` now has **no production
call site** — its only live callers are its own 8 unit tests. Should it (and its
three orphan states) be deleted (COLLAPSE to a 5-state lattice), or retained?

## Decision

**RETAIN** the full 8-state `TaintState` lattice, the `taint_join` operator, and
its `_JOIN_TABLE`. `taint_join` is kept deliberately as the documented contrast
operator — the "why we did NOT use this" record — and is explicitly marked in its
docstring as having no production call site.

The reachable-set invariant is instead made **enforced** at the two previously
ungated dynamic-construction entry points (audit F5):

- `stdlib_taint.py` — constrained to `{ASSURED, GUARDED, EXTERNAL_RAW, UNKNOWN_RAW}`.
- `summary_cache.py` `_deserialise_summary` — constrained to the full reachable
  set `{INTEGRAL, ASSURED, GUARDED, EXTERNAL_RAW, UNKNOWN_RAW}` (a `@trusted`
  function legitimately caches `INTEGRAL`).

Both reject the unreachable trio with a `ValueError` that cites the invariant.

## Consequences

### Positive

- **No orphaned references.** ~18 regression-guard comments across the test suite
  cite `taint_join` by name as the operator the migrations contrast against;
  `taint_join`'s 8 unit tests pin the provenance-clash semantics
  (`taint_join(INTEGRAL, ASSURED) == MIXED_RAW`) those comments reference.
  Retaining the operator keeps that record intact and authoritative.
- **Invariant is enforced, not incidental.** The F5 parser guards make the trio's
  unreachability a checked property at every dynamic entry point, rather than a
  fact that holds only because nobody deleted the states. A corrupted/tampered
  on-disk cache or a future stdlib-table entry carrying `MIXED_RAW` is now
  rejected, not silently injected.
- **Extensibility headroom.** The `UNKNOWN_*` family and the provenance-clash
  semantics remain available should a future analysis tier (e.g. true value-level
  provenance tracking) need them, without re-litigating the lattice design.

### Negative / accepted

- The codebase carries an operator with no production call site. This is a
  deliberate, documented exception to a strict no-dead-code stance — mitigated by
  the explicit docstring marker, this ADR, and `docs/concepts/taint-algebra.md`.

### Rejected alternative — COLLAPSE to 5 states

Delete `taint_join`, `_JOIN_TABLE`, the three orphan states, and the 8 unit
tests; soften every regression-guard comment to reference `least_trusted` only.
Rejected because it is a larger, lower-value churn that orphans the very
references that document *why* the migrations were necessary, and it would rely on
deletion (rather than an enforced guard) to keep the trio unreachable — a weaker
guarantee that silently breaks the moment any state is re-added.

## References

- Audit: `docs/audits/2026-05-31-taint-combination-audit.md` (F1, F3, F4, F5)
- Taint algebra spec: `docs/concepts/taint-algebra.md`
- Operator definitions: `src/wardline/core/taints.py`
