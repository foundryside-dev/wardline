# L2 Parameter Taint Propagation Design

**Date:** 2026-04-08
**Status:** Draft (sketch-level)
**Scope:** Intra-function parameter taint tracking at analysis level 2

## Context

L1 assigns a single `TaintState` per function based on decorators or module-level
defaults. L2 extends this to per-variable taint within function bodies. This
document defines how function parameters receive and propagate taint at L2.

## Parameter Taint Assignment

At L2, each function parameter is assigned an initial taint state:

1. **Decorated functions** — Parameters inherit from the decorator's declared tier.
   An `@external_boundary` function's parameters start as `EXTERNAL_RAW`.
2. **`@data_flow(consumes=N, produces=M)`** — Parameters receive taint
   corresponding to tier N (the consumed tier). Return values are tracked at
   tier M (the produced tier).
3. **Undecorated functions** — Parameters start as `UNKNOWN_RAW` (the default).
   L3 call-graph propagation may later refine this.
4. **`self` parameter** — Inherits the class-level taint, not `UNKNOWN_RAW`.

## @data_flow at L2

The `@data_flow(consumes=N, produces=M)` decorator is advisory at L1. At L2 it
becomes enforceable:

- All parameters (except `self`/`cls`) receive the taint for tier N.
- The return taint must be compatible with tier M. If the function returns data
  that traces back to a higher-numbered (less trusted) tier than M, a finding
  is emitted.
- Conflict detection: `@data_flow(produces=1)` on a function whose body assigns
  `EXTERNAL_RAW` data to the return value is a violation.

## Taint Flow Through Parameters

Within a function body, L2 tracks taint per variable using SSA-like assignment
analysis:

```
def transform(raw_input):       # raw_input: EXTERNAL_RAW (from decorator)
    cleaned = validate(raw_input)  # cleaned: taint of validate's return
    return cleaned                 # return taint: same as cleaned
```

Parameter taint flows forward through assignments, function calls, and container
operations. The `taint_join()` lattice merges taints at control-flow merge points.

## L2 vs L1 Scope Boundaries

| Aspect              | L1                        | L2                          |
|---------------------|---------------------------|-----------------------------|
| Granularity         | Per-function              | Per-variable                |
| Parameter tracking  | No                        | Yes                         |
| `@data_flow` use    | Advisory (ignored)        | Enforced (input/output)     |
| Call resolution     | No                        | Intra-function only         |
| Control flow        | No                        | Branch merge via join       |
| Scope               | Module-wide               | Single function body        |

L2 does NOT resolve callees across function boundaries — that is L3's domain
(call-graph propagation). L2 treats called functions as opaque, using their
L1 taint as the return taint.

## Interactions with L3

L3 call-graph propagation consumes L2 parameter taint as seeds. When L3 refines
a function's effective taint, L2 re-runs with updated parameter taints. This
creates a two-pass pipeline: L2 → L3 → L2 (refined). Convergence is guaranteed
because the trust lattice is finite and propagation is monotonic toward less trust.

## Open Questions

- Whether default parameter values should carry their own taint (e.g.,
  `def f(x=SOME_GLOBAL)` — should x's default taint reflect the global's taint?).
- Container unpacking: `a, b = func()` — should each target get the same taint
  or should tuple-element tracking be attempted?
