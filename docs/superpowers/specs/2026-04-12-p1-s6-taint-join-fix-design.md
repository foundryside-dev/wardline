# Design: P1-S6 Taint Join Algebra Fix

**Date**: 2026-04-12
**Obligation**: `P1-S6-TAINT-JOIN-ABSORBING`
**Tracker**: `wardline-cf49edcde8`
**Status**: Design — pending approval

## Problem Statement

The L3 callgraph propagation module (`src/wardline/scanner/taint/callgraph_propagation.py`)
does not use the normative `taint_join()` algebra defined in §6 of the Wardline
specification. Instead it maps taint states to integer ranks via `TRUST_RANK`
(a total order from INTEGRAL=0 to MIXED_RAW=7), takes `max()` across callee
ranks, and maps back. This treats taint states as a total order when the spec
defines a lattice where cross-classification pairs collapse to MIXED_RAW.

**Example divergence:** A function calling both an ASSURED callee and a GUARDED
callee. Under `TRUST_RANK/max()`: `max(1, 2) = 2` → GUARDED. Under
`taint_join()`: `join(ASSURED, GUARDED) = MIXED_RAW`. The spec is explicit:
cross-classification merges MUST produce MIXED_RAW.

The correct `taint_join()` function exists at `src/wardline/core/taints.py:58`
with a complete 8×8 truth table test. It is simply not used in propagation.

## Security Impact

Eight cross-classification merge cases silently under-taint today:

| Merge | Current (TRUST_RANK) | Correct (taint_join) |
|---|---|---|
| INTEGRAL + ASSURED | ASSURED | MIXED_RAW |
| INTEGRAL + GUARDED | GUARDED | MIXED_RAW |
| INTEGRAL + EXTERNAL_RAW | EXTERNAL_RAW | MIXED_RAW |
| ASSURED + GUARDED | GUARDED | MIXED_RAW |
| ASSURED + EXTERNAL_RAW | EXTERNAL_RAW | MIXED_RAW |
| ASSURED + UNKNOWN_RAW | UNKNOWN_RAW | MIXED_RAW |
| GUARDED + EXTERNAL_RAW | EXTERNAL_RAW | MIXED_RAW |
| GUARDED + UNKNOWN_* | varies | MIXED_RAW |

These are genuine missed findings — functions that mix data from different
trust classifications are not flagged as MIXED_RAW, potentially allowing
trust-boundary violations to pass undetected by downstream PY-WL-001/002 rules.

## Design Decision: Approach A

**Panel review**: 7-reviewer panel conducted 2026-04-12. Verdict: 6–1 for
Approach A (Systems Thinker dissenting, recommending B with caveat).

### What Approach A does

1. **Replace** `TRUST_RANK/max()` with `taint_join()` for all **callee taint
   combination** operations in `propagate_callgraph_taints()`.
2. **Retain** `TRUST_RANK` for all **ordering comparison** operations: floor
   clamps, post-assertions, via_callee provenance selection,
   L3_LOW_RESOLUTION threshold checks.

### Why not Approach B (taint_join everywhere including floor clamps)

The SAE reviewer proved Approach B **unsound** with a counterexample:

- L1 taint = ASSURED (rank 1), callee combined = INTEGRAL (rank 0).
- Floor clamp intent: result should be ASSURED (the floor — "never more
  trusted than L1").
- `taint_join(ASSURED, INTEGRAL)` = MIXED_RAW (rank 7) — catastrophic
  over-taint.

The floor clamp is an ordering constraint ("result ≥ L1 baseline"), not a
data-flow merge. `taint_join()` is the wrong operation for it.

### The principled boundary

| Operation | Algebra | Rationale |
|---|---|---|
| Combining callee taints into a single result | `taint_join()` | Data-flow merge — §6 MUST |
| Floor clamp: "L3 ≥ L1 baseline" | `TRUST_RANK` ordering | Monotonicity guard — ordering comparison |
| Post-assertion: "anchored unchanged" | `TRUST_RANK` ordering | Invariant check |
| Post-assertion: "module_default not upgraded" | `TRUST_RANK` ordering | Invariant check |
| via_callee: "which callee contributed most distrust" | `TRUST_RANK` ordering | Diagnostic provenance — deterministic tiebreak |
| L3_LOW_RESOLUTION: unresolved call ratio | Not taint-related | Threshold arithmetic |

Each surviving `TRUST_RANK` usage site in the propagation module will carry a
code comment: `# TRUST_RANK: ordering comparison, not taint combination (see §6)`

## Detailed Change Specification

### File: `src/wardline/scanner/taint/callgraph_propagation.py`

#### Import changes

Add:
```python
from functools import reduce
from wardline.core.taints import taint_join
```

The existing `TRUST_RANK` import stays (needed for floor clamps and provenance).

#### Phase 1: External influence computation (lines ~140–200)

**Current**: Collects `ext_ranks: list[int]` from external callees, takes
`ext_max = max(ext_ranks)`, applies floor clamp as `ext_max = max(ext_max,
l1_rank)`, converts to state via `rank_to_state[ext_max]`.

**New**: Collects `ext_taints: list[TaintState]` from external callees, folds
with `ext_combined = reduce(taint_join, ext_taints)`, applies floor clamp as
a rank comparison:

```python
ext_taints: list[TaintState] = []
for c in ext_callees:
    if c in anchored:
        ext_taints.append(return_taint_map.get(c, current[c]))
    else:
        ext_taints.append(current[c])
ext_combined = reduce(taint_join, ext_taints)  # safe: ext_callees non-empty

# Floor clamp: TRUST_RANK ordering comparison, not taint combination (see §6)
l1_rank = TRUST_RANK[taint_map[f]]
ext_rank = TRUST_RANK[ext_combined]
if l1_rank > ext_rank:
    ext_taint = taint_map[f]
else:
    ext_taint = ext_combined

# Unresolved calls pessimistic floor (ordering, not combination)
if f_unresolved > 0:
    if TRUST_RANK[taint_map[f]] > TRUST_RANK[ext_taint]:
        ext_taint = taint_map[f]
```

#### Phase 2: Worklist iteration (lines ~206–269)

**Current**: Collects `callee_ranks: list[int]`, takes `max_callee_rank =
max(callee_ranks, default=...)`, applies floor clamp, converts via
`rank_to_state`.

**New**: Collects `callee_taints: list[TaintState]`, folds with
`callee_combined = reduce(taint_join, callee_taints)`, applies floor clamp
via rank comparison:

```python
callee_taints: list[TaintState] = []
for c in callee_set:
    if c in anchored:
        callee_taints.append(return_taint_map.get(c, current[c]))
    else:
        callee_taints.append(current[c])

if not callee_taints:
    continue  # no resolved callees — stay at current taint

callee_combined = reduce(taint_join, callee_taints)

# Floor clamp: ordering comparison, not taint combination (see §6)
if func in floating_down or func in floating_free:
    l1_rank = TRUST_RANK[taint_map[func]]
    combined_rank = TRUST_RANK[callee_combined]
    if l1_rank > combined_rank:
        new_taint = taint_map[func]
    else:
        new_taint = callee_combined
else:
    continue  # anchored — skip

# Unresolved calls pessimistic floor (ordering, not combination)
if func_unresolved > 0:
    if TRUST_RANK[taint_map[func]] > TRUST_RANK[new_taint]:
        new_taint = taint_map[func]
```

#### `rank_to_state` removal

The `rank_to_state` reverse map (line 125) becomes unnecessary for the
combination path. It is only needed if floor-clamp logic needs to convert
a rank back to a state — but under the new design, floor-clamping selects
between `taint_map[func]` (the L1 state) and `callee_combined` (the joined
state), both already `TaintState` values. **Remove `rank_to_state`.**

#### via_callee provenance (lines ~186–200, ~275–293)

No change. Provenance tracking answers "which callee contributed the most
distrust" — an ordering question. `TRUST_RANK` is correct here. Add comment:
`# TRUST_RANK: diagnostic provenance tiebreak, not taint combination`.

#### Post-assertions (lines ~305–328)

No change. These check `TRUST_RANK[current[func]] < TRUST_RANK[taint_map[func]]`
— ordering comparisons verifying invariants. Add comment where missing.

### File: `src/wardline/scanner/taint/callgraph.py`

No changes. `TRUST_RANK`, `least_trusted()`, and `extract_call_edges()` are
unchanged. `TRUST_RANK` remains the canonical total order for comparison
operations. `least_trusted()` is an ordering function, not a join — its name
and semantics are correct.

### Files NOT changed

- `src/wardline/core/taints.py` — no changes needed. `taint_join()` is correct.
- `src/wardline/scanner/engine.py` — imports `extract_call_edges` and
  `propagate_callgraph_taints`. No API change.
- `src/wardline/cli/exception_cmds.py` — calls `propagate_callgraph_taints`
  with same signature. No API change.

## Convergence Analysis

The `taint_join()` lattice is a finite join-semilattice with 8 elements. Key
properties (proved by SAE reviewer):

- **Lattice height**: 3 (longest chain: e.g., UNKNOWN_ASSURED → UNKNOWN_GUARDED
  → UNKNOWN_RAW, or any singleton → MIXED_RAW in one step). Down from height 7
  under the TRUST_RANK total order.
- **Monotonicity**: `taint_join`-fold is monotone — if a callee's taint increases
  in the lattice, the fold result can only increase or stay the same.
- **Convergence**: Each node can change at most `height` (= 3) times. The safety
  bound of `8 * |SCC|²` iterations is more than sufficient.
- **Composition with floor clamp**: The composed operation
  `max(TRUST_RANK[fold(taint_join, callees)], l1_rank)` is monotone because
  TRUST_RANK is a monotone embedding of the join lattice into the integers.

## Test Impact

### Tests that WILL break (expectations change)

1. **`test_diamond_pattern`**: A(UNKNOWN_RAW fallback) calls B(ASSURED) and
   C(EXTERNAL_RAW). Currently expects UNKNOWN_RAW. New: `join(ASSURED,
   EXTERNAL_RAW) = MIXED_RAW` (rank 7) > L1 floor (rank 6) → expects MIXED_RAW.

2. **`test_fallback_floor_clamp_at_unknown_raw`**: fb_fn(UNKNOWN_RAW) calls
   ext_fn(EXTERNAL_RAW). Single callee, no cross-classification join. Stays
   UNKNOWN_RAW. **Actually unchanged** — single callee means `reduce` returns
   the callee's taint directly, floor clamp applies. Confirmed: no break.

3. **`test_multi_hop_chain`**: A→B→C(@EXTERNAL_RAW), A and B are UNKNOWN_RAW
   fallback. Single-callee chains — no cross-classification join. **Unchanged.**

4. **`test_module_default_caller_refined_by_return_taint`**: caller(INTEGRAL
   module_default) calls validator(@EXTERNAL_RAW body, @GUARDED return). Single
   callee, return taint GUARDED used. `join` of single element = GUARDED. Floor
   clamp: max(TRUST_RANK[GUARDED]=2, TRUST_RANK[INTEGRAL]=0) = 2 → GUARDED.
   **Unchanged.**

5. **Property tests**: `test_fallback_bounded_by_callees` uses `TRUST_RANK`
   ordering as oracle. It checks `result_rank >= max(TRUST_RANK[result_map[c]]
   for c in callees)`. After the fix, some callees' `result_map` entries may
   now be MIXED_RAW (rank 7) where previously they were lower-ranked. The
   caller's result will also be MIXED_RAW or floor-clamped higher, so the
   `>=` assertion holds. **Confirmed: passes unchanged.** The other property
   tests (`test_convergence`, `test_idempotence`, `test_anchored_immutability`,
   `test_module_default_monotone_downward`) test structural invariants that
   are preserved by the join algebra — all pass unchanged.

### Tests that MUST be added

1. **Cross-classification callee combination**: Fallback(ASSURED) calling
   GUARDED + EXTERNAL_RAW → expects MIXED_RAW (not EXTERNAL_RAW).

2. **Cross-classification with floor clamp dominance**: Fallback(MIXED_RAW)
   calling ASSURED + GUARDED → expects MIXED_RAW (floor clamp at rank 7
   dominates the join result which is also MIXED_RAW — both paths agree).

3. **UNKNOWN family combination preserved**: Fallback(INTEGRAL) calling
   UNKNOWN_RAW + UNKNOWN_ASSURED → expects UNKNOWN_RAW (within-family join),
   then floor clamp: max(rank 6, rank 0) = 6 → UNKNOWN_RAW. Confirms the
   UNKNOWN-family demotion rules survive the refactor.

4. **Single callee — no join divergence**: Fallback(ASSURED) calling only
   GUARDED → expects GUARDED (rank 2 > rank 1, so callee dominates). Same
   result as before because single-callee `reduce` returns the callee itself.

5. **GUARDED + EXTERNAL_RAW explicit coverage**: Fallback(GUARDED) calling
   GUARDED + EXTERNAL_RAW → expects MIXED_RAW. Explicitly covers one of the
   8 security-relevant divergence cases from the impact table.

6. **L3 commutativity at propagation level**: Verify that calling A then B
   produces the same result as calling B then A — the `taint_join` is
   commutative, but the worklist iteration must not introduce order dependence.

7. **MIXED_RAW absorption at propagation level**: Verify that if any callee
   is MIXED_RAW, the combined result is MIXED_RAW regardless of other callees.

## Evidence Artefacts for BAR Pipeline

Per IRAP reviewer guidance:

1. **Unit tests** demonstrating `taint_join()` commutativity and MIXED_RAW
   absorption at the L3 propagation level (not just in `taints.py`).
2. **Corpus specimen** where two callees from different classification families
   converge, confirming MIXED_RAW output in SARIF.
3. **Diff audit** showing every `TRUST_RANK` usage in the combination path is
   replaced, and every surviving usage is exclusively ordering/comparison.
4. **Code comment** at each surviving `TRUST_RANK` usage:
   `# TRUST_RANK: ordering comparison, not taint combination (see §6)`.
5. **Compliance ledger update**: `P1-S6-TAINT-JOIN-ABSORBING` transitions from
   `non_compliant` to `evidenced` (pending BAR pipeline review for `verified`).

## Scope Boundaries

### In scope
- `propagate_callgraph_taints()` Phase 1 and Phase 2 callee combination
- Test updates for changed expectations
- New cross-classification tests
- Documentation comments at TRUST_RANK usage sites
- Compliance ledger state update

### Out of scope
- `least_trusted()` in `callgraph.py` — ordering function, not a join
- `extract_call_edges()` — unrelated to taint combination
- `TRUST_RANK` definition — stays as the canonical total order for comparisons
- Other obligations (`P2A-A3-L1-MINIMUM-CONFORMANCE` etc.) — separate work
- Corpus specimen creation — tracked separately under C-CRIT-6
