# P1-S6 Taint Join Algebra Fix — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the TRUST_RANK/max() callee combination in L3 callgraph propagation with the normative taint_join() algebra, fixing obligation P1-S6-TAINT-JOIN-ABSORBING.

**Architecture:** Surgical replacement of callee taint combination in `propagate_callgraph_taints()` Phase 1 and Phase 2. Join operations switch to `taint_join()` from `src/wardline/core/taints.py`. Floor clamps, post-assertions, and provenance tracking retain `TRUST_RANK` ordering (these are comparison operations, not joins). TDD: write the cross-classification tests first, watch them fail against the current code, then implement the fix.

**Tech Stack:** Python 3.12+, pytest, hypothesis (property tests), wardline core taints module.

**Design spec:** `docs/superpowers/specs/2026-04-12-p1-s6-taint-join-fix-design.md`

**Obligation:** `P1-S6-TAINT-JOIN-ABSORBING` (tracker `wardline-cf49edcde8`)

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `tests/unit/scanner/test_callgraph_propagation.py` | Modify | Add 6 new cross-classification tests, update 1 existing test |
| `tests/unit/scanner/test_callgraph_properties.py` | Modify | Add 1 new property test for cross-classification join correctness |
| `src/wardline/scanner/taint/callgraph_propagation.py` | Modify | Replace callee combination with taint_join(), remove rank_to_state, add annotation comments |
| `wardline.compliance.json` | Modify | Update obligation state from non_compliant to evidenced |

---

## Task 1: Add cross-classification combination tests (red)

These tests encode the spec's §6 join algebra at the L3 propagation level. They will **fail** against the current TRUST_RANK/max() implementation because cross-classification merges should produce MIXED_RAW but currently produce the higher-ranked operand.

**Files:**
- Modify: `tests/unit/scanner/test_callgraph_propagation.py`

- [ ] **Step 1: Add the TestCrossClassificationJoin test class**

Add this class at the end of the file (after the existing `TestReturnTaintMapSplit` class):

```python
class TestCrossClassificationJoin:
    """Cross-classification callee combinations must produce MIXED_RAW.

    These tests exercise the §6 join algebra at the L3 propagation level.
    When a function calls callees from different trust classifications
    (e.g., ASSURED + GUARDED), the combined taint MUST be MIXED_RAW per
    the spec's absorbing-element rule.
    """

    def test_assured_plus_guarded_produces_mixed_raw(self) -> None:
        """Fallback(ASSURED) calling GUARDED + EXTERNAL_RAW -> MIXED_RAW."""
        edges = {"A": {"B", "C"}, "B": set(), "C": set()}
        taint_map = {
            "A": TaintState.ASSURED,
            "B": TaintState.GUARDED,
            "C": TaintState.EXTERNAL_RAW,
        }
        taint_sources = {"A": "fallback", "B": "decorator", "C": "decorator"}
        result, _, _diags = propagate_callgraph_taints(
            edges, taint_map, taint_sources,
            {"A": 2, "B": 0, "C": 0}, {"A": 0, "B": 0, "C": 0},
            return_taint_map=taint_map,
        )
        # join(GUARDED, EXTERNAL_RAW) = MIXED_RAW (cross-classification)
        # Floor clamp: max(TRUST_RANK[MIXED_RAW]=7, TRUST_RANK[ASSURED]=1) = 7
        # Result: MIXED_RAW
        assert result["A"] == TaintState.MIXED_RAW

    def test_floor_clamp_dominates_when_already_mixed(self) -> None:
        """Fallback(MIXED_RAW) calling ASSURED + GUARDED -> MIXED_RAW."""
        edges = {"A": {"B", "C"}, "B": set(), "C": set()}
        taint_map = {
            "A": TaintState.MIXED_RAW,
            "B": TaintState.ASSURED,
            "C": TaintState.GUARDED,
        }
        taint_sources = {"A": "fallback", "B": "decorator", "C": "decorator"}
        result, _, _diags = propagate_callgraph_taints(
            edges, taint_map, taint_sources,
            {"A": 2, "B": 0, "C": 0}, {"A": 0, "B": 0, "C": 0},
            return_taint_map=taint_map,
        )
        # join(ASSURED, GUARDED) = MIXED_RAW
        # Floor clamp: max(7, 7) = 7 -> MIXED_RAW (both paths agree)
        assert result["A"] == TaintState.MIXED_RAW

    def test_unknown_family_demotion_preserved(self) -> None:
        """Fallback(INTEGRAL) calling UNKNOWN_RAW + UNKNOWN_ASSURED -> UNKNOWN_RAW."""
        edges = {"A": {"B", "C"}, "B": set(), "C": set()}
        taint_map = {
            "A": TaintState.INTEGRAL,
            "B": TaintState.UNKNOWN_RAW,
            "C": TaintState.UNKNOWN_ASSURED,
        }
        taint_sources = {"A": "fallback", "B": "decorator", "C": "decorator"}
        result, _, _diags = propagate_callgraph_taints(
            edges, taint_map, taint_sources,
            {"A": 2, "B": 0, "C": 0}, {"A": 0, "B": 0, "C": 0},
            return_taint_map=taint_map,
        )
        # join(UNKNOWN_RAW, UNKNOWN_ASSURED) = UNKNOWN_RAW (within-family)
        # Floor clamp: max(TRUST_RANK[UNKNOWN_RAW]=6, TRUST_RANK[INTEGRAL]=0) = 6
        # Result: UNKNOWN_RAW
        assert result["A"] == TaintState.UNKNOWN_RAW

    def test_single_callee_no_join_divergence(self) -> None:
        """Fallback(ASSURED) calling only GUARDED -> GUARDED (no cross-class join)."""
        edges = {"A": {"B"}, "B": set()}
        taint_map = {
            "A": TaintState.ASSURED,
            "B": TaintState.GUARDED,
        }
        taint_sources = {"A": "fallback", "B": "decorator"}
        result, _, _diags = propagate_callgraph_taints(
            edges, taint_map, taint_sources,
            {"A": 1, "B": 0}, {"A": 0, "B": 0},
            return_taint_map=taint_map,
        )
        # Single callee: no join needed. GUARDED rank=2 > ASSURED rank=1.
        # Floor clamp: max(2, 1) = 2 -> GUARDED
        assert result["A"] == TaintState.GUARDED

    def test_mixed_raw_absorption_at_propagation_level(self) -> None:
        """If any callee is MIXED_RAW, combined result is MIXED_RAW."""
        edges = {"A": {"B", "C"}, "B": set(), "C": set()}
        taint_map = {
            "A": TaintState.ASSURED,
            "B": TaintState.INTEGRAL,
            "C": TaintState.MIXED_RAW,
        }
        taint_sources = {"A": "fallback", "B": "decorator", "C": "decorator"}
        result, _, _diags = propagate_callgraph_taints(
            edges, taint_map, taint_sources,
            {"A": 2, "B": 0, "C": 0}, {"A": 0, "B": 0, "C": 0},
            return_taint_map=taint_map,
        )
        # join(INTEGRAL, MIXED_RAW) = MIXED_RAW (absorbing)
        assert result["A"] == TaintState.MIXED_RAW

    def test_guarded_plus_external_raw_produces_mixed_raw(self) -> None:
        """Fallback(GUARDED) calling GUARDED + EXTERNAL_RAW -> MIXED_RAW."""
        edges = {"A": {"B", "C"}, "B": set(), "C": set()}
        taint_map = {
            "A": TaintState.GUARDED,
            "B": TaintState.GUARDED,
            "C": TaintState.EXTERNAL_RAW,
        }
        taint_sources = {"A": "fallback", "B": "decorator", "C": "decorator"}
        result, _, _diags = propagate_callgraph_taints(
            edges, taint_map, taint_sources,
            {"A": 2, "B": 0, "C": 0}, {"A": 0, "B": 0, "C": 0},
            return_taint_map=taint_map,
        )
        # join(GUARDED, EXTERNAL_RAW) = MIXED_RAW (cross-classification)
        # Floor clamp: max(TRUST_RANK[MIXED_RAW]=7, TRUST_RANK[GUARDED]=2) = 7
        # Result: MIXED_RAW
        assert result["A"] == TaintState.MIXED_RAW

    def test_module_default_cross_classification(self) -> None:
        """Module_default(INTEGRAL) calling ASSURED + UNKNOWN_RAW -> MIXED_RAW."""
        edges = {"A": {"B", "C"}, "B": set(), "C": set()}
        taint_map = {
            "A": TaintState.INTEGRAL,
            "B": TaintState.ASSURED,
            "C": TaintState.UNKNOWN_RAW,
        }
        taint_sources = {"A": "module_default", "B": "decorator", "C": "decorator"}
        result, _, _diags = propagate_callgraph_taints(
            edges, taint_map, taint_sources,
            {"A": 2, "B": 0, "C": 0}, {"A": 0, "B": 0, "C": 0},
            return_taint_map=taint_map,
        )
        # join(ASSURED, UNKNOWN_RAW) = MIXED_RAW (cross-classification)
        # Floor clamp: max(TRUST_RANK[MIXED_RAW]=7, TRUST_RANK[INTEGRAL]=0) = 7
        # Result: MIXED_RAW
        assert result["A"] == TaintState.MIXED_RAW
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `uv run pytest tests/unit/scanner/test_callgraph_propagation.py::TestCrossClassificationJoin -v`

Expected: At least `test_assured_plus_guarded_produces_mixed_raw`, `test_guarded_plus_external_raw_produces_mixed_raw`, and `test_module_default_cross_classification` FAIL with `assert <TaintState.EXTERNAL_RAW: 'EXTERNAL_RAW'> == <TaintState.MIXED_RAW: 'MIXED_RAW'>` or similar. The single-callee test and the UNKNOWN-family test may pass (no cross-classification divergence in those cases).

- [ ] **Step 3: Commit the red tests**

```
git add tests/unit/scanner/test_callgraph_propagation.py
git commit -m "test: add cross-classification join tests for P1-S6 (red)

Tests encode the §6 join algebra at the L3 propagation level.
Cross-classification callee combinations must produce MIXED_RAW.
These fail against the current TRUST_RANK/max() implementation."
```

---

## Task 2: Add L3 commutativity property test (red)

This property test verifies that the propagation result is independent of callee ordering — a structural requirement of the commutative join algebra.

**Files:**
- Modify: `tests/unit/scanner/test_callgraph_properties.py`

- [ ] **Step 1: Add the commutativity property test**

Add this test after the existing `test_fallback_bounded_by_callees` function (at the end of the property tests section, before the `_diff_maps` helper):

```python
@given(data=call_graphs())
@settings(max_examples=200)
def test_join_commutativity_at_propagation_level(
    data: tuple[
        dict[str, set[str]],
        dict[str, TaintState],
        dict[str, TaintSource],
        dict[str, int],
        dict[str, int],
    ],
) -> None:
    """Propagation result is independent of callee set iteration order.

    Since taint_join is commutative and associative, the fold over callees
    must produce the same result regardless of iteration order. This is
    already enforced by sorted() in the worklist, but this test verifies
    the algebraic property holds at the propagation output level.
    """
    edges, taint_map, taint_sources, resolved_counts, unresolved_counts = data

    # Run twice with identical inputs — idempotence already tested,
    # but here we also verify that the result matches when we reverse
    # all edge sets (which changes iteration order of callees).
    reversed_edges = {k: set(sorted(v, reverse=True)) for k, v in edges.items()}

    result1, _, _ = propagate_callgraph_taints(
        edges, taint_map, taint_sources, resolved_counts, unresolved_counts,
        return_taint_map=taint_map,
    )
    result2, _, _ = propagate_callgraph_taints(
        reversed_edges, taint_map, taint_sources, resolved_counts, unresolved_counts,
        return_taint_map=taint_map,
    )

    assert result1 == result2, (
        f"Propagation not commutative over callee order.\n"
        f"Differences: {_diff_maps(result1, result2)}"
    )
```

- [ ] **Step 2: Run the property test to verify it passes (green — this tests an existing invariant)**

Run: `uv run pytest tests/unit/scanner/test_callgraph_properties.py::test_join_commutativity_at_propagation_level -v`

Expected: PASS (the current implementation is order-independent due to sorted() and max()). This test becomes a regression guard after the refactor.

- [ ] **Step 3: Commit**

```
git add tests/unit/scanner/test_callgraph_properties.py
git commit -m "test: add L3 commutativity property test for P1-S6

Verifies propagation result is independent of callee iteration order.
Passes on current code; guards the invariant after taint_join refactor."
```

---

## Task 3: Implement taint_join in Phase 1 (external influence)

Replace the TRUST_RANK/max() callee combination in Phase 1 with taint_join(). Keep TRUST_RANK for floor clamps.

**Files:**
- Modify: `src/wardline/scanner/taint/callgraph_propagation.py:7-13` (imports)
- Modify: `src/wardline/scanner/taint/callgraph_propagation.py:123-200` (Phase 1)

- [ ] **Step 1: Update imports**

In `src/wardline/scanner/taint/callgraph_propagation.py`, add `reduce` to the top-level imports and move the `taint_join` import to the function body alongside the existing `TaintState` import.

Change line 9:
```python
import logging
```
to:
```python
import logging
from functools import reduce
```

Then inside `propagate_callgraph_taints()`, change line 72:
```python
    from wardline.core.taints import TaintState
```
to:
```python
    from wardline.core.taints import TaintState, taint_join
```

- [ ] **Step 2: Remove rank_to_state**

Delete line 125:
```python
    rank_to_state = {r: s for s, r in TRUST_RANK.items()}
```

This reverse map is no longer needed — the new code selects between existing TaintState values rather than converting ranks back to states.

- [ ] **Step 3: Replace Phase 1 external influence combination**

Replace the Phase 1 external influence block (lines ~155-180). Find this code:

```python
                ext_ranks: list[int] = []
                for c in ext_callees:
                    if c in anchored:
                        try:
                            c_return_taint = return_taint_map[c]
                        except KeyError:
                            c_return_taint = current[c]
                        ext_ranks.append(TRUST_RANK[c_return_taint])
                    else:
                        ext_ranks.append(TRUST_RANK[current[c]])
                ext_max = max(ext_ranks)
                if f in floating_down:
                    l1_rank = TRUST_RANK[taint_map[f]]
                    ext_max = max(ext_max, l1_rank)
                elif f in floating_free:
                    # Fix 1: floor clamp for floating_free in Phase 1
                    l1_rank = TRUST_RANK[taint_map[f]]
                    ext_max = max(ext_max, l1_rank)
                # Fix 2: unresolved calls pessimistic floor in Phase 1
                try:
                    f_unresolved = unresolved_counts[f]
                except KeyError:
                    f_unresolved = 0
                if f_unresolved > 0:
                    ext_max = max(ext_max, TRUST_RANK[taint_map[f]])
                ext_taint = rank_to_state[ext_max]
```

Replace with:

```python
                # Combine callee taints using §6 join algebra
                ext_taints: list[TaintState] = []
                for c in ext_callees:
                    if c in anchored:
                        try:
                            c_return_taint = return_taint_map[c]
                        except KeyError:
                            c_return_taint = current[c]
                        ext_taints.append(c_return_taint)
                    else:
                        ext_taints.append(current[c])
                ext_combined = reduce(taint_join, ext_taints)

                # TRUST_RANK: ordering comparison, not taint combination (see §6)
                ext_taint = ext_combined
                if f in floating_down or f in floating_free:
                    l1_rank = TRUST_RANK[taint_map[f]]
                    if l1_rank > TRUST_RANK[ext_taint]:
                        ext_taint = taint_map[f]
                # Unresolved calls pessimistic floor (ordering, not combination)
                try:
                    f_unresolved = unresolved_counts[f]
                except KeyError:
                    f_unresolved = 0
                if f_unresolved > 0:
                    if TRUST_RANK[taint_map[f]] > TRUST_RANK[ext_taint]:
                        ext_taint = taint_map[f]
```

- [ ] **Step 4: Run all existing tests to check Phase 1 in isolation**

Run: `uv run pytest tests/unit/scanner/test_callgraph_propagation.py -v`

Expected: All existing tests still pass. Phase 1 only affects functions with external callees outside their SCC. Most test cases use simple DAG topologies where Phase 2 dominates.

- [ ] **Step 5: Commit Phase 1 changes**

```
git add src/wardline/scanner/taint/callgraph_propagation.py
git commit -m "fix(P1-S6): replace TRUST_RANK/max with taint_join in Phase 1

Phase 1 external influence now uses taint_join() to combine callee
taints per §6 join algebra. TRUST_RANK retained for floor clamps
(ordering comparison, not taint combination)."
```

---

## Task 4: Implement taint_join in Phase 2 (worklist iteration)

Replace the TRUST_RANK/max() callee combination in the Phase 2 worklist with taint_join().

**Files:**
- Modify: `src/wardline/scanner/taint/callgraph_propagation.py:223-269` (Phase 2)

- [ ] **Step 1: Replace Phase 2 callee combination**

Find the Phase 2 callee combination block:

```python
            # Compute max_rank (least trusted) among callees
            callee_ranks: list[int] = []
            for c in callee_set:
                if c in anchored:
                    try:
                        c_return_taint = return_taint_map[c]
                    except KeyError:
                        c_return_taint = current[c]
                    callee_ranks.append(TRUST_RANK[c_return_taint])
                else:
                    callee_ranks.append(TRUST_RANK[current[c]])
            max_callee_rank = max(callee_ranks, default=TRUST_RANK[TaintState.INTEGRAL])

            # Floor clamp for module_default: result >= L1 rank
            if func in floating_down:
                l1_rank = TRUST_RANK[taint_map[func]]
                result_rank = max(max_callee_rank, l1_rank)
            elif func in floating_free:
                # Fix 1: floor clamp — L3 must never make a function MORE
                # trusted than its L1 baseline.
                l1_rank = TRUST_RANK[taint_map[func]]
                result_rank = max(max_callee_rank, l1_rank)
            else:
                # anchored — skip (shouldn't reach here due to worklist filter)
                continue

            # Fix 2: unresolved calls pessimistic floor — if this function
            # has unresolved calls, it cannot be more trusted than its L1
            # baseline (unresolved calls could go anywhere).
            try:
                func_unresolved = unresolved_counts[func]
            except KeyError:
                func_unresolved = 0
            if func_unresolved > 0:
                result_rank = max(result_rank, TRUST_RANK[taint_map[func]])

            new_taint = rank_to_state[result_rank]
```

Replace with:

```python
            # Combine callee taints using §6 join algebra
            callee_taints: list[TaintState] = []
            for c in callee_set:
                if c in anchored:
                    try:
                        c_return_taint = return_taint_map[c]
                    except KeyError:
                        c_return_taint = current[c]
                    callee_taints.append(c_return_taint)
                else:
                    callee_taints.append(current[c])

            if not callee_taints:
                continue  # no resolved callees — stay at current taint

            callee_combined = reduce(taint_join, callee_taints)

            # TRUST_RANK: ordering comparison, not taint combination (see §6)
            if func in floating_down or func in floating_free:
                l1_rank = TRUST_RANK[taint_map[func]]
                combined_rank = TRUST_RANK[callee_combined]
                if l1_rank > combined_rank:
                    new_taint = taint_map[func]
                else:
                    new_taint = callee_combined
            else:
                # anchored — skip (shouldn't reach here due to worklist filter)
                continue

            # Unresolved calls pessimistic floor (ordering, not combination)
            try:
                func_unresolved = unresolved_counts[func]
            except KeyError:
                func_unresolved = 0
            if func_unresolved > 0:
                if TRUST_RANK[taint_map[func]] > TRUST_RANK[new_taint]:
                    new_taint = taint_map[func]
```

- [ ] **Step 2: Run the cross-classification tests to verify they now pass**

Run: `uv run pytest tests/unit/scanner/test_callgraph_propagation.py::TestCrossClassificationJoin -v`

Expected: All 6 tests PASS. The cross-classification combinations now produce MIXED_RAW.

- [ ] **Step 3: Run the full test suite to find breakage**

Run: `uv run pytest tests/unit/scanner/test_callgraph_propagation.py -v`

Expected: `test_diamond_pattern` FAILS. All other tests pass.

- [ ] **Step 4: Commit Phase 2 changes (with known test breakage)**

```
git add src/wardline/scanner/taint/callgraph_propagation.py
git commit -m "fix(P1-S6): replace TRUST_RANK/max with taint_join in Phase 2

Phase 2 worklist iteration now uses taint_join() to combine callee
taints per §6 join algebra. Cross-classification merges correctly
produce MIXED_RAW. TRUST_RANK retained for floor clamps only.

Known: test_diamond_pattern expects UNKNOWN_RAW but now gets MIXED_RAW
because join(ASSURED, EXTERNAL_RAW) = MIXED_RAW. Fix in next commit."
```

---

## Task 5: Update test_diamond_pattern expectation

The diamond test has a function A(UNKNOWN_RAW fallback) calling B(ASSURED) and C(EXTERNAL_RAW). Under the correct join algebra, `join(ASSURED, EXTERNAL_RAW) = MIXED_RAW` (rank 7), which exceeds the L1 floor (rank 6), so the result is MIXED_RAW.

**Files:**
- Modify: `tests/unit/scanner/test_callgraph_propagation.py:306-320`

- [ ] **Step 1: Update the test expectation and docstring**

Find:

```python
    def test_diamond_pattern(self) -> None:
        """A calls B(ASSURED) and C(EXTERNAL_RAW) -> A stays UNKNOWN_RAW (floor clamp)."""
        edges = {"A": {"B", "C"}, "B": set(), "C": set()}
        taint_map = {
            "A": TaintState.UNKNOWN_RAW,
            "B": TaintState.ASSURED,
            "C": TaintState.EXTERNAL_RAW,
        }
        taint_sources = {"A": "fallback", "B": "decorator", "C": "decorator"}
        result, _, _diags = propagate_callgraph_taints(
            edges, taint_map, taint_sources,
            {"A": 2, "B": 0, "C": 0}, {"A": 0, "B": 0, "C": 0}, return_taint_map=taint_map,
)
        # Floor clamp: max(EXTERNAL_RAW=5, UNKNOWN_RAW=6) = 6 = UNKNOWN_RAW
        assert result["A"] == TaintState.UNKNOWN_RAW
```

Replace with:

```python
    def test_diamond_pattern(self) -> None:
        """A calls B(ASSURED) and C(EXTERNAL_RAW) -> MIXED_RAW (cross-classification join)."""
        edges = {"A": {"B", "C"}, "B": set(), "C": set()}
        taint_map = {
            "A": TaintState.UNKNOWN_RAW,
            "B": TaintState.ASSURED,
            "C": TaintState.EXTERNAL_RAW,
        }
        taint_sources = {"A": "fallback", "B": "decorator", "C": "decorator"}
        result, _, _diags = propagate_callgraph_taints(
            edges, taint_map, taint_sources,
            {"A": 2, "B": 0, "C": 0}, {"A": 0, "B": 0, "C": 0}, return_taint_map=taint_map,
)
        # join(ASSURED, EXTERNAL_RAW) = MIXED_RAW (cross-classification, §6)
        # MIXED_RAW rank=7 > L1 floor rank=6 -> result is MIXED_RAW
        assert result["A"] == TaintState.MIXED_RAW
```

- [ ] **Step 2: Run all propagation tests**

Run: `uv run pytest tests/unit/scanner/test_callgraph_propagation.py -v`

Expected: ALL PASS.

- [ ] **Step 3: Run property tests**

Run: `uv run pytest tests/unit/scanner/test_callgraph_properties.py -v`

Expected: ALL PASS (including the new commutativity test).

- [ ] **Step 4: Commit**

```
git add tests/unit/scanner/test_callgraph_propagation.py
git commit -m "test: update diamond pattern expectation for §6 join algebra

join(ASSURED, EXTERNAL_RAW) = MIXED_RAW per §6 cross-classification
rule. MIXED_RAW (rank 7) exceeds the L1 floor (UNKNOWN_RAW rank 6),
so the result is correctly MIXED_RAW, not UNKNOWN_RAW."
```

---

## Task 6: Add TRUST_RANK annotation comments

Document the principled boundary between combination (taint_join) and ordering (TRUST_RANK) at each surviving TRUST_RANK usage site in the propagation module.

**Files:**
- Modify: `src/wardline/scanner/taint/callgraph_propagation.py`

- [ ] **Step 1: Add annotation comments at surviving TRUST_RANK sites**

The following TRUST_RANK usages remain in the propagation module after Tasks 3–4. Each needs a short annotation comment. Add the comment `# TRUST_RANK: ordering comparison, not taint combination (see §6)` or `# TRUST_RANK: diagnostic provenance tiebreak, not taint combination` at each site that doesn't already have one from Tasks 3-4.

Sites to annotate (verify against the actual file — line numbers will have shifted):

1. **Phase 1 via_callee provenance** — the block that finds `best_callee` by iterating `ext_callees` and comparing `c_rank > best_rank`. Add before the loop:
   ```python
   # TRUST_RANK: diagnostic provenance tiebreak, not taint combination
   ```

2. **Phase 2 via_callee provenance** — the block that finds `best_callee_wl` by iterating `callee_set` and comparing `c_rank > best_rank_wl`. Add before the loop:
   ```python
   # TRUST_RANK: diagnostic provenance tiebreak, not taint combination
   ```

3. **Post-assertion for module_default** — the check `if TRUST_RANK[current[func]] < TRUST_RANK[taint_map[func]]`. Add before:
   ```python
   # TRUST_RANK: ordering assertion, not taint combination (see §6)
   ```

- [ ] **Step 2: Update the module docstring**

Change line 1-5 from:

```python
"""SCC decomposition and fixed-point call-graph taint propagation (L3).

Provides iterative Tarjan's SCC algorithm and the main propagation loop
that refines L1 function-level taints by analysing what each function calls.
"""
```

to:

```python
"""SCC decomposition and fixed-point call-graph taint propagation (L3).

Provides iterative Tarjan's SCC algorithm and the main propagation loop
that refines L1 function-level taints by analysing what each function calls.

Callee taint combination uses taint_join() from the §6 join algebra.
TRUST_RANK is used only for ordering comparisons (floor clamps,
post-assertions, provenance tiebreaks) — never for taint combination.
"""
```

- [ ] **Step 3: Run full test suite**

Run: `uv run pytest tests/unit/scanner/ -v`

Expected: ALL PASS. Comments don't affect behaviour.

- [ ] **Step 4: Commit**

```
git add src/wardline/scanner/taint/callgraph_propagation.py
git commit -m "docs: annotate TRUST_RANK usage sites with §6 boundary rationale

Each surviving TRUST_RANK usage in the propagation module now carries
a comment explaining it is an ordering comparison, not a taint
combination. Supports audit defensibility per IRAP reviewer guidance."
```

---

## Task 7: Full verification pass

Run the complete test suite, type checker, and linter to confirm no regressions.

**Files:** None modified — verification only.

- [ ] **Step 1: Run full unit test suite**

Run: `uv run pytest`

Expected: ALL PASS (2509+ tests). No regressions outside the propagation module.

- [ ] **Step 2: Run integration tests**

Run: `uv run pytest -m integration`

Expected: ALL PASS. Integration tests exercise the full scan pipeline end-to-end and will surface regressions where changed propagation output affects SARIF or finding counts.

- [ ] **Step 3: Run type checker on modified files and their tests**

Run: `uv run mypy src/wardline/scanner/taint/callgraph_propagation.py tests/unit/scanner/test_callgraph_propagation.py tests/unit/scanner/test_callgraph_properties.py`

Expected: Success, no errors. The `reduce(taint_join, ...)` call returns `TaintState`, matching all downstream usage.

- [ ] **Step 4: Run linter**

Run: `uv run ruff check src/wardline/scanner/taint/callgraph_propagation.py`

Expected: No new warnings.

- [ ] **Step 5: Run corpus verify**

Run: `uv run wardline corpus verify`

Expected: Corpus verification passes. If any specimen expected verdicts shift due to changed propagation output, the failure will surface here. Any failures must be triaged before proceeding.

- [ ] **Step 6: Run self-hosting scan and triage new findings**

Run: `uv run wardline scan src/`

Expected: Scan completes. May produce new or changed findings because functions previously assigned lower-ranked states (e.g., EXTERNAL_RAW) may now correctly be MIXED_RAW, triggering PY-WL-001/002 violations that were previously invisible.

**Finding triage protocol:** If new findings appear, classify each as:
- **(a) Genuine bug** — file as a new filigree issue. These are real trust-boundary violations the old code missed.
- **(b) Expected reclassification** — document in the commit. The function's taint changed from under-tainted to correctly-tainted; no action needed beyond acknowledgement.
- **(c) False positive** — if a finding is genuinely wrong, add a manifest exception with rationale.

Do NOT silently ignore new findings. Record the scan output for evidence binding regardless of outcome.

---

## Task 8: Update compliance ledger

Update the compliance ledger to reflect the fix.

**Files:**
- Modify: `wardline.compliance.json` — obligation `P1-S6-TAINT-JOIN-ABSORBING`

- [ ] **Step 1: Update the obligation state**

In `wardline.compliance.json`, find the `P1-S6-TAINT-JOIN-ABSORBING` obligation (starts around line 358). Make these changes:

Change `"state": "non_compliant"` to `"state": "evidenced"`.

Update the `evidence_classes` entry. Replace:

```json
        {
          "class": "ast_inspection",
          "target": "src/wardline/scanner/taint/callgraph_propagation.py",
          "note": "L3 callgraph propagation uses TRUST_RANK and max() rather than taint_join(); the divergence from the §6 join algebra is visible by static reading of this module."
        },
```

with:

```json
        {
          "class": "unit_tests",
          "target": "tests/unit/scanner/test_callgraph_propagation.py::TestCrossClassificationJoin",
          "note": "Six cross-classification combination tests verify taint_join() algebra at the L3 propagation level: cross-family merges produce MIXED_RAW, UNKNOWN-family demotion preserved, single-callee identity, MIXED_RAW absorption."
        },
        {
          "class": "unit_tests",
          "target": "tests/unit/scanner/test_callgraph_properties.py::test_join_commutativity_at_propagation_level",
          "note": "Hypothesis property test verifying propagation result is independent of callee iteration order."
        },
```

Update `notes` to:

```json
"notes": "Fixed: L3 callgraph propagation now uses taint_join() for callee combination per §6 join algebra. TRUST_RANK retained for floor clamps (ordering comparison, not taint combination). Cross-classification merges correctly produce MIXED_RAW. State evidenced pending BAR pipeline review."
```

- [ ] **Step 2: Verify the JSON is valid**

Run: `python3 -c "import json; json.load(open('wardline.compliance.json'))"`

Expected: No error output.

- [ ] **Step 3: Commit**

```
git add wardline.compliance.json
git commit -m "compliance: P1-S6 transitions from non_compliant to evidenced

L3 callgraph propagation now uses taint_join() for callee combination.
Evidence bound to TestCrossClassificationJoin (6 tests) and
test_join_commutativity_at_propagation_level (property test).
Pending BAR pipeline review for verified state."
```
