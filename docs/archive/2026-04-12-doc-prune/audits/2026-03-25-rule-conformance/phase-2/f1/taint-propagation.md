# Phase 2 / F1: Taint Propagation Assessment

**Auditor:** Taint Propagation Agent
**Date:** 2026-03-25
**Scope:** Join lattice, taint assignment, propagation depth, call-graph infrastructure, MIXED_RAW handling

---

## 1. Join Lattice Implementation

**File:** `src/wardline/core/taints.py`

The join lattice is implemented correctly per spec section 5.1.

**MIXED_RAW absorption:** Lines 54-55 handle MIXED_RAW as the absorbing element explicitly: `if a == MIXED_RAW or b == MIXED_RAW: return MIXED_RAW`. This fires before the lookup table, ensuring absorption for all state combinations.

**Self-join identity:** Line 51-52: `if a == b: return a`. Correct.

**UNKNOWN chain joins:** The `_JOIN_TABLE` (lines 34-41) encodes three non-trivial pairs:
- `(UNKNOWN_RAW, UNKNOWN_SEM_VALIDATED) -> UNKNOWN_RAW` -- validated status lost. Correct per spec.
- `(UNKNOWN_RAW, UNKNOWN_SHAPE_VALIDATED) -> UNKNOWN_RAW` -- validated status lost. Correct per spec.
- `(UNKNOWN_SEM_VALIDATED, UNKNOWN_SHAPE_VALIDATED) -> UNKNOWN_SHAPE_VALIDATED` -- demotes to weaker validation. Correct per spec.

**Cross-classification merges:** All pairs not in the table fall through to `MIXED_RAW` (line 59). This correctly implements the spec rule that any merge of values from different trust classifications produces MIXED_RAW.

**Operand normalization:** Keys are sorted by `.value` string (line 58) for deterministic, commutative lookup. The table keys are pre-sorted to match. Correct.

**Assessment: PASS.** The join lattice faithfully implements all 36 unique state-pairs from the spec's join table.

---

## 2. Taint Assignment

**File:** `src/wardline/scanner/taint/function_level.py`

Taint assignment follows a strict three-level precedence:

1. **Decorator taint** (highest): `DECORATOR_TAINT_MAP` maps seven canonical decorator names to taint states (lines 41-48). Resolution via `taint_from_annotations()` checks the discovery-pass annotations for the function's qualname.
2. **Module tiers**: `resolve_module_default()` performs path-prefix matching against manifest `module_tiers` entries, with most-specific (longest path) winning.
3. **UNKNOWN_RAW** (fallback): All undecorated functions in unregistered modules get `UNKNOWN_RAW`.

The precedence is enforced in `_walk_and_assign()` (lines 180-188): decorator check first, then module default, then fallback. Each function also records its `TaintSource` (`"decorator"`, `"module_default"`, or `"fallback"`) for downstream provenance tracking.

**Assessment: PASS.** Resolution order matches the spec's security invariant that explicit annotations override module defaults.

---

## 3. Taint Propagation Depth

The engine implements three analysis levels, gated by `analysis_level`:

### Level 1 (default): Function-level taint
- `assign_function_taints()` assigns a single taint per function based on decorators/manifest/fallback.
- No cross-function propagation. Pure per-function assignment.
- **Spec conformance:** Satisfies the MUST for direct-flow taint between declared boundaries (section 8.1).

### Level 2 (`analysis_level >= 2`): Variable-level taint
- `compute_variable_taints()` in `scanner/taint/variable_level.py` tracks per-variable taint within function bodies.
- Handles assignments, augmented assignments, tuple unpacking, for-loops, with-as, exception-as, walrus operators.
- Control-flow merges (if/else, try/except, loops) use `taint_join()` for branch convergence.
- Call resolution is limited to simple `Name` calls looked up in the function-level `taint_map` (line 171-174). Method calls and complex expressions fall back to `function_taint`.
- **Spec conformance:** Implements intraprocedural explicit-flow taint analysis. Does not cross function boundaries.

### Level 3 (`analysis_level >= 3`): Call-graph taint propagation
- `callgraph.py` extracts intra-module call edges: module-level function calls, `self.method()` calls, constructor calls.
- `callgraph_propagation.py` performs SCC-based fixed-point iteration using Tarjan's algorithm.
- Propagation refines non-anchored (non-decorator) functions: their taint can only get less trusted (never more trusted) based on their callees.
- Anchored functions (decorator-assigned) are immutable during propagation.
- Floor clamp: L3 never makes a function more trusted than its L1 baseline.
- Unresolved calls enforce a pessimistic floor (cannot improve beyond L1).
- Post-fixed-point assertions verify anchored functions did not change and module-default functions did not upgrade.
- **Spec conformance:** This is full transitive intra-module inference. It satisfies the "full transitive inference across the call graph" tool quality target from section 8.1 for intra-module analysis. Cross-module propagation is not implemented (edges are intra-module only).

**Assessment: PASS** for the propagation levels implemented. The three-tier analysis system is well-structured and the L3 propagation is sound (SCC + fixed-point with convergence bounds).

---

## 4. Call-Graph Infrastructure vs. Two-Hop Rejection Path Resolution

**Spec requirement (section 7.2, section 8.1):** WL-007 rejection paths include "a call to a function that unconditionally raises, if the called function is resolvable via two-hop call-graph analysis." The spec further states: "Two-hop delegation satisfies the requirement; deeper delegation requires full interprocedural analysis."

**Current PY-WL-008 implementation** (`src/wardline/scanner/rules/py_wl_008.py`):
- `_has_rejection_path()` checks only the boundary function's own body (lines 84-95).
- It looks for direct `raise` statements and guarded `if` blocks with rejection terminators.
- There is **no call-graph resolution** -- it does not follow calls to determine whether a callee unconditionally raises.

**Available infrastructure:**
- `callgraph.py` already extracts intra-module call edges with resolved/unresolved counts.
- `callgraph_propagation.py` performs full SCC-based propagation.
- The call-graph extraction resolves: module-level function calls, `self.method()` calls, and constructor calls.

**Gap analysis:** The call-graph infrastructure could support two-hop rejection path resolution. Specifically:
1. The edge extraction in `extract_call_edges()` already resolves the first hop (which functions a boundary calls).
2. A second pass over the callee's body to check for unconditional `raise` would complete the two-hop chain.
3. This does not require the full SCC/fixed-point machinery -- a simple two-step lookup would suffice.

However, PY-WL-008 does not use any of the call-graph infrastructure. The rule operates purely intraprocedurally with no awareness of callee behavior.

**Note on rule mapping:** The spec's WL-007 (boundary with no rejection path) maps to PY-WL-008 in this binding. The code file is named `py_wl_008.py` and uses `RuleId.PY_WL_008`, but the docstring says "WL-007 applies to the boundary function itself." The two-hop requirement applies to this rule regardless of numbering.

**Assessment: CONCERN.** The call-graph infrastructure exists and could support two-hop resolution with modest additional work (estimated: a helper that checks whether a callee unconditionally raises, plus wiring it into `_has_rejection_path()`). The gap is a known issue from Phase 1. The infrastructure distance is small -- the call-graph module already resolves the relevant call targets -- but the wiring is absent.

---

## 5. MIXED_RAW Handling and Normalisation Boundaries

**Spec (section 5.1):** "A declared normalisation boundary may collapse mixed inputs into a new Tier 2 artefact -- the normalisation step is semantically a new construction, not a passthrough of the original mixed data."

**Implementation:**
- There is no normalisation boundary concept in the scanner. A grep for "normalisation", "normalization", and "collapse" across `src/wardline/scanner/` returns no results related to MIXED_RAW collapse.
- The `DECORATOR_TAINT_MAP` has no entry for a normalisation boundary decorator.
- The `_BOUNDARY_TRANSITIONS` set in PY-WL-008 does not include a normalisation transition.
- The join lattice correctly produces MIXED_RAW as the absorbing element, but there is no mechanism to exit MIXED_RAW through a declared normalisation boundary.

**Spec conformance:** The spec describes normalisation boundaries as a MAY-level mechanism ("A declared normalisation boundary may collapse..."). The absence of this feature is not a conformance violation, but it means MIXED_RAW is a terminal state from which recovery is impossible in the current implementation.

**Assessment: Not a conformance issue.** The spec uses permissive language. However, this is a functional limitation worth noting: any data path that produces MIXED_RAW cannot be recovered, even through a legitimate normalisation step.

---

## Summary of Findings

| Area | Verdict | Detail |
|------|---------|--------|
| Join lattice | PASS | All 36 state-pairs correct, MIXED_RAW absorption, UNKNOWN chain demotions |
| Taint assignment | PASS | Correct precedence: decorator > module_tiers > UNKNOWN_RAW |
| L1 function-level taint | PASS | Direct-flow MUST satisfied |
| L2 variable-level taint | PASS | Intraprocedural explicit-flow with join-based branch merging |
| L3 call-graph propagation | PASS | SCC-based fixed-point, sound monotonicity, convergence bounds |
| Two-hop rejection path | CONCERN | Infrastructure exists but PY-WL-008 does not use it |
| MIXED_RAW normalisation | N/A | Not required by spec (MAY-level); not implemented |

---

## Verdict: CONCERN

**Rationale:** The core taint machinery -- join lattice, assignment precedence, variable-level tracking, and call-graph propagation -- is correctly implemented and conforms to the spec. The single concern is that PY-WL-008 (implementing the spec's WL-007 rejection-path requirement) does not perform two-hop call-graph resolution for rejection paths, despite:

1. The spec stating this as a MUST at section 7.2: "A call to a function that unconditionally raises, if the called function is resolvable via two-hop call-graph analysis"
2. Section 8.1 reinforcing: "WL-007 is primarily intraprocedural: a validation function that delegates to a called function for rejection does not satisfy WL-007 unless the delegation is resolvable via two-hop call-graph analysis"
3. The call-graph infrastructure (`scanner/taint/callgraph.py`) already resolving the relevant call targets

The gap is small in implementation terms but represents a spec MUST that is not met. This is consistent with the Phase 1 finding.

**Evidence:**
- `src/wardline/scanner/rules/py_wl_008.py`, function `_has_rejection_path()` (lines 84-95): no call-graph awareness
- `src/wardline/scanner/taint/callgraph.py`, function `extract_call_edges()`: infrastructure that could support two-hop resolution
- Spec section 7.2: two-hop call-graph analysis is part of the formal rejection-path definition
- Spec section 8.1: explicit MUST for two-hop delegation resolution on WL-007
