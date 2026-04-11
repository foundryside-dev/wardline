# Tier Consistency Assessment

**Assessor:** Tier Consistency Agent (Phase 2, F1)
**Date:** 2026-03-25
**Scope:** Tier-to-taint-state mapping, coding posture enforcement, taint state reachability, module-tier defaults

---

## 1. Tier-to-Taint-State Mapping

### 1.1 Decorator-to-taint mapping

The `DECORATOR_TAINT_MAP` in `src/wardline/scanner/taint/function_level.py` (lines 41-48) maps each Group 1 decorator to a taint state:

| Decorator | Assigned Taint | Spec Tier |
|-----------|---------------|-----------|
| `external_boundary` | EXTERNAL_RAW | Tier 4 |
| `validates_shape` | SHAPE_VALIDATED | Tier 3 |
| `validates_semantic` | PIPELINE | Tier 2 |
| `validates_external` | PIPELINE | Tier 2 |
| `tier1_read` | AUDIT_TRAIL | Tier 1 |
| `audit_writer` | AUDIT_TRAIL | Tier 1 |
| `authoritative_construction` | AUDIT_TRAIL | Tier 1 |

Cross-checked against `TAINT_TO_TIER` in `src/wardline/core/tiers.py` (lines 18-27): every taint state maps to the correct authority tier. The completeness guard at line 30-32 ensures no TaintState member is missed.

**Finding 1.1a:** `@tier1_read` correctly produces AUDIT_TRAIL taint. PASS.

**Finding 1.1b:** The decorator definitions in `src/wardline/decorators/authority.py` carry `_wardline_tier_source` or `_wardline_transition` attributes that are consistent with the taint map. For example, `tier1_read` has `_wardline_tier_source=TaintState.AUDIT_TRAIL` (line 48), and `validates_shape` has `_wardline_transition=(TaintState.EXTERNAL_RAW, TaintState.SHAPE_VALIDATED)` (line 31). The taint assignment in `DECORATOR_TAINT_MAP` uses the **output state** of each transition, not the input state. PASS.

### 1.2 Body evaluation taint: output-taint vs input-taint

The Python binding spec (Part II-A, around line 209-216) states:

> At the first analysis level, the scanner evaluates pattern rules within validation boundary bodies using the severity lookups of the **input tier** -- the tier the validator operates on, not the tier it produces.

The implementation assigns **output taint** to validation functions:
- `@validates_shape` gets SHAPE_VALIDATED (output), not EXTERNAL_RAW (input)
- `@validates_semantic` gets PIPELINE (output), not SHAPE_VALIDATED (input)
- `@validates_external` gets PIPELINE (output), not EXTERNAL_RAW (input)

The implementation compensates through **per-rule boundary suppression mechanisms** rather than input-tier taint:

| Rule | Compensation mechanism | Spec intent met? |
|------|----------------------|-----------------|
| PY-WL-003 | `_SUPPRESSED_BOUNDARY_TRANSITIONS` set in `py_wl_003.py` (lines 31-37) suppresses all existence checks inside shape/combined validation boundaries. | Yes -- full suppression matches spec table. |
| PY-WL-007 | `_has_declared_boundary()` in `py_wl_007.py` (lines 107-120) suppresses isinstance checks in any function with a manifest boundary entry. | Yes -- full suppression matches spec intent (isinstance is the implementation of the contract). |

**Finding 1.2a (CONCERN):** The function-level taint for validation boundary bodies uses output taint, not input taint as the spec prescribes. For PY-WL-003 and PY-WL-007, per-rule suppression compensates correctly. However, any **future rule** that relies solely on the taint-based severity matrix for validation boundary bodies will use the wrong severity. For example:

- PY-WL-004 (broad exception handlers) at SHAPE_VALIDATED: (W, St). At EXTERNAL_RAW: (W, R). A `@validates_shape` body gets STANDARD exceptionability instead of RELAXED. The difference is minor (both WARNING severity) but the governance burden differs.

This is an architectural concern, not a current functional bug. The existing rules are functionally correct through their boundary-aware suppression mechanisms.

### 1.3 Taint precedence chain

The engine in `src/wardline/scanner/engine.py` calls `assign_function_taints()` (line 183-184), which implements the three-level precedence in `src/wardline/scanner/taint/function_level.py` (lines 165-210):

1. **Decorator taint** (highest) -- `taint_from_annotations()` checks DECORATOR_TAINT_MAP
2. **Module tiers** -- `resolve_module_default()` does path-prefix matching with most-specific-wins
3. **UNKNOWN_RAW fallback** -- hardcoded at line 187

This precedence is tested in `tests/unit/scanner/test_taint.py`:
- `TestTaintPrecedence.test_decorator_overrides_module_default` (line 208)
- `TestTaintPrecedence.test_module_default_overrides_unknown_raw` (line 234)

**Finding 1.3:** Precedence chain is correct and tested. Decorator taint overrides module default, which overrides UNKNOWN_RAW fallback. PASS.

---

## 2. Coding Posture Enforcement

### 2.1 Tier 1: Offensive programming

The spec requires offensive programming at Tier 1 (AUDIT_TRAIL): invariant-enforcing, halt-on-breach.

From the severity matrix (`src/wardline/core/matrix.py`):
- PY-WL-001 at AUDIT_TRAIL: (E, U) -- ERROR, UNCONDITIONAL. Dict key access with fallback default is unconditionally an error.
- PY-WL-002 at AUDIT_TRAIL: (E, U) -- ERROR, UNCONDITIONAL. Attribute access with fallback default is unconditionally an error.
- PY-WL-003 at AUDIT_TRAIL: (E, U) -- ERROR, UNCONDITIONAL. Existence-checking is unconditionally an error.
- PY-WL-004 at AUDIT_TRAIL: (E, U) -- ERROR, UNCONDITIONAL. Broad exception handlers are unconditionally an error.
- PY-WL-005 at AUDIT_TRAIL: (E, U) -- ERROR, UNCONDITIONAL. Silent exception catching is unconditionally an error.

All five defensive-programming rules fire at ERROR/UNCONDITIONAL for AUDIT_TRAIL. This correctly enforces the offensive programming posture: no exceptions allowed, all violations are unconditional errors.

**Finding 2.1:** Tier 1 coding posture enforcement is correct. PASS.

### 2.2 Tier 4: Sceptical programming

The spec requires sceptical programming at Tier 4 (EXTERNAL_RAW): treat as hostile, validate structure first.

From the severity matrix:
- PY-WL-001 at EXTERNAL_RAW: (E, St) -- fallback defaults are errors (cannot trust structure).
- PY-WL-003 at EXTERNAL_RAW: (E, St) -- existence-checking is expected but still flagged as standard (the structural gate pattern is a warning that structure is not yet validated).
- PY-WL-004 at EXTERNAL_RAW: (W, R) -- broad handlers are warnings with relaxed governance (may be acceptable at boundaries).
- PY-WL-007 at EXTERNAL_RAW: (Su, T) -- type-checking is suppressed (it is the correct behaviour for external data).

The enforcement gradient is present: Tier 4 is strict on access-with-defaults (PY-WL-001/002) but relaxed on type-checking (PY-WL-007). This correctly reflects that sceptical programming requires validation but does not penalise the act of validating.

**Finding 2.2:** Tier 4 coding posture enforcement is correct. PASS.

### 2.3 Tier 2 and Tier 3 intermediate postures

- PY-WL-007 at PIPELINE (Tier 2): (W, R) -- type-checking is a warning (confident programming should not need it, but it is governable).
- PY-WL-007 at SHAPE_VALIDATED (Tier 3): (W, R) -- same as Tier 2 (guarded programming may still type-check).
- PY-WL-004 at PIPELINE (Tier 2): (E, St) -- broad handlers are errors (confident programming means you know what exceptions are possible).
- PY-WL-004 at SHAPE_VALIDATED (Tier 3): (W, St) -- broad handlers are warnings (guarded programming may need them).

**Finding 2.3:** Intermediate postures show appropriate gradation. PASS.

---

## 3. Taint State Completeness

### 3.1 Level 1 reachability

At Level 1 (function-level taint from decorators and manifest), the following states are directly reachable:

| State | Reachable via | Evidence |
|-------|-------------|----------|
| AUDIT_TRAIL | `@tier1_read`, `@audit_writer`, `@authoritative_construction`, or module_tiers | DECORATOR_TAINT_MAP lines 46-48 |
| PIPELINE | `@validates_semantic`, `@validates_external`, or module_tiers | DECORATOR_TAINT_MAP lines 44-45 |
| SHAPE_VALIDATED | `@validates_shape` or module_tiers | DECORATOR_TAINT_MAP line 43 |
| EXTERNAL_RAW | `@external_boundary` or module_tiers | DECORATOR_TAINT_MAP line 42 |
| UNKNOWN_RAW | Fallback for unannotated functions in undeclared modules | `_walk_and_assign` line 187 |

The following states are **not directly reachable** at Level 1 via decorators:

| State | Reachable via | Evidence |
|-------|-------------|----------|
| UNKNOWN_SHAPE_VALIDATED | module_tiers only (string "UNKNOWN_SHAPE_VALIDATED") | `resolve_module_default` accepts any valid TaintState string |
| UNKNOWN_SEM_VALIDATED | module_tiers only (string "UNKNOWN_SEM_VALIDATED") | Same mechanism |
| MIXED_RAW | module_tiers only (string "MIXED_RAW") | Same mechanism |

### 3.2 Level 2 and Level 3 reachability

- **MIXED_RAW** is reachable at Level 2 via `taint_join()` when variables from different trust classifications merge (tested in `tests/unit/scanner/test_variable_level_taint.py`).
- **UNKNOWN_SHAPE_VALIDATED** and **UNKNOWN_SEM_VALIDATED** are reachable at Level 3 via call-graph propagation and the join table in `src/wardline/core/taints.py` (lines 34-41).
- **MIXED_RAW** is reachable at Level 3 via call-graph propagation when functions call across trust classifications.

### 3.3 Assessment

**Finding 3.3a (CONCERN):** UNKNOWN_SHAPE_VALIDATED and UNKNOWN_SEM_VALIDATED have no dedicated decorators. They are only reachable at Level 1 through the module_tiers manifest escape hatch (declaring `default_taint: "UNKNOWN_SHAPE_VALIDATED"`) or at Level 3 through call-graph propagation. The spec defines these states for unknown-provenance data that has passed validation (Section 5.1), and they are part of the restoration boundary model (Section 5.3). No restoration boundary decorator currently produces these states at Level 1.

This is not a bug -- these states represent data whose provenance is unknown, which is inherently a situation where the decorator surface may be incomplete. However, it means that at Level 1 analysis, an application consuming data from a restoration boundary with only structural evidence has no decorator that directly assigns UNKNOWN_SHAPE_VALIDATED. The module_tiers mechanism is the intended workaround.

**Finding 3.3b:** All 8 states appear in the severity matrix, the join table, and the TAINT_TO_TIER mapping. No state is orphaned or missing from the enforcement infrastructure. PASS.

---

## 4. Module-Tier Defaults

### 4.1 Mechanism

`resolve_module_default()` in `src/wardline/scanner/taint/function_level.py` (lines 94-138):

1. Iterates all `module_tiers` entries from the manifest
2. Uses `PurePath.relative_to()` for directory-boundary-safe path matching
3. Selects the most-specific match (longest path) when multiple entries match
4. Converts the string taint to `TaintState` enum, logging a warning on invalid values

### 4.2 Correctness

The implementation correctly assigns default taint to unannotated functions in declared modules. Tests in `tests/unit/scanner/test_taint.py`:

- `TestModuleTiersTaint.test_declared_module_gets_module_default` -- basic path matching
- `TestModuleTiersTaint.test_subdirectory_matches_module_tier` -- subdirectory inheritance
- `TestModuleTiersTaint.test_partial_name_does_not_match` -- no false prefix matches (api vs api_v2)
- `TestMostSpecificModuleTier.test_most_specific_module_tier_wins` -- specificity ordering
- `TestMostSpecificModuleTier.test_most_specific_wins_regardless_of_order` -- order-independence

### 4.3 Security invariant

The spec states (Section 13): "a module declared as AUDIT_TRAIL context has its unannotated functions treated as Tier 1, activating the full pattern-rule suite at the strictest severity."

`resolve_module_default()` accepts any valid TaintState string, including AUDIT_TRAIL. The precedence chain ensures that decorator taint overrides module defaults -- so an `@external_boundary` function in an AUDIT_TRAIL module correctly gets EXTERNAL_RAW, not AUDIT_TRAIL.

**Finding 4.1:** Module-tier defaults are correct, well-tested, and respect the precedence invariant. PASS.

---

## Summary

| Area | Finding | Status |
|------|---------|--------|
| Decorator-to-taint mapping | All 7 decorators map to correct taint states | PASS |
| Taint precedence | decorator > module_tiers > UNKNOWN_RAW, tested | PASS |
| Body evaluation taint | Uses output-taint, not input-taint per spec; compensated by per-rule suppression | CONCERN |
| Tier 1 offensive posture | All defensive-pattern rules fire at E/U | PASS |
| Tier 4 sceptical posture | Correct severity gradient; type-checking suppressed | PASS |
| Tier 2/3 intermediate postures | Appropriate gradation | PASS |
| State reachability (L1) | 5 of 8 states directly reachable via decorators; 3 require module_tiers or L3 | CONCERN |
| State reachability (L2/L3) | All 8 states reachable | PASS |
| Module-tier defaults | Correct path matching, specificity ordering, tested | PASS |
| TAINT_TO_TIER completeness | All 8 states mapped, enforced at import time | PASS |

---

## Verdict: CONCERN

The tier-to-taint infrastructure is functionally correct. The severity matrix, taint assignment, precedence chain, and tier mapping are all sound. No current rule produces incorrect enforcement behaviour.

Two architectural concerns exist:

1. **Output-taint vs input-taint for validation boundaries.** The spec prescribes input-tier severity for validation boundary bodies (Part II-A, Section A.4). The implementation assigns output-tier taint and compensates with per-rule boundary-aware suppression. This works for PY-WL-003 and PY-WL-007 today, but creates a trap for future rules: any new rule that does not add explicit boundary suppression will use the wrong severity for validation boundary bodies. Specifically, `@validates_shape` bodies will be evaluated at SHAPE_VALIDATED (Tier 3) severity instead of EXTERNAL_RAW (Tier 4) severity. The current severity difference is minor (e.g., PY-WL-004 exceptionability: STANDARD vs RELAXED), but the architectural debt accumulates with each new rule.

2. **UNKNOWN_SHAPE_VALIDATED and UNKNOWN_SEM_VALIDATED are not directly reachable at Level 1.** No decorator produces these states. They require module_tiers configuration or Level 3 call-graph propagation. This is acceptable given the spec's restoration boundary model (these states arise from restoration with partial evidence), but it means Level 1 analysis cannot distinguish "unknown-provenance shape-validated data" from "known-provenance shape-validated data" without manifest configuration.

Neither concern represents a current functional defect. Both represent structural risks that should be tracked for future development.

**Evidence:**
- `src/wardline/scanner/taint/function_level.py` lines 41-48 (DECORATOR_TAINT_MAP)
- `src/wardline/core/matrix.py` lines 45-64 (severity matrix data)
- `src/wardline/core/tiers.py` lines 18-32 (TAINT_TO_TIER with completeness guard)
- `src/wardline/scanner/rules/py_wl_003.py` lines 31-37, 85-99 (boundary suppression)
- `src/wardline/scanner/rules/py_wl_007.py` lines 107-120, 171-174 (boundary suppression)
- `docs/wardline/wardline-02-A-python-binding.md` lines 209-216 (body evaluation spec)
- `tests/unit/scanner/test_taint.py` (25 tests covering all precedence branches)
