# Quality Engineer Audit -- Group C: Structural Verification Rules

**Date:** 2026-03-25
**Scope:** PY-WL-007 (WL-006), PY-WL-008 (WL-007), PY-WL-009 (WL-008)
**Test files:** `tests/unit/scanner/test_py_wl_007.py`, `tests/unit/scanner/test_py_wl_008.py`, `tests/unit/scanner/test_py_wl_009.py`

---

## 1. PY-WL-007 (WL-006): Runtime type-checking on internal data

### Severity matrix: E/St, W/R, W/R, Su/T, Su/T, W/R, W/R, W/St

**Taint-gated severity cell coverage:**

| # | Taint State | Expected Sev/Exc | Tested? | Evidence |
|---|-------------|-------------------|---------|----------|
| 1 | AUDIT_TRAIL | E/St | TESTED | `test_audit_trail_is_error` -- asserts ERROR severity |
| 2 | PIPELINE | W/R | TESTED | `test_pipeline_is_warning` -- asserts WARNING severity |
| 3 | SHAPE_VALIDATED | W/R | UNTESTED | No test for this taint state |
| 4 | EXTERNAL_RAW | Su/T | TESTED | `test_external_raw_is_suppress` -- asserts SUPPRESS severity |
| 5 | UNKNOWN_RAW | Su/T | TESTED | `test_unknown_raw_is_suppress` -- asserts SUPPRESS severity |
| 6 | UNKNOWN_SHAPE_VALIDATED | W/R | UNTESTED | No test for this taint state |
| 7 | UNKNOWN_SEM_VALIDATED | W/R | UNTESTED | No test for this taint state |
| 8 | MIXED_RAW | W/St | TESTED | `test_mixed_raw_is_warning` -- asserts WARNING severity |

**Cell coverage: 5/8 tested (62.5%).** Three WARNING/RELAXED cells are untested: SHAPE_VALIDATED, UNKNOWN_SHAPE_VALIDATED, UNKNOWN_SEM_VALIDATED.

**Exceptionability coverage gap:** No test asserts the exceptionability value for any cell. All five taint tests assert only `severity`, never `exceptionability`. This means STANDARD vs RELAXED vs TRANSPARENT is entirely unverified.

**Suppression tests:**

| Suppression Pattern | Positive Test (fires) | Negative Test (suppressed) |
|--------------------|-----------------------|---------------------------|
| AST dispatch (`ast.Assign`) | `test_isinstance_non_ast_still_fires`, `test_isinstance_ast_bare_name_still_fires` | `test_isinstance_ast_type_silent`, `test_isinstance_ast_tuple_silent` |
| Dunder protocol (`__eq__` + `NotImplemented`) | `test_isinstance_in_eq_without_not_implemented_fires` | `test_isinstance_in_eq_returning_not_implemented_silent`, `test_isinstance_in_ne_returning_not_implemented_silent` |
| Frozen dataclass (`__post_init__` + `object.__setattr__`) | `test_isinstance_in_post_init_without_freeze_fires` | `test_isinstance_in_post_init_with_freeze_silent` |
| Declared boundary | `test_isinstance_without_boundary_declaration_fires` | `test_isinstance_in_declared_boundary_silent`, `test_isinstance_in_declared_boundary_no_raise_still_silent`, `test_isinstance_external_boundary_silent` |

Suppression coverage is strong -- each suppression path has both positive and negative specimens.

**SUPPRESS cells negative specimen requirement (per spec section 10):** EXTERNAL_RAW and UNKNOWN_RAW carry SUPPRESS severity. The spec states SUPPRESS cells require only negative specimens (confirming the rule does not fire). However, the tests for these cells (`test_external_raw_is_suppress`, `test_unknown_raw_is_suppress`) assert that the rule DOES emit a finding with SUPPRESS severity -- the finding is produced but at SUPPRESS level. This is consistent with the implementation (finding emitted, severity set to SUPPRESS) rather than the spec expectation (no finding emitted). This is an implementation design choice, not a test bug, but corpus specimens should clarify whether SUPPRESS means "finding emitted at SUPPRESS" or "no finding emitted."

**Other coverage notes:**
- isinstance detection: 6 positive tests (dict, str, tuple types, if-wrapped, assert-wrapped, multiple)
- type() comparison: 5 positive tests (==, is, !=, is not, if-wrapped)
- Async function: 1 test
- Nested functions: 1 test
- False positive suppression: 5 negative tests (regular call, method call, type() alone, comparison without type, empty function)

### PY-WL-007 Gaps

1. **Three taint cells untested** (SHAPE_VALIDATED, UNKNOWN_SHAPE_VALIDATED, UNKNOWN_SEM_VALIDATED)
2. **Zero exceptionability assertions** across all tests
3. No test for `type()` comparison in a declared boundary (suppression only tested for isinstance)

---

## 2. PY-WL-008 (WL-007): Declared boundary with no rejection path

### Severity matrix: E/U across all 8 states (uniform UNCONDITIONAL)

**Boundary type coverage:**

| Boundary Type | Tested? | Evidence |
|---------------|---------|----------|
| shape_validation | TESTED | `test_boundary_without_rejection_path_fires` (default transition) |
| semantic_validation | TESTED | `test_semantic_boundary_without_rejection_path_fires` |
| combined_validation | UNTESTED | No test for combined_validation boundary |
| external_validation | UNTESTED | No test for external_validation boundary |
| restoration | TESTED | `test_restoration_boundary_without_rejection_path_fires` |

**Boundary type coverage: 3/5 tested (60%).** Missing: combined_validation, external_validation. The implementation in `_BOUNDARY_TRANSITIONS` includes all five types, but tests only exercise three.

**Rejection path tests:**

| Rejection Pattern | Should Suppress? | Tested? | Evidence |
|-------------------|-----------------|---------|----------|
| `if not ...: raise` | Yes | TESTED | `test_if_with_raise_silent` |
| `assert ...` | No (should fire) | TESTED | `test_assert_still_fires` |
| Guarded early return (`if not ...: return None`) | Yes | TESTED | `test_guarded_early_return_silent` |
| Positive guard return (`if valid: return`) | No (should fire) | TESTED | `test_positive_guard_return_still_fires` |
| Bare `raise` | Yes | TESTED | `test_bare_raise_silent` |
| No rejection path | No (should fire) | TESTED | `test_boundary_without_rejection_path_fires` |

Rejection path coverage is thorough.

**Dropped heuristics tests:**

| Heuristic | Tested? | Evidence |
|-----------|---------|----------|
| Helper call (`abort_if_invalid()`) | TESTED | `test_rejection_like_helper_call_still_fires` |
| Return validation result | TESTED | `test_returning_validation_result_still_fires` |

**Decorator fallback tests:**

| Pattern | Tested? | Evidence |
|---------|---------|----------|
| `@validates_shape` decorator (fires) | TESTED | `test_validates_shape_decorator_without_context_fires` |
| `@restoration_boundary` decorator (silent) | TESTED | `test_restoration_boundary_decorator_with_rejection_is_silent` |

**Nested/Async tests:**

| Pattern | Tested? | Evidence |
|---------|---------|----------|
| Nested def rejection does not suppress outer | TESTED | `test_nested_rejection_does_not_suppress_outer` |
| Async boundary fires | TESTED | `test_async_boundary_without_rejection_path_fires` |

**Taint matrix cell coverage:**

| # | Taint State | Expected Sev/Exc | Tested? | Evidence |
|---|-------------|-------------------|---------|----------|
| 1 | AUDIT_TRAIL | E/U | TESTED | `test_audit_trail_is_error` -- asserts ERROR severity |
| 2 | PIPELINE | E/U | UNTESTED | No test |
| 3 | SHAPE_VALIDATED | E/U | UNTESTED | No test |
| 4 | EXTERNAL_RAW | E/U | TESTED | `test_external_raw_is_error` -- asserts ERROR severity |
| 5 | UNKNOWN_RAW | E/U | UNTESTED | No test (default taint in helper, but no explicit assertion) |
| 6 | UNKNOWN_SHAPE_VALIDATED | E/U | UNTESTED | No test |
| 7 | UNKNOWN_SEM_VALIDATED | E/U | UNTESTED | No test |
| 8 | MIXED_RAW | E/U | UNTESTED | No test |

**Cell coverage: 2/8 tested (25%).** Since the matrix is uniform E/U, the practical risk is lower (any cell that fires proves the severity for all cells), but the spec requires per-cell coverage for corpus conformance. Six cells have no explicit severity assertion.

**Exceptionability coverage:** No test asserts UNCONDITIONAL exceptionability. Only severity (ERROR) is verified.

**Note on UNKNOWN_RAW:** The `_run_rule` helper defaults to `taint=TaintState.UNKNOWN_RAW`, so many tests implicitly execute under UNKNOWN_RAW taint. However, no test explicitly asserts the severity for that taint state. The two explicit taint tests are AUDIT_TRAIL and EXTERNAL_RAW only.

**Two-hop delegation:** Not tested. No test exercises a boundary function that delegates validation to a helper function across call boundaries.

### PY-WL-008 Gaps

1. **Two boundary types untested** (combined_validation, external_validation)
2. **Only 2/8 taint cells have explicit severity assertions**
3. **Zero exceptionability assertions**
4. **No two-hop delegation test**

---

## 3. PY-WL-009 (WL-008): Semantic boundary without prior shape validation

### Severity matrix: E/U across all 8 states (uniform UNCONDITIONAL)

**Combined boundary exemption tests:**

| Pattern | Tested? | Evidence |
|---------|---------|----------|
| `combined_validation` transition suppresses | TESTED | `test_combined_boundary_is_silent` |
| `@validates_external` decorator suppresses | TESTED | `test_validates_external_decorator_suppresses_without_context` |

Both combined boundary exemption paths are tested.

**Shape evidence detection tests:**

| Shape Evidence | Tested? | Evidence |
|----------------|---------|----------|
| isinstance() | TESTED | `test_isinstance_before_semantic_check_silent` |
| hasattr() | UNTESTED | No test for hasattr as shape evidence |
| Schema-qualified call (`validate_schema()`) | TESTED | `test_validate_schema_call_before_silent` |
| Membership test (`"key" in data`) | TESTED | `test_inline_membership_guard_silent` |
| Schema-qualified method (`jsonschema.validate()`) | UNTESTED | No test for receiver-qualified method calls |

**Shape evidence coverage: 3/5 distinct patterns tested.** Missing: hasattr(), schema-qualified method calls (e.g., `jsonschema.validate()`).

**Subscript-only scope tests:**

| Pattern | Tested? | Evidence |
|---------|---------|----------|
| Attribute-only access (should NOT fire) | TESTED | `test_attribute_access_only_is_silent` |
| Subscript access (should fire) | TESTED | `test_semantic_boundary_without_shape_evidence_fires` (uses `data["amount"]`) |

Subscript-only scoping is tested in both directions.

**Decorator fallback tests:**

| Pattern | Tested? | Evidence |
|---------|---------|----------|
| `@validates_semantic` fires without context | TESTED | `test_validates_semantic_decorator_fires_without_context` |
| `@validates_external` suppresses | TESTED | `test_validates_external_decorator_suppresses_without_context` |

**Nested/Async tests:**

| Pattern | Tested? | Evidence |
|---------|---------|----------|
| Shape check in nested def does not suppress outer | TESTED | `test_shape_check_in_nested_def_does_not_suppress_outer` |
| Async semantic boundary fires | TESTED | `test_async_semantic_boundary_fires` |

**Taint matrix cell coverage:**

| # | Taint State | Expected Sev/Exc | Tested? | Evidence |
|---|-------------|-------------------|---------|----------|
| 1 | AUDIT_TRAIL | E/U | TESTED | `test_audit_trail_is_error` -- asserts ERROR severity |
| 2 | PIPELINE | E/U | UNTESTED | Default taint in helper, but no explicit assertion |
| 3 | SHAPE_VALIDATED | E/U | UNTESTED | No test |
| 4 | EXTERNAL_RAW | E/U | UNTESTED | No test |
| 5 | UNKNOWN_RAW | E/U | UNTESTED | No test |
| 6 | UNKNOWN_SHAPE_VALIDATED | E/U | TESTED | `test_unknown_shape_validated_is_error` -- asserts ERROR severity |
| 7 | UNKNOWN_SEM_VALIDATED | E/U | UNTESTED | No test |
| 8 | MIXED_RAW | E/U | UNTESTED | No test |

**Cell coverage: 2/8 tested (25%).** Same situation as PY-WL-008 -- uniform matrix reduces practical risk but spec requires per-cell evidence.

**Exceptionability coverage:** No test asserts UNCONDITIONAL exceptionability.

**Note on PIPELINE:** The `_run_rule` helper defaults to `taint=TaintState.PIPELINE`, so most tests implicitly run under PIPELINE taint. However, no test explicitly asserts the severity for that taint state.

### PY-WL-009 Gaps

1. **Only 2/8 taint cells have explicit severity assertions**
2. **Zero exceptionability assertions**
3. **hasattr() not tested as shape evidence**
4. **Schema-qualified method calls not tested as shape evidence** (e.g., `jsonschema.validate()`)

---

## 4. Severity Matrix Cell Coverage Summary

### PY-WL-007 (non-uniform matrix -- 8 distinct cells)

| Cell | Sev/Exc | Severity Tested | Exceptionability Tested |
|------|---------|-----------------|------------------------|
| AUDIT_TRAIL | E/St | YES | NO |
| PIPELINE | W/R | YES | NO |
| SHAPE_VALIDATED | W/R | NO | NO |
| EXTERNAL_RAW | Su/T | YES | NO |
| UNKNOWN_RAW | Su/T | YES | NO |
| UNKNOWN_SHAPE_VALIDATED | W/R | NO | NO |
| UNKNOWN_SEM_VALIDATED | W/R | NO | NO |
| MIXED_RAW | W/St | YES | NO |

**Severity: 5/8 (62.5%). Exceptionability: 0/8 (0%).**

### PY-WL-008 (uniform E/U matrix)

| Cell | Sev/Exc | Severity Tested | Exceptionability Tested |
|------|---------|-----------------|------------------------|
| AUDIT_TRAIL | E/U | YES | NO |
| PIPELINE | E/U | NO | NO |
| SHAPE_VALIDATED | E/U | NO | NO |
| EXTERNAL_RAW | E/U | YES | NO |
| UNKNOWN_RAW | E/U | NO | NO |
| UNKNOWN_SHAPE_VALIDATED | E/U | NO | NO |
| UNKNOWN_SEM_VALIDATED | E/U | NO | NO |
| MIXED_RAW | E/U | NO | NO |

**Severity: 2/8 (25%). Exceptionability: 0/8 (0%).**

### PY-WL-009 (uniform E/U matrix)

| Cell | Sev/Exc | Severity Tested | Exceptionability Tested |
|------|---------|-----------------|------------------------|
| AUDIT_TRAIL | E/U | YES | NO |
| PIPELINE | E/U | NO | NO |
| SHAPE_VALIDATED | E/U | NO | NO |
| EXTERNAL_RAW | E/U | NO | NO |
| UNKNOWN_RAW | E/U | NO | NO |
| UNKNOWN_SHAPE_VALIDATED | E/U | YES | NO |
| UNKNOWN_SEM_VALIDATED | E/U | NO | NO |
| MIXED_RAW | E/U | NO | NO |

**Severity: 2/8 (25%). Exceptionability: 0/8 (0%).**

---

## 5. Corpus Alignment vs Section 10 Requirements

The spec (section 10) requires: **one positive specimen and one negative specimen per cell** in the severity matrix. For the three rules under audit, that is 24 cells total (8 per rule).

**Current state:**
- PY-WL-007: 5/8 cells have positive specimens with severity assertions. 2/8 SUPPRESS cells have specimens (though they emit findings at SUPPRESS rather than suppressing entirely). No per-cell negative specimens organized by taint state.
- PY-WL-008: 2/8 cells have positive specimens with severity assertions. No per-cell negative specimens.
- PY-WL-009: 2/8 cells have positive specimens with severity assertions. No per-cell negative specimens.

**Minimum specimen count (per spec):** 24 cells across 3 rules. PY-WL-007 has 2 SUPPRESS cells, so effective minimum is 22 positive + 24 negative = 46 specimens minimum. Current explicit per-cell severity tests: 9 total.

**Adversarial specimen gap:** The spec requires adversarial specimens per rule (min 1 adversarial false positive + 1 adversarial false negative per rule). No tests are labelled or organized as adversarial specimens, though some suppression tests (e.g., AST dispatch, dunder protocol) function as adversarial false-positive tests in practice.

**Note:** The current tests are unit tests, not formal corpus specimens in the YAML format described in section 10. The corpus infrastructure does not yet exist. This is expected at the current project stage but represents a gap for conformance assessment.

---

## 6. Summary of Findings

### Critical Gaps (affecting conformance claims)

| ID | Rule | Gap | Impact |
|----|------|-----|--------|
| C1 | ALL | Zero exceptionability assertions across all three rules (0/24 cells) | Cannot verify UNCONDITIONAL vs STANDARD vs RELAXED vs TRANSPARENT assignment |
| C2 | PY-WL-008 | combined_validation and external_validation boundary types untested | Two of five declared boundary transitions have no coverage |
| C3 | PY-WL-007 | Three taint cells untested (SHAPE_VALIDATED, UNKNOWN_SHAPE_VALIDATED, UNKNOWN_SEM_VALIDATED) | Non-uniform matrix means untested cells could have wrong severity |
| C4 | PY-WL-008 | Only 2/8 taint cells tested | Per-cell coverage below corpus minimum |
| C5 | PY-WL-009 | Only 2/8 taint cells tested | Per-cell coverage below corpus minimum |

### Notable Gaps (not blocking but should be addressed)

| ID | Rule | Gap | Impact |
|----|------|-----|--------|
| N1 | PY-WL-009 | hasattr() not tested as shape evidence | Implementation accepts it but no test proves it |
| N2 | PY-WL-009 | Schema-qualified method calls untested | `jsonschema.validate()` pattern recognized by impl but untested |
| N3 | PY-WL-008 | No two-hop delegation test | Spec mentions two-hop delegation; no test exercises it |
| N4 | PY-WL-007 | type() comparison not tested in declared boundary context | Only isinstance suppression is tested for declared boundaries |
| N5 | ALL | No formal corpus specimens exist (YAML format per section 10) | Expected at current stage but blocks conformance assessment |

### Strengths

- PY-WL-007 suppression logic is thoroughly tested with both positive and negative specimens for all four suppression patterns
- PY-WL-008 rejection path analysis is well-covered (raise, guarded return, assert rejection, bare raise, dropped heuristics)
- PY-WL-009 combined boundary exemption is tested from both manifest and decorator paths
- All three rules test nested function isolation and async behavior
- PY-WL-009 subscript-only scoping is verified in both directions

---

## Verdict: CONCERN

**Rationale:** The functional behavior of all three rules is well-tested -- detection logic, suppression patterns, rejection path analysis, and boundary type handling are covered with meaningful positive and negative specimens. However, systematic severity matrix coverage is incomplete across all three rules (9/24 cells have explicit severity assertions, 0/24 have exceptionability assertions). For PY-WL-007 specifically, three cells in a non-uniform matrix are untested, meaning incorrect severity assignment would go undetected. For PY-WL-008, two of five boundary types lack any test coverage. These gaps do not indicate broken behavior but do prevent a conformance claim against the section 10 requirements.

The verdict is CONCERN rather than FAIL because: (a) the uniform matrices of PY-WL-008 and PY-WL-009 mean any tested cell implicitly validates all cells (the code path is identical), reducing practical risk; (b) functional coverage of the rule logic itself is strong; (c) the missing exceptionability assertions are a systematic gap that affects all rules equally and can be addressed with a focused pass. A FAIL verdict would require evidence of actual incorrect behavior, which was not found.
