# Group A — Quality Engineer Assessment

**Date:** 2026-03-25
**Rules:** PY-WL-001, PY-WL-002, PY-WL-003
**Test files:** `tests/unit/scanner/test_py_wl_001.py`, `tests/unit/scanner/test_py_wl_002.py`, `tests/unit/scanner/test_py_wl_003.py`

---

## Severity Matrix Cell Coverage

The severity matrix defines 8 taint states per rule. A test "exercises a cell" only if it injects a specific taint state via `ScanContext.function_level_taint_map` and asserts the resulting severity AND exceptionability.

### PY-WL-001 — Expected: E/U, E/St, E/St, E/St, E/St, E/St, E/St, E/St

| Taint State | Expected | Tested? | Notes |
|---|---|---|---|
| AUDIT_TRAIL | E/U | UNTESTED | No test sets this taint state |
| PIPELINE | E/St | UNTESTED | No test sets this taint state |
| SHAPE_VALIDATED | E/St | UNTESTED | No test sets this taint state |
| EXTERNAL_RAW | E/St | UNTESTED | No test sets this taint state |
| UNKNOWN_RAW | E/St | **IMPLICIT** | Default taint (no context set), but severity/exceptionability not asserted per-cell |
| UNKNOWN_SHAPE_VALIDATED | E/St | UNTESTED | No test sets this taint state |
| UNKNOWN_SEM_VALIDATED | E/St | UNTESTED | No test sets this taint state |
| MIXED_RAW | E/St | UNTESTED | No test sets this taint state |

**Summary:** 0 of 8 cells explicitly tested. Tests call `_run_rule()` without setting a `ScanContext`, so `_get_function_taint()` returns `UNKNOWN_RAW` by default. The test at line 61 asserts `severity == Severity.ERROR` but does not assert exceptionability, and does not parameterize across taint states. The `_run_rule_with_context()` helper passes `function_level_taint_map={}`, which also defaults to UNKNOWN_RAW. No test exercises the AUDIT_TRAIL cell (E/U) which has a distinct exceptionability from the other 7 cells.

### PY-WL-002 — Expected: E/U, E/St, E/St, E/St, E/St, E/St, E/St, E/St

| Taint State | Expected | Tested? | Notes |
|---|---|---|---|
| AUDIT_TRAIL | E/U | UNTESTED | No test sets any taint state |
| PIPELINE | E/St | UNTESTED | |
| SHAPE_VALIDATED | E/St | UNTESTED | |
| EXTERNAL_RAW | E/St | UNTESTED | |
| UNKNOWN_RAW | E/St | **IMPLICIT** | Default path, severity asserted (ERROR), exceptionability not asserted |
| UNKNOWN_SHAPE_VALIDATED | E/St | UNTESTED | |
| UNKNOWN_SEM_VALIDATED | E/St | UNTESTED | |
| MIXED_RAW | E/St | UNTESTED | |

**Summary:** 0 of 8 cells explicitly tested. No test in this file imports `ScanContext`, `TaintState`, or `Exceptionability`. The only severity assertion is `severity == Severity.ERROR` on the default (UNKNOWN_RAW) path.

### PY-WL-003 — Expected: E/U, E/U, E/U, E/St, E/St, E/U, E/U, E/St

| Taint State | Expected | Tested? | Notes |
|---|---|---|---|
| AUDIT_TRAIL | E/U | UNTESTED | No test sets AUDIT_TRAIL |
| PIPELINE | E/U | UNTESTED | |
| SHAPE_VALIDATED | E/U | UNTESTED | |
| EXTERNAL_RAW | E/St | **IMPLICIT** | `_run_rule_with_boundary()` defaults to `TaintState.EXTERNAL_RAW`, but those tests verify suppression, not the cell's severity/exceptionability |
| UNKNOWN_RAW | E/St | **IMPLICIT** | Default path via `_run_rule()`, severity asserted (ERROR), exceptionability not asserted |
| UNKNOWN_SHAPE_VALIDATED | E/U | UNTESTED | |
| UNKNOWN_SEM_VALIDATED | E/U | UNTESTED | |
| MIXED_RAW | E/St | UNTESTED | |

**Summary:** 0 of 8 cells explicitly tested with both severity and exceptionability assertions. PY-WL-003's matrix has a non-trivial split (4 cells E/U, 4 cells E/St) that is entirely unverified. This is the most critical gap because the U vs St distinction is load-bearing for governance.

---

## Pattern Coverage (Positive Cases)

### PY-WL-001

| Pattern | Test Exists? | Test Reference |
|---|---|---|
| `.get(k, default)` | YES | `TestGetWithDefault` (3 variants: string, None, variable) |
| `.setdefault(k, default)` | YES | `TestSetdefault.test_setdefault_with_default_fires` |
| `defaultdict(factory)` | YES | `TestDefaultdict.test_defaultdict_with_factory_fires` |
| `collections.defaultdict(factory)` | YES | `TestDefaultdict.test_collections_defaultdict_fires` |
| `defaultdict(lambda: ...)` | YES | `TestDefaultdict.test_defaultdict_with_lambda_fires` |

**All positive patterns covered.**

### PY-WL-002

| Pattern | Test Exists? | Test Reference |
|---|---|---|
| `getattr(obj, name, default)` | YES | `TestGetattrWithDefault` (3 variants) |
| `obj.attr or default` | YES | `TestAttributeOrDefault` (2 variants) |

**All positive patterns covered.**

### PY-WL-003

| Pattern | Test Exists? | Test Reference |
|---|---|---|
| `key in dict` | YES | `TestInOperator.test_key_in_dict_fires` |
| `key not in dict` | YES | `TestInOperator.test_not_in_fires` |
| `key in d.keys()` | YES | `TestInOperator.test_key_in_dict_keys_fires` |
| `hasattr(obj, name)` | YES | `TestHasattr` (2 variants) |
| `match/case MatchMapping` | YES | `TestMatchCase.test_match_mapping_fires` |
| `match/case MatchClass` | YES | `TestMatchCase.test_match_class_fires` |

**All positive patterns covered.**

---

## Negative Cases (Should NOT Fire)

### PY-WL-001

| Negative Case | Test Exists? | Test Reference |
|---|---|---|
| `.get(k)` with no default | YES | `TestGetWithoutDefault.test_get_without_default_silent` |
| `.get()` with zero args | YES | `TestGetWithoutDefault.test_get_no_args_silent` |
| Regular method calls (`.items()`) | YES | `TestNoFalsePositives.test_regular_method_call_silent` |
| Subscript access (`d["key"]`) | YES | `TestNoFalsePositives.test_dict_subscript_silent` |
| Regular function call (`print()`) | YES | `TestNoFalsePositives.test_regular_function_call_silent` |
| `.setdefault(key)` with 1 arg | YES | `TestSetdefault.test_setdefault_one_arg_silent` |
| `defaultdict()` with no args | YES | `TestDefaultdict.test_defaultdict_no_args_silent` |

**All critical negative patterns covered.**

### PY-WL-002

| Negative Case | Test Exists? | Test Reference |
|---|---|---|
| `getattr(obj, name)` 2-arg | YES | `TestNegative.test_getattr_2arg_silent` |
| `hasattr(obj, name)` | YES | `TestNegative.test_hasattr_silent` |
| `setattr(obj, name, value)` | YES | `TestNegative.test_setattr_silent` |
| No getattr at all | YES | `TestNegative.test_no_getattr_silent` |
| `obj.attr and "fallback"` | YES | `TestNegative.test_attribute_and_default_silent` |
| `obj.name() or "fallback"` (method call) | YES | `TestNegative.test_method_call_or_default_silent` |

**All critical negative patterns covered.**

### PY-WL-003

| Negative Case | Test Exists? | Test Reference |
|---|---|---|
| `getattr(obj, name, default)` | YES | `TestNoFalsePositives.test_getattr_with_default_silent` |
| Regular comparison (`==`) | YES | `TestNoFalsePositives.test_regular_comparison_silent` |
| No existence checks | YES | `TestNoFalsePositives.test_no_existence_checks_silent` |
| `match/case` MatchValue | YES | `TestNoFalsePositives.test_match_value_silent` |
| `match/case` MatchSequence | YES | `TestNoFalsePositives.test_match_sequence_silent` |
| `match/case` MatchStar | YES | `TestNoFalsePositives.test_match_star_silent` |
| `match/case` MatchOr | YES | `TestNoFalsePositives.test_match_or_silent` |
| `match/case` MatchAs/wildcard | YES | `TestNoFalsePositives.test_match_as_wildcard_silent` |
| Less-than comparison (`<`) | **UNTESTED** | No test for `x < y` |

**Negative coverage is strong. Minor gap: no explicit test for `<` or `>` comparisons, though `==` is covered and the implementation only matches `ast.In`/`ast.NotIn`.**

---

## schema_default() Test Coverage (PY-WL-001 only)

| Scenario | Expected Outcome | Tested? | Test Reference |
|---|---|---|---|
| Governed: boundary + optional field + matching default | SUPPRESS | YES | `TestSchemaDefaultGoverned.test_wrapped_get_with_boundary_and_optional_field_suppresses` |
| Governed: matching overlay scope | SUPPRESS | YES | `TestSchemaDefaultGoverned.test_matching_scope_suppresses` |
| Governed: class method with boundary | SUPPRESS | YES | `TestSchemaDefaultGoverned.test_class_method_with_boundary_suppresses` |
| Governed: most specific optional field scope wins | SUPPRESS | YES | `TestSchemaDefaultGoverned.test_most_specific_optional_field_scope_wins` |
| Governed: multiple boundaries, only match suppresses | SUPPRESS | YES | `TestSchemaDefaultGoverned.test_multiple_boundaries_only_match_suppresses` |
| Ungoverned: no boundary | ERROR/STANDARD | YES | `TestSchemaDefaultUngoverned.test_no_boundary_emits_error` |
| Ungoverned: wrong function name | ERROR | YES | `TestSchemaDefaultUngoverned.test_wrong_function_emits_error` |
| Ungoverned: wrong transition type | ERROR | YES | `TestSchemaDefaultUngoverned.test_wrong_transition_emits_error` |
| Ungoverned: wrong overlay scope | ERROR | YES | `TestSchemaDefaultUngoverned.test_wrong_scope_emits_error` |
| Ungoverned: empty overlay scope | ERROR | YES | `TestSchemaDefaultUngoverned.test_empty_scope_does_not_match` |
| Ungoverned: no context at all | ERROR | YES | `TestSchemaDefaultUngoverned.test_no_context_emits_error` |
| Ungoverned: case-sensitive qualname mismatch | ERROR | YES | `TestSchemaDefaultUngoverned.test_case_sensitive_qualname` |
| Ungoverned: missing optional field declaration | ERROR/STANDARD | YES | `TestSchemaDefaultUngoverned.test_missing_optional_field_declaration_emits_error` |
| Ungoverned: mismatched approved default | ERROR/UNCONDITIONAL | YES | `TestSchemaDefaultUngoverned.test_mismatched_approved_default_is_unconditional` |
| Regular .get() unchanged by boundaries | ERROR (PY-WL-001) | YES | `TestSchemaDefaultUngoverned.test_non_schema_default_unchanged` |

**schema_default() coverage is thorough. All specified scenarios are tested with correct severity and exceptionability assertions.**

---

## Boundary Conditions

| Condition | PY-WL-001 | PY-WL-002 | PY-WL-003 |
|---|---|---|---|
| Async functions | **UNTESTED** | YES (`TestAsyncFunction`) | YES (`TestMultipleAndAsync.test_in_async_function`) |
| Nested functions | **UNTESTED** | **UNTESTED** | **UNTESTED** |
| Class methods | YES (schema_default class method test) | **UNTESTED** | **UNTESTED** |
| Empty function bodies | **UNTESTED** | **UNTESTED** | **UNTESTED** |
| Multiple findings in same function | YES (`TestMultiplePatterns`) | YES (`TestMultipleGetattr`) | YES (`TestMultipleAndAsync.test_multiple_patterns_in_same_function`) |
| Lambda bodies | YES (`TestLambdaGet`) | **UNTESTED** | **UNTESTED** |

**Gaps:** Async function support is untested for PY-WL-001. Nested function handling is untested for all three rules. Empty function body is untested for all three rules.

---

## Corpus Alignment

Per section 10 of the spec, the golden corpus requires:
- **Minimum:** 1 positive + 1 negative specimen per severity matrix cell
- **Adversarial:** at least 1 adversarial false-positive and 1 adversarial false-negative per rule

### Current State vs Required

**PY-WL-001 (8 cells):**
- Required: 16 specimens minimum (8 positive + 8 negative)
- Cell-specific tests with taint injection: **0**
- Pattern-level positive tests (no taint parameterization): 8
- Negative tests: 7
- Adversarial specimens: 1 (lambda .get() could be considered adversarial, but not labelled as such)
- **Gap: 16 cell-specific specimens needed, 0 present. No taint-parameterized tests exist.**

**PY-WL-002 (8 cells):**
- Required: 16 specimens minimum
- Cell-specific tests with taint injection: **0**
- Pattern-level positive tests: 5
- Negative tests: 6
- Adversarial specimens: 0
- **Gap: 16 cell-specific specimens needed, 0 present.**

**PY-WL-003 (8 cells):**
- Required: 16 specimens minimum
- Cell-specific tests with taint injection: **0** (boundary tests use EXTERNAL_RAW but test suppression, not cell severity)
- Pattern-level positive tests: 8
- Negative tests: 8
- Adversarial specimens: 0
- **Gap: 16 cell-specific specimens needed, 0 present. PY-WL-003 has a non-trivial exceptionability split (4 U, 4 St) that is completely unverified.**

### Distance from Spec Standard

The spec requires 126+ specimens across the full 8-rule matrix. For Group A alone (3 rules, 24 cells), the minimum is 48 cell-specific specimens. Current count: **0 cell-specific specimens**. The existing tests verify pattern detection and schema_default governance logic but do not parameterize across taint states and do not assert the severity matrix cell values (severity + exceptionability) for each taint state.

The existing tests are functional smoke tests for pattern matching, not corpus-aligned verification tests. The two testing concerns are distinct:
1. **Pattern detection** (does the AST visitor find the right nodes?) -- well covered
2. **Severity matrix cell correctness** (does each taint state produce the right severity + exceptionability?) -- not covered

---

## Verdict: CONCERN

### Evidence

**Strengths:**
- Pattern detection coverage is complete for all three rules (positive and negative)
- schema_default() governance logic is thoroughly tested with 15 scenarios
- Negative cases are well-covered, including adversarial-adjacent cases (e.g., `.get()` on non-dict, `setattr`, MatchSequence/MatchStar/MatchOr)
- Multiple-finding-per-function cases are tested for all three rules

**Critical Gaps:**
1. **Zero severity matrix cell coverage.** No test for any rule injects a specific taint state and asserts the resulting (severity, exceptionability) pair. This means the severity matrix is entirely untested at the rule level. The AUDIT_TRAIL cell (E/U) for PY-WL-001 and PY-WL-002 has a different exceptionability than the other 7 cells, and this distinction is never verified. PY-WL-003's 4-way U/St split is never verified.

2. **No exceptionability assertions on base findings.** Outside of schema_default() tests, no test asserts `finding.exceptionability`. The distinction between UNCONDITIONAL and STANDARD is the most governance-critical property in the matrix, and it is unverified for base PY-WL-001, all of PY-WL-002, and all of PY-WL-003.

3. **Async function gap for PY-WL-001.** PY-WL-002 and PY-WL-003 test async functions; PY-WL-001 does not.

4. **Nested function gap for all rules.** `walk_skip_nested_defs` is a critical implementation detail (it prevents double-counting in nested functions). No test for any of the three rules verifies that nested function bodies are handled correctly.

5. **No formal corpus specimens.** The spec requires YAML-format corpus specimens organized by `corpus/{rule}/{taint_state}/`. No such structure exists. The current tests are pytest unit tests, not corpus specimens. The gap between current state and spec-compliant corpus is structural, not incremental.

**Recommendation:** The pattern detection layer is solid and the schema_default governance logic is well-tested. The primary remediation is adding taint-state-parameterized tests (a `@pytest.mark.parametrize` over all 8 taint states asserting both severity and exceptionability per cell) for each rule. This would close the most critical gap with approximately 24 new test cases (8 per rule). Async and nested function boundary tests are secondary but should be addressed.
