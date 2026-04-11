# Quality Engineer Audit: SCN-021 Test Coverage

**Rule:** SCN-021 -- Contradictory and suspicious decorator-combination detection
**Spec:** wardline-02-A-python-binding.md, Section A.4.3 (29 combinations)
**Test file:** `tests/unit/scanner/test_scn_021.py`
**Implementation:** `src/wardline/scanner/rules/scn_021.py`
**Date:** 2026-03-25

---

## 1. Combination Coverage (29 spec combinations)

The implementation defines all 29 combinations in `_COMBINATIONS`. The test file exercises only **4 of 29**:

| # | Combination | Status |
|---|-------------|--------|
| 1 | `@fail_open` + `@fail_closed` | TESTED (test_fail_open_and_fail_closed_fire) |
| 2 | `@fail_open` + `@tier1_read` | UNTESTED |
| 3 | `@fail_open` + `@audit_writer` | UNTESTED |
| 4 | `@fail_open` + `@authoritative_construction` | UNTESTED |
| 5 | `@fail_open` + `@audit_critical` | UNTESTED |
| 6 | `@external_boundary` + `@int_data` | UNTESTED |
| 7 | `@external_boundary` + `@tier1_read` | UNTESTED |
| 8 | `@external_boundary` + `@authoritative_construction` | UNTESTED |
| 9 | `@validates_shape` + `@validates_semantic` | UNTESTED |
| 10 | `@validates_shape` + `@tier1_read` | UNTESTED |
| 11 | `@validates_semantic` + `@external_boundary` | UNTESTED |
| 12 | `@exception_boundary` + `@must_propagate` | TESTED (test_exception_boundary_and_must_propagate_fire) |
| 13 | `@idempotent` + `@compensatable` | UNTESTED |
| 14 | `@deterministic` + `@time_dependent` | UNTESTED |
| 15 | `@deterministic` + `@external_boundary` | UNTESTED |
| 16 | `@tier1_read` + `@restoration_boundary` | UNTESTED |
| 17 | `@audit_writer` + `@restoration_boundary` | UNTESTED |
| 18 | `@fail_closed` + `@emits_or_explains` | UNTESTED |
| 19 | `@audit_critical` + `@fail_open` | UNTESTED |
| 20 | `@validates_external` + `@validates_shape` | UNTESTED |
| 21 | `@validates_external` + `@validates_semantic` | UNTESTED |
| 22 | `@int_data` + `@validates_shape` | UNTESTED |
| 23 | `@preserve_cause` + `@exception_boundary` | TESTED (test_preserve_cause_and_exception_boundary_fire) |
| 24 | `@compensatable` + `@audit_writer` | UNTESTED |
| 25 | `@data_flow(produces=...)` + `@external_boundary` | UNTESTED |
| 26 | `@system_plugin` + `@tier1_read` | UNTESTED |
| 27 | `@fail_open` + `@deterministic` | TESTED (test_fail_open_and_deterministic_warn) |
| 28 | `@compensatable` + `@deterministic` | UNTESTED |
| 29 | `@time_dependent` + `@idempotent` | UNTESTED |

**Coverage: 4/29 (13.8%).** Spec requires minimum 3 TP + 2 TN per rule for smoke test; only 4 TP and 1 TN exist.

---

## 2. Severity Verification

- **Contradictory -> ERROR:** Verified for #1, #12, #23 (3 of 26 contradictory combinations).
- **Suspicious -> WARNING:** Verified for #27 (1 of 3 suspicious combinations).
- **Gap:** 23 contradictory and 2 suspicious combinations have no severity assertion.

---

## 3. Exceptionability Verification

The implementation hard-codes `Exceptionability.UNCONDITIONAL` in `_emit_finding`. **No test asserts** `finding.exceptionability == Exceptionability.UNCONDITIONAL`. This is a conformance-critical gap -- the spec mandates UNCONDITIONAL for all SCN-021 findings and tests must verify it.

---

## 4. Negative Cases

- **1 negative test:** `test_single_decorator_is_silent` -- confirms single decorator does not fire.
- **Missing negative tests:**
  - Two non-conflicting wardline decorators together (e.g., `@fail_closed` + `@deterministic`).
  - Non-wardline decorators mixed with wardline decorators.
  - Functions with zero decorators.
  - Valid multi-decorator stacks (3+ wardline decorators, none conflicting).

**Negative case count: 1.** Minimum smoke-test requirement is 2 TN per rule.

---

## 5. Alias Pairs (#5/#19 and #12/#23)

Spec explicitly calls out #5/#19 (`@fail_open` + `@audit_critical` vs `@audit_critical` + `@fail_open`) and #12/#23 (`@exception_boundary` + `@must_propagate` vs `@preserve_cause` + `@exception_boundary`) as alias pairs that must fire regardless of decorator ordering.

- **#12 tested, #23 tested** -- but only in one ordering each. No test verifies reversed ordering.
- **#5 untested, #19 untested** -- neither direction tested.
- **Alias annotation context test exists** (`test_context_annotations_drive_detection_for_alias_imports`) but tests import aliasing, not spec alias pairs.

**Gap:** No test verifies that the same semantic conflict fires in both decorator orderings.

Note: The implementation uses set membership (`spec.left in names and spec.right in names`) which is inherently order-independent, so the logic is correct. However, the spec explicitly requires both orderings to be caught, and tests should verify this property rather than relying on implementation knowledge.

---

## 6. Parameterized Decorators

Combination #25 (`@data_flow(produces=...)` + `@external_boundary`) involves a parameterized decorator. The implementation resolves parameterized decorators via `ast.Call` unwrapping in `_decorator_name`. **No test exercises this path.** The `_decorator_name` function handles `ast.Call` -> `func` extraction, but this code path has zero test coverage for SCN-021.

---

## 7. Forward References (Not-Yet-Implemented Decorators)

Combinations #16 and #17 involve `@restoration_boundary`, which the spec notes as a forward reference. The implementation includes these in the `_COMBINATIONS` tuple. The annotation-context test (`test_context_annotations_drive_detection_for_alias_imports`) demonstrates that annotations can inject arbitrary canonical names, which would cover forward references.

**However:** No test explicitly exercises #16 or #17 via annotation injection. The mechanism exists but is not verified for the specific forward-reference combinations.

---

## 8. Edge Cases

| Edge Case | Tested? |
|-----------|---------|
| `async def` functions | NOT TESTED -- `visit_function` accepts `AsyncFunctionDef` but no test uses `async def` |
| Class methods (`def method(self)`) | NOT TESTED |
| Decorator stacks with >2 wardline decorators | NOT TESTED -- e.g., 3 decorators where 2 separate pairs conflict should produce 2 findings |
| Multiple simultaneous conflicts on same function | NOT TESTED |
| Decorators via `module.decorator` attribute access | NOT TESTED -- `_decorator_name` handles `ast.Attribute` but no test covers it |
| Empty decorator list | NOT TESTED explicitly (covered implicitly by early return `len(names) < 2`) |
| Nested function definitions | NOT TESTED -- inner function with conflicting decorators should fire independently |

---

## 9. Corpus Alignment (Section 10 Requirements)

Section 10 requires:
- **Minimum 3 TP + 2 TN per rule** for smoke test: Current state is 4 TP + 1 TN. **Below minimum.**
- **Adversarial specimens:** 0 adversarial false-positive, 0 adversarial false-negative. **Below minimum** (1 per category required).
- **SARIF output verification:** No test verifies SARIF rendering of SCN-021 findings.
- **Exceptionability field in findings:** Not asserted.
- **Per-cell precision/recall measurement:** Not applicable at unit test level but the sparse coverage makes corpus-level measurement impossible.

The golden corpus format (YAML specimens under `corpus/`) does not appear to exist yet for SCN-021. No `corpus/SCN-021/` directory was found.

---

## Summary of Gaps

| Category | Finding | Severity |
|----------|---------|----------|
| Combination coverage | 25/29 combinations untested | Critical |
| Severity assertions | 25/29 combinations lack severity verification | Critical |
| Exceptionability | Zero assertions on UNCONDITIONAL | Critical |
| Negative cases | Only 1 TN, need minimum 2 | High |
| Alias pair ordering | Neither alias pair tested in both orderings | Medium |
| Parameterized decorators (#25) | Zero coverage | High |
| Forward references (#16, #17) | Zero coverage via annotation injection | Medium |
| Async functions | Zero coverage | Medium |
| Multi-conflict stacks | Zero coverage | Medium |
| Class methods | Zero coverage | Low |
| SARIF output | Zero coverage | Medium |

---

## Verdict: FAIL

**Evidence:** The test suite covers 4 of 29 spec-mandated combinations (13.8%), fails to assert exceptionability on any finding, has only 1 negative test (below the 2 TN minimum), and provides zero coverage for parameterized decorators, async functions, multi-conflict stacks, and SARIF output. The current test file is a skeleton that verifies the rule's basic wiring but falls far short of the combination-completeness, severity-verification, and corpus-alignment requirements specified in Section A.4.3 and Section 10.

To reach PASS, the test suite needs at minimum:
1. One dedicated test per combination (29 tests) asserting rule_id, severity, and exceptionability.
2. At least 2 true-negative tests for valid decorator combinations.
3. Tests for parameterized decorator resolution (combination #25).
4. Tests for annotation-injected forward references (#16, #17).
5. At least one async function test and one multi-conflict stack test.
6. Exceptionability assertions (`== Exceptionability.UNCONDITIONAL`) on all positive findings.
