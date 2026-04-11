# Audit Remediation Phase 1: Correctness & Test Foundation

**Date:** 2026-03-25
**Status:** Design
**Source:** `docs/audits/2026-03-25-rule-conformance/synthesis.md`
**Scope:** CF-1, CF-2, HC-1, HC-5, HC-10 from audit synthesis

---

## Context

The 35-agent conformance audit found 4 critical findings, 12 high-priority concerns, and 22 tracked debt items. This is Phase 1 of a 3-phase remediation, addressing the correctness bug and test foundation that all subsequent work depends on.

**Dependency rationale:** CF-1 changes the taint state that rules see inside validator bodies, which affects what findings fire and at what severity. Matrix cell tests (HC-1) must be written against the corrected taint behavior, not the current buggy behavior. SCN-021 (CF-2) is the foundation rule other rules depend on — its test coverage must be solid before we build on it.

---

## Items

### 1. CF-1: Fix body evaluation taint map

**Audit source:** F2-Validation Boundary (FAIL), F1-Tier Consistency (independent confirmation)
**File:** `src/wardline/scanner/taint/function_level.py`
**Spec:** Part II-A §A.4.3 body evaluation context table

**Problem:** `DECORATOR_TAINT_MAP` (lines 41-49) conflates two distinct concerns:
- What taint state should rules evaluate at inside the function body (input tier)
- What taint state should the return value carry for propagation (output tier)

Currently `@validates_shape` body evaluates at GUARDED (output). Per spec, it should evaluate at EXTERNAL_RAW (input). `@validates_external` similarly evaluates at ASSURED (output) instead of EXTERNAL_RAW (input). This produces systematic false negatives for pattern rules inside validator bodies.

**Fix:** Split the existing 7-entry `DECORATOR_TAINT_MAP` into two maps in `function_level.py`:

**BODY_EVAL_TAINT** — used by the engine when assigning taint context for rule severity lookup:

| Decorator | Current Taint | Corrected Body Taint | Change |
|-----------|--------------|---------------------|--------|
| `validates_shape` | GUARDED | **EXTERNAL_RAW** | Bug fix |
| `validates_external` | ASSURED | **EXTERNAL_RAW** | Bug fix |
| `validates_semantic` | ASSURED | **GUARDED** | Bug fix |
| `integral_read` | INTEGRAL | INTEGRAL | No change |
| `integral_writer` | INTEGRAL | INTEGRAL | No change |
| `integral_construction` | INTEGRAL | INTEGRAL | No change |
| `external_boundary` | EXTERNAL_RAW | EXTERNAL_RAW | No change |

**RETURN_TAINT** — used by the taint propagation engine when computing callee return taints:

| Decorator | Return Value Taint |
|-----------|-------------------|
| `validates_shape` | GUARDED |
| `validates_external` | ASSURED |
| `validates_semantic` | ASSURED |
| `integral_read` | INTEGRAL |
| `integral_writer` | INTEGRAL |
| `integral_construction` | INTEGRAL |
| `external_boundary` | EXTERNAL_RAW |

Both maps contain exactly the 7 decorators currently in `DECORATOR_TAINT_MAP`. No new decorators are added in this phase — `int_data`, `system_plugin`, and `fail_closed` are out of scope (they aren't in the current map and adding them is a behavioral expansion, not a bug fix).

**Implementation detail — `taint_from_annotations`:** The current function (`taint_from_annotations`) iterates decorator names and returns the first match from `DECORATOR_TAINT_MAP`. After the split, it needs to accept a parameter or return both body and return taints. The simplest approach: rename `taint_from_annotations` to return a `(body_taint, return_taint)` tuple, or add a `purpose: Literal["body", "return"]` parameter. The call sites in `assign_function_taints` and the L2/L3 propagation code each use the appropriate map.

**Expected test impact:** The following test files are likely to need updates because they contain tests with code inside `@validates_shape`, `@validates_semantic`, or `@validates_external` bodies:
- `tests/unit/scanner/test_py_wl_003.py` — boundary suppression tests (existence checks inside validators will now evaluate at EXTERNAL_RAW instead of GUARDED/ASSURED, changing the severity lookup)
- `tests/unit/scanner/test_py_wl_007.py` — declared boundary suppression tests
- `tests/unit/scanner/test_py_wl_008.py` — boundary rejection path tests (taint context changes)
- `tests/unit/scanner/test_py_wl_009.py` — validation ordering tests
- `tests/integration/test_scan_cmd.py` — integration tests that scan files with validation boundaries

The direction of change: tests asserting findings inside validator bodies at GUARDED or ASSURED severity will need to assert EXTERNAL_RAW or GUARDED severity instead (one tier lower in each case). Tests asserting return value taint should be unchanged.

**Consequences for per-rule suppressions:** After the fix, PY-WL-003's `_is_structural_validation_boundary` suppression and PY-WL-007's declared-boundary suppression may become partially redundant — with correct body taint, existence checking inside `@validates_shape` evaluates at EXTERNAL_RAW where PY-WL-003 is already E/St (governable), not E/U. Review whether these suppressions should be simplified or retained as defence-in-depth. Do not remove them in this phase — assess after matrix cell tests confirm the new behavior is correct.

**Verification:** After the fix, add tests that:
- `@validates_shape` body evaluates at EXTERNAL_RAW
- `@validates_semantic` body evaluates at GUARDED
- `@validates_external` body evaluates at EXTERNAL_RAW
- Return values carry the correct output taint for propagation (GUARDED, ASSURED, ASSURED respectively)

### 2. CF-2: SCN-021 test coverage to all combinations

**Audit source:** D-Quality Engineer (FAIL), corroborated by D-SA, D-PE, D-SAS, D-SecA

**Problem:** 4 of 29 combinations tested (14%). Zero exceptionability assertions. Only 1 negative test. Foundation rule with thinnest coverage in the codebase.

**Fix:**
1. Add parametrized positive test iterating all entries in `_COMBINATIONS`. For each entry, construct a function with both decorators, run the rule, assert:
   - Finding fires (count >= 1)
   - Correct severity: ERROR for contradictory, WARNING for suspicious
   - Correct exceptionability: UNCONDITIONAL for all
   - Correct rule_id: SCN_021

2. Add at least 5 negative test cases for valid decorator combinations that must NOT fire. Examples: `@fail_closed + @deterministic`, `@atomic + @fail_closed`, `@handles_pii + @integral_read`, `@thread_safe + @atomic`, `@test_only + @deprecated_by`.

3. Add test for alias pair behavior — verify that after HC-5 dedup fix, each semantic contradiction produces exactly 1 finding.

### 3. HC-5: Remove SCN-021 duplicate entry #19

**Audit source:** D-SA, D-PE, D-SAS, D-SecA (4 independent agents)
**File:** `src/wardline/scanner/rules/scn_021.py`

**Problem:** Entry #5 (`fail_open + integrity_critical`) and entry #19 (`integrity_critical + fail_open`) are the same decorator pair reversed. The matching at line ~132 checks `spec.left in names and spec.right in names` — since both left and right are checked independently against the decorator name set, order is irrelevant and both entries fire, producing 2 findings for 1 violation.

**Fix:** Remove entry #19 from `_COMBINATIONS`. Add a comment: `# Spec entry #19 (integrity_critical + fail_open) is an alias of #5 — removed to prevent duplicate findings.`

**Verification:** Confirm no other true duplicates exist. Entry #23 (`preserve_cause + exception_boundary`) appears to alias #12 (`exception_boundary + must_propagate`) per the spec's note, but these are NOT the same pair — they involve different decorator names (`preserve_cause` vs `must_propagate`) and both should remain.

### 4. HC-1: Parametrized matrix cell tests

**Audit source:** A-QE, B-QE, C-QE, D-QE (unanimous across all 4 Quality Engineers)

**Problem:** Zero tests inject a taint state and verify the resulting (severity, exceptionability). The governance-critical UNCONDITIONAL/STANDARD distinction is unverified.

**Fix:** Create a shared test module `tests/unit/scanner/test_matrix_cells.py` containing parametrized tests for each rule.

**Taint injection mechanism:** The test should pass the taint state at `ScanContext` construction time via `function_level_taint_map`. `ScanContext` is a frozen dataclass and `function_level_taint_map` is wrapped in `MappingProxyType` by `__post_init__` — it cannot be mutated after construction. Pattern:
```python
def _run_rule_with_taint(rule_cls, code: str, taint_state: TaintState, func_name: str = "target"):
    """Run a rule against code with a specific taint state injected."""
    ctx = ScanContext(
        file_path="test.py",
        function_level_taint_map={func_name: taint_state},
    )
    rule = rule_cls(context=ctx)
    tree = ast.parse(code)
    rule.visit(tree)
    return rule.findings
```

For each rule, the test data is the spec's severity matrix row. This produces:
- PY-WL-001: 8 tests (1 E/U + 7 E/St)
- PY-WL-002: 8 tests (1 E/U + 7 E/St)
- PY-WL-003: 8 tests (5 E/U + 3 E/St)
- PY-WL-004: 8 tests (1 E/U + 3 W/St + 1 W/R + 3 E/St — most diverse row)
- PY-WL-005: 8 tests (1 E/U + 7 E/St)
- PY-WL-006: 8 tests (2 E/U + 6 E/St)
- PY-WL-007: 8 tests (1 E/St + 4 W/R + 2 Su/T + 1 W/St)
- PY-WL-008: 8 tests (8 E/U — uniform)
- PY-WL-009: 8 tests (8 E/U — uniform)

**Total: 72 parametrized test cases.**

For SUPPRESS cells (PY-WL-007 EXTERNAL_RAW and UNKNOWN_RAW), the test verifies the finding is emitted at SUPPRESS severity with TRANSPARENT exceptionability. SUPPRESS-severity findings are still emitted in SARIF at "note" level — this is the matrix severity behavior, distinct from the exception register's suppression mechanism.

**Dependency on CF-1:** These tests must be written after the body evaluation taint fix. However, since the taint injection mechanism sets taint directly on `ScanContext.function_level_taint_map` (bypassing decorator-to-taint resolution), most tests are actually independent of CF-1 — they test the matrix lookup, not the taint assignment. The exception is rules that fire inside validation boundary bodies where the taint affects which code snippet triggers the rule. For those rules, write the snippets to trigger in a non-boundary context so the injected taint is the only factor.

### 5. HC-10: PY-WL-006 TryStar deduplication

**Audit source:** B-Python Engineer
**File:** `src/wardline/scanner/rules/py_wl_006.py`

**Problem:** PY-WL-004 and PY-WL-005 both track TryStar handler IDs to prevent duplicate findings on Python 3.11+ `except*` handlers. PY-WL-006 does not.

**Reference pattern:** PY-WL-004 at lines 43-59 does two passes:
1. First pass: collect TryStar handler IDs AND process those handlers immediately
2. Second pass: process non-TryStar ExceptHandler nodes, skipping those in the TryStar set

PY-WL-006's `visit_function` (lines 210-227) currently does a single pass over ExceptHandler nodes. The adaptation requires restructuring to a two-pass approach matching PY-WL-004's pattern. Study PY-WL-004's actual implementation directly — the pattern involves `getattr(ast, "TryStar", None)` for backwards compatibility and `id(handler)` for the exclusion set.

Add a test with an `except*` handler containing an audit call to verify exactly 1 finding is produced (not 2 from double-counting).

---

## Execution Order

```
1. CF-1  — Fix taint map (changes rule behavior, updates affected tests)
2. HC-5  — Remove SCN-021 duplicate #19 (trivial, unblocks CF-2)
3. CF-2  — SCN-021 full test coverage (depends on HC-5 for correct finding count)
4. HC-10 — PY-WL-006 TryStar dedup (independent of 1-3)
5. HC-1  — Matrix cell tests (write after CF-1 to use correct taint behavior)
```

**Parallelization:** Steps 2+3 (sequential) can run in parallel with step 4. Step 5 depends on step 1 being complete. Step 1 must be first.

---

## Success Criteria

- `@validates_shape` body evaluates at EXTERNAL_RAW, not GUARDED
- `@validates_semantic` body evaluates at GUARDED, not ASSURED
- `@validates_external` body evaluates at EXTERNAL_RAW, not ASSURED
- Return value taints are unchanged (GUARDED, ASSURED, ASSURED)
- SCN-021 has tests for all 28 combinations (after #19 removal) + 5+ negative cases
- SCN-021 tests assert exceptionability (UNCONDITIONAL) on every finding
- Every severity matrix cell (72 total) has a test asserting correct (severity, exceptionability)
- PY-WL-006 produces exactly 1 finding for audit calls in `except*` handlers
- All existing tests pass (updated for corrected taint — see expected test impact in CF-1)
- `uv run pytest` green, `uv run ruff check` clean, `uv run mypy` clean
