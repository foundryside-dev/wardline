# Group B -- Quality Engineer Assessment

**Date:** 2026-03-25
**Rules:** PY-WL-004, PY-WL-005, PY-WL-006
**Test files:** `tests/unit/scanner/test_py_wl_004.py`, `tests/unit/scanner/test_py_wl_005.py`, `tests/unit/scanner/test_py_wl_006.py`

---

## 1. Severity Matrix Cell Coverage

The severity matrix defines 8 taint states per rule. A test "exercises a cell" only if it injects a specific taint state via `ScanContext.function_level_taint_map` and asserts the resulting severity AND exceptionability.

**No test in any of the three files imports `ScanContext`, `TaintState`, or `Exceptionability`.** All tests call `_run_rule()` or `_run_rule_module()` without setting a context, so `_get_function_taint()` returns `UNKNOWN_RAW` by default for every test.

### PY-WL-004 -- Expected: E/U, E/St, W/St, W/R, E/St, W/St, W/St, E/St

| Taint State | Expected | Tested? | Notes |
|---|---|---|---|
| AUDIT_TRAIL | E/U | UNTESTED | No test sets this taint state |
| PIPELINE | E/St | UNTESTED | No test sets this taint state |
| SHAPE_VALIDATED | W/St | UNTESTED | No test sets this taint state |
| EXTERNAL_RAW | W/R | UNTESTED | No test sets this taint state |
| UNKNOWN_RAW | E/St | **IMPLICIT** | Default taint; `test_bare_except_fires` asserts `severity == ERROR` but not exceptionability |
| UNKNOWN_SHAPE_VALIDATED | W/St | UNTESTED | No test sets this taint state |
| UNKNOWN_SEM_VALIDATED | W/St | UNTESTED | No test sets this taint state |
| MIXED_RAW | E/St | UNTESTED | No test sets this taint state |

**Summary:** 0 of 8 cells explicitly tested. PY-WL-004 has the most heterogeneous matrix in Group B: 3 cells are E (ERROR), 4 are W (WARNING), and 1 is W/R (RELAXED). This 3-way severity split and the unique RELAXED exceptionability in EXTERNAL_RAW are entirely unverified. The AUDIT_TRAIL cell (E/U) has distinct exceptionability from all other cells and is never tested.

### PY-WL-005 -- Expected: E/U, E/St, E/St, E/St, E/St, E/St, E/St, E/St

| Taint State | Expected | Tested? | Notes |
|---|---|---|---|
| AUDIT_TRAIL | E/U | UNTESTED | No test sets this taint state |
| PIPELINE | E/St | UNTESTED | No test sets this taint state |
| SHAPE_VALIDATED | E/St | UNTESTED | No test sets this taint state |
| EXTERNAL_RAW | E/St | UNTESTED | No test sets this taint state |
| UNKNOWN_RAW | E/St | **IMPLICIT** | Default taint; `test_bare_except_pass` asserts `severity == ERROR` but not exceptionability |
| UNKNOWN_SHAPE_VALIDATED | E/St | UNTESTED | No test sets this taint state |
| UNKNOWN_SEM_VALIDATED | E/St | UNTESTED | No test sets this taint state |
| MIXED_RAW | E/St | UNTESTED | No test sets this taint state |

**Summary:** 0 of 8 cells explicitly tested. PY-WL-005 has a uniform matrix (all E/St except AUDIT_TRAIL at E/U). The AUDIT_TRAIL U vs St distinction is the only variation and it is never verified.

### PY-WL-006 -- Expected: E/U, E/U, E/St, E/St, E/St, E/St, E/St, E/St

| Taint State | Expected | Tested? | Notes |
|---|---|---|---|
| AUDIT_TRAIL | E/U | UNTESTED | No test sets this taint state |
| PIPELINE | E/U | UNTESTED | No test sets this taint state |
| SHAPE_VALIDATED | E/St | UNTESTED | No test sets this taint state |
| EXTERNAL_RAW | E/St | UNTESTED | No test sets this taint state |
| UNKNOWN_RAW | E/St | **IMPLICIT** | Default taint; `test_audit_emit_fires` asserts `severity == ERROR` but not exceptionability |
| UNKNOWN_SHAPE_VALIDATED | E/St | UNTESTED | No test sets this taint state |
| UNKNOWN_SEM_VALIDATED | E/St | UNTESTED | No test sets this taint state |
| MIXED_RAW | E/St | UNTESTED | No test sets this taint state |

**Summary:** 0 of 8 cells explicitly tested. PY-WL-006 has 2 UNCONDITIONAL cells (AUDIT_TRAIL, PIPELINE) and 6 STANDARD cells. The U/St boundary is never verified.

---

## 2. Pattern Coverage (Positive Cases)

### PY-WL-004

| Pattern | Test Exists? | Test Reference |
|---|---|---|
| Bare `except:` | YES | `TestBareExcept.test_bare_except_fires` |
| `except Exception:` | YES | `TestExceptException.test_except_exception_fires` |
| `except Exception as e:` | YES | `TestExceptException.test_except_exception_as_e_fires` |
| `except BaseException:` | YES | `TestExceptBaseException.test_except_base_exception_fires` |
| Tuple with broad member `except (Exception, ValueError):` | YES | `TestSpecificExceptions.test_except_tuple_with_broad_member_fires` |
| `except* Exception:` (TryStar, 3.11+) | YES | `TestTryStar.test_except_star_exception_fires` |
| `contextlib.suppress(Exception)` | YES | `TestContextlibSuppress.test_contextlib_suppress_exception_fires` |
| Imported `suppress(BaseException)` | YES | `TestContextlibSuppress.test_imported_suppress_baseexception_fires` |
| Qualified `builtins.Exception` | **UNTESTED** | Implementation supports `ast.Attribute` resolution in `_resolve_broad_name()` but no test covers it |
| Multiple broad handlers in same function | YES | `TestMultipleBroadHandlers.test_multiple_broad_handlers` |

**Gap:** No test for qualified `builtins.Exception` or `builtins.BaseException` despite the implementation explicitly handling `ast.Attribute` nodes in `_resolve_broad_name()`.

### PY-WL-005

| Pattern | Test Exists? | Test Reference |
|---|---|---|
| `except: pass` | YES | `TestPassBody.test_bare_except_pass` |
| `except Exception: pass` | YES | `TestPassBody.test_typed_except_pass` |
| `except ValueError: pass` (specific) | YES | `TestPassBody.test_specific_exception_pass` |
| `except: ...` (Ellipsis) | YES | `TestEllipsisBody.test_bare_except_ellipsis` |
| `except: continue` | YES | `TestContinueBody.test_except_continue` |
| `except: break` | YES | `TestBreakBody.test_except_break` |
| `except* Exception: pass` (3.11+) | YES | `TestTryStar.test_except_star_pass` |
| Multiple silent handlers | YES | `TestMultipleHandlers.test_two_silent_handlers` |

**All documented silent-body patterns are covered.**

### PY-WL-006

| Pattern | Test Exists? | Test Reference |
|---|---|---|
| `audit.emit()` in broad handler | YES | `TestAuditShapedSinks.test_audit_emit_fires` |
| `db.record_failure()` in broad handler | YES | `TestAuditShapedSinks.test_db_record_failure_fires` |
| `audit_ledger.emit_event()` in broad handler | YES | `TestAuditShapedSinks.test_ledger_emit_event_fires` |
| `@audit_writer` decorated local call in broad handler | YES | `TestDecoratedAuditTargets.test_local_audit_writer_call_fires` |
| `@audit_critical` decorated local call in broad handler | YES | `TestDecoratedAuditTargets.test_local_audit_critical_call_fires` |
| Dominance bypass: success branch without audit | YES | `TestAuditPathDominance.test_success_branch_without_audit_fires` |
| Dominance bypass: broad handler fallback | YES | `TestAuditPathDominance.test_broad_handler_fallback_success_without_audit_fires` |
| Dominance bypass: local audit writer | YES | `TestAuditPathDominance.test_local_audit_writer_must_dominate_success_paths` |

**Positive pattern coverage is thorough for PY-WL-006, including both the broad-handler masking and dominance analysis sub-rules.**

---

## 3. Negative Cases (Should NOT Fire)

### PY-WL-004

| Negative Case | Test Exists? | Test Reference |
|---|---|---|
| `except ValueError:` (specific) | YES | `TestSpecificExceptions.test_except_value_error_silent` |
| `except (TypeError, ValueError):` (specific tuple) | YES | `TestSpecificExceptions.test_except_tuple_specific_silent` |
| `except KeyError as e:` | YES | `TestSpecificExceptions.test_except_key_error_as_e_silent` |
| No try/except at all | YES | `TestSpecificExceptions.test_no_try_except_silent` |
| Re-raise: `except Exception: raise` | YES | `TestSpecificExceptions.test_except_exception_reraise_silent` |
| Re-raise: `except Exception as e: raise e` | YES | `TestSpecificExceptions.test_except_exception_as_e_raise_e_silent` |
| `contextlib.suppress(ValueError)` | YES | `TestContextlibSuppress.test_suppress_value_error_silent` |

**All critical negative patterns covered.**

### PY-WL-005

| Negative Case | Test Exists? | Test Reference |
|---|---|---|
| Logging call in handler | YES | `TestNegativeMeaningfulBody.test_logging_call_silent` |
| Re-raise in handler | YES | `TestNegativeMeaningfulBody.test_reraise_silent` |
| Assignment in handler | YES | `TestNegativeMeaningfulBody.test_assignment_silent` |
| Print call in handler | YES | `TestNegativeMeaningfulBody.test_print_call_silent` |
| Multi-statement body (pass + logging) | YES | `TestNegativeMeaningfulBody.test_pass_with_extra_statement_silent` |
| No try/except at all | YES | `TestNoTryExcept.test_no_try_except` |
| `except: raise` (single re-raise) | **UNTESTED as non-silent** | The test `test_reraise_silent` covers this but note: re-raise detection is handled by PY-WL-005's body-length check (len == 1 + `raise` is not pass/ellipsis/continue/break), not by explicit re-raise logic |

**Negative coverage is solid. The multi-statement body test (pass + logging.info = 2 statements = not silent) is a particularly good adversarial-adjacent case.**

### PY-WL-006

| Negative Case | Test Exists? | Test Reference |
|---|---|---|
| Audit call in specific handler (`except ValueError`) | YES | `TestSpecificHandlersNoFire.test_audit_call_in_specific_handler_silent` |
| `logger.error()` in broad handler | YES | `TestNonAuditTelemetryNoFire.test_logger_error_silent` |
| `print()` in broad handler | YES | `TestNonAuditTelemetryNoFire.test_print_silent` |
| `cleanup()` in broad handler | YES | `TestNonAuditTelemetryNoFire.test_cleanup_call_silent` |
| Dominance: rejection path (raise) without audit | YES | `TestAuditPathDominance.test_rejection_path_without_audit_is_allowed` |
| Dominance: fallback raise without audit | YES | `TestAuditPathDominance.test_fallback_raise_without_audit_is_allowed` |

**Negative coverage is good for PY-WL-006 including both sub-rules (masking and dominance).**

---

## 4. PY-WL-006-Specific Analysis

### Audit-Call Detection Tests

| Detection Method | Tested? | Test Reference |
|---|---|---|
| Attribute-based heuristic (`audit.emit()`) | YES | `test_audit_emit_fires` |
| Attribute prefix matching (`record_failure`) | YES | `test_db_record_failure_fires` |
| Receiver-name matching (`audit_ledger`) | YES | `test_ledger_emit_event_fires` |
| Bare function name in `_AUDIT_FUNC_NAMES` | **UNTESTED** | No test calls a bare `audit()`, `record()`, or `emit()` function without a receiver |
| Qualified builtins-style receiver | **UNTESTED** | No test for deeply qualified receiver like `module.audit.emit()` |

### Dominance Analysis Tests

| Scenario | Tested? | Test Reference |
|---|---|---|
| If-branch success bypass | YES | `test_success_branch_without_audit_fires` |
| Broad handler return bypass | YES | `test_broad_handler_fallback_success_without_audit_fires` |
| Decorated audit writer bypass | YES | `test_local_audit_writer_must_dominate_success_paths` |
| Rejection path (raise) allowed | YES | `test_rejection_path_without_audit_is_allowed` |
| Handler re-raise allowed | YES | `test_fallback_raise_without_audit_is_allowed` |
| Loop body bypass | **UNTESTED** | `_analyze_loop()` is implemented but not tested |
| Match/case bypass | **UNTESTED** | `_analyze_match()` is implemented but not tested |
| Try/except/else/finally interactions | **UNTESTED** | `_analyze_try()` handles orelse/finalbody but is only tested via the broad handler sub-case |

### Decorator-Based Audit Target Tests

| Scenario | Tested? | Test Reference |
|---|---|---|
| `@audit_writer` decorated function | YES | `test_local_audit_writer_call_fires` |
| `@audit_critical` decorated function | YES | `test_local_audit_critical_call_fires` |
| Decorated function in dominance analysis | YES | `test_local_audit_writer_must_dominate_success_paths` |
| Nested class method with decorator | **UNTESTED** | `_iter_defs_with_qualnames` handles `ast.ClassDef` but no test covers it |
| Call-form decorator `@audit_writer()` | **UNTESTED** | `_decorator_name()` handles `ast.Call` wrappers but no test covers it |

---

## 5. Boundary Conditions

| Condition | PY-WL-004 | PY-WL-005 | PY-WL-006 |
|---|---|---|---|
| Async functions | YES (`TestAsyncFunction`) | YES (`TestAsyncFunction`) | YES (`TestNestedAndAsyncBehavior.test_async_broad_handler_with_audit_emit_fires`) |
| Nested try/except | YES (`TestTryStar.test_nested_try_inside_except_star`) | **UNTESTED** | **UNTESTED** |
| Class methods | **UNTESTED** | **UNTESTED** | **UNTESTED** |
| Empty handlers | **UNTESTED** | N/A (empty body is 0 statements, rule checks len==1) | **UNTESTED** |
| Nested functions | **UNTESTED** | **UNTESTED** | YES (`test_nested_function_handler_fires_separately`) |
| Multiple findings per function | YES (`TestMultipleBroadHandlers`) | YES (`TestMultipleHandlers`) | YES (`test_nested_function_handler_fires_separately`, 2 findings) |
| Nested try inside except* | YES (`test_nested_try_inside_except_star`) | **UNTESTED** | **UNTESTED** |

**Gaps:** Class methods are untested for all three rules. Nested functions are only tested for PY-WL-006. Nested try/except (non-TryStar) is untested for PY-WL-005 and PY-WL-006.

---

## 6. Corpus Alignment

Per section 10 of the spec, the golden corpus requires:
- **Minimum:** 1 positive + 1 negative specimen per severity matrix cell
- **Adversarial:** at least 1 adversarial false-positive and 1 adversarial false-negative per rule

### PY-WL-004 Corpus Status

All 8 taint state directories exist with both `positive/` and `negative/` subdirectories.

| Taint State | Positive Specimen | Negative Specimen | Status |
|---|---|---|---|
| AUDIT_TRAIL | PY-WL-004-TP-AUDIT_TRAIL | PY-WL-004-TN-AUDIT_TRAIL | COMPLETE |
| PIPELINE | PY-WL-004-TP-PIPELINE | PY-WL-004-TN-PIPELINE | COMPLETE |
| SHAPE_VALIDATED | PY-WL-004-TP-SHAPE_VALIDATED | PY-WL-004-TN-SHAPE_VALIDATED | COMPLETE |
| EXTERNAL_RAW | PY-WL-004-TP-EXTERNAL_RAW + TP-01 + TP-03 | TN-EXTERNAL_RAW + TN-01 + TN-02 + KFN-01 | COMPLETE (3 positive, 4 negative) |
| UNKNOWN_RAW | PY-WL-004-TP-UNKNOWN_RAW + TP-02 + TP-async-except | TN-UNKNOWN_RAW + TN-03 | COMPLETE (3 positive, 2 negative) |
| UNKNOWN_SHAPE_VALIDATED | PY-WL-004-TP-UNKNOWN_SHAPE_VALIDATED | TN-UNKNOWN_SHAPE_VALIDATED | COMPLETE |
| UNKNOWN_SEM_VALIDATED | PY-WL-004-TP-UNKNOWN_SEM_VALIDATED | TN-UNKNOWN_SEM_VALIDATED | COMPLETE |
| MIXED_RAW | PY-WL-004-TP-MIXED_RAW | TN-MIXED_RAW | COMPLETE |

Adversarial: KFN-01 present (adversarial false negative). Contextlib-suppress and reraise specimens present as additional coverage.
**All 8 cells have minimum 1P + 1N. Adversarial specimen present. PY-WL-004 corpus meets minimum requirements.**

### PY-WL-005 Corpus Status

All 8 taint state directories exist. However, there is a **structural defect**: negative specimen YAML files (TN-*) are misplaced in `positive/` directories for 6 of 8 taint states while their corresponding `.py` files are correctly in `negative/` directories.

| Taint State | Positive Specimen | Negative Specimen | Status |
|---|---|---|---|
| AUDIT_TRAIL | PY-WL-005-TP-AUDIT_TRAIL | PY-WL-005-TN-AUDIT_TRAIL (**YAML in positive/ dir**) | CONCERN -- YAML misplaced |
| PIPELINE | PY-WL-005-TP-PIPELINE | PY-WL-005-TN-PIPELINE (**YAML in positive/ dir**) | CONCERN -- YAML misplaced |
| SHAPE_VALIDATED | PY-WL-005-TP-SHAPE_VALIDATED | PY-WL-005-TN-SHAPE_VALIDATED (**YAML in positive/ dir**) | CONCERN -- YAML misplaced |
| EXTERNAL_RAW | TP-01 + TP-03 + TP-EXTERNAL_RAW + TP-long-function | TN-01 + TN-02 (correct) + TN-EXTERNAL_RAW (**YAML in positive/ dir**) | CONCERN -- 1 YAML misplaced |
| UNKNOWN_RAW | TP-02 + TP-UNKNOWN_RAW | TN-UNKNOWN_RAW (**YAML in positive/ dir**) | CONCERN -- YAML misplaced |
| UNKNOWN_SHAPE_VALIDATED | PY-WL-005-TP-UNKNOWN_SHAPE_VALIDATED | TN-UNKNOWN_SHAPE_VALIDATED (**YAML in positive/ dir**) | CONCERN -- YAML misplaced |
| UNKNOWN_SEM_VALIDATED | PY-WL-005-TP-UNKNOWN_SEM_VALIDATED | TN-UNKNOWN_SEM_VALIDATED (**YAML in positive/ dir**) | CONCERN -- YAML misplaced |
| MIXED_RAW | TP-MIXED_RAW + TP-async-silent | TN-MIXED_RAW (**YAML in positive/ dir**) | CONCERN -- YAML misplaced |

Adversarial: No explicitly labelled adversarial specimens present.
**All 8 cells have positive + negative specimens, but 8 negative YAML manifests are in `positive/` directories while their `.py` fragments are correctly in `negative/` directories. This is a corpus integrity defect that would fail directory-structure-based coverage analysis and could mislead `wardline corpus verify`.**

### PY-WL-006 Corpus Status

All 8 taint state directories exist with correctly placed specimens.

| Taint State | Positive Specimen | Negative Specimen | Status |
|---|---|---|---|
| AUDIT_TRAIL | PY-WL-006-TP-AUDIT_TRAIL | PY-WL-006-TN-AUDIT_TRAIL | COMPLETE |
| PIPELINE | PY-WL-006-TP-PIPELINE + TP-PIPELINE-DOMINANCE | TN-PIPELINE + TN-PIPELINE-DOMINANCE-RAISE | COMPLETE (2 positive, 2 negative) |
| SHAPE_VALIDATED | PY-WL-006-TP-SHAPE_VALIDATED | PY-WL-006-TN-SHAPE_VALIDATED | COMPLETE |
| EXTERNAL_RAW | PY-WL-006-TP-EXTERNAL_RAW | PY-WL-006-TN-EXTERNAL_RAW | COMPLETE |
| UNKNOWN_RAW | PY-WL-006-TP-UNKNOWN_RAW | PY-WL-006-TN-UNKNOWN_RAW | COMPLETE |
| UNKNOWN_SHAPE_VALIDATED | PY-WL-006-TP-UNKNOWN_SHAPE_VALIDATED | PY-WL-006-TN-UNKNOWN_SHAPE_VALIDATED | COMPLETE |
| UNKNOWN_SEM_VALIDATED | PY-WL-006-TP-UNKNOWN_SEM_VALIDATED | PY-WL-006-TN-UNKNOWN_SEM_VALIDATED | COMPLETE |
| MIXED_RAW | PY-WL-006-TP-MIXED_RAW | PY-WL-006-TN-MIXED_RAW | COMPLETE |

Adversarial: PIPELINE has dominance-specific positive/negative pair (bypass vs raise). No explicitly category-labelled adversarial specimens.
**All 8 cells have minimum 1P + 1N. PY-WL-006 corpus meets minimum cell requirements. Adversarial labelling is missing.**

### Distance from Spec Standard

The spec requires 1 positive + 1 negative per cell for Group B's 24 cells (3 rules x 8 states) = 48 minimum specimens, plus adversarial specimens per rule.

- **Corpus specimens:** PY-WL-004 has 26 YAML specimens across all 8 cells. PY-WL-005 has 23 YAML specimens across all 8 cells. PY-WL-006 has 20 YAML specimens across all 8 cells. Total: 69 corpus specimens. **Cell coverage minimum (48) is met.**
- **Unit tests with taint injection:** 0 across all three rules. The corpus specimens exist but **no unit test parameterizes across taint states to verify the matrix cells produce correct severity + exceptionability**.
- **Adversarial specimens:** PY-WL-004 has KFN-01. PY-WL-005 and PY-WL-006 have no explicitly labelled adversarial specimens. Spec requires minimum 1 adversarial false-positive + 1 adversarial false-negative per rule = 6 adversarial specimens needed, **1 present**.
- **PY-WL-005 corpus structural defect:** 8 negative YAML manifests are in `positive/` directories.

---

## Verdict: CONCERN

### Evidence

**Strengths:**
- Pattern detection coverage is complete or near-complete for all three rules (positive and negative)
- PY-WL-004 tests cover all documented broad-exception patterns including TryStar, contextlib.suppress, tuple-with-broad-member, and re-raise suppression
- PY-WL-005 tests cover all four silent body patterns (pass, ellipsis, continue, break) and the multi-statement non-silent case
- PY-WL-006 tests cover both sub-rules: broad-handler masking (3 positive, 3 negative) and dominance analysis (3 positive, 2 negative)
- Async function support is tested for all three rules
- Golden corpus has 1P + 1N for all 24 matrix cells (meets minimum specimen count)

**Critical Gaps:**

1. **Zero severity matrix cell coverage in unit tests.** No test for any of the three rules injects a specific taint state and asserts the resulting (severity, exceptionability) pair. PY-WL-004's matrix is the most heterogeneous in the entire rule set (E/U, E/St, W/St, W/R, E/St, W/St, W/St, E/St) with 3 distinct severity levels and 3 distinct exceptionability values -- none of this variation is verified by unit tests. The RELAXED exceptionability in EXTERNAL_RAW is unique to PY-WL-004 across the entire matrix and is untested.

2. **No exceptionability assertions in any test.** Outside of the single `severity == ERROR` assertion in each rule's first positive test, no test checks the `exceptionability` field on any finding. The UNCONDITIONAL vs STANDARD distinction is governance-critical and entirely unverified at the unit test level.

3. **PY-WL-005 corpus structural defect.** 8 negative YAML manifests are located in `positive/` subdirectories while their corresponding `.py` fragment files are correctly in `negative/` subdirectories. This inconsistency would produce incorrect results from any directory-structure-based corpus coverage analysis and could cause `wardline corpus verify` to misclassify specimens.

4. **Missing adversarial specimens.** PY-WL-005 and PY-WL-006 have no labelled adversarial specimens. PY-WL-004 has 1 (KFN-01). Spec requires 2 per rule (1 false-positive + 1 false-negative) = 6 total, 1 present.

5. **PY-WL-006 dominance analysis under-tested.** The `_analyze_loop()`, `_analyze_match()`, and `_analyze_try()` (orelse/finalbody paths) implementations are present but have no direct tests. Only the if-branch and broad-handler-return paths are tested.

6. **PY-WL-004 missing test for qualified builtins.** `_resolve_broad_name()` handles `ast.Attribute` (e.g., `builtins.Exception`) but no test exercises this path.

7. **Class methods untested for all three rules.** No test wraps exception handling in a method inside a class body.

**Recommendation:** The pattern detection layer is solid for all three rules. The primary remediation items in priority order:
1. Add taint-state-parameterized tests (`@pytest.mark.parametrize` over all 8 taint states asserting severity + exceptionability per cell) for each rule -- approximately 24 new test cases.
2. Fix PY-WL-005 corpus: move 8 misplaced TN-*.yaml files from `positive/` to `negative/` directories.
3. Add adversarial specimens for PY-WL-005 (e.g., `except: pass; log.info()` multi-statement adversarial FP) and PY-WL-006 (e.g., audit call in specific handler that looks audit-critical but should not fire).
4. Add dominance analysis tests for loop, match/case, and try/else/finally paths in PY-WL-006.
5. Add `builtins.Exception` test for PY-WL-004 and class method boundary tests for all three rules.
