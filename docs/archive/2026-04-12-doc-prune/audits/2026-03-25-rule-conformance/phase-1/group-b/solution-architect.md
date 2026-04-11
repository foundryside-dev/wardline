# Conformance Audit: Group B (Exception Handling)

**Auditor role:** Solution Architect
**Date:** 2026-03-25
**Rules:** PY-WL-004 (WL-003), PY-WL-005 (WL-004), PY-WL-006 (WL-005)

---

## 1. Severity Matrix Cell Verification

Reference: spec section 7.3, implementation in `src/wardline/core/matrix.py` lines 45-57.

Column order: AUDIT_TRAIL, PIPELINE, SHAPE_VALIDATED, EXTERNAL_RAW, UNKNOWN_RAW, UNKNOWN_SHAPE_VALIDATED, UNKNOWN_SEM_VALIDATED, MIXED_RAW.

### PY-WL-004 (WL-003): Broad exception handlers

| Taint State | Spec | Code | Result |
|---|---|---|---|
| AUDIT_TRAIL | E/U | E/U | PASS |
| PIPELINE | E/St | E/St | PASS |
| SHAPE_VALIDATED | W/St | W/St | PASS |
| EXTERNAL_RAW | W/R | W/R | PASS |
| UNKNOWN_RAW | E/St | E/St | PASS |
| UNKNOWN_SHAPE_VALIDATED | W/St | W/St | PASS |
| UNKNOWN_SEM_VALIDATED | W/St | W/St | PASS |
| MIXED_RAW | E/St | E/St | PASS |

**Result: 8/8 cells PASS.**

### PY-WL-005 (WL-004): Silent exception handling

| Taint State | Spec | Code | Result |
|---|---|---|---|
| AUDIT_TRAIL | E/U | E/U | PASS |
| PIPELINE | E/St | E/St | PASS |
| SHAPE_VALIDATED | E/St | E/St | PASS |
| EXTERNAL_RAW | E/St | E/St | PASS |
| UNKNOWN_RAW | E/St | E/St | PASS |
| UNKNOWN_SHAPE_VALIDATED | E/St | E/St | PASS |
| UNKNOWN_SEM_VALIDATED | E/St | E/St | PASS |
| MIXED_RAW | E/St | E/St | PASS |

**Result: 8/8 cells PASS.**

### PY-WL-006 (WL-005): Audit-critical writes in broad handlers

| Taint State | Spec | Code | Result |
|---|---|---|---|
| AUDIT_TRAIL | E/U | E/U | PASS |
| PIPELINE | E/U | E/U | PASS |
| SHAPE_VALIDATED | E/St | E/St | PASS |
| EXTERNAL_RAW | E/St | E/St | PASS |
| UNKNOWN_RAW | E/St | E/St | PASS |
| UNKNOWN_SHAPE_VALIDATED | E/St | E/St | PASS |
| UNKNOWN_SEM_VALIDATED | E/St | E/St | PASS |
| MIXED_RAW | E/St | E/St | PASS |

**Result: 8/8 cells PASS.**

**Matrix summary: 24/24 cells PASS.** All three rules conform to spec section 7.3.

---

## 2. SARIF Short Descriptions

Reference: `src/wardline/scanner/sarif.py` lines 31-43.

| Rule ID | Current Description | Expected (per spec) | Result |
|---|---|---|---|
| PY-WL-004 | "Unvalidated decorator argument" | Broad exception handler (WL-003) | **FAIL** |
| PY-WL-005 | "Unsafe type coercion on tainted data" | Silent exception handling (WL-004) | **FAIL** |
| PY-WL-006 | "Missing audit trail annotation" | Audit-critical writes in broad exception handler (WL-005) | **FAIL** |

All three SARIF short descriptions are incorrect. They appear to be placeholder text that was never updated to reflect the actual rule semantics. The descriptions describe unrelated concepts:

- PY-WL-004's description ("Unvalidated decorator argument") has no relation to broad exception handling.
- PY-WL-005's description ("Unsafe type coercion on tainted data") has no relation to silent exception catching.
- PY-WL-006's description ("Missing audit trail annotation") is tangentially related to audit concepts but does not describe the actual rule (audit writes *inside* broad handlers).

**Recommended corrections:**

| Rule ID | Corrected Description |
|---|---|
| PY-WL-004 | "Broad exception handler swallowing errors" |
| PY-WL-005 | "Silent exception handler — no action taken" |
| PY-WL-006 | "Audit-critical write inside broad exception handler" |

---

## 3. Interface Contract Conformance

### 3.1 RULE_ID Declarations

| Rule | Class | RULE_ID Value | Matches RuleId Enum | Result |
|---|---|---|---|---|
| PY-WL-004 | `RulePyWl004` | `RuleId.PY_WL_004` | Yes (`"PY-WL-004"`) | PASS |
| PY-WL-005 | `RulePyWl005` | `RuleId.PY_WL_005` | Yes (`"PY-WL-005"`) | PASS |
| PY-WL-006 | `RulePyWl006` | `RuleId.PY_WL_006` | Yes (`"PY-WL-006"`) | PASS |

### 3.2 SARIF Property Bag Keys (spec section A.3, item 4)

The `_make_result` function in `sarif.py` (lines 113-145) emits the following keys on each result's `properties` dict:

| Required Key (spec A.3) | Present | Result |
|---|---|---|
| `wardline.rule` | Yes (line 117) | PASS |
| `wardline.taintState` | Yes (line 118-120) | PASS |
| `wardline.severity` | Yes (line 121) | PASS |
| `wardline.exceptionability` | Yes (line 122) | PASS |
| `wardline.analysisLevel` | Yes (line 123) | PASS |

Additional keys emitted: `wardline.qualname`, `wardline.sourceSnippet`, `wardline.exceptionId`, `wardline.exceptionExpires`. These are not required by spec but are valid extensions.

**Result: All mandatory property bag keys present. PASS.**

---

## 4. Pattern Coverage (per spec section A.3 mapping table)

### PY-WL-004 (WL-003): Broad exception handlers

Spec section A.3 maps PY-WL-004 to: "Broad exception handlers swallowing errors (`except Exception`, bare `except`)".

| Pattern | Covered | Evidence |
|---|---|---|
| Bare `except:` | Yes | `_check_handler`: `handler.type is None` (line 71-77) |
| `except Exception:` | Yes | `_BROAD_NAMES = {"Exception", "BaseException"}` (line 20), `_resolve_broad_name` (lines 130-149) |
| `except BaseException:` | Yes | Included in `_BROAD_NAMES` |
| Tuple containing broad type | Yes | `_resolve_broad_name` handles `ast.Tuple` (lines 140-148) |
| Qualified names (`builtins.Exception`) | Yes | `ast.Attribute` branch in `_resolve_broad_name` (lines 138-139) |
| `except*` (TryStar, Python 3.11+) | Yes | Explicit TryStar handling (lines 45-51) |
| `contextlib.suppress(Exception)` | Yes | `_check_suppress_call` (lines 88-103) |
| Immediate re-raise suppression | Yes | `_is_immediate_reraise` returns True, handler skipped (line 69) |

**Coverage assessment: Comprehensive. PASS.**

### PY-WL-005 (WL-004): Silent exception handling

Spec section A.3 maps PY-WL-005 to: "Catching exceptions silently -- no action taken in handler (`except: pass`, bare `except` with no re-raise or logging)".

| Pattern | Covered | Evidence |
|---|---|---|
| `except: pass` | Yes | `_SILENT_MESSAGES` includes `ast.Pass` (line 25-27) |
| `except: ...` (Ellipsis) | Yes | `_is_ellipsis_stmt` (lines 45-51), `_ELLIPSIS_MESSAGE` (lines 39-42) |
| `except: continue` | Yes | `_SILENT_MESSAGES` includes `ast.Continue` (lines 28-31) |
| `except: break` | Yes | `_SILENT_MESSAGES` includes `ast.Break` (lines 32-36) |
| Multi-statement body | Correctly excluded | `len(handler.body) != 1` check (line 104) |
| `except*` (TryStar) | Yes | TryStar handler deduplication (lines 86-93) |

**Coverage assessment: Comprehensive. PASS.**

### PY-WL-006 (WL-005): Audit-critical writes in broad handlers

Spec section A.3 maps PY-WL-006 to: "Audit-critical writes inside broad exception handlers". Spec section A.4.2 row for `@audit_writer` states: "Call-site bans: enclosing swallowing `except`. Audit must dominate telemetry on shared execution paths. Fallback paths that bypass the audit call produce a finding."

| Pattern | Covered | Evidence |
|---|---|---|
| Audit call inside broad handler body | Yes | `visit_function` lines 210-227 |
| Broad handler detection (bare, Exception, BaseException, tuple, qualified) | Yes | `_is_broad_handler` (lines 65-79) |
| Heuristic audit call recognition (attr prefixes, decorator names) | Yes | `_looks_audit_scoped`, `_is_audit_call` (lines 101-120) |
| Local audit name pre-scan from decorators | Yes | `visit_Module` (lines 191-201) |
| Success-path audit bypass detection | Yes | `_analyze_block`/`_analyze_stmt` family (lines 256-422) |
| If/else branch analysis | Yes | `_analyze_if` (lines 320-336) |
| Try/except/else/finally analysis | Yes | `_analyze_try` (lines 338-381) |
| Loop analysis (conservative) | Yes | `_analyze_loop` (lines 383-404) |
| Match/case analysis | Yes | `_analyze_match` (lines 406-422) |
| Return as success exit | Yes | `_analyze_return` (lines 305-318) |
| Raise as non-continuing path | Yes | `_analyze_stmt` returns empty continue_states (line 289) |

**Coverage assessment: Comprehensive. The dominance/bypass analysis is architecturally sophisticated and goes beyond simple pattern matching. PASS.**

---

## 5. Architectural Fit

### 5.1 RuleBase Pattern

All three rules correctly follow the RuleBase contract:

| Requirement | PY-WL-004 | PY-WL-005 | PY-WL-006 |
|---|---|---|---|
| Subclasses `RuleBase` | Yes | Yes | Yes |
| Sets `RULE_ID` class variable | Yes | Yes | Yes |
| Implements `visit_function(node, *, is_async)` | Yes | Yes | Yes |
| Does NOT override `visit_FunctionDef`/`visit_AsyncFunctionDef` | Correct | Correct | Correct |
| Appends to `self.findings` | Yes | Yes | Yes |
| Uses `matrix.lookup(self.RULE_ID, taint)` for severity | Yes | Yes | Yes |
| Constructs `Finding` with all required fields | Yes | Yes | Yes |

### 5.2 walk_skip_nested_defs Usage

| Rule | Uses walk_skip_nested_defs | Correct Usage |
|---|---|---|
| PY-WL-004 | Yes (lines 48, 54) | Correct: prevents duplicate findings from nested function bodies |
| PY-WL-005 | Yes (lines 89, 95) | Correct: same pattern as PY-WL-004 |
| PY-WL-006 | Yes (lines 210, 131) | Correct: used for handler scanning and audit call containment checks |

### 5.3 PY-WL-006 visit_Module Override

PY-WL-006 additionally overrides `visit_Module` (line 191) to pre-scan for locally declared audit call targets via decorator inspection. This is architecturally sound -- it collects module-level context before per-function traversal begins, and delegates to `generic_visit(node)` to continue normal traversal. The pattern does not conflict with RuleBase's dispatch mechanism.

### 5.4 TryStar Deduplication

Both PY-WL-004 and PY-WL-005 use an identical pattern to handle Python 3.11+ `except*` (ExceptionGroup) handlers: they pre-collect handler IDs from TryStar nodes, process them once, then skip them during the main walk. This prevents double-counting since `ast.walk` yields ExceptHandler nodes from both Try and TryStar nodes. The pattern is correct and consistent across both rules.

---

## 6. Spec Cross-Reference Verification

### Worked Examples (spec section 7.4)

- **(c) WL-003 in SHAPE_VALIDATED vs EXTERNAL_RAW**: Spec says W/St vs W/R. Matrix has W/St and W/R. **Consistent.**
- **(e) WL-005 [sic -- spec says WL-005 but the example text describes WL-004+WL-005 semantics] in PIPELINE**: Spec example (e) actually discusses "audit-critical writes inside broad exception handlers" which is WL-005, mapped to PY-WL-006. Matrix has E/U for PIPELINE. **Consistent.**
- **(f) WL-003 in UNKNOWN_RAW vs EXTERNAL_RAW**: Spec says E/St vs W/R. Matrix has E/St and W/R. **Consistent.**

---

## 7. Findings Summary

| # | Category | Severity | Detail |
|---|---|---|---|
| F-B-01 | SARIF description | **FAIL** | PY-WL-004 description is "Unvalidated decorator argument" -- completely unrelated to broad exception handling |
| F-B-02 | SARIF description | **FAIL** | PY-WL-005 description is "Unsafe type coercion on tainted data" -- completely unrelated to silent exception handling |
| F-B-03 | SARIF description | **FAIL** | PY-WL-006 description is "Missing audit trail annotation" -- does not describe the actual rule |

No other conformance issues found. Matrix cells, interface contracts, pattern coverage, and architectural fit all conform to spec.

---

## Verdict: CONCERN

**Rationale:** All 24 severity matrix cells match spec. All three rules implement the correct patterns per the A.3 mapping table. Interface contracts (RULE_ID, property bag keys) are correct. Architectural fit (RuleBase pattern, walk_skip_nested_defs usage) is sound.

However, three SARIF `_RULE_SHORT_DESCRIPTIONS` entries are factually wrong -- they describe entirely different concepts than the rules they label. These descriptions surface in SARIF `shortDescription.text` on rule descriptors (sarif.py line 155-158) and would be visible to any downstream consumer (CI dashboards, code review tools, governance reports). This is a documentation/metadata defect, not a logic defect, but it undermines the integrity of the SARIF output for these three rules.

**Evidence:** `src/wardline/scanner/sarif.py` lines 34-37:
```python
RuleId.PY_WL_004: "Unvalidated decorator argument",
RuleId.PY_WL_005: "Unsafe type coercion on tainted data",
RuleId.PY_WL_006: "Missing audit trail annotation",
```

**Recommendation:** Fix the three SARIF descriptions. Once corrected, this group is PASS with no remaining concerns.
