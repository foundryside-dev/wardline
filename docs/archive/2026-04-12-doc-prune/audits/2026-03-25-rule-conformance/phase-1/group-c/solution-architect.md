# Group C: Structural Verification Rules -- Solution Architect Audit

**Date:** 2026-03-25
**Reviewer:** Solution Architect
**Rules:** PY-WL-007 (WL-006), PY-WL-008 (WL-007), PY-WL-009 (WL-008)
**Scope:** Spec conformance, severity matrix, architectural fit

---

## 1. Severity Matrix Verification

### PY-WL-007 (WL-006): Runtime type-checking internal data

**Expected (spec SS7.3):** E/St, W/R, W/R, Su/T, Su/T, W/R, W/R, W/St

**Implemented (matrix.py line 59):**
```python
(RuleId.PY_WL_007, [(_E,_St), (_W,_R), (_W,_R), (_Su,_T), (_Su,_T), (_W,_R), (_W,_R), (_W,_St)])
```

| Column | Taint State | Expected | Implemented | Status |
|--------|------------|----------|-------------|--------|
| 1 | AUDIT_TRAIL | E/St | E/St | PASS |
| 2 | PIPELINE | W/R | W/R | PASS |
| 3 | SHAPE_VALIDATED | W/R | W/R | PASS |
| 4 | EXTERNAL_RAW | Su/T | Su/T | PASS |
| 5 | UNKNOWN_RAW | Su/T | Su/T | PASS |
| 6 | UNKNOWN_SHAPE_VALIDATED | W/R | W/R | PASS |
| 7 | UNKNOWN_SEM_VALIDATED | W/R | W/R | PASS |
| 8 | MIXED_RAW | W/St | W/St | PASS |

**Result: All 8 cells PASS.**

### PY-WL-008 (WL-007): Validation boundary with no rejection path

**Expected (spec SS7.3):** E/U across all 8 columns.

**Implemented (matrix.py line 61):**
```python
(RuleId.PY_WL_008, [(_E,_U), (_E,_U), (_E,_U), (_E,_U), (_E,_U), (_E,_U), (_E,_U), (_E,_U)])
```

| Column | Taint State | Expected | Implemented | Status |
|--------|------------|----------|-------------|--------|
| 1 | AUDIT_TRAIL | E/U | E/U | PASS |
| 2 | PIPELINE | E/U | E/U | PASS |
| 3 | SHAPE_VALIDATED | E/U | E/U | PASS |
| 4 | EXTERNAL_RAW | E/U | E/U | PASS |
| 5 | UNKNOWN_RAW | E/U | E/U | PASS |
| 6 | UNKNOWN_SHAPE_VALIDATED | E/U | E/U | PASS |
| 7 | UNKNOWN_SEM_VALIDATED | E/U | E/U | PASS |
| 8 | MIXED_RAW | E/U | E/U | PASS |

**Result: All 8 cells PASS.**

### PY-WL-009 (WL-008): Semantic validation without prior shape validation

**Expected (spec SS7.3):** E/U across all 8 columns.

**Implemented (matrix.py line 63):**
```python
(RuleId.PY_WL_009, [(_E,_U), (_E,_U), (_E,_U), (_E,_U), (_E,_U), (_E,_U), (_E,_U), (_E,_U)])
```

| Column | Taint State | Expected | Implemented | Status |
|--------|------------|----------|-------------|--------|
| 1 | AUDIT_TRAIL | E/U | E/U | PASS |
| 2 | PIPELINE | E/U | E/U | PASS |
| 3 | SHAPE_VALIDATED | E/U | E/U | PASS |
| 4 | EXTERNAL_RAW | E/U | E/U | PASS |
| 5 | UNKNOWN_RAW | E/U | E/U | PASS |
| 6 | UNKNOWN_SHAPE_VALIDATED | E/U | E/U | PASS |
| 7 | UNKNOWN_SEM_VALIDATED | E/U | E/U | PASS |
| 8 | MIXED_RAW | E/U | E/U | PASS |

**Result: All 8 cells PASS.**

---

## 2. PY-WL-007: Taint-Gated Suppression and Detection Coverage

### 2.1 SUPPRESS in EXTERNAL_RAW and UNKNOWN_RAW

**Spec requirement (SS7.1 WL-006, SS7.5d):** "In EXTERNAL_RAW, type-checking is expected and appropriate, so SUPPRESS." The matrix assigns Su/T to both EXTERNAL_RAW and UNKNOWN_RAW columns.

**Implementation:** PY-WL-007 does not hard-code suppression logic. Instead, it delegates to `matrix.lookup(self.RULE_ID, taint)` (py_wl_007.py line 208). When the function taint is EXTERNAL_RAW or UNKNOWN_RAW, the matrix returns `SeverityCell(SUPPRESS, TRANSPARENT)`. The finding is still emitted with severity=SUPPRESS, which maps to SARIF level "note" (sarif.py line 28).

**Assessment:** Correct. The rule emits findings for all taint states and the matrix governs severity. SUPPRESS findings appear in SARIF output as "note" level, which is the spec-intended behaviour -- the finding is not silently dropped but is informationally present. **PASS.**

### 2.2 Detection of isinstance() calls

**Spec requirement (SS7.1 WL-006):** "Type-checking internal data at runtime."

**Implementation (py_wl_007.py lines 148-180):** `_check_isinstance` detects `isinstance(obj, type)` calls where `call.func` is `ast.Name` with `id == "isinstance"`. **PASS.**

### 2.3 Detection of type() comparisons

**Spec requirement:** WL-006 covers "runtime type-checking" broadly.

**Implementation (py_wl_007.py lines 182-203):** `_check_type_compare` detects `type(x) == T`, `type(x) is T`, `type(x) != T`, `type(x) is not T`. Checks that the left side of a Compare is a `type(...)` call and that comparison operators include Eq, NotEq, Is, IsNot. **PASS.**

### 2.4 Suppression patterns

The rule suppresses three structurally different patterns that are not WL-006 violations:

1. **AST node type dispatch** (isinstance with `ast.*` types) -- structural dispatch on tagged unions, not trust boundary doubt. Lines 48-62.
2. **Dunder comparison protocol** (`__eq__` etc. returning `NotImplemented`) -- Python data model requirement. Lines 130-134.
3. **Frozen dataclass construction** (`__post_init__` with `object.__setattr__`) -- defensive freezing pattern. Lines 135-137.
4. **Declared boundary functions** -- isinstance inside a wardline boundary function is the *implementation* of the declared contract, not evidence of structural doubt. Lines 107-120, 172-173.

**Assessment:** All four suppressions are architecturally sound. The declared-boundary suppression is particularly important: it prevents PY-WL-007 from firing inside `@validates_shape` bodies where isinstance is the correct security primitive. **PASS.**

---

## 3. PY-WL-008: Rejection Path Analysis

### 3.1 Rejection path definition (spec SS7.2)

The spec defines three constructs that constitute rejection paths:

| Rejection Path Type | Spec Reference | Implemented | Evidence |
|---|---|---|---|
| Exception-raising statement (`raise`) | SS7.2 bullet 1 | YES | `_has_rejection_path` line 87: `isinstance(child, ast.Raise)` |
| Early return preceded by conditional guard | SS7.2 bullet 2 | YES | Lines 90-94: checks `ast.If` with negative guard + branch terminator |
| Two-hop call-graph delegation | SS7.2 bullet 3, SS8.1 | NO | Not implemented |

**Two-hop analysis gap:** The spec states: "A call to a function that unconditionally raises, if the called function is resolvable via two-hop call-graph analysis (SS8.1)." The implementation does not perform any call-graph resolution. A boundary function that delegates rejection to a helper (e.g., `schema_lib.validate(data)` which raises on failure) will generate a false positive.

This is a **significant conformance gap**. The spec language in SS8.1 uses MUST: "MUST perform structural verification (WL-007) on all validation boundary functions [...] WL-007 is primarily intraprocedural: a validation function that delegates to a called function for rejection does not satisfy WL-007 unless the delegation is resolvable via two-hop call-graph analysis." The two-hop limit is the minimum bar for the MUST requirement. Without it, the rule will produce false positives on structurally sound validators that use thin wrappers.

**Assessment: CONCERN.** Two-hop delegation analysis is absent.

### 3.2 Constructs that do NOT constitute rejection paths (spec SS7.2)

| Non-rejection construct | Spec Reference | Correctly excluded | Evidence |
|---|---|---|---|
| `assert` statements | SS7.2 paragraph 4 | YES | `_has_rejection_path` does not match `ast.Assert` |
| Unconditional None return | SS7.2 paragraph 4 | YES | `_branch_has_rejection_terminator` only fires inside if-branches |
| Constant-False guards (SHOULD) | SS7.2 paragraph 4 | NO | Not implemented |
| Unconditional-raise-only bodies (SHOULD) | SS7.2 paragraph 4 | N/A | Advisory, not WL-007 finding |

**Constant-False guard detection:** The spec says "the scanner SHOULD detect trivially unreachable rejection paths (constant-False guards, `if 0:`, `if "":`) and treat them as absent." This is a SHOULD requirement, not MUST. Not a conformance failure but a noted gap.

**Assessment:** SHOULD-level gap on constant-False guard detection. Not a conformance failure.

### 3.3 Negative guard detection

`_is_negative_guard` (py_wl_008.py lines 36-49) recognises:
- `not expr` (UnaryOp/Not)
- Comparisons with `is not`, `!=`
- Comparisons with `is None`, `is False`, `== None`, `== False`

The else-branch path is also covered: line 93 checks `child.orelse` for rejection terminators, which handles positive-guard if-statements where the else-branch rejects.

**Assessment: PASS** on guard detection breadth.

### 3.4 Boundary type coverage

**Spec requirement (SS7.1 WL-007):** "Applies to shape-validation boundaries (T4 to T3), semantic-validation boundaries (T3 to T2), combined-validation boundaries (T4 to T2), and restoration boundaries (SS5.3)."

**Implementation (py_wl_008.py lines 20-33):**
```python
_BOUNDARY_TRANSITIONS = frozenset({
    "shape_validation",
    "semantic_validation",
    "external_validation",
    "combined_validation",
    "restoration",
})

_BOUNDARY_DECORATORS = frozenset({
    "validates_shape",
    "validates_semantic",
    "validates_external",
    "restoration_boundary",
})
```

| Boundary Type | Transition | Decorator | Present |
|---|---|---|---|
| Shape validation (T4 to T3) | `shape_validation` | `validates_shape` | YES |
| Semantic validation (T3 to T2) | `semantic_validation` | `validates_semantic` | YES |
| Combined validation (T4 to T2) | `external_validation` + `combined_validation` | `validates_external` | YES |
| Restoration (SS5.3) | `restoration` | `restoration_boundary` | YES |

Note: `_BOUNDARY_TRANSITIONS` includes both `external_validation` and `combined_validation`, which correctly handles both manifest-declared names for the T4-to-T2 transition.

**Assessment: PASS.** All four boundary types are covered.

### 3.5 Dual detection path (manifest + decorator)

`_is_checked_boundary` (py_wl_008.py lines 124-137) checks both:
1. Manifest-declared boundaries via `self._context.boundaries` (with scope check via `path_within_scope`)
2. Direct decorator presence via `_has_direct_boundary_decorator`

This dual path ensures the rule works both with and without a manifest. **PASS.**

---

## 4. PY-WL-009: Semantic Validation Without Prior Shape Validation

### 4.1 Combined boundary exemption

**Spec requirement (SS7.2, SS5.2 invariant 3):** "A combined validation boundary (e.g., `@validates_external`, T4 to T2) satisfies this requirement internally because it performs both phases."

**Implementation (py_wl_009.py lines 229-231):**
```python
if self._is_combined_boundary(node):
    return
```

`_is_combined_boundary` (lines 258-271) checks for:
- Manifest transitions in `_COMBINED_BOUNDARY_TRANSITIONS`: `{"combined_validation", "external_validation"}`
- Direct decorator in `_COMBINED_BOUNDARY_DECORATORS`: `{"validates_external"}`

**Assessment: PASS.** Combined boundaries are correctly exempted. `@validates_external` satisfies the shape-before-semantic ordering internally per SS5.2.

### 4.2 Semantic check detection

`_get_semantic_check_nodes` (py_wl_009.py lines 179-206) identifies if/assert nodes that:
1. Access data via subscript (`data["key"]`) -- attribute access is excluded because class definitions provide shape guarantees
2. Do NOT contain inline shape checks (isinstance, hasattr, membership tests in the condition itself)

This is a pragmatic heuristic. The rule only fires when subscript access is present, which reduces false positives on code that uses typed objects (attribute access).

**Assessment: PASS** on heuristic design. The subscript-only restriction is documented and architecturally sound.

### 4.3 Shape check evidence detection

`_has_shape_check_before` (py_wl_009.py lines 48-69) looks for evidence of shape validation before the semantic check line:
- `isinstance()` and `hasattr()` calls
- Membership tests (`key in data`)
- Calls to functions with shape-validation names (validate_schema, check_shape, etc.)
- Schema-qualified method calls (`jsonschema.validate()`, `schema.is_valid()`)

**Assessment: PASS.** The detection covers the common patterns. The line-ordering check (`getattr(node, "lineno", 0) >= stop_line`) ensures only *prior* shape checks count.

### 4.4 Ordering enforcement scope

**Spec requirement (SS7.2 WL-008):** "The scanner verifies that a declared semantic-validation boundary's inputs trace back to a shape-validation boundary's outputs."

**Implementation:** PY-WL-009 checks for shape-validation *evidence within the function body* (intraprocedural). It does NOT trace inputs back to a prior `@validates_shape` call at the interprocedural level. This is a pragmatic L1 approximation: the rule checks whether the semantic boundary body contains shape checks before semantic checks, rather than verifying the full data-flow path.

The spec's framing ("inputs trace back to a shape-validation boundary's outputs") implies interprocedural analysis, but the binding context (SS8.1) scopes L1 to intraprocedural analysis: "MUST detect the six active pattern rules within annotated function and method bodies -- intraprocedural analysis." For WL-008 specifically: "MUST enforce validation ordering (WL-008): data reaching a declared semantic-validation boundary must have passed through a declared shape-validation boundary." The intraprocedural check is a conservative approximation -- it fires when no evidence of shape validation is found in the body, which may produce false positives when shape validation was performed by a caller.

**Assessment: Architecturally acceptable** for L1 analysis. The rule's intraprocedural scope is consistent with the L1 analysis level.

---

## 5. Interface Contract and SARIF Output

### 5.1 Finding structure

All three rules emit findings via `Finding` dataclass (context.py) with all required SARIF property bag fields:
- `rule_id` (maps to `wardline.rule`)
- `taint_state` (maps to `wardline.taintState`)
- `severity` (maps to `wardline.severity`)
- `exceptionability` (maps to `wardline.exceptionability`)
- `analysis_level` (maps to `wardline.analysisLevel`) -- set to 1 for all three rules

**Assessment: PASS.**

### 5.2 SARIF level mapping

`_SEVERITY_TO_SARIF_LEVEL` (sarif.py lines 24-28) correctly maps:
- ERROR -> "error"
- WARNING -> "warning"
- SUPPRESS -> "note"

PY-WL-007 findings in EXTERNAL_RAW/UNKNOWN_RAW will appear as SARIF "note" level. PY-WL-008 and PY-WL-009 findings always appear as SARIF "error" level. **PASS.**

### 5.3 SARIF short descriptions

The SARIF short descriptions (sarif.py lines 31-43) for these rules are:
- PY-WL-007: "Pipeline stage ordering violation"
- PY-WL-008: "Taint state escalation without validation"
- PY-WL-009: "Governance registry mismatch"

**CONCERN:** These descriptions appear to be placeholder/incorrect values that do not match the actual rule semantics:
- PY-WL-007 detects runtime type-checking, not pipeline stage ordering
- PY-WL-008 detects missing rejection paths, not taint state escalation
- PY-WL-009 detects missing shape validation, not governance registry mismatch

These descriptions flow into SARIF `shortDescription` on rule descriptors and are visible to consumers. While non-blocking (they do not affect finding severity or exceptionability), they are misleading.

**Assessment: CONCERN.** SARIF rule short descriptions are incorrect for PY-WL-007, PY-WL-008, and PY-WL-009.

---

## 6. Architectural Fit

### 6.1 Rule base class conformance

All three rules:
- Subclass `RuleBase` (which extends `ast.NodeVisitor`)
- Set `RULE_ID` class variable to the correct `RuleId` enum member
- Implement `visit_function(node, is_async)` as required
- Do NOT override `visit_FunctionDef` or `visit_AsyncFunctionDef`
- Use `walk_skip_nested_defs` for body traversal (prevents duplicate findings on nested functions)
- Delegate taint lookup to `_get_function_taint` (base class, falls back to UNKNOWN_RAW)
- Delegate severity lookup to `matrix.lookup`

**Assessment: PASS.**

### 6.2 Engine integration

The engine (engine.py) calls `rule.set_context(ctx)` then `rule.visit(tree)` for each rule. All three rules read from `self._context` for boundary and taint information. The engine collects `rule.findings` after execution. No special-casing needed for any of these rules. **PASS.**

### 6.3 Frozen finding immutability

`Finding` is `frozen=True` (context.py line 21). All three rules construct findings via keyword arguments to the frozen dataclass. No post-construction mutation. **PASS.**

---

## 7. Summary of Findings

| Item | Rule | Status | Detail |
|------|------|--------|--------|
| Matrix cells (24/24) | All | PASS | All cells match spec exactly |
| SUPPRESS in EXTERNAL_RAW/UNKNOWN_RAW | PY-WL-007 | PASS | Delegated to matrix lookup |
| isinstance() detection | PY-WL-007 | PASS | |
| type() comparison detection | PY-WL-007 | PASS | |
| Suppression patterns | PY-WL-007 | PASS | 4 structurally sound suppressions |
| Raise as rejection path | PY-WL-008 | PASS | |
| Guarded early return as rejection path | PY-WL-008 | PASS | |
| **Two-hop call-graph delegation** | **PY-WL-008** | **CONCERN** | **Not implemented; SS8.1 MUST requirement** |
| Assert exclusion | PY-WL-008 | PASS | |
| Constant-False guard detection (SHOULD) | PY-WL-008 | NOTE | Not implemented; SHOULD, not MUST |
| Boundary type coverage (4/4) | PY-WL-008 | PASS | shape, semantic, combined, restoration |
| Combined boundary exemption | PY-WL-009 | PASS | @validates_external correctly exempted |
| Semantic check detection heuristic | PY-WL-009 | PASS | Subscript-only scope is sound |
| Shape check evidence detection | PY-WL-009 | PASS | |
| SARIF property bag fields | All | PASS | All 5 mandatory fields present |
| **SARIF short descriptions** | **All 3** | **CONCERN** | **Descriptions are incorrect/stale** |
| RuleBase conformance | All | PASS | |
| Engine integration | All | PASS | |

---

## Verdict: CONCERN

Two issues prevent a clean PASS:

1. **PY-WL-008 two-hop call-graph delegation is absent.** SS8.1 uses MUST language for two-hop analysis on WL-007 boundary functions. The current implementation is intraprocedural only. A boundary function that delegates rejection to a helper function (a common pattern with schema libraries) will generate a false positive. This is a conformance gap against a MUST requirement. Severity: medium -- the rule is conservative (over-reports), not unsound (under-reports).

2. **SARIF `shortDescription` values for PY-WL-007, PY-WL-008, and PY-WL-009 are incorrect.** They appear to be leftover placeholder text from initial scaffolding. PY-WL-007 says "Pipeline stage ordering violation" (should describe runtime type-checking); PY-WL-008 says "Taint state escalation without validation" (should describe missing rejection path); PY-WL-009 says "Governance registry mismatch" (should describe missing shape validation). Severity: low -- does not affect finding correctness but is misleading to SARIF consumers.

All severity matrix cells are correct. All three rules have sound architectural integration. The detection logic for the patterns each rule targets is correct and well-scoped for L1 analysis. The combined-boundary exemption in PY-WL-009 correctly implements SS5.2 invariant 3.
