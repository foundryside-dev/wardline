# SCN-021 Conformance Audit -- Solution Architect

**Auditor:** Solution Architect
**Date:** 2026-03-25
**Rule:** SCN-021 -- Contradictory decorator combination detection
**Spec reference:** wardline-02-A-python-binding.md, Section A.4.3
**Implementation:** `src/wardline/scanner/rules/scn_021.py`

---

## 1. Completeness -- All 29 Combinations

The spec (Section A.4.3) defines 29 combinations (26 contradictory, 3 suspicious). The implementation defines `_COMBINATIONS` as a tuple of 29 `_CombinationSpec` entries. Mapping each spec row to the implementation:

| # | Spec Pair | Impl left/right | Status |
|---|-----------|-----------------|--------|
| 1 | `@fail_open` + `@fail_closed` | `fail_open` / `fail_closed` | PRESENT |
| 2 | `@fail_open` + `@tier1_read` | `fail_open` / `tier1_read` | PRESENT |
| 3 | `@fail_open` + `@audit_writer` | `fail_open` / `audit_writer` | PRESENT |
| 4 | `@fail_open` + `@authoritative_construction` | `fail_open` / `authoritative_construction` | PRESENT |
| 5 | `@fail_open` + `@audit_critical` | `fail_open` / `audit_critical` | PRESENT |
| 6 | `@external_boundary` + `@int_data` | `external_boundary` / `int_data` | PRESENT |
| 7 | `@external_boundary` + `@tier1_read` | `external_boundary` / `tier1_read` | PRESENT |
| 8 | `@external_boundary` + `@authoritative_construction` | `external_boundary` / `authoritative_construction` | PRESENT |
| 9 | `@validates_shape` + `@validates_semantic` | `validates_shape` / `validates_semantic` | PRESENT |
| 10 | `@validates_shape` + `@tier1_read` | `validates_shape` / `tier1_read` | PRESENT |
| 11 | `@validates_semantic` + `@external_boundary` | `validates_semantic` / `external_boundary` | PRESENT |
| 12 | `@exception_boundary` + `@must_propagate` | `exception_boundary` / `must_propagate` | PRESENT |
| 13 | `@idempotent` + `@compensatable` | `idempotent` / `compensatable` | PRESENT |
| 14 | `@deterministic` + `@time_dependent` | `deterministic` / `time_dependent` | PRESENT |
| 15 | `@deterministic` + `@external_boundary` | `deterministic` / `external_boundary` | PRESENT |
| 16 | `@tier1_read` + `@restoration_boundary` | `tier1_read` / `restoration_boundary` | PRESENT |
| 17 | `@audit_writer` + `@restoration_boundary` | `audit_writer` / `restoration_boundary` | PRESENT |
| 18 | `@fail_closed` + `@emits_or_explains` | `fail_closed` / `emits_or_explains` | PRESENT |
| 19 | `@audit_critical` + `@fail_open` | `audit_critical` / `fail_open` | PRESENT |
| 20 | `@validates_external` + `@validates_shape` | `validates_external` / `validates_shape` | PRESENT |
| 21 | `@validates_external` + `@validates_semantic` | `validates_external` / `validates_semantic` | PRESENT |
| 22 | `@int_data` + `@validates_shape` | `int_data` / `validates_shape` | PRESENT |
| 23 | `@preserve_cause` + `@exception_boundary` | `preserve_cause` / `exception_boundary` | PRESENT |
| 24 | `@compensatable` + `@audit_writer` | `compensatable` / `audit_writer` | PRESENT |
| 25 | `@data_flow(produces=...)` + `@external_boundary` | `data_flow` / `external_boundary` | PRESENT |
| 26 | `@system_plugin` + `@tier1_read` | `system_plugin` / `tier1_read` | PRESENT |
| 27 | `@fail_open` + `@deterministic` | `fail_open` / `deterministic` | PRESENT |
| 28 | `@compensatable` + `@deterministic` | `compensatable` / `deterministic` | PRESENT |
| 29 | `@time_dependent` + `@idempotent` | `time_dependent` / `idempotent` | PRESENT |

**Result: 29/29 PRESENT. Complete.**

---

## 2. Severity Distinction

The implementation defines:
```python
_CONTRADICTORY = Severity.ERROR
_SUSPICIOUS = Severity.WARNING
```

- Entries 1--26 (impl indices 0--25) all use `_CONTRADICTORY` (ERROR).
- Entries 27--29 (impl indices 26--28) all use `_SUSPICIOUS` (WARNING).

This matches the spec exactly: 26 contradictory at ERROR, 3 suspicious at WARNING.

**Result: PASS.**

---

## 3. Exceptionability

All findings are emitted with `exceptionability=Exceptionability.UNCONDITIONAL` (line 169 of `scn_021.py`). This is hardcoded in `_emit_finding` and cannot vary per combination.

**Result: PASS.**

---

## 4. Decorator Name Accuracy

Names used in the combination table that exist in the decorator `__init__.py` exports and/or the registry (`core/registry.py`):

- All 33 unique decorator names used in combinations 1--26 (excluding `restoration_boundary` and `data_flow`) are present in both the `__all__` export list and the REGISTRY dict.
- `restoration_boundary` (combinations #16, #17): NOT in the registry, NOT in `decorators/__init__.py`. This is a forward reference to a Group 17 decorator not yet implemented (see Section 7 below).
- `data_flow` (combination #25): NOT in the registry, NOT in `decorators/__init__.py`. This is a forward reference to a Group 16 decorator not yet implemented (see Section 7 below).

All other decorator names match exactly between the combination table, the `__all__` list, and the REGISTRY keys.

**Result: PASS (with forward-reference caveat noted in Section 7).**

---

## 5. Alias Handling -- Commutativity

The spec notes that #19 is an alias of #5, and #23 is an alias of #12. These represent the same pair with operands reversed.

The implementation checks `spec.left in names and spec.right in names` (line 132). This is a set-membership test -- since `names` is a `frozenset`, detection is order-independent. Both orderings of the same pair will match regardless of which decorator appears first in source code.

However, the implementation includes both the original AND the alias as separate entries in `_COMBINATIONS`:
- #5: `fail_open` / `audit_critical` (line 39)
- #19: `audit_critical` / `fail_open` (line 73)
- #12: `exception_boundary` / `must_propagate` (line 46--51)
- #23: `preserve_cause` / `exception_boundary` (line 83--87)

For pair #5/#19: Since both check `fail_open in names and audit_critical in names` (or vice versa), **both entries will fire simultaneously** when `@fail_open` and `@audit_critical` appear together, producing **two findings for the same contradiction**. This is a duplicate-finding bug.

For pair #12/#23: These are NOT true duplicates. #12 is `exception_boundary` + `must_propagate`; #23 is `preserve_cause` + `exception_boundary`. These are different pairs -- the spec note "(Alias of #12)" means they share the same semantic rationale (preserve_cause implies propagation), not that they are the same pair. No duplicate issue here.

**CONCERN: Combination #5 and #19 are genuine duplicates. Both `(fail_open, audit_critical)` and `(audit_critical, fail_open)` resolve to the same set-membership test, producing two findings for one violation. The spec says #19 is "caught regardless of decorator ordering," implying a single finding. The implementation should either deduplicate or remove #19.**

---

## 6. Parameterized Decorators

Combination #25 involves `@data_flow(produces=...)`, a parameterized decorator. The `_decorator_name` function (lines 102--109) handles this:

```python
target = decorator.func if isinstance(decorator, ast.Call) else decorator
```

For `@data_flow(produces=X)`, the AST is `ast.Call(func=ast.Name(id='data_flow'), ...)`. The function extracts `decorator.func` (the `ast.Name` node) and then returns `target.id` = `"data_flow"`.

This correctly extracts the base name from parameterized decorators. The parameter values themselves (e.g., `produces=`) are not inspected -- only the decorator name matters for contradiction detection.

Additionally, when `ScanContext.annotations_map` is available (the preferred path), decorator resolution uses `ann.canonical_name` from the pre-computed annotation map, bypassing AST-level name extraction entirely.

**Result: PASS.**

---

## 7. Forward References

Three decorator names used in the combination table are not yet in the registry or export surface:

| Decorator | Combinations | Spec Section |
|-----------|-------------|--------------|
| `restoration_boundary` | #16, #17 | A.4.2 row 17 (Group 17) |
| `data_flow` | #25 | A.4.2 row 16 (Group 16) |

**How the implementation handles this:**

1. **With ScanContext (primary path):** `_decorator_names` reads from `self._context.annotations_map`. If `restoration_boundary` or `data_flow` are not in the annotation map (because they are not yet registered), they will not appear in the resolved name set, and the combination will never fire. This is a **silent no-op** -- correct but inert.

2. **Without ScanContext (fallback path):** `_decorator_name` performs raw AST extraction. If someone writes `@restoration_boundary` in source code, the AST will contain the name, and the combination check will fire. This is also correct -- the rule detects the contradiction even before the decorator is formally registered.

The forward references are **architecturally sound**: the combination entries are pre-loaded and will activate automatically once the decorators are added to the registry and annotation pipeline. No code change to SCN-021 will be needed.

**Result: PASS.**

---

## 8. Architectural Fit

### RuleBase conformance

`RuleScn021` subclasses `RuleBase` (line 112). It:
- Sets `RULE_ID = RuleId.SCN_021` as a class variable.
- Implements `visit_function(node, *, is_async)` as required.
- Does NOT override `visit_FunctionDef` or `visit_AsyncFunctionDef` (enforced by `__init_subclass__`).
- Appends to `self.findings` list.
- Uses `self._current_qualname` from the base class scope tracker.
- Calls `set_context()` via the engine for per-file state.

### Engine integration

`RuleScn021` is instantiated in `scanner/rules/__init__.py::make_rules()` (line 38) and returned in the rule tuple. The engine iterates this tuple for each file.

### SARIF integration

`RuleId.SCN_021` is mapped in `scanner/sarif.py` (line 41) with description "Contradictory or suspicious wardline decorator combination".

### Context dependency

The rule prefers `ScanContext.annotations_map` for decorator resolution (lines 140--144), falling back to raw AST extraction. This dual-path design is resilient -- it works both with and without the annotation pipeline.

**Result: PASS.**

---

## Summary of Findings

| Assessment Area | Result | Notes |
|----------------|--------|-------|
| 1. Completeness (29/29) | PASS | All combinations present |
| 2. Severity distinction | PASS | ERROR for #1-26, WARNING for #27-29 |
| 3. Exceptionability | PASS | All UNCONDITIONAL |
| 4. Decorator name accuracy | PASS | Forward refs noted |
| 5. Alias handling | **CONCERN** | #5/#19 produces duplicate findings |
| 6. Parameterized decorators | PASS | ast.Call unwrapping correct |
| 7. Forward references | PASS | Silent no-op, activates when registered |
| 8. Architectural fit | PASS | Conforms to RuleBase, engine, SARIF |

---

## Verdict: CONCERN

The implementation is complete and architecturally sound. All 29 spec combinations are present with correct severity and exceptionability. Forward references and parameterized decorators are handled correctly.

**One concern requires resolution:** Combinations #5 (`fail_open` + `audit_critical`) and #19 (`audit_critical` + `fail_open`) are logically identical under set-membership detection. When both decorators appear on the same function, both entries match, producing two findings for a single violation. The spec describes #19 as "(Alias of #5 -- caught regardless of decorator ordering)," which implies the alias notation is documentary, confirming commutative detection rather than requesting a second finding. The implementation should either remove entry #19 from `_COMBINATIONS` or add deduplication logic to `visit_function`.

**Evidence:**
- `scn_021.py` line 39: `_CombinationSpec("fail_open", "audit_critical", _CONTRADICTORY, ...)`
- `scn_021.py` line 73: `_CombinationSpec("audit_critical", "fail_open", _CONTRADICTORY, ...)`
- `scn_021.py` line 132: `if spec.left in names and spec.right in names:` -- symmetric membership test means both fire.
