# SCN-021 Python Engineering Audit

**Rule:** SCN-021 -- Contradictory decorator combination detection
**Reviewer:** Python Engineer
**Date:** 2026-03-25
**File:** `src/wardline/scanner/rules/scn_021.py`

---

## 1. Decorator Resolution

SCN-021 uses a two-path resolution strategy in `_decorator_names()` (lines 135-149):

**Primary path (annotations_map):** When `self._context` and `self._context.annotations_map` are both non-None, it looks up `self._current_qualname` in the map and collects `ann.canonical_name` from each `WardlineAnnotation`. This is the high-fidelity path that handles aliased imports, re-exports, and any decorator form that pass 1 resolved.

**Fallback path (AST):** When annotations are unavailable (or the annotations_map lookup yields an empty set), it iterates `node.decorator_list` and extracts names via `_decorator_name()`.

**Correctness note:** The fallback triggers when `names` is empty after the annotations_map lookup (line 143: `if names: return`). This means if the function has decorators but none were resolved by pass 1, it silently falls through to AST. This is correct behavior -- it degrades gracefully.

## 2. Parameterized Decorator Handling

`_decorator_name()` (lines 102-109) handles parameterized decorators correctly:

```python
target = decorator.func if isinstance(decorator, ast.Call) else decorator
```

- `@fail_open` -> `ast.Name` -> returns `target.id` = `"fail_open"`
- `@fail_open()` -> `ast.Call(func=ast.Name)` -> unwraps to `ast.Name` -> `"fail_open"`
- `@wardline.fail_open` -> `ast.Attribute` -> returns `target.attr` = `"fail_open"`
- `@wardline.fail_open()` -> `ast.Call(func=ast.Attribute)` -> unwraps to `ast.Attribute` -> `"fail_open"`

All four forms are handled. This is correct.

## 3. Combination Matching -- Commutativity

The combination table uses ordered `(left, right)` pairs, but the matching logic (line 132) tests:

```python
if spec.left in names and spec.right in names:
```

This is a set membership test, so it is order-independent. The combination `(A, B)` fires whether the decorators appear as `@A @B` or `@B @A`. This is correct.

**However, there is a duplicate entry.** The pair `fail_open + audit_critical` appears twice:

- Line 39: `_CombinationSpec("fail_open", "audit_critical", ...)` with rationale "Audit-critical paths must not have fallback paths"
- Line 73: `_CombinationSpec("audit_critical", "fail_open", ...)` with identical rationale

Because matching is order-independent, both entries will fire for the same function, producing **two duplicate findings** for a single violation. This is a bug.

**Severity:** Medium. Duplicate findings will confuse users and inflate SARIF output.

## 4. `__wrapped__` Chain Traversal

SCN-021 does **not** traverse `__wrapped__` chains. It resolves decorators from either:
1. The annotations_map (populated by pass 1 decorator discovery), or
2. Direct AST inspection of `node.decorator_list`.

Both paths operate on the syntactic decorator list, not on runtime wrapper chains. This is the correct approach for a static analysis rule -- `__wrapped__` is a runtime concept. The `get_wardline_attrs()` function in `_base.py` handles runtime chain traversal, but that is for the runtime enforcement layer, not the scanner.

No issue here.

## 5. Edge Cases

### Decorator via variable (`x = fail_open; @x`)

The AST fallback sees `ast.Name(id="x")` and returns `"x"`, which will not match any combination table entry. This is a **false negative**, but it is expected and acceptable -- variable-assigned decorators cannot be reliably resolved statically. The annotations_map path (pass 1) is the correct mechanism for handling this case if it performs import resolution.

### Star imports (`from wardline.decorators import *`)

AST fallback: works correctly because `@fail_open` is still `ast.Name(id="fail_open")`.
Annotations_map path: depends on pass 1's import resolution capability.

### Qualified imports (`@wardline.fail_open`)

AST fallback: `_decorator_name` extracts `target.attr` = `"fail_open"`. Correct.

### Decorator factories

Handled correctly via the `ast.Call` unwrapping (see section 2).

### Nested decorators on inner functions

The base class `_dispatch` method correctly maintains `_current_qualname` via the scope stack. Inner function `outer.inner` will have its own qualname for the annotations_map lookup. Correct.

## 6. Performance

The matching loop iterates `_COMBINATIONS` (currently 31 entries) once per function with 2+ decorators. Each iteration performs two `frozenset.__contains__` lookups (O(1) each). Total cost per function: O(C) where C = len(_COMBINATIONS) = 31.

This is **not** O(n^2) in decorator count -- the combination table is fixed-size and small. The `frozenset` construction from the decorator list is O(d) where d is the decorator count per function. Total per-function cost: O(d + C). This is efficient and acceptable.

The `frozenset` is constructed fresh on each call rather than cached, but since d is typically 1-5, this is negligible.

## 7. Code Clarity and Maintainability

The `_CombinationSpec` dataclass is clean and self-documenting. Each entry carries its rationale, which flows directly into the finding message. The severity constants `_CONTRADICTORY` and `_SUSPICIOUS` improve readability over raw `Severity.ERROR`/`Severity.WARNING`.

The combination table is easy to extend: add a new `_CombinationSpec` line.

**Minor concern:** The table is a flat tuple with 31 entries and no grouping comments. As it grows, it would benefit from section comments (e.g., `# --- Failure mode conflicts ---`, `# --- Tier conflicts ---`).

## 8. Phantom Combination Entries

Two decorator names in the combination table do not exist in `REGISTRY` and have no decorator implementation:

- `data_flow` (line 91-94): referenced in `_CombinationSpec("data_flow", "external_boundary", ...)`
- `restoration_boundary` (lines 57-60, 63-66): referenced in two `_CombinationSpec` entries

These entries are dead code. They can never fire because:
1. The annotations_map will never contain these canonical names (no registry entry to discover).
2. The AST fallback would only match if the source happens to use a decorator literally named `data_flow` or `restoration_boundary`, which would be a non-wardline decorator.

**Severity:** Low. No false positives, but dead entries obscure the real coverage of the rule and suggest incomplete implementation or stale references from a design document.

## 9. Test Coverage

The test file covers:
- Contradictory pair detection (3 cases)
- Suspicious pair detection (1 case)
- Annotation context resolution with aliased imports (1 case)
- Single-decorator no-fire (1 case)

**Missing test coverage:**
- Parameterized decorators in AST fallback (e.g., `@fail_open()` with parens)
- Qualified decorator names (e.g., `@wardline.fail_open`)
- Async function defs
- Multiple contradictory pairs on one function (should produce multiple findings)
- The duplicate `fail_open + audit_critical` pair (would reveal the double-fire bug)

---

## Findings Summary

| # | Category | Severity | Description |
|---|----------|----------|-------------|
| 1 | Bug | Medium | Duplicate combination entry `fail_open + audit_critical` (lines 39 and 73) causes two findings for one violation |
| 2 | Dead code | Low | `data_flow` and `restoration_boundary` in combination table have no registry entry or decorator implementation; entries can never fire |
| 3 | Test gap | Low | No test for parameterized decorators, async defs, qualified imports, or multi-pair functions |

---

## Verdict: CONCERN

The core AST handling is correct and the resolution strategy (annotations_map with AST fallback) is sound. Performance is fine. However, the duplicate combination entry is a real bug that produces duplicate findings, and the phantom decorator names (`data_flow`, `restoration_boundary`) indicate either incomplete implementation or stale design artifacts that should be cleaned up or documented as forward declarations.
