# Group B: Exception Handling Rules -- Python Engineer Audit

**Rules:** PY-WL-004, PY-WL-005, PY-WL-006
**Auditor:** Python Engineer
**Date:** 2026-03-25

---

## 1. AST Handling Correctness

### ExceptHandler detection and handler.type resolution

All three rules correctly handle the four `handler.type` shapes:

| Shape | PY-WL-004 | PY-WL-005 | PY-WL-006 |
|---|---|---|---|
| `None` (bare except) | `_check_handler` line 71 | N/A (005 does not filter by type) | `_is_broad_handler` line 67 |
| `ast.Name` | `_resolve_broad_name` line 136 | N/A | `_is_broad_handler` line 69 |
| `ast.Attribute` (qualified) | `_resolve_broad_name` line 138 | N/A | `_is_broad_handler` line 71 |
| `ast.Tuple` (multi-except) | `_resolve_broad_name` lines 140-148 | N/A | `_is_broad_handler` lines 73-78 |

PY-WL-005 intentionally does not inspect handler type -- it fires on any silent handler regardless of exception specificity. This is correct for its semantics.

### TryStar (Python 3.11+ except*) handling

PY-WL-004 and PY-WL-005 both use identical TryStar deduplication logic:

1. First pass: `getattr(ast, "TryStar", None)` for forward-compat on <3.11.
2. Walk with `walk_skip_nested_defs`, collect TryStar handler `id()` values into a set, and process them immediately.
3. Second pass: walk again, skip any `ExceptHandler` whose `id()` is in the TryStar set.

This is correct and avoids double-counting.

**PY-WL-006 does NOT handle TryStar.** Its `visit_function` (line 210) walks for `ast.ExceptHandler` instances and checks `_is_broad_handler`, but has no TryStar-aware deduplication. On Python 3.11+, a broad `except*` handler containing an audit call would be double-reported: once when walking the TryStar children (ExceptHandler nodes are still yielded by `walk_skip_nested_defs`), and the TryStar node itself is never directly inspected. More precisely: the ExceptHandler children of a TryStar node ARE yielded by `ast.walk`/`walk_skip_nested_defs`, so they will be detected -- but there is no deduplication guard. If a TryStar has two handlers both matching, each fires independently, which is acceptable. The risk is if the engine or future code changes cause TryStar handlers to be visited twice. This is a **minor inconsistency** rather than a current bug, since `walk_skip_nested_defs` yields each node exactly once. But the pattern diverges from 004/005 without justification.

## 2. Edge Cases

### Nested try/except

`walk_skip_nested_defs` correctly handles nested try/except within the same function -- it skips nested function/async function definitions but walks into nested try blocks. All three rules benefit from this correctly.

### Immediate reraise suppression (PY-WL-004)

`_is_immediate_reraise` (004, lines 106-115) checks:
- Single-statement body
- `raise` with no argument (bare re-raise) -- correct
- `raise e` where `e` matches `handler.name` -- correct

Edge case handled well: `raise some_other_var` is NOT treated as immediate reraise, which is correct.

### Qualified names (builtins.Exception)

`_resolve_broad_name` in PY-WL-004 and `_is_broad_handler` in PY-WL-006 both check `ast.Attribute` with `.attr in _BROAD_NAMES`. This catches `builtins.Exception`, `foo.Exception`, etc. The check is deliberately loose on the receiver -- `foo.Exception` would also match. This is a reasonable heuristic: false positives from user-defined classes named `Exception` are rare, and a stricter check would need import resolution.

### Tuple with mixed broad/specific types

PY-WL-004 `_resolve_broad_name` returns the first broad name found in a tuple -- correct behavior. PY-WL-006 `_is_broad_handler` similarly short-circuits on first broad member. Both are correct.

### contextlib.suppress (PY-WL-004 only)

`_is_suppress_call` checks both `suppress(...)` and `contextlib.suppress(...)`. Does not handle deeper attribute chains like `from contextlib import suppress as s` -- but this is a known limitation of static analysis without import resolution and is acceptable.

One minor note: the `isinstance(arg, ast.expr)` check on line 97 is always true for valid AST arguments to a Call node (all arguments are expressions), so it is redundant but harmless.

## 3. PY-WL-005 Precision Gate: What Counts as "Silent"

The rule fires when `len(handler.body) == 1` and the single statement matches:

| Pattern | Detected | Correct |
|---|---|---|
| `pass` | Yes (ast.Pass) | Yes |
| `...` (Ellipsis) | Yes (ast.Expr + ast.Constant with value `is ...`) | Yes |
| `continue` | Yes (ast.Continue) | Yes |
| `break` | Yes (ast.Break) | Yes |

**Not detected (by design):**

| Pattern | Detected | Assessment |
|---|---|---|
| Docstring-only (`"""ignored"""`) | No | Correct -- docstring is `ast.Expr(ast.Constant(str))`, not Ellipsis |
| `return None` | No | Reasonable -- explicit return has control-flow semantics |
| `return` (bare) | No | Reasonable -- same rationale |
| String literal body (`"suppress"`) | No | Correct -- same shape as docstring |

The `len(handler.body) == 1` gate is important: `except: pass; log.info(...)` correctly does not fire because the body has 2 statements. This is tested (`test_pass_with_extra_statement_silent`).

**Ellipsis detection correctness:** `stmt.value.value is ...` uses identity comparison with the Ellipsis singleton. This is correct -- `ast.Constant` stores the actual Python value, and `...` is a singleton.

## 4. PY-WL-006 Specifics

### Audit-call detection heuristic

`_looks_audit_scoped` uses a three-pronged heuristic:
1. Bare function names in `_AUDIT_FUNC_NAMES`: `audit`, `record`, `emit`
2. Attribute names matching `_AUDIT_ATTR_PREFIXES` (`audit`, `record`, `emit`) either exactly or as prefix with underscore
3. Receiver name containing `"audit"` or `"ledger"` (case-insensitive)

This is well-calibrated. The prefix check `attr.startswith(prefix + "_")` correctly avoids matching `emission()` (no underscore) while catching `emit_event()`.

`_is_audit_call` adds local decorator-discovered names (`@audit_writer`, `@audit_critical`). The module pre-scan in `visit_Module` collects these names by walking `_iter_defs_with_qualnames` and checking decorator names.

### Dominance analysis

The `_analyze_block`/`_analyze_stmt` framework implements a forward dataflow analysis tracking a boolean `audited` state through control flow. Key observations:

- **`_analyze_return`**: treats unaudited returns as bypass nodes -- correct.
- **`_analyze_if`**: explores both branches independently -- correct.
- **`_analyze_try`**: handlers start from the incoming `audited` state (not from body's exit state) -- this is correct because the exception could happen on the first statement of the try body before any audit call.
- **`_analyze_loop`**: conservatively includes the incoming state (loop may execute zero times) -- correct.
- **`_analyze_match`**: each case analyzed independently from incoming state -- correct. However, `match` without a wildcard case could allow fall-through. The analysis does not add `{audited}` for the "no case matches" path. This could cause false negatives if a match statement has no default case and the audit call is only inside the match. This is a **minor concern** but unlikely in practice since match exhaustiveness is not guaranteed in Python.

The `_has_normal_path_audit` gate ensures dominance analysis only runs when audit calls exist on non-handler paths, preventing double-reporting with the handler-masking check. This is well-designed.

### visit_Module pre-scan

`visit_Module` calls `_iter_defs_with_qualnames` to find decorated functions, then stores only the terminal name (`.split(".")[-1]`). This means a method `Foo.write_audit` decorated with `@audit_writer` registers `"write_audit"` -- any call to `write_audit()` in the file would match, even if it refers to a different function. This is a known limitation of name-based heuristics without scope resolution. Acceptable for v1.

The `self.generic_visit(node)` call at line 201 is important -- it kicks off the normal visitor traversal after the pre-scan. Correct.

## 5. Performance

### Double walk in PY-WL-004 and PY-WL-005

Both rules call `walk_skip_nested_defs(node)` twice in `visit_function`: once for TryStar collection, once for the main pass. On Python < 3.11 where `TryStar` does not exist, the first walk is skipped entirely (guarded by `if _TryStar is not None`). On 3.11+, the double walk is O(n) + O(n) = O(n) -- linear, not quadratic. Acceptable.

### PY-WL-006 inner walk

In `visit_function` (line 216), for each broad handler found via `walk_skip_nested_defs`, the code calls `ast.walk(child)` on the handler body. This is a walk-within-a-walk, but the inner walk covers only the handler subtree (disjoint from other handlers). Total work is bounded by the function's AST size. Not quadratic.

### _contains_audit_call

Called from `_analyze_stmt` for each non-control-flow statement, and internally uses `walk_skip_nested_defs`. For deeply nested if/try chains, each statement is walked independently. In pathological cases (deeply nested control flow with many statements), this could revisit nodes, but in practice function bodies are bounded. Not a concern for real-world code.

### _has_normal_path_audit

Recursive descent through try/if/match/loop bodies. Each statement is visited once per path through the recursion. Linear in function body size.

**No quadratic patterns identified.**

## 6. TryStar Deduplication Consistency

| Rule | TryStar dedup | Approach |
|---|---|---|
| PY-WL-004 | Yes | `id()` set + two-pass walk |
| PY-WL-005 | Yes | `id()` set + two-pass walk (identical pattern) |
| PY-WL-006 | **No** | Single pass, no TryStar awareness |

PY-WL-006 lacks TryStar handling. As noted in section 1, this is not currently a double-counting bug because `walk_skip_nested_defs` yields each node once. However, it is an inconsistency that could become a bug if the walker semantics change, and it means PY-WL-006 does not explicitly test or document its behavior with `except*` blocks.

## 7. Additional Observations

### _BlockAnalysis dataclass

The `bypass_nodes` field has a default factory of `tuple` but is built up with list operations and then frozen into a tuple at return. The `field(default_factory=tuple)` is correct but slightly unusual -- `()` would be cleaner as a default since tuples are immutable. Not a bug.

### _decorator_name handling

Line 57: `target = decorator.func if isinstance(decorator, ast.Call) else decorator` -- correctly handles both `@audit_writer` and `@audit_writer()` (with or without call parentheses). Good.

### Test coverage gaps

- No test for PY-WL-006 with TryStar (`except*` with audit call in broad handler).
- No test for PY-WL-004 with `builtins.Exception` qualified name.
- No test for PY-WL-005 with a bare `return` or `return None` to confirm they do NOT fire (they should not, per current logic).
- No test for PY-WL-006 `match` statement without wildcard case (the false-negative scenario in dominance analysis).

---

## Verdict: CONCERN

**Evidence:**

1. **PY-WL-006 missing TryStar deduplication** -- inconsistent with PY-WL-004 and PY-WL-005. Not currently a double-counting bug due to `walk_skip_nested_defs` semantics, but the pattern divergence is unjustified and fragile. Should be harmonized.

2. **PY-WL-006 `_analyze_match` does not account for the "no case matches" path** -- when a `match` statement has no wildcard/default case, the analysis does not consider that control may fall through without entering any case. This can produce false negatives in dominance analysis (an unaudited path is not detected). Low practical impact but semantically incorrect.

3. **Minor: redundant `isinstance(arg, ast.expr)` guard** in PY-WL-004 line 97 -- harmless but should be cleaned up for clarity.

All three rules are otherwise well-structured, correct in their core AST handling, and free of performance issues. The concerns are addressable without architectural changes.
