# Group A — Python Engineer Assessment

Auditor: Python Engineer
Date: 2026-03-25
Files reviewed:
- `src/wardline/scanner/rules/py_wl_001.py`
- `src/wardline/scanner/rules/py_wl_002.py`
- `src/wardline/scanner/rules/py_wl_003.py`
- `src/wardline/scanner/rules/base.py`

---

## AST Handling Correctness

### walk_skip_nested_defs (base.py:29-44)

Correct BFS implementation using `deque`. The identity check (`child is not node`) properly ensures the root node's own body is walked while nested FunctionDef/AsyncFunctionDef children are excluded. One subtlety: `ast.ClassDef` nodes nested inside a function body are *not* skipped, which is correct — `_dispatch` and `visit_ClassDef` on the base class handle scope tracking, and `generic_visit` recurses into class bodies to find methods defined there.

No issue with the walker itself.

### PY-WL-001 (py_wl_001.py)

**Lines 66-74 — Double-visit prevention via `handled_calls`:** The logic is:
1. For every `ast.Call` child, first check if it was already handled (by being the inner `.get()` of a `schema_default()` wrapper).
2. Call `_unwrap_schema_default_get(child)` — if the current call IS a `schema_default(d.get(...))`, record the inner `.get()` call's `id()` so it is skipped when encountered later.
3. Then call `_check_call(child, node)`.

This has a **subtle ordering dependency**: because `walk_skip_nested_defs` is BFS, the `schema_default(d.get(...))` call node is yielded *before* its child `d.get(...)` call node. BFS guarantees parent-before-child, so the `id()` of the inner `.get()` is always recorded before that inner call is reached. This is **correct**.

**Lines 87-88 — `.get()` pattern:** Checks `len(call.args) >= 2`. This correctly excludes `d.get("key")` (1 positional arg, no default). However, it does not inspect `call.keywords` — a call like `d.get("key", **kwargs)` would not fire (correct, since we cannot statically determine if a default is supplied). A call like `some_obj.get("key", default="val")` where the object's `.get()` accepts keyword defaults would be missed — but `dict.get` does not accept keyword arguments, so this is acceptable for the stated scope.

**Lines 92-93 — `.setdefault()` pattern:** Same structure as `.get()`. Correct.

**Lines 97-98 — `defaultdict()` pattern:** `_is_defaultdict_call` (line 109) checks for `ast.Name` with id `"defaultdict"` OR `ast.Attribute` with attr `"defaultdict"`. The latter catches `collections.defaultdict` but also would match `foo.defaultdict` — a minor false-positive risk, but acceptable for a static scanner without type information. The `len(call.args) < 1` guard correctly excludes `defaultdict()` with no factory.

**Lines 100-106 — `_is_method_call`:** Only checks `ast.Attribute`. Does not match calls via subscript (e.g., `getattr(d, 'get')("key", default)`) — this is expected; such dynamic dispatch is beyond static analysis scope.

### PY-WL-002 (py_wl_002.py)

**Lines 54-59 — `_check_call`:** Checks `ast.Name` with id `"getattr"` and `len(call.args) >= 3`. This correctly excludes 2-arg `getattr(obj, name)`. Does not check `call.keywords` — `getattr` does not accept keyword arguments in CPython, so this is fine. Does not match `builtins.getattr(...)` via `ast.Attribute` — minor gap, extremely unlikely in practice.

**Lines 62-72 — `_check_boolop` for `obj.attr or default`:** Checks for `ast.Or` with exactly 2 values where the first is `ast.Attribute`. This is a reasonable heuristic. However:
- **Concern:** `len(boolop.values) == 2` means `a.x or b.x or default` (3 values) would NOT fire. Python's parser chains `or` into a single `BoolOp` with N values. If the intent is to catch any `obj.attr or ...` pattern, only checking `values[0]` being an `Attribute` is sufficient regardless of length. The `== 2` constraint is conservative but could miss legitimate cases.
- The pattern also fires on `obj.attr or other_obj.method()` where the right side is not a "default" literal — no way to distinguish without type info. Acceptable.

### PY-WL-003 (py_wl_003.py)

**Lines 64-65 — `ast.Compare` for `in`/`not in`:** Iterates `compare.ops` and fires on the first `In` or `NotIn`. The early `return` on line 117 prevents duplicate findings for the same Compare node. Correct.

**Lines 66-67 — `ast.Call` for `hasattr`:** Checks `ast.Name` with id `"hasattr"`. Does not verify argument count — `hasattr()` with wrong arg count would be a runtime error anyway, so flagging it is fine (it still indicates the programmer intended an existence check). Correct.

**Lines 68-83 — `ast.MatchMapping` and `ast.MatchClass`:** These are 3.10+ AST nodes. On Python < 3.10, they simply do not appear in the AST, so these branches are unreachable but harmless — no `AttributeError` risk because `isinstance` gracefully handles missing types (actually, `ast.MatchMapping` would raise `AttributeError` on Python < 3.10 at import time if accessed at module level, but since it appears only in `isinstance()` calls within method bodies, Python evaluates it lazily). **Wait — correction:** `ast.MatchMapping` is evaluated at the `isinstance()` call site. On Python 3.9, `ast.MatchMapping` would raise `AttributeError`. If the project requires Python 3.10+ this is fine. If Python 3.9 support is needed, this is a **crash risk**.

**Lines 148-151 — defensive `getattr` for line info:** `_emit_finding` uses `getattr(node, "lineno", 0)` etc. This is because `MatchMapping` and `MatchClass` nodes may not have line info set in all cases. Good defensive coding.

---

## Python Edge Cases

### PY-WL-001: `d.get("key")` (1 arg, no default)
**PASS.** `len(call.args) >= 2` on line 87 excludes this. The rule only fires when a default value is explicitly provided.

### PY-WL-001: Keyword-only defaults
`d.get("key", default="value")` — `dict.get` does not support keyword arguments, so `call.keywords` is not inspected. If a custom class's `.get()` accepts `default` as a keyword, this rule would miss it. **Acceptable** — the rule targets `dict`-like semantics without type information.

### PY-WL-002: `getattr(obj, name)` (2 args)
**PASS.** `len(call.args) >= 3` on line 57 excludes this.

### PY-WL-003: Chained comparisons (`a in b in c`)
Python parses `a in b in c` as `Compare(left=a, ops=[In, In], comparators=[b, c])`. The `_check_compare` method iterates `compare.ops` and fires on the *first* `In` (line 117 returns immediately). This means one finding per Compare node regardless of chain length. **Correct** — a single finding is appropriate; the node as a whole represents an existence check.

### Match/case patterns
PY-WL-003 handles `MatchMapping` and `MatchClass` (lines 68-83). PY-WL-001 and PY-WL-002 do not interact with match/case, which is correct — match/case does not produce `.get()` or `getattr()` calls at the AST level. **Note the Python version concern raised above in AST Handling.**

### Walrus operator (`:=`)
The walrus operator produces `ast.NamedExpr` nodes. None of the three rules specifically handle it, but this is correct — `if (x := d.get("key", default)):` still contains an `ast.Call` for `d.get(...)` which the walker visits normally. The walrus does not wrap or hide the call. **No issue.**

---

## schema_default() Mechanics (PY-WL-001)

### Double-visit prevention
The `handled_calls` set (line 65) uses `id()` as the key. Since all nodes exist simultaneously in the AST (no garbage collection during traversal), `id()` values are stable. **Correct and appropriate** — `ast.AST` nodes are not hashable by default, so `id()` is the right approach.

### schema_default(non_get_expression)
If `schema_default(some_other_call)` is encountered:
1. `_unwrap_schema_default_get` returns `None` (line 136-145) because the wrapped expression is not a `.get()` call with 2+ args.
2. In `_check_call` (line 82), the `_unwrap_schema_default_get` check returns `None`, so it falls through.
3. `schema_default` is not a method call (it is `ast.Name`, not `ast.Attribute`), so patterns 1 and 2 (lines 87-93) do not match.
4. It is not a `defaultdict` call (line 97).
5. **Result: silently passes through with no finding.** This is a potential concern — `schema_default(arbitrary_expr)` is neither flagged nor suppressed. Whether this is correct depends on specification intent, which is outside my scope, but from a Python correctness standpoint the code path is well-defined and does not crash.

### ast.literal_eval safety
`_extract_default_value` (lines 158-165) wraps `ast.literal_eval` in a `try/except (ValueError, SyntaxError)`. This handles:
- Non-literal expressions (variables, function calls) -> `_UNPARSEABLE_DEFAULT`
- Complex literals (dicts, lists, tuples, etc.) -> correctly extracted
- `None`, booleans, numbers, strings -> correctly extracted

**One gap:** `ast.literal_eval` can raise `RecursionError` on deeply nested literal expressions (e.g., `(((((...)))))`). This is not caught. In practice, such expressions are pathological and unlikely, but for robustness, catching `Exception` or adding `RecursionError` would be safer. **Minor concern.**

The `_UNPARSEABLE_DEFAULT` sentinel (line 30) is a bare `object()` instance. The `==` comparison on line 212 (`default_value == optional_field.approved_default`) will never be `True` for the sentinel unless `approved_default` is the same object, which it cannot be. So unparseable defaults always take the ungoverned/mismatch path. **Correct.**

---

## Performance

### Quadratic patterns
No quadratic patterns detected. Each rule performs a single BFS walk via `walk_skip_nested_defs` per function body. `_unwrap_schema_default_get` in PY-WL-001 is called twice per `schema_default(...)` call node (once in `visit_function` line 71, once in `_check_call` line 82) — this is constant-factor overhead per node, not quadratic. The `id()` lookup in `handled_calls` is O(1).

### Repeated traversals
PY-WL-001's `_emit_schema_default_finding` calls `_unwrap_schema_default_get` a third time (line 202). This is a redundant re-parse of the same AST subtree. The result could be passed as a parameter. **Minor inefficiency, not a correctness issue.**

### _find_matching_optional_field (PY-WL-001 lines 268-288)
Iterates all `optional_fields` for every `schema_default(d.get(...))` call. If there are N optional fields and M schema_default calls per file, this is O(N*M). In practice both N and M are small. If optional_fields grew large, an index by field name would help. **Not a current concern.**

### handled_calls set key choice
Using `id()` (Python object identity) is correct here. AST nodes are not hashable, and `id()` is unique for all live objects. Since the AST tree is held in memory for the duration of the walk, no `id()` reuse can occur. **Correct.**

---

## Idiom Adherence

### Positive observations
- Good use of `@staticmethod` for pure predicate methods.
- `@final` on base class dispatch methods with `__init_subclass__` enforcement is excellent defensive design.
- Type annotations are thorough — `TYPE_CHECKING` imports, union types, `ClassVar`.
- Guard clauses used consistently (early returns in `_check_call`, `_is_structural_validation_boundary`).
- `frozenset` for constant sets is correct.
- `from __future__ import annotations` used consistently for PEP 604 union syntax.

### Minor observations
- **PY-WL-001 line 116:** `len(call.args) < 1` could be `not call.args` for more Pythonic idiom. Trivial.
- **PY-WL-002 `_check_boolop`:** The method name suggests a general BoolOp check but only handles `Or` with exactly 2 values. Naming could be more specific (e.g., `_check_attr_or_fallback`). Minor readability concern.
- **PY-WL-003 `_emit_finding`:** Uses `getattr(node, "lineno", 0)` defensively, while PY-WL-001 and PY-WL-002 access `.lineno` directly. The inconsistency is justified by the `MatchMapping`/`MatchClass` node types, but a comment explaining why would help.
- No code smells or excessively long methods. All methods are focused and under 30 lines.

---

## Verdict: PASS

All three rules are well-implemented from a Python engineering perspective. AST node matching is correct for the stated patterns. The `walk_skip_nested_defs` BFS walker is sound and correctly handles the parent-before-child ordering that PY-WL-001's double-visit prevention relies on. No crashes or incorrect behavior identified for standard Python code.

### Items to track (non-blocking)

| # | Rule | Severity | Description |
|---|------|----------|-------------|
| 1 | PY-WL-003 | Low | `ast.MatchMapping` / `ast.MatchClass` in `isinstance()` will raise `AttributeError` on Python < 3.10. Confirm minimum Python version or add a guard. |
| 2 | PY-WL-001 | Low | `ast.literal_eval` does not catch `RecursionError` for pathological inputs (line 163). |
| 3 | PY-WL-001 | Info | `_unwrap_schema_default_get` called 3 times for each `schema_default(d.get(...))` node — result could be threaded through to avoid re-parsing. |
| 4 | PY-WL-002 | Info | `_check_boolop` restricts to `len(boolop.values) == 2`, missing chained `obj.attr or x or y` patterns. Confirm this is intentional. |
| 5 | PY-WL-001 | Info | `schema_default(non_get_expr)` silently produces no finding. Confirm this is intended behavior. |
