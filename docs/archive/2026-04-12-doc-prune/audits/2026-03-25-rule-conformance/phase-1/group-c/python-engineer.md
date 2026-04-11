# Group C: Structural Verification — Python Engineer Audit

**Reviewer:** Python Engineer
**Date:** 2026-03-25
**Files reviewed:**
- `src/wardline/scanner/rules/py_wl_007.py`
- `src/wardline/scanner/rules/py_wl_008.py`
- `src/wardline/scanner/rules/py_wl_009.py`
- `src/wardline/scanner/rules/base.py`
- `src/wardline/scanner/context.py`
- `src/wardline/manifest/models.py`

---

## 1. PY-WL-007: isinstance() / type() Detection

### AST Pattern Correctness

**isinstance detection** (lines 148-180): Correctly matches `ast.Call` where
`call.func` is `ast.Name` with `id == "isinstance"`. This handles the standard
unqualified call. It does NOT detect `builtins.isinstance()` — acceptable since
that form is vanishingly rare in real codebases and documenting it as a known
limitation is sufficient.

**type() comparison detection** (lines 182-203): Matches `ast.Compare` where
the left operand is a `type(...)` call, and any operator is `Eq`, `NotEq`, `Is`,
or `IsNot`. Correct. Early return after first matching operator prevents
duplicate findings for chained comparisons like `type(x) == int == type(y)` —
good.

**`_is_type_call`** (lines 196-203): Static method, checks `ast.Call` with
`ast.Name` func where `id == "type"`. Same builtins-qualified limitation as
isinstance — acceptable.

### Suppression Mechanisms

1. **AST type dispatch** (`_isinstance_has_ast_type`, lines 48-62): Checks if
   the second arg to isinstance is `ast.SomeType` (qualified) or a tuple of
   `ast.*` types. The `all()` check on tuples means a mixed tuple like
   `(ast.Name, str)` is NOT suppressed — correct, since that mix suggests
   non-dispatch intent. Empty tuple edge case: `isinstance(x, ())` returns
   `False` from `_isinstance_has_ast_type` because of the `and type_arg.elts`
   guard — correct (no suppression).

2. **Dunder protocol** (lines 130-133): Only suppresses when function name is in
   `_COMPARISON_DUNDERS` AND body contains `return NotImplemented`. Both
   conditions are required — correct. `_function_returns_not_implemented` uses
   `ast.walk` which descends into nested functions — minor imprecision (a
   `return NotImplemented` in a nested lambda/def would trigger suppression), but
   the dunder+NotImplemented conjunction makes false suppression extremely
   unlikely in practice.

3. **Frozen dataclass** (lines 134-137): Checks `node.name == "__post_init__"`
   AND `object.__setattr__` in body. `_body_has_object_setattr` also uses
   `ast.walk` — same nested-function imprecision as above. Same risk assessment:
   negligible in practice.

4. **Declared boundary** (lines 107-120): Delegates to context boundaries list,
   checking `boundary.function == qualname`. Correct use of `_current_qualname`
   which is set by `_dispatch` in the base class before `visit_function` runs.

### Concern: `ast.walk` in suppression helpers vs `walk_skip_nested_defs`

`_function_returns_not_implemented` (line 67) and `_body_has_object_setattr`
(line 79) both use `ast.walk(node)` rather than `walk_skip_nested_defs(node)`.
This means a nested function containing `return NotImplemented` or
`object.__setattr__` would incorrectly suppress the *enclosing* function's
isinstance findings. The main traversal in `visit_function` correctly uses
`walk_skip_nested_defs`, but these helpers do not.

**Severity:** Low. The conjunction of conditions (dunder name + NotImplemented in
nested def; `__post_init__` + `object.__setattr__` in nested def) makes real
false suppression extremely unlikely. However, it is a structural inconsistency
worth noting.

---

## 2. PY-WL-008: Boundary with No Rejection Path

### `_is_negative_guard` (lines 36-50)

Recognized patterns:
- `not X` (UnaryOp + Not)
- `X is not Y` / `X != Y` (IsNot, NotEq)
- `X is None` / `X == None` / `X is False` / `X == False` (Is/Eq with Constant
  value in `{False, None}`)

**Missing patterns:**
- `X == 0` or `X == ""` — not recognized as negative guards. This is defensible:
  these are value checks, not validation guards. No issue.
- `not isinstance(...)` — handled correctly: `not X` is caught by the UnaryOp
  branch regardless of what `X` is.

The zip with `strict=False` on line 48 is correct — `ops` and `comparators`
always have the same length in a well-formed AST from CPython's parser, but
`strict=False` is the safe default.

### `_branch_has_rejection_terminator` (lines 53-61)

Uses `ast.walk` on each statement, looking for `ast.Raise` or `ast.Return`.

**Concern:** Any `return` is treated as rejection, including `return result` in
the happy path. This is by design for the "branch" context — it's only called on
the if-body of a negative guard or on the else-branch, so a return there IS
rejection (early return on bad input). Correct.

**Concern:** Uses `ast.walk` which descends into nested functions. A `raise`
inside a nested `def` within the branch body would incorrectly count as a
rejection terminator. Same low-severity pattern as PY-WL-007.

### `_has_rejection_path` (lines 84-95)

Walks the function body (using `walk_skip_nested_defs` — correct) looking for:
1. Bare `ast.Raise` anywhere (unconditional raise = rejection)
2. `ast.If` with negative guard test + rejection in if-body
3. `ast.If` with rejection in else-body (positive guard with else-rejection)

**Missing: match/case statements.** Python 3.10+ `match`/`case` is not handled.
A boundary function that uses `match` with a wildcard case that raises would not
be recognized as having a rejection path. This is a gap for modern Python
codebases.

**Missing: ternary raise.** `raise X if cond else Y` is a `Raise` node at the
top level, so it IS caught by check #1. No issue.

**Missing: for/while + raise.** A pattern like `for x in data: if bad: raise`
would be caught because `walk_skip_nested_defs` descends into for-loops and
finds the `ast.Raise`. Correct.

### Boundary Detection (`_is_checked_boundary`, lines 124-137)

Context-based lookup checks `boundary.function == self._current_qualname`,
`boundary.transition in _BOUNDARY_TRANSITIONS`, and `path_within_scope`. Falls
back to `_has_direct_boundary_decorator`.

**Decorator fallback** (`_decorator_name`, lines 64-71): Handles both bare
decorators (`@validates_shape`) and parameterized decorators
(`@restoration_boundary(...)`) via the `decorator.func if isinstance(decorator,
ast.Call)` dispatch. For `@pkg.validates_shape`, it extracts `validates_shape`
via `ast.Attribute.attr`. Correct.

**Edge case:** A double-call decorator like `@validates_shape()()` would extract
the func of the outer Call, which is itself a Call — neither `ast.Name` nor
`ast.Attribute` — so `_decorator_name` returns `None`. Correct behavior: this
exotic pattern should not be silently recognized.

---

## 3. PY-WL-009: Semantic Validation Without Shape Check

### `_has_shape_check_before` (lines 48-69)

Wraps `stmts` in `ast.Module(body=stmts, type_ignores=[])` and uses
`walk_skip_nested_defs` on it. The `stop_line` filter uses `>=` (skips nodes at
or after stop_line).

**Edge case — same-line statements:** If a shape check and a semantic check are
on the same line (e.g., `isinstance(x, dict); if x["k"]: ...` on a single line
via semicolons), the shape check's `lineno` equals `stop_line`, so
`getattr(node, "lineno", 0) >= stop_line` is `True` and the shape check is
skipped. This means same-line shape checks are NOT recognized as "before" the
semantic check. This is a minor edge case — semicolon-separated statements on
one line are rare in real code, and the behavior is conservative (flags rather
than suppresses).

**Wrapping in ast.Module:** The synthetic Module node has `lineno=0` (no lineno
attribute), so it passes the `>= stop_line` check only if `stop_line <= 0` which
is impossible for real code. `walk_skip_nested_defs` yields it first but it
matches no check patterns. Clean.

### `_is_shape_validation_call` (lines 93-130)

Recognized patterns:
- `isinstance(...)`, `hasattr(...)`
- Bare calls matching `_SHAPE_VALIDATION_NAMES` (exact) or containing
  `_SHAPE_VALIDATION_SUBSTRINGS` (substring, case-insensitive via `.lower()`)
- Method calls: `obj.validate_schema(...)`, `obj.check_shape(...)`, etc.
- Schema-qualified: `jsonschema.validate()`, `schema.is_valid()` — generic
  method name + receiver name containing a schema substring

The substring matching is inclusive (any function with "schema" in its name
counts). This is a pragmatic choice for recall over precision.

**`_receiver_name`** (lines 133-145): Recursively extracts dotted names. Returns
`None` for complex expressions (subscripts, calls as receivers). Correct — no
risk of infinite recursion since AST depth is bounded.

### `_has_subscript_access` (lines 153-161)

Uses `ast.walk(node)` to find any `ast.Subscript`. This correctly includes the
node itself (a Subscript test expression). The docstring explicitly documents
that attribute access is excluded — matches implementation.

**Note:** `ast.walk` here descends into all children including nested calls. A
test like `if func(data["key"]) > 0` would match because `data["key"]` is a
Subscript inside the Call inside the Compare. This is correct — the subscript
access is still present and needs shape validation.

### `_test_contains_shape_check` (lines 164-176)

Inline shape check detection in conditional tests. Handles isinstance/hasattr
calls and membership tests within the same condition. Uses `ast.walk(test)` —
correct for examining the full expression tree of a condition.

### `_get_semantic_check_nodes` (lines 179-206)

Finds `ast.If` and `ast.Assert` nodes with subscript access in the test,
excluding those with inline shape checks. Uses `walk_skip_nested_defs` — correct.

**Missing: match/case as semantic checks.** A `match data["key"]` with case arms
performing value validation would not be detected. Same gap as PY-WL-008.

### Boundary Detection

Same pattern as PY-WL-008 — context-based lookup with decorator fallback.
Combined boundaries (`combined_validation`, `external_validation`) are correctly
excluded first (line 229) before checking for semantic boundaries.

`_COMBINED_BOUNDARY_DECORATORS` contains `validates_external` but NOT
`restoration_boundary` — correct, since restoration is not a combined validation
boundary.

---

## 4. Performance Analysis

### Quadratic Patterns

**PY-WL-009 `_has_shape_check_before`:** Called once per semantic check node. For
each call, it walks all statements before `stop_line` via `walk_skip_nested_defs`
on the entire function body. If a function has N semantic checks, this is O(N *
body_size). In practice N is small (few semantic checks per function), so this is
acceptable. However, a pathological function with many if-statements accessing
subscripts would exhibit quadratic behavior.

**PY-WL-007 suppression checks:** `_function_returns_not_implemented` and
`_body_has_object_setattr` are called once per function, not per-finding.
Pre-computed as flags in `visit_function`. Good design — avoids redundant walks.

**PY-WL-008 `_has_rejection_path`:** Single walk per function via
`walk_skip_nested_defs`. `_branch_has_rejection_terminator` uses `ast.walk` on
individual branches — bounded by branch size. No quadratic concern.

### Redundant AST Walks

No redundant walks detected. Each rule's `visit_function` does a single primary
walk. Helper functions operate on targeted subtrees.

---

## 5. Python 3.10+ match/case Handling

**PY-WL-007:** Not affected. `match`/`case` does not introduce isinstance or
type() calls into the AST — pattern matching compiles to different AST nodes
(`ast.Match`, `ast.match_case`). No gap.

**PY-WL-008:** `_has_rejection_path` does not check `ast.Match` nodes. A
boundary function using `match`/`case` with a wildcard case that raises would
NOT be recognized as having a rejection path. The `walk_skip_nested_defs` walk
yields `ast.Match` nodes, but they are not `ast.If` or `ast.Raise` at the
top level. However, a `raise` inside a `case` body IS yielded by the walk and IS
caught by the bare `ast.Raise` check on line 87. **Correction:** This is
actually handled — `walk_skip_nested_defs` descends into match-case bodies, and
any `raise` statement found there satisfies the check on line 87. No gap for
`raise` in match/case. A `return` in a case body would also be found by
`_branch_has_rejection_terminator`. The only gap would be a match statement used
as the sole guard (analogous to `if`), which is not checked for negative-guard
semantics — but this is an extremely narrow edge case.

**PY-WL-009:** `_get_semantic_check_nodes` only checks `ast.If` and
`ast.Assert`. A `match data["key"]` performing semantic validation would not be
detected. Minor gap — `match` in validation boundaries is currently uncommon.

---

## 6. Additional Observations

### `_decorator_name` Duplication

`_decorator_name` is independently defined in both `py_wl_008.py` (line 64) and
`py_wl_009.py` (line 72) with identical implementations. Should be extracted to
`base.py` or a shared utility module.

### `walk_skip_nested_defs` vs `ast.walk` Inconsistency

As noted in PY-WL-007 section, the suppression helpers use `ast.walk` while the
main traversal uses `walk_skip_nested_defs`. This is a minor structural
inconsistency. The same pattern appears in PY-WL-008's
`_branch_has_rejection_terminator`.

### `strict=False` on zip

Line 48 of `py_wl_008.py` uses `strict=False` on `zip(expr.ops,
expr.comparators)`. Since CPython guarantees these lists have the same length,
`strict=True` would be a stronger correctness assertion, though the difference
is academic.

---

## Verdict: PASS

All three rules are structurally sound with correct AST handling for their
documented scope. The identified concerns are:

1. **Low:** `ast.walk` vs `walk_skip_nested_defs` inconsistency in suppression
   helpers (PY-WL-007 lines 67, 79; PY-WL-008 line 56) — nested-function
   content can influence parent-function suppression/rejection decisions. Risk is
   negligible due to required condition conjunctions.

2. **Low:** `_decorator_name` duplicated across PY-WL-008 and PY-WL-009 — DRY
   violation, no behavioral impact.

3. **Low:** PY-WL-009 same-line `stop_line` edge case with `>=` comparison —
   semicolon-separated statements are vanishingly rare and the behavior errs on
   the side of flagging.

4. **Informational:** match/case not handled as a semantic check source in
   PY-WL-009, though rejection via raise/return in match bodies IS correctly
   found by PY-WL-008's walk.

None of these rise to CONCERN level. The code is well-structured, idiomatically
Pythonic, and free of correctness bugs in practical scenarios.
