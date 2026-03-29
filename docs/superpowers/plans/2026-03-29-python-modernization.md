# Python Modernization: Dead Code Removal, match/case, type Aliases

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove `_AST_TRY_STAR` dead code from scanner rules, convert the best isinstance-chain candidates to `match/case`, and adopt the `type` statement for type aliases — all within the existing `>=3.12` floor.

**Architecture:** Three independent cleanup streams that touch non-overlapping code. Dead code removal simplifies `base.py` and 3 rule files. `match/case` rewrites target statement-dispatch functions in `variable_level.py` and `py_wl_006.py`. Type alias adoption is a single-line change in `function_level.py`.

**Tech Stack:** Python 3.12+ (`match/case` since 3.10, `type` statement since 3.12), pytest, ruff, mypy

---

### Task 1: Remove `_AST_TRY_STAR` dead code from `base.py`

`ast.TryStar` was a Python 3.11-only AST node merged back into `ast.Try` in 3.12. The `_AST_TRY_STAR` guard, `trystar_ids` tracking set, and dual isinstance paths are all dead code under `>=3.12`.

**Files:**
- Modify: `src/wardline/scanner/rules/base.py:33-36` (remove `_AST_TRY_STAR` definition)
- Modify: `src/wardline/scanner/rules/base.py:97-112` (simplify `iter_exception_handlers`)
- Test: `tests/unit/scanner/test_rules.py:206-226` (update `TestTryStar` class)

- [ ] **Step 1: Run existing tests to establish baseline**

Run: `uv run pytest tests/unit/scanner/test_rules.py tests/unit/scanner/test_py_wl_004.py tests/unit/scanner/test_py_wl_005.py tests/unit/scanner/test_py_wl_006.py -v --tb=short`
Expected: All PASS

- [ ] **Step 2: Remove `_AST_TRY_STAR` constant and simplify `iter_exception_handlers`**

In `src/wardline/scanner/rules/base.py`, remove lines 33-36:

```python
# Python 3.11 introduced ast.TryStar for ``except*``. Python 3.12 merged
# it back into ast.Try, so TryStar may not exist. Cache at module level
# to avoid repeated getattr() inside hot rule loops.
_AST_TRY_STAR: type | None = getattr(ast, "TryStar", None)
```

Replace the `iter_exception_handlers` function (lines 97-112) with:

```python
def iter_exception_handlers(node: ast.AST) -> Iterator[ast.ExceptHandler]:
    """Yield all ExceptHandler nodes under *node*, skipping nested defs."""
    for child in walk_skip_nested_defs(node):
        if isinstance(child, ast.ExceptHandler):
            yield child
```

Update the docstring/comments accordingly — the TryStar dedup logic is gone because `ast.TryStar` doesn't exist in 3.12+.

- [ ] **Step 3: Update test_rules.py `TestTryStar`**

In `tests/unit/scanner/test_rules.py`, replace the `TestTryStar` class (lines 203-226):

```python
# ── except* syntax ──────────────────────────────────────────────


class TestExceptStar:
    """except* syntax parses and rules visit the enclosing function."""

    def test_except_star_parseable(self) -> None:
        """except* syntax parses correctly."""
        source = textwrap.dedent("""\
            def handler():
                try:
                    pass
                except* ValueError:
                    pass
        """)
        tree = ast.parse(source)
        rule = _ValidRule()
        rule.visit(tree)
        assert ("handler", False) in rule.visited
```

The `test_try_star_node_exists` test asserted `hasattr(ast, "TryStar")` — this is a fact about 3.11/3.12 internals that isn't our concern. Delete it.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/unit/scanner/test_rules.py tests/unit/scanner/test_py_wl_005.py -v --tb=short`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/wardline/scanner/rules/base.py tests/unit/scanner/test_rules.py
git commit -m "refactor: remove dead _AST_TRY_STAR code from base.py

ast.TryStar was a Python 3.11-only node merged back into ast.Try in 3.12.
The guard, trystar_ids tracking, and dual isinstance paths were dead code
under the >=3.12 floor. Simplifies iter_exception_handlers to a plain walk."
```

---

### Task 2: Remove `_AST_TRY_STAR` dead code from `py_wl_004.py`

**Files:**
- Modify: `src/wardline/scanner/rules/py_wl_004.py:16` (remove `_AST_TRY_STAR` import)
- Modify: `src/wardline/scanner/rules/py_wl_004.py:40-48` (simplify `visit_function`)
- Test: `tests/unit/scanner/test_py_wl_004.py`

- [ ] **Step 1: Remove the import and simplify `visit_function`**

In `src/wardline/scanner/rules/py_wl_004.py`, change the import on line 16 from:

```python
from wardline.scanner.rules.base import _AST_TRY_STAR, RuleBase, walk_skip_nested_defs
```

to:

```python
from wardline.scanner.rules.base import RuleBase, iter_exception_handlers, walk_skip_nested_defs
```

Replace the `visit_function` method body (lines 40-48) with:

```python
    def visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> None:
        """Walk the function body looking for PY-WL-004 patterns."""
        for child in iter_exception_handlers(node):
            self._check_handler(child, node)
        for child in walk_skip_nested_defs(node):
            if isinstance(child, ast.Call):
                self._check_suppress_call(child, node)
```

Note: we split into two passes because `iter_exception_handlers` and `walk_skip_nested_defs` both walk the tree — but `_check_suppress_call` only cares about `ast.Call` nodes, not handlers. This keeps handler dedup inside `iter_exception_handlers` and suppress checking in its own pass.

- [ ] **Step 2: Run tests**

Run: `uv run pytest tests/unit/scanner/test_py_wl_004.py -v --tb=short`
Expected: All PASS

- [ ] **Step 3: Commit**

```bash
git add src/wardline/scanner/rules/py_wl_004.py
git commit -m "refactor: remove dead _AST_TRY_STAR code from py_wl_004"
```

---

### Task 3: Remove `_AST_TRY_STAR` dead code from `py_wl_006.py`

**Files:**
- Modify: `src/wardline/scanner/rules/py_wl_006.py:20` (remove `_AST_TRY_STAR` import)
- Modify: `src/wardline/scanner/rules/py_wl_006.py:178-200` (simplify `visit_function` Pass 1+2)
- Test: `tests/unit/scanner/test_py_wl_006.py`

- [ ] **Step 1: Remove the import and simplify the two-pass handler logic**

In `src/wardline/scanner/rules/py_wl_006.py`, change line 20 from:

```python
from wardline.scanner.rules.base import (
    _AST_TRY_STAR,
    RuleBase,
    call_name,
    decorator_name,
    receiver_name,
    walk_skip_nested_defs,
)
```

to:

```python
from wardline.scanner.rules.base import (
    RuleBase,
    call_name,
    decorator_name,
    iter_exception_handlers,
    receiver_name,
    walk_skip_nested_defs,
)
```

Replace the two-pass handler logic in `visit_function` (lines 185-200) with a single pass:

```python
        # ── Check broad handlers for masked audit calls ──
        for handler in iter_exception_handlers(node):
            self._check_broad_handler_for_audit(handler)
```

This replaces ~16 lines of TryStar dedup with a single call to the now-simplified `iter_exception_handlers`.

- [ ] **Step 2: Run tests**

Run: `uv run pytest tests/unit/scanner/test_py_wl_006.py -v --tb=short`
Expected: All PASS

- [ ] **Step 3: Commit**

```bash
git add src/wardline/scanner/rules/py_wl_006.py
git commit -m "refactor: remove dead _AST_TRY_STAR code from py_wl_006"
```

---

### Task 4: Convert `_process_stmt` in `variable_level.py` to match/case

This is the strongest candidate — a 12-branch isinstance dispatch with an else fallback, operating on `ast.stmt` subtypes. This is exactly what structural pattern matching was designed for.

**Files:**
- Modify: `src/wardline/scanner/taint/variable_level.py:262-314`
- Test: `tests/unit/scanner/test_variable_level_taint.py` (existing)

- [ ] **Step 1: Run existing tests to establish baseline**

Run: `uv run pytest tests/unit/scanner/test_variable_level_taint.py -v --tb=short`
Expected: All PASS

- [ ] **Step 2: Convert `_process_stmt` to match/case**

Replace the isinstance chain in `_process_stmt` (lines 262-314) with:

```python
def _process_stmt(
    stmt: ast.stmt,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
    dep_dotted: dict[str, TaintState] | None,
    dep_prefixes: frozenset[str],
) -> None:
    """Process a single statement, dispatching by type."""
    match stmt:
        case ast.Assign():
            _handle_assign(stmt, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)

        case ast.AugAssign():
            _handle_augassign(stmt, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)

        case ast.AnnAssign(value=value, target=ast.Name(id=name)) if value is not None:
            taint = _resolve_expr(value, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)
            var_taints[name] = taint

        case ast.AnnAssign(value=value) if value is not None:
            _resolve_expr(value, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)

        case ast.For():
            _handle_for(stmt, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)

        case ast.While():
            _handle_while(stmt, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)

        case ast.If():
            _handle_if(stmt, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)

        case ast.With() | ast.AsyncWith():
            _handle_with(stmt, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)

        case ast.Try():
            _handle_try(stmt, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)

        case ast.Expr(value=value):
            # Expression statement — walk for side-effects (walrus operators).
            _resolve_expr(value, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)

        case ast.FunctionDef() | ast.AsyncFunctionDef():
            pass  # Nested function — don't descend (separate scope).

        case ast.ClassDef():
            pass  # Nested class — don't descend (separate scope).

        case _:
            # Return, Raise, Import, Pass, Break, Continue, etc.
            _walk_exprs_for_walrus(stmt, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)
```

Key design note: the `AnnAssign` case is split into two match arms — one that destructures to `ast.Name` target (updating `var_taints`), and a fallback that still resolves the value expression for side effects (walrus operators). The original code only processed `AnnAssign` when `value is not None` and only updated `var_taints` when the target was `ast.Name` — but it silently dropped the `_resolve_expr` call when the target wasn't `ast.Name`. The second arm preserves this by still calling `_resolve_expr` for walrus operator side effects.

- [ ] **Step 3: Run tests**

Run: `uv run pytest tests/unit/scanner/test_variable_level_taint.py -v --tb=short`
Expected: All PASS

- [ ] **Step 4: Run mypy**

Run: `uv run mypy src/wardline/scanner/taint/variable_level.py`
Expected: No errors

- [ ] **Step 5: Commit**

```bash
git add src/wardline/scanner/taint/variable_level.py
git commit -m "refactor: convert _process_stmt isinstance chain to match/case

Structural pattern matching is a natural fit for AST node type dispatch.
The AnnAssign case now also resolves values when target is not ast.Name
(walrus operator side effects), fixing a subtle omission."
```

---

### Task 5: Convert `_analyze_stmt` in `py_wl_006.py` to match/case

Another strong candidate — 7-branch isinstance dispatch on `ast.stmt` subtypes with a default fallback.

**Files:**
- Modify: `src/wardline/scanner/rules/py_wl_006.py:270-294`
- Test: `tests/unit/scanner/test_py_wl_006.py` (existing)

- [ ] **Step 1: Convert `_analyze_stmt` to match/case**

Replace the isinstance chain in `_analyze_stmt` (lines 270-294) with:

```python
    def _analyze_stmt(
        self,
        stmt: ast.stmt,
        *,
        audited: bool,
    ) -> _BlockAnalysis:
        """Analyze one statement under the given incoming audit state."""
        match stmt:
            case ast.Return():
                return self._analyze_return(stmt, audited=audited)
            case ast.Raise():
                return _BlockAnalysis()
            case ast.If():
                return self._analyze_if(stmt, audited=audited)
            case ast.Try():
                return self._analyze_try(stmt, audited=audited)
            case ast.For() | ast.AsyncFor() | ast.While():
                return self._analyze_loop(stmt, audited=audited)
            case ast.Match():
                return self._analyze_match(stmt, audited=audited)
            case _:
                next_audited = audited or _contains_audit_call(
                    stmt,
                    self._local_audit_names,
                )
                return _BlockAnalysis(continue_states=frozenset({next_audited}))
```

- [ ] **Step 2: Run tests**

Run: `uv run pytest tests/unit/scanner/test_py_wl_006.py -v --tb=short`
Expected: All PASS

- [ ] **Step 3: Commit**

```bash
git add src/wardline/scanner/rules/py_wl_006.py
git commit -m "refactor: convert _analyze_stmt isinstance chain to match/case"
```

---

### Task 6: Convert `_has_normal_path_audit` in `py_wl_006.py` to match/case

Same function — 5-branch isinstance dispatch on statement types.

**Files:**
- Modify: `src/wardline/scanner/rules/py_wl_006.py:109-149`
- Test: `tests/unit/scanner/test_py_wl_006.py` (existing)

- [ ] **Step 1: Convert `_has_normal_path_audit` to match/case**

Replace the isinstance chain (lines 119-149) with:

```python
def _has_normal_path_audit(
    stmts: list[ast.stmt],
    local_audit_names: frozenset[str],
) -> bool:
    """Return True when audit appears on a non-handler path.

    This keeps the dominance pass focused on "success can bypass audit"
    scenarios instead of double-reporting functions that only audit in
    exception handlers.
    """
    for stmt in stmts:
        match stmt:
            case ast.Try():
                if _has_normal_path_audit(stmt.body, local_audit_names):
                    return True
                if _has_normal_path_audit(stmt.orelse, local_audit_names):
                    return True
                if _has_normal_path_audit(stmt.finalbody, local_audit_names):
                    return True
            case ast.If():
                if _has_normal_path_audit(stmt.body, local_audit_names):
                    return True
                if _has_normal_path_audit(stmt.orelse, local_audit_names):
                    return True
            case ast.Match():
                if any(
                    _has_normal_path_audit(case.body, local_audit_names)
                    for case in stmt.cases
                ):
                    return True
            case ast.For() | ast.AsyncFor() | ast.While():
                if _has_normal_path_audit(stmt.body, local_audit_names):
                    return True
                if _has_normal_path_audit(stmt.orelse, local_audit_names):
                    return True
            case _ if _contains_audit_call(stmt, local_audit_names):
                return True
    return False
```

- [ ] **Step 2: Run tests**

Run: `uv run pytest tests/unit/scanner/test_py_wl_006.py -v --tb=short`
Expected: All PASS

- [ ] **Step 3: Commit**

```bash
git add src/wardline/scanner/rules/py_wl_006.py
git commit -m "refactor: convert _has_normal_path_audit to match/case"
```

---

### Task 7: Adopt `type` statement for `TaintSource` alias

**Files:**
- Modify: `src/wardline/scanner/taint/function_level.py:31`

- [ ] **Step 1: Convert to `type` statement**

In `src/wardline/scanner/taint/function_level.py`, replace line 31:

```python
TaintSource = Literal["decorator", "module_default", "fallback"]
```

with:

```python
type TaintSource = Literal["decorator", "module_default", "fallback"]
```

Also update the `typing` import on line 21 — `Literal` is still needed (it's the RHS), but confirm it's still imported. The import `from typing import TYPE_CHECKING, Literal, NamedTuple` stays the same.

- [ ] **Step 2: Run tests and mypy**

Run: `uv run pytest tests/unit/scanner/ -v --tb=short -q` and `uv run mypy src/wardline/scanner/taint/function_level.py`
Expected: All PASS, no mypy errors

- [ ] **Step 3: Commit**

```bash
git add src/wardline/scanner/taint/function_level.py
git commit -m "refactor: adopt type statement for TaintSource alias"
```

---

### Task 8: Final validation

- [ ] **Step 1: Run full test suite**

Run: `uv run pytest --tb=short -q`
Expected: All PASS, same count as baseline

- [ ] **Step 2: Run ruff**

Run: `uv run ruff check src/`
Expected: Clean

- [ ] **Step 3: Run mypy**

Run: `uv run mypy src/`
Expected: Clean

- [ ] **Step 4: Run self-hosting scan**

Run: `uv run wardline scan src/`
Expected: No new findings from the refactored rules
