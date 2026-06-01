# L2 `match`-Statement Taint Handling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the L2 under-taint where `compute_variable_taints` ignores `match` statements — so assignments and capture-pattern bindings inside `match`/`case` arms propagate taint to locals, eliminating the `assign-tainted-in-arm → return-the-var-later` false negative that lets a real leak slip past PY-WL-101.

**Architecture:** Add an `ast.Match` branch to `variable_level._process_stmt`, handled by a new `_handle_match` that mirrors the existing snapshot-branch-join pattern (`_handle_if`/`_handle_try`): resolve the subject (for walrus + capture taint), walk each case body on a copy of the pre-match state seeded with that case's capture-pattern bindings (each bound name → the subject's taint, conservative), include the implicit no-match fall-through (pre-match state) as a branch, and `taint_join`-merge all branches per variable. Capture-pattern target names are extracted by a recursive `_collect_pattern_targets` covering every binding node (`MatchAs`, `MatchStar`, `MatchSequence`, `MatchMapping`+`rest`, `MatchClass` positional+kwd, `MatchOr`).

**Tech Stack:** Python 3.12 stdlib `ast`; existing `wardline.core.taints` (`taint_join`); reuses `variable_level`'s `_resolve_expr`/`_walk_body`. Pure, in-file change to one module + tests.

**Why subject taint (conservative) for captures:** element-precise extraction (e.g. taking `subject[0]`'s taint for `case [a, *_]`) is more precise but not modelled at L2; assigning the whole subject's taint to every bound name is a safe over-approximation (never under-taints — the dangerous direction). Documented as the chosen approximation.

**Why include the no-match fall-through branch:** even with an irrefutable `case _`, joining the pre-match state is taint-safe (`taint_join` only moves toward less-trusted / `MIXED_RAW`); it correctly models variables assigned in only some arms and the no-arm-matched path. This matches `_handle_if`'s "no else → else branch is pre-if state" treatment.

> **IMPLEMENTER CONSTRAINT — NO GIT.** Never run ANY `git` command (not `add`/`commit`/`status`/`diff`/`log`/`stash`/`checkout`/`restore`/`reset`/`rm`/`branch`/`switch`/`merge`/`push`/`pull` — none). The controller does ALL git. Edit files only. Always use `.venv/bin/python` / `.venv/bin/pytest` / `.venv/bin/ruff` / `.venv/bin/mypy`, never bare tools.

---

## File Structure

- Modify `src/wardline/scanner/taint/variable_level.py` — add `_collect_pattern_targets` + `_handle_match`; add an `ast.Match` branch to `_process_stmt`.
- Test `tests/unit/scanner/taint/test_variable_level.py` — unit tests for the new behavior.
- Test `tests/unit/scanner/rules/test_untrusted_reaches_trusted.py` — end-to-end regression: the assign-in-arm → return-var-later leak now fires PY-WL-101.

No other files change. `compute_return_taint` already descends into match arms (fixed in SP2c), so once `_handle_match` tracks the assignments, both the direct-return-in-arm and the assign-then-return-var paths are covered.

---

### Task 1: Capture-pattern target extraction

**Files:**
- Modify: `src/wardline/scanner/taint/variable_level.py`
- Test: `tests/unit/scanner/taint/test_variable_level.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/scanner/taint/test_variable_level.py`:

```python
def test_collect_pattern_targets_covers_all_binding_shapes() -> None:
    import ast

    from wardline.scanner.taint.variable_level import _collect_pattern_targets

    def targets(pattern_src: str) -> set[str]:
        # parse `match _:\n case <pattern>: pass` and pull the case pattern
        m = ast.parse(f"match x:\n case {pattern_src}:\n  pass\n").body[0]
        return _collect_pattern_targets(m.cases[0].pattern)  # type: ignore[attr-defined]

    assert targets("1") == set()                      # MatchValue — no binding
    assert targets("_") == set()                      # wildcard — no binding
    assert targets("y") == {"y"}                      # MatchAs capture
    assert targets("[a, b]") == {"a", "b"}            # MatchSequence
    assert targets("[a, *rest]") == {"a", "rest"}     # MatchStar
    assert targets("Point(x=px, y=py)") == {"px", "py"}    # MatchClass kwd patterns
    assert targets("Point(px, py)") == {"px", "py"}        # MatchClass positional
    assert targets("{'k': v, **others}") == {"v", "others"}  # MatchMapping + rest
    assert targets("Point() as whole") == {"whole"}   # MatchAs with sub-pattern
    assert targets("[a] | (b)") == {"a", "b"}         # MatchOr — union of alternatives
    assert targets("1 | 2") == set()                  # MatchOr of values — no binding
```

- [ ] **Step 2: Run it; expect failure**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_variable_level.py::test_collect_pattern_targets_covers_all_binding_shapes -q`
Expected: FAIL — `_collect_pattern_targets` does not exist.

- [ ] **Step 3: Implement `_collect_pattern_targets`**

Add to `variable_level.py` (place it in the "Control flow handlers" section, just above `_handle_match` which Task 2 adds; for now add it anywhere after `_assign_target`). It must be `set`-returning and recursive:

```python
def _collect_pattern_targets(pattern: ast.pattern) -> set[str]:
    """Collect every name a ``match`` *pattern* binds (capture targets).

    Recurses through all binding-bearing pattern nodes. ``MatchValue`` /
    ``MatchSingleton`` bind nothing; ``MatchAs``/``MatchStar`` carry an optional
    ``name`` (``None`` for ``_`` / ``*_``); the rest nest sub-patterns. Python
    requires every ``MatchOr`` alternative to bind the same names, so the union is
    well-defined.
    """
    names: set[str] = set()
    if isinstance(pattern, ast.MatchAs):
        if pattern.name is not None:
            names.add(pattern.name)
        if pattern.pattern is not None:
            names |= _collect_pattern_targets(pattern.pattern)
    elif isinstance(pattern, ast.MatchStar):
        if pattern.name is not None:
            names.add(pattern.name)
    elif isinstance(pattern, ast.MatchSequence):
        for sub in pattern.patterns:
            names |= _collect_pattern_targets(sub)
    elif isinstance(pattern, ast.MatchMapping):
        for sub in pattern.patterns:
            names |= _collect_pattern_targets(sub)
        if pattern.rest is not None:
            names.add(pattern.rest)
    elif isinstance(pattern, ast.MatchClass):
        for sub in (*pattern.patterns, *pattern.kwd_patterns):
            names |= _collect_pattern_targets(sub)
    elif isinstance(pattern, ast.MatchOr):
        for sub in pattern.patterns:
            names |= _collect_pattern_targets(sub)
    # MatchValue / MatchSingleton: no bindings.
    return names
```

- [ ] **Step 4: Run; expect PASS**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_variable_level.py::test_collect_pattern_targets_covers_all_binding_shapes -q`
Expected: PASS.

- [ ] **Step 5: Lint/type**

Run: `.venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: clean.

---

### Task 2: `_handle_match` + dispatch wiring

**Files:**
- Modify: `src/wardline/scanner/taint/variable_level.py`
- Test: `tests/unit/scanner/taint/test_variable_level.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/unit/scanner/taint/test_variable_level.py` (the module already has the `_vt` helper: `_vt(src, function_taint=..., taint_map=...)` returning the var-taint dict):

```python
def test_match_arm_assignment_merges_across_arms() -> None:
    # x assigned raw in one arm, integral in another; join + the no-match
    # fall-through (pre-match x=INTEGRAL) -> MIXED_RAW (cross-family clash).
    src = (
        "def f(p):\n"
        "    x = 1\n"
        "    match p:\n"
        "        case 1:\n"
        "            x = tainted()\n"
        "        case _:\n"
        "            x = 2\n"
    )
    out = _vt(src, function_taint=T.INTEGRAL, taint_map={"tainted": T.EXTERNAL_RAW})
    assert out["x"] == T.MIXED_RAW


def test_match_capture_binds_subject_taint() -> None:
    # `case y:` binds y to the subject's taint (conservative: whole-subject taint).
    src = "def f(p):\n    match tainted():\n        case y:\n            z = y\n"
    out = _vt(src, function_taint=T.INTEGRAL, taint_map={"tainted": T.EXTERNAL_RAW})
    assert out["z"] == T.EXTERNAL_RAW


def test_match_sequence_and_class_captures_bind_subject_taint() -> None:
    seq = _vt(
        "def f(p):\n    match tainted():\n        case [a, b]:\n            z = a\n",
        function_taint=T.INTEGRAL, taint_map={"tainted": T.EXTERNAL_RAW},
    )
    assert seq["z"] == T.EXTERNAL_RAW
    cls = _vt(
        "def f(p):\n    match tainted():\n        case Point(x=px):\n            z = px\n",
        function_taint=T.INTEGRAL, taint_map={"tainted": T.EXTERNAL_RAW},
    )
    assert cls["z"] == T.EXTERNAL_RAW


def test_match_guard_walrus_is_captured() -> None:
    # A walrus in a case guard binds the enclosing scope (evaluated when testing
    # the arm). Pin it like the if/try walrus handling.
    src = "def f(p):\n    match p:\n        case 1 if (w := tainted()):\n            z = w\n"
    out = _vt(src, function_taint=T.INTEGRAL, taint_map={"tainted": T.EXTERNAL_RAW})
    assert out["w"] == T.EXTERNAL_RAW


def test_match_subject_walrus_is_captured() -> None:
    src = "def f(p):\n    match (s := tainted()):\n        case _:\n            pass\n"
    out = _vt(src, function_taint=T.INTEGRAL, taint_map={"tainted": T.EXTERNAL_RAW})
    assert out["s"] == T.EXTERNAL_RAW


def test_match_does_not_descend_into_nested_function() -> None:
    src = (
        "def f(p):\n"
        "    match p:\n"
        "        case 1:\n"
        "            def inner():\n"
        "                y = tainted()\n"
        "            x = 1\n"
    )
    out = _vt(src, function_taint=T.INTEGRAL, taint_map={"tainted": T.EXTERNAL_RAW})
    assert "x" in out
    assert "y" not in out  # nested scope is its own entity
```

- [ ] **Step 2: Run; expect failure**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_variable_level.py -k match -q`
Expected: the new tests FAIL (match arms currently fall through to the walrus-only `else` branch, so `x` stays INTEGRAL, captures are unbound, etc.).

- [ ] **Step 3: Wire `ast.Match` into `_process_stmt`**

In `_process_stmt`, add a branch alongside the other control-flow handlers (e.g. after the `ast.Try` branch, before the `ast.Expr` branch):

```python
    elif isinstance(stmt, ast.Match):
        _handle_match(stmt, function_taint, taint_map, var_taints)
```

- [ ] **Step 4: Implement `_handle_match`**

Add to `variable_level.py` in the "Control flow handlers" section (near `_handle_try`):

```python
def _handle_match(
    stmt: ast.Match,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> None:
    """Handle ``match``/``case`` — snapshot, walk each arm on a copy seeded with
    that arm's capture bindings, then join all arms with the no-match fall-through.

    Each capture-pattern target is bound to the *subject's* taint (a conservative
    whole-subject over-approximation — element-precise extraction is not modelled
    at L2; this never under-taints). The pre-match state is included as an extra
    branch to model the no-arm-matched path and variables assigned in only some
    arms; including it is taint-safe (``taint_join`` only moves toward less-trusted)
    and mirrors :func:`_handle_if`'s implicit-else treatment.
    """
    # Subject is evaluated once, before any arm — resolve it for walrus side
    # effects and to obtain the taint that capture targets inherit.
    subject_taint = _resolve_expr(stmt.subject, function_taint, taint_map, var_taints)

    pre_match = dict(var_taints)
    branches: list[dict[str, TaintState]] = []
    for case in stmt.cases:
        case_taints = dict(pre_match)
        for name in _collect_pattern_targets(case.pattern):
            case_taints[name] = subject_taint
        if case.guard is not None:
            # The guard is tested with the arm's captures in scope; resolve it for
            # walrus side effects (binds into this arm's state).
            _resolve_expr(case.guard, function_taint, taint_map, case_taints)
        _walk_body(case.body, function_taint, taint_map, case_taints)
        branches.append(case_taints)

    # The implicit "no arm matched" path keeps the pre-match state.
    branches.append(pre_match)

    all_vars: set[str] = set()
    for branch in branches:
        all_vars.update(branch)
    for var in all_vars:
        vals = [branch[var] for branch in branches if var in branch]
        merged = vals[0]
        for v in vals[1:]:
            merged = taint_join(merged, v)
        var_taints[var] = merged
```

- [ ] **Step 5: Run the new tests + the whole module**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_variable_level.py -q`
Expected: PASS (all, including the new match tests and the SP2c `test_compute_return_taint_reaches_match_and_except_returns`).

- [ ] **Step 6: Lint/type**

Run: `.venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: clean.

---

### Task 3: End-to-end PY-WL-101 regression + self-hosting confirmation

**Files:**
- Test: `tests/unit/scanner/rules/test_untrusted_reaches_trusted.py`

- [ ] **Step 1: Write the failing regression test**

Add to `tests/unit/scanner/rules/test_untrusted_reaches_trusted.py` (reuses the module's `_analyze`/`_run` helpers):

```python
def test_trusted_leaking_raw_via_match_arm_assignment_fires(tmp_path) -> None:
    # The closed L2 gap: a @trusted function that assigns raw to a local inside a
    # match arm and returns the var LATER (not a direct return in the arm). Before
    # L2 match-handling this was a fail-open under-taint that PY-WL-101 missed.
    ctx, _ = _analyze(tmp_path, {
        "io.py": "from wardline.decorators import external_boundary\n"
                 "@external_boundary\ndef read_raw(p):\n    return p\n",
        "svc.py": "from wardline.decorators import trusted\nfrom io import read_raw\n"
                  "@trusted\ndef leaky(p):\n    x = 1\n    match p:\n"
                  "        case 1:\n            x = read_raw(p)\n"
                  "        case _:\n            x = 2\n    return x\n",
    })
    assert ("PY-WL-101", "svc.leaky") in {(f.rule_id, f.qualname) for f in _run(ctx)}
```

- [ ] **Step 2: Run; expect failure (before Task 2) / pass (after)**

Run: `.venv/bin/python -m pytest tests/unit/scanner/rules/test_untrusted_reaches_trusted.py::test_trusted_leaking_raw_via_match_arm_assignment_fires -q`
Expected: PASS once Tasks 1–2 are in (the leak now resolves to `MIXED_RAW` via the arm-merge, which is strictly less-trusted than the declared `INTEGRAL`, so PY-WL-101 fires). If run before Task 2, it FAILS (under-taint) — confirming the test is non-vacuous.

- [ ] **Step 3: Confirm self-hosting still green + full gate**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: ALL PASS. `src/wardline` is undecorated (UNKNOWN_RAW), so the new match-handling cannot introduce DEFECT findings on the codebase itself — the self-hosting gate stays at 0 DEFECT. Report the new total (current baseline before this unit: 550 passed).

---

## Self-Review

**Coverage:** the spec §12 limitation (assign-in-arm → return-var-later misses PY-WL-101) is closed by Task 2 and pinned end-to-end by Task 3. Capture-pattern bindings (the other half of the gap) are covered by Tasks 1–2.

**Type consistency:** `_collect_pattern_targets(pattern: ast.pattern) -> set[str]`; `_handle_match(stmt: ast.Match, …) -> None` matches the other `_handle_*` signatures `(stmt, function_taint, taint_map, var_taints)`. `taint_join` (not `least_trusted`) is the merge operator, consistent with `_handle_if`/`_handle_try`.

**Placeholder scan:** no TBD/TODO; every code step is complete.

**Edge cases handled:** `case _` / `*_` (name `None` → no binding); `MatchOr` union; guard walrus; subject walrus; nested-function non-descent (delegated to `_walk_body`'s existing `FunctionDef`/`ClassDef` skip in `_process_stmt`). Conservative subject-taint binding is documented as the chosen (never-under-taint) approximation.
