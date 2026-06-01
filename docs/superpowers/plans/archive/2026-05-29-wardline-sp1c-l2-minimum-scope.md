# SP1c — L2 Variable-Level Taint + Minimum-Scope Bounded Propagation (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.
>
> **GIT PROHIBITION (controller-enforced):** Implementer/reviewer subagents MUST NEVER run any git command — no `git add/commit/stash/checkout/restore/reset/rm/branch/switch`. They write files, run tests, report. **The controller does every commit.**

**Goal:** Land L2 intra-function variable-level taint propagation (`compute_variable_taints`) and the bounded one-hop cross-file "minimum-scope" refinement (`build_minimum_scope_edges` + `refine_minimum_scope_taints`), plus the `resolve_call_fqn` primitive minimum-scope needs.

**Architecture:** Both modules port `.old`'s governance-free taint algebra (stdlib + `core.taints` only). L2 walks a function body, computing per-variable taint through assignments, control-flow joins (snapshot-branch-`taint_join`), and call-site resolution against a caller-supplied `taint_map`. Minimum-scope builds project-local call edges and refines a function's L1 taint using callees' taints, bounded to one undecorated intermediary (the full transitive SCC engine is SP1d). `.old`'s manifest-coupled features are dropped; `.old`'s decorator vocabulary becomes SP1b's `FunctionSeed.source`.

**Tech Stack:** Python 3.12; `ast` + `wardline.core.taints` + `wardline.scanner.{index,ast_primitives}`. pytest, ruff, mypy strict. Use `.venv/bin/python` for all commands.

**Source:** `.old` `scanner/taint/variable_level.py`, `scanner/taint/minimum_scope.py`, `scanner/import_resolver.py:73-98` (`resolve_call_fqn`).

**SP1 design spec:** `docs/superpowers/specs/2026-05-29-wardline-sp1-analyzer-core-design.md` §2 (L2 + minimum-scope), §4.5 (discards), §6 (SP1c row).

**Branch:** `sp1c-l2-minimum-scope` (already created off `main`).

---

## Generalization & scope decisions (read before coding)

1. **Drop `.old`'s manifest dependency params.** `compute_variable_taints` in `.old` takes `dependency_dotted_map` + `dependency_local_prefixes` (the manifest `dependency_taint` overlay + its §6.5 declared-package fallback). SP1 §4.5 discards the manifest tier, and nothing in SP1c populates these. **Remove both params** and the two `_resolve_call` branches that use them (branches 3 and 4). `.old`'s `test_dependency_taint_resolution` is **deferred to SP1f** — when a real external-dotted-taint channel exists — not silently dropped.
2. **Keep the serialization-sink heuristic verbatim** (`_SERIALISATION_SINKS`). It is a generic, fail-closed heuristic (serialization erases validation provenance), not governance. **Do not trim it.** It overlaps `stdlib_taint.yaml` only on `json.load`/`json.loads` (sink → `UNKNOWN_RAW`; stdlib_taint → `GUARDED`). There is NO live collision in SP1c (stdlib_taint isn't wired into L2 until SP1f). **SP1f forward note (in spec §8):** when both apply, conservative wins — the sink's `UNKNOWN_RAW` overrides `stdlib_taint`'s `GUARDED`.
3. **`taint_map` key contract for L2:** keyed by the **call-site name as written** — a bare name for `foo()` (key `"foo"`) or a dotted name for `mod.fn()` (key `"mod.fn"`) — mapping to that call's **return taint**. Unresolved calls (key absent) fall back to `function_taint`. In SP1c this map is supplied directly by tests; SP1f's engine populates it (project returns + canonicalized stdlib externals). NOTE: this is a *different* map shape from minimum-scope's `seed_taints`, which is keyed by **full qualname**.
4. **Pull `resolve_call_fqn` forward into `ast_primitives.py`.** SP1a deferred the `resolve_*` resolvers to "the consuming stage"; SP1c minimum-scope is that stage. Port **only** `resolve_call_fqn`. Leave `resolve_same_class_call_fqn`/`resolve_nested_call_fqn` unported (no consumer yet; the first lands in SP1d — see #6).
5. **Minimum-scope edge enumeration uses SP1a's `iter_calls_in_function_body`** instead of `.old`'s `rejection_path.iter_reachable_calls`. The only behavioral difference is that `.old` skipped statically-dead branches (`if False:`). Including those calls **over-approximates** edges → can only *over*-taint → **false-positive direction = conservative-safe**. Keep the simpler primitive.
6. **Drop `.old`'s `self.method()` edge resolution in minimum-scope.** It needs the caller's enclosing class name, which `Entity` doesn't store and is fiddly to derive under `<locals>`. Omitting it **under-taints** (a missed `self.raw_method()` edge leaves the caller looking *more trusted than reality* — the false-NEGATIVE direction). This is acceptable here ONLY because **SP1d's full callgraph is the soundness backstop**. **HARD SP1d forward note (in spec §8):** SP1d must port `resolve_same_class_call_fqn` so self-method flows resolve in the full callgraph, or the flow is lost everywhere, not just deferred.

> **Asymmetry to record (so reviewers don't conflate #5 and #6):** dropping dead-branch skipping (#5) over-taints (safe); dropping `self.method()` (#6) under-taints (recovered only by SP1d).

---

## File Structure

| File | Responsibility |
|---|---|
| `src/wardline/scanner/ast_primitives.py` (modify) | add `resolve_call_fqn` |
| `src/wardline/scanner/taint/variable_level.py` (create) | L2 `compute_variable_taints` |
| `src/wardline/scanner/taint/minimum_scope.py` (create) | `ProjectFileData`, `MinimumScopeProvenance`, `build_minimum_scope_edges`, `refine_minimum_scope_taints` |
| `tests/unit/scanner/test_ast_primitives.py` (modify) | `resolve_call_fqn` tests |
| `tests/unit/scanner/taint/test_variable_level.py` (create) | L2 tests |
| `tests/unit/scanner/taint/test_minimum_scope.py` (create) | edges + refinement tests |

---

## Task 1: `resolve_call_fqn` in `ast_primitives.py`

**Files:** Modify `src/wardline/scanner/ast_primitives.py`; modify `tests/unit/scanner/test_ast_primitives.py`.

- [ ] **Step 1: Append the failing tests** to `tests/unit/scanner/test_ast_primitives.py`:

```python
from wardline.scanner.ast_primitives import resolve_call_fqn  # add to existing imports


def _call(src: str) -> ast.Call:
    node = ast.parse(src, mode="eval").body
    assert isinstance(node, ast.Call)
    return node


def test_resolve_bare_name_local_function() -> None:
    fqn = resolve_call_fqn(
        _call("foo()"), {}, frozenset({"pkg.mod.foo"}), "pkg.mod"
    )
    assert fqn == "pkg.mod.foo"


def test_resolve_bare_name_via_import_alias() -> None:
    fqn = resolve_call_fqn(
        _call("check()"), {"check": "other.check"}, frozenset(), "pkg.mod"
    )
    assert fqn == "other.check"


def test_local_takes_precedence_over_import() -> None:
    fqn = resolve_call_fqn(
        _call("foo()"), {"foo": "elsewhere.foo"}, frozenset({"pkg.mod.foo"}), "pkg.mod"
    )
    assert fqn == "pkg.mod.foo"


def test_resolve_bare_name_unresolved() -> None:
    assert resolve_call_fqn(_call("xyz()"), {}, frozenset(), "pkg.mod") is None


def test_resolve_attribute_via_alias() -> None:
    fqn = resolve_call_fqn(
        _call("mod.func()"), {"mod": "pkg.mod"}, frozenset(), "caller.mod"
    )
    assert fqn == "pkg.mod.func"


def test_resolve_attribute_unknown_receiver() -> None:
    # self.m() — 'self' is not in the alias map → unresolved
    assert resolve_call_fqn(_call("self.m()"), {}, frozenset(), "pkg.mod") is None
```

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/python -m pytest tests/unit/scanner/test_ast_primitives.py -q -k resolve`
Expected: FAIL — `ImportError: cannot import name 'resolve_call_fqn'`

- [ ] **Step 3: Add the implementation** to `src/wardline/scanner/ast_primitives.py` (ported verbatim from `.old/scanner/import_resolver.py:73-98`; append after `build_import_alias_map`):

```python
def resolve_call_fqn(
    call: ast.Call,
    alias_map: dict[str, str],
    local_fqns: frozenset[str],
    module_prefix: str,
) -> str | None:
    """Resolve an ``ast.Call`` to a fully-qualified name, or None if unresolvable.

    Resolution order:
      1. A bare name matching a local function FQN (``{module_prefix}.{name}``).
      2. A bare name or attribute receiver found in ``alias_map`` (an import).
      3. Otherwise None.
    """
    if isinstance(call.func, ast.Name):
        bare_name = call.func.id
        local_candidate = f"{module_prefix}.{bare_name}" if module_prefix else bare_name
        if local_candidate in local_fqns:
            return local_candidate
        return alias_map.get(bare_name)

    if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
        prefix_fqn = alias_map.get(call.func.value.id)
        if prefix_fqn is not None:
            return f"{prefix_fqn}.{call.func.attr}"

    return None
```

Also update the module docstring's "(The `resolve_*` call resolvers from `.old` land then.)" line to note `resolve_call_fqn` now lives here (the same-class/nested resolvers remain SP1d).

- [ ] **Step 4: Run to verify pass**

Run: `.venv/bin/python -m pytest tests/unit/scanner/test_ast_primitives.py -q`
Expected: PASS (existing + 6 new).

- [ ] **Step 5: Controller commits** (`feat(sp1c): port resolve_call_fqn into ast_primitives`).

---

## Task 2: L2 `variable_level.py`

**Files:** Create `src/wardline/scanner/taint/variable_level.py`; create `tests/unit/scanner/taint/test_variable_level.py`.

- [ ] **Step 1: Write the failing test** (`tests/unit/scanner/taint/test_variable_level.py`). All expected values below were verified against the repo's `taint_join`.

```python
from __future__ import annotations

import ast

from wardline.core.taints import TaintState
from wardline.scanner.taint.variable_level import compute_variable_taints

T = TaintState


def _vt(
    src: str,
    function_taint: TaintState = T.UNKNOWN_RAW,
    taint_map: dict[str, TaintState] | None = None,
) -> dict[str, TaintState]:
    func = ast.parse(src).body[0]
    assert isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef)
    return compute_variable_taints(func, function_taint, taint_map or {})


def test_literal_is_integral() -> None:
    assert _vt("def f():\n    x = 42\n")["x"] == T.INTEGRAL


def test_parameters_inherit_function_taint() -> None:
    out = _vt("def f(a, b, *c, **d):\n    pass\n", function_taint=T.EXTERNAL_RAW)
    assert out["a"] == out["b"] == out["c"] == out["d"] == T.EXTERNAL_RAW


def test_binop_joins_operands() -> None:
    # a=INTEGRAL, p=function_taint(UNKNOWN_RAW); INTEGRAL ⋈ UNKNOWN_RAW = MIXED_RAW
    out = _vt("def f(p):\n    a = 42\n    b = a + p\n", function_taint=T.UNKNOWN_RAW)
    assert out["a"] == T.INTEGRAL
    assert out["b"] == T.MIXED_RAW


def test_collection_joins_elements_and_empty_is_integral() -> None:
    out = _vt("def f(p):\n    x = [42, p]\n    y = []\n", function_taint=T.EXTERNAL_RAW)
    assert out["x"] == T.MIXED_RAW  # INTEGRAL ⋈ EXTERNAL_RAW
    assert out["y"] == T.INTEGRAL


def test_ternary_joins_branches() -> None:
    out = _vt("def f(p):\n    x = 42 if cond else p\n", function_taint=T.EXTERNAL_RAW)
    assert out["x"] == T.MIXED_RAW


def test_if_else_merges_branches() -> None:
    src = "def f(p):\n    if c:\n        x = 42\n    else:\n        x = p\n"
    assert _vt(src, function_taint=T.EXTERNAL_RAW)["x"] == T.MIXED_RAW


def test_if_without_else_merges_with_pre_state() -> None:
    # x assigned only in the if-branch; the implicit else is the pre-if value.
    src = "def f():\n    x = 42\n    if c:\n        x = unknown\n"
    # if-branch: x=unknown→function_taint=GUARDED; else(pre)=INTEGRAL → join
    assert _vt(src, function_taint=T.GUARDED)["x"] == T.MIXED_RAW


def test_try_except_merges_branches() -> None:
    src = (
        "def f():\n"
        "    x = unknown\n"
        "    try:\n"
        "        x = 42\n"
        "    except Exception:\n"
        "        x = 7\n"
    )
    # try→INTEGRAL, handler→INTEGRAL → join = INTEGRAL
    assert _vt(src, function_taint=T.EXTERNAL_RAW)["x"] == T.INTEGRAL


def test_for_loop_merges_body_with_pre_loop() -> None:
    # loop may not execute: body assignment joins with pre-loop state
    src = "def f(p):\n    x = 42\n    for i in p:\n        x = i\n"
    out = _vt(src, function_taint=T.UNKNOWN_RAW)
    # i gets iterable(p=UNKNOWN_RAW) taint; x = join(INTEGRAL pre, UNKNOWN_RAW body)
    assert out["x"] == T.MIXED_RAW


def test_walrus_assigns_target() -> None:
    out = _vt("def f(p):\n    if (x := p):\n        pass\n", function_taint=T.EXTERNAL_RAW)
    assert out["x"] == T.EXTERNAL_RAW


def test_tuple_unpack_elementwise() -> None:
    out = _vt("def f(p):\n    a, b = 42, p\n", function_taint=T.EXTERNAL_RAW)
    assert out["a"] == T.INTEGRAL
    assert out["b"] == T.EXTERNAL_RAW


def test_aug_assign_joins_existing() -> None:
    out = _vt("def f(p):\n    x = 42\n    x += p\n", function_taint=T.UNKNOWN_RAW)
    assert out["x"] == T.MIXED_RAW


def test_call_bare_name_resolved_via_taint_map() -> None:
    out = _vt("def f():\n    x = helper()\n", taint_map={"helper": T.GUARDED})
    assert out["x"] == T.GUARDED


def test_call_dotted_name_resolved_via_taint_map() -> None:
    out = _vt("def f():\n    x = mod.fn()\n", taint_map={"mod.fn": T.ASSURED})
    assert out["x"] == T.ASSURED


def test_serialisation_sink_sheds_to_unknown_raw() -> None:
    # Even from a fully-trusted context, json.dumps output is UNKNOWN_RAW.
    out = _vt("def f():\n    x = json.dumps(d)\n", function_taint=T.INTEGRAL)
    assert out["x"] == T.UNKNOWN_RAW


def test_unresolved_call_falls_back_to_function_taint() -> None:
    out = _vt("def f():\n    x = mystery()\n", function_taint=T.GUARDED, taint_map={})
    assert out["x"] == T.GUARDED


def test_nested_function_body_is_skipped() -> None:
    src = "def f():\n    x = 42\n    def inner():\n        y = unknown\n"
    out = _vt(src, function_taint=T.UNKNOWN_RAW)
    assert "x" in out
    assert "y" not in out  # nested scope handled as its own entity
```

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_variable_level.py -q`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation.** Two parts.

**(3a) The resolution core — type this EXACTLY** (this is the part where the manifest params were removed; it is the authoritative simplified version):

```python
# src/wardline/scanner/taint/variable_level.py
"""Level 2 taint — per-variable taint tracking within a function body.

Given a function AST node and its Level 1 (function-level) taint, walks the body
tracking taint per variable through assignments, control-flow joins, and call
sites. Pure (returns a new dict); conservative (unknown expressions inherit the
function's L1 taint); join-based (branches merge via ``taint_join``).

Ported from ``wardline.old`` minus the manifest ``dependency_taint`` overlay
(SP1 §4.5): the ``dependency_dotted_map`` / ``dependency_local_prefixes`` params
and their two ``_resolve_call`` branches are removed. Call resolution is solely
against the caller-supplied ``taint_map`` (see ``compute_variable_taints``).
"""

from __future__ import annotations

import ast

from wardline.core.taints import TaintState, taint_join

# Serialisation sinks — calls that cross the representation boundary. Their
# output sheds validation provenance (raw bytes/str), so → UNKNOWN_RAW. This is
# a generic fail-closed heuristic, not governance. (SP1f note: where this and
# stdlib_taint disagree — only json.load/loads — the conservative UNKNOWN_RAW
# wins.)
_SERIALISATION_SINKS: frozenset[str] = frozenset(
    {
        "json.dumps", "json.dump", "json.loads", "json.load",
        "pickle.dumps", "pickle.dump", "pickle.loads", "pickle.load",
        "yaml.dump", "yaml.safe_dump", "yaml.dump_all",
        "yaml.safe_load", "yaml.load", "yaml.safe_load_all", "yaml.load_all",
        "marshal.dumps", "marshal.dump", "marshal.loads", "marshal.load",
        "tomllib.loads", "tomllib.load", "tomli_w.dumps", "tomli_w.dump",
    }
)


def compute_variable_taints(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
) -> dict[str, TaintState]:
    """Compute per-variable taint for a function body.

    Args:
        func_node: the function AST node to analyze.
        function_taint: this function's L1 taint; seeds parameters and is the
            fallback for unknown expressions.
        taint_map: call-resolution map keyed by the call-site name AS WRITTEN —
            bare (``"foo"``) for ``foo()``, dotted (``"mod.fn"``) for
            ``mod.fn()`` — mapping to that call's return taint. Calls whose name
            is absent fall back to ``function_taint``.

    Returns:
        ``{variable_name: TaintState}`` for every assigned variable and parameter
        in the function body. Nested function/class scopes are not descended.
    """
    var_taints: dict[str, TaintState] = {}
    _seed_parameters(func_node, function_taint, var_taints)
    _walk_body(func_node.body, function_taint, taint_map, var_taints)
    return var_taints


def _seed_parameters(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    function_taint: TaintState,
    var_taints: dict[str, TaintState],
) -> None:
    args = func_node.args
    for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs):
        var_taints[arg.arg] = function_taint
    if args.vararg:
        var_taints[args.vararg.arg] = function_taint
    if args.kwarg:
        var_taints[args.kwarg.arg] = function_taint


def _dotted_name(node: ast.expr) -> str | None:
    """Extract a dotted name from an attribute chain (``json.dumps`` → that str)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else None
    return None


def _resolve_expr(
    node: ast.expr,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> TaintState:
    if isinstance(node, ast.Constant):
        return TaintState.INTEGRAL
    if isinstance(node, ast.Name):
        return var_taints.get(node.id, function_taint)
    if isinstance(node, ast.Call):
        return _resolve_call(node, function_taint, taint_map, var_taints)
    if isinstance(node, ast.BinOp):
        left = _resolve_expr(node.left, function_taint, taint_map, var_taints)
        right = _resolve_expr(node.right, function_taint, taint_map, var_taints)
        return taint_join(left, right)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        if not node.elts:
            return TaintState.INTEGRAL
        result = _resolve_expr(node.elts[0], function_taint, taint_map, var_taints)
        for elt in node.elts[1:]:
            result = taint_join(result, _resolve_expr(elt, function_taint, taint_map, var_taints))
        return result
    if isinstance(node, ast.Dict):
        parts = [
            _resolve_expr(v, function_taint, taint_map, var_taints)
            for v in node.values
            if v is not None
        ]
        if not parts:
            return TaintState.INTEGRAL
        result = parts[0]
        for p in parts[1:]:
            result = taint_join(result, p)
        return result
    if isinstance(node, ast.NamedExpr):
        taint = _resolve_expr(node.value, function_taint, taint_map, var_taints)
        if isinstance(node.target, ast.Name):
            var_taints[node.target.id] = taint
        return taint
    if isinstance(node, ast.IfExp):
        true_t = _resolve_expr(node.body, function_taint, taint_map, var_taints)
        false_t = _resolve_expr(node.orelse, function_taint, taint_map, var_taints)
        return taint_join(true_t, false_t)
    if isinstance(node, ast.UnaryOp):
        return _resolve_expr(node.operand, function_taint, taint_map, var_taints)
    # Fallback: attribute access, subscript, comprehensions, etc.
    return function_taint


def _resolve_call(
    node: ast.Call,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> TaintState:
    if isinstance(node.func, ast.Attribute):
        dotted = _dotted_name(node.func)
        if dotted is not None:
            if dotted in _SERIALISATION_SINKS:
                return TaintState.UNKNOWN_RAW
            taint_hit = taint_map.get(dotted)
            if taint_hit is not None:
                return taint_hit
    if isinstance(node.func, ast.Name):
        try:
            return taint_map[node.func.id]
        except KeyError:
            pass
    return function_taint
```

**(3b) The statement walkers.** Port `_walk_body` and every `_handle_*` statement-handler function from `.old/src/wardline/scanner/taint/variable_level.py` (lines ~252–630): `_walk_body`, `_handle_assign`, `_handle_unpack`, `_handle_aug_assign`, `_handle_ann_assign`, `_handle_for`, `_handle_while`, `_handle_if`, `_handle_with`, `_handle_try`, `_handle_expr` (use the actual names in the source). Make **exactly one** mechanical change throughout: **delete the two parameters** `dep_dotted: dict[str, TaintState] | None` and `dep_prefixes: frozenset[str]` from every function signature AND every call site (they thread through every helper). Change nothing else — the snapshot-branch-`taint_join` merge logic for if/try, the pre-loop merge for for/while, walrus handling, tuple unpacking, and the "skip nested def/class" rule must all be preserved exactly. The test oracle above pins the load-bearing behaviors; `mypy --strict` will flag any dangling `dep_dotted`/`dep_prefixes` reference.

- [ ] **Step 4: Run to verify pass**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_variable_level.py -q`
Expected: PASS (all cases). If a control-flow test fails, the handler port drifted — fix the handler, never the oracle.

- [ ] **Step 5: Controller commits** (`feat(sp1c): L2 variable-level taint propagation`).

---

## Task 3: minimum-scope edges — `build_minimum_scope_edges`

**Files:** Create `src/wardline/scanner/taint/minimum_scope.py` (this task adds `ProjectFileData` + `build_minimum_scope_edges`; Task 4 appends the refiner). Create `tests/unit/scanner/taint/test_minimum_scope.py`.

- [ ] **Step 1: Write the failing test:**

```python
# tests/unit/scanner/taint/test_minimum_scope.py
from __future__ import annotations

import ast

from wardline.core.taints import TaintState
from wardline.scanner.ast_primitives import build_import_alias_map
from wardline.scanner.index import discover_file_entities
from wardline.scanner.taint.minimum_scope import (
    MinimumScopeProvenance,
    ProjectFileData,
    build_minimum_scope_edges,
    refine_minimum_scope_taints,
)

T = TaintState


def _file(src: str, module: str, path: str) -> ProjectFileData:
    tree = ast.parse(src)
    return ProjectFileData(
        entities=tuple(discover_file_entities(tree, module=module, path=path)),
        import_aliases=build_import_alias_map(tree, module),
        module_path=module,
    )


def test_edges_resolve_local_bare_call() -> None:
    src = "def caller():\n    callee()\ndef callee():\n    pass\n"
    edges, unresolved = build_minimum_scope_edges([_file(src, "m", "m.py")])
    assert edges["m.caller"] == frozenset({"m.callee"})
    assert unresolved["m.caller"] == 0


def test_edges_resolve_imported_project_function() -> None:
    caller = "from other import helper\ndef caller():\n    helper()\n"
    other = "def helper():\n    pass\n"
    files = [_file(caller, "main", "main.py"), _file(other, "other", "other.py")]
    edges, _ = build_minimum_scope_edges(files)
    assert edges["main.caller"] == frozenset({"other.helper"})


def test_unresolved_call_counted_not_edged() -> None:
    src = "def caller():\n    external_thing()\n"
    edges, unresolved = build_minimum_scope_edges([_file(src, "m", "m.py")])
    assert edges["m.caller"] == frozenset()
    assert unresolved["m.caller"] == 1
```

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_minimum_scope.py -q -k edges or unresolved`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the implementation** (create the file with the imports, `ProjectFileData`, `MinimumScopeProvenance`, and `build_minimum_scope_edges`; the refiner is Task 4):

```python
# src/wardline/scanner/taint/minimum_scope.py
"""Bounded minimum-scope taint propagation: direct flows plus one undecorated
intermediary hop. Intentionally smaller than SP1d's transitive SCC engine — it
is a cheap pre-L3 refinement, and any flow it misses is recovered by SP1d.

Ported from ``wardline.old`` with two simplifications (see the SP1c plan):
  - edges are enumerated via ``iter_calls_in_function_body`` (over-approximates
    by including statically-dead branches — the conservative direction);
  - ``self.method()`` resolution is deferred to SP1d's callgraph (its omission
    under-taints, which only SP1d's full resolution recovers).
The ``.old`` "decorator"-anchored concept maps to SP1b's provider-declared
source (``FunctionSeed.source == "provider"``).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from functools import reduce
from typing import NamedTuple

from wardline.core.taints import TRUST_RANK, TaintState, taint_join
from wardline.scanner.ast_primitives import iter_calls_in_function_body, resolve_call_fqn
from wardline.scanner.index import Entity


class ProjectFileData(NamedTuple):
    """Per-file metadata for bounded call-edge resolution."""

    entities: tuple[Entity, ...]
    import_aliases: dict[str, str]
    module_path: str


@dataclass(frozen=True, slots=True)
class MinimumScopeProvenance:
    """Audit record for a function whose taint the minimum-scope pass changed."""

    via_callee: str | None
    resolved_call_count: int
    unresolved_call_count: int
    source: str = "minimum_scope"


def build_minimum_scope_edges(
    file_data: list[ProjectFileData],
) -> tuple[dict[str, frozenset[str]], dict[str, int]]:
    """Build project-local call edges keyed by caller qualname.

    Resolution (conservative): local bare-name functions and imported/project
    aliases via ``resolve_call_fqn``. Everything else is counted as unresolved.
    """
    global_fqns = frozenset(e.qualname for fd in file_data for e in fd.entities)

    edges: dict[str, frozenset[str]] = {}
    unresolved_counts: dict[str, int] = {}

    for fd in file_data:
        local_fqns = frozenset(e.qualname for e in fd.entities)
        for entity in fd.entities:
            resolved: set[str] = set()
            unresolved = 0
            for call in iter_calls_in_function_body(entity.node):
                callee_fqn = resolve_call_fqn(
                    call, fd.import_aliases, local_fqns, fd.module_path
                )
                if callee_fqn is not None and callee_fqn in global_fqns:
                    resolved.add(callee_fqn)
                else:
                    unresolved += 1
            edges[entity.qualname] = frozenset(resolved)
            unresolved_counts[entity.qualname] = unresolved

    return edges, unresolved_counts
```

- [ ] **Step 4: Run to verify pass**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_minimum_scope.py -q -k "edges or unresolved"`
Expected: PASS (the three edge tests). The refinement tests will error on the missing `refine_minimum_scope_taints` import until Task 4 — that's expected; run only the edge tests here.

- [ ] **Step 5: Controller commits** (`feat(sp1c): minimum-scope call-edge builder`).

---

## Task 4: minimum-scope refinement — `refine_minimum_scope_taints`

**Files:** Modify `src/wardline/scanner/taint/minimum_scope.py` (append the refiner); append tests to `tests/unit/scanner/taint/test_minimum_scope.py`.

- [ ] **Step 1: Append the failing tests.** Expected refined values were derived against the repo's `taint_join`/`TRUST_RANK`. Inputs are FunctionSeed-shaped: `seed_taints` (body taint by qualname), `seed_sources` (`"provider"`/`"default"`), `return_taints` (provider-declared return taint).

```python
def test_one_hop_refines_via_provider_callee() -> None:
    # handler (ASSURED) calls fetch (provider-declared, returns EXTERNAL_RAW)
    refined, prov = refine_minimum_scope_taints(
        target_functions=["m.handler"],
        edges={"m.handler": frozenset({"m.fetch"})},
        seed_taints={"m.handler": T.ASSURED, "m.fetch": T.EXTERNAL_RAW},
        seed_sources={"m.handler": "default", "m.fetch": "provider"},
        return_taints={"m.fetch": T.EXTERNAL_RAW},
        unresolved_counts={"m.handler": 0, "m.fetch": 0},
    )
    assert refined["m.handler"] == T.EXTERNAL_RAW
    assert prov["m.handler"].via_callee == "m.fetch"
    assert prov["m.handler"].source == "minimum_scope"


def test_two_hop_through_undecorated_intermediary() -> None:
    # handler → helper(default) → raw(provider, EXTERNAL_RAW)
    refined, _ = refine_minimum_scope_taints(
        target_functions=["m.handler"],
        edges={"m.handler": frozenset({"m.helper"}), "m.helper": frozenset({"m.raw"})},
        seed_taints={"m.handler": T.ASSURED, "m.helper": T.ASSURED, "m.raw": T.EXTERNAL_RAW},
        seed_sources={"m.handler": "default", "m.helper": "default", "m.raw": "provider"},
        return_taints={"m.raw": T.EXTERNAL_RAW},
        unresolved_counts={},
    )
    assert refined["m.handler"] == T.EXTERNAL_RAW


def test_three_hop_is_bounded_out() -> None:
    # handler → hop1 → hop2 → raw : one intermediary max, so handler stays ASSURED
    refined, prov = refine_minimum_scope_taints(
        target_functions=["m.handler"],
        edges={
            "m.handler": frozenset({"m.hop1"}),
            "m.hop1": frozenset({"m.hop2"}),
            "m.hop2": frozenset({"m.raw"}),
        },
        seed_taints={
            "m.handler": T.ASSURED, "m.hop1": T.ASSURED,
            "m.hop2": T.ASSURED, "m.raw": T.EXTERNAL_RAW,
        },
        seed_sources={
            "m.handler": "default", "m.hop1": "default",
            "m.hop2": "default", "m.raw": "provider",
        },
        return_taints={"m.raw": T.EXTERNAL_RAW},
        unresolved_counts={},
    )
    assert refined["m.handler"] == T.ASSURED
    assert "m.handler" not in prov  # unchanged → no provenance


def test_self_call_is_ignored() -> None:
    refined, prov = refine_minimum_scope_taints(
        target_functions=["m.handler"],
        edges={"m.handler": frozenset({"m.handler"})},
        seed_taints={"m.handler": T.ASSURED},
        seed_sources={"m.handler": "default"},
        return_taints={},
        unresolved_counts={},
    )
    assert refined["m.handler"] == T.ASSURED
    assert "m.handler" not in prov


def test_no_callees_leaves_taint_unchanged() -> None:
    refined, prov = refine_minimum_scope_taints(
        target_functions=["m.leaf"],
        edges={"m.leaf": frozenset()},
        seed_taints={"m.leaf": T.GUARDED},
        seed_sources={"m.leaf": "default"},
        return_taints={},
        unresolved_counts={},
    )
    assert refined["m.leaf"] == T.GUARDED
    assert "m.leaf" not in prov


def test_floor_clamp_never_increases_trust() -> None:
    # seed EXTERNAL_RAW(rank 5); callee INTEGRAL(rank 0) would be MORE trusted —
    # clamp keeps the less-trusted seed.
    refined, _ = refine_minimum_scope_taints(
        target_functions=["m.handler"],
        edges={"m.handler": frozenset({"m.pure"})},
        seed_taints={"m.handler": T.EXTERNAL_RAW, "m.pure": T.INTEGRAL},
        seed_sources={"m.handler": "default", "m.pure": "provider"},
        return_taints={"m.pure": T.INTEGRAL},
        unresolved_counts={},
    )
    assert refined["m.handler"] == T.EXTERNAL_RAW
```

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_minimum_scope.py -q -k hop or clamp or self or callees`
Expected: FAIL — `ImportError: cannot import name 'refine_minimum_scope_taints'`

- [ ] **Step 3: Append the implementation** to `src/wardline/scanner/taint/minimum_scope.py` (adapted from `.old`; `taint_sources=="decorator"` → `seed_sources=="provider"`, `taint_map`→`seed_taints`, `return_taint_map`→`return_taints`, `TaintProvenance`→`MinimumScopeProvenance`):

```python
def refine_minimum_scope_taints(
    *,
    target_functions: Iterable[str],
    edges: Mapping[str, frozenset[str]],
    seed_taints: Mapping[str, TaintState],
    seed_sources: Mapping[str, str],
    return_taints: Mapping[str, TaintState],
    unresolved_counts: Mapping[str, int],
) -> tuple[dict[str, TaintState], dict[str, MinimumScopeProvenance]]:
    """Refine each target's L1 taint using its callees, bounded to one
    undecorated intermediary hop.

    A callee whose source is ``"provider"`` is *anchored*: its declared return
    taint is used directly (no recursion). Other callees are refined one hop
    deeper. Combined callee taint is floored so refinement never makes a
    function MORE trusted than its own seed (and likewise when it has any
    unresolved calls). Provenance is recorded only for functions whose taint
    actually changed.
    """

    def _seed(func: str) -> TaintState:
        return seed_taints[func]

    def _opt_seed(func: str) -> TaintState | None:
        return seed_taints.get(func)

    def _edges(func: str) -> frozenset[str]:
        return edges.get(func, frozenset())

    def _unresolved(func: str) -> int:
        return unresolved_counts.get(func, 0)

    def _anchor_or_seed(func: str) -> TaintState:
        if seed_sources.get(func) == "provider":
            return return_taints.get(func, _seed(func))
        return _seed(func)

    def _refine(
        func: str, *, remaining_intermediaries: int, stack: frozenset[str]
    ) -> tuple[TaintState, str | None]:
        seed = _seed(func)
        if remaining_intermediaries < 0:
            return seed, None

        direct_callees = [
            callee
            for callee in sorted(_edges(func))
            if callee not in stack and callee != func and _opt_seed(callee) is not None
        ]
        if not direct_callees:
            return seed, None

        influenced: list[tuple[str, TaintState]] = []
        for callee in direct_callees:
            if seed_sources.get(callee) == "provider":
                influenced.append((callee, _anchor_or_seed(callee)))
                continue
            callee_taint, _ = _refine(
                callee,
                remaining_intermediaries=remaining_intermediaries - 1,
                stack=stack | {callee},
            )
            influenced.append((callee, callee_taint))

        combined = reduce(taint_join, (taint for _, taint in influenced))
        if TRUST_RANK[seed] > TRUST_RANK[combined]:
            combined = seed
        if _unresolved(func) > 0 and TRUST_RANK[seed] > TRUST_RANK[combined]:
            combined = seed

        via_callee = max(influenced, key=lambda item: (TRUST_RANK[item[1]], item[0]))[0]
        return combined, via_callee

    refined: dict[str, TaintState] = {}
    provenance: dict[str, MinimumScopeProvenance] = {}

    for func in target_functions:
        seed = _opt_seed(func)
        if seed is None:
            continue
        refined_taint, via_callee = _refine(
            func, remaining_intermediaries=1, stack=frozenset({func})
        )
        refined[func] = refined_taint
        if refined_taint != seed:
            provenance[func] = MinimumScopeProvenance(
                via_callee=via_callee,
                resolved_call_count=len(_edges(func)),
                unresolved_call_count=_unresolved(func),
            )

    return refined, provenance
```

- [ ] **Step 4: Run to verify pass**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_minimum_scope.py -q`
Expected: PASS (all edge + refinement tests).

- [ ] **Step 5: Controller commits** (`feat(sp1c): minimum-scope bounded one-hop taint refinement`).

---

## Final Gate (controller runs after all tasks)

- [ ] Full suite green: `.venv/bin/python -m pytest -q` (SP0+SP1a+SP1b+SP1c; self-hosting xfail still xfails).
- [ ] Lint clean: `.venv/bin/python -m ruff check src tests`
- [ ] Types clean: `.venv/bin/python -m mypy src` (strict).
- [ ] Update spec §8 with the two forward notes: (a) **SP1d HARD:** port `resolve_same_class_call_fqn` so `self.method()` flows resolve in the full callgraph (else minimum-scope's omission loses them everywhere); (b) **SP1f:** when a serialization sink and `stdlib_taint` disagree (`json.load`/`loads`), the sink's `UNKNOWN_RAW` wins; also wire `test_dependency_taint_resolution`'s external-dotted-taint channel.
- [ ] Dispatch a final code reviewer over the whole SP1c diff.
- [ ] Use superpowers:finishing-a-development-branch to merge `sp1c-l2-minimum-scope` back to `main`.

---

## Self-Review (controller checklist)

1. **Spec coverage:** §6 SP1c row = "L2 `variable_level` + `minimum_scope` bounded propagation"; acceptance "variable-taint join tests; one-hop refinement test" → Task 2 (join tests across BinOp/collection/if/try/for/aug/ternary), Tasks 3-4 (edges + one/two/three-hop refinement). ✓
2. **No placeholders:** resolution core, minimum-scope, and resolve_call_fqn fully embedded; statement handlers are a precise mechanical port (delete 2 params) with a behavior-pinning oracle. ✓
3. **Type consistency:** `compute_variable_taints(func_node, function_taint, taint_map)`; `ProjectFileData(entities, import_aliases, module_path)`; `build_minimum_scope_edges(file_data) -> (edges, unresolved)`; `refine_minimum_scope_taints(*, target_functions, edges, seed_taints, seed_sources, return_taints, unresolved_counts)`; `MinimumScopeProvenance(via_callee, resolved_call_count, unresolved_call_count, source)`. Consistent across impl + tests. ✓
4. **Scope guard / generalization:** manifest dep params dropped (deferred test → SP1f); serialization sinks kept verbatim; only `resolve_call_fqn` pulled forward; `self.method()` + dead-branch handled per the documented asymmetry with forward notes. ✓
