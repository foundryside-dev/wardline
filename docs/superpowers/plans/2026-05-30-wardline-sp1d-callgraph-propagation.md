# SP1d — Callgraph + SCC Fixed-Point Propagation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the whole-project transitive taint engine — resolve the inter-module call graph (including `self`/`cls` method flows), decompose it into SCCs, and run a monotone fixed-point to refine L1 seeds across module boundaries — generalized from `wardline.old` and decoupled from its governance/`RuleId`/manifest coupling.

**Architecture:** Six new modules under `scanner/taint/` + two new primitives on existing files. The SCC kernel (`propagation.py`) is ported **verbatim in algorithm** from `.old`'s `callgraph_propagation.py` (the subtle part — port its convergence/monotonicity logic intact) but emits plain string diagnostic codes instead of `RuleId`. The callgraph builder reuses SP1a/c primitives and adds `self.method()` resolution (the one piece of genuinely new logic — the HARD debt from SP1c). The resolver is the **cold path only** (no summary cache — that is SP1e) and returns a `ResolverResult` data object; it emits **no `Finding`s** (that is SP1f).

**Tech Stack:** Python 3.12, stdlib `ast`, `dataclasses`, `functools.reduce`, `types.MappingProxyType`. Gate: `.venv/bin/python -m pytest -q` (1 expected xfail in `test_self_hosting.py` must stay xfail), `ruff check src tests`, `mypy src`.

---

## Context for the implementer

You are continuing a six-stage build of Wardline's analyzer core. SP1a–c are merged and green. The pieces already on disk that you build on:

- `src/wardline/core/taints.py` — `TaintState` (8 states), `TRUST_RANK` (`MappingProxyType`, 0–7), `taint_join` (provenance combination — `MIXED_RAW`-absorbing), `least_trusted` (pure rank demotion). **These two operators are distinct and must never be collapsed.** The kernel combines callee taints with `taint_join`; it uses `TRUST_RANK` *only* for floor/monotonicity ordering — it never uses `least_trusted` for combination.
- `src/wardline/scanner/index.py` — `Entity(qualname, kind, node, location)` + `discover_file_entities(tree, *, module, path)`. Functions/methods only; classes are scope. Uses `reconstruct_qualname` for Clarion-aligned qualnames.
- `src/wardline/scanner/ast_primitives.py` — `build_import_alias_map`, `iter_calls_in_function_body`, `resolve_call_fqn(call, alias_map, local_fqns, module_prefix)`.
- `src/wardline/scanner/taint/provider.py` — `TaintSourceProvider` Protocol, `SeedContext`, `FunctionTaint(body_taint, return_taint)`, `DefaultTaintSourceProvider`.
- `src/wardline/scanner/taint/function_level.py` — `FunctionSeed(qualname, body_taint, return_taint, source: Literal["provider","default"])`, `seed_function_taints`.

**Clarion qualname facts you rely on:** a method's qualname is `module.Class.method` (no marker); a class's qualname is `module.Class`; a closure's is `module.func.<locals>.inner`. So for a method `m`, `qualname.rsplit(".", 1)[0]` is exactly its enclosing class's qualname **iff** that string is a known class qualname. This is the basis for `self.method()` resolution and is strictly more correct than `.old` (which only handled top-level classes).

**Generalization decisions already settled (apply them; do not re-litigate):**
1. Kernel diagnostics are plain `(code: str, message: str)` tuples with string codes (`"L3_CONVERGENCE_BOUND"`, `"L3_MONOTONICITY_VIOLATION"`, `"L3_LOW_RESOLUTION"`). **No `RuleId`, no `Severity`, no `Finding`.**
2. The taint-source class enum is `Literal["anchored", "module_default", "fallback"]` — renamed from `.old`'s `"decorator"`. `FunctionSeed.source == "provider"` → `"anchored"`; `== "default"` → `"fallback"`. The `"module_default"` tier is **dormant** in SP1d (SP2's richer provider will populate it) but the kernel handles all three classes.
3. `self`/`cls` method calls resolve; bare `ClassName()` constructor calls are **not** resolved (unresolved → raises the pessimistic floor = the safe over-taint direction — document it). Closure-captured `self` is a documented under-taint limitation.
4. Module-scope header/decorator calls are **not** attributed to any entity (a `@app.route(...)` call's taint does not flow into the decorated function's body — dropping it is correct). Document it.
5. `cache_key` is minimal: `source_bytes + schema_version + resolver_version + provider_fingerprint`. **No** import-topology hash (source-redundant) and **no** decorator-surface hash. Transitive cross-module invalidation is SP1e's reverse-edge dirty-closure, **not** the cache key — say so in a comment so nobody re-adds a topology hash.
6. No `deep_immutability.freeze_fields` (discarded per spec §4.5) — use frozen dataclasses + `MappingProxyType` via `object.__setattr__` in `__post_init__`.
7. `project_resolver` is the **cold path only** — no `summary_cache` / `dirty_modules` params, no `_apply_cache_to_summaries`. Star imports are deferred (multi-module fixture uses explicit imports only — note the omission).

**Gate commands (run from repo root; use `.venv/bin/python`, NOT bare `python`):**
```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check src tests
.venv/bin/mypy src
```

---

## File structure

| File | Responsibility | Task |
|---|---|---|
| `src/wardline/scanner/index.py` (modify) | add `discover_class_qualnames` | 1 |
| `src/wardline/scanner/ast_primitives.py` (modify) | add `resolve_self_method_fqn` | 1 |
| `src/wardline/scanner/taint/callgraph.py` (create) | `build_call_edges` — call-edge extraction incl. `self.method()` | 2 |
| `src/wardline/scanner/taint/propagation.py` (create) | `compute_sccs` + `propagate_callgraph_taints` + `TaintProvenance` | 3 |
| `src/wardline/scanner/taint/provider.py` (modify) | add `fingerprint()` to the seam | 4 |
| `src/wardline/scanner/taint/summary.py` (create) | slim `FunctionSummary` + `compute_cache_key` | 4 |
| `src/wardline/scanner/taint/module_summariser.py` (create) | `summarise_module` | 5 |
| `src/wardline/scanner/taint/resolver_metadata.py` (create) | `ResolverResult` + `ResolverRunMetadata` | 6 |
| `src/wardline/scanner/taint/project_resolver.py` (create) | `resolve_project_taints` orchestration | 7 |

Tests mirror under `tests/unit/scanner/` and `tests/unit/scanner/taint/`; the integration fixture lives in `tests/unit/scanner/taint/test_project_resolver.py`.

---

## Task 1: New AST primitives — class-qualname discovery + self-method resolution

**Files:**
- Modify: `src/wardline/scanner/index.py`
- Modify: `src/wardline/scanner/ast_primitives.py`
- Test: `tests/unit/scanner/test_index.py` (append), `tests/unit/scanner/test_ast_primitives.py` (append)

**Why:** The callgraph builder needs (a) the set of all class qualnames in the project to recognise a method's enclosing class, and (b) a resolver for `self`/`cls` method calls. The class-qualname set MUST be built with the **same** `reconstruct_qualname` that produced the method qualnames — any divergence makes the `rsplit(...) in class_qualnames` check silently miss and re-opens the under-taint gap with no error.

- [ ] **Step 1: Write the failing test for `discover_class_qualnames`** (append to `tests/unit/scanner/test_index.py`)

```python
from wardline.scanner.index import discover_class_qualnames


def test_discover_class_qualnames_top_level_and_nested() -> None:
    src = (
        "class Outer:\n"
        "    def m(self): pass\n"
        "    class Inner:\n"
        "        def n(self): pass\n"
        "def free(): pass\n"
    )
    tree = ast.parse(src)
    classes = discover_class_qualnames(tree, module="pkg.mod")
    assert classes == {"pkg.mod.Outer", "pkg.mod.Outer.Inner"}


def test_class_qualname_is_rsplit_prefix_of_its_methods() -> None:
    # The invariant the callgraph relies on: a method's enclosing class qualname
    # equals method_qualname.rsplit('.', 1)[0], and is built by the SAME
    # reconstruct_qualname as the methods.
    src = (
        "class Outer:\n"
        "    class Inner:\n"
        "        def n(self): pass\n"
    )
    tree = ast.parse(src)
    entities = discover_file_entities(tree, module="pkg.mod", path="pkg/mod.py")
    classes = discover_class_qualnames(tree, module="pkg.mod")
    method = next(e for e in entities if e.qualname.endswith(".n"))
    assert method.qualname == "pkg.mod.Outer.Inner.n"
    assert method.qualname.rsplit(".", 1)[0] in classes
```

(Ensure `import ast` and `from wardline.scanner.index import discover_file_entities` are present at the top of the test file.)

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/scanner/test_index.py -q`
Expected: FAIL with `ImportError`/`AttributeError` for `discover_class_qualnames`.

- [ ] **Step 3: Implement `discover_class_qualnames`** (append to `src/wardline/scanner/index.py`)

It mirrors `discover_file_entities`' traversal exactly but emits `ClassDef` qualnames, reusing `reconstruct_qualname` (the same-machinery pin):

```python
def discover_class_qualnames(tree: ast.Module, *, module: str) -> set[str]:
    """Discover the qualnames of every class in *tree*.

    Mirrors :func:`discover_file_entities`' scope traversal so class qualnames
    are produced by the SAME :func:`reconstruct_qualname` that produces method
    qualnames. The callgraph builder relies on this identity: for a method
    ``module.Class.method``, ``rsplit('.', 1)[0]`` equals ``module.Class`` and
    is therefore a member of this set. Any divergence in qualname construction
    would silently break ``self.method()`` resolution.
    """
    classes: set[str] = set()

    def visit(node: ast.AST, scope: list[ast.AST]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                local = reconstruct_qualname(child.name, list(reversed(scope)))
                classes.add(f"{module}.{local}")
                visit(child, [*scope, child])
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(child, [*scope, child])
            else:
                visit(child, scope)

    visit(tree, [])
    return classes
```

- [ ] **Step 4: Run to verify it passes**

Run: `.venv/bin/python -m pytest tests/unit/scanner/test_index.py -q`
Expected: PASS.

- [ ] **Step 5: Write the failing test for `resolve_self_method_fqn`** (append to `tests/unit/scanner/test_ast_primitives.py`)

```python
from wardline.scanner.ast_primitives import resolve_self_method_fqn


def _call(src: str) -> ast.Call:
    # src is a single expression statement containing one call
    node = ast.parse(src).body[0]
    assert isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
    return node.value


def test_self_method_resolves_to_class_method() -> None:
    call = _call("self.helper()")
    out = resolve_self_method_fqn(
        call,
        caller_class_fqn="pkg.mod.Cls",
        project_fqns=frozenset({"pkg.mod.Cls.helper"}),
    )
    assert out == "pkg.mod.Cls.helper"


def test_cls_method_resolves() -> None:
    call = _call("cls.make()")
    out = resolve_self_method_fqn(
        call,
        caller_class_fqn="pkg.mod.Cls",
        project_fqns=frozenset({"pkg.mod.Cls.make"}),
    )
    assert out == "pkg.mod.Cls.make"


def test_nested_class_self_method_resolves() -> None:
    call = _call("self.n()")
    out = resolve_self_method_fqn(
        call,
        caller_class_fqn="pkg.mod.Outer.Inner",
        project_fqns=frozenset({"pkg.mod.Outer.Inner.n"}),
    )
    assert out == "pkg.mod.Outer.Inner.n"


def test_self_method_not_in_project_is_none() -> None:
    call = _call("self.absent()")
    assert resolve_self_method_fqn(
        call, caller_class_fqn="pkg.mod.Cls", project_fqns=frozenset()
    ) is None


def test_non_self_receiver_is_none() -> None:
    call = _call("other.method()")
    assert resolve_self_method_fqn(
        call, caller_class_fqn="pkg.mod.Cls",
        project_fqns=frozenset({"pkg.mod.Cls.method"}),
    ) is None


def test_no_caller_class_is_none() -> None:
    call = _call("self.helper()")
    assert resolve_self_method_fqn(
        call, caller_class_fqn=None,
        project_fqns=frozenset({"pkg.mod.Cls.helper"}),
    ) is None
```

(Ensure `import ast` is present at the top of the test file.)

- [ ] **Step 6: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/scanner/test_ast_primitives.py -q`
Expected: FAIL with `ImportError` for `resolve_self_method_fqn`.

- [ ] **Step 7: Implement `resolve_self_method_fqn`** (append to `src/wardline/scanner/ast_primitives.py`)

```python
def resolve_self_method_fqn(
    call: ast.Call,
    *,
    caller_class_fqn: str | None,
    project_fqns: frozenset[str],
) -> str | None:
    """Resolve a ``self.method()`` / ``cls.method()`` call to a project FQN.

    Returns the callee FQN when the call is ``self.<attr>(...)`` or
    ``cls.<attr>(...)``, the caller is a method of a known class
    (``caller_class_fqn`` is not None), and ``{caller_class_fqn}.{attr}`` is a
    project function. Otherwise None.

    Constructor calls (``ClassName()``) are intentionally NOT resolved here: an
    unresolved call raises the caller's pessimistic floor (over-taint, the safe
    direction). Closure-captured ``self`` (``self`` referenced inside a nested
    def) is likewise not resolved — ``caller_class_fqn`` is None for a closure
    qualname (it ends in ``.<locals>.<name>``), a documented under-taint limit.
    """
    if caller_class_fqn is None:
        return None
    func = call.func
    if (
        isinstance(func, ast.Attribute)
        and isinstance(func.value, ast.Name)
        and func.value.id in {"self", "cls"}
    ):
        candidate = f"{caller_class_fqn}.{func.attr}"
        if candidate in project_fqns:
            return candidate
    return None
```

- [ ] **Step 8: Run to verify it passes + full gate**

Run: `.venv/bin/python -m pytest tests/unit/scanner -q && .venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: PASS; ruff + mypy clean.

- [ ] **Step 9: Commit**

```bash
git add src/wardline/scanner/index.py src/wardline/scanner/ast_primitives.py tests/unit/scanner/test_index.py tests/unit/scanner/test_ast_primitives.py
git commit -m "feat(sp1d): class-qualname discovery + self-method FQN resolution"
```

---

## Task 2: `callgraph.py` — call-edge extraction

**Files:**
- Create: `src/wardline/scanner/taint/callgraph.py`
- Test: `tests/unit/scanner/taint/test_callgraph.py`

**Why:** Convert each function's body calls into resolved project edges + resolved/unresolved counts. This is where `self.method()` (the HARD debt) is recovered. Edges are per-caller `frozenset` of callee FQNs; counts feed the kernel's floor + low-resolution diagnostic.

- [ ] **Step 1: Write the failing test**

```python
from __future__ import annotations

import ast

from wardline.scanner.ast_primitives import build_import_alias_map
from wardline.scanner.index import discover_class_qualnames, discover_file_entities
from wardline.scanner.taint.callgraph import build_call_edges


def _module(src: str, *, module: str):
    tree = ast.parse(src)
    return (
        tree,
        tuple(discover_file_entities(tree, module=module, path=f"{module}.py")),
        discover_class_qualnames(tree, module=module),
        build_import_alias_map(tree, module_path=module),
    )


def test_local_bare_call_edge() -> None:
    src = "def a():\n    return b()\ndef b():\n    return 1\n"
    tree, entities, classes, aliases = _module(src, module="m")
    project_fqns = frozenset(e.qualname for e in entities)
    edges, resolved, unresolved = build_call_edges(
        entities=entities, class_qualnames=classes, alias_map=aliases,
        module_prefix="m", project_fqns=project_fqns,
    )
    assert edges["m.a"] == frozenset({"m.b"})
    assert resolved["m.a"] == 1
    assert unresolved["m.a"] == 0
    assert edges["m.b"] == frozenset()


def test_imported_call_edge() -> None:
    src = "from other import helper\ndef a():\n    return helper()\n"
    tree, entities, classes, aliases = _module(src, module="m")
    project_fqns = frozenset({"m.a", "other.helper"})
    edges, resolved, unresolved = build_call_edges(
        entities=entities, class_qualnames=classes, alias_map=aliases,
        module_prefix="m", project_fqns=project_fqns,
    )
    assert edges["m.a"] == frozenset({"other.helper"})


def test_self_method_edge() -> None:
    src = (
        "class C:\n"
        "    def process(self):\n"
        "        return self.helper()\n"
        "    def helper(self):\n"
        "        return 1\n"
    )
    tree, entities, classes, aliases = _module(src, module="m")
    project_fqns = frozenset(e.qualname for e in entities)
    edges, resolved, unresolved = build_call_edges(
        entities=entities, class_qualnames=classes, alias_map=aliases,
        module_prefix="m", project_fqns=project_fqns,
    )
    assert edges["m.C.process"] == frozenset({"m.C.helper"})
    assert resolved["m.C.process"] == 1


def test_unresolved_external_call_counted() -> None:
    src = "def a():\n    return some_external_thing()\n"
    tree, entities, classes, aliases = _module(src, module="m")
    project_fqns = frozenset({"m.a"})
    edges, resolved, unresolved = build_call_edges(
        entities=entities, class_qualnames=classes, alias_map=aliases,
        module_prefix="m", project_fqns=project_fqns,
    )
    assert edges["m.a"] == frozenset()
    assert unresolved["m.a"] == 1


def test_constructor_call_is_unresolved() -> None:
    # ClassName() is deliberately not resolved -> counts as unresolved (safe).
    src = "class C:\n    def __init__(self): pass\ndef make():\n    return C()\n"
    tree, entities, classes, aliases = _module(src, module="m")
    project_fqns = frozenset(e.qualname for e in entities)
    edges, resolved, unresolved = build_call_edges(
        entities=entities, class_qualnames=classes, alias_map=aliases,
        module_prefix="m", project_fqns=project_fqns,
    )
    assert edges["m.make"] == frozenset()
    assert unresolved["m.make"] == 1


def test_nested_def_calls_not_attributed_to_outer() -> None:
    src = (
        "def outer():\n"
        "    def inner():\n"
        "        return b()\n"
        "    return inner()\n"
        "def b():\n    return 1\n"
    )
    tree, entities, classes, aliases = _module(src, module="m")
    project_fqns = frozenset(e.qualname for e in entities)
    edges, resolved, unresolved = build_call_edges(
        entities=entities, class_qualnames=classes, alias_map=aliases,
        module_prefix="m", project_fqns=project_fqns,
    )
    # outer() calls inner() (a nested def, not a project entity) -> unresolved;
    # b() is called only inside inner's body, NOT attributed to outer.
    assert "m.b" not in edges["m.outer"]
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_callgraph.py -q`
Expected: FAIL (`ModuleNotFoundError` for `callgraph`).

- [ ] **Step 3: Implement `callgraph.py`**

```python
# src/wardline/scanner/taint/callgraph.py
"""Call-edge extraction for the L3 project graph.

For each function entity, resolve its body's call sites to project FQNs and
count resolved/unresolved sites. Resolution order per call:
  1. ``resolve_call_fqn`` — local bare-name functions + imported aliases;
  2. ``resolve_self_method_fqn`` — ``self``/``cls`` method calls against the
     caller's enclosing class (recovers the SP1c self-method under-taint gap).
A call resolving to a project FQN becomes an edge; everything else (externals,
constructors, dynamic dispatch, closure-captured self) counts as unresolved —
the unresolved count raises the caller's pessimistic floor in the kernel.

Nested-scope calls are excluded via ``iter_calls_in_function_body`` (they belong
to the nested entity). Module-scope header/decorator calls are not attributed to
any entity by construction (no module entity exists) — correct, since a
decorator call's taint does not flow into the decorated body.
"""

from __future__ import annotations

from collections.abc import Sequence

from wardline.scanner.ast_primitives import (
    iter_calls_in_function_body,
    resolve_call_fqn,
    resolve_self_method_fqn,
)
from wardline.scanner.index import Entity


def build_call_edges(
    *,
    entities: Sequence[Entity],
    class_qualnames: frozenset[str],
    alias_map: dict[str, str],
    module_prefix: str,
    project_fqns: frozenset[str],
) -> tuple[dict[str, frozenset[str]], dict[str, int], dict[str, int]]:
    """Resolve intra-/inter-module call edges for one module's entities.

    Returns ``(edges, resolved_counts, unresolved_counts)`` keyed by caller
    qualname. ``edges[caller]`` is the set of resolved project callee FQNs;
    counts are per-call-site (a callee reached twice counts twice toward
    ``resolved_counts`` but appears once in the edge set).
    """
    edges: dict[str, frozenset[str]] = {}
    resolved_counts: dict[str, int] = {}
    unresolved_counts: dict[str, int] = {}

    for entity in entities:
        caller_class_fqn: str | None = entity.qualname.rsplit(".", 1)[0]
        if caller_class_fqn not in class_qualnames:
            caller_class_fqn = None

        callees: set[str] = set()
        resolved = 0
        unresolved = 0
        for call in iter_calls_in_function_body(entity.node):
            target = resolve_call_fqn(call, alias_map, project_fqns, module_prefix)
            if target is None or target not in project_fqns:
                target = resolve_self_method_fqn(
                    call,
                    caller_class_fqn=caller_class_fqn,
                    project_fqns=project_fqns,
                )
            if target is not None and target in project_fqns:
                callees.add(target)
                resolved += 1
            else:
                unresolved += 1

        edges[entity.qualname] = frozenset(callees)
        resolved_counts[entity.qualname] = resolved
        unresolved_counts[entity.qualname] = unresolved

    return edges, resolved_counts, unresolved_counts
```

- [ ] **Step 4: Run to verify it passes + gate**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_callgraph.py -q && .venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: PASS; clean.

- [ ] **Step 5: Commit**

```bash
git add src/wardline/scanner/taint/callgraph.py tests/unit/scanner/taint/test_callgraph.py
git commit -m "feat(sp1d): call-edge extraction with self-method resolution"
```

---

## Task 3: `propagation.py` — SCC kernel + fixed-point (the verbatim port)

**Files:**
- Create: `src/wardline/scanner/taint/propagation.py`
- Test: `tests/unit/scanner/taint/test_propagation.py`

**Why:** This is the transitive engine. Port `.old`'s `callgraph_propagation.py` **algorithm verbatim** — `compute_sccs` (iterative Tarjan), `propagate_callgraph_taints` (the Phase-1 external-influence / Phase-1b seed-join / Phase-2 fixed-point loop), `_compute_scc_round`, `_check_monotonicity_violation`, `_scc_convergence_bound`, `_seed_provenance_only`, `TaintProvenance`. **The only changes** are decoupling (string codes, not `RuleId`; `TRUST_RANK`/`taint_join` imported from `core.taints`; the source enum renamed to `anchored`/`module_default`/`fallback`).

> **Implementer:** Read `/home/john/wardline.old/src/wardline/scanner/taint/callgraph_propagation.py` for the algorithm. Reproduce it faithfully. Do NOT redesign the Phase-1/1b/2 structure, the floor logic, or the convergence bound — these are load-bearing and tested below against ground-truth values produced by the original kernel. Apply ONLY the decoupling diffs listed in Step 3.

- [ ] **Step 1: Write the failing tests** (all expected values were produced by running the original `.old` kernel — they are ground truth)

```python
from __future__ import annotations

from wardline.core.taints import TaintState as T
from wardline.scanner.taint.propagation import (
    DIAG_CONVERGENCE_BOUND,
    DIAG_MONOTONICITY_VIOLATION,
    compute_sccs,
    propagate_callgraph_taints,
)


def _run(edges, taint_map, sources, *, return_map=None, unresolved=None):
    resolved = {k: len(v) for k, v in edges.items()}
    unresolved = unresolved or {k: 0 for k in taint_map}
    return_map = return_map if return_map is not None else dict(taint_map)
    return propagate_callgraph_taints(
        edges=edges, taint_map=taint_map, taint_sources=sources,
        resolved_counts=resolved, unresolved_counts=unresolved,
        return_taint_map=return_map,
    )


def test_compute_sccs_reverse_topo_order() -> None:
    g = {"A": {"B"}, "B": {"C"}, "C": set(), "D": {"E"}, "E": {"D"}}
    sccs = compute_sccs(g)
    # leaves first; the cycle {D,E} is one component
    assert {frozenset(s) for s in sccs} == {
        frozenset({"C"}), frozenset({"B"}), frozenset({"A"}), frozenset({"D", "E"}),
    }
    assert sccs.index({"C"}) < sccs.index({"B"}) < sccs.index({"A"})


def test_transitive_chain_all_fallback_propagates_raw() -> None:
    edges = {"A": {"B"}, "B": {"C"}, "C": set()}
    tm = {"A": T.INTEGRAL, "B": T.INTEGRAL, "C": T.UNKNOWN_RAW}
    src = {"A": "fallback", "B": "fallback", "C": "fallback"}
    refined, _prov, diags, _it = _run(edges, tm, src)
    assert refined == {"A": T.UNKNOWN_RAW, "B": T.UNKNOWN_RAW, "C": T.UNKNOWN_RAW}
    assert diags == []


def test_two_hop_anchored_mixed_leaf_flows_up() -> None:
    edges = {"A": {"B"}, "B": {"C"}, "C": set()}
    tm = {"A": T.UNKNOWN_RAW, "B": T.UNKNOWN_RAW, "C": T.MIXED_RAW}
    src = {"A": "fallback", "B": "fallback", "C": "anchored"}
    refined, _prov, _diags, _it = _run(edges, tm, src)
    assert refined == {"A": T.MIXED_RAW, "B": T.MIXED_RAW, "C": T.MIXED_RAW}


def test_module_default_trusted_chain_demotes() -> None:
    edges = {"A": {"B"}, "B": {"C"}, "C": set()}
    tm = {"A": T.INTEGRAL, "B": T.INTEGRAL, "C": T.UNKNOWN_RAW}
    src = {"A": "module_default", "B": "module_default", "C": "anchored"}
    refined, _prov, _diags, _it = _run(edges, tm, src)
    assert refined == {"A": T.UNKNOWN_RAW, "B": T.UNKNOWN_RAW, "C": T.UNKNOWN_RAW}


def test_anchored_trusted_leaf_does_not_promote_fallback_caller() -> None:
    edges = {"A": {"B"}, "B": set()}
    tm = {"A": T.UNKNOWN_RAW, "B": T.GUARDED}
    src = {"A": "fallback", "B": "anchored"}
    refined, _prov, _diags, _it = _run(edges, tm, src)
    assert refined["A"] == T.UNKNOWN_RAW  # floor holds — can't prove trust
    assert refined["B"] == T.GUARDED


def test_module_default_never_upgrades_toward_trust() -> None:
    edges = {"A": {"B"}, "B": set()}
    tm = {"A": T.UNKNOWN_RAW, "B": T.INTEGRAL}
    src = {"A": "module_default", "B": "anchored"}
    refined, _prov, _diags, _it = _run(edges, tm, src)
    assert refined["A"] == T.UNKNOWN_RAW


def test_discriminating_join_two_anchored_callees_yields_mixed() -> None:
    # A calls a GUARDED and an EXTERNAL_RAW anchored callee. Combining with
    # taint_join yields MIXED_RAW — a result least_trusted (EXTERNAL_RAW) could
    # NEVER produce. This guards against collapsing the two operators.
    edges = {"A": {"B", "C"}, "B": set(), "C": set()}
    tm = {"A": T.UNKNOWN_RAW, "B": T.GUARDED, "C": T.EXTERNAL_RAW}
    src = {"A": "fallback", "B": "anchored", "C": "anchored"}
    refined, _prov, _diags, _it = _run(edges, tm, src)
    assert refined["A"] == T.MIXED_RAW
    assert refined["A"] != T.EXTERNAL_RAW


def test_cyclic_scc_converges() -> None:
    # A <-> B, B also calls raw C. The Phase-1b seed-join clashes the INTEGRAL
    # sibling with the raw external via taint_join -> MIXED_RAW. Converges (no
    # convergence-bound diagnostic).
    edges = {"A": {"B"}, "B": {"A", "C"}, "C": set()}
    tm = {"A": T.INTEGRAL, "B": T.INTEGRAL, "C": T.UNKNOWN_RAW}
    src = {"A": "fallback", "B": "fallback", "C": "fallback"}
    refined, _prov, diags, _it = _run(edges, tm, src)
    assert refined["A"] == T.MIXED_RAW
    assert refined["B"] == T.MIXED_RAW
    assert refined["C"] == T.UNKNOWN_RAW
    assert not any(code == DIAG_CONVERGENCE_BOUND for code, _ in diags)


def test_long_chain_converges_without_bound_diagnostic() -> None:
    n = 20
    edges = {f"f{i}": {f"f{i+1}"} for i in range(n)}
    edges[f"f{n}"] = set()
    tm = {f"f{i}": (T.MIXED_RAW if i == n else T.INTEGRAL) for i in range(n + 1)}
    src = {f"f{i}": ("anchored" if i == n else "module_default") for i in range(n + 1)}
    refined, _prov, diags, _it = _run(edges, tm, src)
    assert all(refined[f"f{i}"] == T.MIXED_RAW for i in range(n))
    assert not any(code == DIAG_CONVERGENCE_BOUND for code, _ in diags)


def test_anchored_function_provenance_source() -> None:
    edges = {"A": {"B"}, "B": set()}
    tm = {"A": T.UNKNOWN_RAW, "B": T.GUARDED}
    src = {"A": "fallback", "B": "anchored"}
    _refined, prov, _diags, _it = _run(edges, tm, src)
    assert prov["B"].source == "anchored"
    assert prov["A"].source in {"callgraph", "fallback"}


def test_empty_taint_map_returns_empty() -> None:
    refined, prov, diags, it = propagate_callgraph_taints(
        edges={}, taint_map={}, taint_sources={},
        resolved_counts={}, unresolved_counts={}, return_taint_map={},
    )
    assert refined == {} and prov == {} and diags == [] and it == {}
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_propagation.py -q`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement `propagation.py` — port with these EXACT decoupling diffs**

Port `.old`'s `callgraph_propagation.py` verbatim in algorithm, applying ONLY:

1. **Module docstring** — describe it as the SP1d L3 kernel; keep the `taint_join` vs `TRUST_RANK` note.
2. **Imports** — replace
   ```python
   from wardline.core.severity import RuleId
   from wardline.scanner.taint.callgraph import L3_LOW_RESOLUTION_THRESHOLD, TRUST_RANK
   ```
   with
   ```python
   from wardline.core.taints import TRUST_RANK
   ```
   and define module constants:
   ```python
   L3_LOW_RESOLUTION_THRESHOLD = 0.70
   DIAG_CONVERGENCE_BOUND = "L3_CONVERGENCE_BOUND"
   DIAG_MONOTONICITY_VIOLATION = "L3_MONOTONICITY_VIOLATION"
   DIAG_LOW_RESOLUTION = "L3_LOW_RESOLUTION"
   ```
   Keep `from wardline.core.taints import taint_join` as the local (inside-function) import exactly as `.old` does, OR hoist it to the top — either is fine; do NOT change call sites.
   The `TYPE_CHECKING` block: replace `from wardline.scanner.taint.function_level import TaintSource` with a local type alias near the top (outside TYPE_CHECKING, since it is a `Literal`):
   ```python
   TaintSourceClass = Literal["anchored", "module_default", "fallback"]
   ```
   and type `taint_sources: dict[str, TaintSourceClass]` in the signature.
3. **Classification** (the `for func, src in taint_sources.items()` block) — change the literal `"decorator"` to `"anchored"`:
   ```python
   if src == "anchored":
       anchored.add(func)
   elif src == "module_default":
       floating_down.add(func)
   else:
       floating_free.add(func)
   ```
4. **`TaintProvenance.source`** — change the `Literal` member `"decorator"` to `"anchored"`:
   ```python
   source: Literal["anchored", "module_default", "minimum_scope", "callgraph", "fallback"]
   ```
   and in the provenance-building block (Section 7) and `_seed_provenance_only`, replace the `"decorator"` source value with `"anchored"` (the `if func in anchored:` branch sets `source="anchored"`; the `src == "decorator"` check in `_seed_provenance_only` becomes `src == "anchored"`).
5. **Diagnostics** — replace the three `RuleId.<X>.value` diagnostic appends with the string constants:
   - `RuleId.L3_CONVERGENCE_BOUND.value` → `DIAG_CONVERGENCE_BOUND`
   - `RuleId.L3_MONOTONICITY_VIOLATION.value` → `DIAG_MONOTONICITY_VIOLATION`
   - `RuleId.L3_LOW_RESOLUTION.value` → `DIAG_LOW_RESOLUTION`
   (the diagnostics list stays `list[tuple[str, str]]`.)
6. **Nothing else changes** — `compute_sccs`, `_compute_scc_round`, `_scc_convergence_bound`, `_check_monotonicity_violation`, the Phase-1/1b/2 loop, the post-fixed-point assertions, the low-resolution detection, and the return shape `(current, provenance, diagnostics, scc_iteration_counts)` are reproduced exactly.

Keep `from __future__ import annotations`, `logging`, `from dataclasses import dataclass`, `from functools import reduce`, `from typing import Literal` (+ `TYPE_CHECKING`, `Iterator` for `compute_sccs`'s work-stack type).

- [ ] **Step 4: Run to verify it passes + gate**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_propagation.py -q && .venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: PASS; clean. (If any expected-value assertion fails, the port deviated from `.old` — fix the port, not the test; the test values are kernel ground truth.)

- [ ] **Step 5: Commit**

```bash
git add src/wardline/scanner/taint/propagation.py tests/unit/scanner/taint/test_propagation.py
git commit -m "feat(sp1d): SCC fixed-point propagation kernel (ported, decoupled from RuleId)"
```

---

## Task 4: provider `fingerprint()` seam + slim `FunctionSummary` + `cache_key`

**Files:**
- Modify: `src/wardline/scanner/taint/provider.py`
- Create: `src/wardline/scanner/taint/summary.py`
- Test: `tests/unit/scanner/taint/test_provider.py` (append), `tests/unit/scanner/taint/test_summary.py`

**Why:** The summary is the cacheable per-function unit SP1e will store; SP1d defines its shape + a deterministic cache key. The provider gains a `fingerprint()` so the key invalidates when an out-of-source provider (SP2's decorator vocabulary / config) changes a function's declared taint — something a pure source hash cannot see.

- [ ] **Step 1: Write the failing provider test** (append to `tests/unit/scanner/taint/test_provider.py`)

```python
def test_default_provider_fingerprint_is_stable() -> None:
    from wardline.scanner.taint.provider import DefaultTaintSourceProvider
    p = DefaultTaintSourceProvider()
    assert isinstance(p.fingerprint(), str)
    assert p.fingerprint() == DefaultTaintSourceProvider().fingerprint()


def test_provider_protocol_requires_fingerprint() -> None:
    from wardline.scanner.taint.provider import DefaultTaintSourceProvider, TaintSourceProvider
    assert isinstance(DefaultTaintSourceProvider(), TaintSourceProvider)
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_provider.py -q`
Expected: FAIL (`AttributeError: fingerprint`).

- [ ] **Step 3: Add `fingerprint` to the provider seam** (`src/wardline/scanner/taint/provider.py`)

Add the method to the Protocol and the default impl:

```python
@runtime_checkable
class TaintSourceProvider(Protocol):
    """Maps a function entity to its declared taint, or ``None`` for 'no opinion'."""

    def taint_for(self, entity: Entity, ctx: SeedContext) -> FunctionTaint | None: ...

    def fingerprint(self) -> str:
        """A stable string identifying this provider's *declaration surface*.

        Bound into the summary cache key so that a change in out-of-source
        declarations (SP2's decorator vocabulary, config-declared taints) — which
        a per-module source hash cannot observe — invalidates affected summaries.
        Constant for the SP1 default provider; SP2's provider derives it from its
        loaded vocabulary/config.
        """
        ...
```

```python
class DefaultTaintSourceProvider:
    """The trivial provider: declares nothing. With no decorator vocabulary in
    SP1, every function falls back to ``UNKNOWN_RAW`` (fail-closed)."""

    def taint_for(self, entity: Entity, ctx: SeedContext) -> FunctionTaint | None:
        return None

    def fingerprint(self) -> str:
        return "default-v1"
```

- [ ] **Step 4: Write the failing summary test** (`tests/unit/scanner/taint/test_summary.py`)

```python
from __future__ import annotations

import pytest

from wardline.core.taints import TaintState as T
from wardline.scanner.taint.summary import (
    SUMMARY_SCHEMA_VERSION,
    FunctionSummary,
    compute_cache_key,
)


def _key(**over) -> str:
    base = dict(
        source_bytes=b"def f(): pass\n",
        schema_version=SUMMARY_SCHEMA_VERSION,
        resolver_version="sp1d",
        provider_fingerprint="default-v1",
    )
    base.update(over)
    return compute_cache_key(**base)


def test_cache_key_is_deterministic() -> None:
    assert _key() == _key()


def test_cache_key_changes_with_each_input() -> None:
    base = _key()
    assert _key(source_bytes=b"def g(): pass\n") != base
    assert _key(provider_fingerprint="sp2-vocab-7") != base
    assert _key(resolver_version="sp1e") != base
    assert _key(schema_version=SUMMARY_SCHEMA_VERSION + 1) != base


def test_cache_key_rejects_crlf_source() -> None:
    with pytest.raises(ValueError, match="CRLF"):
        _key(source_bytes=b"def f():\r\n    pass\r\n")


def test_cache_key_length_prefixed_no_collision() -> None:
    # ("ab","c") vs ("a","bc") must not collide across adjacent fields.
    assert compute_cache_key(
        source_bytes=b"ab", schema_version=1, resolver_version="c",
        provider_fingerprint="x",
    ) != compute_cache_key(
        source_bytes=b"a", schema_version=1, resolver_version="bc",
        provider_fingerprint="x",
    )


def test_summary_rejects_wrong_schema_version() -> None:
    with pytest.raises(ValueError, match="schema_version"):
        FunctionSummary(
            fqn="m.f", body_taint=T.UNKNOWN_RAW, return_taint=T.UNKNOWN_RAW,
            taint_source="fallback", unresolved_calls=0,
            schema_version=SUMMARY_SCHEMA_VERSION + 99, cache_key="x",
        )


def test_summary_rejects_negative_unresolved() -> None:
    with pytest.raises(ValueError, match="unresolved_calls"):
        FunctionSummary(
            fqn="m.f", body_taint=T.UNKNOWN_RAW, return_taint=T.UNKNOWN_RAW,
            taint_source="fallback", unresolved_calls=-1,
            schema_version=SUMMARY_SCHEMA_VERSION, cache_key="x",
        )


def test_summary_is_frozen() -> None:
    s = FunctionSummary(
        fqn="m.f", body_taint=T.UNKNOWN_RAW, return_taint=T.UNKNOWN_RAW,
        taint_source="fallback", unresolved_calls=0,
        schema_version=SUMMARY_SCHEMA_VERSION, cache_key="x",
    )
    with pytest.raises((AttributeError, TypeError)):
        s.fqn = "m.g"  # type: ignore[misc]
```

- [ ] **Step 5: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_summary.py -q`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 6: Implement `summary.py`**

```python
# src/wardline/scanner/taint/summary.py
"""Slim per-function taint summary + deterministic cache key.

A ``FunctionSummary`` is the cacheable unit SP1e will store and the cold-path
intermediate the project resolver assembles into the kernel's input maps. It
carries exactly what the kernel needs per function (body/return taint, the
3-valued taint-source class, the unresolved-call count) plus a content-addressed
``cache_key``.

The cache key binds source bytes + schema version + resolver version + the
provider's declaration fingerprint. It deliberately omits any import-topology
hash: that would be redundant with ``source_bytes`` for a single module, and
cross-module invalidation is NOT the key's job — it is SP1e's reverse-edge
dirty-closure. Do not re-add a topology hash here.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from wardline.core.taints import TaintState  # noqa: TC001  # runtime: dataclass field type

if TYPE_CHECKING:
    from hashlib import _Hash

SUMMARY_SCHEMA_VERSION = 1
"""Bumped whenever FunctionSummary's structural shape changes (purges cache)."""

TaintSourceClass = Literal["anchored", "module_default", "fallback"]


@dataclass(frozen=True, slots=True)
class FunctionSummary:
    """A function's taint contract for the L3 resolver / SP1e cache."""

    fqn: str
    body_taint: TaintState
    return_taint: TaintState
    taint_source: TaintSourceClass
    unresolved_calls: int
    schema_version: int
    cache_key: str

    def __post_init__(self) -> None:
        if self.schema_version != SUMMARY_SCHEMA_VERSION:
            raise ValueError(
                f"FunctionSummary schema_version={self.schema_version} != "
                f"SUMMARY_SCHEMA_VERSION={SUMMARY_SCHEMA_VERSION} — purge cache or upgrade"
            )
        if self.unresolved_calls < 0:
            raise ValueError(
                f"unresolved_calls must be non-negative, got {self.unresolved_calls}"
            )


def compute_cache_key(
    *,
    source_bytes: bytes,
    schema_version: int,
    resolver_version: str,
    provider_fingerprint: str,
) -> str:
    """Content-addressed cache key for a module's summaries.

    Each component is length-prefixed before hashing so distinct inputs cannot
    collide (without it, ``(b"ab", "c")`` and ``(b"a", "bc")`` would hash alike).
    CRLF in ``source_bytes`` is rejected so Linux/Windows checkouts of the same
    commit produce identical keys.
    """
    if source_bytes.find(b"\r\n") != -1:
        raise ValueError("CRLF bytes in source — normalise to LF before hashing")
    hasher = hashlib.sha256()
    _write_len_prefixed(hasher, source_bytes)
    _write_len_prefixed(hasher, str(schema_version).encode("ascii"))
    _write_len_prefixed(hasher, resolver_version.encode("utf-8"))
    _write_len_prefixed(hasher, provider_fingerprint.encode("utf-8"))
    return hasher.hexdigest()


def _write_len_prefixed(hasher: _Hash, value: bytes) -> None:
    hasher.update(len(value).to_bytes(8, "big"))
    hasher.update(value)
```

- [ ] **Step 7: Run to verify both pass + gate**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_provider.py tests/unit/scanner/taint/test_summary.py -q && .venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: PASS; clean.

- [ ] **Step 8: Commit**

```bash
git add src/wardline/scanner/taint/provider.py src/wardline/scanner/taint/summary.py tests/unit/scanner/taint/test_provider.py tests/unit/scanner/taint/test_summary.py
git commit -m "feat(sp1d): provider fingerprint seam + slim FunctionSummary + cache_key"
```

---

## Task 5: `module_summariser.py` — per-module summaries

**Files:**
- Create: `src/wardline/scanner/taint/module_summariser.py`
- Test: `tests/unit/scanner/taint/test_module_summariser.py`

**Why:** Turn each module's L1 seeds + the callgraph's unresolved counts into `FunctionSummary` objects. This maps `FunctionSeed.source` (2-valued) onto the kernel's `taint_source` class (3-valued; `module_default` dormant) and computes the cache key once per module.

- [ ] **Step 1: Write the failing test**

```python
from __future__ import annotations

from wardline.core.taints import TaintState as T
from wardline.scanner.taint.function_level import FunctionSeed
from wardline.scanner.taint.module_summariser import summarise_module
from wardline.scanner.taint.summary import SUMMARY_SCHEMA_VERSION


def _seed(q, body, ret, source) -> FunctionSeed:
    return FunctionSeed(qualname=q, body_taint=body, return_taint=ret, source=source)


def test_summaries_map_provider_seed_to_anchored() -> None:
    seeds = {
        "m.a": _seed("m.a", T.GUARDED, T.GUARDED, "provider"),
        "m.b": _seed("m.b", T.UNKNOWN_RAW, T.UNKNOWN_RAW, "default"),
    }
    summaries = summarise_module(
        seeds=seeds, unresolved_counts={"m.a": 0, "m.b": 2},
        source_bytes=b"x\n", resolver_version="sp1d", provider_fingerprint="default-v1",
    )
    by_fqn = {s.fqn: s for s in summaries}
    assert by_fqn["m.a"].taint_source == "anchored"
    assert by_fqn["m.a"].body_taint == T.GUARDED
    assert by_fqn["m.b"].taint_source == "fallback"
    assert by_fqn["m.b"].unresolved_calls == 2
    assert all(s.schema_version == SUMMARY_SCHEMA_VERSION for s in summaries)


def test_all_summaries_in_module_share_cache_key() -> None:
    seeds = {
        "m.a": _seed("m.a", T.UNKNOWN_RAW, T.UNKNOWN_RAW, "default"),
        "m.b": _seed("m.b", T.UNKNOWN_RAW, T.UNKNOWN_RAW, "default"),
    }
    summaries = summarise_module(
        seeds=seeds, unresolved_counts={"m.a": 0, "m.b": 0},
        source_bytes=b"x\n", resolver_version="sp1d", provider_fingerprint="default-v1",
    )
    keys = {s.cache_key for s in summaries}
    assert len(keys) == 1  # cache_key is module-granular


def test_missing_unresolved_count_defaults_zero() -> None:
    seeds = {"m.a": _seed("m.a", T.UNKNOWN_RAW, T.UNKNOWN_RAW, "default")}
    summaries = summarise_module(
        seeds=seeds, unresolved_counts={},
        source_bytes=b"x\n", resolver_version="sp1d", provider_fingerprint="default-v1",
    )
    assert summaries[0].unresolved_calls == 0
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_module_summariser.py -q`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement `module_summariser.py`**

```python
# src/wardline/scanner/taint/module_summariser.py
"""Per-module FunctionSummary emission.

Maps each L1 ``FunctionSeed`` + the callgraph's unresolved-call count into a
``FunctionSummary``. The seed's 2-valued source (``provider``/``default``) maps
onto the kernel's 3-valued taint-source class: ``provider -> anchored``,
``default -> fallback``. The ``module_default`` class is dormant in SP1 (no
provider expresses a module-wide default yet); SP2's richer provider populates
it. The cache key is computed once and shared by all functions in the module
(module-granular invalidation).
"""

from __future__ import annotations

from collections.abc import Mapping

from wardline.scanner.taint.function_level import FunctionSeed
from wardline.scanner.taint.summary import (
    SUMMARY_SCHEMA_VERSION,
    FunctionSummary,
    TaintSourceClass,
    compute_cache_key,
)

_SEED_SOURCE_TO_CLASS: dict[str, TaintSourceClass] = {
    "provider": "anchored",
    "default": "fallback",
}


def summarise_module(
    *,
    seeds: Mapping[str, FunctionSeed],
    unresolved_counts: Mapping[str, int],
    source_bytes: bytes,
    resolver_version: str,
    provider_fingerprint: str,
) -> tuple[FunctionSummary, ...]:
    """Emit one FunctionSummary per seeded function in this module."""
    cache_key = compute_cache_key(
        source_bytes=source_bytes,
        schema_version=SUMMARY_SCHEMA_VERSION,
        resolver_version=resolver_version,
        provider_fingerprint=provider_fingerprint,
    )
    summaries: list[FunctionSummary] = []
    for fqn, seed in seeds.items():
        summaries.append(
            FunctionSummary(
                fqn=fqn,
                body_taint=seed.body_taint,
                return_taint=seed.return_taint,
                taint_source=_SEED_SOURCE_TO_CLASS[seed.source],
                unresolved_calls=unresolved_counts.get(fqn, 0),
                schema_version=SUMMARY_SCHEMA_VERSION,
                cache_key=cache_key,
            )
        )
    return tuple(summaries)
```

- [ ] **Step 4: Run to verify it passes + gate**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_module_summariser.py -q && .venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: PASS; clean.

- [ ] **Step 5: Commit**

```bash
git add src/wardline/scanner/taint/module_summariser.py tests/unit/scanner/taint/test_module_summariser.py
git commit -m "feat(sp1d): per-module FunctionSummary emission"
```

---

## Task 6: `resolver_metadata.py` — `ResolverResult` + `ResolverRunMetadata`

**Files:**
- Create: `src/wardline/scanner/taint/resolver_metadata.py`
- Test: `tests/unit/scanner/taint/test_resolver_metadata.py`

**Why:** The resolver's return shape. Slimmed from `.old`: no SARIF `SummaryProvenance`, no `deep_immutability` — frozen dataclasses with `MappingProxyType`-wrapped inner collections, diagnostics carried as plain `(code, message)` data (SP1f turns them into Findings).

- [ ] **Step 1: Write the failing test**

```python
from __future__ import annotations

from types import MappingProxyType

import pytest

from wardline.core.taints import TaintState as T
from wardline.scanner.taint.propagation import TaintProvenance
from wardline.scanner.taint.resolver_metadata import ResolverResult, ResolverRunMetadata


def _meta(**over) -> ResolverRunMetadata:
    base = dict(
        scc_size_distribution=((1, 3),),
        convergence_iterations_max=2,
        convergence_iterations_histogram=((1, 2), (2, 1)),
        taint_source_counts={"anchored": 1, "module_default": 0, "fallback": 2},
    )
    base.update(over)
    return ResolverRunMetadata(**base)


def test_metadata_valid() -> None:
    m = _meta()
    assert m.convergence_iterations_max == 2
    assert isinstance(m.taint_source_counts, MappingProxyType)


def test_metadata_rejects_unsorted_histogram() -> None:
    with pytest.raises(ValueError, match="sorted"):
        _meta(convergence_iterations_histogram=((2, 1), (1, 2)))


def test_metadata_rejects_negative_max() -> None:
    with pytest.raises(ValueError, match="convergence_iterations_max"):
        _meta(convergence_iterations_max=-1)


def test_result_wraps_mappings_immutably() -> None:
    res = ResolverResult(
        taint_map={"m.f": T.UNKNOWN_RAW},
        project_edges={"m.f": frozenset()},
        taint_provenance={"m.f": TaintProvenance(source="fallback")},
        diagnostics=(("L3_LOW_RESOLUTION", "m.f has 80% unresolved"),),
        metadata=_meta(),
    )
    assert isinstance(res.taint_map, MappingProxyType)
    assert isinstance(res.project_edges, MappingProxyType)
    assert isinstance(res.taint_provenance, MappingProxyType)
    assert res.diagnostics[0][0] == "L3_LOW_RESOLUTION"
    with pytest.raises(TypeError):
        res.taint_map["m.g"] = T.INTEGRAL  # type: ignore[index]
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_resolver_metadata.py -q`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement `resolver_metadata.py`**

```python
# src/wardline/scanner/taint/resolver_metadata.py
"""Return-shape carriers for the project resolver.

Slimmed from ``.old``: no SARIF SummaryProvenance, no cache-mode/analysis-level
fields (SP1e/SP1f concerns), no ``deep_immutability`` (discarded per spec §4.5).
Inner collections are wrapped in ``MappingProxyType`` at construction so
downstream stages receive immutable views. Kernel diagnostics ride as plain
``(code, message)`` tuples — SP1f maps them to ``Finding``s.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

    from wardline.core.taints import TaintState
    from wardline.scanner.taint.propagation import TaintProvenance


@dataclass(frozen=True, slots=True, kw_only=True)
class ResolverRunMetadata:
    """Run-level metrics (SP1f promotes these to engine ``kind=metric`` findings)."""

    scc_size_distribution: tuple[tuple[int, int], ...]
    convergence_iterations_max: int
    convergence_iterations_histogram: tuple[tuple[int, int], ...]
    taint_source_counts: "Mapping[str, int]"

    def __post_init__(self) -> None:
        if self.convergence_iterations_max < 0:
            raise ValueError(
                f"convergence_iterations_max must be >= 0, got {self.convergence_iterations_max}"
            )
        for name, hist in (
            ("scc_size_distribution", self.scc_size_distribution),
            ("convergence_iterations_histogram", self.convergence_iterations_histogram),
        ):
            if hist and tuple(sorted(hist)) != hist:
                raise ValueError(f"{name} must be sorted ascending; got {hist!r}")
            for _bucket, count in hist:
                if count < 1:
                    raise ValueError(f"{name} counts must be >= 1; got {count}")
        object.__setattr__(
            self, "taint_source_counts", MappingProxyType(dict(self.taint_source_counts))
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class ResolverResult:
    """Project-scope resolution output."""

    taint_map: "Mapping[str, TaintState]"
    project_edges: "Mapping[str, frozenset[str]]"
    taint_provenance: "Mapping[str, TaintProvenance]"
    diagnostics: tuple[tuple[str, str], ...]
    metadata: ResolverRunMetadata

    def __post_init__(self) -> None:
        object.__setattr__(self, "taint_map", MappingProxyType(dict(self.taint_map)))
        object.__setattr__(self, "project_edges", MappingProxyType(dict(self.project_edges)))
        object.__setattr__(
            self, "taint_provenance", MappingProxyType(dict(self.taint_provenance))
        )
```

> **Note on `slots=True` + `object.__setattr__`:** frozen+slots dataclasses still permit `object.__setattr__` for the declared slots. This is the sanctioned way to normalise a field in `__post_init__`. If mypy objects to the `Mapping` re-assignment, keep the field typed `Mapping[...]` (the `MappingProxyType` is a `Mapping`).

- [ ] **Step 4: Run to verify it passes + gate**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_resolver_metadata.py -q && .venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: PASS; clean.

- [ ] **Step 5: Commit**

```bash
git add src/wardline/scanner/taint/resolver_metadata.py tests/unit/scanner/taint/test_resolver_metadata.py
git commit -m "feat(sp1d): ResolverResult + ResolverRunMetadata return-shape carriers"
```

---

## Task 7: `project_resolver.py` — orchestration + multi-module integration

**Files:**
- Create: `src/wardline/scanner/taint/project_resolver.py`
- Test: `tests/unit/scanner/taint/test_project_resolver.py`

**Why:** The top-level L3 entry point. Given per-module parsed data + seeds, it builds the project graph (callgraph), assembles the kernel's input maps from summaries + edges, runs the fixed-point, and returns a `ResolverResult`. This is the **cold path only** (no cache). The integration test is the spec's acceptance gate: transitive taint correct on a multi-module fixture, including a `self.method()` flow.

- [ ] **Step 1: Write the failing test** (expected taints are kernel ground truth — verified against `.old`)

```python
from __future__ import annotations

import ast

from wardline.core.taints import TaintState as T
from wardline.scanner.ast_primitives import build_import_alias_map
from wardline.scanner.index import discover_class_qualnames, discover_file_entities
from wardline.scanner.taint.function_level import seed_function_taints
from wardline.scanner.taint.provider import (
    DefaultTaintSourceProvider,
    FunctionTaint,
    SeedContext,
)
from wardline.scanner.taint.project_resolver import ModuleInput, resolve_project_taints


class _RawLeafProvider:
    """Declares any function whose qualname ends in '.read_raw' as an anchored
    MIXED_RAW source; silent on everything else (fallback)."""

    def taint_for(self, entity, ctx):  # noqa: ANN001, ANN201
        if entity.qualname.endswith(".read_raw"):
            return FunctionTaint(body_taint=T.MIXED_RAW, return_taint=T.MIXED_RAW)
        return None

    def fingerprint(self) -> str:
        return "rawleaf-v1"


_IO = "def read_raw(p):\n    return p\n"
_SERVICE = "from pkg.io_layer import read_raw\ndef fetch(p):\n    return read_raw(p)\n"
_HANDLER = (
    "from pkg.service import fetch\n"
    "class Handler:\n"
    "    def process(self, p):\n"
    "        return self.fetch_wrap(p)\n"
    "    def fetch_wrap(self, p):\n"
    "        return fetch(p)\n"
)


def _module_input(module: str, src: str, provider) -> ModuleInput:
    tree = ast.parse(src)
    entities = tuple(discover_file_entities(tree, module=module, path=f"{module}.py"))
    seeds = seed_function_taints(entities, ctx=SeedContext(module=module), provider=provider)
    return ModuleInput(
        module_path=module,
        entities=entities,
        class_qualnames=discover_class_qualnames(tree, module=module),
        alias_map=build_import_alias_map(tree, module_path=module),
        seeds=seeds,
        source_bytes=src.encode("utf-8"),
    )


def test_transitive_raw_flows_across_modules_and_self_method() -> None:
    provider = _RawLeafProvider()
    inputs = [
        _module_input("pkg.io_layer", _IO, provider),
        _module_input("pkg.service", _SERVICE, provider),
        _module_input("pkg.handler", _HANDLER, provider),
    ]
    result = resolve_project_taints(modules=inputs, provider_fingerprint=provider.fingerprint())
    tm = result.taint_map
    # Raw leaf flows 3 hops up; the process->fetch_wrap edge is the self.method().
    assert tm["pkg.io_layer.read_raw"] == T.MIXED_RAW
    assert tm["pkg.service.fetch"] == T.MIXED_RAW
    assert tm["pkg.handler.Handler.fetch_wrap"] == T.MIXED_RAW
    assert tm["pkg.handler.Handler.process"] == T.MIXED_RAW
    # The self.method() edge is present in the project graph.
    assert "pkg.handler.Handler.fetch_wrap" in result.project_edges["pkg.handler.Handler.process"]
    assert "pkg.service.fetch" in result.project_edges["pkg.handler.Handler.fetch_wrap"]


def test_default_provider_leaves_everything_unknown_raw() -> None:
    provider = DefaultTaintSourceProvider()
    inputs = [
        _module_input("pkg.io_layer", _IO, provider),
        _module_input("pkg.service", _SERVICE, provider),
        _module_input("pkg.handler", _HANDLER, provider),
    ]
    result = resolve_project_taints(modules=inputs, provider_fingerprint=provider.fingerprint())
    # With the trivial provider, every function is fallback UNKNOWN_RAW and the
    # floor keeps them there — the kernel is sound but a no-op on taint values.
    assert set(result.taint_map.values()) == {T.UNKNOWN_RAW}


def test_metadata_records_scc_distribution() -> None:
    provider = _RawLeafProvider()
    inputs = [
        _module_input("pkg.io_layer", _IO, provider),
        _module_input("pkg.service", _SERVICE, provider),
        _module_input("pkg.handler", _HANDLER, provider),
    ]
    result = resolve_project_taints(modules=inputs, provider_fingerprint=provider.fingerprint())
    # 3 non-anchored singleton SCCs are recorded (the anchored read_raw SCC is
    # skipped by the kernel).
    assert result.metadata.scc_size_distribution == ((1, 3),)
    assert result.metadata.taint_source_counts["anchored"] == 1
    assert result.metadata.taint_source_counts["fallback"] == 3
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_project_resolver.py -q`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement `project_resolver.py`**

```python
# src/wardline/scanner/taint/project_resolver.py
"""Project-scope L3 resolver — cold path.

Assembles per-module parsed data + L1 seeds into the inter-module call graph,
runs the SCC fixed-point kernel, and returns a ``ResolverResult``. This is the
cold path only: there is no summary cache (SP1e) and no ``Finding`` emission
(SP1f) — kernel diagnostics ride on the result as ``(code, message)`` data.
Star imports are not yet materialised for edge resolution (deferred); the
multi-module graph resolves explicit imports + local + self/cls method calls.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING

from wardline.scanner.taint.callgraph import build_call_edges
from wardline.scanner.taint.module_summariser import summarise_module
from wardline.scanner.taint.propagation import propagate_callgraph_taints
from wardline.scanner.taint.resolver_metadata import ResolverResult, ResolverRunMetadata
from wardline.scanner.taint.summary import TaintSourceClass

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from wardline.core.taints import TaintState
    from wardline.scanner.index import Entity
    from wardline.scanner.taint.function_level import FunctionSeed

_RESOLVER_VERSION = "sp1d"


@dataclass(frozen=True, slots=True)
class ModuleInput:
    """Everything the resolver needs from one parsed module."""

    module_path: str
    entities: "tuple[Entity, ...]"
    class_qualnames: frozenset[str]
    alias_map: dict[str, str]
    seeds: "Mapping[str, FunctionSeed]"
    source_bytes: bytes


def resolve_project_taints(
    *,
    modules: "Sequence[ModuleInput]",
    provider_fingerprint: str,
) -> ResolverResult:
    """Run whole-project transitive taint resolution over ``modules``."""
    project_fqns = frozenset(
        e.qualname for m in modules for e in m.entities
    )
    all_classes = frozenset(c for m in modules for c in m.class_qualnames)

    edges: dict[str, frozenset[str]] = {}
    resolved_counts: dict[str, int] = {}
    unresolved_counts: dict[str, int] = {}
    for m in modules:
        m_edges, m_resolved, m_unresolved = build_call_edges(
            entities=m.entities,
            class_qualnames=all_classes,
            alias_map=m.alias_map,
            module_prefix=m.module_path,
            project_fqns=project_fqns,
        )
        edges.update(m_edges)
        resolved_counts.update(m_resolved)
        unresolved_counts.update(m_unresolved)

    # Summaries (the cacheable unit + cold-path intermediate).
    summaries = tuple(
        s
        for m in modules
        for s in summarise_module(
            seeds=m.seeds,
            unresolved_counts=unresolved_counts,
            source_bytes=m.source_bytes,
            resolver_version=_RESOLVER_VERSION,
            provider_fingerprint=provider_fingerprint,
        )
    )

    taint_map: dict[str, TaintState] = {s.fqn: s.body_taint for s in summaries}
    return_taint_map: dict[str, TaintState] = {s.fqn: s.return_taint for s in summaries}
    taint_sources: dict[str, TaintSourceClass] = {s.fqn: s.taint_source for s in summaries}

    refined, provenance, diagnostics, scc_iteration_counts = propagate_callgraph_taints(
        edges={k: set(v) for k, v in edges.items()},
        taint_map=taint_map,
        taint_sources=taint_sources,
        resolved_counts=resolved_counts,
        unresolved_counts=unresolved_counts,
        return_taint_map=return_taint_map,
    )

    scc_size_distribution = tuple(
        sorted(Counter(len(k) for k in scc_iteration_counts).items())
    )
    convergence_iterations_histogram = tuple(
        sorted(Counter(scc_iteration_counts.values()).items())
    )
    convergence_iterations_max = max(scc_iteration_counts.values(), default=0)
    taint_source_counts = Counter(taint_sources.values())
    metadata = ResolverRunMetadata(
        scc_size_distribution=scc_size_distribution,
        convergence_iterations_max=convergence_iterations_max,
        convergence_iterations_histogram=convergence_iterations_histogram,
        taint_source_counts={
            "anchored": taint_source_counts.get("anchored", 0),
            "module_default": taint_source_counts.get("module_default", 0),
            "fallback": taint_source_counts.get("fallback", 0),
        },
    )

    return ResolverResult(
        taint_map=MappingProxyType(refined),
        project_edges=MappingProxyType(
            {fqn: frozenset(callees) for fqn, callees in edges.items()}
        ),
        taint_provenance=MappingProxyType(dict(provenance)),
        diagnostics=tuple(diagnostics),
        metadata=metadata,
    )
```

> **Implementer note:** `propagate_callgraph_taints` mutates its `edges`/`taint_map` inputs minimally but treats them as owned; pass fresh copies (`{k: set(v) ...}`, the dicts built above) so the resolver's own `edges` frozensets stay intact for `project_edges`. The `taint_source_counts` keys must be exactly the three canonical classes.

- [ ] **Step 4: Run to verify it passes + FULL gate**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: PASS (1 expected xfail in `test_self_hosting.py` stays xfail); ruff + mypy clean. (If the integration taints differ from `MIXED_RAW`, the wiring is wrong — the kernel values are ground-truthed.)

- [ ] **Step 5: Commit**

```bash
git add src/wardline/scanner/taint/project_resolver.py tests/unit/scanner/taint/test_project_resolver.py
git commit -m "feat(sp1d): project-scope L3 resolver + multi-module transitive fixture"
```

---

## Final review

After all 7 tasks: dispatch a final code-reviewer over the whole SP1d diff, then use `superpowers:finishing-a-development-branch` to merge `sp1d-callgraph-propagation` → `main` (`--no-ff`), verify green on the merged result, delete the branch, and update `memory/project_generic_rebuild.md` (mark SP1d done; record any new SP1e/SP1f debts; note self.method recovered, constructor/closure-self/star-imports documented limits).

## Self-review notes (author)

- **Spec coverage:** SP1d row of §6 — `callgraph` (Task 2), SCC `propagation` kernel (Task 3), `module_summariser` (Task 5), `project_resolver` (Task 7), `resolver_metadata` (Task 6); `summary.py`+`cache_key` (Task 4, listed under SP1d in §3). SCC/fixed-point tests incl. cyclic SCC + monotonicity + convergence bound (Task 3); transitive taint on multi-module fixture (Task 7). HARD self.method debt (Tasks 1–2). Header-call decision documented (Task 2). ✓
- **Type consistency:** `taint_source` is `Literal["anchored","module_default","fallback"]` everywhere (`summary.TaintSourceClass`); `propagation.TaintProvenance.source` adds `"minimum_scope"`/`"callgraph"`. `FunctionSummary` fields match across summariser + resolver. `ModuleInput` fields match the integration test's constructor. ✓
- **Ground truth:** every kernel/integration expected value was produced by running `.old`'s kernel (oracle) before writing the assertion. ✓
