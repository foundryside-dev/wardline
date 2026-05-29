# SP2c — Rules, Severity Model, Fingerprint & Self-Hosting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the SP1/SP2b taint *engine* into a taint *policy tool* — ship the compact tier-modulation severity model, the four hybrid policy rules, the taint-path fingerprint, the default-populated `RuleRegistry` wired into the analyzer, and flip the self-hosting xfail to a passing regression gate.

**Architecture:** Four rules consume the `AnalysisContext`. To make them correct AND decorator-agnostic, SP2c exposes an **effective return-taint map** (`anchored → declared return tier`, `non-anchored → refined body taint`) on `ResolverResult` and `AnalysisContext`, and an **actual returned-value taint** per function (`function_return_taints`). With body taint (`project_taints`), declared return (`project_return_taints`), actual return (`function_return_taints`) and `taint_provenance` all on the context, every rule is expressible by taint *shape* alone — no decorator re-parsing, no `alias_map` in the context. This also fixes a latent SP1 under-resolution: `build_call_taint_map` promises "the call's return taint" but the analyzer fed it *body* taint (harmless while `body==return`, wrong the moment `@trust_boundary` makes them differ — it would false-positive the central validate-to-raise-trust use case).

**Tech Stack:** Python 3.12, stdlib `ast`/`hashlib`/`fnmatch`, existing `wardline.core.taints` lattice (`TRUST_RANK`, `least_trusted`), `wardline.core.finding` (`Severity`/`Kind`/`Finding`).

**Rule formulations (taint-shape, decorator-agnostic):**
- **PY-WL-101 untrusted-reaches-trusted** — an *anchored* function whose **actual** returned taint is strictly less-trusted (higher `TRUST_RANK`) than its **declared** return tier, **gated** so it fires only when the declared return is a genuine trust claim (NOT in the raw/freedom zone `{EXTERNAL_RAW, UNKNOWN_RAW, MIXED_RAW}`). The gate excludes `@external_boundary` (whose job is to return raw) and all undecorated code, and is what makes strict rank comparison safe.
- **PY-WL-102 boundary-without-rejection** — an *anchored* **trust-raising transition** (`TRUST_RANK[body] > TRUST_RANK[return]`, i.e. body less-trusted than return — uniquely identifies `@trust_boundary` among the three vocabulary shapes) with **no rejection path** (no `raise`, no falsy-constant `return`).
- **PY-WL-103 broad-exception** / **PY-WL-104 silent-exception** — syntactic; severity **tier-modulated** by the function's own body taint, so they are silent on undecorated (`UNKNOWN_RAW`) code.

**Severity policy:** PY-WL-101/102 are *declaration-gated* and emit at base severity (NOT modulated). PY-WL-103/104 are *tier-modulated* via `modulate(base, taint)`.

**Self-hosting clean by construction:** `src/wardline` applies none of its own decorators (verified), so every function resolves to `UNKNOWN_RAW`: 101/102 are gated out (not anchored), 103/104 modulate to `NONE` (freedom zone). The flipped test pins this.

---

## File Structure

- Modify `src/wardline/scanner/taint/resolver_metadata.py` — `ResolverResult` gains `return_taint_map`.
- Modify `src/wardline/scanner/taint/project_resolver.py` — compute + pass the effective return map.
- Modify `src/wardline/scanner/taint/variable_level.py` — add public `compute_return_taint`.
- Modify `src/wardline/scanner/context.py` — `AnalysisContext` gains `project_return_taints` + `function_return_taints`.
- Modify `src/wardline/scanner/analyzer.py` — build the call bucket from the return map; compute `function_return_taints`; build + run the default registry honoring config.
- Create `src/wardline/scanner/rules/__init__.py` — package + `build_default_registry`.
- Create `src/wardline/scanner/rules/metadata.py` — `RuleMetadata`.
- Create `src/wardline/scanner/rules/severity_model.py` — `modulate`.
- Create `src/wardline/scanner/rules/_ast_helpers.py` — scope-respecting except-handler iteration + rejection-path / broad / silent predicates.
- Create `src/wardline/scanner/rules/untrusted_reaches_trusted.py` — PY-WL-101.
- Create `src/wardline/scanner/rules/boundary_without_rejection.py` — PY-WL-102.
- Create `src/wardline/scanner/rules/broad_exception.py` — PY-WL-103.
- Create `src/wardline/scanner/rules/silent_exception.py` — PY-WL-104.
- Modify `src/wardline/core/finding.py` — replace `compute_placeholder_fingerprint` with `compute_finding_fingerprint`.
- **Delete** `src/wardline/rules/__init__.py` — dead stub (no importers; spec §5 homes rules in `scanner/rules/`). Controller handles the `git rm`.
- Tests under `tests/unit/scanner/rules/`, plus modifications to `tests/unit/core/test_finding.py`, `tests/unit/scanner/test_analyzer.py`, and `tests/test_self_hosting.py`.

> **IMPLEMENTER CONSTRAINT — NO GIT.** You must NEVER run any `git` command: not `add`, `commit`, `status`, `diff`, `log`, `stash`, `checkout`, `restore`, `reset`, `rm`, `branch`, `switch`, `merge`, or any other. The controller does ALL git operations. Edit files only. Always use `.venv/bin/python` / `.venv/bin/pytest` / `.venv/bin/ruff` / `.venv/bin/mypy` — never bare `python`.

---

### Task 1: Expose the effective return-taint map from the resolver

**Files:**
- Modify: `src/wardline/scanner/taint/resolver_metadata.py`
- Modify: `src/wardline/scanner/taint/project_resolver.py`
- Test: `tests/unit/scanner/taint/test_project_resolver.py` (add a test; file exists)

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/scanner/taint/test_project_resolver.py` (import what the existing tests import; `ModuleInput`, `resolve_project_taints` are already used there):

```python
def test_resolver_exposes_effective_return_taint_map() -> None:
    # An anchored @trust_boundary-shaped function: body EXTERNAL_RAW, return ASSURED.
    # Its effective return taint must be the DECLARED return (ASSURED), while its
    # body taint (taint_map) stays EXTERNAL_RAW. A non-anchored function's effective
    # return must equal its refined body taint.
    import ast
    from wardline.core.taints import TaintState as T
    from wardline.scanner.ast_primitives import build_import_alias_map
    from wardline.scanner.index import discover_class_qualnames, discover_file_entities
    from wardline.scanner.taint.function_level import seed_function_taints
    from wardline.scanner.taint.provider import FunctionTaint, SeedContext

    src = (
        "def validate(p):\n"
        "    if not p:\n        raise ValueError\n"
        "    return p\n"
        "def plain(p):\n    return p\n"
    )
    tree = ast.parse(src)
    module = "m"
    entities = tuple(discover_file_entities(tree, module=module, path="m.py"))
    classes = frozenset(discover_class_qualnames(tree, module=module))
    alias_map = build_import_alias_map(tree, module_path=module)

    class _Provider:
        def taint_for(self, entity, ctx):  # noqa: ANN001, ANN201
            if entity.qualname.endswith(".validate"):
                return FunctionTaint(body_taint=T.EXTERNAL_RAW, return_taint=T.ASSURED)
            return None

        def fingerprint(self) -> str:
            return "test-effret-v1"

    provider = _Provider()
    seeds = seed_function_taints(
        entities, ctx=SeedContext(module=module, alias_map=alias_map), provider=provider
    )
    modules = [
        ModuleInput(
            module_path=module,
            entities=entities,
            class_qualnames=classes,
            alias_map=alias_map,
            seeds=seeds,
            source_bytes=src.encode("utf-8"),
        )
    ]
    result = resolve_project_taints(modules=modules, provider_fingerprint=provider.fingerprint())

    assert result.taint_map["m.validate"] == T.EXTERNAL_RAW          # body unchanged
    assert result.return_taint_map["m.validate"] == T.ASSURED         # declared return
    # non-anchored: effective return == refined body taint
    assert result.return_taint_map["m.plain"] == result.taint_map["m.plain"]
```

- [ ] **Step 2: Run it; expect failure**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_project_resolver.py::test_resolver_exposes_effective_return_taint_map -q`
Expected: FAIL — `ResolverResult` has no attribute `return_taint_map`.

- [ ] **Step 3: Add the field to `ResolverResult`**

In `resolver_metadata.py`, add the field to `ResolverResult` (after `taint_map`) and wrap it in `__post_init__`:

```python
@dataclass(frozen=True, slots=True, kw_only=True)
class ResolverResult:
    """Project-scope resolution output."""

    taint_map: Mapping[str, TaintState]
    return_taint_map: Mapping[str, TaintState]
    project_edges: Mapping[str, frozenset[str]]
    taint_provenance: Mapping[str, TaintProvenance]
    diagnostics: tuple[tuple[str, str], ...]
    metadata: ResolverRunMetadata

    def __post_init__(self) -> None:
        object.__setattr__(self, "taint_map", MappingProxyType(dict(self.taint_map)))
        object.__setattr__(
            self, "return_taint_map", MappingProxyType(dict(self.return_taint_map))
        )
        object.__setattr__(self, "project_edges", MappingProxyType(dict(self.project_edges)))
        object.__setattr__(
            self, "taint_provenance", MappingProxyType(dict(self.taint_provenance))
        )
```

Update the docstring of `ResolverResult` to:

```python
    """Project-scope resolution output.

    ``taint_map`` is the L3-refined *body* taint per function. ``return_taint_map``
    is the *effective return* taint: for anchored functions, the provider's
    declared return tier (never refined — anchored taints are fixed); for
    non-anchored functions, the refined body taint (``body == return`` holds for
    them). Callers building call-resolution maps want ``return_taint_map`` (a
    caller observes a callee's *return*, not its body); rules wanting a function's
    own operating tier want ``taint_map``.
    """
```

- [ ] **Step 4: Compute the effective return map in `project_resolver.py`**

In `resolve_project_taints`, after `refined, provenance, ... = propagate_callgraph_taints(...)` and before building `metadata`, compute the effective return map and pass it to `ResolverResult`. The local `return_taint_map` (L1) and `taint_sources` are already in scope:

```python
    # Effective return taint: anchored functions surface their DECLARED return
    # tier (L3 never refines anchored taints — see the post-fixed-point
    # assertions); non-anchored functions have body == return, so the refined
    # body taint is also their return. Callers building L2 call-resolution maps
    # must read THIS, not the body ``refined`` map, or a @trust_boundary's
    # validated output is mis-read as its raw body taint (an over-taint that
    # false-positives PY-WL-101).
    effective_return: dict[str, TaintState] = {
        fqn: (return_taint_map[fqn] if taint_sources.get(fqn) == "anchored" else refined[fqn])
        for fqn in refined
    }
```

Then add `return_taint_map=MappingProxyType(effective_return),` to the `ResolverResult(...)` constructor call (keyword, after `taint_map=`).

- [ ] **Step 5: Run the new test + the resolver suite**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_project_resolver.py -q`
Expected: PASS (including the new test). If any existing test constructs `ResolverResult(...)` directly, it will fail for the missing required `return_taint_map=` kwarg — fix each such construction by passing `return_taint_map={}` (or a suitable map). Search first: `grep -rn "ResolverResult(" tests | grep -v __pycache__`.

- [ ] **Step 6: Commit-readiness check**

Run: `.venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: clean.

---

### Task 2: Public `compute_return_taint` helper

**Files:**
- Modify: `src/wardline/scanner/taint/variable_level.py`
- Test: `tests/unit/scanner/taint/test_variable_level.py` (file exists; add tests)

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/scanner/taint/test_variable_level.py`:

```python
def test_compute_return_taint_all_shapes() -> None:
    import ast
    import textwrap
    from wardline.core.taints import TaintState as T
    from wardline.scanner.taint.variable_level import compute_return_taint, compute_variable_taints

    tm = {"read_raw": T.EXTERNAL_RAW, "validate": T.ASSURED}

    def rt(src: str) -> T | None:
        node = ast.parse(textwrap.dedent(src)).body[0]
        var_taints = compute_variable_taints(node, T.INTEGRAL, dict(tm))
        return compute_return_taint(node, T.INTEGRAL, dict(tm), var_taints)

    assert rt("def f(p):\n x = read_raw(p)\n return x\n") == T.EXTERNAL_RAW
    assert rt("def f(p):\n return read_raw(p)\n") == T.EXTERNAL_RAW
    assert rt("def f(p):\n return validate(read_raw(p))\n") == T.ASSURED
    assert rt("def f():\n return 1\n") == T.INTEGRAL
    # least-trusted across multiple return paths
    assert rt("def f(p):\n if p:\n  return 1\n return read_raw(p)\n") == T.EXTERNAL_RAW
    # no value-bearing return -> None (nothing to check)
    assert rt("def f():\n return\n") is None
    assert rt("def f():\n pass\n") is None
    # a return inside a NESTED function must not count toward THIS function
    assert rt("def f():\n def g():\n  return read_raw(1)\n return 1\n") == T.INTEGRAL
```

- [ ] **Step 2: Run it; expect failure**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_variable_level.py::test_compute_return_taint_all_shapes -q`
Expected: FAIL — `compute_return_taint` does not exist.

- [ ] **Step 3: Implement `compute_return_taint`**

Append to `variable_level.py` (after `compute_variable_taints`). It reuses the module-private `_resolve_expr`; add `least_trusted` to the existing `from wardline.core.taints import` line:

```python
def compute_return_taint(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> TaintState | None:
    """Compute the *actual* taint a function returns (least-trusted of all paths).

    Resolves every value-bearing ``return`` statement in *func_node*'s own scope
    (nested functions/lambdas excluded) against the already-computed ``var_taints``
    and the call-resolution ``taint_map``, and joins them with :func:`least_trusted`
    — the worst (least-trusted) value any path can return. Returns ``None`` when the
    function has no value-bearing ``return`` (implicit ``None`` / bare ``return`` /
    pure side-effect): there is no returned data to police.

    This is the precise input PY-WL-101 needs — distinct from ``project_taints``
    (the function's anchored *body* taint, pinned to its declaration).
    """
    returns: list[TaintState] = []
    _collect_return_taints(func_node.body, function_taint, taint_map, var_taints, returns)
    if not returns:
        return None
    result = returns[0]
    for r in returns[1:]:
        result = least_trusted(result, r)
    return result


def _collect_return_taints(
    stmts: list[ast.stmt],
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
    out: list[TaintState],
) -> None:
    """Recurse statements collecting value-bearing return taints, NOT descending
    into nested ``FunctionDef``/``AsyncFunctionDef``/``ClassDef`` (separate scopes;
    their returns bind their own function, not this one)."""
    for stmt in stmts:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(stmt, ast.Return) and stmt.value is not None:
            out.append(_resolve_expr(stmt.value, function_taint, taint_map, var_taints))
        for child in ast.iter_child_nodes(stmt):
            if isinstance(child, ast.stmt):
                _collect_return_taints(
                    [child], function_taint, taint_map, var_taints, out
                )
```

> NOTE: `_collect_return_taints` recurses into every nested statement (if/for/while/try/with bodies) via `ast.iter_child_nodes`, descending only through `ast.stmt` children, so it sees returns at any nesting depth EXCEPT inside nested defs/classes (skipped at the top of the loop). A `Lambda` is an expression, never an `ast.stmt`, so its body is never entered.

- [ ] **Step 4: Run; expect PASS**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_variable_level.py -q`
Expected: PASS.

- [ ] **Step 5: Lint/type**

Run: `.venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: clean.

---

### Task 3: Thread the maps into `AnalysisContext`; fix the call bucket

**Files:**
- Modify: `src/wardline/scanner/context.py`
- Modify: `src/wardline/scanner/analyzer.py`
- Test: `tests/unit/scanner/test_analyzer.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/scanner/test_analyzer.py`:

```python
def test_analyzer_exposes_return_taints_and_resolves_validators(tmp_path) -> None:
    # @trust_boundary validator raises trust EXTERNAL_RAW(body) -> ASSURED(return).
    # A @trusted(ASSURED) caller that returns the VALIDATED value must see ASSURED
    # (the validator's RETURN), not EXTERNAL_RAW (its body) — proving the call
    # bucket now resolves callee RETURN taints.
    _write(tmp_path, "io_layer.py",
           "from wardline.decorators import external_boundary, trust_boundary\n"
           "@external_boundary\ndef read_raw(p):\n    return p\n"
           "@trust_boundary(to_level='ASSURED')\n"
           "def validate(p):\n    if not p:\n        raise ValueError\n    return p\n")
    _write(tmp_path, "service.py",
           "from wardline.decorators import trusted\n"
           "from io_layer import read_raw, validate\n"
           "@trusted(level='ASSURED')\n"
           "def safe(p):\n    return validate(read_raw(p))\n"
           "@trusted\ndef leaky(p):\n    return read_raw(p)\n")
    files = [tmp_path / "io_layer.py", tmp_path / "service.py"]
    analyzer = WardlineAnalyzer()
    analyzer.analyze(files, WardlineConfig(), root=tmp_path)
    ctx = analyzer.last_context
    assert ctx is not None
    # effective return taint of the validator is its declared return
    assert ctx.project_return_taints["io_layer.validate"] == T.ASSURED
    assert ctx.project_taints["io_layer.validate"] == T.EXTERNAL_RAW  # body unchanged
    # actual returned-value taint per function
    assert ctx.function_return_taints["service.safe"] == T.ASSURED     # validated -> clean
    assert ctx.function_return_taints["service.leaky"] == T.EXTERNAL_RAW  # leaks raw
```

- [ ] **Step 2: Run it; expect failure**

Run: `.venv/bin/python -m pytest tests/unit/scanner/test_analyzer.py::test_analyzer_exposes_return_taints_and_resolves_validators -q`
Expected: FAIL — `AnalysisContext` has no `project_return_taints` / `function_return_taints`.

- [ ] **Step 3: Extend `AnalysisContext`**

In `context.py`, add two fields to the dataclass (after `project_taints`) and wrap them in `__post_init__`:

```python
    project_taints: Mapping[str, TaintState]
    project_return_taints: Mapping[str, TaintState]
    function_var_taints: Mapping[str, Mapping[str, TaintState]]
    function_return_taints: Mapping[str, TaintState]
    entities: Mapping[str, Entity]
    taint_provenance: Mapping[str, TaintProvenance]
```

```python
    def __post_init__(self) -> None:
        object.__setattr__(self, "project_taints", MappingProxyType(dict(self.project_taints)))
        object.__setattr__(
            self, "project_return_taints", MappingProxyType(dict(self.project_return_taints))
        )
        object.__setattr__(
            self, "function_var_taints", MappingProxyType(dict(self.function_var_taints))
        )
        object.__setattr__(
            self, "function_return_taints", MappingProxyType(dict(self.function_return_taints))
        )
        object.__setattr__(self, "entities", MappingProxyType(dict(self.entities)))
        object.__setattr__(
            self, "taint_provenance", MappingProxyType(dict(self.taint_provenance))
        )
```

Update the class docstring to mention `project_return_taints` (effective return tier per function) and `function_return_taints` (actual least-trusted returned-value taint per function).

- [ ] **Step 4: Wire the analyzer**

In `analyzer.py`:

(a) Add the import near the other taint imports:
```python
from wardline.scanner.taint.variable_level import compute_return_taint, compute_variable_taints
```

(b) Build the call bucket from the **effective return** map. Replace the `project_by_module` build block (the loop that does `bucket[rest] = project_taints.get(...)`) so it reads the return map, and update its comment:

```python
        # Pre-bucket EFFECTIVE RETURN taints by module → {top_level_func_name:
        # return_taint}, once, for O(aliases) call resolution. A caller observes a
        # callee's RETURN taint, not its body — for anchored callees (e.g. a
        # @trust_boundary validator) body != return, and using body here would
        # mis-read validated output as raw (over-taint -> PY-WL-101 false positive).
        project_return_taints = dict(result.return_taint_map)
        project_by_module: dict[str, dict[str, TaintState]] = {}
        for _relpath, module, _tree, entities, _alias_map in file_meta:
            prefix = module + "."
            bucket = project_by_module.setdefault(module, {})
            for ent in entities:
                rest = ent.qualname[len(prefix):] if ent.qualname.startswith(prefix) else ent.qualname
                if "." not in rest:  # top-level function (methods aren't bare-callable)
                    bucket[rest] = project_return_taints.get(ent.qualname, TaintState.UNKNOWN_RAW)
```

(c) In the per-function L2 loop, compute `function_return_taints` alongside `function_var_taints`. The function's **own seed stays its body taint** (`project_taints`), which seeds parameters; only call *resolution* uses return taints:

```python
        function_var_taints: dict[str, dict[str, TaintState]] = {}
        function_return_taints: dict[str, TaintState] = {}
        entity_index: dict[str, Entity] = {}
        for _relpath, module, _tree, entities, alias_map in file_meta:
            call_tm = build_call_taint_map(
                module_path=module, alias_map=alias_map, project_by_module=project_by_module
            )
            for ent in entities:
                entity_index[ent.qualname] = ent
                seed = project_taints.get(ent.qualname, TaintState.UNKNOWN_RAW)
                try:
                    var_taints = compute_variable_taints(ent.node, seed, dict(call_tm))
                    ret_taint = compute_return_taint(ent.node, seed, dict(call_tm), var_taints)
                except RecursionError:
                    var_taints = {}  # fail-closed; absent vars read as the function taint
                    ret_taint = None
                function_var_taints[ent.qualname] = var_taints
                if ret_taint is not None:
                    function_return_taints[ent.qualname] = ret_taint
```

(d) Pass the two new maps into `AnalysisContext(...)`:

```python
        context = AnalysisContext(
            project_taints=project_taints,
            project_return_taints=project_return_taints,
            function_var_taints=function_var_taints,
            function_return_taints=function_return_taints,
            entities=entity_index,
            taint_provenance=dict(result.taint_provenance),
        )
```

- [ ] **Step 5: Run the analyzer suite**

Run: `.venv/bin/python -m pytest tests/unit/scanner/test_analyzer.py -q`
Expected: PASS — including the new test. The existing transitive-taint test still passes (its `_Provider` anchors `read_raw` to `MIXED_RAW` where body==return, so the call bucket is unchanged for it).

- [ ] **Step 6: Full suite + lint/type**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: only the pre-existing `1 xfailed` (self-hosting, flipped in Task 11); all else green.

---

### Task 4: Severity model + `RuleMetadata`

**Files:**
- Create: `src/wardline/scanner/rules/__init__.py` (minimal for now — package marker; the registry factory is added in Task 10)
- Create: `src/wardline/scanner/rules/metadata.py`
- Create: `src/wardline/scanner/rules/severity_model.py`
- Test: `tests/unit/scanner/rules/__init__.py` (empty), `tests/unit/scanner/rules/test_severity_model.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/scanner/rules/__init__.py` (empty file) and `tests/unit/scanner/rules/test_severity_model.py`:

```python
from __future__ import annotations

from wardline.core.finding import Severity
from wardline.core.taints import TaintState as T
from wardline.scanner.rules.severity_model import modulate


def test_trusted_tiers_pass_base_through() -> None:
    for tier in (T.INTEGRAL, T.ASSURED):
        assert modulate(Severity.ERROR, tier) == Severity.ERROR
        assert modulate(Severity.CRITICAL, tier) == Severity.CRITICAL


def test_partial_tiers_downgrade_one_step() -> None:
    for tier in (T.GUARDED, T.UNKNOWN_ASSURED, T.UNKNOWN_GUARDED):
        assert modulate(Severity.CRITICAL, tier) == Severity.ERROR
        assert modulate(Severity.ERROR, tier) == Severity.WARN
        assert modulate(Severity.WARN, tier) == Severity.INFO
        assert modulate(Severity.INFO, tier) == Severity.INFO  # floor


def test_freedom_tiers_suppress_to_none() -> None:
    for tier in (T.EXTERNAL_RAW, T.UNKNOWN_RAW, T.MIXED_RAW):
        assert modulate(Severity.CRITICAL, tier) == Severity.NONE
        assert modulate(Severity.INFO, tier) == Severity.NONE


def test_every_taint_state_is_classified() -> None:
    # No TaintState may fall through unmapped (would silently mis-modulate).
    for tier in T:
        assert isinstance(modulate(Severity.ERROR, tier), Severity)
```

- [ ] **Step 2: Run; expect failure**

Run: `.venv/bin/python -m pytest tests/unit/scanner/rules/test_severity_model.py -q`
Expected: FAIL — module does not exist.

- [ ] **Step 3: Create the package + metadata + severity model**

`src/wardline/scanner/rules/__init__.py`:
```python
# src/wardline/scanner/rules/__init__.py
"""SP2 policy rules: the trust-vocabulary-driven defect rule set, the compact
tier-modulation severity model, and the default ``RuleRegistry`` factory."""
```

`src/wardline/scanner/rules/metadata.py`:
```python
# src/wardline/scanner/rules/metadata.py
"""``RuleMetadata`` — the per-rule descriptor (id, base severity, kind, docs).

Carried by every rule and exported by SP2d's NG-25 vocabulary descriptor.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from wardline.core.finding import Kind, Severity


@dataclass(frozen=True, slots=True)
class RuleMetadata:
    rule_id: str
    base_severity: Severity
    kind: Kind
    description: str
    examples_violation: tuple[str, ...] = field(default_factory=tuple)
    examples_clean: tuple[str, ...] = field(default_factory=tuple)
```

`src/wardline/scanner/rules/severity_model.py`:
```python
# src/wardline/scanner/rules/severity_model.py
"""Compact tier-modulation severity model (SP2 §5).

A rule declares a ``base_severity``; ``modulate`` scales it by the function's
resolved taint tier. ``.old``'s 80-cell (rule × taint) matrix in ~10 lines:
trusted tiers keep the base, partial tiers downgrade one step, and the
developer-freedom / fail-closed tiers suppress to ``NONE``. The freedom-zone
suppression is what makes undecorated code (which resolves to ``UNKNOWN_RAW``)
silent — and Wardline self-host clean — under the tier-modulated rules.
"""

from __future__ import annotations

from wardline.core.finding import Severity
from wardline.core.taints import TaintState

_TRUSTED: frozenset[TaintState] = frozenset({TaintState.INTEGRAL, TaintState.ASSURED})
_PARTIAL: frozenset[TaintState] = frozenset(
    {TaintState.GUARDED, TaintState.UNKNOWN_ASSURED, TaintState.UNKNOWN_GUARDED}
)
# _FREEDOM = {EXTERNAL_RAW, UNKNOWN_RAW, MIXED_RAW} — the implicit else branch.

_DOWNGRADE: dict[Severity, Severity] = {
    Severity.CRITICAL: Severity.ERROR,
    Severity.ERROR: Severity.WARN,
    Severity.WARN: Severity.INFO,
    Severity.INFO: Severity.INFO,  # floor — never below INFO via downgrade
    Severity.NONE: Severity.NONE,
}


def modulate(base: Severity, taint: TaintState) -> Severity:
    """Modulate *base* severity by a function's resolved taint tier."""
    if taint in _TRUSTED:
        return base
    if taint in _PARTIAL:
        return _DOWNGRADE[base]
    return Severity.NONE  # freedom / fail-closed zone — suppressed
```

- [ ] **Step 4: Run; expect PASS**

Run: `.venv/bin/python -m pytest tests/unit/scanner/rules/test_severity_model.py -q`
Expected: PASS.

- [ ] **Step 5: Lint/type**

Run: `.venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: clean.

---

### Task 5: AST helpers for the rules

**Files:**
- Create: `src/wardline/scanner/rules/_ast_helpers.py`
- Test: `tests/unit/scanner/rules/test_ast_helpers.py`

- [ ] **Step 1: Write the failing test**

`tests/unit/scanner/rules/test_ast_helpers.py`:
```python
from __future__ import annotations

import ast
import textwrap

from wardline.scanner.rules._ast_helpers import (
    has_rejection_path,
    is_broad_except,
    is_silent_handler,
    own_except_handlers,
)


def _fn(src: str) -> ast.FunctionDef:
    return ast.parse(textwrap.dedent(src)).body[0]  # type: ignore[return-value]


def test_has_rejection_path_detects_raise_and_falsy_returns() -> None:
    assert has_rejection_path(_fn("def f(p):\n if not p:\n  raise ValueError\n return p\n"))
    assert has_rejection_path(_fn("def f(p):\n if not p:\n  return None\n return p\n"))
    assert has_rejection_path(_fn("def f(p):\n if not p:\n  return False\n return p\n"))
    assert has_rejection_path(_fn("def f(p):\n if not p:\n  return\n return p\n"))
    assert has_rejection_path(_fn("def f(p):\n if not p:\n  return []\n return p\n"))
    # no rejection: always returns the (possibly raw) input
    assert not has_rejection_path(_fn("def f(p):\n return p\n"))
    assert not has_rejection_path(_fn("def f(p):\n x = p\n return x\n"))


def test_own_except_handlers_skips_nested_functions() -> None:
    fn = _fn(
        "def f():\n"
        "    try:\n        a()\n    except ValueError:\n        pass\n"
        "    def g():\n"
        "        try:\n            b()\n        except KeyError:\n            pass\n"
    )
    handlers = list(own_except_handlers(fn))
    assert len(handlers) == 1
    assert isinstance(handlers[0].type, ast.Name) and handlers[0].type.id == "ValueError"


def test_is_broad_except() -> None:
    def handler(src: str) -> ast.ExceptHandler:
        fn = _fn("def f():\n try:\n  a()\n" + src)
        return next(own_except_handlers(fn))

    assert is_broad_except(handler(" except:\n  pass\n"))             # bare
    assert is_broad_except(handler(" except Exception:\n  pass\n"))
    assert is_broad_except(handler(" except BaseException:\n  pass\n"))
    assert not is_broad_except(handler(" except ValueError:\n  pass\n"))
    assert not is_broad_except(handler(" except (KeyError, IndexError):\n  pass\n"))


def test_is_silent_handler() -> None:
    def handler(body: str) -> ast.ExceptHandler:
        fn = _fn("def f():\n try:\n  a()\n except Exception:\n" + body)
        return next(own_except_handlers(fn))

    assert is_silent_handler(handler("  pass\n"))
    assert is_silent_handler(handler("  ...\n"))
    assert is_silent_handler(handler("  continue\n"))
    assert not is_silent_handler(handler("  raise\n"))
    assert not is_silent_handler(handler("  log(e)\n"))
    assert not is_silent_handler(handler("  return None\n"))
```

- [ ] **Step 2: Run; expect failure**

Run: `.venv/bin/python -m pytest tests/unit/scanner/rules/test_ast_helpers.py -q`
Expected: FAIL — module does not exist.

- [ ] **Step 3: Implement the helpers**

`src/wardline/scanner/rules/_ast_helpers.py`:
```python
# src/wardline/scanner/rules/_ast_helpers.py
"""Shared AST predicates for the SP2 rules.

All helpers operate on a single function's *own* scope — they never descend into
nested ``FunctionDef``/``AsyncFunctionDef``/``ClassDef`` bodies, so a finding is
attributed to the function that lexically owns the construct (nested functions
are separate entities and are analysed in their own right).
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

_BROAD_NAMES: frozenset[str] = frozenset({"Exception", "BaseException"})


def _own_statements(node: ast.AST) -> Iterator[ast.stmt]:
    """Yield every statement in *node*'s own scope, not descending into nested
    def/class bodies. Includes the bodies of if/for/while/try/with at any depth."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(child, ast.stmt):
            yield child
        yield from _own_statements(child)


def own_except_handlers(node: ast.FunctionDef | ast.AsyncFunctionDef) -> Iterator[ast.ExceptHandler]:
    """Yield the ``except`` handlers in *node*'s own scope (excludes nested defs)."""
    for stmt in _own_statements(node):
        if isinstance(stmt, ast.Try):
            yield from stmt.handlers


def is_broad_except(handler: ast.ExceptHandler) -> bool:
    """True for a bare ``except:`` or ``except Exception`` / ``except BaseException``
    (dotted forms like ``builtins.Exception`` match on the final attribute)."""
    t = handler.type
    if t is None:
        return True
    if isinstance(t, ast.Name):
        return t.id in _BROAD_NAMES
    if isinstance(t, ast.Attribute):
        return t.attr in _BROAD_NAMES
    return False


def _is_ellipsis(stmt: ast.stmt) -> bool:
    return (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Constant)
        and stmt.value.value is Ellipsis
    )


def is_silent_handler(handler: ast.ExceptHandler) -> bool:
    """True when the handler body only swallows: every statement is ``pass``,
    ``...``, ``continue``, or ``break`` (no logging, re-raise, return, or other
    handling)."""
    return all(
        isinstance(stmt, (ast.Pass, ast.Continue, ast.Break)) or _is_ellipsis(stmt)
        for stmt in handler.body
    )


def _is_falsy_constant_return(value: ast.expr | None) -> bool:
    """True for a returned value that signals rejection: a bare ``return`` (None),
    a falsy constant (``None``/``False``/``0``/``""``), or an empty literal
    container (``[]``/``()``/``{}``)."""
    if value is None:
        return True
    if isinstance(value, ast.Constant):
        return not value.value
    if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        return not value.elts
    if isinstance(value, ast.Dict):
        return not value.keys
    return False


def has_rejection_path(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True when *node* can reject: any ``raise`` or any falsy-constant ``return``
    in its own scope. Deliberately generous — PY-WL-102 is always-on, so we err
    toward SEEING a rejection path (risk a missed finding) over firing on a real
    validator."""
    for stmt in _own_statements(node):
        if isinstance(stmt, ast.Raise):
            return True
        if isinstance(stmt, ast.Return) and _is_falsy_constant_return(stmt.value):
            return True
    return False
```

- [ ] **Step 4: Run; expect PASS**

Run: `.venv/bin/python -m pytest tests/unit/scanner/rules/test_ast_helpers.py -q`
Expected: PASS.

- [ ] **Step 5: Lint/type**

Run: `.venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: clean.

---

### Task 6: Taint-path fingerprint

**Files:**
- Modify: `src/wardline/core/finding.py`
- Test: `tests/unit/core/test_finding.py`

- [ ] **Step 1: Rewrite the failing test**

In `tests/unit/core/test_finding.py`, change the import `compute_placeholder_fingerprint` → `compute_finding_fingerprint`, and replace `test_placeholder_fingerprint_is_deterministic_and_path_sensitive` with:

```python
def test_finding_fingerprint_is_deterministic_and_discriminating() -> None:
    a = compute_finding_fingerprint(
        rule_id="PY-WL-101", path="a.py", line_start=1, qualname="m.f", taint_path="EXTERNAL_RAW|g"
    )
    b = compute_finding_fingerprint(
        rule_id="PY-WL-101", path="a.py", line_start=1, qualname="m.f", taint_path="EXTERNAL_RAW|g"
    )
    # same inputs -> stable
    assert a == b
    assert len(a) == 64
    # path-sensitive
    assert a != compute_finding_fingerprint(
        rule_id="PY-WL-101", path="b.py", line_start=1, qualname="m.f", taint_path="EXTERNAL_RAW|g"
    )
    # TWO TAINT PATHS INTO ONE SINK: same (rule, file, line, qualname) but a
    # different taint path -> DISTINCT fingerprint (Filigree constraint, §7).
    assert a != compute_finding_fingerprint(
        rule_id="PY-WL-101", path="a.py", line_start=1, qualname="m.f", taint_path="MIXED_RAW|h"
    )
    # optional fields default cleanly
    assert len(compute_finding_fingerprint(rule_id="WLN-ENGINE-X", path="a.py", line_start=None)) == 64
```

- [ ] **Step 2: Run; expect failure**

Run: `.venv/bin/python -m pytest tests/unit/core/test_finding.py -q`
Expected: FAIL — `compute_finding_fingerprint` does not exist (import error).

- [ ] **Step 3: Replace the placeholder in `finding.py`**

Replace the `# --- SP0 PLACEHOLDER ---` block and `compute_placeholder_fingerprint` with:

```python
# --- Finding fingerprint (SP2 §7) --------------------------------------------
# Stable cross-run identity that folds in qualname + a taint-path signature so
# two taint paths into one sink (same file/rule/line, different path) get
# DISTINCT fingerprints (Filigree drift constraint). Discrimination is only as
# fine as the supplied ``taint_path`` — callers derive it from ``taint_provenance``
# (a single best-callee, not a full path), so two paths sharing best-callee AND
# returned taint will still collide. That is the spec's accepted granularity.
def compute_finding_fingerprint(
    *,
    rule_id: str,
    path: str,
    line_start: int | None,
    qualname: str | None = None,
    taint_path: str | None = None,
) -> str:
    digest = hashlib.sha256()
    parts = (rule_id, path, str(line_start), qualname or "", taint_path or "")
    digest.update("\x00".join(parts).encode())
    return digest.hexdigest()
```

- [ ] **Step 4: Run; expect PASS**

Run: `.venv/bin/python -m pytest tests/unit/core/test_finding.py -q`
Expected: PASS.

- [ ] **Step 5: Lint/type**

Run: `.venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: clean (no lingering references to the old name; `grep -rn compute_placeholder_fingerprint src tests` returns nothing).

---

### Task 7: PY-WL-101 untrusted-reaches-trusted

**Files:**
- Create: `src/wardline/scanner/rules/untrusted_reaches_trusted.py`
- Test: `tests/unit/scanner/rules/test_untrusted_reaches_trusted.py`

> CONTEXT: rules consume `AnalysisContext`. A test harness must build a real context. Provide this shared helper at the top of EACH rule test module (copy it — the engine wiring is identical and small):

```python
from __future__ import annotations

import textwrap
from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind
from wardline.scanner.analyzer import WardlineAnalyzer


def _analyze(tmp_path: Path, files: dict[str, str]):
    paths = []
    for rel, src in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(src), encoding="utf-8")
        paths.append(p)
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze(sorted(paths), WardlineConfig(), root=tmp_path)
    assert analyzer.last_context is not None
    return analyzer.last_context, findings
```

- [ ] **Step 1: Write the failing test**

`tests/unit/scanner/rules/test_untrusted_reaches_trusted.py` (paste the `_analyze` helper above, then):

```python
from wardline.scanner.rules.untrusted_reaches_trusted import UntrustedReachesTrusted


def _run(ctx) -> list:
    return UntrustedReachesTrusted().check(ctx)


def test_trusted_returning_raw_fires(tmp_path) -> None:
    ctx, _ = _analyze(tmp_path, {
        "io.py": "from wardline.decorators import external_boundary\n"
                 "@external_boundary\ndef read_raw(p):\n    return p\n",
        "svc.py": "from wardline.decorators import trusted\n"
                  "from io import read_raw\n"
                  "@trusted\ndef leaky(p):\n    return read_raw(p)\n",
    })
    findings = _run(ctx)
    ids = {(f.rule_id, f.qualname) for f in findings}
    assert ("PY-WL-101", "svc.leaky") in ids
    assert all(f.kind == Kind.DEFECT for f in findings)


def test_trusted_returning_validated_is_clean(tmp_path) -> None:
    # @trusted(ASSURED) returning a @trust_boundary(ASSURED) result == declared; no fire.
    ctx, _ = _analyze(tmp_path, {
        "io.py": "from wardline.decorators import external_boundary, trust_boundary\n"
                 "@external_boundary\ndef read_raw(p):\n    return p\n"
                 "@trust_boundary(to_level='ASSURED')\n"
                 "def validate(p):\n    if not p:\n        raise ValueError\n    return p\n",
        "svc.py": "from wardline.decorators import trusted\n"
                  "from io import read_raw, validate\n"
                  "@trusted(level='ASSURED')\ndef safe(p):\n    return validate(read_raw(p))\n",
    })
    assert _run(ctx) == []


def test_external_boundary_returning_raw_is_gated_out(tmp_path) -> None:
    # @external_boundary's declared return is EXTERNAL_RAW (raw zone) -> trust-claim
    # gate excludes it even though it returns raw data. (Idiomatic boundary code.)
    ctx, _ = _analyze(tmp_path, {
        "io.py": "from wardline.decorators import external_boundary\n"
                 "@external_boundary\ndef handler(p):\n    return p\n",
    })
    assert _run(ctx) == []


def test_undecorated_is_silent(tmp_path) -> None:
    ctx, _ = _analyze(tmp_path, {"m.py": "def f(p):\n    return p\n"})
    assert _run(ctx) == []


def test_trusted_returning_constant_is_clean(tmp_path) -> None:
    ctx, _ = _analyze(tmp_path, {
        "m.py": "from wardline.decorators import trusted\n@trusted\ndef f():\n    return 1\n",
    })
    assert _run(ctx) == []
```

- [ ] **Step 2: Run; expect failure**

Run: `.venv/bin/python -m pytest tests/unit/scanner/rules/test_untrusted_reaches_trusted.py -q`
Expected: FAIL — module does not exist.

- [ ] **Step 3: Implement PY-WL-101**

`src/wardline/scanner/rules/untrusted_reaches_trusted.py`:
```python
# src/wardline/scanner/rules/untrusted_reaches_trusted.py
"""PY-WL-101 — untrusted data reaches a trusted producer.

Fires on an *anchored* function whose ACTUAL returned-value taint is strictly
less-trusted than its DECLARED return tier — i.e. untrusted data flows out of a
function that claims to produce trusted data. Gated by a trust claim: the
declared return must NOT be in the raw/freedom zone, which excludes
``@external_boundary`` (whose job is to return raw) and all undecorated code, and
is what makes the strict rank comparison safe. Declaration-gated, so it emits at
base severity (NOT tier-modulated).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Location, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.taints import TRUST_RANK, TaintState
from wardline.scanner.rules.metadata import RuleMetadata

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext

_RAW_ZONE: frozenset[TaintState] = frozenset(
    {TaintState.EXTERNAL_RAW, TaintState.UNKNOWN_RAW, TaintState.MIXED_RAW}
)

METADATA = RuleMetadata(
    rule_id="PY-WL-101",
    base_severity=Severity.ERROR,
    kind=Kind.DEFECT,
    description=(
        "A trust-anchored function returns data less trusted than the level it "
        "declares — untrusted data reaches a trusted producer with no validation."
    ),
    examples_violation=("@trusted\ndef f(p):\n    return read_raw(p)",),
    examples_clean=("@trusted(level='ASSURED')\ndef f(p):\n    return validate(read_raw(p))",),
)


class UntrustedReachesTrusted:
    rule_id = METADATA.rule_id
    metadata = METADATA

    def __init__(self, base_severity: Severity | None = None) -> None:
        self.base_severity = base_severity or METADATA.base_severity

    def check(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for qualname, entity in context.entities.items():
            prov = context.taint_provenance.get(qualname)
            if prov is None or prov.source != "anchored":
                continue
            declared = context.project_return_taints.get(qualname)
            if declared is None or declared in _RAW_ZONE:
                continue  # trust-claim gate
            actual = context.function_return_taints.get(qualname)
            if actual is None:
                continue  # no value-bearing return -> nothing to police
            if TRUST_RANK[actual] <= TRUST_RANK[declared]:
                continue  # returns data at-least-as-trusted as declared
            taint_path = f"{actual.value}->{declared.value}|{prov.via_callee or ''}"
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    message=(
                        f"{qualname} declares return trust {declared.value} but actually "
                        f"returns {actual.value} (less trusted) — untrusted data reaches a "
                        f"trusted producer"
                    ),
                    severity=self.base_severity,
                    kind=Kind.DEFECT,
                    location=entity.location,
                    fingerprint=_fp(
                        rule_id=self.rule_id,
                        path=entity.location.path,
                        line_start=entity.location.line_start,
                        qualname=qualname,
                        taint_path=taint_path,
                    ),
                    qualname=qualname,
                    properties={"declared_return": declared.value, "actual_return": actual.value},
                )
            )
        return findings
```

- [ ] **Step 4: Run; expect PASS**

Run: `.venv/bin/python -m pytest tests/unit/scanner/rules/test_untrusted_reaches_trusted.py -q`
Expected: PASS.

- [ ] **Step 5: Lint/type**

Run: `.venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: clean.

---

### Task 8: PY-WL-102 boundary-without-rejection

**Files:**
- Create: `src/wardline/scanner/rules/boundary_without_rejection.py`
- Test: `tests/unit/scanner/rules/test_boundary_without_rejection.py`

- [ ] **Step 1: Write the failing test** (paste the `_analyze` helper, then):

```python
from wardline.core.finding import Kind
from wardline.scanner.rules.boundary_without_rejection import BoundaryWithoutRejection


def _run(ctx):
    return BoundaryWithoutRejection().check(ctx)


def test_boundary_without_rejection_fires(tmp_path) -> None:
    # @trust_boundary that just returns its input — cannot reject -> DEFECT.
    ctx, _ = _analyze(tmp_path, {
        "m.py": "from wardline.decorators import trust_boundary\n"
                "@trust_boundary(to_level='ASSURED')\ndef v(p):\n    return p\n",
    })
    findings = _run(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-102", "m.v")]
    assert findings[0].kind == Kind.DEFECT


def test_boundary_with_raise_is_clean(tmp_path) -> None:
    ctx, _ = _analyze(tmp_path, {
        "m.py": "from wardline.decorators import trust_boundary\n"
                "@trust_boundary(to_level='ASSURED')\n"
                "def v(p):\n    if not p:\n        raise ValueError\n    return p\n",
    })
    assert _run(ctx) == []


def test_boundary_with_falsy_return_is_clean(tmp_path) -> None:
    ctx, _ = _analyze(tmp_path, {
        "m.py": "from wardline.decorators import trust_boundary\n"
                "@trust_boundary(to_level='GUARDED')\n"
                "def v(p):\n    if not p:\n        return None\n    return p\n",
    })
    assert _run(ctx) == []


def test_non_boundary_decorators_are_ignored(tmp_path) -> None:
    # @trusted (body == return, not a trust-raising transition) and @external_boundary
    # are NOT trust boundaries -> never flagged by PY-WL-102.
    ctx, _ = _analyze(tmp_path, {
        "m.py": "from wardline.decorators import trusted, external_boundary\n"
                "@trusted\ndef a():\n    return 1\n"
                "@external_boundary\ndef b(p):\n    return p\n",
    })
    assert _run(ctx) == []


def test_undecorated_is_silent(tmp_path) -> None:
    ctx, _ = _analyze(tmp_path, {"m.py": "def v(p):\n    return p\n"})
    assert _run(ctx) == []
```

- [ ] **Step 2: Run; expect failure**

Run: `.venv/bin/python -m pytest tests/unit/scanner/rules/test_boundary_without_rejection.py -q`
Expected: FAIL — module does not exist.

- [ ] **Step 3: Implement PY-WL-102**

`src/wardline/scanner/rules/boundary_without_rejection.py`:
```python
# src/wardline/scanner/rules/boundary_without_rejection.py
"""PY-WL-102 — a trust boundary with no rejection path.

A trust-RAISING transition (declared return strictly MORE trusted than body —
the taint shape unique to ``@trust_boundary`` among the vocabulary) that contains
no ``raise`` and no falsy-constant ``return`` cannot actually reject bad input,
so it is not validating. Declaration-gated (the decorator is the opt-in), so it
emits at base severity (NOT tier-modulated).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Location, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.taints import TRUST_RANK
from wardline.scanner.rules._ast_helpers import has_rejection_path
from wardline.scanner.rules.metadata import RuleMetadata

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext

METADATA = RuleMetadata(
    rule_id="PY-WL-102",
    base_severity=Severity.ERROR,
    kind=Kind.DEFECT,
    description=(
        "A trust boundary (a function that raises declared trust on its return) "
        "has no rejection path — no raise, no falsy-constant return — so it cannot "
        "validate."
    ),
    examples_violation=("@trust_boundary(to_level='ASSURED')\ndef v(p):\n    return p",),
    examples_clean=(
        "@trust_boundary(to_level='ASSURED')\n"
        "def v(p):\n    if not p:\n        raise ValueError\n    return p",
    ),
)


class BoundaryWithoutRejection:
    rule_id = METADATA.rule_id
    metadata = METADATA

    def __init__(self, base_severity: Severity | None = None) -> None:
        self.base_severity = base_severity or METADATA.base_severity

    def check(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for qualname, entity in context.entities.items():
            prov = context.taint_provenance.get(qualname)
            if prov is None or prov.source != "anchored":
                continue
            body = context.project_taints.get(qualname)
            ret = context.project_return_taints.get(qualname)
            if body is None or ret is None:
                continue
            # Trust-raising transition (== @trust_boundary): body less-trusted than return.
            if TRUST_RANK[body] <= TRUST_RANK[ret]:
                continue
            if has_rejection_path(entity.node):
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    message=(
                        f"{qualname} declares a trust boundary ({body.value} -> {ret.value}) "
                        f"but has no rejection path (no raise / no falsy return) — it cannot validate"
                    ),
                    severity=self.base_severity,
                    kind=Kind.DEFECT,
                    location=entity.location,
                    fingerprint=_fp(
                        rule_id=self.rule_id,
                        path=entity.location.path,
                        line_start=entity.location.line_start,
                        qualname=qualname,
                        taint_path=f"{body.value}->{ret.value}",
                    ),
                    qualname=qualname,
                    properties={"body_taint": body.value, "return_taint": ret.value},
                )
            )
        return findings
```

- [ ] **Step 4: Run; expect PASS**

Run: `.venv/bin/python -m pytest tests/unit/scanner/rules/test_boundary_without_rejection.py -q`
Expected: PASS.

- [ ] **Step 5: Lint/type**

Run: `.venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: clean.

---

### Task 9: PY-WL-103 broad-exception (tier-modulated)

**Files:**
- Create: `src/wardline/scanner/rules/broad_exception.py`
- Test: `tests/unit/scanner/rules/test_broad_exception.py`

- [ ] **Step 1: Write the failing test** (paste the `_analyze` helper, then):

```python
from wardline.core.finding import Kind, Severity
from wardline.scanner.rules.broad_exception import BroadException


def _run(ctx):
    return BroadException().check(ctx)


def test_broad_except_in_trusted_fires_at_base(tmp_path) -> None:
    ctx, _ = _analyze(tmp_path, {
        "m.py": "from wardline.decorators import trusted\n"
                "@trusted\ndef f():\n    try:\n        g()\n    except Exception:\n        h()\n",
    })
    findings = _run(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-103", "m.f")]
    assert findings[0].kind == Kind.DEFECT
    assert findings[0].severity == Severity.WARN  # base for PY-WL-103, trusted tier -> unchanged


def test_broad_except_in_undecorated_is_suppressed(tmp_path) -> None:
    # Undecorated -> UNKNOWN_RAW (freedom zone) -> modulate to NONE -> no finding.
    ctx, _ = _analyze(tmp_path, {
        "m.py": "def f():\n    try:\n        g()\n    except Exception:\n        h()\n",
    })
    assert _run(ctx) == []


def test_bare_except_fires(tmp_path) -> None:
    ctx, _ = _analyze(tmp_path, {
        "m.py": "from wardline.decorators import trusted\n"
                "@trusted\ndef f():\n    try:\n        g()\n    except:\n        h()\n",
    })
    assert [f.rule_id for f in _run(ctx)] == ["PY-WL-103"]


def test_specific_except_is_clean(tmp_path) -> None:
    ctx, _ = _analyze(tmp_path, {
        "m.py": "from wardline.decorators import trusted\n"
                "@trusted\ndef f():\n    try:\n        g()\n    except ValueError:\n        h()\n",
    })
    assert _run(ctx) == []
```

- [ ] **Step 2: Run; expect failure**

Run: `.venv/bin/python -m pytest tests/unit/scanner/rules/test_broad_exception.py -q`
Expected: FAIL — module does not exist.

> NOTE on the expected base severity: PY-WL-103 base = `Severity.WARN`. A `@trusted` function resolves to `INTEGRAL` (trusted tier) → `modulate(WARN, INTEGRAL) == WARN`. Confirm the assertion matches the base you set in METADATA.

- [ ] **Step 3: Implement PY-WL-103**

`src/wardline/scanner/rules/broad_exception.py`:
```python
# src/wardline/scanner/rules/broad_exception.py
"""PY-WL-103 — broad exception handler in a trusted-tier function.

``except:`` / ``except Exception`` / ``except BaseException`` swallows error
classes indiscriminately. Tier-modulated: the function's own body taint scales
the base severity (§5), so it is silent on undecorated (``UNKNOWN_RAW``) code and
only speaks where trust is declared.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Location, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.taints import TaintState
from wardline.scanner.rules._ast_helpers import is_broad_except, own_except_handlers
from wardline.scanner.rules.metadata import RuleMetadata
from wardline.scanner.rules.severity_model import modulate

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext

METADATA = RuleMetadata(
    rule_id="PY-WL-103",
    base_severity=Severity.WARN,
    kind=Kind.DEFECT,
    description="A broad exception handler (bare except / Exception / BaseException) "
    "in a trusted-tier function.",
    examples_violation=("@trusted\ndef f():\n    try:\n        g()\n    except Exception:\n        h()",),
    examples_clean=("@trusted\ndef f():\n    try:\n        g()\n    except ValueError:\n        h()",),
)


class BroadException:
    rule_id = METADATA.rule_id
    metadata = METADATA

    def __init__(self, base_severity: Severity | None = None) -> None:
        self.base_severity = base_severity or METADATA.base_severity

    def check(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for qualname, entity in context.entities.items():
            tier = context.project_taints.get(qualname, TaintState.UNKNOWN_RAW)
            severity = modulate(self.base_severity, tier)
            if severity == Severity.NONE:
                continue  # suppressed outside trusted/partial tiers
            for handler in own_except_handlers(entity.node):
                if not is_broad_except(handler):
                    continue
                line = handler.lineno
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        message=f"{qualname}: broad exception handler at line {line}",
                        severity=severity,
                        kind=Kind.DEFECT,
                        location=Location(path=entity.location.path, line_start=line),
                        fingerprint=_fp(
                            rule_id=self.rule_id,
                            path=entity.location.path,
                            line_start=line,
                            qualname=qualname,
                            taint_path=tier.value,
                        ),
                        qualname=qualname,
                        properties={"tier": tier.value},
                    )
                )
        return findings
```

- [ ] **Step 4: Run; expect PASS**

Run: `.venv/bin/python -m pytest tests/unit/scanner/rules/test_broad_exception.py -q`
Expected: PASS.

- [ ] **Step 5: Lint/type**

Run: `.venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: clean.

---

### Task 10: PY-WL-104 silent-exception (tier-modulated)

**Files:**
- Create: `src/wardline/scanner/rules/silent_exception.py`
- Test: `tests/unit/scanner/rules/test_silent_exception.py`

- [ ] **Step 1: Write the failing test** (paste the `_analyze` helper, then):

```python
from wardline.core.finding import Kind, Severity
from wardline.scanner.rules.silent_exception import SilentException


def _run(ctx):
    return SilentException().check(ctx)


def test_silent_handler_in_trusted_fires(tmp_path) -> None:
    ctx, _ = _analyze(tmp_path, {
        "m.py": "from wardline.decorators import trusted\n"
                "@trusted\ndef f():\n    try:\n        g()\n    except ValueError:\n        pass\n",
    })
    findings = _run(ctx)
    assert [(f.rule_id, f.qualname) for f in findings] == [("PY-WL-104", "m.f")]
    assert findings[0].severity == Severity.WARN  # base, trusted tier unchanged


def test_silent_handler_in_undecorated_is_suppressed(tmp_path) -> None:
    ctx, _ = _analyze(tmp_path, {
        "m.py": "def f():\n    try:\n        g()\n    except ValueError:\n        pass\n",
    })
    assert _run(ctx) == []


def test_handled_exception_is_clean(tmp_path) -> None:
    ctx, _ = _analyze(tmp_path, {
        "m.py": "from wardline.decorators import trusted\n"
                "@trusted\ndef f():\n    try:\n        g()\n    except ValueError:\n        log()\n",
    })
    assert _run(ctx) == []


def test_reraise_is_clean(tmp_path) -> None:
    ctx, _ = _analyze(tmp_path, {
        "m.py": "from wardline.decorators import trusted\n"
                "@trusted\ndef f():\n    try:\n        g()\n    except ValueError:\n        raise\n",
    })
    assert _run(ctx) == []
```

- [ ] **Step 2: Run; expect failure**

Run: `.venv/bin/python -m pytest tests/unit/scanner/rules/test_silent_exception.py -q`
Expected: FAIL — module does not exist.

- [ ] **Step 3: Implement PY-WL-104**

`src/wardline/scanner/rules/silent_exception.py` — identical structure to PY-WL-103, swapping the predicate and metadata:
```python
# src/wardline/scanner/rules/silent_exception.py
"""PY-WL-104 — silently swallowed exception in a trusted-tier function.

A handler whose body only ``pass``/``...``/``continue``/``break`` discards the
error with no logging, re-raise, or recovery. Tier-modulated (§5) — silent on
undecorated code.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Location, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.taints import TaintState
from wardline.scanner.rules._ast_helpers import is_silent_handler, own_except_handlers
from wardline.scanner.rules.metadata import RuleMetadata
from wardline.scanner.rules.severity_model import modulate

if TYPE_CHECKING:
    from wardline.scanner.context import AnalysisContext

METADATA = RuleMetadata(
    rule_id="PY-WL-104",
    base_severity=Severity.WARN,
    kind=Kind.DEFECT,
    description="An exception handler that silently swallows the error "
    "(only pass/.../continue/break) in a trusted-tier function.",
    examples_violation=("@trusted\ndef f():\n    try:\n        g()\n    except ValueError:\n        pass",),
    examples_clean=("@trusted\ndef f():\n    try:\n        g()\n    except ValueError:\n        log(e)",),
)


class SilentException:
    rule_id = METADATA.rule_id
    metadata = METADATA

    def __init__(self, base_severity: Severity | None = None) -> None:
        self.base_severity = base_severity or METADATA.base_severity

    def check(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for qualname, entity in context.entities.items():
            tier = context.project_taints.get(qualname, TaintState.UNKNOWN_RAW)
            severity = modulate(self.base_severity, tier)
            if severity == Severity.NONE:
                continue
            for handler in own_except_handlers(entity.node):
                if not is_silent_handler(handler):
                    continue
                line = handler.lineno
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        message=f"{qualname}: exception silently swallowed at line {line}",
                        severity=severity,
                        kind=Kind.DEFECT,
                        location=Location(path=entity.location.path, line_start=line),
                        fingerprint=_fp(
                            rule_id=self.rule_id,
                            path=entity.location.path,
                            line_start=line,
                            qualname=qualname,
                            taint_path=tier.value,
                        ),
                        qualname=qualname,
                        properties={"tier": tier.value},
                    )
                )
        return findings
```

- [ ] **Step 4: Run; expect PASS**

Run: `.venv/bin/python -m pytest tests/unit/scanner/rules/test_silent_exception.py -q`
Expected: PASS.

- [ ] **Step 5: Lint/type**

Run: `.venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: clean.

---

### Task 11: Default registry, analyzer wiring, config honoring, vocabulary-shape pin & xfail flip

**Files:**
- Modify: `src/wardline/scanner/rules/__init__.py` (add `build_default_registry`)
- Modify: `src/wardline/scanner/analyzer.py` (build + run default registry)
- Modify: `tests/test_self_hosting.py` (flip xfail)
- Test: `tests/unit/scanner/rules/test_default_registry.py`, `tests/unit/scanner/rules/test_vocabulary_shape_pin.py`

- [ ] **Step 1: Write the failing tests**

`tests/unit/scanner/rules/test_default_registry.py` (paste the `_analyze` helper from Task 7, then):
```python
from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind, Severity
from wardline.scanner.rules import build_default_registry


def test_default_registry_has_all_four_rules() -> None:
    reg = build_default_registry(WardlineConfig())
    ids = {r.rule_id for r in reg.rules}
    assert ids == {"PY-WL-101", "PY-WL-102", "PY-WL-103", "PY-WL-104"}


def test_rules_enable_filters() -> None:
    reg = build_default_registry(WardlineConfig(rules_enable=("PY-WL-101",)))
    assert {r.rule_id for r in reg.rules} == {"PY-WL-101"}
    reg2 = build_default_registry(WardlineConfig(rules_enable=("PY-WL-10[34]",)))  # fnmatch
    assert {r.rule_id for r in reg2.rules} == {"PY-WL-103", "PY-WL-104"}


def test_rules_severity_overrides_base() -> None:
    reg = build_default_registry(
        WardlineConfig(rules_severity={"PY-WL-103": "CRITICAL"})
    )
    rule = next(r for r in reg.rules if r.rule_id == "PY-WL-103")
    assert rule.base_severity == Severity.CRITICAL


def test_analyzer_runs_default_rules_end_to_end(tmp_path) -> None:
    # A @trusted function that leaks raw -> the analyzer (default registry) emits PY-WL-101.
    _, findings = _analyze(tmp_path, {
        "io.py": "from wardline.decorators import external_boundary\n"
                 "@external_boundary\ndef read_raw(p):\n    return p\n",
        "svc.py": "from wardline.decorators import trusted\nfrom io import read_raw\n"
                  "@trusted\ndef leaky(p):\n    return read_raw(p)\n",
    })
    defects = [f for f in findings if f.kind == Kind.DEFECT]
    assert any(f.rule_id == "PY-WL-101" and f.qualname == "svc.leaky" for f in defects)
```

`tests/unit/scanner/rules/test_vocabulary_shape_pin.py` (paste `_analyze`, then) — pins that the taint shapes the rules key off uniquely identify the three decorators (so SP2d cannot silently break the shape→decorator coupling):
```python
from wardline.core.taints import TaintState as T, TRUST_RANK


def test_decorator_taint_shapes_are_distinct_and_stable(tmp_path) -> None:
    ctx, _ = _analyze(tmp_path, {
        "m.py": "from wardline.decorators import external_boundary, trust_boundary, trusted\n"
                "@external_boundary\ndef eb(p):\n    return p\n"
                "@trust_boundary(to_level='ASSURED')\ndef tb(p):\n    return p\n"
                "@trusted(level='ASSURED')\ndef tr(p):\n    return p\n",
    })
    body = ctx.project_taints
    ret = ctx.project_return_taints
    # @external_boundary: body == return == EXTERNAL_RAW (raw-zone return -> PY-WL-101 gated)
    assert body["m.eb"] == T.EXTERNAL_RAW and ret["m.eb"] == T.EXTERNAL_RAW
    # @trust_boundary: trust-RAISING transition (body strictly less trusted than return)
    assert TRUST_RANK[body["m.tb"]] > TRUST_RANK[ret["m.tb"]]
    # @trusted: body == return, both trusted (NOT a transition)
    assert body["m.tr"] == ret["m.tr"] == T.ASSURED
```

- [ ] **Step 2: Run; expect failure**

Run: `.venv/bin/python -m pytest tests/unit/scanner/rules/test_default_registry.py tests/unit/scanner/rules/test_vocabulary_shape_pin.py -q`
Expected: FAIL — `build_default_registry` does not exist (the shape-pin test may pass already once Task 3 is in).

- [ ] **Step 3: Implement `build_default_registry`**

Append to `src/wardline/scanner/rules/__init__.py`:
```python
from __future__ import annotations

import fnmatch
from typing import TYPE_CHECKING

from wardline.core.finding import Severity
from wardline.scanner.context import RuleRegistry
from wardline.scanner.rules.boundary_without_rejection import BoundaryWithoutRejection
from wardline.scanner.rules.broad_exception import BroadException
from wardline.scanner.rules.silent_exception import SilentException
from wardline.scanner.rules.untrusted_reaches_trusted import UntrustedReachesTrusted

if TYPE_CHECKING:
    from wardline.core.config import WardlineConfig

# Registration order = emission order (deterministic findings stream).
_ALL_RULE_CLASSES = (
    UntrustedReachesTrusted,
    BoundaryWithoutRejection,
    BroadException,
    SilentException,
)


def _enabled(rule_id: str, patterns: tuple[str, ...]) -> bool:
    """A rule is enabled if any pattern is ``*`` or fnmatch-matches its id."""
    return any(p == "*" or fnmatch.fnmatch(rule_id, p) for p in patterns)


def build_default_registry(config: WardlineConfig) -> RuleRegistry:
    """Build the SP2 rule set, honoring ``config.rules_enable`` (fnmatch include
    list; ``*`` = all) and ``config.rules_severity`` (per-rule base-severity
    override, applied BEFORE tier modulation). An unknown severity string raises
    ``ValueError`` (a config error surfaced eagerly)."""
    registry = RuleRegistry()
    for cls in _ALL_RULE_CLASSES:
        rule_id = cls.rule_id
        if not _enabled(rule_id, config.rules_enable):
            continue
        override = config.rules_severity.get(rule_id)
        base = Severity(override) if override is not None else None
        registry.register(cls(base_severity=base))
    return registry
```

> NOTE: the module already has the package docstring from Task 4. Keep `from __future__ import annotations` as the FIRST statement after the docstring — move it to the top if the docstring-only `__init__.py` lacked it. Do not duplicate the docstring.

- [ ] **Step 4: Wire the analyzer to build + run the default registry**

In `analyzer.py`:

(a) Add import (top level, not under TYPE_CHECKING — it is called at runtime):
```python
from wardline.scanner.rules import build_default_registry
```

(b) Change `__init__` so an un-injected registry is built per-config at `analyze` time. Replace `self._registry = registry or RuleRegistry()` with:
```python
        self._registry = registry  # None -> build the default set per-config in analyze()
```
(Keep the `RuleRegistry` import for the type annotation / injected case.)

(c) Replace the final `findings.extend(self._registry.run(context))  # empty in SP1` with:
```python
        registry = self._registry if self._registry is not None else build_default_registry(config)
        findings.extend(registry.run(context))
```

- [ ] **Step 5: Flip the self-hosting xfail**

Replace the entire body of `tests/test_self_hosting.py` with:
```python
from __future__ import annotations

from pathlib import Path

from wardline.core.config import WardlineConfig
from wardline.core.finding import Kind
from wardline.scanner.analyzer import WardlineAnalyzer


def test_wardline_scans_itself_clean() -> None:
    # SP2c: run Wardline's default rule set over its own src/wardline and assert
    # zero DEFECT findings. Clean BY CONSTRUCTION — src/wardline applies none of
    # its own trust decorators, so every function resolves to UNKNOWN_RAW:
    # PY-WL-101/102 are not-anchored-gated, PY-WL-103/104 tier-modulate to NONE.
    repo_root = Path(__file__).resolve().parent.parent
    src = repo_root / "src" / "wardline"
    files = sorted(src.rglob("*.py"))
    assert files, "expected to find Wardline source files"
    analyzer = WardlineAnalyzer()
    findings = analyzer.analyze(files, WardlineConfig(), root=repo_root)
    defects = [f for f in findings if f.kind == Kind.DEFECT]
    assert defects == [], (
        f"self-hosting found {len(defects)} DEFECT(s): "
        f"{[(d.rule_id, d.location.path, d.location.line_start) for d in defects]}"
    )
```

- [ ] **Step 6: Run the full suite + lint/type**

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: ALL PASS — **no xfail remaining** (self-hosting now passes). Report the new total.

- [ ] **Step 7: Verify the CLI scan path is unaffected**

Run: `.venv/bin/python -m pytest tests/unit/cli -q`
Expected: PASS — the CLI uses `WardlineAnalyzer` and now emits DEFECT findings where trust is declared; CLI tests over undecorated fixtures stay clean.

---

## Self-Review

**Spec coverage (§ → task):** §5 severity model → Task 4; §4 four rules → Tasks 7–10 (+ helpers Task 5); §7 fingerprint → Task 6; §6 registry import surface — unchanged (preserved since SP2a), NG-25 descriptor is SP2d; §8 analyzer wiring + `rules_enable`/`rules_severity` → Task 11; xfail flip → Task 11; body-vs-return plumbing (risk §11.3) → Tasks 1–3.

**Type consistency:** `RuleMetadata.rule_id` == each rule's `rule_id` class attr == `METADATA.rule_id`. `AnalysisContext` field order is fixed in Task 3 and consumed positionally nowhere (all keyword construction). `compute_finding_fingerprint` is keyword-only; every call site uses keywords. `modulate(base, taint)` arg order consistent across all callers.

**Placeholder scan:** no TBD/TODO; every code step shows complete code. The one trap — the deliberately-not-to-add `_REJECTION_STMTS` line in Task 5 — is called out explicitly to remove.

**Known granularity limit (documented, not a bug):** fingerprint discrimination is bounded by `taint_provenance.via_callee` (single best-callee), per spec §7.
