# CORE-011: Dependency Taint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement §5.5 dependency taint — manifest-declared taint for third-party library calls with explicit UNKNOWN_RAW fallback for undeclared patterns.

**Architecture:** Manifest `dependency_taint` entries declare what taint state third-party function calls return. At scan time, the engine resolves import aliases per-file to map FQN declarations to local call syntax (both bare names like `read_csv()` and dotted names like `pd.read_csv()`). Unresolved calls to declared dependency packages fall back to UNKNOWN_RAW. The taint_map passed to Level 2 variable-level tracking carries both project-local and dependency-resolved entries, keeping the L2 code unaware of the distinction.

**Tech Stack:** Python 3.12+, JSON Schema, pytest, existing wardline manifest/scanner infrastructure.

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `src/wardline/manifest/schemas/wardline.schema.json` | Modify | Add `dependency_taint` property |
| `src/wardline/manifest/models.py` | Modify | Add `DependencyTaintEntry` dataclass, add field to `WardlineManifest` |
| `src/wardline/manifest/loader.py` | Modify | Parse `dependency_taint` entries in `_build_manifest()` |
| `src/wardline/scanner/engine.py` | Modify | Build per-file resolved dependency taint map, inject into callee_taint_map |
| `src/wardline/scanner/taint/variable_level.py` | Modify | Extend `_resolve_call()` to check taint_map for dotted dependency names, add UNKNOWN_RAW fallback for declared-but-unresolved package calls |
| `tests/unit/manifest/test_loader.py` | Modify | Test dependency_taint loading |
| `tests/unit/scanner/test_variable_level_taint.py` | Modify | Test dependency taint resolution + UNKNOWN_RAW fallback |
| `tests/unit/scanner/test_engine_dependency_taint.py` | Create | Integration test: engine wires dependency taint through to L2 |
| `docs/spec/wardline-02-A-python-binding.md` | Modify | Add §A.15 dependency taint documentation |

---

### Task 1: Schema — Add dependency_taint to wardline.schema.json

**Files:**
- Modify: `src/wardline/manifest/schemas/wardline.schema.json:157-162`
- Test: `tests/unit/manifest/test_loader.py`

- [ ] **Step 1: Write the failing test — schema rejects dependency_taint**

Add to `tests/unit/manifest/test_loader.py`:

```python
class TestDependencyTaintLoading:
    """Test dependency_taint manifest section loading."""

    def test_dependency_taint_loads(self, tmp_path: Path) -> None:
        """A manifest with dependency_taint entries loads without error."""
        manifest_yaml = tmp_path / "wardline.yaml"
        manifest_yaml.write_text(textwrap.dedent("""\
            $id: "https://wardline.dev/schemas/0.1/wardline.schema.json"
            tiers:
              - id: INTEGRAL
                tier: 1
              - id: EXTERNAL_RAW
                tier: 4
            dependency_taint:
              - package: "requests>=2.0"
                function: "requests.get"
                returns_taint: "EXTERNAL_RAW"
                rationale: "HTTP response is untrusted external data"
              - package: "requests>=2.0"
                function: "requests.post"
                returns_taint: "EXTERNAL_RAW"
                rationale: "HTTP response is untrusted external data"
        """))
        manifest = load_manifest(manifest_yaml)
        assert len(manifest.dependency_taint) == 2
        assert manifest.dependency_taint[0].function == "requests.get"
        assert manifest.dependency_taint[0].returns_taint == "EXTERNAL_RAW"
        assert manifest.dependency_taint[0].package == "requests>=2.0"
        assert manifest.dependency_taint[0].rationale == "HTTP response is untrusted external data"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/manifest/test_loader.py::TestDependencyTaintLoading::test_dependency_taint_loads -xvs`
Expected: FAIL — schema validation rejects `dependency_taint` (additionalProperties: false)

- [ ] **Step 3: Add dependency_taint to JSON Schema**

In `src/wardline/manifest/schemas/wardline.schema.json`, add before `"overlay_paths"`:

```json
    "dependency_taint": {
      "type": "array",
      "description": "Third-party dependency taint declarations (§5.5). Declares what taint state a library function's return value carries.",
      "items": {
        "type": "object",
        "properties": {
          "package": {
            "type": "string",
            "description": "Package identifier with optional version constraint (e.g. 'requests>=2.0,<3.0')."
          },
          "function": {
            "type": "string",
            "description": "Fully-qualified function name (e.g. 'requests.get')."
          },
          "returns_taint": {
            "type": "string",
            "enum": [
              "INTEGRAL", "ASSURED", "GUARDED",
              "EXTERNAL_RAW", "UNKNOWN_RAW",
              "UNKNOWN_GUARDED", "UNKNOWN_ASSURED",
              "MIXED_RAW"
            ],
            "description": "Taint state of the function's return value."
          },
          "rationale": {
            "type": "string",
            "description": "Governance justification for this taint declaration."
          }
        },
        "required": ["package", "function", "returns_taint", "rationale"],
        "additionalProperties": false
      }
    },
```

- [ ] **Step 4: Run test to verify schema passes but model fails**

Run: `uv run pytest tests/unit/manifest/test_loader.py::TestDependencyTaintLoading::test_dependency_taint_loads -xvs`
Expected: FAIL — `WardlineManifest` has no `dependency_taint` attribute (not yet added to model)

- [ ] **Step 5: Commit**

```bash
git add src/wardline/manifest/schemas/wardline.schema.json tests/unit/manifest/test_loader.py
git commit -m "feat(schema): add dependency_taint to wardline.schema.json (CORE-011)"
```

---

### Task 2: Model + Loader — DependencyTaintEntry and manifest loading

**Files:**
- Modify: `src/wardline/manifest/models.py`
- Modify: `src/wardline/manifest/loader.py`
- Test: `tests/unit/manifest/test_loader.py`

- [ ] **Step 1: Add DependencyTaintEntry dataclass to models.py**

After `ModuleTierEntry` (around line 93), add:

```python
@dataclass(frozen=True)
class DependencyTaintEntry:
    """A third-party dependency taint declaration (§5.5).

    Declares what taint state a specific library function's return value
    carries. Undeclared functions in declared packages fall back to
    UNKNOWN_RAW.
    """

    package: str
    function: str
    returns_taint: str
    rationale: str
```

- [ ] **Step 2: Add dependency_taint field to WardlineManifest**

In `WardlineManifest` (after `module_tiers`), add:

```python
    dependency_taint: tuple[DependencyTaintEntry, ...] = ()
```

- [ ] **Step 3: Add loading logic to loader.py**

In `_build_manifest()` (around line 270, after `module_tiers`), add:

```python
    dependency_taint = tuple(
        DependencyTaintEntry(
            package=d["package"],
            function=d["function"],
            returns_taint=d["returns_taint"],
            rationale=d["rationale"],
        )
        for d in data.get("dependency_taint", [])
    )
```

Also add `DependencyTaintEntry` to the imports at the top of loader.py, and pass `dependency_taint=dependency_taint` to the `WardlineManifest(...)` constructor.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/unit/manifest/test_loader.py::TestDependencyTaintLoading -xvs`
Expected: PASS

- [ ] **Step 5: Add edge-case tests**

Add to `TestDependencyTaintLoading`:

```python
    def test_empty_dependency_taint(self, tmp_path: Path) -> None:
        """Manifest without dependency_taint loads with empty tuple."""
        manifest_yaml = tmp_path / "wardline.yaml"
        manifest_yaml.write_text(textwrap.dedent("""\
            $id: "https://wardline.dev/schemas/0.1/wardline.schema.json"
            tiers:
              - id: INTEGRAL
                tier: 1
        """))
        manifest = load_manifest(manifest_yaml)
        assert manifest.dependency_taint == ()

    def test_dependency_taint_missing_required_field(self, tmp_path: Path) -> None:
        """Missing required field in dependency_taint entry fails schema validation."""
        manifest_yaml = tmp_path / "wardline.yaml"
        manifest_yaml.write_text(textwrap.dedent("""\
            $id: "https://wardline.dev/schemas/0.1/wardline.schema.json"
            dependency_taint:
              - package: "requests>=2.0"
                function: "requests.get"
        """))
        with pytest.raises(ManifestLoadError, match="Schema validation failed"):
            load_manifest(manifest_yaml)

    def test_dependency_taint_invalid_taint_state(self, tmp_path: Path) -> None:
        """Invalid returns_taint value fails schema validation."""
        manifest_yaml = tmp_path / "wardline.yaml"
        manifest_yaml.write_text(textwrap.dedent("""\
            $id: "https://wardline.dev/schemas/0.1/wardline.schema.json"
            dependency_taint:
              - package: "requests>=2.0"
                function: "requests.get"
                returns_taint: "INVALID_TAINT"
                rationale: "test"
        """))
        with pytest.raises(ManifestLoadError, match="Schema validation failed"):
            load_manifest(manifest_yaml)
```

- [ ] **Step 6: Run all tests**

Run: `uv run pytest tests/unit/manifest/test_loader.py -xvs`
Expected: All PASS

- [ ] **Step 7: Commit**

```bash
git add src/wardline/manifest/models.py src/wardline/manifest/loader.py tests/unit/manifest/test_loader.py
git commit -m "feat(manifest): add DependencyTaintEntry model and loader (CORE-011)"
```

---

### Task 3: Engine — Build resolved dependency taint map and inject into L2

**Files:**
- Modify: `src/wardline/scanner/engine.py:654-690` (`_run_variable_taint`)
- Test: `tests/unit/scanner/test_engine_dependency_taint.py` (create)

- [ ] **Step 1: Write the failing integration test**

Create `tests/unit/scanner/test_engine_dependency_taint.py`:

```python
"""Integration test: engine wires dependency taint through to L2 variable taint."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from wardline.core.taints import TaintState
from wardline.manifest.models import (
    DependencyTaintEntry,
    ModuleTierEntry,
    TierEntry,
    WardlineManifest,
)
from wardline.scanner.engine import ScanEngine


def _minimal_manifest(
    dependency_taint: tuple[DependencyTaintEntry, ...] = (),
) -> WardlineManifest:
    return WardlineManifest(
        tiers=(
            TierEntry(id="INTEGRAL", tier=1),
            TierEntry(id="ASSURED", tier=2),
            TierEntry(id="GUARDED", tier=3),
            TierEntry(id="EXTERNAL_RAW", tier=4),
        ),
        module_tiers=(
            ModuleTierEntry(path="src", default_taint="INTEGRAL"),
        ),
        dependency_taint=dependency_taint,
    )


class TestDependencyTaintWiring:
    """Verify engine resolves dependency taint declarations into L2 variable taint."""

    def test_dotted_call_gets_declared_taint(self, tmp_path: Path) -> None:
        """import requests; x = requests.get(url) → x is EXTERNAL_RAW."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "app.py").write_text(textwrap.dedent("""\
            import requests

            def fetch():
                x = requests.get("http://example.com")
                return x
        """))
        manifest = _minimal_manifest(
            dependency_taint=(
                DependencyTaintEntry(
                    package="requests>=2.0",
                    function="requests.get",
                    returns_taint="EXTERNAL_RAW",
                    rationale="HTTP response is untrusted",
                ),
            ),
        )
        engine = ScanEngine(
            manifest=manifest,
            target_paths=(src,),
            analysis_level=2,
        )
        result = engine.scan()
        # Find the variable taint for fetch.x
        for file_result in result.file_results:
            if file_result.context is not None and file_result.context.variable_taint_map is not None:
                fetch_vars = file_result.context.variable_taint_map.get("fetch")
                if fetch_vars is not None:
                    assert fetch_vars["x"] == TaintState.EXTERNAL_RAW
                    return
        pytest.fail("Variable taint for fetch.x not found")

    def test_bare_import_gets_declared_taint(self, tmp_path: Path) -> None:
        """from requests import get; x = get(url) → x is EXTERNAL_RAW."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "app.py").write_text(textwrap.dedent("""\
            from requests import get

            def fetch():
                x = get("http://example.com")
                return x
        """))
        manifest = _minimal_manifest(
            dependency_taint=(
                DependencyTaintEntry(
                    package="requests>=2.0",
                    function="requests.get",
                    returns_taint="EXTERNAL_RAW",
                    rationale="HTTP response is untrusted",
                ),
            ),
        )
        engine = ScanEngine(
            manifest=manifest,
            target_paths=(src,),
            analysis_level=2,
        )
        result = engine.scan()
        for file_result in result.file_results:
            if file_result.context is not None and file_result.context.variable_taint_map is not None:
                fetch_vars = file_result.context.variable_taint_map.get("fetch")
                if fetch_vars is not None:
                    assert fetch_vars["x"] == TaintState.EXTERNAL_RAW
                    return
        pytest.fail("Variable taint for fetch.x not found")

    def test_aliased_import_gets_declared_taint(self, tmp_path: Path) -> None:
        """import requests as req; x = req.get(url) → x is EXTERNAL_RAW."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "app.py").write_text(textwrap.dedent("""\
            import requests as req

            def fetch():
                x = req.get("http://example.com")
                return x
        """))
        manifest = _minimal_manifest(
            dependency_taint=(
                DependencyTaintEntry(
                    package="requests>=2.0",
                    function="requests.get",
                    returns_taint="EXTERNAL_RAW",
                    rationale="HTTP response is untrusted",
                ),
            ),
        )
        engine = ScanEngine(
            manifest=manifest,
            target_paths=(src,),
            analysis_level=2,
        )
        result = engine.scan()
        for file_result in result.file_results:
            if file_result.context is not None and file_result.context.variable_taint_map is not None:
                fetch_vars = file_result.context.variable_taint_map.get("fetch")
                if fetch_vars is not None:
                    assert fetch_vars["x"] == TaintState.EXTERNAL_RAW
                    return
        pytest.fail("Variable taint for fetch.x not found")

    def test_undeclared_function_in_declared_package_gets_unknown_raw(self, tmp_path: Path) -> None:
        """import requests; x = requests.head(url) when only requests.get is declared → UNKNOWN_RAW."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "app.py").write_text(textwrap.dedent("""\
            import requests

            def fetch():
                x = requests.head("http://example.com")
                return x
        """))
        manifest = _minimal_manifest(
            dependency_taint=(
                DependencyTaintEntry(
                    package="requests>=2.0",
                    function="requests.get",
                    returns_taint="EXTERNAL_RAW",
                    rationale="HTTP response is untrusted",
                ),
            ),
        )
        engine = ScanEngine(
            manifest=manifest,
            target_paths=(src,),
            analysis_level=2,
        )
        result = engine.scan()
        for file_result in result.file_results:
            if file_result.context is not None and file_result.context.variable_taint_map is not None:
                fetch_vars = file_result.context.variable_taint_map.get("fetch")
                if fetch_vars is not None:
                    # Undeclared function in declared package → UNKNOWN_RAW
                    assert fetch_vars["x"] == TaintState.UNKNOWN_RAW
                    return
        pytest.fail("Variable taint for fetch.x not found")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/scanner/test_engine_dependency_taint.py -xvs`
Expected: FAIL — dependency taint not wired through engine

- [ ] **Step 3: Add engine wiring in _run_variable_taint()**

In `src/wardline/scanner/engine.py`, in the `_run_variable_taint()` method, after building `callee_taint_map` (around line 676), add the dependency taint resolution:

```python
        # Dependency taint: resolve manifest declarations via import aliases.
        # Build a dict of FQN → TaintState from manifest entries.
        dep_fqn_map: dict[str, TaintState] = {}
        dep_packages: set[str] = set()
        if self._manifest is not None:
            for entry in self._manifest.dependency_taint:
                try:
                    dep_fqn_map[entry.function] = TaintState(entry.returns_taint)
                except ValueError:
                    pass
                # Track package prefixes for UNKNOWN_RAW fallback
                pkg_prefix = entry.function.rsplit(".", 1)[0]
                dep_packages.add(pkg_prefix)

        # Resolve dependency FQNs to local names using import aliases.
        # This populates callee_taint_map with both bare and dotted local names.
        resolved_dep_dotted: dict[str, TaintState] = {}
        dep_local_prefixes: frozenset[str] = frozenset()
        if dep_fqn_map:
            import_aliases = build_import_alias_map(tree)
            local_prefix_set: set[str] = set()
            for local_name, resolved_fqn in import_aliases.items():
                # Bare import: from requests import get → get is local name
                if resolved_fqn in dep_fqn_map:
                    callee_taint_map.setdefault(local_name, dep_fqn_map[resolved_fqn])
                # Module import: import requests → requests.get is dotted local
                for fqn, taint in dep_fqn_map.items():
                    if fqn.startswith(resolved_fqn + "."):
                        suffix = fqn[len(resolved_fqn) + 1:]
                        dotted_local = f"{local_name}.{suffix}"
                        resolved_dep_dotted[dotted_local] = taint
                # Track if this import maps to a declared package
                if resolved_fqn in dep_packages or any(
                    fqn.startswith(resolved_fqn + ".") for fqn in dep_fqn_map
                ):
                    local_prefix_set.add(local_name)
            dep_local_prefixes = frozenset(local_prefix_set)
```

Then update the `compute_variable_taints` call (inside the `for node in ast.walk(tree):` loop) to pass the new params:

```python
                        var_taints = compute_variable_taints(
                            node, func_taint, callee_taint_map,
                            dependency_dotted_map=resolved_dep_dotted,
                            dependency_local_prefixes=dep_local_prefixes,
                        )
```

- [ ] **Step 4: Run tests to verify they still fail (variable_level.py not updated yet)**

Run: `uv run pytest tests/unit/scanner/test_engine_dependency_taint.py::TestDependencyTaintWiring::test_bare_import_gets_declared_taint -xvs`
Expected: This one might PASS now (bare import resolved into callee_taint_map). The dotted tests will still fail.

- [ ] **Step 5: Commit**

```bash
git add src/wardline/scanner/engine.py tests/unit/scanner/test_engine_dependency_taint.py
git commit -m "feat(engine): resolve dependency taint into callee_taint_map (CORE-011)"
```

---

### Task 4: Variable-level — Extend _resolve_call() for dotted dependency taint + UNKNOWN_RAW fallback

**Files:**
- Modify: `src/wardline/scanner/taint/variable_level.py`
- Test: `tests/unit/scanner/test_variable_level_taint.py`

- [ ] **Step 1: Write unit tests for dotted dependency taint resolution**

Add to `tests/unit/scanner/test_variable_level_taint.py`:

```python
# ── Dependency taint (§5.5 / CORE-011) ──────────────────────────


class TestDependencyTaint:
    """§5.5: third-party dependency taint declarations."""

    def test_dotted_call_resolved_via_taint_map(self) -> None:
        """pd.read_csv() with 'pd.read_csv' in taint_map → declared taint."""
        func = _parse_func("""
            def f():
                x = pd.read_csv("data.csv")
        """)
        taint_map = {"pd.read_csv": TaintState.EXTERNAL_RAW}
        result = compute_variable_taints(func, TaintState.INTEGRAL, taint_map)
        assert result["x"] == TaintState.EXTERNAL_RAW

    def test_undeclared_function_in_declared_package_unknown_raw(self) -> None:
        """pd.merge() when only pd.read_csv declared → UNKNOWN_RAW."""
        func = _parse_func("""
            def f():
                x = pd.merge(a, b)
        """)
        taint_map = {"pd.read_csv": TaintState.EXTERNAL_RAW}
        result = compute_variable_taints(
            func, TaintState.INTEGRAL, taint_map,
            dependency_dotted_map={"pd.read_csv": TaintState.EXTERNAL_RAW},
            dependency_local_prefixes=frozenset({"pd"}),
        )
        assert result["x"] == TaintState.UNKNOWN_RAW

    def test_non_dependency_dotted_call_inherits_function_taint(self) -> None:
        """self.method() is not a dependency call — inherits function taint."""
        func = _parse_func("""
            def f(self):
                x = self.process()
        """)
        result = compute_variable_taints(
            func, TaintState.INTEGRAL, {},
            dependency_local_prefixes=frozenset({"pd"}),
        )
        assert result["x"] == TaintState.INTEGRAL

    def test_serialisation_sinks_still_take_priority(self) -> None:
        """json.dumps still sheds to UNKNOWN_RAW even with dependency taint."""
        func = _parse_func("""
            def f():
                x = json.dumps(data)
        """)
        # Even if json is in dependency declarations, serialisation sinks win
        taint_map = {"json.dumps": TaintState.INTEGRAL}
        result = compute_variable_taints(func, TaintState.INTEGRAL, taint_map)
        assert result["x"] == TaintState.UNKNOWN_RAW

    def test_declared_taint_overrides_function_taint(self) -> None:
        """Declared dependency taint is used instead of inheriting function taint."""
        func = _parse_func("""
            def f():
                x = pd.read_csv("data.csv")
                y = pd.DataFrame(data)
        """)
        taint_map = {
            "pd.read_csv": TaintState.EXTERNAL_RAW,
            "pd.DataFrame": TaintState.GUARDED,
        }
        result = compute_variable_taints(func, TaintState.INTEGRAL, taint_map)
        assert result["x"] == TaintState.EXTERNAL_RAW
        assert result["y"] == TaintState.GUARDED
```

- [ ] **Step 2: Run tests to verify failures**

Run: `uv run pytest tests/unit/scanner/test_variable_level_taint.py::TestDependencyTaint -xvs`
Expected: FAIL — `_resolve_call()` doesn't check taint_map for dotted names, `compute_variable_taints` doesn't accept new params

- [ ] **Step 3: Update compute_variable_taints signature**

Add optional keyword-only parameters:

```python
def compute_variable_taints(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    *,
    dependency_dotted_map: dict[str, TaintState] | None = None,
    dependency_local_prefixes: frozenset[str] = frozenset(),
) -> dict[str, TaintState]:
```

Thread these two values through to `_walk_body` → `_process_stmt` → all `_handle_*` functions → `_resolve_expr` → `_resolve_call`. Every internal function in variable_level.py that currently takes `(function_taint, taint_map, var_taints)` needs two additional params: `dep_dotted: dict[str, TaintState] | None` and `dep_prefixes: frozenset[str]`.

The threading is mechanical — each function passes the params through unchanged. Only `_resolve_call()` uses them.

- [ ] **Step 4: Update _resolve_call() with dependency taint logic**

```python
def _resolve_call(
    node: ast.Call,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
    dep_dotted: dict[str, TaintState] | None,
    dep_prefixes: frozenset[str],
) -> TaintState:
    """Resolve taint for a function call expression.

    Resolution order for dotted calls:
    1. Serialisation sinks (§5.2) → UNKNOWN_RAW
    2. Exact match in taint_map (dependency or local) → declared taint
    3. Prefix matches a declared dependency package → UNKNOWN_RAW (§5.5 fallback)
    4. Fallback → function_taint
    """
    if isinstance(node.func, ast.Attribute):
        dotted = _dotted_name(node.func)
        if dotted is not None:
            # 1. Serialisation sinks always shed to UNKNOWN_RAW
            if dotted in _SERIALISATION_SINKS:
                return TaintState.UNKNOWN_RAW
            # 2. Exact match in taint_map (pre-resolved dependency entries)
            if dotted in taint_map:
                return taint_map[dotted]
            # 3. §5.5 fallback: undeclared function in a declared package
            prefix = dotted.split(".", 1)[0]
            if prefix in dep_prefixes:
                return TaintState.UNKNOWN_RAW

    if isinstance(node.func, ast.Name):
        callee_name = node.func.id
        try:
            return taint_map[callee_name]
        except KeyError:
            pass
    return function_taint
```

- [ ] **Step 5: Run variable-level tests**

Run: `uv run pytest tests/unit/scanner/test_variable_level_taint.py -xvs`
Expected: All PASS (existing + new)

- [ ] **Step 6: Run engine integration tests**

Run: `uv run pytest tests/unit/scanner/test_engine_dependency_taint.py -xvs`
Expected: All PASS

- [ ] **Step 7: Run full test suite**

Run: `uv run pytest -x -q`
Expected: All pass (1950+ tests), no regressions

- [ ] **Step 8: Commit**

```bash
git add src/wardline/scanner/taint/variable_level.py tests/unit/scanner/test_variable_level_taint.py
git commit -m "feat(taint): dependency taint resolution + UNKNOWN_RAW fallback in L2 (CORE-011)"
```

---

### Task 5: Binding doc — Document dependency taint in Part II-A

**Files:**
- Modify: `docs/spec/wardline-02-A-python-binding.md`

- [ ] **Step 1: Add §A.15 Dependency taint**

Append after the existing §A.14:

```markdown
#### A.15 Dependency taint (§5.5)

*This section is non-normative. It documents the Python binding's approach to third-party dependency taint.*

**Manifest declaration.** Third-party library function return taints are declared in the root manifest under `dependency_taint`:

```yaml
dependency_taint:
  - package: "requests>=2.0,<3.0"
    function: "requests.get"
    returns_taint: "EXTERNAL_RAW"
    rationale: "HTTP response is untrusted external data"
  - package: "requests>=2.0,<3.0"
    function: "requests.post"
    returns_taint: "EXTERNAL_RAW"
    rationale: "HTTP response is untrusted external data"
```

**Resolution.** At scan time, the engine resolves declarations against each file's import statements:

| Import Form | Call Syntax | Resolution |
|---|---|---|
| `import requests` | `requests.get(url)` | `requests.get` → FQN match → declared taint |
| `import requests as req` | `req.get(url)` | `req` → alias for `requests` → `requests.get` → declared taint |
| `from requests import get` | `get(url)` | `get` → FQN `requests.get` → declared taint |

**UNKNOWN_RAW fallback (§5.5 MUST).** When a call targets a function in a package that has dependency_taint declarations, but the specific function is not declared, the return taint is `UNKNOWN_RAW`. This prevents undeclared library functions from inheriting the caller's taint.

**Compound patterns.** The following compound patterns fall back to `UNKNOWN_RAW` in v1.0:

| Pattern | Example | v1.0 Behaviour |
|---|---|---|
| Method chaining | `df.groupby("x").agg({"y": "sum"})` | UNKNOWN_RAW (intermediate not tracked) |
| Generator iteration | `for row in cursor.fetchall()` | Inherits iterable taint (use `for` target) |
| Context managers | `with db.connect() as conn` | Inherits context expr taint (use `with` target) |
| Async variants | `async for item in stream()` | Same as sync equivalents |

Method chaining beyond the first call is not resolved. Declare the root function; downstream methods inherit the root's declared taint through the variable taint system.

**Dependency taint is not a boundary declaration.** The manifest declares what data *is* when it arrives from ungoverned code. The application's own annotated boundaries declare what happens to it next.
```

- [ ] **Step 2: Commit**

```bash
git add docs/spec/wardline-02-A-python-binding.md
git commit -m "docs: add §A.15 dependency taint documentation (CORE-011)"
```

---

### Task 6: Update assessment

**Files:**
- Modify: `docs/requirements/spec-fitness/assessment-2026-03-29.md`

- [ ] **Step 1: Update CORE-011 from partial to pass**

Change the CORE-011 row to:

```
| WL-FIT-CORE-011 | Dependency taint compound call fallback | `pass` | `wardline.schema.json` dependency_taint section; `DependencyTaintEntry` model; engine resolves FQN→local via import aliases; `_resolve_call()` checks taint_map for dotted names; undeclared functions in declared packages → UNKNOWN_RAW; `test_engine_dependency_taint.py` + `test_variable_level_taint.py::TestDependencyTaint` | Full §5.5 MUST compliance; compound patterns documented as UNKNOWN_RAW fallback |
```

- [ ] **Step 2: Update summary metrics**

Framework Core: 13 pass → 14 pass, 4 partial → 3 partial. Total: 82 → 83 pass, 18 → 17 partial.

- [ ] **Step 3: Commit**

```bash
git add docs/requirements/spec-fitness/assessment-2026-03-29.md
git commit -m "docs: update CORE-011 assessment to pass"
```

---

## Implementation Notes

**Threading dep_dotted and dep_prefixes through variable_level.py.** Every internal function in this file that calls `_resolve_expr()` needs the two new params. The full list of functions requiring signature changes:

1. `compute_variable_taints()` — entry point, adds keyword-only params
2. `_walk_body()` — threads through
3. `_process_stmt()` — threads through
4. `_resolve_expr()` — threads to `_resolve_call()`
5. `_resolve_call()` — uses them
6. `_handle_assign()` — threads through
7. `_handle_unpack()` — threads through
8. `_handle_augassign()` — threads through
9. `_handle_if()` — threads through
10. `_handle_for()` — threads through
11. `_handle_while()` — threads through
12. `_handle_with()` — threads through
13. `_handle_try()` — threads through
14. `_walk_exprs_for_walrus()` — threads through

Each of these adds `dep_dotted: dict[str, TaintState] | None, dep_prefixes: frozenset[str]` to its signature and passes them through unchanged to any function it calls that also needs them. Only `_resolve_call()` reads the values.

**Why not a context object?** Adding a bundling dataclass would reduce the param count but requires changing every call site in variable_level.py anyway. The current approach is more explicit and follows the existing codebase convention of explicit param threading.
