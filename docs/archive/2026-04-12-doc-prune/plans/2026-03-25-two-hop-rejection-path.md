# Two-Hop Rejection Path Resolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable PY-WL-008 to recognise rejection paths delegated through function calls, eliminating false positives on validators that use schema libraries.

**Architecture:** Pre-compute a rejection path index (set of FQNs) during the engine's project indexing pass. Seed from direct rejection paths + known_validators config, expand one round for wrappers. PY-WL-008 checks the index when no direct rejection path is found. Import alias maps resolve call targets to FQNs.

**Tech Stack:** Python 3.12+, ast module, wardline scanner framework

**Spec:** `docs/superpowers/specs/2026-03-25-two-hop-rejection-path-design.md`

---

## File Structure

| Action | File | Responsibility |
|--------|------|----------------|
| Create | `src/wardline/scanner/rejection_path.py` | Extract `_has_rejection_path` + helpers, fix `_is_inside_dead_branch` bug |
| Create | `src/wardline/scanner/import_resolver.py` | `build_import_alias_map(tree)` + `resolve_call_fqn()` |
| Create | `tests/unit/scanner/test_import_resolver.py` | Tests for import alias resolution (12 cases) |
| Create | `tests/unit/scanner/test_delegated_rejection.py` | Tests for `_has_delegated_rejection` (6 cases) |
| Modify | `src/wardline/scanner/rules/py_wl_008.py` | Import from `rejection_path`, add `_has_delegated_rejection` |
| Modify | `src/wardline/scanner/context.py` | Add `rejection_path_index` + `import_alias_map` fields |
| Modify | `src/wardline/scanner/engine.py` | `ProjectIndex` dataclass, index computation, alias maps |
| Modify | `src/wardline/core/severity.py` | Add `GOVERNANCE_CUSTOM_KNOWN_VALIDATOR` RuleId |
| Modify | `src/wardline/scanner/sarif.py` | Register new RuleId |
| Modify | `src/wardline/manifest/models.py` | `known_validators` + `known_validators_extra` config |
| Modify | `tests/unit/scanner/test_py_wl_008.py` | Integration tests (13-23) + backward compat (29-30) |
| Modify | `tests/unit/core/test_severity.py` | Update RuleId count |

---

### Task 1: Extract `_has_rejection_path` to shared module

**Files:**
- Create: `src/wardline/scanner/rejection_path.py`
- Modify: `src/wardline/scanner/rules/py_wl_008.py`

This task extracts existing code with zero behavior change + fixes the `_is_inside_dead_branch` bug (uses `ast.walk` instead of `walk_skip_nested_defs`).

- [ ] **Step 1: Create `rejection_path.py` with extracted functions**

Copy from `py_wl_008.py` lines 36-129 into `src/wardline/scanner/rejection_path.py`:
- `_is_negative_guard`
- `_branch_has_rejection_terminator`
- `_is_constant_false`
- `_is_inside_dead_branch` — **FIX:** replace `ast.walk(root)` with `walk_skip_nested_defs(root)` and `ast.walk(stmt)` with `walk_skip_nested_defs(stmt)` to prevent nested function raises from affecting the outer function
- `_has_rejection_path`
- `has_rejection_path` (public alias, no underscore)

Import `walk_skip_nested_defs` from `wardline.scanner.rules.base`.

- [ ] **Step 2: Update `py_wl_008.py` to import from the new module**

Replace the local function definitions with:
```python
from wardline.scanner.rejection_path import has_rejection_path as _has_rejection_path
```

Remove the old function definitions (lines 36-129). Keep `_is_constant_false` and `_is_inside_dead_branch` removed — they live in `rejection_path.py` now.

- [ ] **Step 3: Run existing PY-WL-008 tests**

Run: `uv run pytest tests/unit/scanner/test_py_wl_008.py -v`
Expected: all pass (no behavior change except the nested-def bug fix)

- [ ] **Step 4: Run full suite**

Run: `uv run pytest tests/ -x --tb=short -q`
Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add src/wardline/scanner/rejection_path.py src/wardline/scanner/rules/py_wl_008.py
git commit -m "refactor(scanner): extract _has_rejection_path to scanner/rejection_path.py

Moved to scanner/ (not scanner/rules/) to avoid circular import
when the engine needs to call it during project indexing.

Also fixes pre-existing bug: _is_inside_dead_branch now uses
walk_skip_nested_defs to prevent nested function raises from
affecting the outer function's rejection path analysis."
```

---

### Task 2: Create import alias resolver

**Files:**
- Create: `src/wardline/scanner/import_resolver.py`
- Create: `tests/unit/scanner/test_import_resolver.py`

- [ ] **Step 1: Write tests for all 4 import forms + edge cases**

Create `tests/unit/scanner/test_import_resolver.py`:

```python
"""Tests for import alias resolution."""
from __future__ import annotations

import ast
import pytest

from wardline.scanner.import_resolver import build_import_alias_map


class TestBuildImportAliasMap:
    def test_import_module(self) -> None:
        tree = ast.parse("import jsonschema")
        assert build_import_alias_map(tree) == {"jsonschema": "jsonschema"}

    def test_import_module_as_alias(self) -> None:
        tree = ast.parse("import jsonschema as js")
        assert build_import_alias_map(tree) == {"js": "jsonschema"}

    def test_from_import(self) -> None:
        tree = ast.parse("from jsonschema import validate")
        assert build_import_alias_map(tree) == {"validate": "jsonschema.validate"}

    def test_from_import_as_alias(self) -> None:
        tree = ast.parse("from jsonschema import validate as v")
        assert build_import_alias_map(tree) == {"v": "jsonschema.validate"}

    def test_multiple_imports(self) -> None:
        tree = ast.parse("import os\nimport jsonschema as js\nfrom marshmallow import Schema")
        m = build_import_alias_map(tree)
        assert m["os"] == "os"
        assert m["js"] == "jsonschema"
        assert m["Schema"] == "marshmallow.Schema"

    def test_from_import_multiple_names(self) -> None:
        tree = ast.parse("from jsonschema import validate, Draft7Validator")
        m = build_import_alias_map(tree)
        assert m["validate"] == "jsonschema.validate"
        assert m["Draft7Validator"] == "jsonschema.Draft7Validator"

    def test_star_import_not_in_map(self) -> None:
        tree = ast.parse("from jsonschema import *")
        assert build_import_alias_map(tree) == {}

    def test_nested_import_in_function_ignored(self) -> None:
        tree = ast.parse("def f():\n    import jsonschema")
        assert build_import_alias_map(tree) == {}

    def test_empty_module(self) -> None:
        tree = ast.parse("")
        assert build_import_alias_map(tree) == {}

    def test_subpackage_import(self) -> None:
        tree = ast.parse("from jsonschema.validators import Draft7Validator")
        m = build_import_alias_map(tree)
        assert m["Draft7Validator"] == "jsonschema.validators.Draft7Validator"

    def test_dotted_module_import(self) -> None:
        tree = ast.parse("import jsonschema.validators")
        m = build_import_alias_map(tree)
        assert m["jsonschema"] == "jsonschema"

    def test_dotted_module_import_as_alias(self) -> None:
        tree = ast.parse("import jsonschema.validators as jv")
        m = build_import_alias_map(tree)
        assert m["jv"] == "jsonschema.validators"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/scanner/test_import_resolver.py -v`
Expected: ImportError (module doesn't exist yet)

- [ ] **Step 3: Implement `build_import_alias_map`**

Create `src/wardline/scanner/import_resolver.py`:

```python
"""Import alias resolution for two-hop rejection path analysis.

Builds a per-file mapping from local names to fully-qualified names
by walking module-level Import and ImportFrom statements.
"""
from __future__ import annotations

import ast


def build_import_alias_map(tree: ast.Module) -> dict[str, str]:
    """Build {local_name: fully_qualified_name} from module-level imports.

    Only processes top-level statements (not imports inside functions).
    Star imports (``from X import *``) are ignored — they cannot be
    resolved without executing the import.
    """
    alias_map: dict[str, str] = {}

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                # import jsonschema → {"jsonschema": "jsonschema"}
                # import jsonschema as js → {"js": "jsonschema"}
                # import jsonschema.validators → {"jsonschema": "jsonschema"}
                # import jsonschema.validators as jv → {"jv": "jsonschema.validators"}
                local_name = alias.asname if alias.asname else alias.name.split(".")[0]
                alias_map[local_name] = alias.name if alias.asname else alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue  # relative import with no module — skip
            for alias in node.names:
                if alias.name == "*":
                    continue  # star import — unresolvable
                # from jsonschema import validate → {"validate": "jsonschema.validate"}
                # from jsonschema import validate as v → {"v": "jsonschema.validate"}
                local_name = alias.asname if alias.asname else alias.name
                fqn = f"{node.module}.{alias.name}"
                alias_map[local_name] = fqn

    return alias_map


def resolve_call_fqn(
    call: ast.Call,
    alias_map: dict[str, str],
    local_fqns: frozenset[str],
    module_prefix: str,
) -> str | None:
    """Resolve an ast.Call to a fully-qualified name.

    Resolution order:
    1. If bare name matches a local FunctionDef FQN → return the local FQN
    2. If bare name or attribute prefix is in alias_map → resolve via import
    3. Otherwise → None (unresolvable)

    Args:
        call: The AST Call node.
        alias_map: {local_name: fqn} from build_import_alias_map.
        local_fqns: Set of FQNs for functions defined in this module.
        module_prefix: Module name prefix (e.g., "myproject.validators").
    """
    if isinstance(call.func, ast.Name):
        bare_name = call.func.id
        # Local definitions shadow imports
        local_candidate = f"{module_prefix}.{bare_name}" if module_prefix else bare_name
        if local_candidate in local_fqns:
            return local_candidate
        # Try import alias
        fqn = alias_map.get(bare_name)
        return fqn

    if isinstance(call.func, ast.Attribute):
        # obj.method() → resolve obj via alias map, concat .method
        if isinstance(call.func.value, ast.Name):
            prefix_fqn = alias_map.get(call.func.value.id)
            if prefix_fqn is not None:
                return f"{prefix_fqn}.{call.func.attr}"
        # self.method() → resolve via class qualname in local_fqns
        # (handled by caller building local_fqns with class.method qualnames)

    return None
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/unit/scanner/test_import_resolver.py -v`
Expected: all pass

- [ ] **Step 5: Lint and commit**

```bash
uv run ruff check src/wardline/scanner/import_resolver.py tests/unit/scanner/test_import_resolver.py
git add src/wardline/scanner/import_resolver.py tests/unit/scanner/test_import_resolver.py
git commit -m "feat(scanner): add import alias resolver for two-hop rejection path

build_import_alias_map() extracts {local_name: FQN} from module-level
Import/ImportFrom statements. resolve_call_fqn() resolves ast.Call
nodes to FQNs using the alias map with local-definition shadowing."
```

---

### Task 3: Add `known_validators` config support

**Files:**
- Modify: `src/wardline/manifest/models.py`
- Modify: `src/wardline/core/severity.py`
- Modify: `src/wardline/scanner/sarif.py`
- Modify: `tests/unit/core/test_severity.py`

- [ ] **Step 1: Add `GOVERNANCE_CUSTOM_KNOWN_VALIDATOR` RuleId**

In `src/wardline/core/severity.py`, add after line ~64:
```python
    GOVERNANCE_CUSTOM_KNOWN_VALIDATOR = "GOVERNANCE-CUSTOM-KNOWN-VALIDATOR"
```

In `src/wardline/scanner/sarif.py`, add to `_RULE_SHORT_DESCRIPTIONS`:
```python
    RuleId.GOVERNANCE_CUSTOM_KNOWN_VALIDATOR: "Custom known_validators entry (governance)",
```

Add to `_PSEUDO_RULE_IDS` if it exists.

Update `tests/unit/core/test_severity.py` `test_canonical_count` to the new count.

- [ ] **Step 2: Add `known_validators` to config model**

In `src/wardline/manifest/models.py`, add to `_KNOWN_KEYS` (line ~200):
```python
    "known_validators",
    "known_validators_extra",
```

Add to `ScannerConfig` dataclass:
```python
    known_validators: tuple[str, ...] | None = None
    known_validators_extra: tuple[str, ...] = ()
```

Add parsing in `ScannerConfig.from_toml()` — read both keys, apply merge/replace logic with the built-in default.

- [ ] **Step 3: Define the built-in default list**

Add to `src/wardline/scanner/rejection_path.py` (or a new constants module):
```python
BUILTIN_KNOWN_VALIDATORS: frozenset[str] = frozenset({
    "jsonschema.validate",
    "jsonschema.Draft4Validator.validate",
    "jsonschema.Draft7Validator.validate",
    "pydantic.TypeAdapter.validate_python",
    "pydantic.BaseModel.model_validate",
    "marshmallow.Schema.load",
    "marshmallow.Schema.loads",
})
```

- [ ] **Step 4: Write config tests**

Add tests to `tests/unit/manifest/test_models.py` or a new file:
- `known_validators_extra` merges with built-in defaults
- `known_validators` replaces built-in defaults
- Both present → `known_validators` wins (with warning logged)
- Neither present → built-in defaults used

- [ ] **Step 5: Run tests and commit**

```bash
uv run pytest tests/unit/manifest/ tests/unit/core/test_severity.py -v
git add src/wardline/core/severity.py src/wardline/scanner/sarif.py src/wardline/manifest/models.py src/wardline/scanner/rejection_path.py tests/
git commit -m "feat(config): add known_validators + known_validators_extra to wardline.toml

known_validators_extra merges with built-in defaults (recommended).
known_validators replaces entirely (advanced). Built-in list covers
jsonschema, pydantic, marshmallow.

Adds GOVERNANCE_CUSTOM_KNOWN_VALIDATOR RuleId for custom entries."
```

---

### Task 4: Add `rejection_path_index` and `import_alias_map` to ScanContext

**Files:**
- Modify: `src/wardline/scanner/context.py`

- [ ] **Step 1: Add both fields + `__post_init__` conversions**

Add after the existing fields (~line 103):
```python
    # Two-hop rejection path index: FQNs of functions with rejection paths.
    rejection_path_index: frozenset[str] = frozenset()
    # Per-file import alias map: {local_name: FQN}.
    import_alias_map: MappingProxyType[str, str] | None = None
```

Add to `__post_init__` (~after line 157):
```python
        if isinstance(self.rejection_path_index, set):
            object.__setattr__(
                self,
                "rejection_path_index",
                frozenset(self.rejection_path_index),
            )
        if isinstance(self.import_alias_map, dict):
            object.__setattr__(
                self,
                "import_alias_map",
                MappingProxyType(self.import_alias_map),
            )
```

- [ ] **Step 2: Run existing tests**

Run: `uv run pytest tests/unit/scanner/test_context.py -v`
Expected: all pass (new fields have defaults)

- [ ] **Step 3: Commit**

```bash
git add src/wardline/scanner/context.py
git commit -m "feat(scanner): add rejection_path_index and import_alias_map to ScanContext"
```

---

### Task 5: Compute rejection path index in engine

**Files:**
- Modify: `src/wardline/scanner/engine.py`

This is the largest task. It introduces the `ProjectIndex` dataclass, computes the rejection path index during `_build_project_indexes`, and wires it through to ScanContext.

- [ ] **Step 1: Create `ProjectIndex` dataclass**

Add to `engine.py` imports or near the top:
```python
from wardline.scanner.rejection_path import has_rejection_path, BUILTIN_KNOWN_VALIDATORS
from wardline.scanner.import_resolver import build_import_alias_map, resolve_call_fqn
from wardline.scanner._qualnames import build_qualname_map
```

Add the dataclass:
```python
@dataclass(frozen=True)
class ProjectIndex:
    """Pre-computed project-wide indexes built before per-file scanning."""
    annotations: MappingProxyType[tuple[str, str], tuple[WardlineAnnotation, ...]]
    module_file_map: MappingProxyType[str, str]
    string_literal_counts: MappingProxyType[str, int]
    rejection_path_index: frozenset[str]
```

- [ ] **Step 2: Update `_build_project_indexes` to compute the rejection path index**

In the per-file loop (after string literal counting, ~line 277):
1. Call `build_qualname_map(tree)` to get `{id(node): qualname}`
2. Call `build_import_alias_map(tree)` to get `{local_name: fqn}`
3. Derive `module_prefix` from `module_name` (already computed)
4. For each FunctionDef/AsyncFunctionDef, check `has_rejection_path(node)`. If True, add the FQN (`module_prefix.qualname`) to a seed set.
5. Store the per-file `(alias_map, qualname_map, module_prefix, tree)` for the expansion step.

After all files are processed:
1. Add `known_validators` entries to the seed set
2. Expansion: re-walk each file's function bodies, resolve calls via that file's alias map + local FQNs, check if any call target is in the seed set. If so, add the calling function's FQN to an expanded set.
3. Combine seed + expanded into `rejection_path_index: frozenset[str]`

Return a `ProjectIndex` instead of a 3-tuple.

- [ ] **Step 3: Update `scan()` and `_scan_file()` to use `ProjectIndex`**

Replace the 3-tuple destructuring in `scan()` with:
```python
self._project_index = self._build_project_indexes()
```

Update all `self._project_annotations` → `self._project_index.annotations`, `self._module_file_map` → `self._project_index.module_file_map`, `self._string_literal_counts` → `self._project_index.string_literal_counts`.

In `_scan_file()`, build the per-file alias map and pass both to ScanContext:
```python
import_alias_map = build_import_alias_map(tree)
ctx = ScanContext(
    ...
    rejection_path_index=self._project_index.rejection_path_index,
    import_alias_map=import_alias_map,
)
```

- [ ] **Step 4: Add error handling for rejection path computation**

Wrap the `has_rejection_path(node)` call in try/except during the index pass. On exception, log a warning and skip the function (don't add to index). Follow the existing pattern at `_scan_file` line 186.

- [ ] **Step 5: Run existing tests**

Run: `uv run pytest tests/ -x --tb=short -q`

Expect some test failures in `test_engine_taint_wiring.py` because the return type changed. Fix: update mocks to return `ProjectIndex(...)` instead of 3-tuples. Update `self._project_annotations` references in tests to `self._project_index.annotations`.

- [ ] **Step 6: Run full suite green and commit**

```bash
uv run pytest tests/ --tb=short -q
git add src/wardline/scanner/engine.py tests/
git commit -m "feat(scanner): compute rejection path index in _build_project_indexes

ProjectIndex dataclass replaces the 3-tuple return. Index is seeded
from direct rejection paths + known_validators, then expanded one
round for wrappers. Per-file import alias maps built during indexing
for expansion resolution."
```

---

### Task 6: Add `_has_delegated_rejection` to PY-WL-008

**Files:**
- Modify: `src/wardline/scanner/rules/py_wl_008.py`
- Create: `tests/unit/scanner/test_delegated_rejection.py`

- [ ] **Step 1: Write isolated unit tests for `_has_delegated_rejection`**

Create `tests/unit/scanner/test_delegated_rejection.py` with 6 test cases:
1. Body calls function in index → True
2. Body calls function NOT in index → False
3. Multiple calls, one in index → True
4. No calls → False
5. `self.validate()` with FQN in index → resolved correctly
6. Lambda in body → not matched

Use `parse_function_source` from conftest, construct a ScanContext with a rejection_path_index and import_alias_map, call `_has_delegated_rejection` directly.

- [ ] **Step 2: Implement `_has_delegated_rejection` in `py_wl_008.py`**

Add method to `RulePyWl008`:
```python
def _has_delegated_rejection(
    self,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    """Check if the boundary delegates rejection to a function in the index."""
    if self._context is None or not self._context.rejection_path_index:
        return False
    alias_map = dict(self._context.import_alias_map or {})
    # Build local FQNs from annotations or qualname inference
    local_fqns = self._context.rejection_path_index  # index already contains locals
    module_prefix = self._file_path.replace("/", ".").removesuffix(".py").split("src.")[-1] if self._file_path else ""

    for child in walk_skip_nested_defs(node):
        if not isinstance(child, ast.Call):
            continue
        fqn = resolve_call_fqn(child, alias_map, local_fqns, module_prefix)
        if fqn is not None and fqn in self._context.rejection_path_index:
            return True
    return False
```

Update `visit_function`:
```python
def visit_function(self, node, *, is_async):
    if not self._is_checked_boundary(node):
        return
    if _has_rejection_path(node):
        return
    if self._has_delegated_rejection(node):
        return
    self._emit_finding(node)
```

- [ ] **Step 3: Run tests**

Run: `uv run pytest tests/unit/scanner/test_delegated_rejection.py tests/unit/scanner/test_py_wl_008.py -v`
Expected: all pass

- [ ] **Step 4: Commit**

```bash
git add src/wardline/scanner/rules/py_wl_008.py tests/unit/scanner/test_delegated_rejection.py
git commit -m "feat(scanner): add delegated rejection path resolution to PY-WL-008

Boundaries that delegate to functions in the rejection path index
(local helpers with raise, known_validators, wrappers) now satisfy
WL-007 through two-hop delegation. Fixes HC-2."
```

---

### Task 7: Integration tests

**Files:**
- Modify: `tests/unit/scanner/test_py_wl_008.py`

- [ ] **Step 1: Add integration tests (cases 13-23, 29-30 from spec)**

Add test classes to `test_py_wl_008.py` that exercise the full `visit_function` path with rejection_path_index and import_alias_map injected via ScanContext. Key cases:

- Boundary calls local helper that raises → no finding
- Boundary calls known validator (dotted: `jsonschema.validate()`) → no finding
- Boundary calls known validator (bare: `validate()` via `from jsonschema import validate`) → no finding
- Boundary calls unknown third-party → finding fires
- Wrapper pattern: boundary → wrapper → known validator → no finding
- Three-hop chain → finding fires
- Async boundary + delegation → no finding
- Decorator-detected boundary + delegation → no finding
- Empty index → existing behavior preserved
- Boundary with `jsonschema.validate()` but empty index → fires

- [ ] **Step 2: Run all PY-WL-008 tests**

Run: `uv run pytest tests/unit/scanner/test_py_wl_008.py -v`
Expected: all pass

- [ ] **Step 3: Commit**

```bash
git add tests/unit/scanner/test_py_wl_008.py
git commit -m "test(scanner): add integration tests for two-hop rejection path resolution

13 integration tests covering local delegation, known validators,
import aliases, wrapper pattern, three-hop limit, async boundaries,
and backward compatibility."
```

---

### Task 8: Final verification

- [ ] **Step 1: Run full test suite**

Run: `uv run pytest tests/ -v --tb=short -q`
Expected: all pass

- [ ] **Step 2: Run linter**

Run: `uv run ruff check src/wardline/scanner/rejection_path.py src/wardline/scanner/import_resolver.py src/wardline/scanner/rules/py_wl_008.py src/wardline/scanner/engine.py src/wardline/scanner/context.py`
Expected: clean

- [ ] **Step 3: Run type checker**

Run: `uv run mypy src/wardline/scanner/rejection_path.py src/wardline/scanner/import_resolver.py src/wardline/scanner/rules/py_wl_008.py src/wardline/scanner/engine.py`
Expected: clean

- [ ] **Step 4: Verify success criteria from spec**

Check each criterion:
- [ ] `@validates_shape` + `jsonschema.validate()` (any import form) → no finding
- [ ] `@validates_shape` + local helper with raise → no finding
- [ ] `@validates_shape` + wrapper around known validator → no finding
- [ ] `@validates_shape` with no rejection → fires
- [ ] Existing tests pass with empty index
- [ ] Config merge/replace works
- [ ] Custom entries produce GOVERNANCE finding
- [ ] `_is_inside_dead_branch` uses `walk_skip_nested_defs`

- [ ] **Step 5: Final commit if any cleanup needed**

```bash
git add -u
git commit -m "chore: final cleanup for two-hop rejection path resolution"
```
