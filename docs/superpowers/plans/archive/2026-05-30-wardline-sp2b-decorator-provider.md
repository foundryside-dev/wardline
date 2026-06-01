# SP2b — DecoratorTaintSourceProvider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the trivial `DefaultTaintSourceProvider` with a real provider that seeds L1 taints by reading the SP2a trust vocabulary (`@external_boundary`, `@trust_boundary`, `@trusted`) off each function's AST, so the engine produces non-trivial transitive taints on decorated code.

**Architecture:** A new `DecoratorTaintSourceProvider` implements the SP1 `TaintSourceProvider` Protocol. `taint_for` resolves each decorator's dotted name through the file's import-alias map, requires the `wardline.decorators` namespace (so a coincidental same-named user decorator is ignored), maps the canonical name + AST keyword args to a `FunctionTaint`, and is fail-closed (unreadable/disallowed/malformed level ⇒ no opinion ⇒ engine falls back to `UNKNOWN_RAW`). `SeedContext` gains an `alias_map` field. The analyzer wires the new provider as its default and constructs `SeedContext` with the per-file alias map.

**Tech Stack:** Python 3.12+, stdlib `ast`; `wardline.core.{registry,taints}`, `wardline.scanner.taint.provider`, `wardline.scanner.index.Entity`.

**Vocabulary → `FunctionTaint(body_taint, return_taint)` (from spec §2):**
- `@external_boundary` → `(EXTERNAL_RAW, EXTERNAL_RAW)`
- `@trust_boundary(to_level=L)` → `(EXTERNAL_RAW, L)`, `L ∈ {GUARDED, ASSURED}`
- `@trusted(level=L)` → `(L, L)`, `L ∈ {INTEGRAL, ASSURED}`, default `INTEGRAL`

**Gate (run after every task):** `.venv/bin/python -m pytest -q` (1 expected xfail in `tests/test_self_hosting.py`), `.venv/bin/ruff check src tests`, `.venv/bin/mypy src`.

---

### Task 1: Extend `SeedContext` with the import-alias map

**Files:**
- Modify: `src/wardline/scanner/taint/provider.py`
- Test: `tests/unit/scanner/taint/test_provider_seedcontext.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/scanner/taint/test_provider_seedcontext.py
from __future__ import annotations

import pytest

from wardline.scanner.taint.provider import SeedContext


def test_seedcontext_defaults_to_empty_alias_map() -> None:
    ctx = SeedContext(module="m")
    assert ctx.module == "m"
    assert dict(ctx.alias_map) == {}


def test_seedcontext_carries_alias_map() -> None:
    ctx = SeedContext(module="m", alias_map={"t": "wardline.decorators.trusted"})
    assert ctx.alias_map["t"] == "wardline.decorators.trusted"


def test_seedcontext_is_frozen() -> None:
    ctx = SeedContext(module="m")
    with pytest.raises(AttributeError):
        ctx.module = "other"  # type: ignore[misc]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_provider_seedcontext.py -q`
Expected: FAIL (`TypeError: ... unexpected keyword argument 'alias_map'`).

- [ ] **Step 3: Modify `SeedContext`**

In `src/wardline/scanner/taint/provider.py`, update the imports and the `SeedContext` dataclass:

```python
# --- change the dataclass import line near the top ---
from dataclasses import dataclass, field
```

Add (with the other `from __future__`/typing imports) a `Mapping` import:

```python
from collections.abc import Mapping
```

Then replace the existing `SeedContext` definition:

```python
@dataclass(frozen=True, slots=True)
class SeedContext:
    """Per-file context handed to a provider for each entity in that file.

    ``alias_map`` is the file's ``{local_name: fully_qualified_name}`` import
    map (from ``build_import_alias_map``); a provider uses it to resolve aliased
    decorator names against the trust vocabulary. Defaults to empty so callers
    that do not seed from decorators (e.g. the trivial default provider's tests)
    need not supply it.
    """

    module: str
    alias_map: Mapping[str, str] = field(default_factory=dict)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_provider_seedcontext.py -q`
Expected: PASS (3 tests). Also run the full gate; nothing else should break (the field has a default).

- [ ] **Step 5: Commit** (controller performs this; the implementer does NOT run git)

---

### Task 2: `DecoratorTaintSourceProvider`

**Files:**
- Create: `src/wardline/scanner/taint/decorator_provider.py`
- Test: `tests/unit/scanner/taint/test_decorator_provider.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/scanner/taint/test_decorator_provider.py
from __future__ import annotations

import ast

from wardline.core.registry import REGISTRY_VERSION
from wardline.core.taints import TaintState as T
from wardline.scanner.ast_primitives import build_import_alias_map
from wardline.scanner.index import discover_file_entities
from wardline.scanner.taint.decorator_provider import DecoratorTaintSourceProvider
from wardline.scanner.taint.provider import FunctionTaint, SeedContext


def _seed(src: str, *, module: str = "m") -> dict[str, FunctionTaint | None]:
    """Run the provider over every function entity in *src*; map qualname -> result."""
    tree = ast.parse(src)
    alias_map = build_import_alias_map(tree, module_path=module)
    entities = discover_file_entities(tree, module=module, path="m.py")
    ctx = SeedContext(module=module, alias_map=alias_map)
    provider = DecoratorTaintSourceProvider()
    return {e.qualname: provider.taint_for(e, ctx) for e in entities}


def test_external_boundary_from_import() -> None:
    out = _seed("from wardline.decorators import external_boundary\n"
                "@external_boundary\ndef read(p):\n    return p\n")
    assert out["m.read"] == FunctionTaint(T.EXTERNAL_RAW, T.EXTERNAL_RAW)


def test_external_boundary_aliased_from_import() -> None:
    out = _seed("from wardline.decorators import external_boundary as eb\n"
                "@eb\ndef read(p):\n    return p\n")
    assert out["m.read"] == FunctionTaint(T.EXTERNAL_RAW, T.EXTERNAL_RAW)


def test_external_boundary_module_alias_attribute() -> None:
    out = _seed("import wardline.decorators as wd\n"
                "@wd.external_boundary\ndef read(p):\n    return p\n")
    assert out["m.read"] == FunctionTaint(T.EXTERNAL_RAW, T.EXTERNAL_RAW)


def test_external_boundary_plain_import_dotted() -> None:
    out = _seed("import wardline.decorators\n"
                "@wardline.decorators.external_boundary\ndef read(p):\n    return p\n")
    assert out["m.read"] == FunctionTaint(T.EXTERNAL_RAW, T.EXTERNAL_RAW)


def test_trust_boundary_to_level_string() -> None:
    out = _seed("from wardline.decorators import trust_boundary\n"
                "@trust_boundary(to_level='ASSURED')\ndef v(x):\n    return x\n")
    assert out["m.v"] == FunctionTaint(T.EXTERNAL_RAW, T.ASSURED)


def test_trust_boundary_to_level_enum_attribute() -> None:
    out = _seed("from wardline.decorators import trust_boundary\n"
                "from wardline.core.taints import TaintState\n"
                "@trust_boundary(to_level=TaintState.GUARDED)\ndef v(x):\n    return x\n")
    assert out["m.v"] == FunctionTaint(T.EXTERNAL_RAW, T.GUARDED)


def test_trust_boundary_disallowed_level_is_no_opinion() -> None:
    # INTEGRAL is not a valid boundary target -> fail-closed (None).
    out = _seed("from wardline.decorators import trust_boundary\n"
                "@trust_boundary(to_level='INTEGRAL')\ndef v(x):\n    return x\n")
    assert out["m.v"] is None


def test_trust_boundary_bare_is_no_opinion() -> None:
    out = _seed("from wardline.decorators import trust_boundary\n"
                "@trust_boundary\ndef v(x):\n    return x\n")
    assert out["m.v"] is None


def test_trusted_bare_defaults_integral() -> None:
    out = _seed("from wardline.decorators import trusted\n"
                "@trusted\ndef f():\n    return 1\n")
    assert out["m.f"] == FunctionTaint(T.INTEGRAL, T.INTEGRAL)


def test_trusted_level_assured() -> None:
    out = _seed("from wardline.decorators import trusted\n"
                "@trusted(level='ASSURED')\ndef f():\n    return 1\n")
    assert out["m.f"] == FunctionTaint(T.ASSURED, T.ASSURED)


def test_trusted_disallowed_level_is_no_opinion() -> None:
    out = _seed("from wardline.decorators import trusted\n"
                "@trusted(level='GUARDED')\ndef f():\n    return 1\n")
    assert out["m.f"] is None


def test_trusted_dynamic_level_is_no_opinion() -> None:
    # A non-literal level (a Name) cannot be read statically -> fail-closed.
    out = _seed("from wardline.decorators import trusted\n"
                "LV = 'ASSURED'\n@trusted(level=LV)\ndef f():\n    return 1\n")
    assert out["m.f"] is None


def test_undecorated_is_no_opinion() -> None:
    out = _seed("def f(p):\n    return p\n")
    assert out["m.f"] is None


def test_non_vocabulary_decorator_is_no_opinion() -> None:
    out = _seed("import functools\n@functools.cache\ndef f():\n    return 1\n")
    assert out["m.f"] is None


def test_coincidental_local_name_not_from_wardline_is_no_opinion() -> None:
    # A user's own 'trusted' with no wardline import must NOT be seeded.
    out = _seed("def trusted(fn):\n    return fn\n@trusted\ndef f():\n    return 1\n")
    assert out["m.f"] is None


def test_conflicting_decorators_pick_least_trusted_return() -> None:
    # An authoring conflict: @trusted (INTEGRAL) + @external_boundary (EXTERNAL_RAW).
    # Fail-closed: the least-trusted return wins (never over-trust).
    out = _seed("from wardline.decorators import external_boundary, trusted\n"
                "@trusted\n@external_boundary\ndef f(p):\n    return p\n")
    assert out["m.f"] == FunctionTaint(T.EXTERNAL_RAW, T.EXTERNAL_RAW)


def test_fingerprint_is_version_derived_and_stable() -> None:
    p = DecoratorTaintSourceProvider()
    assert p.fingerprint() == f"decorator-vocab:{REGISTRY_VERSION}"
    assert p.fingerprint() == p.fingerprint()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_decorator_provider.py -q`
Expected: FAIL (`ModuleNotFoundError: ...decorator_provider`).

- [ ] **Step 3: Write the implementation**

```python
# src/wardline/scanner/taint/decorator_provider.py
"""The real taint-source provider: seeds L1 taints from the trust vocabulary.

Reads ``@external_boundary`` / ``@trust_boundary`` / ``@trusted`` off each
function's AST decorator list (resolving import aliases via
``SeedContext.alias_map``) and maps them to ``FunctionTaint``. Replaces
``DefaultTaintSourceProvider`` as ``WardlineAnalyzer``'s default. An undecorated
function — or any decorator whose level cannot be read statically or is outside
the allowed set — gets *no opinion* (``None``), so the engine falls back to the
unchanged fail-closed ``UNKNOWN_RAW`` L1 precedence.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from wardline.core.registry import REGISTRY, REGISTRY_VERSION
from wardline.core.taints import TRUST_RANK, TaintState
from wardline.scanner.taint.provider import FunctionTaint

if TYPE_CHECKING:
    from collections.abc import Mapping

    from wardline.scanner.index import Entity
    from wardline.scanner.taint.provider import SeedContext

_VOCAB_PREFIX = "wardline.decorators"
_BOUNDARY_LEVELS = frozenset({TaintState.GUARDED, TaintState.ASSURED})
_TRUSTED_LEVELS = frozenset({TaintState.INTEGRAL, TaintState.ASSURED})


def _dotted_name(node: ast.expr) -> str | None:
    """Reconstruct a dotted name (``a.b.c``) from a Name/Attribute chain."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base is not None else None
    return None


def _resolve_decorator_fqn(deco: ast.expr, alias_map: Mapping[str, str]) -> str | None:
    """Resolve a decorator node to a fully-qualified name via the alias map.

    Strips a call wrapper (``@d(...)`` -> ``d``), reconstructs the dotted name,
    and rewrites its head through ``alias_map`` (an import alias). Returns None
    for non-name decorators.
    """
    func = deco.func if isinstance(deco, ast.Call) else deco
    dotted = _dotted_name(func)
    if dotted is None:
        return None
    head, _, rest = dotted.partition(".")
    head_fqn = alias_map.get(head, head)
    return f"{head_fqn}.{rest}" if rest else head_fqn


def _level_token(value: ast.expr) -> str | None:
    """Extract a TaintState name token from a keyword-argument value node.

    Handles a string literal (``"ASSURED"``) and an attribute access
    (``TaintState.ASSURED`` -> ``"ASSURED"``). Anything else (a Name, a call,
    an f-string) is not statically readable -> None.
    """
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    if isinstance(value, ast.Attribute):
        return value.attr
    return None


def _read_level(
    deco: ast.expr, arg: str, *, allowed: frozenset[TaintState], default: TaintState | None
) -> TaintState | None:
    """Read a level keyword arg from a decorator, normalised + allow-checked.

    Returns ``default`` when the decorator is not called or the arg is absent;
    ``None`` (fail-closed) when the arg is present but unreadable, an invalid
    state, or outside ``allowed``.
    """
    if not isinstance(deco, ast.Call):
        return default
    for kw in deco.keywords:
        if kw.arg == arg:
            token = _level_token(kw.value)
            if token is None:
                return None
            try:
                level = TaintState(token)
            except ValueError:
                return None
            return level if level in allowed else None
    return default


class DecoratorTaintSourceProvider:
    """Seeds taints from the generic trust-decorator vocabulary (SP2)."""

    def taint_for(self, entity: Entity, ctx: SeedContext) -> FunctionTaint | None:
        candidates: list[FunctionTaint] = []
        for deco in entity.node.decorator_list:
            ft = self._match(deco, ctx.alias_map)
            if ft is not None:
                candidates.append(ft)
        if not candidates:
            return None
        # Multiple trust decorators on one function is an authoring conflict; pick
        # the LEAST-trusted return (highest TRUST_RANK) so contradictory
        # annotations can never over-trust. Deterministic regardless of order.
        return max(candidates, key=lambda ft: TRUST_RANK[ft.return_taint])

    def fingerprint(self) -> str:
        return f"decorator-vocab:{REGISTRY_VERSION}"

    def _match(self, deco: ast.expr, alias_map: Mapping[str, str]) -> FunctionTaint | None:
        fqn = _resolve_decorator_fqn(deco, alias_map)
        if fqn is None or not fqn.startswith(_VOCAB_PREFIX + "."):
            return None
        canonical = fqn.rsplit(".", 1)[-1]
        if canonical not in REGISTRY:
            return None
        if canonical == "external_boundary":
            return FunctionTaint(TaintState.EXTERNAL_RAW, TaintState.EXTERNAL_RAW)
        if canonical == "trust_boundary":
            to_level = _read_level(deco, "to_level", allowed=_BOUNDARY_LEVELS, default=None)
            if to_level is None:
                return None
            return FunctionTaint(TaintState.EXTERNAL_RAW, to_level)
        if canonical == "trusted":
            level = _read_level(
                deco, "level", allowed=_TRUSTED_LEVELS, default=TaintState.INTEGRAL
            )
            if level is None:
                return None
            return FunctionTaint(level, level)
        return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/unit/scanner/taint/test_decorator_provider.py -q`
Expected: PASS (17 tests).

- [ ] **Step 5: Commit** (controller performs this)

---

### Task 3: Wire `DecoratorTaintSourceProvider` as the analyzer default

**Files:**
- Modify: `src/wardline/scanner/analyzer.py`
- Test: `tests/unit/scanner/test_analyzer.py` (add an end-to-end test)

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/scanner/test_analyzer.py` (the helpers `_write` and the imports already exist in that file).

**Engine-semantics note (verified at the REPL, 2026-05-30):** an undecorated caller's fail-closed floor is `UNKNOWN_RAW` (rank 6), which is *already less-trusted* than an `EXTERNAL_RAW` (rank 5) callee. The L3 fixed point only moves non-anchored functions toward *less*-trusted (monotone demotion), so a single more-trusted-than-floor callee never raises the caller — `EXTERNAL_RAW` does NOT "flow up" into an already-more-tainted caller. The visible transitive effect comes from a *provenance clash*: joining two incompatible seeded sources yields `MIXED_RAW` (rank 7), which DOES propagate past the floor. Both tests below pin this.

```python
def test_analyzer_default_provider_seeds_from_decorators(tmp_path) -> None:
    # The DEFAULT provider (no provider= arg) now reads the trust vocabulary and
    # seeds real, non-trivial taints in both directions.
    _write(tmp_path, "io_layer.py",
           "from wardline.decorators import external_boundary, trusted\n"
           "@external_boundary\ndef read_raw(p):\n    return p\n"
           "@trusted\ndef constant():\n    return 1\n")
    _write(tmp_path, "service.py",
           "from io_layer import read_raw\ndef fetch(p):\n    return read_raw(p)\n")
    files = [tmp_path / "io_layer.py", tmp_path / "service.py"]

    analyzer = WardlineAnalyzer()  # default provider
    analyzer.analyze(files, WardlineConfig(), root=tmp_path)
    ctx = analyzer.last_context
    assert ctx is not None
    assert ctx.project_taints["io_layer.read_raw"] == T.EXTERNAL_RAW
    assert ctx.project_taints["io_layer.constant"] == T.INTEGRAL
    # fetch stays at its UNKNOWN_RAW floor (already more-tainted than its callee).
    assert ctx.project_taints["service.fetch"] == T.UNKNOWN_RAW


def test_analyzer_seeded_taints_drive_transitive_propagation(tmp_path) -> None:
    # Joining two provenance-incompatible decorator-seeded sources -> MIXED_RAW,
    # which DOES propagate up into the undecorated caller.
    _write(tmp_path, "m.py",
           "from wardline.decorators import external_boundary, trusted\n"
           "@external_boundary\ndef ext(p):\n    return p\n"
           "@trusted\ndef tru():\n    return 1\n"
           "def mix(p):\n    a = ext(p)\n    b = tru()\n    return a if p else b\n")
    analyzer = WardlineAnalyzer()
    analyzer.analyze([tmp_path / "m.py"], WardlineConfig(), root=tmp_path)
    ctx = analyzer.last_context
    assert ctx is not None
    assert ctx.project_taints["m.ext"] == T.EXTERNAL_RAW
    assert ctx.project_taints["m.tru"] == T.INTEGRAL
    assert ctx.project_taints["m.mix"] == T.MIXED_RAW
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/scanner/test_analyzer.py::test_analyzer_default_provider_seeds_from_decorators -q`
Expected: FAIL (both assertions: default provider is still `DefaultTaintSourceProvider`, so taints are `UNKNOWN_RAW`).

- [ ] **Step 3: Modify the analyzer**

In `src/wardline/scanner/analyzer.py`:

1. Replace the provider import block:

```python
from wardline.scanner.taint.decorator_provider import DecoratorTaintSourceProvider
from wardline.scanner.taint.provider import SeedContext, TaintSourceProvider
```

(removing `DefaultTaintSourceProvider` from the import — it is no longer referenced here.)

2. Change the default in `__init__`:

```python
        self._provider: TaintSourceProvider = provider or DecoratorTaintSourceProvider()
```

3. Pass the alias map into `SeedContext` (the `alias_map` local is already built two lines above the `seed_function_taints` call):

```python
                seeds = seed_function_taints(
                    entities,
                    ctx=SeedContext(module=module, alias_map=alias_map),
                    provider=self._provider,
                )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/unit/scanner/test_analyzer.py -q`
Expected: PASS (the new test + all existing analyzer tests; `test_analyzer_default_provider_all_unknown_raw` still passes because *undecorated* code yields no opinion → `UNKNOWN_RAW`).

- [ ] **Step 5: Full gate + commit** (controller performs the commit)

Run: `.venv/bin/python -m pytest -q && .venv/bin/ruff check src tests && .venv/bin/mypy src`
Expected: all green (1 xfail in `test_self_hosting.py` — rules are SP2c).

---

## Self-Review

- **Spec coverage:** §3 (provider reads decorators w/ alias resolution → `FunctionTaint`; `fingerprint` from `REGISTRY_VERSION`; `SeedContext.alias_map` added; wired as default; precedence stays provider>stdlib>UNKNOWN_RAW) → Tasks 1-3. §9 SP2b acceptance (decorated functions seed correct taint; aliased/from-import/attribute forms resolve; fingerprint stable+version-derived; engine produces non-trivial taints on a decorated fixture) → tests in Tasks 2-3. `module_default` deferral honored (not implemented).
- **No placeholders:** every step has complete code.
- **Type consistency:** `FunctionTaint(body_taint, return_taint)` matches `provider.py`; `TRUST_RANK[...]` is the `MappingProxyType` subscript; `SeedContext(module, alias_map)` matches the Task 1 dataclass; `taint_for(entity, ctx)`/`fingerprint()` match the `TaintSourceProvider` Protocol; the analyzer's `alias_map` local is in scope where `SeedContext` is built. Fail-closed direction (unreadable/disallowed → `None` → `UNKNOWN_RAW`) is the safe (over-taint) direction.
