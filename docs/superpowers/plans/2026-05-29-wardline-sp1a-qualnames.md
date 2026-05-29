# SP1a — Clarion-Aligned Qualnames + AST Primitives + Conformance Corpus (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **GIT PROHIBITION (controller-enforced):** Implementer/reviewer subagents MUST NEVER run any git command — no `git add/commit/stash/checkout/restore/reset/rm/branch/switch`. They write files, run tests, and report. **The controller does every commit.** This overrides the skill's "implementer commits" step.

**Goal:** Stand up Wardline's qualname identity layer — `module_dotted_name` + `reconstruct_qualname` matching Clarion's producer contract byte-for-byte — plus per-file entity discovery and the portable AST primitives, all gated by a shared qualname conformance corpus.

**Architecture:** `core/qualname.py` is new stdlib-only code implementing Clarion's exact algorithm (NOT a port — `wardline.old`'s `_qualnames.py` diverges: it emits `outer.inner` with no `<locals>`, has no overload/first-wins handling, and adds descriptor-accessor suffixing Clarion does not). `scanner/index.py` walks a module AST and emits function/method `Entity`s using those qualnames. `scanner/ast_primitives.py` ports the two genuinely-reusable stdlib-clean helpers from `.old`. The conformance corpus (`tests/conformance/qualnames.json`) is the shared design-review artifact both Wardline and Clarion test against; its nesting-shape expectations were generated from CPython `co_qualname` ground truth.

**Tech Stack:** Python 3.12, stdlib `ast`, pytest, ruff, mypy (strict). Zero runtime deps.

**Contract source:** `docs/integration/2026-05-29-wardline-loom-integration-brief.md` §"Clarion (Python plugin) — qualname PRODUCER contract" (lines 229-253).

**Branch:** `sp1a-qualnames-ast-primitives` (already created off `main`).

---

## File Structure

| File | Responsibility |
|---|---|
| `src/wardline/core/qualname.py` (create) | `module_dotted_name`, `reconstruct_qualname`, `is_overload_stub` — stdlib-only, no project imports |
| `src/wardline/scanner/index.py` (create) | `Entity` dataclass + `discover_file_entities` — per-file function/method enumeration |
| `src/wardline/scanner/ast_primitives.py` (create) | `build_import_alias_map`, `iter_calls_in_function_body` — ported verbatim from `.old` (stdlib-only) |
| `tests/conformance/qualnames.json` (create) | Shared qualname conformance corpus (Wardline ⇄ Clarion) |
| `tests/conformance/__init__.py` (create) | empty (package marker, if test layout needs it) |
| `tests/conformance/test_qualname_conformance.py` (create) | Drives the corpus through `module_dotted_name` + `discover_file_entities` |
| `tests/unit/core/test_qualname.py` (create) | Unit tests for the three `qualname.py` functions |
| `tests/unit/scanner/test_index.py` (create) | Unit tests for `discover_file_entities` incl. Location anchoring |
| `tests/unit/scanner/test_ast_primitives.py` (create) | Unit tests for the two ported helpers |

**Gating note:** The conformance corpus (Task 4) is the hard correctness gate. The two `.old` ports (Tasks 5-6) are stdlib-clean and reused later (callgraph is SP1d), so SP1a exercises them only via unit tests — that is porting-what's-reused, not deferral.

---

## Task 1: `core/qualname.py` — `module_dotted_name`

**Files:**
- Create: `src/wardline/core/qualname.py`
- Test: `tests/unit/core/test_qualname.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/core/test_qualname.py
from __future__ import annotations

import ast

import pytest

from wardline.core.qualname import (
    is_overload_stub,
    module_dotted_name,
    reconstruct_qualname,
)


@pytest.mark.parametrize(
    ("rel_path", "expected"),
    [
        ("demo.py", "demo"),
        ("src/demo.py", "demo"),
        ("src.py", "src"),  # file *named* src; only a path component is stripped
        ("pkg/__init__.py", "pkg"),
        ("src/pkg/__init__.py", "pkg"),
        ("pkg/sub/mod.py", "pkg.sub.mod"),
        ("src/pkg/sub/mod.py", "pkg.sub.mod"),
        ("src/src/pkg/mod.py", "src.pkg.mod"),  # one level only
        ("__init__.py", None),  # top-level package init -> no module -> no entity
    ],
)
def test_module_dotted_name(rel_path: str, expected: str | None) -> None:
    assert module_dotted_name(rel_path) == expected
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/core/test_qualname.py::test_module_dotted_name -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'wardline.core.qualname'`

- [ ] **Step 3: Write the implementation**

```python
# src/wardline/core/qualname.py
"""Clarion-aligned qualname computation (stdlib-only).

Implements the qualname PRODUCER contract from the Loom integration brief
(§"Clarion (Python plugin) — qualname PRODUCER contract"). Wardline emits
``metadata.wardline.qualname`` as ``f"{module_dotted_name(path)}.{__qualname__}"``;
this module is the single source of truth for both halves so finding-to-Clarion
entity reconciliation stays lossless. A shared conformance corpus
(``tests/conformance/qualnames.json``) pins the behavior on both sides.

This deliberately does NOT match ``wardline.old``'s ``_qualnames.py``: that
emits ``outer.inner`` (no ``<locals>``), lacks overload/first-wins handling, and
adds descriptor-accessor suffixing that Clarion does not. Do not port it.
"""

from __future__ import annotations

import ast
from collections.abc import Sequence

_OVERLOAD_MODULES = frozenset({"typing", "typing_extensions"})


def module_dotted_name(rel_path: str) -> str | None:
    """Return the dotted module name for a project-relative POSIX path, or None.

    None means the path maps to no module (a top-level ``__init__.py``); callers
    must emit no entities for such a file.

    Rules (byte-for-byte with Clarion's ``extractor.module_dotted_name``):
      1. Strip exactly one leading ``src/`` *component* (not a ``src`` prefix of
         a filename).
      2. Drop the ``.py`` suffix.
      3. If the resulting final component is ``__init__``, remove it.
      4. Join the remaining components with ``.``.

    Examples::

        demo.py            -> demo
        src/demo.py        -> demo
        src.py             -> src
        pkg/__init__.py    -> pkg
        src/pkg/sub/mod.py -> pkg.sub.mod
        src/src/pkg/mod.py -> src.pkg.mod   # one level only
        __init__.py        -> None
    """
    parts = rel_path.split("/")
    if parts and parts[0] == "src":
        parts = parts[1:]
    if not parts:
        return None
    last = parts[-1]
    if not last.endswith(".py"):
        return None
    parts[-1] = last[:-3]
    if parts[-1] == "__init__":
        parts = parts[:-1]
    if not parts:
        return None
    return ".".join(parts)


def reconstruct_qualname(name: str, ancestors: Sequence[ast.AST]) -> str:
    """Reconstruct a symbol's ``__qualname__`` from its enclosing scope nodes.

    ``ancestors`` are the enclosing definition nodes ordered innermost->outermost
    (the symbol's direct parent first). The result matches CPython
    ``__qualname__`` / ``co_qualname`` for every nesting shape:
      - a ``FunctionDef``/``AsyncFunctionDef`` ancestor contributes
        ``"{name}.<locals>."``
      - a ``ClassDef`` ancestor contributes ``"{name}."``
      - any other node (Module/If/With/Try/...) contributes nothing.

    The literal ``<locals>`` (with angle brackets) is a verbatim component and is
    never re-dotted.
    """
    qualname = name
    for ancestor in ancestors:
        if isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qualname = f"{ancestor.name}.<locals>.{qualname}"
        elif isinstance(ancestor, ast.ClassDef):
            qualname = f"{ancestor.name}.{qualname}"
    return qualname


def is_overload_stub(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if *node* carries an ``@overload`` decorator that must drop.

    Recognizes exactly the syntactic forms ``@overload`` (bare),
    ``@typing.overload`` and ``@typing_extensions.overload``. An aliased import
    (``from typing import overload as o`` then ``@o``) is deliberately NOT
    recognized, per the contract.
    """
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Name) and decorator.id == "overload":
            return True
        if (
            isinstance(decorator, ast.Attribute)
            and decorator.attr == "overload"
            and isinstance(decorator.value, ast.Name)
            and decorator.value.id in _OVERLOAD_MODULES
        ):
            return True
    return False
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/core/test_qualname.py::test_module_dotted_name -q`
Expected: PASS (9 cases)

- [ ] **Step 5: Controller commits** (implementer: STOP here, report DONE — do not git)

---

## Task 2: `core/qualname.py` — `reconstruct_qualname` + `is_overload_stub`

The implementation already landed in Task 1 (single file). This task adds their unit tests.

**Files:**
- Test: `tests/unit/core/test_qualname.py` (append)

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/core/test_qualname.py`:

```python
def _ancestors(src: str, target: str) -> tuple[str, list[ast.AST]]:
    """Parse *src*, locate the def/class named *target*, return (name, ancestors).

    ``ancestors`` is innermost->outermost, matching reconstruct_qualname's contract.
    """
    tree = ast.parse(src)
    found: list[tuple[ast.AST, list[ast.AST]]] = []

    def walk(node: ast.AST, scope: list[ast.AST]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                found.append((child, list(scope)))
                walk(child, [child, *scope])  # prepend -> innermost first
            else:
                walk(child, scope)

    walk(tree, [])
    node, ancestors = next(
        (n, a) for n, a in found if getattr(n, "name", None) == target
    )
    return node.name, ancestors  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("src", "target", "expected"),
    [
        ("def outer():\n    def inner():\n        pass\n", "inner", "outer.<locals>.inner"),
        (
            "class Outer:\n    class Inner:\n        def method(self):\n            pass\n",
            "method",
            "Outer.Inner.method",
        ),
        (
            "class Foo:\n    def bar(self):\n        class Local:\n            def meth(self):\n                pass\n",
            "meth",
            "Foo.bar.<locals>.Local.meth",
        ),
        ("class Foo:\n    def bar(self):\n        pass\n", "bar", "Foo.bar"),
        (
            "def a():\n    def b():\n        def c():\n            pass\n",
            "c",
            "a.<locals>.b.<locals>.c",
        ),
    ],
)
def test_reconstruct_qualname(src: str, target: str, expected: str) -> None:
    name, ancestors = _ancestors(src, target)
    assert reconstruct_qualname(name, ancestors) == expected


def test_reconstruct_qualname_module_level() -> None:
    assert reconstruct_qualname("top", []) == "top"


@pytest.mark.parametrize(
    "decorator_src",
    ["@overload\n", "@typing.overload\n", "@typing_extensions.overload\n"],
)
def test_is_overload_stub_recognized(decorator_src: str) -> None:
    node = ast.parse(f"{decorator_src}def f(): ...\n").body[0]
    assert isinstance(node, ast.FunctionDef)
    assert is_overload_stub(node) is True


@pytest.mark.parametrize(
    "src",
    [
        "def f(): ...\n",  # no decorator
        "@staticmethod\ndef f(): ...\n",  # unrelated decorator
        "@o\ndef f(): ...\n",  # aliased overload -> NOT recognized
        "@mod.overload\ndef f(): ...\n",  # wrong module name
    ],
)
def test_is_overload_stub_not_recognized(src: str) -> None:
    node = ast.parse(src).body[0]
    assert isinstance(node, ast.FunctionDef)
    assert is_overload_stub(node) is False
```

- [ ] **Step 2: Run to verify pass** (implementation already exists from Task 1)

Run: `python -m pytest tests/unit/core/test_qualname.py -q`
Expected: PASS (all parametrizations)

- [ ] **Step 3: Controller commits** — Tasks 1+2 may be committed together as one logical commit (`feat(sp1a): Clarion-aligned qualname + overload primitives`).

---

## Task 3: `scanner/index.py` — `Entity` + `discover_file_entities`

**Files:**
- Create: `src/wardline/scanner/index.py`
- Test: `tests/unit/scanner/test_index.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/scanner/test_index.py
from __future__ import annotations

import ast

from wardline.scanner.index import Entity, discover_file_entities


def _quals(src: str, module: str = "demo", path: str = "demo.py") -> list[tuple[str, str]]:
    tree = ast.parse(src)
    return [
        (e.qualname, e.kind)
        for e in discover_file_entities(tree, module=module, path=path)
    ]


def test_module_function_and_closure() -> None:
    src = "def outer():\n    def inner():\n        pass\n"
    assert _quals(src) == [
        ("demo.outer", "function"),
        ("demo.outer.<locals>.inner", "function"),
    ]


def test_methods_and_nested_class_in_closure() -> None:
    src = (
        "class Foo:\n"
        "    def bar(self):\n"
        "        class Local:\n"
        "            def meth(self):\n"
        "                pass\n"
    )
    assert _quals(src) == [
        ("demo.Foo.bar", "method"),
        ("demo.Foo.bar.<locals>.Local.meth", "method"),
    ]


def test_nested_classes_method_only() -> None:
    src = "class Outer:\n    class Inner:\n        def method(self):\n            pass\n"
    assert _quals(src) == [("demo.Outer.Inner.method", "method")]


def test_async_treated_as_function() -> None:
    src = "async def afn():\n    async def inner():\n        pass\n"
    assert _quals(src) == [
        ("demo.afn", "function"),
        ("demo.afn.<locals>.inner", "function"),
    ]


def test_overload_dropped_before_first_wins() -> None:
    # Both stubs drop; the real implementation (3rd def) survives.
    src = (
        "from typing import overload\n"
        "@overload\n"
        "def f(x: int) -> int: ...\n"
        "@overload\n"
        "def f(x: str) -> str: ...\n"
        "def f(x):\n"
        "    return x\n"
    )
    assert _quals(src) == [("demo.f", "function")]


def test_aliased_overload_not_recognized() -> None:
    # @o is not recognized as overload, so the decorated def is a real entity.
    src = "from typing import overload as o\n@o\ndef h(x):\n    return x\n"
    assert _quals(src) == [("demo.h", "function")]


def test_property_setter_collapses_first_wins() -> None:
    # getter and setter share __qualname__ "C.x"; first-wins keeps the getter.
    src = (
        "class C:\n"
        "    @property\n"
        "    def x(self):\n"
        "        return 1\n"
        "    @x.setter\n"
        "    def x(self, v):\n"
        "        pass\n"
    )
    assert _quals(src) == [("demo.C.x", "method")]


def test_redefinition_first_wins() -> None:
    src = "def dup():\n    return 1\ndef dup():\n    return 2\n"
    entities = discover_file_entities(ast.parse(src), module="demo", path="demo.py")
    assert [e.qualname for e in entities] == ["demo.dup"]
    # first-wins keeps the FIRST definition's node (returns 1)
    body = entities[0].node.body[0]
    assert isinstance(body, ast.Return)
    assert isinstance(body.value, ast.Constant)
    assert body.value.value == 1


def test_function_inside_if_at_class_scope_is_method() -> None:
    # A def guarded by `if` in a class body still belongs to the class scope.
    src = "class C:\n    if True:\n        def m(self):\n            pass\n"
    assert _quals(src) == [("demo.C.m", "method")]


def test_location_anchors_on_def_line() -> None:
    src = "x = 1\n\n@staticmethod\ndef target():\n    pass\n"
    entities = discover_file_entities(ast.parse(src), module="demo", path="pkg/demo.py")
    assert len(entities) == 1
    loc = entities[0].location
    assert loc.path == "pkg/demo.py"
    assert loc.line_start == 4  # the `def` line, not the decorator (line 3)
    assert loc.col_start == 0
    assert loc.line_end == 5


def test_returns_entity_instances() -> None:
    entities = discover_file_entities(
        ast.parse("def f():\n    pass\n"), module="demo", path="demo.py"
    )
    assert all(isinstance(e, Entity) for e in entities)
    assert isinstance(entities[0].node, ast.FunctionDef)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/scanner/test_index.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'wardline.scanner.index'`

- [ ] **Step 3: Write the implementation**

```python
# src/wardline/scanner/index.py
"""Per-file entity discovery (stdlib + ``wardline.core`` only).

An *entity* is a ``FunctionDef`` or ``AsyncFunctionDef`` — the unit the taint
engine seeds. Classes are traversed as *scope* only (they contribute to
qualnames) and are not emitted. ``@overload`` stubs are dropped before
deduplication; duplicate qualnames are resolved first-wins (source order), so a
``@property`` getter wins over its setter and an earlier redefinition wins over
a later one.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from wardline.core.finding import Location
from wardline.core.qualname import is_overload_stub, reconstruct_qualname


@dataclass(frozen=True, slots=True)
class Entity:
    """A discovered function/method with its Clarion-aligned identity."""

    qualname: str  # full dotted ``module.__qualname__`` (reconciliation key)
    kind: str  # "function" | "method"
    node: ast.FunctionDef | ast.AsyncFunctionDef
    location: Location


def discover_file_entities(
    tree: ast.Module, *, module: str, path: str
) -> list[Entity]:
    """Discover function/method entities in *tree*, in source order.

    Args:
        tree: the parsed module AST.
        module: the file's dotted module name (from
            :func:`wardline.core.qualname.module_dotted_name`). Callers MUST skip
            files where that returned ``None`` (a top-level ``__init__.py``).
        path: project-relative POSIX path, recorded on each entity's Location.

    The first definition wins when two produce the same qualname. ``@overload``
    stubs are dropped *before* this deduplication, so a real implementation
    following stubs is the surviving entity.
    """
    entities: list[Entity] = []
    seen: set[str] = set()

    def visit(node: ast.AST, scope: list[ast.AST], *, parent_is_class: bool) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not is_overload_stub(child):
                    # ``scope`` is outermost->innermost; reconstruct wants
                    # innermost->outermost.
                    local = reconstruct_qualname(child.name, list(reversed(scope)))
                    qualname = f"{module}.{local}"
                    if qualname not in seen:
                        seen.add(qualname)
                        entities.append(
                            Entity(
                                qualname=qualname,
                                kind="method" if parent_is_class else "function",
                                node=child,
                                location=Location(
                                    path=path,
                                    line_start=child.lineno,
                                    line_end=child.end_lineno,
                                    col_start=child.col_offset,
                                    col_end=child.end_col_offset,
                                ),
                            )
                        )
                # A function nested inside this one is a "function", not a method.
                visit(child, [*scope, child], parent_is_class=False)
            elif isinstance(child, ast.ClassDef):
                visit(child, [*scope, child], parent_is_class=True)
            else:
                # Non-scope node (If/With/Try/...): scope and class-ness unchanged.
                visit(child, scope, parent_is_class=parent_is_class)

    visit(tree, [], parent_is_class=False)
    return entities
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/scanner/test_index.py -q`
Expected: PASS (all cases)

- [ ] **Step 5: Controller commits** (`feat(sp1a): per-file entity discovery`).

---

## Task 4: Conformance corpus + harness (the correctness gate)

**Files:**
- Create: `tests/conformance/__init__.py` (empty)
- Create: `tests/conformance/qualnames.json`
- Create: `tests/conformance/test_qualname_conformance.py`

- [ ] **Step 1: Write the corpus**

```json
{
  "_doc": "Shared qualname conformance corpus (Wardline <-> Clarion). Both tools test against this. 'module_dotted_name' cases assert the path->module rule; 'entities' cases assert per-file function/method qualnames+kinds (classes are scope only and not emitted). Nesting-shape expectations were generated from CPython co_qualname. Seeded by Wardline (SP1a); Clarion vendors a copy. Nothing imports this file at runtime.",
  "module_dotted_name": [
    {"rel_path": "demo.py", "expected": "demo"},
    {"rel_path": "src/demo.py", "expected": "demo"},
    {"rel_path": "src.py", "expected": "src"},
    {"rel_path": "pkg/__init__.py", "expected": "pkg"},
    {"rel_path": "src/pkg/__init__.py", "expected": "pkg"},
    {"rel_path": "pkg/sub/mod.py", "expected": "pkg.sub.mod"},
    {"rel_path": "src/pkg/sub/mod.py", "expected": "pkg.sub.mod"},
    {"rel_path": "src/src/pkg/mod.py", "expected": "src.pkg.mod"},
    {"rel_path": "__init__.py", "expected": null}
  ],
  "entities": [
    {
      "name": "module_function_and_closure",
      "rel_path": "demo.py",
      "source": "def outer():\n    def inner():\n        pass\n",
      "expected": [
        {"qualname": "demo.outer", "kind": "function"},
        {"qualname": "demo.outer.<locals>.inner", "kind": "function"}
      ]
    },
    {
      "name": "nested_classes_method",
      "rel_path": "demo.py",
      "source": "class Outer:\n    class Inner:\n        def method(self):\n            pass\n",
      "expected": [
        {"qualname": "demo.Outer.Inner.method", "kind": "method"}
      ]
    },
    {
      "name": "class_in_closure",
      "rel_path": "demo.py",
      "source": "class Foo:\n    def bar(self):\n        class Local:\n            def meth(self):\n                pass\n",
      "expected": [
        {"qualname": "demo.Foo.bar", "kind": "method"},
        {"qualname": "demo.Foo.bar.<locals>.Local.meth", "kind": "method"}
      ]
    },
    {
      "name": "deep_closures",
      "rel_path": "src/pkg/mod.py",
      "source": "def a():\n    def b():\n        def c():\n            pass\n",
      "expected": [
        {"qualname": "pkg.mod.a", "kind": "function"},
        {"qualname": "pkg.mod.a.<locals>.b", "kind": "function"},
        {"qualname": "pkg.mod.a.<locals>.b.<locals>.c", "kind": "function"}
      ]
    },
    {
      "name": "async_equiv_def",
      "rel_path": "demo.py",
      "source": "async def afn():\n    async def inner():\n        pass\n",
      "expected": [
        {"qualname": "demo.afn", "kind": "function"},
        {"qualname": "demo.afn.<locals>.inner", "kind": "function"}
      ]
    },
    {
      "name": "overload_dropped_before_first_wins",
      "rel_path": "demo.py",
      "source": "from typing import overload\n@overload\ndef f(x: int) -> int: ...\n@overload\ndef f(x: str) -> str: ...\ndef f(x):\n    return x\n",
      "expected": [
        {"qualname": "demo.f", "kind": "function"}
      ]
    },
    {
      "name": "typing_overload_form_dropped",
      "rel_path": "demo.py",
      "source": "import typing\n@typing.overload\ndef g(x: int) -> int: ...\ndef g(x):\n    return x\n",
      "expected": [
        {"qualname": "demo.g", "kind": "function"}
      ]
    },
    {
      "name": "aliased_overload_not_recognized",
      "rel_path": "demo.py",
      "source": "from typing import overload as o\n@o\ndef h(x):\n    return x\n",
      "expected": [
        {"qualname": "demo.h", "kind": "function"}
      ]
    },
    {
      "name": "property_setter_first_wins",
      "rel_path": "demo.py",
      "source": "class C:\n    @property\n    def x(self):\n        return 1\n    @x.setter\n    def x(self, v):\n        pass\n",
      "expected": [
        {"qualname": "demo.C.x", "kind": "method"}
      ]
    },
    {
      "name": "redefinition_first_wins",
      "rel_path": "demo.py",
      "source": "def dup():\n    return 1\ndef dup():\n    return 2\n",
      "expected": [
        {"qualname": "demo.dup", "kind": "function"}
      ]
    },
    {
      "name": "toplevel_init_emits_nothing",
      "rel_path": "__init__.py",
      "source": "def helper():\n    pass\n",
      "expected": []
    }
  ]
}
```

- [ ] **Step 2: Write the harness (failing until it can import + read corpus)**

```python
# tests/conformance/test_qualname_conformance.py
"""Drive the shared qualname conformance corpus through Wardline's producer.

The corpus (qualnames.json) is the cross-tool design-review artifact; Clarion
vendors a copy and runs the same assertions. Keep them in lockstep.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import pytest

from wardline.core.qualname import module_dotted_name
from wardline.scanner.index import discover_file_entities

_CORPUS = json.loads((Path(__file__).parent / "qualnames.json").read_text("utf-8"))


@pytest.mark.parametrize(
    "case", _CORPUS["module_dotted_name"], ids=lambda c: c["rel_path"]
)
def test_module_dotted_name(case: dict[str, Any]) -> None:
    assert module_dotted_name(case["rel_path"]) == case["expected"]


@pytest.mark.parametrize("case", _CORPUS["entities"], ids=lambda c: c["name"])
def test_entities(case: dict[str, Any]) -> None:
    module = module_dotted_name(case["rel_path"])
    if module is None:
        # A file with no module emits no entities (top-level __init__.py).
        assert case["expected"] == []
        return
    tree = ast.parse(case["source"])
    found = [
        {"qualname": e.qualname, "kind": e.kind}
        for e in discover_file_entities(tree, module=module, path=case["rel_path"])
    ]
    assert found == case["expected"]
```

- [ ] **Step 3: Run to verify pass**

Run: `python -m pytest tests/conformance/test_qualname_conformance.py -q`
Expected: PASS (9 module-name cases + 11 entity cases)

- [ ] **Step 4: Controller commits** (`test(sp1a): shared qualname conformance corpus + harness`).

---

## Task 5: `scanner/ast_primitives.py` — port `build_import_alias_map`

**Files:**
- Create: `src/wardline/scanner/ast_primitives.py`
- Test: `tests/unit/scanner/test_ast_primitives.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/scanner/test_ast_primitives.py
from __future__ import annotations

import ast

from wardline.scanner.ast_primitives import (
    build_import_alias_map,
    iter_calls_in_function_body,
)


def _alias_map(src: str, **kw: object) -> dict[str, str]:
    return build_import_alias_map(ast.parse(src), **kw)  # type: ignore[arg-type]


def test_plain_import_keeps_top_component() -> None:
    assert _alias_map("import os\n") == {"os": "os"}


def test_dotted_import_maps_first_component() -> None:
    assert _alias_map("import a.b.c\n") == {"a": "a"}


def test_dotted_import_with_alias() -> None:
    assert _alias_map("import a.b as ab\n") == {"ab": "a.b"}


def test_from_import() -> None:
    assert _alias_map("from a.b import c\n") == {"c": "a.b.c"}


def test_from_import_with_alias() -> None:
    assert _alias_map("from a.b import c as d\n") == {"d": "a.b.c"}


def test_star_import_ignored() -> None:
    assert _alias_map("from a.b import *\n") == {}


def test_nested_import_ignored() -> None:
    src = "def f():\n    import os\n"
    assert _alias_map(src) == {}


def test_relative_import_in_module() -> None:
    # module pkg.sub.mod ; `from . import x` -> pkg.sub.x
    assert _alias_map(
        "from . import x\n", module_path="pkg.sub.mod"
    ) == {"x": "pkg.sub.x"}


def test_relative_import_with_submodule() -> None:
    assert _alias_map(
        "from .helpers import check\n", module_path="pkg.sub.mod"
    ) == {"check": "pkg.sub.helpers.check"}


def test_relative_import_in_package_init() -> None:
    # pkg/__init__.py : current package is `pkg`, not `pkg`'s parent.
    assert _alias_map(
        "from . import x\n", module_path="pkg", is_package=True
    ) == {"x": "pkg.x"}


def test_double_relative_import() -> None:
    assert _alias_map(
        "from ..other import y\n", module_path="pkg.sub.mod"
    ) == {"y": "pkg.other.y"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/unit/scanner/test_ast_primitives.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'wardline.scanner.ast_primitives'`

- [ ] **Step 3: Write the implementation** (port verbatim from `wardline.old/src/wardline/scanner/import_resolver.py` lines 1-70 + `_scope.py` lines 55-99; the `resolve_*` call resolvers are NOT ported — they belong to SP1d's callgraph)

```python
# src/wardline/scanner/ast_primitives.py
"""Reusable, stdlib-only AST primitives ported from ``wardline.old``.

- ``build_import_alias_map`` — local-name -> fully-qualified-name from a module's
  top-level imports (resolving relative imports).
- ``iter_calls_in_function_body`` — every ``ast.Call`` in a function body without
  descending into nested function/class/lambda scopes.

Both are exercised only by unit tests in SP1a; their first engine consumer is
the SP1d callgraph. (The ``resolve_*`` call resolvers from ``.old`` land then.)
"""

from __future__ import annotations

import ast
from collections.abc import Iterator


def build_import_alias_map(
    tree: ast.Module,
    module_path: str = "",
    *,
    is_package: bool = False,
) -> dict[str, str]:
    """Build ``{local_name: fully_qualified_name}`` from module-level imports.

    Only top-level statements are processed (not imports inside functions). Star
    imports (``from X import *``) are ignored — they cannot be resolved without
    executing the import.

    Args:
        tree: parsed AST module.
        module_path: dotted module path of the file being analysed (e.g.
            ``"mypackage.submod"``); required to resolve relative imports.
        is_package: whether ``module_path`` names a package initializer
            (``pkg/__init__.py`` -> ``module_path="pkg"``, ``is_package=True``)
            so ``from . import y`` resolves against the current package.
    """
    alias_map: dict[str, str] = {}

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local_name = (
                    alias.asname if alias.asname else alias.name.split(".")[0]
                )
                alias_map[local_name] = (
                    alias.name if alias.asname else alias.name.split(".")[0]
                )
            continue
        if isinstance(node, ast.ImportFrom):
            if node.module is None and (node.level or 0) == 0:
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                local_name = alias.asname if alias.asname else alias.name
                level = node.level or 0
                if level > 0 and module_path:
                    parts = module_path.split(".")
                    package_parts = parts if is_package else parts[:-1]
                    ascend = level - 1
                    if ascend == 0:
                        base_parts = package_parts
                    elif ascend <= len(package_parts):
                        base_parts = package_parts[:-ascend]
                    else:
                        base_parts = []
                    base = ".".join(base_parts)
                    if node.module:
                        fqn = (
                            f"{base}.{node.module}.{alias.name}"
                            if base
                            else f"{node.module}.{alias.name}"
                        )
                    else:
                        fqn = f"{base}.{alias.name}" if base else alias.name
                elif node.module is not None:
                    fqn = f"{node.module}.{alias.name}"
                else:
                    continue
                alias_map[local_name] = fqn

    return alias_map


def iter_calls_in_function_body(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> Iterator[ast.Call]:
    """Yield every ``ast.Call`` in ``node``'s body without descending into nested
    function scopes.

    Stops at ``FunctionDef``, ``AsyncFunctionDef``, ``Lambda``, and ``ClassDef``
    — each introduces a new scope whose body calls are attributed elsewhere.
    Header expressions that execute in the enclosing scope (decorators, default
    values, base classes, metaclass keywords) are still attributed to ``node``.
    """

    def walk_node(current: ast.AST) -> Iterator[ast.Call]:
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in current.decorator_list:
                yield from walk_node(decorator)
            yield from _walk_argument_defaults(current.args)
            return
        if isinstance(current, ast.ClassDef):
            for decorator in current.decorator_list:
                yield from walk_node(decorator)
            for base in current.bases:
                yield from walk_node(base)
            for keyword in current.keywords:
                yield from walk_node(keyword.value)
            return
        if isinstance(current, ast.Lambda):
            yield from _walk_argument_defaults(current.args)
            return
        if isinstance(current, ast.Call):
            yield current
        for child in ast.iter_child_nodes(current):
            yield from walk_node(child)

    def _walk_argument_defaults(args: ast.arguments) -> Iterator[ast.Call]:
        for default in args.defaults:
            yield from walk_node(default)
        for kw_default in args.kw_defaults:
            if kw_default is None:
                continue
            yield from walk_node(kw_default)

    for stmt in node.body:
        yield from walk_node(stmt)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/unit/scanner/test_ast_primitives.py::test_plain_import_keeps_top_component tests/unit/scanner/test_ast_primitives.py -k import -q`
Expected: PASS (import-alias cases)

- [ ] **Step 5: Controller commits** — Tasks 5+6 may share one commit.

---

## Task 6: `scanner/ast_primitives.py` — `iter_calls_in_function_body` tests

The implementation already landed in Task 5. This task adds its tests.

**Files:**
- Test: `tests/unit/scanner/test_ast_primitives.py` (append)

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/scanner/test_ast_primitives.py`:

```python
def _func(src: str) -> ast.FunctionDef:
    node = ast.parse(src).body[0]
    assert isinstance(node, ast.FunctionDef)
    return node


def _call_names(src: str) -> list[str]:
    names: list[str] = []
    for call in iter_calls_in_function_body(_func(src)):
        func = call.func
        if isinstance(func, ast.Name):
            names.append(func.id)
        elif isinstance(func, ast.Attribute):
            names.append(func.attr)
    return names


def test_collects_direct_body_calls() -> None:
    src = "def f():\n    a()\n    b()\n"
    assert _call_names(src) == ["a", "b"]


def test_does_not_descend_into_nested_function() -> None:
    src = "def f():\n    a()\n    def g():\n        b()\n    g()\n"
    # b() is inside g's scope and is excluded; a() and g() remain.
    assert _call_names(src) == ["a", "g"]


def test_does_not_descend_into_nested_class_body() -> None:
    src = "def f():\n    a()\n    class C:\n        x = b()\n"
    assert _call_names(src) == ["a"]


def test_does_not_descend_into_lambda_body() -> None:
    src = "def f():\n    g = lambda: b()\n    a()\n"
    assert _call_names(src) == ["a"]


def test_nested_function_default_attributed_to_enclosing() -> None:
    # default value executes in f's scope -> default_call() is attributed to f,
    # but the body call b() inside g is not.
    src = "def f():\n    def g(x=default_call()):\n        b()\n"
    assert _call_names(src) == ["default_call"]


def test_calls_inside_control_flow_are_collected() -> None:
    src = "def f():\n    if cond():\n        a()\n    else:\n        b()\n"
    assert sorted(_call_names(src)) == ["a", "b", "cond"]
```

- [ ] **Step 2: Run full file to verify pass**

Run: `python -m pytest tests/unit/scanner/test_ast_primitives.py -q`
Expected: PASS (all cases)

- [ ] **Step 3: Controller commits** (`feat(sp1a): port reusable AST primitives (import-alias + call walker)`).

---

## Final Gate (controller runs after all tasks)

- [ ] Full suite green: `python -m pytest -q` (all SP0 tests + new SP1a tests; the SP0 self-hosting xfail must still xfail — no analyzer wiring yet).
- [ ] Lint clean: `python -m ruff check src tests`
- [ ] Types clean: `python -m mypy src` (strict).
- [ ] Dispatch a final code reviewer over the whole SP1a diff.
- [ ] Use superpowers:finishing-a-development-branch to merge `sp1a-qualnames-ast-primitives` back to `main`.

---

## Self-Review (controller checklist before execution)

1. **Spec coverage:** SP1 spec §6 SP1a row = "`core/qualname.py` (Clarion-aligned) + AST primitives (import-alias resolver, scope walkers) + entity discovery + conformance corpus" → Tasks 1-2 (qualname), 3 (entity discovery), 4 (corpus), 5-6 (AST primitives). ✓ Acceptance "corpus passes; entities for a fixture match expected qualnames incl. nested-class/closure/`__init__` cases" → Task 4 corpus covers closure, nested class, class-in-closure, `__init__` skip. ✓
2. **No placeholders:** every code step shows full code; no TBDs. ✓
3. **Type consistency:** `discover_file_entities(tree, *, module, path)` signature identical across index.py impl, unit tests, and conformance harness. `Entity(qualname, kind, node, location)` consistent. `module_dotted_name -> str | None` consistent. ✓
4. **Contract fidelity:** `module_dotted_name`/`reconstruct_qualname`/`is_overload_stub` match brief lines 233-251; overload-drop precedes first-wins; descriptor suffixing deliberately NOT ported. ✓
