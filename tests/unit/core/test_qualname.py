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


def _ancestors(src: str, target: str) -> tuple[str, list[ast.AST]]:
    """Parse *src*, locate the def/class named *target*, return (name, ancestors).

    ``ancestors`` is innermost->outermost, matching reconstruct_qualname's contract.
    """
    tree = ast.parse(src)
    found: list[tuple[ast.AST, list[ast.AST]]] = []

    def walk(node: ast.AST, scope: list[ast.AST]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                found.append((child, list(scope)))
                walk(child, [child, *scope])  # prepend -> innermost first
            else:
                walk(child, scope)

    walk(tree, [])
    node, ancestors = next((n, a) for n, a in found if getattr(n, "name", None) == target)
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
