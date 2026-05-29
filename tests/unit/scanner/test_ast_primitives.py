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


def test_own_decorator_and_defaults_not_yielded() -> None:
    # The analyzed function's OWN header (decorator + default-value calls)
    # executes in the enclosing scope, so iter_calls_in_function_body must not
    # yield it — only body calls. Pins the node.body-only walk against regression.
    src = "@reg(setup())\ndef f(x=default_call()):\n    a()\n"
    assert _call_names(src) == ["a"]
