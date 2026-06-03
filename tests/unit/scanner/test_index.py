# tests/unit/scanner/test_index.py
from __future__ import annotations

import ast

from wardline.scanner.index import Entity, discover_class_qualnames, discover_file_entities


def _quals(src: str, module: str = "demo", path: str = "demo.py") -> list[tuple[str, str]]:
    tree = ast.parse(src)
    return [(e.qualname, e.kind) for e in discover_file_entities(tree, module=module, path=path)]


def test_module_function_and_closure() -> None:
    src = "def outer():\n    def inner():\n        pass\n"
    assert _quals(src) == [
        ("demo.outer", "function"),
        ("demo.outer.<locals>.inner", "function"),
    ]


def test_methods_and_nested_class_in_closure() -> None:
    src = "class Foo:\n    def bar(self):\n        class Local:\n            def meth(self):\n                pass\n"
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


def test_property_setter_registers_separately() -> None:
    # getter and setter get distinct qualnames; both are registered.
    src = (
        "class C:\n"
        "    @property\n"
        "    def x(self):\n"
        "        return 1\n"
        "    @x.setter\n"
        "    def x(self, v):\n"
        "        pass\n"
    )
    entities = discover_file_entities(ast.parse(src), module="demo", path="demo.py")
    assert [(e.qualname, e.kind) for e in entities] == [
        ("demo.C.x", "method"),
        ("demo.C.x:setter", "method"),
    ]
    # Prove the GETTER has @property and returns 1
    getter = entities[0].node
    assert [d.id for d in getter.decorator_list if isinstance(d, ast.Name)] == ["property"]
    ret = getter.body[0]
    assert isinstance(ret, ast.Return)
    assert isinstance(ret.value, ast.Constant)
    assert ret.value.value == 1

    # Prove the SETTER is registered too
    setter = entities[1].node
    assert [d.attr for d in setter.decorator_list if isinstance(d, ast.Attribute)] == ["setter"]


def test_redefinition_last_wins() -> None:
    src = "def dup():\n    return 1\ndef dup():\n    return 2\n"
    entities = discover_file_entities(ast.parse(src), module="demo", path="demo.py")
    assert [e.qualname for e in entities] == ["demo.dup"]
    # Plain Python redefinition keeps the later runtime-live definition.
    body = entities[0].node.body[0]
    assert isinstance(body, ast.Return)
    assert isinstance(body.value, ast.Constant)
    assert body.value.value == 2
    assert entities[0].location.line_start == 3


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
    entities = discover_file_entities(ast.parse("def f():\n    pass\n"), module="demo", path="demo.py")
    assert all(isinstance(e, Entity) for e in entities)
    assert isinstance(entities[0].node, ast.FunctionDef)


def test_discover_class_qualnames_top_level_and_nested() -> None:
    src = "class Outer:\n    def m(self): pass\n    class Inner:\n        def n(self): pass\ndef free(): pass\n"
    tree = ast.parse(src)
    classes = discover_class_qualnames(tree, module="pkg.mod")
    assert classes == {"pkg.mod.Outer", "pkg.mod.Outer.Inner"}


def test_class_qualname_is_rsplit_prefix_of_its_methods() -> None:
    # The invariant the callgraph relies on: a method's enclosing class qualname
    # equals method_qualname.rsplit('.', 1)[0], and is built by the SAME
    # reconstruct_qualname as the methods.
    src = "class Outer:\n    class Inner:\n        def n(self): pass\n"
    tree = ast.parse(src)
    entities = discover_file_entities(tree, module="pkg.mod", path="pkg/mod.py")
    classes = discover_class_qualnames(tree, module="pkg.mod")
    method = next(e for e in entities if e.qualname.endswith(".n"))
    assert method.qualname == "pkg.mod.Outer.Inner.n"
    assert method.qualname.rsplit(".", 1)[0] in classes
