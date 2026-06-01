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
        entities=entities,
        class_qualnames=classes,
        alias_map=aliases,
        module_prefix="m",
        project_fqns=project_fqns,
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
        entities=entities,
        class_qualnames=classes,
        alias_map=aliases,
        module_prefix="m",
        project_fqns=project_fqns,
    )
    assert edges["m.a"] == frozenset({"other.helper"})


def test_self_method_edge() -> None:
    src = "class C:\n    def process(self):\n        return self.helper()\n    def helper(self):\n        return 1\n"
    tree, entities, classes, aliases = _module(src, module="m")
    project_fqns = frozenset(e.qualname for e in entities)
    edges, resolved, unresolved = build_call_edges(
        entities=entities,
        class_qualnames=classes,
        alias_map=aliases,
        module_prefix="m",
        project_fqns=project_fqns,
    )
    assert edges["m.C.process"] == frozenset({"m.C.helper"})
    assert resolved["m.C.process"] == 1


def test_unresolved_external_call_counted() -> None:
    src = "def a():\n    return some_external_thing()\n"
    tree, entities, classes, aliases = _module(src, module="m")
    project_fqns = frozenset({"m.a"})
    edges, resolved, unresolved = build_call_edges(
        entities=entities,
        class_qualnames=classes,
        alias_map=aliases,
        module_prefix="m",
        project_fqns=project_fqns,
    )
    assert edges["m.a"] == frozenset()
    assert unresolved["m.a"] == 1


def test_constructor_call_is_unresolved() -> None:
    # ClassName() is deliberately not resolved -> counts as unresolved (safe).
    src = "class C:\n    def __init__(self): pass\ndef make():\n    return C()\n"
    tree, entities, classes, aliases = _module(src, module="m")
    project_fqns = frozenset(e.qualname for e in entities)
    edges, resolved, unresolved = build_call_edges(
        entities=entities,
        class_qualnames=classes,
        alias_map=aliases,
        module_prefix="m",
        project_fqns=project_fqns,
    )
    assert edges["m.make"] == frozenset()
    assert unresolved["m.make"] == 1


def test_nested_def_calls_not_attributed_to_outer() -> None:
    src = "def outer():\n    def inner():\n        return b()\n    return inner()\ndef b():\n    return 1\n"
    tree, entities, classes, aliases = _module(src, module="m")
    project_fqns = frozenset(e.qualname for e in entities)
    edges, resolved, unresolved = build_call_edges(
        entities=entities,
        class_qualnames=classes,
        alias_map=aliases,
        module_prefix="m",
        project_fqns=project_fqns,
    )
    # outer() calls inner() (a nested def, not a project entity) -> unresolved;
    # b() is called only inside inner's body, NOT attributed to outer.
    assert "m.b" not in edges["m.outer"]
