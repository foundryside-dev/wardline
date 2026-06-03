# src/wardline/core/qualname.py
"""Clarion-aligned qualname computation (stdlib-only).

Implements the qualname PRODUCER contract from the Loom integration brief
(§"Clarion (Python plugin) — qualname PRODUCER contract"). Wardline emits
``metadata.wardline.qualname`` as ``f"{module_dotted_name(path)}.{__qualname__}"``;
this module is the single source of truth for both halves so finding-to-Clarion
entity reconciliation stays lossless. A shared conformance corpus
(``tests/conformance/qualnames.json``) pins the behavior on both sides.

This deliberately does NOT match ``wardline.old``'s ``_qualnames.py``: that
emits ``outer.inner`` (no ``<locals>``), lacks overload/property-dedup handling,
and adds descriptor-accessor suffixing that Clarion does not. Do not port it.
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
