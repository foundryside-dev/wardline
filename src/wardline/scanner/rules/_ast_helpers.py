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


def _names_a_broad_exception(node: ast.expr) -> bool:
    """True if *node* names ``Exception``/``BaseException`` (bare or dotted)."""
    if isinstance(node, ast.Name):
        return node.id in _BROAD_NAMES
    if isinstance(node, ast.Attribute):
        return node.attr in _BROAD_NAMES
    return False


def is_broad_except(handler: ast.ExceptHandler) -> bool:
    """True for a bare ``except:``, ``except Exception`` / ``except BaseException``
    (dotted forms like ``builtins.Exception`` match on the final attribute), or a
    tuple form containing one of those (``except (Exception, OSError):`` is just as
    broad as ``except Exception:``)."""
    t = handler.type
    if t is None:
        return True
    if isinstance(t, ast.Tuple):
        return any(_names_a_broad_exception(elt) for elt in t.elts)
    return _names_a_broad_exception(t)


def _is_ellipsis(stmt: ast.stmt) -> bool:
    return isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis


def is_silent_handler(handler: ast.ExceptHandler) -> bool:
    """True when the handler body only swallows: every statement is ``pass``,
    ``...``, ``continue``, or ``break`` (no logging, re-raise, return, or other
    handling)."""
    return all(isinstance(stmt, (ast.Pass, ast.Continue, ast.Break)) or _is_ellipsis(stmt) for stmt in handler.body)


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
    """True when *node* can reject: any ``raise``, any falsy-constant ``return``,
    or any ``assert`` in its own scope. Deliberately generous — PY-WL-102 is
    always-on, so we err toward SEEING a rejection path (risk a missed finding)
    over firing on a real validator.

    ``assert`` counts as a rejection here so PY-WL-102 does NOT fire on a boundary
    whose only reject is an assert — that boundary DOES reject at runtime. The
    distinct hazard (asserts are stripped under ``python -O``, so the validation
    silently vanishes in production) is PY-WL-111's job, via
    :func:`asserts_are_sole_rejection`. The two rules partition the space cleanly:
    102 fires on "no rejection of any shape", 111 on "the only rejection is an
    assert" — never both on one boundary."""
    for stmt in _own_statements(node):
        if isinstance(stmt, (ast.Raise, ast.Assert)):
            return True
        if isinstance(stmt, ast.Return) and _is_falsy_constant_return(stmt.value):
            return True
    return False


def asserts_are_sole_rejection(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True when *node*'s ONLY rejection mechanism is ``assert`` — at least one
    ``assert`` in its own scope, and NO ``raise`` and NO falsy-constant ``return``.

    This is PY-WL-111's predicate: such a boundary validates in development but is
    stripped under ``python -O`` (CWE-617), so the rejection silently vanishes in
    production. Mutually exclusive with PY-WL-102 (which fires only when
    :func:`has_rejection_path` is False, i.e. NO assert either)."""
    has_assert = False
    for stmt in _own_statements(node):
        if isinstance(stmt, ast.Raise):
            return False
        if isinstance(stmt, ast.Return) and _is_falsy_constant_return(stmt.value):
            return False
        if isinstance(stmt, ast.Assert):
            has_assert = True
    return has_assert
