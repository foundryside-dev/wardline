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
        if isinstance(stmt, (ast.Try, ast.TryStar)):
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


def _is_ellipsis_or_constant(stmt: ast.stmt) -> bool:
    return isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant)


def is_silent_handler(handler: ast.ExceptHandler) -> bool:
    """True when the handler body only swallows: every statement is ``pass``,
    ``...``, ``continue``, ``break``, or a constant expression (no logging,
    re-raise, return, or other handling)."""
    return all(
        isinstance(stmt, (ast.Pass, ast.Continue, ast.Break)) or _is_ellipsis_or_constant(stmt) for stmt in handler.body
    )


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


def _contains_reraise(handler: ast.ExceptHandler) -> bool:
    """True if *handler* re-raises anywhere in its own body (bare ``raise`` /
    ``raise X`` / ``raise X from e``). Does not descend into nested def/class."""
    return any(isinstance(stmt, ast.Raise) for stmt in _own_statements(handler))


def returned_var_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> frozenset[str]:
    """The set of local names *node* returns by value (``return result``) anywhere in
    its own scope. Used to recognise the assign-then-fall-through substitution shape
    in :func:`handler_substitutes_on_failure` — a handler that rebinds a name the
    function later returns substitutes a value just as ``return name`` would."""
    return frozenset(
        stmt.value.id
        for stmt in _own_statements(node)
        if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Name)
    )


def _is_self_assignment(stmt: ast.Assign) -> bool:
    """True for an idempotent ``x = x`` — the RHS is a bare Name equal to a target.
    Such an assignment substitutes nothing new, so it is not a fail-open substitution."""
    return isinstance(stmt.value, ast.Name) and any(
        isinstance(t, ast.Name) and t.id == stmt.value.id for t in stmt.targets
    )


def handler_substitutes_on_failure(handler: ast.ExceptHandler, returned_names: frozenset[str] = frozenset()) -> bool:
    """FAIL-OPEN: does not re-raise and substitutes a value-bearing (non-rejection)
    result. Two substitution shapes match, both bypassing the boundary:

      - an in-handler ``return X`` of a non-falsy value (``return p`` / ``return DEFAULT``);
      - an in-handler ASSIGNMENT of a non-falsy value to a name in *returned_names* —
        a name the owning function then returns by FALL-THROUGH (``result = p`` here,
        ``return result`` after the ``try``). Structurally identical to the return form.

    A falsy/bare ``return`` (or assignment of a falsy value) is a REJECTION signal, not
    substitution, so it does not match; a (even conditional) re-raise never matches.

    The assignment shape is FALL-THROUGH only: it is gated on the handler having no
    UNCONDITIONAL (top-level) ``return`` of its own, because a handler that always exits via
    its own ``return`` (a rejecting ``return None`` or a value-return handled by the first
    branch) never lets an in-handler assignment escape to the function's post-``try`` return
    (wardline-c314a7140b panel-1: ``result = p`` then ``return None`` is fail-CLOSED). The
    gate is TOP-LEVEL only (``handler.body``, NOT the depth-descending ``_own_statements``):
    a merely CONDITIONAL ``return`` nested in an ``if`` does not prevent fall-through, so the
    assignment can still escape on the other path and must match (panel-2: ``if flag: return
    None`` then ``result = p``). A self-assignment (``result = result``) substitutes nothing
    new and is excluded. *returned_names* defaults empty, so the assignment shape is inert
    unless the caller supplies the function's fall-through-returned names. PY-WL-113."""
    if _contains_reraise(handler):
        return False
    handler_returns = any(isinstance(s, ast.Return) for s in handler.body)
    for stmt in _own_statements(handler):
        if isinstance(stmt, ast.Return) and not _is_falsy_constant_return(stmt.value):
            return True
        if handler_returns:
            continue  # the handler exits via its own return — no assignment falls through
        if (
            isinstance(stmt, ast.Assign)
            and not _is_falsy_constant_return(stmt.value)
            and not _is_self_assignment(stmt)
            and any(isinstance(t, ast.Name) and t.id in returned_names for t in stmt.targets)
        ):
            return True
        if (
            isinstance(stmt, ast.AnnAssign)
            and stmt.value is not None
            and not _is_falsy_constant_return(stmt.value)
            and isinstance(stmt.target, ast.Name)
            and stmt.target.id in returned_names
        ):
            return True
    return False


def own_nodes(node: ast.AST) -> Iterator[ast.AST]:
    """Yield *node* itself and all descendant nodes in its own scope (skipping nested scopes)."""
    yield node
    yield from _walk_own(node)


def _walk_own(node: ast.AST) -> Iterator[ast.AST]:
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            yield child
        else:
            yield child
            yield from _walk_own(child)
