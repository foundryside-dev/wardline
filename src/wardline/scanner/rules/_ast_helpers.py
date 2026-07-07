# src/wardline/scanner/rules/_ast_helpers.py
"""Shared AST predicates for the SP2 rules.

All helpers operate on a single function's *own* scope — they never descend into
nested ``FunctionDef``/``AsyncFunctionDef``/``ClassDef`` bodies, so a finding is
attributed to the function that lexically owns the construct (nested functions
are separate entities and are analysed in their own right). The single sanctioned
exception is :func:`rejecting_helper_calls`, a ONE-HOP, SAME-MODULE inspection of
a called helper's body — bounded interprocedural sight so factored-out validators
(``_require_nonempty(p)``) are not misread as "no rejection path".
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from wardline.scanner.index import Entity

_BROAD_NAMES: frozenset[str] = frozenset({"Exception", "BaseException"})
_TYPE_CHECKING_FQN = "typing.TYPE_CHECKING"

# CURATED raising-conversion callables: constructors that raise (ValueError /
# decimal.InvalidOperation / ...) on EVERY invalid input and return a value of
# guaranteed shape — the canonical validate-by-construction idiom
# (``@trust_boundary def to_port(p): return int(p)``). Deliberately a small
# allowlist matched by (possibly dotted) final name: treating ARBITRARY calls as
# rejections would be an FN hole (any helper call would silence PY-WL-102).
# ``str``/``bool``/``repr`` are absent on purpose — they accept everything.
_RAISING_CONVERSION_NAMES: frozenset[str] = frozenset({"int", "float", "complex", "Decimal", "Fraction", "UUID"})


def _own_statements(node: ast.AST) -> Iterator[ast.stmt]:
    """Yield every statement in *node*'s own scope, not descending into nested
    def/class bodies. Includes the bodies of if/for/while/try/with at any depth."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(child, ast.stmt):
            yield child
        yield from _own_statements(child)


def _own_reachable_statements(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    alias_map: Mapping[str, str] | None = None,
) -> Iterator[ast.stmt]:
    yield from _reachable_statements_in_block(node.body, _scope_alias_map(node, alias_map))


def _own_reachable_nodes(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    alias_map: Mapping[str, str] | None = None,
) -> Iterator[ast.AST]:
    for stmt in _own_reachable_statements(node, alias_map):
        yield from _own_nodes_in_reachable_stmt(stmt)


def _own_nodes_in_reachable_stmt(stmt: ast.stmt) -> Iterator[ast.AST]:
    yield stmt
    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return
    yield from _walk_own_non_stmt_children(stmt)


def _walk_own_non_stmt_children(node: ast.AST) -> Iterator[ast.AST]:
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            yield child
        elif isinstance(child, ast.stmt):
            continue
        else:
            yield child
            yield from _walk_own_non_stmt_children(child)


def _reachable_statements_in_block(
    stmts: list[ast.stmt],
    alias_map: Mapping[str, str] | None = None,
) -> Iterator[ast.stmt]:
    for stmt in stmts:
        yield stmt
        if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for block in _child_statement_blocks(stmt, alias_map):
                yield from _reachable_statements_in_block(block, alias_map)
        if _stmt_always_terminates(stmt, alias_map):
            break


def _child_statement_blocks(stmt: ast.stmt, alias_map: Mapping[str, str] | None = None) -> Iterator[list[ast.stmt]]:
    if isinstance(stmt, ast.If):
        if _is_type_checking_guard(stmt.test, alias_map):
            yield stmt.orelse
            return
        yield stmt.body
        yield stmt.orelse
    elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
        yield stmt.body
        yield stmt.orelse
    elif isinstance(stmt, (ast.With, ast.AsyncWith)):
        yield stmt.body
    elif isinstance(stmt, (ast.Try, ast.TryStar)):
        yield stmt.body
        yield stmt.orelse
        yield stmt.finalbody
        for handler in stmt.handlers:
            yield handler.body
    elif isinstance(stmt, ast.Match):
        for case in stmt.cases:
            yield case.body


def _block_always_terminates(stmts: list[ast.stmt], alias_map: Mapping[str, str] | None = None) -> bool:
    return any(_stmt_always_terminates(stmt, alias_map) for stmt in stmts)


def _match_has_irrefutable_case(stmt: ast.Match) -> bool:
    return any(
        isinstance(case.pattern, ast.MatchAs) and case.pattern.pattern is None and case.guard is None
        for case in stmt.cases
    )


def _stmt_always_terminates(stmt: ast.stmt, alias_map: Mapping[str, str] | None = None) -> bool:
    if isinstance(stmt, (ast.Return, ast.Raise)):
        return True
    if isinstance(stmt, ast.If):
        if _is_type_checking_guard(stmt.test, alias_map):
            return bool(stmt.orelse) and _block_always_terminates(stmt.orelse, alias_map)
        return (
            bool(stmt.body)
            and bool(stmt.orelse)
            and _block_always_terminates(stmt.body, alias_map)
            and _block_always_terminates(stmt.orelse, alias_map)
        )
    if isinstance(stmt, ast.Match):
        return _match_has_irrefutable_case(stmt) and all(
            _block_always_terminates(case.body, alias_map) for case in stmt.cases
        )
    return False


def _dotted_expr_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_expr_name(node.value)
        return f"{base}.{node.attr}" if base is not None else None
    return None


def _resolve_dotted_expr(node: ast.expr, alias_map: Mapping[str, str] | None = None) -> str | None:
    dotted = _dotted_expr_name(node)
    if dotted is None:
        return None
    head, sep, rest = dotted.partition(".")
    resolved_head = alias_map.get(head, head) if alias_map is not None else head
    return f"{resolved_head}{sep}{rest}" if sep else resolved_head


def _is_type_checking_guard(test: ast.expr, alias_map: Mapping[str, str] | None = None) -> bool:
    return _resolve_dotted_expr(test, alias_map) == _TYPE_CHECKING_FQN


def _local_binding_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> Iterator[str]:
    """Yield names bound in *node*'s OWN scope that can shadow an outer binding —
    parameters, imports, and local assignment targets. ``from typing import
    TYPE_CHECKING`` / ``import typing`` are yielded here first, then restored by
    :func:`_local_typing_imports`, so only genuine typing bindings keep typing
    semantics. Walks the own scope (skips nested def/class)."""
    args = node.args
    for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs):
        yield arg.arg
    if args.vararg:
        yield args.vararg.arg
    if args.kwarg:
        yield args.kwarg.arg
    for stmt in _own_statements(node):
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            for alias in stmt.names:
                yield alias.asname or alias.name.split(".", 1)[0]
        elif isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                yield from _binding_target_names(target)
        elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign, ast.For, ast.AsyncFor)):
            yield from _binding_target_names(stmt.target)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                if item.optional_vars is not None:
                    yield from _binding_target_names(item.optional_vars)
        elif isinstance(stmt, ast.ExceptHandler) and stmt.name:
            yield stmt.name


def _binding_target_names(target: ast.AST) -> Iterator[str]:
    """Yield names bound by an assignment-like target, including destructuring."""
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, ast.Starred):
        yield from _binding_target_names(target.value)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            yield from _binding_target_names(elt)


def _local_typing_imports(node: ast.FunctionDef | ast.AsyncFunctionDef) -> Iterator[tuple[str, str]]:
    """Yield ``(local_name, fqn)`` for FUNCTION-LOCAL ``typing`` imports that bind
    the real typing constant: ``from typing import TYPE_CHECKING [as X]`` and
    ``import typing [as t]``. These ARE the genuine constant, so a function-local
    guard built on them is honored as the dead typing-only branch exactly like a
    module-level import."""
    for stmt in _own_statements(node):
        if isinstance(stmt, ast.ImportFrom) and stmt.module == "typing" and (stmt.level or 0) == 0:
            for alias in stmt.names:
                if alias.name == "TYPE_CHECKING":
                    yield (alias.asname or alias.name, _TYPE_CHECKING_FQN)
        elif isinstance(stmt, ast.Import):
            for alias in stmt.names:
                if alias.name == "typing":
                    yield (alias.asname or "typing", "typing")


def _scope_alias_map(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    alias_map: Mapping[str, str] | None = None,
) -> Mapping[str, str] | None:
    """The module *alias_map* corrected for *node*'s OWN-SCOPE bindings, so
    ``if TYPE_CHECKING:`` is read as the dead typing-only branch ONLY when the name
    actually refers to the typing constant at that point.

    Three corrections, applied in order:
      1. start from the module-level *alias_map* (module ``import typing`` /
         ``from typing import TYPE_CHECKING`` keep working);
      2. a parameter or local assignment that SHADOWS such a name removes its
         module binding (a ``def f(..., TYPE_CHECKING=True)`` makes the guard a real
         runtime branch — defect #3a);
      3. a function-LOCAL ``typing`` import restores the genuine constant, winning
         over a same-name shadow (defect #3b).

    Returns the unchanged *alias_map* when no own-scope binding touches a
    typing-relevant name, so the common case allocates nothing."""
    shadows = set(_local_binding_names(node))
    local_imports = dict(_local_typing_imports(node))
    if not shadows and not local_imports:
        return alias_map
    effective: dict[str, str] = dict(alias_map or {})
    for name in shadows:
        effective.pop(name, None)
    effective.update(local_imports)
    return effective


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


def _is_raising_conversion(value: ast.expr) -> bool:
    """True for a CURATED raising-expression: a :data:`_RAISING_CONVERSION_NAMES`
    constructor applied to at least one non-constant argument (``int(p)`` — a
    constant argument validates nothing), or a Subscript lookup with a
    non-constant key (``Color[p]`` raises ``KeyError``; ``ALLOWED[p]`` likewise —
    a CONSTANT index like ``parts[0]`` is positional access, not a validating
    lookup of the input)."""
    if isinstance(value, ast.Call):
        func = value.func
        if isinstance(func, ast.Name):
            name = func.id
        elif isinstance(func, ast.Attribute):
            name = func.attr
        else:
            return False
        return name in _RAISING_CONVERSION_NAMES and any(not isinstance(arg, ast.Constant) for arg in value.args)
    if isinstance(value, ast.Subscript):
        return isinstance(value.value, (ast.Name, ast.Attribute)) and not isinstance(value.slice, ast.Constant)
    return False


def _is_rejection_return(value: ast.expr | None) -> bool:
    """A ``return`` value that constitutes a rejection path: a falsy constant, a
    conditional expression with a rejecting branch (``return m.group(0) if m else
    None`` is the ternary form of ``if not m: return None``), or a curated
    raising-conversion (``return int(p)`` rejects-by-construction)."""
    if _is_falsy_constant_return(value):
        return True
    if isinstance(value, ast.IfExp):
        return _is_rejection_return(value.body) or _is_rejection_return(value.orelse)
    return value is not None and _is_raising_conversion(value)


def _stmt_is_real_rejection(stmt: ast.stmt) -> bool:
    """A statement that rejects IN PRODUCTION: a ``raise`` or a rejection-shaped
    ``return``. Excludes ``assert`` (stripped under ``python -O`` — PY-WL-111's
    hazard, never a *real* rejection)."""
    if isinstance(stmt, ast.Raise):
        return True
    return isinstance(stmt, ast.Return) and _is_rejection_return(stmt.value)


def has_real_rejection(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    alias_map: Mapping[str, str] | None = None,
) -> bool:
    """True when *node*'s own scope contains a production-surviving rejection —
    a ``raise`` or a rejection-shaped ``return`` — i.e. NOT counting ``assert``.
    This is PY-WL-113's premise half: a rejection must EXIST (and survive ``-O``)
    before a fail-open handler can be said to defeat it."""
    return any(_stmt_is_real_rejection(stmt) for stmt in _own_reachable_statements(node, alias_map))


def has_rejection_path(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    alias_map: Mapping[str, str] | None = None,
) -> bool:
    """True when *node* can reject: any ``raise``, any rejection-shaped ``return``
    (falsy constant, rejecting ternary branch, curated raising-conversion), or any
    ``assert`` in its own scope. Deliberately generous — PY-WL-102 is always-on,
    so we err toward SEEING a rejection path (risk a missed finding) over firing
    on a real validator.

    ``assert`` counts as a rejection here so PY-WL-102 does NOT fire on a boundary
    whose only reject is an assert — that boundary DOES reject at runtime. The
    distinct hazard (asserts are stripped under ``python -O``, so the validation
    silently vanishes in production) is PY-WL-111's job, via
    :func:`asserts_are_sole_rejection`.

    **The boundary-integrity family partitions FOUR ways** (wardline-718048a518),
    at most one of which fires per boundary:
      - PY-WL-119 — the bare degenerate shape (:func:`is_degenerate_boundary`);
      - PY-WL-102 — any other shape with no rejection path of any kind;
      - PY-WL-111 — the only rejection is ``assert``;
      - PY-WL-113 — a real rejection exists but a fail-open handler defeats it.
    """
    return any(
        isinstance(stmt, ast.Assert) or _stmt_is_real_rejection(stmt)
        for stmt in _own_reachable_statements(node, alias_map)
    )


def asserts_are_sole_rejection(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    alias_map: Mapping[str, str] | None = None,
) -> bool:
    """True when *node*'s ONLY rejection mechanism is ``assert`` — at least one
    ``assert`` in its own scope, and NO real rejection (``raise`` /
    rejection-shaped ``return``).

    This is PY-WL-111's predicate: such a boundary validates in development but is
    stripped under ``python -O`` (CWE-617), so the rejection silently vanishes in
    production. Mutually exclusive with PY-WL-102 (which fires only when
    :func:`has_rejection_path` is False, i.e. NO assert either). Callers that can
    see the project context additionally consult :func:`rejecting_helper_calls` —
    a raising same-module helper survives ``-O`` and rescues the boundary."""
    has_assert = False
    for stmt in _own_reachable_statements(node, alias_map):
        if _stmt_is_real_rejection(stmt):
            return False
        if isinstance(stmt, ast.Assert):
            has_assert = True
    return has_assert


def is_degenerate_boundary(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True for the bare degenerate boundary: the body is (modulo docstrings /
    ``pass``) a single ``return <param>``. PY-WL-119's shape — a strict subset of
    "no rejection path", carved out of PY-WL-102's domain so the family partitions
    cleanly (119 wins on this shape; 102 owns every other no-rejection shape)."""
    param_names = {arg.arg for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)}
    if node.args.vararg:
        param_names.add(node.args.vararg.arg)
    if node.args.kwarg:
        param_names.add(node.args.kwarg.arg)

    non_trivial_stmts = [
        stmt for stmt in node.body if not isinstance(stmt, ast.Pass) and not _is_ellipsis_or_constant(stmt)
    ]
    if len(non_trivial_stmts) == 1 and isinstance(non_trivial_stmts[0], ast.Return):
        ret_val = non_trivial_stmts[0].value
        if isinstance(ret_val, ast.Name) and ret_val.id in param_names:
            return True
    return False


def _resolve_one_hop_callee(
    call: ast.Call,
    entity: Entity,
    entities: Mapping[str, Entity],
    call_site_callees: Mapping[int, str],
) -> Entity | None:
    """Resolve *call* to a SAME-MODULE project entity, or None.

    The engine's resolved target (``call_site_callees``) wins when present; a
    resolved CROSS-module callee is deliberately discarded (one-hop stays
    same-module — cheap and conservative). Otherwise a lexical fallback maps a
    bare ``helper(...)`` or single-attribute ``Cls.method(...)`` callee onto the
    boundary's enclosing qualname prefixes, shortest first (module scope is what
    a bare name actually resolves to; class scopes are tried later only as a
    static/class-method courtesy)."""
    resolved = call_site_callees.get(id(call))
    if resolved is not None:
        callee = entities.get(resolved)
        if callee is not None and callee.location.path == entity.location.path and callee.qualname != entity.qualname:
            return callee
        return None
    func = call.func
    if isinstance(func, ast.Name):
        suffix = func.id
    elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        suffix = f"{func.value.id}.{func.attr}"
    else:
        return None
    parts = entity.qualname.split(".")
    for i in range(1, len(parts)):
        candidate = entities.get(".".join((*parts[:i], suffix)))
        if (
            candidate is not None
            and candidate.location.path == entity.location.path
            and candidate.qualname != entity.qualname
        ):
            return candidate
    return None


def rejecting_helper_calls(
    entity: Entity,
    entities: Mapping[str, Entity],
    call_site_callees: Mapping[int, str],
    alias_map: Mapping[str, str] | None = None,
) -> frozenset[int]:
    """The ``id()``s of own-scope ``Call`` nodes in *entity* that resolve (one hop,
    same module) to a callee whose OWN body has a real rejection — a factored-out
    validator (``_require_nonempty(p)``), a raising staticmethod helper, or
    wholesale delegation to another raising boundary (``return inner(p)``).

    Bounded interprocedural sight for the boundary-integrity family: such a call
    IS the boundary's rejection path, so PY-WL-102/111 must stay silent and
    PY-WL-113 can locate the rejection inside a ``try``. Strictly ONE hop (the
    callee's body is inspected with the own-scope :func:`has_real_rejection`,
    never recursively) and strictly same-module (same ``location.path``).

    SOUNDNESS: the callee must have a REAL rejection — a helper that cannot raise
    (logs and returns) never counts, and an assert-only helper never counts (its
    assert vanishes under ``python -O`` exactly like an inline one, which would
    falsely silence PY-WL-111)."""
    ids: set[int] = set()
    for n in _own_reachable_nodes(entity.node, alias_map):
        if isinstance(n, ast.Call):
            callee = _resolve_one_hop_callee(n, entity, entities, call_site_callees)
            if callee is not None and has_real_rejection(callee.node, alias_map):
                ids.add(id(n))
    return frozenset(ids)


def assert_only_helper_calls(
    entity: Entity,
    entities: Mapping[str, Entity],
    call_site_callees: Mapping[int, str],
    alias_map: Mapping[str, str] | None = None,
) -> frozenset[int]:
    """The ``id()``s of own-scope ``Call`` nodes in *entity* that resolve (one hop,
    same module) to a callee whose only rejection is ``assert``.

    This is the PY-WL-111 mirror of :func:`rejecting_helper_calls`: a factored-out
    assert-only validator is still a rejection path, but it disappears under
    ``python -O`` just like an inline assert. It therefore belongs to 111, not 102.
    """
    ids: set[int] = set()
    for n in _own_reachable_nodes(entity.node, alias_map):
        if isinstance(n, ast.Call):
            callee = _resolve_one_hop_callee(n, entity, entities, call_site_callees)
            if callee is not None and asserts_are_sole_rejection(callee.node, alias_map):
                ids.add(id(n))
    return frozenset(ids)


def _own_reachable_nodes_in_blocks(
    stmts: list[ast.stmt],
    alias_map: Mapping[str, str] | None = None,
) -> Iterator[ast.AST]:
    for stmt in _reachable_statements_in_block(stmts, alias_map):
        yield from _own_nodes_in_reachable_stmt(stmt)


def block_has_real_rejection(
    stmts: list[ast.stmt],
    rejecting_call_ids: frozenset[int] = frozenset(),
    alias_map: Mapping[str, str] | None = None,
) -> bool:
    """True when the statement list *stmts* (a ``try`` body or handler body)
    lexically contains a reachable real rejection — a ``raise`` / rejection-shaped
    ``return`` in its own scope, or a reachable call whose ``id()`` is in
    *rejecting_call_ids* (a one-hop rejecting helper, see
    :func:`rejecting_helper_calls`). PY-WL-113's per-``try`` premise: a handler
    can only swallow a rejection that lives inside its own ``try``."""
    for stmt in _reachable_statements_in_block(stmts, alias_map):
        if _stmt_is_real_rejection(stmt):
            return True
    if rejecting_call_ids:
        for n in _own_reachable_nodes_in_blocks(stmts, alias_map):
            if isinstance(n, ast.Call) and id(n) in rejecting_call_ids:
                return True
    return False


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
