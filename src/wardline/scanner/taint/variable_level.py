# src/wardline/scanner/taint/variable_level.py
"""Level 2 taint — per-variable taint tracking within a function body.

Given a function AST node and its Level 1 (function-level) taint, walks the body
tracking taint per variable through assignments, control-flow joins, and call
sites. Pure (returns a new dict); conservative (unknown expressions inherit the
function's L1 taint); join-based (branches merge via ``taint_join``).

Ported from ``wardline.old`` minus the manifest ``dependency_taint`` overlay
(SP1 §4.5): the ``dependency_dotted_map`` / ``dependency_local_prefixes`` params
and their two ``_resolve_call`` branches are removed. Call resolution is solely
against the caller-supplied ``taint_map`` (see ``compute_variable_taints``).
"""

from __future__ import annotations

import ast

from wardline.core.taints import TaintState, least_trusted, taint_join

# Serialisation sinks — calls that cross the representation boundary. Their
# output sheds validation provenance (raw bytes/str), so → UNKNOWN_RAW. This is
# a generic fail-closed heuristic, not governance. (SP1f note: where this and
# stdlib_taint disagree — only json.load/loads — the conservative UNKNOWN_RAW
# wins.)
_SERIALISATION_SINKS: frozenset[str] = frozenset(
    {
        "json.dumps", "json.dump", "json.loads", "json.load",
        "pickle.dumps", "pickle.dump", "pickle.loads", "pickle.load",
        "yaml.dump", "yaml.safe_dump", "yaml.dump_all",
        "yaml.safe_load", "yaml.load", "yaml.safe_load_all", "yaml.load_all",
        "marshal.dumps", "marshal.dump", "marshal.loads", "marshal.load",
        "tomllib.loads", "tomllib.load", "tomli_w.dumps", "tomli_w.dump",
    }
)


def compute_variable_taints(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
) -> dict[str, TaintState]:
    """Compute per-variable taint for a function body.

    Args:
        func_node: the function AST node to analyze.
        function_taint: this function's L1 taint; seeds parameters and is the
            fallback for unknown expressions.
        taint_map: call-resolution map keyed by the call-site name AS WRITTEN —
            bare (``"foo"``) for ``foo()``, dotted (``"mod.fn"``) for
            ``mod.fn()`` — mapping to that call's return taint. Calls whose name
            is absent fall back to ``function_taint``.

    Returns:
        ``{variable_name: TaintState}`` for every assigned variable and parameter
        in the function body. Nested function/class scopes are not descended.
    """
    var_taints: dict[str, TaintState] = {}
    _seed_parameters(func_node, function_taint, var_taints)
    _walk_body(func_node.body, function_taint, taint_map, var_taints)
    return var_taints


def _seed_parameters(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    function_taint: TaintState,
    var_taints: dict[str, TaintState],
) -> None:
    args = func_node.args
    for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs):
        var_taints[arg.arg] = function_taint
    if args.vararg:
        var_taints[args.vararg.arg] = function_taint
    if args.kwarg:
        var_taints[args.kwarg.arg] = function_taint


def _dotted_name(node: ast.expr) -> str | None:
    """Extract a dotted name from an attribute chain (``json.dumps`` → that str)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else None
    return None


def _resolve_expr(
    node: ast.expr,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> TaintState:
    if isinstance(node, ast.Constant):
        return TaintState.INTEGRAL
    if isinstance(node, ast.Name):
        return var_taints.get(node.id, function_taint)
    if isinstance(node, ast.Call):
        return _resolve_call(node, function_taint, taint_map, var_taints)
    if isinstance(node, ast.BinOp):
        left = _resolve_expr(node.left, function_taint, taint_map, var_taints)
        right = _resolve_expr(node.right, function_taint, taint_map, var_taints)
        return taint_join(left, right)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        if not node.elts:
            return TaintState.INTEGRAL
        result = _resolve_expr(node.elts[0], function_taint, taint_map, var_taints)
        for elt in node.elts[1:]:
            result = taint_join(result, _resolve_expr(elt, function_taint, taint_map, var_taints))
        return result
    if isinstance(node, ast.Dict):
        parts = [
            _resolve_expr(v, function_taint, taint_map, var_taints)
            for v in node.values
            if v is not None
        ]
        if not parts:
            return TaintState.INTEGRAL
        result = parts[0]
        for p in parts[1:]:
            result = taint_join(result, p)
        return result
    if isinstance(node, ast.NamedExpr):
        taint = _resolve_expr(node.value, function_taint, taint_map, var_taints)
        if isinstance(node.target, ast.Name):
            var_taints[node.target.id] = taint
        return taint
    if isinstance(node, ast.IfExp):
        true_t = _resolve_expr(node.body, function_taint, taint_map, var_taints)
        false_t = _resolve_expr(node.orelse, function_taint, taint_map, var_taints)
        return taint_join(true_t, false_t)
    if isinstance(node, ast.UnaryOp):
        return _resolve_expr(node.operand, function_taint, taint_map, var_taints)
    # Fallback: attribute access, subscript, comprehensions, etc.
    return function_taint


def _resolve_call(
    node: ast.Call,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> TaintState:
    # Resolve argument expressions for their walrus side-effects — e.g.
    # ``foo(x := bar())`` must bind ``x`` even though the call's own taint comes
    # from ``node.func``. The returned arg taints are discarded; only any
    # ``NamedExpr`` capture into ``var_taints`` matters here.
    for arg in node.args:
        _resolve_expr(arg, function_taint, taint_map, var_taints)
    for keyword in node.keywords:
        _resolve_expr(keyword.value, function_taint, taint_map, var_taints)
    if isinstance(node.func, ast.Attribute):
        dotted = _dotted_name(node.func)
        if dotted is not None:
            if dotted in _SERIALISATION_SINKS:
                return TaintState.UNKNOWN_RAW
            taint_hit = taint_map.get(dotted)
            if taint_hit is not None:
                return taint_hit
    if isinstance(node.func, ast.Name):
        try:
            return taint_map[node.func.id]
        except KeyError:
            pass
    return function_taint


# ── Statement walkers ────────────────────────────────────────────


def _walk_body(
    stmts: list[ast.stmt],
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> None:
    """Walk a list of statements, updating var_taints in place."""
    for stmt in stmts:
        _process_stmt(stmt, function_taint, taint_map, var_taints)


def _process_stmt(
    stmt: ast.stmt,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> None:
    """Process a single statement, dispatching by type.

    Uses isinstance dispatch rather than match/case to avoid PY-WL-003
    structural-gate findings at ASSURED taint (UNCONDITIONAL severity).
    """
    if isinstance(stmt, ast.Assign):
        _handle_assign(stmt, function_taint, taint_map, var_taints)

    elif isinstance(stmt, ast.AugAssign):
        _handle_augassign(stmt, function_taint, taint_map, var_taints)

    elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
        value = stmt.value
        if isinstance(stmt.target, ast.Name):
            taint = _resolve_expr(value, function_taint, taint_map, var_taints)
            var_taints[stmt.target.id] = taint
        else:
            _resolve_expr(value, function_taint, taint_map, var_taints)

    elif isinstance(stmt, ast.For):
        _handle_for(stmt, function_taint, taint_map, var_taints)

    elif isinstance(stmt, ast.While):
        _handle_while(stmt, function_taint, taint_map, var_taints)

    elif isinstance(stmt, ast.If):
        _handle_if(stmt, function_taint, taint_map, var_taints)

    elif isinstance(stmt, (ast.With, ast.AsyncWith)):
        _handle_with(stmt, function_taint, taint_map, var_taints)

    elif isinstance(stmt, ast.Try):
        _handle_try(stmt, function_taint, taint_map, var_taints)

    elif isinstance(stmt, ast.Expr):
        # Expression statement — walk for side-effects (walrus operators).
        _resolve_expr(stmt.value, function_taint, taint_map, var_taints)

    elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        pass  # Nested function/class — don't descend (separate scope).

    else:
        # Return, Raise, Import, Pass, Break, Continue, etc.
        _walk_exprs_for_walrus(stmt, function_taint, taint_map, var_taints)


def _walk_exprs_for_walrus(
    node: ast.AST,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> None:
    """Capture walrus assignments in a statement's expressions.

    Recurses manually (not ``ast.walk``) so it can skip nested ``Lambda``
    bodies: a walrus inside a lambda binds the *lambda's* scope, not this
    function's, so it must not leak into ``var_taints``. Comprehension walruses
    DO bind the enclosing scope (PEP 572) and are intentionally still captured.
    """
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.Lambda):
            continue  # separate scope — its walruses don't bind here
        if isinstance(child, ast.NamedExpr):
            taint = _resolve_expr(child.value, function_taint, taint_map, var_taints)
            if isinstance(child.target, ast.Name):
                var_taints[child.target.id] = taint
        _walk_exprs_for_walrus(child, function_taint, taint_map, var_taints)


# ── Assignment handlers ──────────────────────────────────────────


def _handle_assign(
    stmt: ast.Assign,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> None:
    """Handle ``x = expr`` and ``a, b = expr1, expr2``."""
    for target in stmt.targets:
        if isinstance(target, ast.Name):
            # Simple: x = expr
            taint = _resolve_expr(
                stmt.value, function_taint, taint_map, var_taints,
            )
            var_taints[target.id] = taint

        elif isinstance(target, (ast.Tuple, ast.List)):
            # Tuple unpacking: a, b = ...
            _handle_unpack(
                target, stmt.value, function_taint, taint_map, var_taints,
            )
        # Ignore attribute/subscript targets (obj.x = ..., d[k] = ...)


def _handle_unpack(
    target: ast.Tuple | ast.List,
    value: ast.expr,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> None:
    """Handle tuple/list unpacking assignment."""
    # If value is a Tuple/List with matching length, do element-wise.
    if isinstance(value, (ast.Tuple, ast.List)) and len(value.elts) == len(
        target.elts
    ):
        for tgt, val in zip(target.elts, value.elts, strict=False):
            if isinstance(tgt, ast.Name):
                taint = _resolve_expr(
                    val, function_taint, taint_map, var_taints,
                )
                var_taints[tgt.id] = taint
            elif isinstance(tgt, (ast.Tuple, ast.List)):
                _handle_unpack(tgt, val, function_taint, taint_map, var_taints)
    else:
        # RHS is not a matching literal tuple — all targets get RHS taint.
        rhs_taint = _resolve_expr(
            value, function_taint, taint_map, var_taints,
        )
        for tgt in target.elts:
            if isinstance(tgt, ast.Name):
                var_taints[tgt.id] = rhs_taint
            elif isinstance(tgt, ast.Starred) and isinstance(
                tgt.value, ast.Name
            ):
                var_taints[tgt.value.id] = rhs_taint


def _handle_augassign(
    stmt: ast.AugAssign,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> None:
    """Handle ``x += expr`` — join existing taint with new value."""
    rhs_taint = _resolve_expr(
        stmt.value, function_taint, taint_map, var_taints,
    )
    if isinstance(stmt.target, ast.Name):
        existing = var_taints.get(stmt.target.id, function_taint)
        var_taints[stmt.target.id] = taint_join(existing, rhs_taint)


# ── Control flow handlers ────────────────────────────────────────


def _handle_if(
    stmt: ast.If,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> None:
    """Handle if/elif/else — merge variable taints from branches."""
    # Resolve test expression (may contain walrus).
    _resolve_expr(stmt.test, function_taint, taint_map, var_taints)

    # Snapshot before branches.
    pre_if = dict(var_taints)

    # Walk the if-body.
    if_taints = dict(var_taints)
    _walk_body(stmt.body, function_taint, taint_map, if_taints)

    if stmt.orelse:
        # Walk the else-body.
        else_taints = dict(var_taints)
        _walk_body(stmt.orelse, function_taint, taint_map, else_taints)
    else:
        # No else — the "else" branch is the pre-if state.
        else_taints = pre_if

    # Merge: for each variable, join the two branch values.
    all_vars = set(if_taints) | set(else_taints)
    for var in all_vars:
        try:
            if_val: TaintState | None = if_taints[var]
        except KeyError:
            if_val = None
        try:
            else_val: TaintState | None = else_taints[var]
        except KeyError:
            else_val = None
        if if_val is not None and else_val is not None:
            var_taints[var] = taint_join(if_val, else_val)
        elif if_val is not None:
            var_taints[var] = if_val
        else:
            var_taints[var] = else_val  # type: ignore[assignment]


def _handle_for(
    stmt: ast.For,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> None:
    """Handle for loops — target gets iterable taint, body merges."""
    iter_taint = _resolve_expr(
        stmt.iter, function_taint, taint_map, var_taints,
    )

    # Assign the loop variable.
    _assign_target(stmt.target, iter_taint, var_taints)

    # Snapshot pre-loop.
    pre_loop = dict(var_taints)

    # Walk body.
    _walk_body(stmt.body, function_taint, taint_map, var_taints)

    # Merge body state with pre-loop (loop may not execute, or
    # body assignments may differ across iterations).
    for var in set(var_taints) | set(pre_loop):
        try:
            current = var_taints[var]
            prior = pre_loop[var]
            var_taints[var] = taint_join(current, prior)
        except KeyError:
            _taint_val = None  # var only in one side of merge — no join needed

    # Walk orelse (runs after normal loop completion).
    if stmt.orelse:
        _walk_body(stmt.orelse, function_taint, taint_map, var_taints)


def _handle_while(
    stmt: ast.While,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> None:
    """Handle while loops — body merges with pre-loop state."""
    _resolve_expr(stmt.test, function_taint, taint_map, var_taints)

    pre_loop = dict(var_taints)

    _walk_body(stmt.body, function_taint, taint_map, var_taints)

    # Merge body state with pre-loop.
    for var in set(var_taints) | set(pre_loop):
        try:
            current = var_taints[var]
            prior = pre_loop[var]
            var_taints[var] = taint_join(current, prior)
        except KeyError:
            _taint_val = None  # var only in one side of merge — no join needed

    if stmt.orelse:
        _walk_body(stmt.orelse, function_taint, taint_map, var_taints)


def _handle_with(
    stmt: ast.With | ast.AsyncWith,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> None:
    """Handle with/async-with statements."""
    for item in stmt.items:
        expr_taint = _resolve_expr(
            item.context_expr, function_taint, taint_map, var_taints,
        )
        if item.optional_vars is not None:
            _assign_target(item.optional_vars, expr_taint, var_taints)

    _walk_body(stmt.body, function_taint, taint_map, var_taints)


def _handle_try(
    stmt: ast.Try,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> None:
    """Handle try/except/else/finally — snapshot-branch-join pattern."""
    pre_try = dict(var_taints)

    # Walk try body on a copy.
    try_taints = dict(pre_try)
    _walk_body(stmt.body, function_taint, taint_map, try_taints)

    # Walk each handler on separate copies (mutually exclusive with try body).
    handler_branches: list[dict[str, TaintState]] = [try_taints]  # try-success is one branch
    for handler in stmt.handlers:
        handler_taints = dict(pre_try)
        if handler.name:
            handler_taints[handler.name] = function_taint
        _walk_body(handler.body, function_taint, taint_map, handler_taints)
        handler_branches.append(handler_taints)

    # Walk orelse on try-success branch (runs only if no exception).
    if stmt.orelse:
        _walk_body(stmt.orelse, function_taint, taint_map, try_taints)

    # Merge all branches.
    all_vars: set[str] = set()
    for branch in handler_branches:
        all_vars.update(branch.keys())

    for var in all_vars:
        taints_to_join: list[TaintState] = []
        for b in handler_branches:
            try:
                taints_to_join.append(b[var])
            except KeyError:
                _taint_val = None  # var absent from this handler branch — skip
        if taints_to_join:
            var_taints[var] = taints_to_join[0]
            for t in taints_to_join[1:]:
                var_taints[var] = taint_join(var_taints[var], t)
        else:
            # Unreachable: ``all_vars`` is drawn solely from ``handler_branches``
            # (the try-success branch + each handler), every branch starts as a
            # copy of pre_try, so each var is present in >=1 branch and
            # ``taints_to_join`` is never empty. Kept for structural parity.
            try:
                var_taints[var] = pre_try[var]
            except KeyError:
                _taint_val = None  # var absent from pre-try state — leave unset

    # finalbody runs unconditionally after merge.
    if stmt.finalbody:
        _walk_body(stmt.finalbody, function_taint, taint_map, var_taints)


# ── Helpers ──────────────────────────────────────────────────────


def _assign_target(
    target: ast.expr,
    taint: TaintState,
    var_taints: dict[str, TaintState],
) -> None:
    """Assign taint to a target node (Name, Tuple, or List)."""
    if isinstance(target, ast.Name):
        var_taints[target.id] = taint
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            _assign_target(elt, taint, var_taints)
    elif isinstance(target, ast.Starred) and isinstance(target.value, ast.Name):
        var_taints[target.value.id] = taint


def compute_return_taint(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> TaintState | None:
    """Compute the *actual* taint a function returns (least-trusted of all paths).

    Resolves every value-bearing ``return`` statement in *func_node*'s own scope
    (nested functions/lambdas excluded) against the already-computed ``var_taints``
    and the call-resolution ``taint_map``, and joins them with :func:`least_trusted`
    — the worst (least-trusted) value any path can return. Returns ``None`` when the
    function has no value-bearing ``return`` (implicit ``None`` / bare ``return`` /
    pure side-effect): there is no returned data to police.

    This is the precise input PY-WL-101 needs — distinct from ``project_taints``
    (the function's anchored *body* taint, pinned to its declaration).
    """
    returns: list[TaintState] = []
    _collect_return_taints(
        list(func_node.body), function_taint, taint_map, var_taints, returns
    )
    if not returns:
        return None
    result = returns[0]
    for r in returns[1:]:
        result = least_trusted(result, r)
    return result


def _collect_return_taints(
    nodes: list[ast.AST],
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
    out: list[TaintState],
) -> None:
    """Recurse the AST collecting value-bearing return taints, descending into ALL
    children EXCEPT nested ``FunctionDef``/``AsyncFunctionDef``/``ClassDef``/
    ``Lambda`` (separate scopes — their returns bind their own callable, not this
    one).

    Descent is unconditional because the constructs that hold returns are not all
    ``ast.stmt``: ``match``/``case`` bodies live under ``ast.match_case`` and
    ``except`` bodies under ``ast.ExceptHandler``, neither of which is an
    ``ast.stmt``. Gating descent on ``isinstance(child, ast.stmt)`` therefore
    silently dropped any ``return`` reachable only through a match arm or an
    exception handler — a fail-open under-taint. The ``Return`` guard is
    ``isinstance``-checked, so passing these non-statement nodes through is
    harmless."""
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(node, ast.Return) and node.value is not None:
            out.append(_resolve_expr(node.value, function_taint, taint_map, var_taints))
        _collect_return_taints(
            list(ast.iter_child_nodes(node)), function_taint, taint_map, var_taints, out
        )
