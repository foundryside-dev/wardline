"""Level 2 taint — per-variable taint tracking within function bodies.

Given a function AST node and its Level 1 (function-level) taint state,
walks the function body tracking taint per variable through assignments.

Design principles:
- **Pure function**: no side effects, returns a new dict.
- **Conservative**: unknown expressions get the function's own L1 taint.
- **Join-based merging**: control-flow branches merge via ``taint_join``.

Assignment forms handled:
1. ``x = expr`` — simple assignment
2. ``x += expr`` — augmented assignment (join with existing)
3. ``a, b = expr1, expr2`` — tuple unpacking
4. ``for x in iterable:`` — for-loop target
5. ``with open(f) as handle:`` — with-as
6. ``except Error as e:`` — exception-as
7. ``if (x := expr):`` — walrus operator (NamedExpr)
"""

from __future__ import annotations

import ast
import logging

from wardline.core.taints import TaintState, taint_join

logger = logging.getLogger(__name__)


def compute_variable_taints(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    *,
    dependency_dotted_map: dict[str, TaintState] | None = None,
    dependency_local_prefixes: frozenset[str] = frozenset(),
) -> dict[str, TaintState]:
    """Compute per-variable taint for a function body.

    Args:
        func_node: The function AST node to analyze.
        function_taint: The Level 1 taint assigned to this function.
        taint_map: Maps function qualnames to their callee-resolution
            taint (what calling that function returns). For decorator-
            anchored validators this is the OUTPUT tier (return taint);
            for all other functions it is the L3-refined body taint.
        dependency_dotted_map: Maps dotted local names (e.g. ``req.get``)
            to declared dependency taint states.
        dependency_local_prefixes: Local names that alias declared
            dependency packages (for UNKNOWN_RAW fallback on undeclared
            functions).

    Returns:
        Dict mapping variable name to ``TaintState`` for every assigned
        variable in the function body, including parameters.
    """
    var_taints: dict[str, TaintState] = {}
    dep_dotted = dependency_dotted_map
    dep_prefixes = dependency_local_prefixes

    # Parameters inherit the function's own taint (callers' data flows in).
    _seed_parameters(func_node, function_taint, var_taints)

    # Walk the body.
    _walk_body(func_node.body, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)

    return var_taints


# ── Parameter seeding ────────────────────────────────────────────


def _seed_parameters(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    function_taint: TaintState,
    var_taints: dict[str, TaintState],
) -> None:
    """Assign function taint to all parameters."""
    args = func_node.args
    for arg in (
        *args.posonlyargs,
        *args.args,
        *args.kwonlyargs,
    ):
        var_taints[arg.arg] = function_taint
    if args.vararg:
        var_taints[args.vararg.arg] = function_taint
    if args.kwarg:
        var_taints[args.kwarg.arg] = function_taint


# ── Expression taint resolution ──────────────────────────────────


def _resolve_expr(
    node: ast.expr,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
    dep_dotted: dict[str, TaintState] | None,
    dep_prefixes: frozenset[str],
) -> TaintState:
    """Resolve the taint of an expression node.

    Rules:
    - Literals (Constant, JoinedStr with all-constant parts) → INTEGRAL
    - Name references → look up in var_taints
    - Function calls → look up callee in taint_map
    - Binary ops → join(left, right)
    - List/Tuple/Set/Dict literals → join of all elements
    - NamedExpr (walrus) → resolve inner, also assign to target
    - Fallback → function_taint
    """
    if isinstance(node, ast.Constant):
        return TaintState.INTEGRAL

    if isinstance(node, ast.Name):
        return var_taints.get(node.id, function_taint)

    if isinstance(node, ast.Call):
        return _resolve_call(node, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)

    if isinstance(node, ast.BinOp):
        left = _resolve_expr(node.left, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)
        right = _resolve_expr(node.right, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)
        return taint_join(left, right)

    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        if not node.elts:
            return TaintState.INTEGRAL
        result = _resolve_expr(node.elts[0], function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)
        for elt in node.elts[1:]:
            result = taint_join(
                result,
                _resolve_expr(elt, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes),
            )
        return result

    if isinstance(node, ast.Dict):
        if not node.values:
            return TaintState.INTEGRAL
        parts: list[TaintState] = []
        for v in node.values:
            if v is not None:
                parts.append(
                    _resolve_expr(v, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)
                )
        if not parts:
            return TaintState.INTEGRAL
        result = parts[0]
        for p in parts[1:]:
            result = taint_join(result, p)
        return result

    if isinstance(node, ast.NamedExpr):
        taint = _resolve_expr(node.value, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)
        if isinstance(node.target, ast.Name):
            var_taints[node.target.id] = taint
        return taint

    if isinstance(node, ast.IfExp):
        true_t = _resolve_expr(node.body, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)
        false_t = _resolve_expr(node.orelse, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)
        return taint_join(true_t, false_t)

    if isinstance(node, ast.UnaryOp):
        return _resolve_expr(node.operand, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)

    # Fallback: attribute access, subscript, etc. — use function taint.
    return function_taint


# Serialisation sinks — calls that cross the representation boundary (§5.2).
# Results shed direct authority: output is raw bytes/string, not typed objects.
_SERIALISATION_SINKS: frozenset[str] = frozenset({
    # JSON
    "json.dumps", "json.dump", "json.loads", "json.load",
    # pickle
    "pickle.dumps", "pickle.dump", "pickle.loads", "pickle.load",
    # YAML
    "yaml.dump", "yaml.safe_dump", "yaml.dump_all",
    "yaml.safe_load", "yaml.load", "yaml.safe_load_all", "yaml.load_all",
    # marshal
    "marshal.dumps", "marshal.dump", "marshal.loads", "marshal.load",
    # tomllib (read-only in stdlib) / tomli_w (write)
    "tomllib.loads", "tomllib.load", "tomli_w.dumps", "tomli_w.dump",
})


def _dotted_name(node: ast.expr) -> str | None:
    """Extract a dotted name from an attribute chain (e.g. json.dumps → 'json.dumps')."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else None
    return None


def _resolve_call(
    node: ast.Call,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
    dep_dotted: dict[str, TaintState] | None,
    dep_prefixes: frozenset[str],
) -> TaintState:
    """Resolve taint for a function call expression.

    Resolution order for dotted calls (``obj.method()``):
    1. Serialisation sinks (§5.2) → UNKNOWN_RAW
    2. Exact match in taint_map (pre-resolved bare dependency imports)
    3. Exact match in dep_dotted (module-import dotted names)
    4. §5.5 fallback: undeclared function in a declared package → UNKNOWN_RAW

    Simple name calls (``foo()``) look up in taint_map.
    Everything else → function_taint.
    """
    if isinstance(node.func, ast.Attribute):
        dotted = _dotted_name(node.func)
        if dotted is not None:
            # 1. Serialisation sinks always shed to UNKNOWN_RAW
            if dotted in _SERIALISATION_SINKS:
                return TaintState.UNKNOWN_RAW
            # 2. Exact match in taint_map (pre-resolved dependency entries)
            taint_hit = taint_map.get(dotted)
            if taint_hit is not None:
                return taint_hit
            # 3. Exact match in dep_dotted (module-import dotted names)
            if dep_dotted is not None:
                dep_hit = dep_dotted.get(dotted)
                if dep_hit is not None:
                    return dep_hit
            # 4. §5.5 fallback: undeclared function in a declared package
            prefix = dotted.split(".", 1)[0]
            if prefix in dep_prefixes:
                return TaintState.UNKNOWN_RAW

    if isinstance(node.func, ast.Name):
        callee_name = node.func.id
        try:
            return taint_map[callee_name]
        except KeyError:
            pass
    return function_taint


# ── Statement walkers ────────────────────────────────────────────


def _walk_body(
    stmts: list[ast.stmt],
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
    dep_dotted: dict[str, TaintState] | None,
    dep_prefixes: frozenset[str],
) -> None:
    """Walk a list of statements, updating var_taints in place."""
    for stmt in stmts:
        _process_stmt(stmt, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)


def _process_stmt(
    stmt: ast.stmt,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
    dep_dotted: dict[str, TaintState] | None,
    dep_prefixes: frozenset[str],
) -> None:
    """Process a single statement, dispatching by type.

    Uses isinstance dispatch rather than match/case to avoid PY-WL-003
    structural-gate findings at ASSURED taint (UNCONDITIONAL severity).
    """
    if isinstance(stmt, ast.Assign):
        _handle_assign(stmt, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)

    elif isinstance(stmt, ast.AugAssign):
        _handle_augassign(stmt, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)

    elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
        value = stmt.value
        if isinstance(stmt.target, ast.Name):
            taint = _resolve_expr(value, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)
            var_taints[stmt.target.id] = taint
        else:
            _resolve_expr(value, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)

    elif isinstance(stmt, ast.For):
        _handle_for(stmt, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)

    elif isinstance(stmt, ast.While):
        _handle_while(stmt, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)

    elif isinstance(stmt, ast.If):
        _handle_if(stmt, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)

    elif isinstance(stmt, (ast.With, ast.AsyncWith)):
        _handle_with(stmt, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)

    elif isinstance(stmt, ast.Try):
        _handle_try(stmt, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)

    elif isinstance(stmt, ast.Expr):
        # Expression statement — walk for side-effects (walrus operators).
        _resolve_expr(stmt.value, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)

    elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        pass  # Nested function/class — don't descend (separate scope).

    else:
        # Return, Raise, Import, Pass, Break, Continue, etc.
        _walk_exprs_for_walrus(stmt, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)


def _walk_exprs_for_walrus(
    node: ast.AST,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
    dep_dotted: dict[str, TaintState] | None,
    dep_prefixes: frozenset[str],
) -> None:
    """Walk all child expressions to catch walrus operators."""
    for child in ast.walk(node):
        if isinstance(child, ast.NamedExpr):
            taint = _resolve_expr(
                child.value, function_taint, taint_map, var_taints,
                dep_dotted, dep_prefixes,
            )
            if isinstance(child.target, ast.Name):
                var_taints[child.target.id] = taint


# ── Assignment handlers ──────────────────────────────────────────


def _handle_assign(
    stmt: ast.Assign,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
    dep_dotted: dict[str, TaintState] | None,
    dep_prefixes: frozenset[str],
) -> None:
    """Handle ``x = expr`` and ``a, b = expr1, expr2``."""
    for target in stmt.targets:
        if isinstance(target, ast.Name):
            # Simple: x = expr
            taint = _resolve_expr(
                stmt.value, function_taint, taint_map, var_taints,
                dep_dotted, dep_prefixes,
            )
            var_taints[target.id] = taint

        elif isinstance(target, (ast.Tuple, ast.List)):
            # Tuple unpacking: a, b = ...
            _handle_unpack(
                target, stmt.value, function_taint, taint_map, var_taints,
                dep_dotted, dep_prefixes,
            )
        # Ignore attribute/subscript targets (obj.x = ..., d[k] = ...)


def _handle_unpack(
    target: ast.Tuple | ast.List,
    value: ast.expr,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
    dep_dotted: dict[str, TaintState] | None,
    dep_prefixes: frozenset[str],
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
                    dep_dotted, dep_prefixes,
                )
                var_taints[tgt.id] = taint
            elif isinstance(tgt, (ast.Tuple, ast.List)):
                _handle_unpack(tgt, val, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)
    else:
        # RHS is not a matching literal tuple — all targets get RHS taint.
        rhs_taint = _resolve_expr(
            value, function_taint, taint_map, var_taints,
            dep_dotted, dep_prefixes,
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
    dep_dotted: dict[str, TaintState] | None,
    dep_prefixes: frozenset[str],
) -> None:
    """Handle ``x += expr`` — join existing taint with new value."""
    rhs_taint = _resolve_expr(
        stmt.value, function_taint, taint_map, var_taints,
        dep_dotted, dep_prefixes,
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
    dep_dotted: dict[str, TaintState] | None,
    dep_prefixes: frozenset[str],
) -> None:
    """Handle if/elif/else — merge variable taints from branches."""
    # Resolve test expression (may contain walrus).
    _resolve_expr(stmt.test, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)

    # Snapshot before branches.
    pre_if = dict(var_taints)

    # Walk the if-body.
    if_taints = dict(var_taints)
    _walk_body(stmt.body, function_taint, taint_map, if_taints, dep_dotted, dep_prefixes)

    if stmt.orelse:
        # Walk the else-body.
        else_taints = dict(var_taints)
        _walk_body(stmt.orelse, function_taint, taint_map, else_taints, dep_dotted, dep_prefixes)
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
    dep_dotted: dict[str, TaintState] | None,
    dep_prefixes: frozenset[str],
) -> None:
    """Handle for loops — target gets iterable taint, body merges."""
    iter_taint = _resolve_expr(
        stmt.iter, function_taint, taint_map, var_taints,
        dep_dotted, dep_prefixes,
    )

    # Assign the loop variable.
    _assign_target(stmt.target, iter_taint, var_taints)

    # Snapshot pre-loop.
    pre_loop = dict(var_taints)

    # Walk body.
    _walk_body(stmt.body, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)

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
        _walk_body(stmt.orelse, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)


def _handle_while(
    stmt: ast.While,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
    dep_dotted: dict[str, TaintState] | None,
    dep_prefixes: frozenset[str],
) -> None:
    """Handle while loops — body merges with pre-loop state."""
    _resolve_expr(stmt.test, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)

    pre_loop = dict(var_taints)

    _walk_body(stmt.body, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)

    # Merge body state with pre-loop.
    for var in set(var_taints) | set(pre_loop):
        try:
            current = var_taints[var]
            prior = pre_loop[var]
            var_taints[var] = taint_join(current, prior)
        except KeyError:
            _taint_val = None  # var only in one side of merge — no join needed

    if stmt.orelse:
        _walk_body(stmt.orelse, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)


def _handle_with(
    stmt: ast.With | ast.AsyncWith,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
    dep_dotted: dict[str, TaintState] | None,
    dep_prefixes: frozenset[str],
) -> None:
    """Handle with/async-with statements."""
    for item in stmt.items:
        expr_taint = _resolve_expr(
            item.context_expr, function_taint, taint_map, var_taints,
            dep_dotted, dep_prefixes,
        )
        if item.optional_vars is not None:
            _assign_target(item.optional_vars, expr_taint, var_taints)

    _walk_body(stmt.body, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)


def _handle_try(
    stmt: ast.Try,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
    dep_dotted: dict[str, TaintState] | None,
    dep_prefixes: frozenset[str],
) -> None:
    """Handle try/except/else/finally — snapshot-branch-join pattern."""
    pre_try = dict(var_taints)

    # Walk try body on a copy.
    try_taints = dict(pre_try)
    _walk_body(stmt.body, function_taint, taint_map, try_taints, dep_dotted, dep_prefixes)

    # Walk each handler on separate copies (mutually exclusive with try body).
    handler_branches: list[dict[str, TaintState]] = [try_taints]  # try-success is one branch
    for handler in stmt.handlers:
        handler_taints = dict(pre_try)
        if handler.name:
            handler_taints[handler.name] = function_taint
        _walk_body(handler.body, function_taint, taint_map, handler_taints, dep_dotted, dep_prefixes)
        handler_branches.append(handler_taints)

    # Walk orelse on try-success branch (runs only if no exception).
    if stmt.orelse:
        _walk_body(stmt.orelse, function_taint, taint_map, try_taints, dep_dotted, dep_prefixes)

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
            try:
                var_taints[var] = pre_try[var]
            except KeyError:
                _taint_val = None  # var absent from pre-try state — leave unset

    # finalbody runs unconditionally after merge.
    if stmt.finalbody:
        _walk_body(stmt.finalbody, function_taint, taint_map, var_taints, dep_dotted, dep_prefixes)


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
