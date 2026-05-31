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

# Curated taint-PROPAGATING builtins. A small explicit table (NOT a general rule
# — unknown calls still fall back to function_taint, so len/int/validate stay
# unaffected and there is no false-positive explosion). These return the join of
# their argument taints: a string conversion / iterator advance carries whatever
# taint went in. ``next`` closes the ``next(genexp)`` shape (the iterator arg).
_PROPAGATING_BUILTINS: frozenset[str] = frozenset(
    {"str", "repr", "ascii", "bytes", "bytearray", "format", "next"}
)

# Curated taint-PROPAGATING methods, keyed by attribute name. ``.format``/``.join``
# combine the receiver with the arguments (``"sep".join(parts)`` carries both);
# ``.get``/``.pop``/``.setdefault`` carry the RECEIVER's taint — a container access
# is the same shape as the ``Subscript`` read handler (``d['k']`` propagating while
# ``d.get('k')`` did not was an inconsistency, not a feature). These do NOT add a
# new SOURCE: ``.get`` returns the container's existing taint, nothing more.
_PROPAGATING_METHODS_WITH_ARGS: frozenset[str] = frozenset({"format", "join"})
_PROPAGATING_METHODS_RECEIVER: frozenset[str] = frozenset({"get", "pop", "setdefault"})


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
    if isinstance(node, ast.Subscript):
        # Resolve the slice for walrus side-effects (discarded); the subscript
        # result carries its container's taint.
        _resolve_expr(node.slice, function_taint, taint_map, var_taints)
        return _resolve_expr(node.value, function_taint, taint_map, var_taints)
    if isinstance(node, ast.Attribute):
        # Attribute access carries the object's taint (the value path; the
        # call-receiver path is handled in _resolve_call via _dotted_name).
        return _resolve_expr(node.value, function_taint, taint_map, var_taints)
    if isinstance(node, ast.Await):
        # Unwrap — the inner expression (typically a Call) is already handled.
        return _resolve_expr(node.value, function_taint, taint_map, var_taints)
    if isinstance(node, ast.BoolOp):
        result = _resolve_expr(node.values[0], function_taint, taint_map, var_taints)
        for value in node.values[1:]:
            result = taint_join(
                result, _resolve_expr(value, function_taint, taint_map, var_taints)
            )
        return result
    if isinstance(node, ast.JoinedStr):
        return _resolve_joined_str(node, function_taint, taint_map, var_taints)
    if isinstance(node, ast.FormattedValue):
        # A standalone interpolation field — resolve its value expression.
        return _resolve_expr(node.value, function_taint, taint_map, var_taints)
    if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
        return _resolve_comprehension(node, function_taint, taint_map, var_taints)
    # Fallback: unmodelled Call shapes (str()/format()/.get()), lambdas, etc.
    return function_taint


def _resolve_joined_str(
    node: ast.JoinedStr,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> TaintState:
    """Combine the taint of every part of an f-string. Empty → INTEGRAL.

    Literal segments are ``ast.Constant`` (INTEGRAL); interpolations are
    ``ast.FormattedValue`` whose ``.value`` is the embedded expression.

    Combines via the rank-meet :func:`least_trusted` (weakest-link), NOT
    :func:`taint_join`: f-string building is a value flow, and a benign INTEGRAL
    literal must not manufacture a MIXED_RAW provenance clash with validated data
    (``least_trusted(INTEGRAL, ASSURED) = ASSURED``, clean — whereas
    ``taint_join`` would yield MIXED_RAW, a false positive). Raw data still
    propagates: ``least_trusted(INTEGRAL, UNKNOWN_RAW) = UNKNOWN_RAW``.
    """
    parts: list[TaintState] = []
    for part in node.values:
        if isinstance(part, ast.FormattedValue):
            parts.append(_resolve_expr(part.value, function_taint, taint_map, var_taints))
        else:
            parts.append(_resolve_expr(part, function_taint, taint_map, var_taints))
    if not parts:
        return TaintState.INTEGRAL
    result = parts[0]
    for p in parts[1:]:
        result = least_trusted(result, p)
    return result


def _resolve_comprehension(
    node: ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> TaintState:
    """Resolve a comprehension's element taint, mirroring :func:`_handle_for`.

    Binds each generator's target to its iterable taint in a LOCAL scope copy
    (so loop-internal names don't leak into ``var_taints``), then resolves the
    element in that scope. PEP 572: a walrus inside a comprehension binds the
    ENCLOSING scope, so NamedExpr captures resolved here are also written back
    into ``var_taints`` (the local copy is seeded from it and NamedExpr handling
    in ``_resolve_expr`` mutates the dict it walks — we pass ``var_taints`` for
    the iterable/if/element so the walrus leaks correctly while loop targets stay
    local).
    """
    # Local scope seeded from the enclosing scope. Loop targets bind here only
    # (they must not leak), but a later generator's iterable can reference an
    # earlier generator's target — so iterables/conditions resolve against
    # ``local``, not ``var_taints`` (resolving against the latter would launder a
    # chained ``[y for row in [raw] for y in row]`` because ``row`` would be
    # absent from ``var_taints`` and fall back to the trusted seed).
    local = dict(var_taints)
    for gen in node.generators:
        iter_t = _resolve_expr(gen.iter, function_taint, taint_map, local)
        _assign_target(gen.target, iter_t, local)
        for cond in gen.ifs:
            # Resolve conditions for walrus side-effects (PEP 572 → enclosing scope,
            # leaked back below).
            _resolve_expr(cond, function_taint, taint_map, local)
    if isinstance(node, ast.DictComp):
        key_t = _resolve_expr(node.key, function_taint, taint_map, local)
        val_t = _resolve_expr(node.value, function_taint, taint_map, local)
        result = taint_join(key_t, val_t)
    else:
        result = _resolve_expr(node.elt, function_taint, taint_map, local)
    # Walrus targets bound by the element (PEP 572) leak to the enclosing scope.
    for name, taint in local.items():
        if name not in var_taints and _name_bound_by_walrus(node, name):
            var_taints[name] = taint
    return result


def _name_bound_by_walrus(node: ast.AST, name: str) -> bool:
    """True if *name* is the target of a NamedExpr anywhere in *node* (not inside
    a nested Lambda — those bind the lambda's scope)."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.Lambda):
            continue
        if (
            isinstance(child, ast.NamedExpr)
            and isinstance(child.target, ast.Name)
            and child.target.id == name
        ):
            return True
        if _name_bound_by_walrus(child, name):
            return True
    return False


def _resolve_call(
    node: ast.Call,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> TaintState:
    # Resolve argument expressions. This binds any walrus side-effects — e.g.
    # ``foo(x := bar())`` must bind ``x`` even when the call's own taint comes
    # from ``node.func`` — AND captures the arg taints for the curated
    # taint-PROPAGATING ops below (str(raw), "{}".format(raw), etc.).
    arg_taints = [
        _resolve_expr(arg, function_taint, taint_map, var_taints) for arg in node.args
    ]
    arg_taints += [
        _resolve_expr(keyword.value, function_taint, taint_map, var_taints)
        for keyword in node.keywords
    ]
    if isinstance(node.func, ast.Attribute):
        dotted = _dotted_name(node.func)
        if dotted is not None:
            # Sink check and the mapped-method lookup stay AHEAD of the generic
            # propagating-method handling, so a serialisation sink or a resolved
            # ``self.method``/import alias still wins.
            if dotted in _SERIALISATION_SINKS:
                return TaintState.UNKNOWN_RAW
            taint_hit = taint_map.get(dotted)
            if taint_hit is not None:
                return taint_hit
        attr = node.func.attr
        if attr in _PROPAGATING_METHODS_WITH_ARGS:
            # ``.format``/``.join`` are string-BUILDING value flows: combine the
            # receiver with the args via the rank-meet least_trusted (weakest-link),
            # NOT taint_join. A benign INTEGRAL separator/template must not clash
            # validated data to MIXED_RAW (false positive); raw data still
            # propagates (least_trusted(INTEGRAL, UNKNOWN_RAW) = UNKNOWN_RAW).
            receiver = _resolve_expr(node.func.value, function_taint, taint_map, var_taints)
            result = receiver
            for at in arg_taints:
                result = least_trusted(result, at)
            return result
        if attr in _PROPAGATING_METHODS_RECEIVER:
            # ``.get``/``.pop``/``.setdefault`` carry the RECEIVER's taint, joined
            # with any DEFAULT value's taint — the default is a possible return
            # value, so a tainted default (``d.get('k', read_raw(p))``) must
            # propagate even from a trusted container (else fail-open). The first
            # positional arg is the LOOKUP KEY, not a return value, so it is
            # excluded; positional args from index 1 onward + keyword values are
            # the defaults. (Joining an existing taint, not adding a new source.)
            result = _resolve_expr(node.func.value, function_taint, taint_map, var_taints)
            # arg_taints = [positional...] + [keyword values...]. Skip the first
            # positional (the lookup key); join the rest (positional defaults +
            # keyword defaults like ``default=``). With no positional args there is
            # no key to skip, so every keyword value is a candidate default.
            skip = 1 if node.args else 0
            for default_taint in arg_taints[skip:]:
                result = taint_join(result, default_taint)
            return result
    if isinstance(node.func, ast.Name):
        try:
            return taint_map[node.func.id]
        except KeyError:
            pass
        if node.func.id in _PROPAGATING_BUILTINS:
            # Curated conversion/iterator builtins (str/repr/.../next): combine all
            # arg taints via the rank-meet least_trusted (these are value-building
            # flows, consistent with the f-string/.format/.join combiner). No args
            # → INTEGRAL (e.g. ``str()``).
            if not arg_taints:
                return TaintState.INTEGRAL
            result = arg_taints[0]
            for at in arg_taints[1:]:
                result = least_trusted(result, at)
            return result
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
        elif isinstance(stmt.target, (ast.Subscript, ast.Attribute)):
            # Annotated container/attribute write (``self.x: str = expr``,
            # ``d['k']: T = expr``) — same fail-open shape as the plain-Assign Part
            # B case: contaminate the base variable so a later read sees it.
            rhs = _resolve_expr(value, function_taint, taint_map, var_taints)
            _taint_container_base(stmt.target, rhs, function_taint, var_taints)
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

    elif isinstance(stmt, ast.Match):
        _handle_match(stmt, function_taint, taint_map, var_taints)

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

        elif isinstance(target, (ast.Subscript, ast.Attribute)):
            # Container/attribute write: d[k] = expr, obj.x = expr. Join the RHS
            # taint into the base variable's tracked taint, so a later READ of the
            # container (handled by the Subscript/Attribute branches of
            # _resolve_expr) sees the contamination. Without this the container is
            # read back at its creation taint — a fail-open under-taint.
            rhs = _resolve_expr(stmt.value, function_taint, taint_map, var_taints)
            _taint_container_base(target, rhs, function_taint, var_taints)


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
    elif isinstance(stmt.target, (ast.Subscript, ast.Attribute)):
        # d[k] += expr / obj.x += expr — contaminate the base container.
        _taint_container_base(stmt.target, rhs_taint, function_taint, var_taints)


def _container_base_name(target: ast.expr) -> str | None:
    """Walk a Subscript/Attribute target chain to its root ``ast.Name`` id.

    ``d[a][b]`` → ``"d"``; ``obj.x.y`` → ``"obj"``; ``self.cache[k]`` → ``"self"``.
    Returns None when the chain does not bottom out at a plain Name (e.g.
    ``foo()[k]``), in which case there is no tracked variable to contaminate.
    """
    cursor: ast.expr = target
    while isinstance(cursor, (ast.Subscript, ast.Attribute)):
        cursor = cursor.value
    return cursor.id if isinstance(cursor, ast.Name) else None


def _taint_container_base(
    target: ast.expr,
    rhs: TaintState,
    function_taint: TaintState,
    var_taints: dict[str, TaintState],
) -> None:
    """Join *rhs* into the tracked taint of the container-write target's root Name."""
    base = _container_base_name(target)
    if base is not None:
        var_taints[base] = taint_join(var_taints.get(base, function_taint), rhs)


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


def _handle_match(
    stmt: ast.Match,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> None:
    """Handle ``match``/``case`` — snapshot, walk each arm on a copy seeded with
    that arm's capture bindings, then join all arms with the no-match fall-through.

    Each capture-pattern target is bound to the *subject's* taint (a conservative
    whole-subject over-approximation — element-precise extraction is not modelled
    at L2; this never under-taints). The pre-match state is included as an extra
    branch to model the no-arm-matched path and variables assigned in only some
    arms; including it is taint-safe (``taint_join`` only moves toward less-trusted)
    and mirrors :func:`_handle_if`'s implicit-else treatment.
    """
    # Subject is evaluated once, before any arm — resolve it for walrus side
    # effects and to obtain the taint that capture targets inherit.
    subject_taint = _resolve_expr(stmt.subject, function_taint, taint_map, var_taints)

    pre_match = dict(var_taints)
    branches: list[dict[str, TaintState]] = []
    for case in stmt.cases:
        case_taints = dict(pre_match)
        for name in _collect_pattern_targets(case.pattern):
            case_taints[name] = subject_taint
        if case.guard is not None:
            # The guard is tested with the arm's captures in scope; resolve it for
            # walrus side effects (binds into this arm's state).
            _resolve_expr(case.guard, function_taint, taint_map, case_taints)
        _walk_body(case.body, function_taint, taint_map, case_taints)
        branches.append(case_taints)

    # The implicit "no arm matched" path keeps the pre-match state.
    branches.append(pre_match)

    all_vars: set[str] = set()
    for branch in branches:
        all_vars.update(branch)
    for var in all_vars:
        vals = [branch[var] for branch in branches if var in branch]
        merged = vals[0]
        for v in vals[1:]:
            merged = taint_join(merged, v)
        var_taints[var] = merged


# ── Helpers ──────────────────────────────────────────────────────


def _collect_pattern_targets(pattern: ast.pattern) -> set[str]:
    """Collect every name a ``match`` *pattern* binds (capture targets).

    Recurses through all binding-bearing pattern nodes. ``MatchValue`` /
    ``MatchSingleton`` bind nothing; ``MatchAs``/``MatchStar`` carry an optional
    ``name`` (``None`` for ``_`` / ``*_``); the rest nest sub-patterns. Python
    requires every ``MatchOr`` alternative to bind the same names, so the union is
    well-defined.
    """
    names: set[str] = set()
    if isinstance(pattern, ast.MatchAs):
        if pattern.name is not None:
            names.add(pattern.name)
        if pattern.pattern is not None:
            names |= _collect_pattern_targets(pattern.pattern)
    elif isinstance(pattern, ast.MatchStar):
        if pattern.name is not None:
            names.add(pattern.name)
    elif isinstance(pattern, ast.MatchSequence):
        for sub in pattern.patterns:
            names |= _collect_pattern_targets(sub)
    elif isinstance(pattern, ast.MatchMapping):
        for sub in pattern.patterns:
            names |= _collect_pattern_targets(sub)
        if pattern.rest is not None:
            names.add(pattern.rest)
    elif isinstance(pattern, ast.MatchClass):
        for sub in (*pattern.patterns, *pattern.kwd_patterns):
            names |= _collect_pattern_targets(sub)
    elif isinstance(pattern, ast.MatchOr):
        for sub in pattern.patterns:
            names |= _collect_pattern_targets(sub)
    # MatchValue / MatchSingleton: no bindings.
    return names


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
    returns: list[tuple[TaintState, str | None]] = []
    _collect_return_paths(
        list(func_node.body), function_taint, taint_map, var_taints, returns
    )
    if not returns:
        return None
    result = returns[0][0]
    for taint, _callee in returns[1:]:
        result = least_trusted(result, taint)
    return result


def compute_return_callee(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> str | None:
    """Identify the callee that contributes a function's *actual* (least-trusted)
    return taint — the property ``explain_finding`` reports for a PY-WL-101 sink.

    Walks the same value-bearing ``return`` statements :func:`compute_return_taint`
    walks (via the shared :func:`_collect_return_paths`), recording for each path
    both its taint AND, when its top-level expression is a direct :class:`ast.Call`,
    the callee NAME (simple ``ast.Name.id`` or dotted via :func:`_dotted_name`).

    Computes the same least-trusted taint :func:`compute_return_taint` returns, then
    returns the callee name of the **first source-order return path whose taint
    equals that worst taint and which is a direct call**. Returns ``None`` when no
    least-trusted path is a direct call (e.g. ``return p`` / ``return some_var`` —
    indirection deferred to SP9), or when there is no value-bearing return.

    Because :func:`least_trusted` always returns one of its inputs, the worst taint
    always equals at least one collected path's taint, so the match is well-defined.
    """
    returns: list[tuple[TaintState, str | None]] = []
    _collect_return_paths(
        list(func_node.body), function_taint, taint_map, var_taints, returns
    )
    if not returns:
        return None
    worst = returns[0][0]
    for taint, _callee in returns[1:]:
        worst = least_trusted(worst, taint)
    for taint, callee in returns:
        if taint == worst and callee is not None:
            return callee
    return None


def _return_callee(node: ast.expr) -> str | None:
    """Callee name if *node* is a direct call to a simple/dotted name, else None."""
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return _dotted_name(node.func)
    return None


def _collect_return_paths(
    nodes: list[ast.AST],
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
    out: list[tuple[TaintState, str | None]],
) -> None:
    """Recurse the AST collecting ``(taint, callee_or_None)`` for each value-bearing
    return, descending into ALL children EXCEPT nested ``FunctionDef``/
    ``AsyncFunctionDef``/``ClassDef``/``Lambda`` (separate scopes — their returns
    bind their own callable, not this one). The callee is the direct-call name of
    the return's top-level expression (``None`` for non-call returns).

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
            taint = _resolve_expr(node.value, function_taint, taint_map, var_taints)
            out.append((taint, _return_callee(node.value)))
        _collect_return_paths(
            list(ast.iter_child_nodes(node)), function_taint, taint_map, var_taints, out
        )
