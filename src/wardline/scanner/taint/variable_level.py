# src/wardline/scanner/taint/variable_level.py
"""Level 2 taint — per-variable taint tracking within a function body.

Given a function AST node and its Level 1 (function-level) taint, walks the body
tracking taint per variable through assignments, control-flow joins, and call
sites. Pure (returns a new dict); conservative (unknown expressions inherit the
function's L1 taint). Both expression/value combiners (BinOp, IfExp, BoolOp,
containers, ``.get`` defaults, ``+=``, container writes) AND control-flow MERGES
(if/else, loop back-edges, match arms, try/except handlers) use the rank-meet
``least_trusted`` (weakest-link): at a merge a variable holds the value of ONE
branch (an alternative), not a mixture, so ``taint_join``'s provenance-clash
``MIXED_RAW`` is the wrong label — ``least_trusted`` keeps any raw branch's rank
(sound: a raw branch still propagates and fires) without the spurious jump to
``MIXED_RAW`` (rank 7) on two clean-but-different-family branches.

Ported from ``wardline.old`` minus the manifest ``dependency_taint`` overlay
(SP1 §4.5): the ``dependency_dotted_map`` / ``dependency_local_prefixes`` params
and their two ``_resolve_call`` branches are removed. Call resolution is solely
against the caller-supplied ``taint_map`` (see ``compute_variable_taints``).
"""

from __future__ import annotations

import ast
import contextvars
from dataclasses import dataclass
from typing import TYPE_CHECKING

from wardline.core.taints import _PROVENANCE_CLASH, RAW_ZONE, TRUST_RANK, TaintState, combine

if TYPE_CHECKING:
    from collections.abc import Iterator

# Serialisation sinks — calls that cross the representation boundary. Their
# output sheds validation provenance (raw bytes/str), so → UNKNOWN_RAW. This is
# a generic fail-closed heuristic, not governance. (SP1f note: where this and
# stdlib_taint disagree — only json.load/loads — the conservative UNKNOWN_RAW
# wins.)
_SERIALISATION_SINKS: frozenset[str] = frozenset(
    {
        "json.dumps",
        "json.dump",
        "json.loads",
        "json.load",
        "pickle.dumps",
        "pickle.dump",
        "pickle.loads",
        "pickle.load",
        "yaml.dump",
        "yaml.safe_dump",
        "yaml.dump_all",
        "yaml.safe_load",
        "yaml.load",
        "yaml.safe_load_all",
        "yaml.load_all",
        "marshal.dumps",
        "marshal.dump",
        "marshal.loads",
        "marshal.load",
        "tomllib.loads",
        "tomllib.load",
        "tomli_w.dumps",
        "tomli_w.dump",
    }
)

# Curated taint-PROPAGATING builtins. A small explicit table (NOT a general rule
# — bare unknown calls still fall back to function_taint, so len/int/validate stay
# unaffected and there is no false-positive explosion). These return the join of
# their argument taints: a string conversion / iterator advance carries whatever
# taint went in. ``next`` closes the ``next(genexp)`` shape (the iterator arg).
_PROPAGATING_BUILTINS: frozenset[str] = frozenset({"str", "repr", "ascii", "bytes", "bytearray", "format", "next"})

# Curated taint-PROPAGATING methods, keyed by attribute name. ``.format``/``.join``
# combine the receiver with the arguments (``"sep".join(parts)`` carries both);
# ``.get``/``.pop``/``.setdefault`` carry the RECEIVER's taint — a container access
# is the same shape as the ``Subscript`` read handler (``d['k']`` propagating while
# ``d.get('k')`` did not was an inconsistency, not a feature). These do NOT add a
# new SOURCE: ``.get`` returns the container's existing taint, nothing more.
_PROPAGATING_METHODS_WITH_ARGS: frozenset[str] = frozenset({"format", "join"})
_PROPAGATING_METHODS_RECEIVER: frozenset[str] = frozenset({"get", "pop", "setdefault"})

# Curated DB-API storage-read methods. A ``cursor.fetchone/fetchall/fetchmany()`` loads
# stored/external data the same way ``open()``/``Path.read_text()`` do, so it seeds
# ``EXTERNAL_RAW`` — without this the PY-WL-120 fetch* matcher was a dead branch (the
# RAW_ZONE gate was unsatisfiable: the result was never seeded raw — wardline-e7c7cda31a).
# Scoped to the three DBAPI-specific names (near-zero collision); bare ``.read`` is
# deliberately NOT seeded (BytesIO/response/buffer ``.read()`` would over-fire, and the
# file case already fires via receiver propagation below).
# Residual FP (accepted, documented): a receiver whose type is NOT statically resolvable
# (a bare param, a chained ``.query(...).fetchall()``) and is NOT a DB cursor but has a
# coincidental fetch* method (SQLAlchemy Result, custom paginators) is seeded raw. A
# project-typed receiver is shadowed by the var_types/taint_map lookups above (they run
# first), so the common case is correct; the residual cuts toward soundness.
_STORAGE_READ_METHODS: frozenset[str] = frozenset({"fetchone", "fetchall", "fetchmany"})

# Curated in-place container MUTATORS. Calling one with a tainted argument contaminates
# the RECEIVER (``box.append(raw)`` makes ``box`` carry ``raw``'s taint), mirroring the
# container-literal ``box = [raw]`` which already taints ``box``. Without this, receiver
# mutation was unmodelled — the mutator form silently dropped the taint the literal form
# kept (wardline-67c7498931). A curated set (NOT a general "any attribute call mutates its
# receiver" rule, which would over-fire on ``.strip()``/``.lower()``/in-place validators).
_RECEIVER_MUTATING_METHODS: frozenset[str] = frozenset({"append", "add", "extend", "update", "insert"})

_CURRENT_ALIAS_MAP: contextvars.ContextVar[dict[str, str] | None] = contextvars.ContextVar(
    "_CURRENT_ALIAS_MAP", default=None
)

_CURRENT_CALL_SITE_ARG_TAINTS: contextvars.ContextVar[dict[int, dict[int | str | None, TaintState]] | None] = (
    contextvars.ContextVar("_CURRENT_CALL_SITE_ARG_TAINTS", default=None)
)

_CURRENT_VAR_TYPES: contextvars.ContextVar[dict[str, str] | None] = contextvars.ContextVar(
    "_CURRENT_VAR_TYPES", default=None
)

# Maps a local name to the CANDIDATE SET of lambda bodies it MAY hold. A single
# slot per name would lose a sink-lambda bound in a non-last branch arm when a later
# arm rebinds the same name (wardline-383f83fafe): only one survived the merge, so a
# post-branch ``cb(raw)`` resolved the wrong body and missed the sink. Within a linear
# scope a name holds exactly one lambda (a rebind REPLACES the list); the set grows
# only across mutually-exclusive branch arms at the merge, where the name MAY be any of
# them. Calls resolve against EVERY candidate (sound over-approximation: an extra body
# only records arg-taints, it never masks a sink). ``list`` not ``set`` — ast nodes are
# id-hashed, so set iteration is non-deterministic and would destabilise the golden corpora.
_CURRENT_LAMBDA_BINDINGS: contextvars.ContextVar[dict[str, list[ast.Lambda]] | None] = contextvars.ContextVar(
    "_CURRENT_LAMBDA_BINDINGS", default=None
)

_CURRENT_MODULE_PREFIX: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "_CURRENT_MODULE_PREFIX", default=None
)

_CONTEXT_ENCODERS: frozenset[str] = frozenset(
    {
        "html.escape",
        "shlex.quote",
        "urllib.parse.quote",
        "urllib.parse.quote_plus",
    }
)


@dataclass(frozen=True, slots=True)
class VariableTaintContext:
    """Explicit inputs that used to be threaded through analyzer-owned contextvars."""

    alias_map: dict[str, str]
    module_prefix: str | None = None
    param_meets: dict[str, TaintState] | None = None
    provenance_clash: bool | None = None


@dataclass(frozen=True, slots=True)
class VariableTaintResult:
    call_site_taints: dict[int, dict[str, TaintState]]
    call_site_arg_taints: dict[int, dict[int | str | None, TaintState]]
    variable_taints: dict[str, TaintState]
    return_taint: TaintState | None
    return_callee: str | None


def analyze_function_variables(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    context: VariableTaintContext,
) -> VariableTaintResult:
    """Run variable, call-site, and return taint analysis for one function."""
    call_site_taints: dict[int, dict[str, TaintState]] = {}
    call_site_arg_taints: dict[int, dict[int | str | None, TaintState]] = {}
    token_alias = _CURRENT_ALIAS_MAP.set(context.alias_map)
    token_args = _CURRENT_CALL_SITE_ARG_TAINTS.set(call_site_arg_taints)
    token_module = _CURRENT_MODULE_PREFIX.set(context.module_prefix)
    try:
        variable_taints = compute_variable_taints(
            func_node,
            function_taint,
            dict(taint_map),
            call_site_taints,
            alias_map=context.alias_map,
            call_site_arg_taints=call_site_arg_taints,
            param_meets=context.param_meets,
            provenance_clash=context.provenance_clash,
        )
        return_taint = compute_return_taint(func_node, function_taint, dict(taint_map), variable_taints)
        return_callee = compute_return_callee(func_node, function_taint, dict(taint_map), dict(variable_taints))
        return VariableTaintResult(
            call_site_taints=call_site_taints,
            call_site_arg_taints=call_site_arg_taints,
            variable_taints=variable_taints,
            return_taint=return_taint,
            return_callee=return_callee,
        )
    finally:
        _CURRENT_ALIAS_MAP.reset(token_alias)
        _CURRENT_CALL_SITE_ARG_TAINTS.reset(token_args)
        _CURRENT_MODULE_PREFIX.reset(token_module)


def _own_scope_lambdas(node: ast.AST) -> Iterator[ast.Lambda]:
    """Yield every ``ast.Lambda`` in *node*'s own scope (descends into lambdas, which
    are not separate entities, but NOT into nested ``def``/``class`` — those are
    analyzed as their own entities)."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(child, ast.Lambda):
            yield child
        yield from _own_scope_lambdas(child)


def _worst_ever_var_taints(
    call_site_taints: dict[int, dict[str, TaintState]],
    final_var_taints: dict[str, TaintState],
) -> dict[str, TaintState]:
    """The least-trusted (highest ``TRUST_RANK``) taint each variable holds ANYWHERE in
    the function — joined over every per-statement snapshot plus the final state.

    This is the sound capture taint for a closure free variable: a lambda defers
    execution to an unknown call time and captures the variable by reference, so it may
    observe ANY value the variable holds. Picking a single program point is unsound —
    the definition-site value misses a later raw assignment, and the final value misses
    a raw value that was cleaned up after the lambda already ran. The whole-function
    worst guarantees no false-negative (at the cost of a conservative over-approximation
    when a raw value existed only *before* the capture — the safe direction)."""
    worst = dict(final_var_taints)
    for snapshot in call_site_taints.values():
        for name, taint in snapshot.items():
            current = worst.get(name)
            if current is None or TRUST_RANK[taint] > TRUST_RANK[current]:
                worst[name] = taint
    return worst


def _resolve_lambda_bodies(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    worst_var_taints: dict[str, TaintState],
) -> None:
    """Record call-site arg taints for calls inside lambda BODIES (sink-rule input).

    Runs AFTER the forward walk, against ``worst_var_taints`` — the worst (least-trusted)
    taint each variable holds anywhere in the function (see :func:`_worst_ever_var_taints`).
    A lambda defers execution and captures free variables by reference, so the body's
    free variables must be resolved against the worst value they could carry at call
    time, not any single program-point snapshot — that is what keeps both a variable
    tainted *after* the lambda is defined and a variable still raw *when the lambda is
    called* (cleaned only later) visible to the sink rules.

    Each lambda body is resolved in an isolated scope copy so lambda-local bindings
    (params, walrus) never leak; the lambda's own parameters are reset to the neutral
    seed (``function_taint``) so they SHADOW enclosing names of the same id rather than
    inheriting their taint. The recording itself happens via the
    ``_CURRENT_CALL_SITE_ARG_TAINTS`` contextvar set by the caller, keyed by ``id(call)``
    (matching what the sink rules look up)."""
    for lam in _own_scope_lambdas(func_node):
        scope = dict(worst_var_taints)
        args = lam.args
        for param in (*args.posonlyargs, *args.args, *args.kwonlyargs):
            scope[param.arg] = function_taint
        if args.vararg is not None:
            scope[args.vararg.arg] = function_taint
        if args.kwarg is not None:
            scope[args.kwarg.arg] = function_taint
        _resolve_expr(lam.body, function_taint, taint_map, scope)


def _resolve_lambda_body_at_call(
    lam: ast.Lambda,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
    pos_taints: list[TaintState],
    kw_taints: dict[str | None, TaintState],
) -> None:
    """Record a bound lambda body's call-site arg taints at a direct call site.

    The final lambda-body pass is deliberately conservative for escaping/deferred
    lambdas, but direct ``cb()`` calls have stronger ordering information: the
    lambda executes with the current enclosing variable taints at this statement.
    Recording the body here prevents a later clean assignment from laundering a
    raw value that was captured when the direct call actually ran.
    """
    scope = dict(var_taints)
    args = lam.args
    positional_params = [*args.posonlyargs, *args.args]
    for param, taint in zip(positional_params, pos_taints, strict=False):
        scope[param.arg] = taint
    for param in positional_params[len(pos_taints) :]:
        scope[param.arg] = function_taint
    if args.vararg is not None:
        extra = pos_taints[len(positional_params) :]
        scope[args.vararg.arg] = extra[0] if extra else function_taint
        for taint in extra[1:]:
            scope[args.vararg.arg] = combine(scope[args.vararg.arg], taint)
    for param in args.kwonlyargs:
        scope[param.arg] = kw_taints.get(param.arg, function_taint)
    for param in positional_params:
        if param.arg in kw_taints:
            scope[param.arg] = combine(scope.get(param.arg, function_taint), kw_taints[param.arg])
    if args.kwarg is not None:
        keyword_values = [taint for name, taint in kw_taints.items() if name is not None]
        scope[args.kwarg.arg] = keyword_values[0] if keyword_values else function_taint
        for taint in keyword_values[1:]:
            scope[args.kwarg.arg] = combine(scope[args.kwarg.arg], taint)
    _resolve_expr(lam.body, function_taint, taint_map, scope)


def compute_variable_taints(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    call_site_taints: dict[int, dict[str, TaintState]] | None = None,
    alias_map: dict[str, str] | None = None,
    call_site_arg_taints: dict[int, dict[int | str | None, TaintState]] | None = None,
    param_meets: dict[str, TaintState] | None = None,
    *,
    provenance_clash: bool | None = None,
) -> dict[str, TaintState]:
    """Compute per-variable taint for a function body.

    Args:
        func_node: the function AST node to analyze.
        function_taint: this function's L1 taint; seeds parameters and is the
            fallback for unknown expressions.
        taint_map: call-resolution map keyed by the call-site name AS WRITTEN —
            bare (``"foo"``) for ``foo()``, dotted (``"mod.fn"``) for
            ``mod.fn()`` — mapping to that call's return taint. Bare calls whose
            name is absent fall back to ``function_taint``; imported-but-unmodeled
            calls resolve to ``UNKNOWN_RAW`` so external code cannot inherit a
            trusted caller seed.
        call_site_taints: optional out-dict for FLOW-SENSITIVE reads. When given,
            records ``{id(stmt): snapshot}`` — the per-variable taint map AS IT IS
            on entry to each statement (in branches, the branch-local copy). A sink
            rule reads the snapshot of a sink call's enclosing statement to get the
            taint of its args AT the sink line, not the final (flow-insensitive)
            map — closing the documented reassignment over-/under-fire. Threaded
            only through the statement layer; the expression combiners are untouched.
        alias_map: optional alias map for imports.
        call_site_arg_taints: optional out-dict to record resolved argument taints.
        param_meets: optional parameter meets mapping param_name -> TaintState to
            seed parameters with instead of function_taint.
        provenance_clash: set True to use provenance-clash semantics.

    Returns:
        ``{variable_name: TaintState}`` for every assigned variable and parameter
        in the function body. Nested function/class scopes are not descended.
    """
    token = None
    token_args = None
    token_clash = None
    if provenance_clash is not None:
        token_clash = _PROVENANCE_CLASH.set(provenance_clash)
    token_types = _CURRENT_VAR_TYPES.set({})
    token_lambdas = _CURRENT_LAMBDA_BINDINGS.set({})
    if alias_map is not None:
        token = _CURRENT_ALIAS_MAP.set(alias_map)
    if call_site_arg_taints is not None:
        token_args = _CURRENT_CALL_SITE_ARG_TAINTS.set(call_site_arg_taints)
    try:
        var_taints: dict[str, TaintState] = {}
        _seed_parameters(func_node, function_taint, var_taints, param_meets, taint_map)
        _walk_body(func_node.body, function_taint, taint_map, var_taints, call_site_taints)
        # Second pass: resolve lambda BODIES against the worst taint each variable holds
        # anywhere in the function, so a deferred lambda that captures a variable tainted
        # at ANY point — before OR after its definition, or still raw when it is called
        # and cleaned only afterwards — stays visible to the sink rules
        # (closure-by-reference soundness; see _worst_ever_var_taints). Requires the
        # per-statement snapshots; without them (a degraded caller that does not request
        # flow-sensitive recording) the bodies are left unrecorded so the sink rules fall
        # back to their pessimistic UNKNOWN_RAW default rather than to a possibly-clean
        # final value — never silently masking a sink.
        if call_site_taints is not None:
            worst = _worst_ever_var_taints(call_site_taints, var_taints)
            _resolve_lambda_bodies(func_node, function_taint, taint_map, worst)
        return var_taints
    finally:
        if token_clash is not None:
            _PROVENANCE_CLASH.reset(token_clash)
        _CURRENT_VAR_TYPES.reset(token_types)
        _CURRENT_LAMBDA_BINDINGS.reset(token_lambdas)
        if token is not None:
            _CURRENT_ALIAS_MAP.reset(token)
        if token_args is not None:
            _CURRENT_CALL_SITE_ARG_TAINTS.reset(token_args)


def _seed_parameters(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    function_taint: TaintState,
    var_taints: dict[str, TaintState],
    param_meets: dict[str, TaintState] | None = None,
    taint_map: dict[str, TaintState] | None = None,
) -> None:
    args = func_node.args
    var_types = _CURRENT_VAR_TYPES.get()
    alias_map = _CURRENT_ALIAS_MAP.get()

    default_taints: dict[str, TaintState] = {}

    # Map positional parameter defaults
    defaults = args.defaults
    total_pos_args = len(args.posonlyargs) + len(args.args)
    num_defaults = len(defaults)
    all_pos_params = args.posonlyargs + args.args
    for i, default_expr in enumerate(defaults):
        param_idx = total_pos_args - num_defaults + i
        if 0 <= param_idx < len(all_pos_params):
            param_name = all_pos_params[param_idx].arg
            default_taints[param_name] = _resolve_expr(default_expr, function_taint, taint_map or {}, {})

    # Map keyword-only parameter defaults
    for param, kw_default_expr in zip(args.kwonlyargs, args.kw_defaults, strict=True):
        if kw_default_expr is not None:
            default_taints[param.arg] = _resolve_expr(kw_default_expr, function_taint, taint_map or {}, {})

    def handle_arg(arg: ast.arg) -> None:
        fallback = default_taints.get(arg.arg, function_taint)
        seed_val = fallback
        if param_meets is not None and arg.arg in param_meets:
            seed_val = combine(seed_val, param_meets[arg.arg])
        var_taints[arg.arg] = seed_val

        if arg.annotation and var_types is not None:
            fqn = _resolve_expr_fqn(arg.annotation, alias_map)
            if fqn:
                var_types[arg.arg] = fqn

    for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs):
        handle_arg(arg)
    if args.vararg:
        handle_arg(args.vararg)
    if args.kwarg:
        handle_arg(args.kwarg)


def _dotted_name(node: ast.expr) -> str | None:
    """Extract a dotted name from an attribute chain (``json.dumps`` → that str)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else None
    return None


def _call_root_name(func: ast.expr) -> str | None:
    """Root receiver/callee name of a call's ``func``: for an attribute call
    ``X.Y.method()`` the chain root ``X``; for a bare call ``foo()`` the name
    ``foo``. ``None`` when the root is not a plain Name (e.g. a subscript or call
    receiver). Used to detect a raw local/parameter shadowing a module/import name
    (wardline-f6a29ce23a)."""
    cur = func
    while isinstance(cur, ast.Attribute):
        cur = cur.value
    return cur.id if isinstance(cur, ast.Name) else None


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
        # Concatenation/arithmetic is a value-BUILDING flow — combine via the
        # rank-meet least_trusted (weakest-link), NOT taint_join: a benign INTEGRAL
        # literal must not manufacture a MIXED_RAW provenance clash with validated
        # data (``least_trusted(INTEGRAL, ASSURED) = ASSURED``, clean). Raw still
        # propagates (``least_trusted(INTEGRAL, UNKNOWN_RAW) = UNKNOWN_RAW``).
        # Consistent with the f-string/.format/.join combiners.
        left = _resolve_expr(node.left, function_taint, taint_map, var_taints)
        right = _resolve_expr(node.right, function_taint, taint_map, var_taints)
        return combine(left, right)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        # Container summary = weakest-link of its elements (least_trusted), so a
        # clean literal element does not clash validated data to MIXED_RAW.
        if not node.elts:
            return TaintState.INTEGRAL
        result = _resolve_expr(node.elts[0], function_taint, taint_map, var_taints)
        for elt in node.elts[1:]:
            result = combine(result, _resolve_expr(elt, function_taint, taint_map, var_taints))
        return result
    if isinstance(node, ast.Dict):
        # Container summary = weakest-link of its values (least_trusted).
        parts = [_resolve_expr(v, function_taint, taint_map, var_taints) for v in node.values if v is not None]
        if not parts:
            return TaintState.INTEGRAL
        result = parts[0]
        for p in parts[1:]:
            result = combine(result, p)
        return result
    if isinstance(node, ast.NamedExpr):
        taint = _resolve_expr(node.value, function_taint, taint_map, var_taints)
        # A NamedExpr (walrus) target is always an ast.Name by the Python grammar
        # (``(x := ...)``), so the False branch is unreachable by any parseable source.
        if isinstance(node.target, ast.Name):  # pragma: no branch
            var_taints[node.target.id] = taint
        return taint
    if isinstance(node, ast.IfExp):
        # ``a if c else b`` evaluates to ONE of its arms — combine via the rank-meet
        # least_trusted (weakest-link), so two clean arms stay clean (no MIXED_RAW
        # clash) while a raw arm still propagates.
        true_t = _resolve_expr(node.body, function_taint, taint_map, var_taints)
        false_t = _resolve_expr(node.orelse, function_taint, taint_map, var_taints)
        return combine(true_t, false_t)
    if isinstance(node, ast.Starred):
        return _resolve_expr(node.value, function_taint, taint_map, var_taints)
    if isinstance(node, ast.UnaryOp):
        return _resolve_expr(node.operand, function_taint, taint_map, var_taints)
    if isinstance(node, ast.Subscript):
        # Resolve the slice for walrus side-effects (discarded); the subscript
        # result carries its container's taint.
        _resolve_expr(node.slice, function_taint, taint_map, var_taints)
        return _resolve_expr(node.value, function_taint, taint_map, var_taints)
    if isinstance(node, ast.Attribute):
        # A ``self.<attr>``/``cls.<attr>`` read whose attribute has a project-computed
        # cross-method summary (injected by the analyzer under that dotted key) reads
        # the summary — closing the function-level fail-open where raw written to an
        # attribute in one method escaped when surfaced from another (PY-WL-101/105 on
        # OO code). Any other attribute access carries the object's own taint (the
        # value path; the call-receiver path is handled in _resolve_call).
        dotted = _dotted_name(node)
        if dotted is not None and dotted in taint_map:
            return taint_map[dotted]
        return _resolve_expr(node.value, function_taint, taint_map, var_taints)
    if isinstance(node, ast.Await):
        # Unwrap — the inner expression (typically a Call) is already handled.
        return _resolve_expr(node.value, function_taint, taint_map, var_taints)
    if isinstance(node, ast.BoolOp):
        # ``a and b`` / ``a or b`` short-circuits to ONE of its values — combine via
        # the rank-meet least_trusted (weakest-link), like IfExp: clean values stay
        # clean, a raw value still propagates.
        result = _resolve_expr(node.values[0], function_taint, taint_map, var_taints)
        for value in node.values[1:]:
            result = combine(result, _resolve_expr(value, function_taint, taint_map, var_taints))
        return result
    if isinstance(node, ast.JoinedStr):
        return _resolve_joined_str(node, function_taint, taint_map, var_taints)
    if isinstance(node, ast.FormattedValue):
        # A standalone interpolation field — resolve its value expression.
        return _resolve_expr(node.value, function_taint, taint_map, var_taints)
    if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
        return _resolve_comprehension(node, function_taint, taint_map, var_taints)
    if isinstance(node, ast.Lambda):
        # Defaults evaluate in the ENCLOSING scope at definition time — resolve them
        # against var_taints (and bind any walrus side-effects there). The lambda
        # BODY is resolved separately, AFTER the forward walk, against the final
        # var_taints (see _resolve_lambda_bodies): a lambda defers execution and
        # captures free variables by reference, so the sound taint for a free var
        # read in the body is its FINAL function-scope taint, not its def-site value.
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                _resolve_expr(default, function_taint, taint_map, var_taints)
        return function_taint
    # Fallback: unmodelled Call shapes (str()/format()/.get()), etc.
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
        result = combine(result, p)
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
        # Container summary = weakest-link of key and value (least_trusted), so a
        # clean key does not clash a validated value to MIXED_RAW.
        key_t = _resolve_expr(node.key, function_taint, taint_map, local)
        val_t = _resolve_expr(node.value, function_taint, taint_map, local)
        result = combine(key_t, val_t)
    else:
        result = _resolve_expr(node.elt, function_taint, taint_map, local)
    # Walrus targets bound by the element (PEP 572) leak to the enclosing scope.
    for name, taint in local.items():
        if _name_bound_by_walrus(node, name):
            var_taints[name] = taint
    return result


def _name_bound_by_walrus(node: ast.AST, name: str) -> bool:
    """True if *name* is the target of a NamedExpr anywhere in *node* (not inside
    a nested Lambda — those bind the lambda's scope)."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.Lambda):
            continue
        if isinstance(child, ast.NamedExpr) and isinstance(child.target, ast.Name) and child.target.id == name:
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
    resolved_args: dict[int | str | None, TaintState] = {}
    pos_taints = []
    for i, arg in enumerate(node.args):
        t = _resolve_expr(arg, function_taint, taint_map, var_taints)
        pos_taints.append(t)
        resolved_args[i] = t
        if isinstance(arg, ast.Starred):
            resolved_args[f"*{i}"] = t
    kw_taints = []
    kw_arg_taints: dict[str | None, TaintState] = {}
    for kw in node.keywords:
        t = _resolve_expr(kw.value, function_taint, taint_map, var_taints)
        kw_taints.append(t)
        if kw.arg in kw_arg_taints:
            kw_arg_taints[kw.arg] = combine(kw_arg_taints[kw.arg], t)
        else:
            kw_arg_taints[kw.arg] = t
        if kw.arg in resolved_args:
            resolved_args[kw.arg] = combine(resolved_args[kw.arg], t)
        else:
            resolved_args[kw.arg] = t
    arg_taints = pos_taints + kw_taints

    call_site_arg_taints = _CURRENT_CALL_SITE_ARG_TAINTS.get()
    if call_site_arg_taints is not None:
        existing = call_site_arg_taints.get(id(node))
        if existing is None:
            call_site_arg_taints[id(node)] = resolved_args
        else:
            for key, taint in resolved_args.items():
                existing[key] = combine(existing[key], taint) if key in existing else taint

    lambda_bindings = _CURRENT_LAMBDA_BINDINGS.get()
    if isinstance(node.func, ast.Name) and lambda_bindings is not None and node.func.id in lambda_bindings:
        # Resolve against EVERY candidate body the name MAY hold (one per linear scope;
        # several only after a branch merge). Each records its own sink calls' arg-taints
        # — distinct AST nodes, so the recordings never collide (wardline-383f83fafe).
        for lam in lambda_bindings[node.func.id]:
            _resolve_lambda_body_at_call(
                lam,
                function_taint,
                taint_map,
                var_taints,
                pos_taints,
                kw_arg_taints,
            )
    elif isinstance(node.func, ast.Lambda):
        _resolve_lambda_body_at_call(
            node.func,
            function_taint,
            taint_map,
            var_taints,
            pos_taints,
            kw_arg_taints,
        )

    # A dotted/imported/bare ``taint_map`` entry always describes a MODULE-LEVEL
    # symbol (``mod.fn`` / from-imported func / config sanitiser / ``Type.method`` —
    # every key minted by ``build_call_taint_map`` is rooted in an import alias or a
    # top-level/bare callable, never a runtime object). When the call's RECEIVER or
    # CALLEE name is instead a tracked LOCAL or PARAMETER holding RAW data, that local
    # SHADOWS the module/import name: the clean entry does NOT describe the raw object,
    # so returning it would launder the raw taint (wardline-f6a29ce23a). The
    # discriminator is membership in ``var_taints`` (a real import is never tracked
    # there; an assigned local / parameter is) plus the RAW_ZONE check, which limits
    # suppression to the only unsound case — a genuine module sanitiser (root not in
    # ``var_taints``, or tracked-but-clean) is untouched. The chain ROOT is used so a
    # chained receiver (``a.b.method()``, root ``a``) is covered, not only one-level
    # ``a.method()``. ``self``/``cls`` are EXCLUDED: their dotted keys are
    # analyzer-injected cross-method summaries (analyzer.py), not module shadows, and
    # must still be read even when the method's ``self`` seed is raw. The early
    # ``taint_map`` short-circuits below defer to the RAW_ZONE receiver guard (and the
    # bare-call path returns the raw callee taint) when this is set.
    _call_root = _call_root_name(node.func)
    root_shadows_raw_local = (
        _call_root is not None and _call_root not in ("self", "cls") and var_taints.get(_call_root) in RAW_ZONE
    )

    alias_map = _CURRENT_ALIAS_MAP.get()
    imported_fqn: str | None = None
    if alias_map is not None:
        from wardline.scanner.ast_primitives import resolve_call_fqn

        module_prefix = _CURRENT_MODULE_PREFIX.get() or ""
        imported_fqn = resolve_call_fqn(node, alias_map, frozenset(taint_map.keys()), module_prefix)
        if imported_fqn in _CONTEXT_ENCODERS and not root_shadows_raw_local:
            if not arg_taints:
                return TaintState.GUARDED
            result = arg_taints[0]
            for at in arg_taints[1:]:
                result = combine(result, at)
            return combine(result, TaintState.GUARDED)
        if imported_fqn in _SERIALISATION_SINKS:
            return TaintState.UNKNOWN_RAW
        if imported_fqn in taint_map and not root_shadows_raw_local:
            return taint_map[imported_fqn]

    if isinstance(node.func, ast.Attribute):
        dotted = _dotted_name(node.func)
        if dotted is not None:
            # Sink check and the mapped-method lookup stay AHEAD of the generic
            # propagating-method handling, so a serialisation sink or a resolved
            # ``self.method``/import alias still wins.
            if dotted in _SERIALISATION_SINKS:
                return TaintState.UNKNOWN_RAW
            taint_hit = taint_map.get(dotted)
            if taint_hit is not None and not root_shadows_raw_local:
                # ``not root_shadows_raw_local``: a raw local/param shadowing the
                # module name must not inherit the module entry (see above).
                return taint_hit
        if isinstance(node.func.value, ast.Name):
            var_types = _CURRENT_VAR_TYPES.get()
            if var_types is not None and node.func.value.id in var_types:
                # This path is reached ONLY for a receiver with a TRACKED TYPE
                # (annotation or ``x = Type()`` constructor) — never a module shadow
                # (a raw ``cfg = read_raw(p)`` carries no tracked type). It is
                # deliberately NOT gated by ``root_shadows_raw_local``: a legitimately
                # typed object routinely has a RAW-ZONE value taint (an unmodeled
                # ``Type()`` constructor defaults to ``UNKNOWN_RAW``), and that object
                # must still resolve ``Type.method`` via its type — gating on the
                # value taint false-positives the ``h = Helper(); h.get_assured()``
                # pattern (test_helper_method_returning_assured_does_not_false_positive).
                # A config sanitiser CAN mint a ``Type.method`` key, so a raw-seeded
                # *typed parameter* could in principle launder here; that narrow
                # residual is accepted over the FP cost (wardline-f6a29ce23a).
                type_prefix = var_types[node.func.value.id]
                resolved_dotted = f"{type_prefix}.{node.func.attr}"
                taint_hit = taint_map.get(resolved_dotted)
                if taint_hit is not None:
                    return taint_hit
        attr = node.func.attr
        if attr in _STORAGE_READ_METHODS:
            # DB-cursor fetch loads stored/external data → seed EXTERNAL_RAW, like a file
            # read (wardline-e7c7cda31a). Placed AFTER the taint_map / var_types-resolved
            # lookups above so a project-summarised ``self.fetchall``/typed receiver still
            # wins; ahead of the generic propagating-method handling.
            return TaintState.EXTERNAL_RAW
        if attr in _RECEIVER_MUTATING_METHODS:
            # In-place container mutation: write the worst (least-trusted) CONTENT-argument
            # taint back onto the receiver variable, so a later read of the container sees
            # it (wardline-67c7498931). Do NOT return — a mutator evaluates to None and the
            # call's own value is discarded; let control fall through unchanged.
            # ``list.insert(index, value)`` is the one outlier whose FIRST positional arg is
            # an index (position metadata, not stored content), so a tainted index must not
            # contaminate the container — skip it (panel finding wardline-67c7498931).
            content_taints = (pos_taints[1:] if attr == "insert" else pos_taints) + kw_taints
            base = _container_base_name(node.func.value)
            if base is not None and content_taints:
                worst = content_taints[0]
                for at in content_taints[1:]:
                    worst = combine(worst, at)
                var_taints[base] = combine(var_taints.get(base, function_taint), worst)
        if attr in _PROPAGATING_METHODS_WITH_ARGS:
            # ``.format``/``.join`` are string-BUILDING value flows: combine the
            # receiver with the args via the rank-meet least_trusted (weakest-link),
            # NOT taint_join. A benign INTEGRAL separator/template must not clash
            # validated data to MIXED_RAW (false positive); raw data still
            # propagates (least_trusted(INTEGRAL, UNKNOWN_RAW) = UNKNOWN_RAW).
            receiver = _resolve_expr(node.func.value, function_taint, taint_map, var_taints)
            result = receiver
            for at in arg_taints:
                result = combine(result, at)
            return result
        if attr in _PROPAGATING_METHODS_RECEIVER:
            # ``.get``/``.pop``/``.setdefault`` evaluate to ONE of the receiver's
            # value or a DEFAULT — an either/or, so combine via the rank-meet
            # least_trusted (weakest-link), NOT taint_join. A tainted default
            # (``d.get('k', read_raw(p))``) still propagates even from a trusted
            # container (least_trusted keeps the raw rank — no fail-open), while a
            # validated default does not clash to MIXED_RAW. The first positional
            # arg is the LOOKUP KEY, not a return value, so it is excluded;
            # positional args from index 1 onward + keyword values are the defaults.
            result = _resolve_expr(node.func.value, function_taint, taint_map, var_taints)
            # arg_taints = [positional...] + [keyword values...]. Skip the first
            # positional (the lookup key); combine the rest (positional defaults +
            # keyword defaults like ``default=``). With no positional args there is
            # no key to skip, so every keyword value is a candidate default.
            skip = 1 if node.args else 0
            for default_taint in arg_taints[skip:]:
                result = combine(result, default_taint)
            return result
    if isinstance(node.func, ast.Name):
        if root_shadows_raw_local:
            # ``foo()`` where ``foo`` is a raw local/param shadowing a clean import:
            # calling raw data yields raw, never the import's clean ``taint_map``
            # entry (wardline-f6a29ce23a). ``var_taints`` holds ``foo`` (the root
            # check passed), so the lookup is safe.
            return var_taints[node.func.id]
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
                result = combine(result, at)
            return result
    if isinstance(node.func, ast.Attribute):
        receiver_taint = _resolve_expr(node.func.value, function_taint, taint_map, var_taints)
        if receiver_taint in RAW_ZONE:
            return receiver_taint
    if imported_fqn is not None:
        # An imported call that was not modeled by project summaries, stdlib_taint,
        # config, sink handling, or propagation rules returns data we cannot prove.
        return TaintState.UNKNOWN_RAW
    return function_taint


# ── Statement walkers ────────────────────────────────────────────


def _walk_body(
    stmts: list[ast.stmt],
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
    call_site_taints: dict[int, dict[str, TaintState]] | None = None,
) -> None:
    """Walk a list of statements, updating var_taints in place."""
    for stmt in stmts:
        _process_stmt(stmt, function_taint, taint_map, var_taints, call_site_taints)


def _process_stmt(
    stmt: ast.stmt,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
    call_site_taints: dict[int, dict[str, TaintState]] | None = None,
) -> None:
    """Process a single statement, dispatching by type.

    Uses isinstance dispatch rather than match/case to avoid PY-WL-003
    structural-gate findings at ASSURED taint (UNCONDITIONAL severity).
    """
    if call_site_taints is not None:
        # Flow-sensitive snapshot: var taints AS THEY ARE before this statement
        # executes (after all prior siblings; branch-local inside if/try/match arms).
        # A sink rule reads this for a sink call's enclosing statement.
        call_site_taints[id(stmt)] = dict(var_taints)

    if isinstance(stmt, ast.Assign):
        _handle_assign(stmt, function_taint, taint_map, var_taints)

    elif isinstance(stmt, ast.AugAssign):
        _handle_augassign(stmt, function_taint, taint_map, var_taints)

    elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
        value = stmt.value
        if isinstance(stmt.target, ast.Name):
            taint = _resolve_expr(value, function_taint, taint_map, var_taints)
            var_taints[stmt.target.id] = taint

            lambda_bindings = _CURRENT_LAMBDA_BINDINGS.get()
            if lambda_bindings is not None:
                if isinstance(value, ast.Lambda):
                    # Linear rebind REPLACES the candidate set (a fresh single-element
                    # list), never appends — only a branch merge unions arms.
                    lambda_bindings[stmt.target.id] = [value]
                else:
                    lambda_bindings.pop(stmt.target.id, None)
        elif isinstance(stmt.target, (ast.Subscript, ast.Attribute)):
            # Annotated container/attribute write (``self.x: str = expr``,
            # ``d['k']: T = expr``) — same fail-open shape as the plain-Assign Part
            # B case: contaminate the base variable so a later read sees it.
            rhs = _resolve_expr(value, function_taint, taint_map, var_taints)
            _taint_container_base(stmt.target, rhs, function_taint, var_taints)
        else:  # pragma: no cover
            # Unreachable: an AnnAssign target is always Name/Attribute/Subscript by
            # the Python grammar, so the two branches above are exhaustive. Kept as a
            # defensive fall-through (resolve for walrus side-effects).
            _resolve_expr(value, function_taint, taint_map, var_taints)

    elif isinstance(stmt, (ast.For, ast.AsyncFor)):
        _handle_for(stmt, function_taint, taint_map, var_taints, call_site_taints)

    elif isinstance(stmt, ast.While):
        _handle_while(stmt, function_taint, taint_map, var_taints, call_site_taints)

    elif isinstance(stmt, ast.If):
        _handle_if(stmt, function_taint, taint_map, var_taints, call_site_taints)

    elif isinstance(stmt, (ast.With, ast.AsyncWith)):
        _handle_with(stmt, function_taint, taint_map, var_taints, call_site_taints)

    elif isinstance(stmt, (ast.Try, ast.TryStar)):
        _handle_try(stmt, function_taint, taint_map, var_taints, call_site_taints)

    elif isinstance(stmt, ast.Match):
        _handle_match(stmt, function_taint, taint_map, var_taints, call_site_taints)

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
            # A walrus target is always an ast.Name by the Python grammar, so the
            # False branch is unreachable by any parseable source.
            if isinstance(child.target, ast.Name):  # pragma: no branch
                var_taints[child.target.id] = taint
        _walk_exprs_for_walrus(child, function_taint, taint_map, var_taints)


def _resolve_expr_fqn(node: ast.expr, alias_map: dict[str, str] | None) -> str | None:
    if isinstance(node, ast.Name):
        if alias_map and node.id in alias_map:
            return alias_map[node.id]
        module_prefix = _CURRENT_MODULE_PREFIX.get()
        if module_prefix:
            return f"{module_prefix}.{node.id}"
        return node.id
    if isinstance(node, ast.Attribute):
        base = _resolve_expr_fqn(node.value, alias_map)
        if base:
            return f"{base}.{node.attr}"
    return None


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
                stmt.value,
                function_taint,
                taint_map,
                var_taints,
            )
            var_taints[target.id] = taint

            lambda_bindings = _CURRENT_LAMBDA_BINDINGS.get()
            if lambda_bindings is not None:
                if isinstance(stmt.value, ast.Lambda):
                    # Linear rebind REPLACES the candidate set (see _resolve_call /
                    # _merge_branch_bindings); only a branch merge unions arms.
                    lambda_bindings[target.id] = [stmt.value]
                else:
                    lambda_bindings.pop(target.id, None)

            var_types = _CURRENT_VAR_TYPES.get()
            if var_types is not None:
                alias_map = _CURRENT_ALIAS_MAP.get()
                new_type: str | None = None
                if isinstance(stmt.value, ast.Call):
                    new_type = _resolve_expr_fqn(stmt.value.func, alias_map) or None
                elif isinstance(stmt.value, ast.Name):
                    new_type = var_types.get(stmt.value.id)
                if new_type is not None:
                    var_types[target.id] = new_type
                else:
                    # Reassignment to an RHS we cannot type precisely (Subscript / BinOp /
                    # IfExp / f-string / comprehension / unresolvable Call / typeless Name)
                    # INVALIDATES any prior recorded type. Keeping the stale type let a method
                    # call on a now-raw value resolve a clean @trusted summary, laundering raw
                    # past the RAW_ZONE receiver guard (wardline-5ba7ce0f98). Dropping it falls
                    # back to conservative resolution (more FPs at worst, never an FN).
                    var_types.pop(target.id, None)

        elif isinstance(target, (ast.Tuple, ast.List)):
            # Tuple unpacking: a, b = ...
            _handle_unpack(
                target,
                stmt.value,
                function_taint,
                taint_map,
                var_taints,
            )

        # An Assign target is always Name/Tuple/List/Subscript/Attribute by the
        # grammar, so these branches are exhaustive — the implicit "no branch matched,
        # continue loop" arc out of this last elif is unreachable.
        elif isinstance(target, (ast.Subscript, ast.Attribute)):  # pragma: no branch
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
    # If value is a Tuple/List with compatible arity, do element-wise. A single
    # starred target captures the middle slice, so bind it to that slice's
    # weakest-link taint instead of silently skipping it.
    if isinstance(value, (ast.Tuple, ast.List)) and _handle_literal_unpack(
        target, value, function_taint, taint_map, var_taints
    ):
        return
    else:
        # RHS is not a matching literal tuple — all targets get RHS taint.
        rhs_taint = _resolve_expr(
            value,
            function_taint,
            taint_map,
            var_taints,
        )
        for tgt in target.elts:
            if isinstance(tgt, ast.Name):
                var_taints[tgt.id] = rhs_taint
            elif isinstance(tgt, ast.Starred) and isinstance(tgt.value, ast.Name):
                var_taints[tgt.value.id] = rhs_taint


def _handle_literal_unpack(
    target: ast.Tuple | ast.List,
    value: ast.Tuple | ast.List,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> bool:
    starred_idx = next((i for i, elt in enumerate(target.elts) if isinstance(elt, ast.Starred)), None)
    if starred_idx is None:
        if len(value.elts) != len(target.elts):
            return False
        for tgt, val in zip(target.elts, value.elts, strict=False):
            if isinstance(tgt, ast.Name):
                taint = _resolve_expr(
                    val,
                    function_taint,
                    taint_map,
                    var_taints,
                )
                var_taints[tgt.id] = taint
            elif isinstance(tgt, (ast.Tuple, ast.List)):
                _handle_unpack(tgt, val, function_taint, taint_map, var_taints)
        return True

    fixed_targets = len(target.elts) - 1
    if len(value.elts) < fixed_targets:
        return False

    suffix_count = len(target.elts) - starred_idx - 1
    for tgt, val in zip(target.elts[:starred_idx], value.elts[:starred_idx], strict=False):
        if isinstance(tgt, ast.Name):
            var_taints[tgt.id] = _resolve_expr(val, function_taint, taint_map, var_taints)
        elif isinstance(tgt, (ast.Tuple, ast.List)):
            _handle_unpack(tgt, val, function_taint, taint_map, var_taints)

    slice_end = len(value.elts) - suffix_count if suffix_count else len(value.elts)
    captured = value.elts[starred_idx:slice_end]
    if captured:
        star_taint = _resolve_expr(captured[0], function_taint, taint_map, var_taints)
        for val in captured[1:]:
            star_taint = combine(star_taint, _resolve_expr(val, function_taint, taint_map, var_taints))
    else:
        star_taint = TaintState.INTEGRAL
    starred = target.elts[starred_idx]
    assert isinstance(starred, ast.Starred)
    _assign_target(starred.value, star_taint, var_taints)

    for offset in range(suffix_count):
        tgt = target.elts[starred_idx + 1 + offset]
        val = value.elts[len(value.elts) - suffix_count + offset]
        if isinstance(tgt, ast.Name):
            var_taints[tgt.id] = _resolve_expr(val, function_taint, taint_map, var_taints)
        elif isinstance(tgt, (ast.Tuple, ast.List)):
            _handle_unpack(tgt, val, function_taint, taint_map, var_taints)
    return True


def _handle_augassign(
    stmt: ast.AugAssign,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> None:
    """Handle ``x += expr`` — combine existing taint with the new value.

    ``x += expr`` is value-building (``x = x <op> expr``), so it combines via the
    rank-meet least_trusted (weakest-link), consistent with the BinOp combiner: a
    clean accumuland does not clash validated data to MIXED_RAW, while raw still
    propagates.
    """
    rhs_taint = _resolve_expr(
        stmt.value,
        function_taint,
        taint_map,
        var_taints,
    )
    if isinstance(stmt.target, ast.Name):
        existing = var_taints.get(stmt.target.id, function_taint)
        var_taints[stmt.target.id] = combine(existing, rhs_taint)
    # An AugAssign target is always Name/Attribute/Subscript by the Python grammar,
    # so these branches are exhaustive — the implicit fall-through is unreachable.
    elif isinstance(stmt.target, (ast.Subscript, ast.Attribute)):  # pragma: no branch
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
    """Contaminate the container-write target's root Name with *rhs*.

    A container write (``d[k] = v``/``obj.x = v``/``d[k] += v``) makes the base hold
    *v*, so the base's summary taint becomes the weakest-link of its prior taint and
    the written value (least_trusted) — consistent with container literals. A raw
    write still contaminates (least_trusted keeps the raw rank — no fail-open); a
    clean write does not clash to MIXED_RAW.
    """
    base = _container_base_name(target)
    if base is not None:
        var_taints[base] = combine(var_taints.get(base, function_taint), rhs)


# ── Control flow handlers ────────────────────────────────────────


def _branch_copy(parent: dict[str, list[ast.Lambda]] | None) -> dict[str, list[ast.Lambda]] | None:
    """An arm-local copy of the lambda-bindings map for one branch arm (``None`` when
    bindings are not being tracked — a degraded caller). Copying per arm is what keeps
    a lambda bound inside one arm from leaking into a mutually-exclusive sibling arm
    (wardline-36016d26f3), mirroring how ``var_taints`` is copied per arm. The candidate
    LISTS are copied too, so an arm's rebind/removal cannot mutate the parent's or a
    sibling's set in place (wardline-383f83fafe)."""
    return {name: list(lams) for name, lams in parent.items()} if parent is not None else None


def _walk_branch_body(
    body: list[ast.stmt],
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
    call_site_taints: dict[int, dict[str, TaintState]] | None,
    arm_bindings: dict[str, list[ast.Lambda]] | None,
) -> None:
    """Walk one branch arm's body with *arm_bindings* as the active (arm-local)
    lambda-bindings map, so lambda assignments inside the arm mutate the copy, not the
    shared parent. A plain ``_walk_body`` when bindings aren't tracked."""
    if arm_bindings is None:
        _walk_body(body, function_taint, taint_map, var_taints, call_site_taints)
        return
    token = _CURRENT_LAMBDA_BINDINGS.set(arm_bindings)
    try:
        _walk_body(body, function_taint, taint_map, var_taints, call_site_taints)
    finally:
        _CURRENT_LAMBDA_BINDINGS.reset(token)


def _merge_branch_bindings(
    parent: dict[str, list[ast.Lambda]] | None,
    arms: list[dict[str, list[ast.Lambda]] | None],
) -> None:
    """Merge mutually-exclusive branch arms' lambda bindings back into *parent* in
    place. Each arm was walked against an arm-local *copy* of *parent*, so a binding
    made in one arm cannot leak into a sibling arm during the walk
    (wardline-36016d26f3); this re-converges the arms into the post-branch state.

    Post-branch a name MAY hold whichever lambda the taken arm bound it to, so its
    candidate set is the UNION of every arm's set for that name (wardline-383f83fafe).
    We rebuild *parent* from that union rather than overwriting slot-by-slot: the old
    single-slot map kept only the last arm's binding, dropping a sink-lambda bound in a
    non-last arm and missing the post-branch sink (the FN this closes).

    The union also subsumes the no-false-negative guard the prior delta-merge protected
    (wardline-36016d26f3): an arm that never touched a name still carries its pre-branch
    set (each arm is a full copy of *parent*), and the implicit no-``else`` /
    no-match-catch-all fall-through arm is exactly such a copy — so a rebinding made in
    one arm is preserved in the union, never reverted by an untouched sibling. A name
    that EVERY arm rebound to a non-lambda is absent from all arm sets and so drops out
    of the union — sound, because on no post-branch path is it still a lambda. (The prior
    delta-merge left such a name in place; that was a harmless over-approximation, not a
    pinned behaviour.) Resolving an extra candidate only records arg-taints — it can
    over-approximate, never mask a sink — so the union is FP-safe.

    Invariant: a name is either ABSENT from the map or maps to a NON-EMPTY list. An empty
    list would make ``_resolve_call``'s ``name in bindings`` check pass while the
    candidate loop does nothing — silently skipping all bodies, a latent FN. Writers
    uphold it (linear rebind stores ``[lam]`` or pops; this merge never buckets an empty
    arm list), so the map never holds an empty list."""
    if parent is None:
        return
    merged: dict[str, list[ast.Lambda]] = {}
    for arm in arms:
        if arm is None:
            continue
        for name, lams in arm.items():
            if not lams:
                continue  # uphold the empty-list-never-stored invariant (see docstring)
            bucket = merged.setdefault(name, [])
            for lam in lams:
                # Dedup by identity (ast nodes don't define __eq__): the same lambda
                # carried unchanged through several arms should be resolved once.
                if not any(lam is seen for seen in bucket):
                    bucket.append(lam)
    parent.clear()
    parent.update(merged)


def _handle_if(
    stmt: ast.If,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
    call_site_taints: dict[int, dict[str, TaintState]] | None = None,
) -> None:
    """Handle if/elif/else — merge variable taints from branches."""
    # Resolve test expression (may contain walrus).
    _resolve_expr(stmt.test, function_taint, taint_map, var_taints)

    # Snapshot before branches.
    pre_if = dict(var_taints)
    parent_lambdas = _CURRENT_LAMBDA_BINDINGS.get()

    # Walk the if-body with an arm-local lambda-bindings copy — branch-local like
    # var_taints, so a lambda bound here cannot leak into the else arm.
    if_taints = dict(var_taints)
    if_lambdas = _branch_copy(parent_lambdas)
    _walk_branch_body(stmt.body, function_taint, taint_map, if_taints, call_site_taints, if_lambdas)

    if stmt.orelse:
        # Walk the else-body on its own arm-local bindings copy.
        else_taints = dict(var_taints)
        else_lambdas = _branch_copy(parent_lambdas)
        _walk_branch_body(stmt.orelse, function_taint, taint_map, else_taints, call_site_taints, else_lambdas)
    else:
        # No else — the "else" branch is the pre-if state with bindings unchanged.
        else_taints = pre_if
        else_lambdas = _branch_copy(parent_lambdas)

    _merge_branch_bindings(parent_lambdas, [if_lambdas, else_lambdas])

    # Merge: for each variable, combine the two branch values. The var holds ONE
    # branch's value (an alternative), so combine via the rank-meet least_trusted
    # (weakest-link), NOT taint_join: two clean-but-different-family branches must
    # not clash to MIXED_RAW; a raw branch still propagates (least_trusted keeps
    # its rank).
    all_vars = set(if_taints) | set(else_taints)
    for var in all_vars:
        if_val = if_taints.get(var)
        else_val = else_taints.get(var)
        if if_val is not None and else_val is not None:
            var_taints[var] = combine(if_val, else_val)
        elif if_val is not None:
            var_taints[var] = if_val
        elif else_val is not None:
            var_taints[var] = else_val


def _handle_for(
    stmt: ast.For | ast.AsyncFor,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
    call_site_taints: dict[int, dict[str, TaintState]] | None = None,
) -> None:
    """Handle for loops — target gets iterable taint, body merges."""
    iter_taint = _resolve_expr(
        stmt.iter,
        function_taint,
        taint_map,
        var_taints,
    )

    # Snapshot pre-loop.
    pre_loop = dict(var_taints)

    # Lambda bindings are mutated in place on the shared map across iterations (no per-arm
    # copy WITHIN the fixpoint — the body's in-place resolution is what gives a sound
    # loop-carried binding: a cb(raw) call placed BEFORE an in-body rebind sees the prior
    # iteration's candidate). A rebind REPLACES with the SAME ast.Lambda node every
    # iteration (parsed once) and in-body branch merges dedup by identity, so the binding
    # state is idempotent across iterations — the var_taints convergence check below is a
    # sufficient fixpoint for the bindings too (no unbounded candidate growth, see
    # wardline-383f83fafe).
    #
    # The loop body is, however, a CONDITIONALLY-executed arm: a reachable 0-iteration path
    # means the post-loop binding for a name MAY still be its pre-loop value. Snapshot the
    # pre-loop bindings (the "loop did not run" arm) and union them back AFTER the fixpoint
    # (see below), exactly like a no-`else` ``if`` — otherwise a sink-lambda bound before
    # the loop and rebound clean inside it is silently dropped on the zero-trip path, and a
    # post-loop call through the name misses the sink (the FN this closes,
    # wardline-d6af917bde).
    pre_loop_lambdas = _branch_copy(_CURRENT_LAMBDA_BINDINGS.get())

    # Iterate the walk until var_taints genuinely converges (WLN-MED-09). The bound is
    # num_vars × lattice_height, NOT lattice_height (8) alone: 8 caps a SINGLE variable's
    # monotone rank climb, but a read-before-write loop-carried chain propagates taint one
    # link per iteration, so an N-variable chain needs N iterations to reach the head — a
    # range(8) cap silently dropped chains longer than 8 (a fail-open FN, wardline-e04db6e656).
    # The convergence break below is the real terminator; the backstop is a never-hit-in-
    # practice safety net (finite monotone lattice over a fixed local-name set guarantees it).
    iterations = 0
    while True:
        current_state = dict(var_taints)
        # Assign the loop variable.
        _assign_target(stmt.target, iter_taint, var_taints)
        # Walk body.
        _walk_body(stmt.body, function_taint, taint_map, var_taints, call_site_taints)
        # Merge body state with pre-loop
        for var in set(var_taints) | set(pre_loop):
            var_taints[var] = combine(var_taints.get(var, function_taint), pre_loop.get(var, function_taint))
        iterations += 1
        if var_taints == current_state:
            break
        if iterations >= len(var_taints) * len(TRUST_RANK) + 1:
            break

    # Union the converged "loop ran" binding arm with the "loop did not run" arm so the
    # post-loop candidate set covers BOTH the zero-trip path (pre_loop_lambdas) and the
    # body's rebinds — the faithful mirror of a no-`else` ``if`` join (wardline-d6af917bde).
    # _merge_branch_bindings preserves the dedup-by-identity and never-empty-list
    # invariants. This lands BEFORE the orelse walk, so a `for...else` body that further
    # rebinds the name still mutates the unioned state in place (accepted limitation: the
    # break-vs-normal-exit distinction is not modelled — orelse is walked unconditionally).
    parent_lambdas = _CURRENT_LAMBDA_BINDINGS.get()
    if parent_lambdas is not None:
        post_body_arm = _branch_copy(parent_lambdas)
        _merge_branch_bindings(parent_lambdas, [post_body_arm, pre_loop_lambdas])

    # Walk orelse (runs after normal loop completion).
    if stmt.orelse:
        _walk_body(stmt.orelse, function_taint, taint_map, var_taints, call_site_taints)


def _handle_while(
    stmt: ast.While,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
    call_site_taints: dict[int, dict[str, TaintState]] | None = None,
) -> None:
    """Handle while loops — body merges with pre-loop state."""
    pre_loop = dict(var_taints)

    # The body is a conditionally-executed arm (a reachable 0-iteration path), so snapshot
    # the pre-loop lambda bindings (the "loop did not run" arm) and union them back after
    # the fixpoint — the no-`else` ``if`` mirror that keeps a pre-loop sink-lambda visible
    # on the zero-trip path (wardline-d6af917bde; see _handle_for for the full rationale).
    pre_loop_lambdas = _branch_copy(_CURRENT_LAMBDA_BINDINGS.get())

    # Iterate to genuine convergence with a num_vars × lattice_height backstop — see
    # _handle_for: a range(8) cap was unsound for loop-carried chains > 8 links
    # (wardline-e04db6e656).
    iterations = 0
    while True:
        current_state = dict(var_taints)
        _resolve_expr(stmt.test, function_taint, taint_map, var_taints)
        _walk_body(stmt.body, function_taint, taint_map, var_taints, call_site_taints)
        for var in set(var_taints) | set(pre_loop):
            var_taints[var] = combine(var_taints.get(var, function_taint), pre_loop.get(var, function_taint))
        iterations += 1
        if var_taints == current_state:
            break
        if iterations >= len(var_taints) * len(TRUST_RANK) + 1:
            break

    # Union the converged "loop ran" arm with the "loop did not run" arm (wardline-d6af917bde).
    parent_lambdas = _CURRENT_LAMBDA_BINDINGS.get()
    if parent_lambdas is not None:
        post_body_arm = _branch_copy(parent_lambdas)
        _merge_branch_bindings(parent_lambdas, [post_body_arm, pre_loop_lambdas])

    if stmt.orelse:
        _walk_body(stmt.orelse, function_taint, taint_map, var_taints, call_site_taints)


def _handle_with(
    stmt: ast.With | ast.AsyncWith,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
    call_site_taints: dict[int, dict[str, TaintState]] | None = None,
) -> None:
    """Handle with/async-with statements."""
    for item in stmt.items:
        expr_taint = _resolve_expr(
            item.context_expr,
            function_taint,
            taint_map,
            var_taints,
        )
        if item.optional_vars is not None:
            _assign_target(item.optional_vars, expr_taint, var_taints)

    _walk_body(stmt.body, function_taint, taint_map, var_taints, call_site_taints)


def _handle_try(
    stmt: ast.Try | ast.TryStar,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
    call_site_taints: dict[int, dict[str, TaintState]] | None = None,
) -> None:
    """Handle try/except/else/finally — snapshot-branch-join pattern."""
    pre_try = dict(var_taints)
    parent_lambdas = _CURRENT_LAMBDA_BINDINGS.get()

    # Walk try body on a copy (arm-local lambda bindings — branch-local like var_taints).
    try_taints = dict(pre_try)
    try_lambdas = _branch_copy(parent_lambdas)
    _walk_branch_body(stmt.body, function_taint, taint_map, try_taints, call_site_taints, try_lambdas)

    # Walk each handler on separate copies (mutually exclusive with try body).
    handler_branches: list[dict[str, TaintState]] = [try_taints]  # try-success is one branch
    arm_bindings: list[dict[str, list[ast.Lambda]] | None] = [try_lambdas]
    for handler in stmt.handlers:
        handler_taints = dict(pre_try)
        if handler.name:
            handler_taints[handler.name] = function_taint
        handler_lambdas = _branch_copy(parent_lambdas)
        _walk_branch_body(handler.body, function_taint, taint_map, handler_taints, call_site_taints, handler_lambdas)
        handler_branches.append(handler_taints)
        arm_bindings.append(handler_lambdas)

    # Walk orelse on the try-success branch (runs only if no exception) — continue the
    # try arm's bindings, not a fresh copy.
    if stmt.orelse:
        _walk_branch_body(stmt.orelse, function_taint, taint_map, try_taints, call_site_taints, try_lambdas)

    # Merge all branches.
    all_vars: set[str] = set()
    for branch in handler_branches:
        all_vars.update(branch.keys())

    for var in all_vars:
        branch_taints: list[TaintState] = []
        for b in handler_branches:
            val = b.get(var)
            if val is not None:
                branch_taints.append(val)
        if branch_taints:
            var_taints[var] = branch_taints[0]
            for t in branch_taints[1:]:
                var_taints[var] = combine(var_taints[var], t)
        else:  # pragma: no cover
            # Unreachable: ``all_vars`` is drawn solely from ``handler_branches``
            # (the try-success branch + each handler), every branch starts as a
            # copy of pre_try, so each var is present in >=1 branch and
            # ``branch_taints`` is never empty. Kept for structural parity.
            try:
                var_taints[var] = pre_try[var]
            except KeyError:
                _taint_val = None  # var absent from pre-try state — leave unset

    # Lambda bindings: union the mutually-exclusive arms (try-success + each handler)
    # back into the parent, mirroring the var_taints join above.
    _merge_branch_bindings(parent_lambdas, arm_bindings)

    # finalbody runs unconditionally after merge — with the merged bindings (in place,
    # the active contextvar dict, since the function body continues into it).
    if stmt.finalbody:
        _walk_body(stmt.finalbody, function_taint, taint_map, var_taints, call_site_taints)


def _handle_match(
    stmt: ast.Match,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
    call_site_taints: dict[int, dict[str, TaintState]] | None = None,
) -> None:
    """Handle ``match``/``case`` — snapshot, walk each arm on a copy seeded with
    that arm's capture bindings, then join all arms with the no-match fall-through.

    Each capture-pattern target is bound to the *subject's* taint (a conservative
    whole-subject over-approximation — element-precise extraction is not modelled
    at L2; this never under-taints). The pre-match state is included as an extra
    branch to model the no-arm-matched path and variables assigned in only some
    arms; including it is taint-safe (``least_trusted`` only moves toward
    less-trusted) and mirrors :func:`_handle_if`'s implicit-else treatment.
    """
    # Subject is evaluated once, before any arm — resolve it for walrus side
    # effects and to obtain the taint that capture targets inherit.
    subject_taint = _resolve_expr(stmt.subject, function_taint, taint_map, var_taints)

    pre_match = dict(var_taints)
    parent_lambdas = _CURRENT_LAMBDA_BINDINGS.get()
    branches: list[dict[str, TaintState]] = []
    arm_bindings: list[dict[str, list[ast.Lambda]] | None] = []
    for case in stmt.cases:
        case_taints = dict(pre_match)
        for name in _collect_pattern_targets(case.pattern):
            case_taints[name] = subject_taint
        # Arm-local lambda bindings (guard + body share the arm), branch-local like
        # var_taints so a lambda bound in one case cannot leak into a sibling case.
        case_lambdas = _branch_copy(parent_lambdas)
        token = _CURRENT_LAMBDA_BINDINGS.set(case_lambdas) if case_lambdas is not None else None
        try:
            if case.guard is not None:
                # The guard is tested with the arm's captures in scope; resolve it for
                # walrus side effects (binds into this arm's state).
                _resolve_expr(case.guard, function_taint, taint_map, case_taints)
            _walk_body(case.body, function_taint, taint_map, case_taints, call_site_taints)
        finally:
            if token is not None:
                _CURRENT_LAMBDA_BINDINGS.reset(token)
        branches.append(case_taints)
        arm_bindings.append(case_lambdas)

    # The implicit "no arm matched" path keeps the pre-match state and bindings.
    branches.append(pre_match)
    arm_bindings.append(_branch_copy(parent_lambdas))

    all_vars: set[str] = set()
    for branch in branches:
        all_vars.update(branch)
    for var in all_vars:
        vals = [branch[var] for branch in branches if var in branch]
        merged = vals[0]
        for v in vals[1:]:
            merged = combine(merged, v)
        var_taints[var] = merged

    # Lambda bindings: union the mutually-exclusive case arms (+ no-match) into parent.
    _merge_branch_bindings(parent_lambdas, arm_bindings)


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


def _self_attr_name(target: ast.expr) -> str | None:
    """The attribute name of a ``self.<attr>`` / ``cls.<attr>`` write target, else None.

    Only a direct attribute of the instance/class receiver (``self.x = ...``) — a
    subscript-into-attribute (``self.cache[k] = ...``) or deeper chain is NOT a direct
    attribute write and is deliberately excluded (it would need container modelling)."""
    if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id in ("self", "cls"):
        return target.attr
    return None


def collect_attribute_writes(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
    class_qualnames: frozenset[str],
    alias_map: dict[str, str],
    module_prefix: str,
    enclosing_class: str | None = None,
) -> dict[str, dict[str, TaintState]]:
    """Return ``{class_qualname: {attr_name: least_trusted RHS taint}}`` for every
    instance attribute assignment in *func_node*'s body.

    Handles both internal ``self.x = ...`` writes (enclosing class) and external
    ``obj.x = ...`` writes where ``obj`` was instantiated via a class constructor
    call.
    """
    from wardline.scanner.ast_primitives import resolve_call_fqn

    out: dict[str, dict[str, TaintState]] = {}
    var_types: dict[str, str] = {}

    def _walk(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue

            # 1. Track variable types assigned to constructors or copied
            targets: list[ast.expr] = []
            value: ast.expr | None = None
            if isinstance(child, ast.Assign):
                targets = child.targets
                value = child.value
            elif isinstance(child, ast.AnnAssign):
                targets = [child.target]
                value = child.value

            class_fqn = None
            if value is not None:
                if isinstance(value, ast.Call):
                    fqn = resolve_call_fqn(value, alias_map, class_qualnames, module_prefix)
                    if fqn in class_qualnames:
                        class_fqn = fqn
                elif isinstance(value, ast.Name):
                    class_fqn = var_types.get(value.id)

            if class_fqn is not None:
                for tgt in targets:
                    if isinstance(tgt, ast.Name):
                        var_types[tgt.id] = class_fqn

            # 2. Record attribute writes
            targets_to_check: list[ast.expr] = []
            if isinstance(child, ast.Assign):
                targets_to_check = child.targets
                value = child.value
            elif isinstance(child, (ast.AnnAssign, ast.AugAssign)):
                targets_to_check = [child.target]
                value = child.value

            for tgt in targets_to_check:
                if isinstance(tgt, ast.Attribute) and isinstance(tgt.value, ast.Name):
                    var_name = tgt.value.id
                    attr_name = tgt.attr
                    target_class = None
                    if var_name in ("self", "cls") and enclosing_class:
                        target_class = enclosing_class
                    elif var_name in var_types:
                        target_class = var_types[var_name]

                    if target_class is not None and value is not None:
                        rhs_taint = _resolve_expr(value, function_taint, taint_map, var_taints)
                        cls_writes = out.setdefault(target_class, {})
                        cls_writes[attr_name] = (
                            combine(cls_writes[attr_name], rhs_taint) if attr_name in cls_writes else rhs_taint
                        )

            _walk(child)

    token_types = _CURRENT_VAR_TYPES.set(var_types)
    token_alias = _CURRENT_ALIAS_MAP.set(alias_map)
    try:
        _walk(func_node)
    finally:
        _CURRENT_VAR_TYPES.reset(token_types)
        _CURRENT_ALIAS_MAP.reset(token_alias)
    return out


def collect_self_attr_writes(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> dict[str, TaintState]:
    """Compatibility wrapper for internal-only writes."""
    writes = collect_attribute_writes(
        func_node,
        function_taint,
        taint_map,
        var_taints,
        class_qualnames=frozenset(),
        alias_map={},
        module_prefix="",
        enclosing_class="dummy",
    )
    return writes.get("dummy", {})


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
    returns: list[tuple[TaintState, str | None, ast.expr]] = []
    _collect_return_paths(list(func_node.body), function_taint, taint_map, var_taints, returns)
    if not returns:
        return None
    result = returns[0][0]
    for taint, _callee, _node in returns[1:]:
        result = combine(result, taint)
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

    When the worst path is an INDIRECT ``return <var>`` (T1.3), resolve a single hop:
    name the callee of the assignment that gave ``<var>`` its worst-taint value. This
    is provenance/explainability only and never changes a fire/no-fire decision — the
    taint VALUE (:func:`compute_return_taint`) is unaffected. Deeper / aliased chains
    beyond one hop stay ``None`` (the N-hop walk lives in the Loomweave stored-fact path).
    """
    returns: list[tuple[TaintState, str | None, ast.expr]] = []
    _collect_return_paths(list(func_node.body), function_taint, taint_map, var_taints, returns)
    if not returns:
        return None
    worst = returns[0][0]
    for taint, _callee, _node in returns[1:]:
        worst = combine(worst, taint)
    # 1) a worst-taint path that is itself a direct call → its callee (unchanged).
    for taint, callee, _node in returns:
        if taint == worst and callee is not None:
            return callee
    # 2) single-hop indirection: a worst-taint ``return <Name>`` whose Name was set by
    #    a direct call. Provenance only — never changes a fire/no-fire decision.
    for taint, callee, node in returns:
        if taint == worst and callee is None and isinstance(node, ast.Name):
            indirect = _assignment_callee(list(func_node.body), node.id, worst, function_taint, taint_map, var_taints)
            if indirect is not None:
                return indirect
    return None


def _assignment_callee(
    nodes: list[ast.AST],
    name: str,
    worst: TaintState,
    function_taint: TaintState,
    taint_map: dict[str, TaintState],
    var_taints: dict[str, TaintState],
) -> str | None:
    """The callee of the LAST (source-order) direct-call assignment to ``name`` whose
    RHS resolves to ``worst`` taint — the single-hop contributing call behind an
    indirect ``return <name>``. Scope-respecting (does not descend into nested
    def/class/lambda, whose assignments bind a different scope). Returns ``None`` when
    ``name`` is not set by a direct call to the worst taint (a parameter, a literal, or
    a deeper var-to-var chain) — honest, never invented.

    This is best-effort PROVENANCE, not a fire/no-fire input: it is branch-unaware
    (source-order last write wins, no reachability model), so in branchy bodies it may
    name a worst-taint assignment from a different branch than the one that produced the
    returned value. Harmless — the taint VALUE is already decided by
    :func:`compute_return_taint`; this only labels the explain surface. NOTE: re-resolves
    RHS expressions via :func:`_resolve_expr`, which mutates ``var_taints`` on walrus
    targets — callers that must not mutate their map pass a copy (the analyzer does)."""
    result: str | None = None
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(node, ast.Assign):
            callee = _return_callee(node.value)
            if (
                callee is not None
                and any(isinstance(t, ast.Name) and t.id == name for t in node.targets)
                and _resolve_expr(node.value, function_taint, taint_map, var_taints) == worst
            ):
                result = callee
        nested = _assignment_callee(
            list(ast.iter_child_nodes(node)), name, worst, function_taint, taint_map, var_taints
        )
        if nested is not None:
            result = nested
    return result


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
    out: list[tuple[TaintState, str | None, ast.expr]],
) -> None:
    """Recurse the AST collecting ``(taint, callee_or_None, value_node)`` for each
    value-bearing return, descending into ALL children EXCEPT nested ``FunctionDef``/
    ``AsyncFunctionDef``/``ClassDef``/``Lambda`` (separate scopes — their returns
    bind their own callable, not this one). The callee is the direct-call name of
    the return's top-level expression (``None`` for non-call returns); ``value_node``
    is that raw ``ast.expr``, used by :func:`compute_return_callee` to resolve
    single-hop indirection on an indirect ``return <name>``.

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
        if isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom)) and node.value is not None:
            taint = _resolve_expr(node.value, function_taint, taint_map, var_taints)
            out.append((taint, _return_callee(node.value), node.value))
        _collect_return_paths(list(ast.iter_child_nodes(node)), function_taint, taint_map, var_taints, out)
