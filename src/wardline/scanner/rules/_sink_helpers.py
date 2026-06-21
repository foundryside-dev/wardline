# src/wardline/scanner/rules/_sink_helpers.py
"""Shared machinery for the dangerous-sink rules (106/107/108/112/115/116/117/121-126).

A "sink rule" fires when raw-zone data reaches a named dangerous call (a
deserialization / dynamic-exec / OS-command / SSRF / XML / template / native-load /
log / mail sink) inside a trusted-tier function. These helpers find the sink calls
in a function's own scope, canonicalize their names through the module import alias
map and the name-binding maps, and resolve the taint of their arguments; the
consolidated :class:`TaintedSinkRule` base (review 2026-06-10) is THE single check
loop the whole family runs on.

**Argument-taint resolution is FLOW-SENSITIVE.** Each sink call reads the engine's
per-call-site resolved argument taints (`function_call_site_arg_taints` — the taint of
every argument AT the sink line, produced by the L2 forward walk). The sink's worst
(least-trusted) argument taint drives the verdict, so a name reassigned raw→trusted
before the sink (or trusted→raw after an earlier sink) resolves at its taint at the call,
not the function's final map. When no call-site snapshot exists (an L2-skipped function),
resolution fails closed: a warning is emitted and any call with arguments is treated as
``UNKNOWN_RAW``.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from wardline.core.finding import Finding, Kind, Location, Severity
from wardline.core.finding import compute_finding_fingerprint as _fp
from wardline.core.taints import RAW_ZONE, TRUST_RANK, TaintState
from wardline.scanner.rules.severity_model import modulate

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from wardline.scanner.context import AnalysisContext
    from wardline.scanner.index import Entity
    from wardline.scanner.rules.metadata import RuleMetadata

__all__ = [
    "RAW_ZONE",
    "ArgSpec",
    "SinkBindings",
    "TaintedSinkRule",
    "build_sink_finding",
    "canonical_call_name",
    "collect_ctor_call_nodes",
    "collect_sink_bindings",
    "dotted_name",
    "enclosing_declared_tier",
    "module_alias_map",
    "module_for_qualname",
    "receiver_ctor_call",
    "resolve_bound_call_fqn",
    "resolved_arg_taints",
    "resolved_sink_calls",
    "sink_calls",
    "sink_method_calls",
    "worst_arg_taint",
    "worst_dangerous_arg_taint",
]


def enclosing_declared_tier(
    qualname: str,
    project_taints: Mapping[str, TaintState],
    declared_qualnames: frozenset[str],
) -> TaintState:
    """Trust tier governing *qualname*, honoring a nested def's OWN trust decorator.

    Walks outward through ``.<locals>.`` enclosing scopes and returns the tier of the
    nearest scope that carries an explicit trust DECLARATION (``declared_qualnames`` — the
    trust surface). So a nested def with its own decorator uses its own tier
    (wardline-bb8396f96e), while a genuinely undeclared nested def inherits the nearest
    declared enclosing scope's tier (wardline-9b88ec5419). Falls back to the full qualname's
    own tier (defaulting ``UNKNOWN_RAW`` → developer-freedom) when no scope in the lexical
    chain is declared.

    Keying off the explicit-declaration set — not a tier heuristic — is what distinguishes
    "this def declared its own trust" from "this def is undeclared and should inherit": an
    undeclared nested def is registered in ``project_taints`` (typically ``UNKNOWN_RAW``) yet
    is absent from ``declared_qualnames``, so the walk correctly steps past it to the parent.
    """
    parts = qualname.split(".<locals>.")
    for i in range(len(parts), 0, -1):
        candidate = ".<locals>.".join(parts[:i])
        if candidate in declared_qualnames:
            return project_taints.get(candidate, TaintState.UNKNOWN_RAW)
    return project_taints.get(qualname, TaintState.UNKNOWN_RAW)


def dotted_name(node: ast.expr) -> str | None:
    """Reconstruct a dotted call name: ``eval`` (Name) / ``pickle.loads`` (Attribute).

    Returns None when the receiver is not a pure Name/Attribute chain (e.g.
    ``get_ctx().eval`` — a Call receiver), so a dynamic attribute access can never be
    mistaken for a bare builtin sink like ``eval``."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base is not None else None
    return None


def canonical_call_name(dotted: str, alias_map: Mapping[str, str]) -> str:
    """Resolve a raw dotted call spelling through the module's import aliases.

    Handles ``import pickle as p; p.loads()``, ``from pickle import loads as l;
    l()``, and nested module aliases like ``import urllib.request as ur;
    ur.urlopen()``.
    """
    for local, target in sorted(alias_map.items(), key=lambda item: len(item[0]), reverse=True):
        if dotted == local:
            return target
        if dotted.startswith(local + "."):
            return f"{target}{dotted[len(local) :]}"
    return dotted


def _own_calls(node: ast.AST) -> Iterator[ast.Call]:
    """Yield every ``ast.Call`` in *node*'s own analyzable scope.

    Function, async-function, and class bodies are indexed as their own entities, so
    they are not traversed here. Lambda bodies are intentionally traversed because
    the entity index does not emit separate lambda entities; skipping them would hide
    dangerous calls from sink rules.
    """
    result: list[ast.Call] = []
    stack = [node]
    while stack:
        current = stack.pop()
        children = list(ast.iter_child_nodes(current))
        if children:
            for child in reversed(children):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                stack.append(child)

        if current is not node and isinstance(current, ast.Call):
            result.append(current)

    return iter(result)


def _direct_sink_fqn(
    call: ast.Call,
    sink_names: frozenset[str],
    aliases: dict[str, str],
    module_prefix: str,
) -> str | None:
    """Canonical sink FQN of *call* when its func is a direct dotted spelling
    (``eval`` / ``pickle.loads`` / an import-aliased form) in *sink_names*, else None."""
    from wardline.scanner.ast_primitives import resolve_call_fqn

    fqn = resolve_call_fqn(call, aliases, frozenset(), module_prefix)
    if fqn is not None and fqn in sink_names:
        return fqn
    dotted = dotted_name(call.func)
    if dotted is None:
        return None
    canonical = canonical_call_name(dotted, aliases)
    return canonical if canonical in sink_names else None


def sink_calls(
    func_node: ast.AST,
    sink_names: frozenset[str],
    alias_map: Mapping[str, str] | None = None,
    module_prefix: str = "",
) -> Iterator[tuple[ast.Call, str]]:
    """Yield ``(call, dotted_name)`` for own-scope calls whose func resolves to a
    canonical name in *sink_names* (matches both ``eval`` and ``pickle.loads`` forms)."""
    aliases = dict(alias_map or {})
    for call in _own_calls(func_node):
        fqn = _direct_sink_fqn(call, sink_names, aliases, module_prefix)
        if fqn is not None:
            yield call, fqn


def sink_method_calls(func_node: ast.AST, method_names: frozenset[str]) -> Iterator[ast.Call]:
    """Yield own-scope calls whose func is an attribute access ``recv.<method>`` whose method
    name is in *method_names* (e.g. ``cursor.execute``).

    Descends into lambda bodies (via :func:`_own_calls`) so a sink wrapped in a lambda is not
    missed — the same lambda-traversal the dotted-FQN :func:`sink_calls` path already has; does
    not enter nested def/class scopes (those are indexed as their own entities). For rules that
    key on the METHOD NAME regardless of receiver (PY-WL-118), as opposed to canonical dotted
    sink FQNs."""
    for call in _own_calls(func_node):
        if isinstance(call.func, ast.Attribute) and call.func.attr in method_names:
            yield call


@dataclass(frozen=True)
class SinkBindings:
    """Statically-known name bindings collected from one lexical scope.

    ``instance_classes`` maps a local var to the resolved FQN of the call that
    constructed it (``c = httpx.Client()`` → ``{"c": "httpx.Client"}``); a method
    call on the var then resolves to ``<ClassFqn>.<method>``. The constructor FQN
    is recorded WITHOUT verifying it names a class — a non-class FQN (``c = g()``
    → ``"m.g"``/``"g"``) yields method names like ``"g.get"`` that match no sink,
    so the over-approximation is silent, never a false sink match.

    ``callable_aliases`` maps a local var assigned DIRECTLY from a resolvable
    dotted callable (``runner = subprocess.run``) to that callable's FQN; a
    bare-name call of the var then participates in sink matching under the FQN.

    A name lives in at most one of the two maps (binding one kind evicts the other).
    """

    instance_classes: Mapping[str, str] = field(default_factory=dict)
    callable_aliases: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ArgSpec:
    """Which argument slots of a sink are dangerous (taint-relevant).

    ``positions`` are 0-based positional indices; ``keywords`` are keyword names.
    A sink with NO spec keeps the historical "worst of ALL args" behavior; a spec
    that names no slots (empty tuples) means "no dangerous slots" and never
    resolves a taint. Declare BOTH spellings of a slot that can be passed either
    way (e.g. ``requests.get`` → ``positions=(0,), keywords=("url",)``).
    """

    positions: tuple[int, ...] = ()
    keywords: tuple[str, ...] = ()


def _resolve_dotted(expr: ast.expr, aliases: Mapping[str, str]) -> str | None:
    """Canonical dotted FQN of a pure Name/Attribute chain through the alias map,
    else None (a dynamic expression — Call/Subscript receiver — never resolves)."""
    dotted = dotted_name(expr)
    return canonical_call_name(dotted, aliases) if dotted is not None else None


def collect_sink_bindings(
    node: ast.AST,
    alias_map: Mapping[str, str] | None = None,
    module_prefix: str = "",  # noqa: ARG001 — reserved: local-class constructor FQNs (not in v1)
    parent: SinkBindings | None = None,
) -> SinkBindings:
    """Collect *node*'s own-scope var→class and var→callable bindings.

    Works on a function OR a module node (nested def/class bodies are their own
    scopes and are skipped). *parent* layers an outer scope's bindings underneath
    (pass the module's bindings when collecting a function); a function-local
    rebind shadows or invalidates the parent entry for that name.

    Binding forms: ``c = pkg.Cls()`` (direct construction), ``with pkg.Cls() as c``
    / ``async with`` (context targets), ``c: pkg.Cls`` (annotation, with or without
    a value — the annotation wins over the value), ``def f(c: pkg.Cls)`` (a
    function's OWN parameter annotations, seeded before the body so a body rebind
    shadows/invalidates them — the most common spelling of an injected
    logger/client receiver), ``r = pkg.fn`` (callable alias), and ``d = c`` (copy
    of an existing binding). All resolve through the module's import alias map.

    NOT branch-aware (v1): the map is LAST-BINDING-WINS in source order across the
    whole scope, so a var rebound to a different class resolves to the NEW class
    everywhere — the stale class is never kept. Any rebind whose RHS does not
    resolve (a non-dotted call, a constant, a tuple unpack, ``for`` targets,
    augmented assignment, ``del``, a match capture) INVALIDATES the name.
    """
    aliases = dict(alias_map or {})
    instances: dict[str, str] = dict(parent.instance_classes) if parent else {}
    callables: dict[str, str] = dict(parent.callable_aliases) if parent else {}

    def invalidate(name: str) -> None:
        instances.pop(name, None)
        callables.pop(name, None)

    def invalidate_target(target: ast.expr) -> None:
        for sub in ast.walk(target):
            if isinstance(sub, ast.Name):
                invalidate(sub.id)

    def bind_instance(name: str, fqn: str) -> None:
        invalidate(name)
        instances[name] = fqn

    def bind_callable(name: str, fqn: str) -> None:
        invalidate(name)
        callables[name] = fqn

    def bind_value(name: str, value: ast.expr) -> None:
        if isinstance(value, ast.NamedExpr):  # c = (d := Cls()) — classify the inner value
            value = value.value
        if isinstance(value, ast.Call):
            fqn = _resolve_dotted(value.func, aliases)
            bind_instance(name, fqn) if fqn is not None else invalidate(name)
        elif isinstance(value, ast.Name) and value.id in instances:
            bind_instance(name, instances[value.id])  # d = c — copy the binding
        elif isinstance(value, ast.Name) and value.id in callables:
            bind_callable(name, callables[value.id])
        elif isinstance(value, (ast.Name, ast.Attribute)):
            fqn = _resolve_dotted(value, aliases)
            bind_callable(name, fqn) if fqn is not None else invalidate(name)
        else:
            invalidate(name)

    def visit(stmts: list[ast.stmt]) -> None:
        for stmt in stmts:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            # a walrus anywhere in the statement binds in THIS scope
            for sub in ast.walk(stmt):
                if isinstance(sub, ast.NamedExpr) and isinstance(sub.target, ast.Name):
                    bind_value(sub.target.id, sub.value)
            if isinstance(stmt, ast.Assign):
                if len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                    bind_value(stmt.targets[0].id, stmt.value)
                else:
                    for target in stmt.targets:
                        invalidate_target(target)
            elif isinstance(stmt, ast.AnnAssign):
                if isinstance(stmt.target, ast.Name):
                    ann_fqn = _resolve_dotted(stmt.annotation, aliases)
                    if ann_fqn is not None:
                        bind_instance(stmt.target.id, ann_fqn)
                    elif stmt.value is not None:
                        bind_value(stmt.target.id, stmt.value)
                    else:
                        invalidate(stmt.target.id)
                else:
                    invalidate_target(stmt.target)
            elif isinstance(stmt, ast.AugAssign):
                invalidate_target(stmt.target)
            elif isinstance(stmt, (ast.For, ast.AsyncFor)):
                invalidate_target(stmt.target)
                visit(stmt.body)
                visit(stmt.orelse)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    if item.optional_vars is None:
                        continue
                    if isinstance(item.optional_vars, ast.Name):
                        if isinstance(item.context_expr, ast.Call):
                            fqn = _resolve_dotted(item.context_expr.func, aliases)
                            if fqn is not None:
                                bind_instance(item.optional_vars.id, fqn)
                            else:
                                invalidate(item.optional_vars.id)
                        else:
                            invalidate(item.optional_vars.id)
                    else:
                        invalidate_target(item.optional_vars)
                visit(stmt.body)
            elif isinstance(stmt, (ast.If, ast.While)):
                visit(stmt.body)
                visit(stmt.orelse)
            elif isinstance(stmt, ast.Try):
                visit(stmt.body)
                for handler in stmt.handlers:
                    if handler.name is not None:
                        invalidate(handler.name)
                    visit(handler.body)
                visit(stmt.orelse)
                visit(stmt.finalbody)
            elif isinstance(stmt, ast.Match):
                for case in stmt.cases:
                    for sub in ast.walk(case.pattern):  # capture patterns bind names
                        captured = getattr(sub, "name", None) or getattr(sub, "rest", None)
                        if isinstance(captured, str):
                            invalidate(captured)
                    visit(case.body)
            elif isinstance(stmt, ast.Delete):
                for target in stmt.targets:
                    invalidate_target(target)

    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        # Parameter annotations seed instance bindings BEFORE the body walk, so a
        # body rebind shadows/invalidates them like any other prior binding.
        # ``*args``/``**kwargs`` are tuples/dicts of the annotated type, never the
        # instance itself, so they are not seeded. An unresolvable annotation
        # (subscripted generic, string literal) proves nothing and binds nothing.
        for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
            if arg.annotation is not None:
                ann_fqn = _resolve_dotted(arg.annotation, aliases)
                if ann_fqn is not None:
                    bind_instance(arg.arg, ann_fqn)
    body = getattr(node, "body", None)
    if isinstance(body, list):
        visit(body)
    return SinkBindings(instance_classes=instances, callable_aliases=callables)


def resolve_bound_call_fqn(
    call: ast.Call,
    bindings: SinkBindings,
    alias_map: Mapping[str, str] | None = None,
    module_prefix: str = "",  # noqa: ARG001 — reserved: local-class constructor FQNs (not in v1)
) -> str | None:
    """Resolve *call* through name BINDINGS (not import spellings), or None.

    Three forms:
      * bare-name callable alias — ``runner(...)`` where ``runner = subprocess.run``
        → ``"subprocess.run"``;
      * method on a bound instance — ``c.get(...)`` where ``c``'s class is in
        ``bindings.instance_classes`` → ``"<ClassFqn>.get"``;
      * chained construction — ``httpx.Client().get(...)`` → ``"httpx.Client.get"``
        (single constructor→method hop only; deeper chains like ``a().b().c()`` do
        not resolve — the intermediate return class is unknown).

    Dynamic receivers (subscript / nested attribute paths like ``self.client``)
    never resolve in v1.
    """
    aliases = dict(alias_map or {})
    func = call.func
    if isinstance(func, ast.Name):
        return bindings.callable_aliases.get(func.id)
    if isinstance(func, ast.Attribute):
        receiver = func.value
        if isinstance(receiver, ast.Name):
            cls_fqn = bindings.instance_classes.get(receiver.id)
            return f"{cls_fqn}.{func.attr}" if cls_fqn is not None else None
        if isinstance(receiver, ast.Call):
            ctor_fqn = _resolve_dotted(receiver.func, aliases)
            return f"{ctor_fqn}.{func.attr}" if ctor_fqn is not None else None
    return None


def resolved_sink_calls(
    func_node: ast.AST,
    sink_names: frozenset[str],
    alias_map: Mapping[str, str] | None = None,
    module_prefix: str = "",
    *,
    module_bindings: SinkBindings | None = None,
) -> Iterator[tuple[ast.Call, str]]:
    """:func:`sink_calls` plus binding-aware resolution — a strict superset.

    Yields ``(call, canonical_fqn)`` for own-scope calls matching *sink_names* via
    EITHER the direct dotted/import-aliased spelling (the :func:`sink_calls` path)
    OR a name binding: construct-then-method (``c = httpx.Client(); c.get(u)`` /
    ``with httpx.Client() as c`` / ``c: httpx.Client`` / chained
    ``httpx.Client().get(u)``) and callable aliases (``runner = subprocess.run;
    runner(...)``). Function-local bindings are collected from *func_node* and
    layered over *module_bindings* (pass :func:`collect_sink_bindings` of the
    module node to honor module-level assignments).

    Binding resolution is last-binding-wins (see :func:`collect_sink_bindings`),
    so the yield for a rebound var reflects its FINAL statically-known class.
    """
    aliases = dict(alias_map or {})
    bindings = collect_sink_bindings(func_node, aliases, module_prefix, parent=module_bindings)
    for call in _own_calls(func_node):
        fqn = _direct_sink_fqn(call, sink_names, aliases, module_prefix)
        if fqn is None:
            bound = resolve_bound_call_fqn(call, bindings, aliases, module_prefix)
            if bound is not None and bound in sink_names:
                fqn = bound
        if fqn is not None:
            yield call, fqn


def module_for_qualname(qualname: str, context: AnalysisContext) -> str | None:
    """The longest module prefix of *qualname* known to ``context.alias_maps``.

    THE single longest-prefix module resolver for the rule layer (consolidation,
    review 2026-06-10 — this used to exist as five per-rule private clones)."""
    modules = context.alias_maps.keys()
    for module in sorted(modules, key=len, reverse=True):
        if qualname == module or qualname.startswith(module + "."):
            return module
    return None


def module_alias_map(qualname: str, context: AnalysisContext) -> Mapping[str, str]:
    """Import alias map of *qualname*'s module (longest module-prefix match), or empty."""
    module = module_for_qualname(qualname, context)
    return context.alias_maps.get(module, {}) if module is not None else {}


def resolved_arg_taints(call: ast.Call, qualname: str, context: AnalysisContext) -> dict[int | str | None, TaintState]:
    """Per-argument resolved taints for *call* — THE single fail-closed argument resolver.

    Returns the engine's flow-sensitive per-call-site snapshot
    (``function_call_site_arg_taints`` — the resolved taint of each argument AT the call
    line), keyed by positional index (``int``), keyword name (``str``), ``None``
    (``**kwargs``), and a ``"*{i}"`` marker alongside the int key for a ``Starred``
    positional. Empty dict when the call takes no arguments.

    Fail-closed: when no L2 snapshot exists for *call* (an L2-skipped function), the
    qualname is recorded into ``context.flow_insensitive_fallbacks`` and a pessimistic
    map marking every syntactic argument ``UNKNOWN_RAW`` is returned. The analyzer
    surfaces the recorded set as ONE ``WLN-ENGINE-FLOW-INSENSITIVE-FALLBACK``
    NONE/FACT finding per scan in addition to the gate-eligible function skip — a
    finding, not a ``UserWarning``, so MCP/library consumers see the degradation and
    a warnings-as-error embedder cannot turn the diagnostic into a rule-aborting raise
    (review 2026-06-10). Each rule then
    SELECTS over this result on its own terms (worst / any-provably-untrusted /
    by-position), so the fail-closed contract lives in exactly one place and cannot
    drift between rules. The pessimism is correctly direction-aware: a
    RAW_ZONE-gate (sink rules / a SQL-string position) still fires on the
    UNKNOWN_RAW fallback, while a *provably*-untrusted gate (PY-WL-105, which excludes
    UNKNOWN_RAW) correctly stays silent — preserving its deliberate no-flood design."""
    snapshot = context.function_call_site_arg_taints.get(qualname, {}).get(id(call))
    if snapshot is not None:
        return dict(snapshot)

    # Flow-sensitive snapshot is missing. Record the degradation (surfaced by the
    # analyzer as one FACT finding per scan) and build a pessimistic per-arg map.
    context.flow_insensitive_fallbacks.add(qualname)
    pessimistic: dict[int | str | None, TaintState] = {}
    for i, arg in enumerate(call.args):
        pessimistic[i] = TaintState.UNKNOWN_RAW
        if isinstance(arg, ast.Starred):
            pessimistic[f"*{i}"] = TaintState.UNKNOWN_RAW
    for kw in call.keywords:
        pessimistic[kw.arg] = TaintState.UNKNOWN_RAW
    return pessimistic


def worst_arg_taint(call: ast.Call, qualname: str, context: AnalysisContext) -> TaintState | None:
    """The LEAST-trusted (highest TRUST_RANK) resolvable argument taint of *call*, or
    None when no argument resolves. Positional + keyword args are considered.

    Thin selector over :func:`resolved_arg_taints` (the shared fail-closed resolver):
    when no snapshot exists, that resolver yields a pessimistic ``UNKNOWN_RAW`` per arg,
    so a call with arguments still resolves to ``UNKNOWN_RAW`` (fail-closed)."""
    worst: TaintState | None = None
    for ts in resolved_arg_taints(call, qualname, context).values():
        if ts is not None and (worst is None or TRUST_RANK[ts] > TRUST_RANK[worst]):
            worst = ts
    return worst


def worst_dangerous_arg_taint(
    call: ast.Call,
    qualname: str,
    context: AnalysisContext,
    spec: ArgSpec | None = None,
) -> TaintState | None:
    """The LEAST-trusted resolvable taint over ONLY the dangerous arg slots of *call*.

    ``spec is None`` → exactly :func:`worst_arg_taint` (worst of ALL args — the
    backward-compatible default for sinks with no :class:`ArgSpec`). With a spec,
    only the declared positional indices and keyword names are considered, so a
    raw value in a non-dangerous slot (``requests.get(url, raw_body)`` with
    ``positions=(0,)``) no longer drives the verdict. Returns None when no
    dangerous slot resolves (including an empty spec — "no dangerous slots").

    Fail-closed widening over the splat forms, where syntactic slots stop mapping
    to runtime slots: a ``*args`` positional makes EVERY positional slot's taint
    eligible when the spec names any position (the star may fill any of them);
    a ``**kwargs`` taint is eligible when the spec names any keyword. The
    underlying per-slot taints come from :func:`resolved_arg_taints`, so the
    missing-snapshot pessimistic ``UNKNOWN_RAW`` fallback applies unchanged.
    """
    if spec is None:
        return worst_arg_taint(call, qualname, context)
    taints = resolved_arg_taints(call, qualname, context)
    worst: TaintState | None = None
    for key in _eligible_slot_keys(call, taints, spec):
        ts = taints[key]
        if ts is not None and (worst is None or TRUST_RANK[ts] > TRUST_RANK[worst]):
            worst = ts
    return worst


def _eligible_slot_keys(
    call: ast.Call,
    taints: Mapping[int | str | None, TaintState],
    spec: ArgSpec | None,
) -> set[int | str | None]:
    """The slot keys of *taints* eligible for a sink's taint verdict under *spec*.

    ``spec is None`` → every key (the historical worst-of-ALL-args selector).
    Otherwise the declared positional indices and keyword names, with the
    fail-closed splat widening :func:`worst_dangerous_arg_taint` documents."""
    if spec is None:
        return set(taints)
    keys: set[int | str | None] = set()
    keys.update(p for p in spec.positions if p in taints)
    keys.update(kw for kw in spec.keywords if kw in taints)
    if spec.positions and any(isinstance(arg, ast.Starred) for arg in call.args):
        # positional indices are unreliable past a *args — widen to every positional slot
        keys.update(k for k in taints if isinstance(k, int) or (isinstance(k, str) and k.startswith("*")))
    if spec.keywords and None in taints:  # **kwargs may supply any keyword
        keys.add(None)
    return keys


def _slot_expr(call: ast.Call, key: int | str | None) -> ast.expr | None:
    """The argument AST expression behind one :func:`resolved_arg_taints` slot key,
    or None for the slots that cannot be syntactically attributed (``**kwargs`` →
    ``None`` key, ``*args`` → ``"*{i}"`` marker)."""
    if isinstance(key, int):
        if 0 <= key < len(call.args) and not isinstance(call.args[key], ast.Starred):
            return call.args[key]
        return None
    if isinstance(key, str) and not key.startswith("*"):
        for kw in call.keywords:
            if kw.arg == key:
                return kw.value
    return None


def collect_ctor_call_nodes(
    node: ast.AST,
    alias_map: Mapping[str, str] | None = None,
    ctor_fqns: frozenset[str] | None = None,
) -> dict[str, ast.Call]:
    """Own-scope var → LAST constructor :class:`ast.Call` bound to it (source order).

    Companion to :func:`collect_sink_bindings`: that map resolves the var's class
    FQN (and is the GATE — it invalidates on every unresolvable rebind), while this
    one supplies the constructor call NODE a receiver-anchored taint is read from.
    Binding forms that carry a call are recorded (``v = Cls(...)``, ``with Cls(...)
    as v``, walrus, ``v: T = Cls(...)``) plus the ``w = v`` copy of an existing
    entry; a non-call, non-copy rebind drops the entry. A residual stale entry is
    harmless: the bindings gate already refused to resolve the method call.

    *ctor_fqns* optionally restricts recording to constructors whose canonical
    dotted FQN (through *alias_map*) is in the set — ``None`` records every call.
    """
    aliases = dict(alias_map or {})
    ctors: dict[str, ast.Call] = {}

    def bind(name: str, value: ast.expr) -> None:
        if isinstance(value, ast.NamedExpr):
            value = value.value
        if isinstance(value, ast.Call):
            if ctor_fqns is None:
                ctors[name] = value
                return
            fqn = _resolve_dotted(value.func, aliases)
            if fqn is not None and fqn in ctor_fqns:
                ctors[name] = value
            else:
                ctors.pop(name, None)
        elif isinstance(value, ast.Name) and value.id in ctors:
            ctors[name] = ctors[value.id]  # w = v — copy the binding
        else:
            ctors.pop(name, None)

    def walk(parent: ast.AST) -> None:
        for child in ast.iter_child_nodes(parent):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue  # nested scopes are their own entities
            if isinstance(child, ast.Assign) and len(child.targets) == 1 and isinstance(child.targets[0], ast.Name):
                bind(child.targets[0].id, child.value)
            elif isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name):
                if child.value is not None:
                    bind(child.target.id, child.value)
            elif isinstance(child, ast.NamedExpr) and isinstance(child.target, ast.Name):
                bind(child.target.id, child.value)
            elif isinstance(child, (ast.With, ast.AsyncWith)):
                for item in child.items:
                    if isinstance(item.optional_vars, ast.Name):
                        bind(item.optional_vars.id, item.context_expr)
            walk(child)

    walk(node)
    return ctors


def receiver_ctor_call(call: ast.Call, ctor_nodes: Mapping[str, ast.Call]) -> ast.Call | None:
    """The constructor call that built *call*'s receiver: the chained receiver itself
    (``Cls(raw).method()``) or the bound var's recorded constructor, else None."""
    if not isinstance(call.func, ast.Attribute):
        return None
    receiver = call.func.value
    if isinstance(receiver, ast.Call):
        return receiver
    if isinstance(receiver, ast.Name):
        return ctor_nodes.get(receiver.id)
    return None


def build_sink_finding(
    *,
    rule_id: str,
    entity: Entity,
    qualname: str,
    call: ast.Call,
    dotted: str,
    severity: Severity,
    tier: TaintState,
    worst: TaintState,
    sink_label: str,
    message: str | None = None,
) -> Finding:
    """THE shared sink-finding constructor — one message shape, one wlfp2
    discriminator, one properties dict for every call-site-anchored sink rule.

    Call-site-anchored: >1 finding per (rule, path, qualname) is possible (several
    sinks in one function). Discriminate by SOURCE only — an ENTITY-RELATIVE line
    offset (call line - the enclosing def's line, invariant to a comment ABOVE the
    function: wlfp2/wardline-8654423823) plus the call's full lexical SPAN and the
    sink dotted-name. The span (start:end), not the start column alone, separates
    the outer/inner calls of a chain (``a.sink(x).sink(y)``), which share a start
    column. Never the resolved arg taint (it drifts across builds: weft-4a9d0f863c).

    *message* overrides the standard message text only — fingerprint and
    properties stay uniform (PathTraversal's receiver-anchored explanations).
    """
    line = call.lineno
    return Finding(
        rule_id=rule_id,
        message=message
        or (f"{qualname}: {worst.value} (untrusted) data reaches the {sink_label} sink {dotted}() at line {line}"),
        severity=severity,
        kind=Kind.DEFECT,
        location=Location(
            path=entity.location.path,
            line_start=line,
            line_end=getattr(call, "end_lineno", line),
            col_start=getattr(call, "col_offset", None),
            col_end=getattr(call, "end_col_offset", None),
        ),
        fingerprint=_fp(
            rule_id=rule_id,
            path=entity.location.path,
            qualname=qualname,
            taint_path=f"{line - (entity.location.line_start or 0)}:{call.col_offset}:{call.end_col_offset}:{dotted}",
        ),
        # OLD (wlfp1) taint_path, byte-exact, for `wardline rekey` (P4).
        taint_path_v0=f"{dotted}@{call.col_offset}:{call.end_col_offset}",
        qualname=qualname,
        properties={"tier": tier.value, "sink": dotted, "arg_taint": worst.value},
    )


class TaintedSinkRule:
    """THE base for the call-site-anchored dangerous-sink rules — raw-zone data
    reaching a named sink inside a trusted-tier function. Tier-MODULATED — silent in
    the developer-freedom zone (undecorated → UNKNOWN_RAW → modulate → NONE),
    speaking only where trust is declared (the same opt-in/fail-closed discipline
    as 103/104).

    Consolidated 2026-06-10 (review): this single ``check`` loop replaces the two
    former mixins (108/112's ``BindingAwareSinkCheckMixin``, the 121–126 family's
    ``SpecSinkCheckMixin``) and the SSRF/deserialization rule-local overrides. The
    loop is binding-aware (:func:`resolved_sink_calls`, layered over
    ``context.module_bindings`` — a strict superset of the old direct-spelling
    match, so the historical base rules gain construct-then-method and
    callable-alias resolution as NEW findings with zero fingerprint drift), and is
    parameterized by:

    * ``SINK_SPECS`` — per-sink :class:`ArgSpec` slot precision (missing/``None``
      entry → the historical worst-of-all-args selector);
    * ``SINK_SEVERITIES`` — per-sink base severity, applied BEFORE tier
      modulation (PY-WL-121's lxml-vs-stdlib split). An operator
      ``rules.severity`` override re-bases the WHOLE rule: the registry passes
      ``base_severity`` only when the config carries an override, recorded as
      ``self.severity_overridden`` — an explicit flag, never inferred by value
      identity, so an override EQUAL to the metadata default still wins;
    * hook :meth:`_accept_call` — extra per-call gate after the sink-name match
      (112's literal ``shell=True``, 106's numpy/torch literal-keyword gates);
    * hook :meth:`_arg_guarded` — per-slot syntactic neutralization (108's
      ``shlex.quote`` concatenation guard);
    * hook :meth:`_taint_anchor_call` — redirects the taint read to another call
      (106's ``pickle.Unpickler(stream).load()`` reads the CONSTRUCTOR's stream
      argument); ``None`` skips the call.

    Subclasses set ``rule_id``, ``metadata``, ``SINKS`` (the curated dotted sink
    names), and ``sink_label`` (for the message). Plain (not ClassVar) annotations
    so the instances satisfy the ``_Rule`` protocol (a settable instance
    ``rule_id``)."""

    rule_id: str
    metadata: RuleMetadata
    SINKS: frozenset[str]
    sink_label: str

    SINK_SPECS: Mapping[str, ArgSpec | None] = {}
    SINK_SEVERITIES: Mapping[str, Severity] = {}

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        missing = [a for a in ("rule_id", "metadata", "SINKS", "sink_label") if not hasattr(cls, a)]
        if missing:  # fail at import time, not at first check() — a config error in our own tree
            raise TypeError(f"{cls.__name__} must define class attribute(s): {', '.join(missing)}")

    def __init__(self, base_severity: Severity | None = None) -> None:
        # The registry passes base_severity ONLY for an operator rules.severity
        # override (build_default_registry), so presence IS the override signal —
        # value identity against the metadata default would silently ignore an
        # explicit override equal to that default (review 2026-06-10).
        self.severity_overridden = base_severity is not None
        self.base_severity = base_severity or self.metadata.base_severity

    def _accept_call(self, call: ast.Call, fqn: str) -> bool:  # noqa: ARG002, PLR6301
        """Extra per-call gate after the SINK-name match. Default: accept."""
        return True

    def _arg_guarded(self, expr: ast.expr, fqn: str, alias_map: Mapping[str, str]) -> bool:  # noqa: ARG002, PLR6301
        """Whether one argument slot of sink *fqn* is syntactically neutralized
        (excluded from the worst-taint selection). Default: never."""
        return False

    def _taint_anchor_call(  # noqa: PLR6301
        self,
        call: ast.Call,
        fqn: str,  # noqa: ARG002
        entity_node: ast.AST,  # noqa: ARG002
        alias_map: Mapping[str, str],  # noqa: ARG002
    ) -> ast.Call | None:
        """The call whose arguments carry the sink's dangerous data — *call* itself
        by default. An override may redirect (a reader-method sink reads its
        CONSTRUCTOR's arguments) or return ``None`` to skip (no resolvable anchor)."""
        return call

    def _worst_sink_arg_taint(
        self,
        call: ast.Call,
        fqn: str,
        qualname: str,
        context: AnalysisContext,
        alias_map: Mapping[str, str],
    ) -> TaintState | None:
        """The LEAST-trusted taint over the sink's dangerous, unguarded arg slots.

        Slot selection honors the sink's :class:`ArgSpec` from ``SINK_SPECS``
        (missing/``None`` → every slot, the historical worst-of-all-args), then
        :meth:`_arg_guarded` excludes syntactically neutralized slots. Slots with
        no attributable expression (``*args`` / ``**kwargs``) are never guarded —
        the fail-closed default."""
        taints = resolved_arg_taints(call, qualname, context)
        worst: TaintState | None = None
        for key in _eligible_slot_keys(call, taints, self.SINK_SPECS.get(fqn)):
            ts = taints[key]
            if ts is None:
                continue
            expr = _slot_expr(call, key)
            if expr is not None and self._arg_guarded(expr, fqn, alias_map):
                continue
            if worst is None or TRUST_RANK[ts] > TRUST_RANK[worst]:
                worst = ts
        return worst

    def check(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for qualname, entity in context.entities.items():
            # Honor a nested def's OWN trust decorator, else inherit the nearest declared
            # enclosing scope's tier (wardline-bb8396f96e / wardline-9b88ec5419).
            tier = enclosing_declared_tier(qualname, context.project_taints, context.declared_qualnames)
            if modulate(self.base_severity, tier) == Severity.NONE:
                continue  # freedom / fail-closed zone — NONE for every base, so skip the entity
            module = module_for_qualname(qualname, context)
            alias_map = context.alias_maps.get(module, {}) if module is not None else {}
            module_bindings = context.module_bindings.get(module or "")
            for call, dotted in resolved_sink_calls(
                entity.node, self.SINKS, alias_map, module or "", module_bindings=module_bindings
            ):
                if not self._accept_call(call, dotted):
                    continue
                base = (
                    self.base_severity
                    if self.severity_overridden
                    else self.SINK_SEVERITIES.get(dotted, self.base_severity)
                )
                severity = modulate(base, tier)
                anchor = self._taint_anchor_call(call, dotted, entity.node, alias_map)
                if anchor is None:
                    continue  # no resolvable taint anchor — bounded FN, never a guess
                worst = self._worst_sink_arg_taint(anchor, dotted, qualname, context, alias_map)
                if worst is None or worst not in RAW_ZONE:
                    continue
                findings.append(
                    build_sink_finding(
                        rule_id=self.rule_id,
                        entity=entity,
                        qualname=qualname,
                        call=call,
                        dotted=dotted,
                        severity=severity,
                        tier=tier,
                        worst=worst,
                        sink_label=self.sink_label,
                    )
                )
        return findings
