# src/wardline/scanner/taint/callgraph.py
"""Call-edge extraction for the L3 project graph.

For each function entity, resolve its body's call sites to project FQNs and
count resolved/unresolved sites. Resolution order per call:
  1. ``resolve_call_fqn`` — local bare-name functions + imported aliases;
  2. ``resolve_self_method_fqn`` — ``self``/``cls`` method calls against the
     caller's enclosing class (recovers the SP1c self-method under-taint gap);
  3. same-project classmethod calls through a class object, such as
     ``Cls.helper(...)``.
A call resolving to a project FQN becomes an edge; everything else (externals,
constructors, closure-captured self) counts as unresolved — the unresolved count
raises the caller's pessimistic floor in the kernel. Variable-typed dispatch
(``o = Cls(); o.m()``) is resolved through a FLOW-SENSITIVE reaching-definitions pass
(``_candidate_receiver_classes``): the classes a receiver MAY hold on a path reaching
the call (branch arms unioned at joins, straight-line reassignment REPLACES, loop body
to a fixpoint). With one reaching class the call resolves single-valued (deterministic);
with >= 2 the full candidate set is recorded in ``call_site_candidate_callees`` so a
sink rule fires on any trusted-sink candidate regardless of AST order
(wardline-499c22bbdd). This replaces the former flat AST-order-dependent last-write-wins
pre-pass, so the single-valued ``call_site_callees`` (which drives edge/count/param-meet)
is now the deterministic reaching-set representative, not the textually-last assignment.

Nested-scope calls are excluded via ``iter_calls_in_function_body`` (they belong
to the nested entity). Module-scope header/decorator calls are not attributed to
any entity by construction (no module entity exists) — correct, since a
decorator call's taint does not flow into the decorated body.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator, Sequence

from wardline.scanner.ast_primitives import (
    iter_calls_in_function_body,
    resolve_call_fqn,
    resolve_self_method_fqn,
)
from wardline.scanner.index import Entity


def _own_nodes_in(node: ast.AST) -> Iterator[ast.AST]:
    """Yield *node* and every descendant in its own scope (including *node* itself), not
    descending into nested def/class/lambda scopes."""
    yield node
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield from _own_nodes_in(child)


def _target_names(target: ast.expr) -> Iterator[str]:
    """Yield the plain ``Name`` ids bound by an assignment/loop target (recursing into
    tuple/list/starred destructuring); attribute/subscript targets bind no local name."""
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, ast.Starred):
        yield from _target_names(target.value)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            yield from _target_names(elt)


def _candidate_receiver_classes(
    func: ast.AST,
    *,
    alias_map: dict[str, str],
    module_prefix: str,
    class_qualnames: frozenset[str],
    known_fqns: frozenset[str],
) -> dict[int, frozenset[str]]:
    """Flow-sensitive reaching-definitions pass over *func*'s own scope.

    Returns ``{id(call): frozenset(class_fqn)}`` for each ``recv.method()`` call site,
    giving the set of project classes the receiver name MAY hold ON A PATH REACHING THAT
    CALL. Branch arms are unioned only at their join; a straight-line reassignment REPLACES
    (kills) the prior binding. So a linear ``o=A(); o=B(); o.m()`` resolves to ``{B}`` (no
    spurious widening), and an in-arm ``if: o=A(); o.m()`` sees only ``{A}`` — eliminating
    the flow-insensitive over-approximation that a flat whole-function union would produce
    (wardline-499c22bbdd). Mirrors the merge discipline of ``variable_level``'s taint walk.
    """
    candidates_at_call: dict[int, frozenset[str]] = {}

    def resolve_class(value: ast.expr | None, env: dict[str, set[str]]) -> set[str]:
        if isinstance(value, ast.NamedExpr):  # ``(x := expr)`` evaluates to expr
            value = value.value
        if isinstance(value, ast.Call):
            fqn = resolve_call_fqn(value, alias_map, known_fqns, module_prefix)
            return {fqn} if fqn in class_qualnames else set()
        if isinstance(value, ast.Name):
            return set(env.get(value.id, set()))
        return set()

    def record(node: ast.AST, env: dict[str, set[str]]) -> None:
        # Walk the expression in own scope, recording dispatch call sites and applying any
        # walrus rebinds (``(o := Plain())`` REPLACES o's class binding, killing a stale
        # earlier one — else a sink rule fires on a class o can no longer be, an FP).
        for sub in _own_nodes_in(node):
            if (
                isinstance(sub, ast.Call)
                and isinstance(sub.func, ast.Attribute)
                and isinstance(sub.func.value, ast.Name)
            ):
                classes = env.get(sub.func.value.id)
                if classes:
                    candidates_at_call[id(sub)] = frozenset(classes)
            elif isinstance(sub, ast.NamedExpr) and isinstance(sub.target, ast.Name):
                bind([sub.target], sub.value, env)

    def bind(targets: list[ast.expr], value: ast.expr | None, env: dict[str, set[str]]) -> None:
        classes = resolve_class(value, env)
        for target in targets:
            for name in _target_names(target):
                if classes:
                    env[name] = set(classes)  # REPLACE — a reassignment kills the prior binding
                else:
                    env.pop(name, None)  # assigned a non-class / unknown value → unbind

    def unbind(targets: list[ast.expr], env: dict[str, set[str]]) -> None:
        for target in targets:
            for name in _target_names(target):
                env.pop(name, None)

    def merge(into: dict[str, set[str]], *envs: dict[str, set[str]]) -> None:
        names: set[str] = set(into)
        for env in envs:
            names |= set(env)
        for name in names:
            union: set[str] = set()
            for env in envs:
                union |= env.get(name, set())
            if union:
                into[name] = union
            else:
                into.pop(name, None)

    def walk(stmts: list[ast.stmt], env: dict[str, set[str]]) -> None:
        for stmt in stmts:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue  # nested scope — a separate entity
            if isinstance(stmt, ast.If):
                record(stmt.test, env)
                body_env = {k: set(v) for k, v in env.items()}
                else_env = {k: set(v) for k, v in env.items()}
                walk(stmt.body, body_env)
                walk(stmt.orelse, else_env)
                env.clear()
                merge(env, body_env, else_env)
            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                loop_targets = [stmt.target] if isinstance(stmt, (ast.For, ast.AsyncFor)) else []
                record(stmt.test if isinstance(stmt, ast.While) else stmt.iter, env)
                pre_env = {k: set(v) for k, v in env.items()}
                # Loop-carried fixpoint: a receiver rebound near the END of the body is
                # visible to a call EARLIER in the body on the next iteration. Walk the body
                # to convergence, feeding the end-of-body env back to the entry, so a
                # top-of-body dispatch sees every class the receiver may carry across
                # iterations (wardline-499c22bbdd). Monotone union over a finite class set →
                # converges; the backstop is keyed to the COPY-CHAIN DEPTH (the number of
                # names assigned in the body, the dimension a binding propagates one link per
                # iteration along — NOT the class count, which is unrelated). The early break
                # fires at real convergence; the backstop is a never-hit termination net.
                loop_names = {
                    n.id
                    for s in stmt.body
                    for n in _own_nodes_in(s)
                    if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)
                }
                entry = {k: set(v) for k, v in env.items()}
                unbind(loop_targets, entry)  # loop var binds an element, not a class
                body_env = dict(entry)
                for _ in range(len(loop_names) + 2):
                    body_env = {k: set(v) for k, v in entry.items()}
                    walk(stmt.body, body_env)
                    widened: dict[str, set[str]] = {}
                    merge(widened, entry, body_env)
                    unbind(loop_targets, widened)
                    if widened == entry:
                        break
                    entry = widened
                env.clear()
                merge(env, pre_env, body_env)  # body may run 0+ times
                unbind(loop_targets, env)
                walk(stmt.orelse, env)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    record(item.context_expr, env)
                    if item.optional_vars is not None:
                        unbind([item.optional_vars], env)  # `as o` binds the context manager
                walk(stmt.body, env)
            elif isinstance(stmt, (ast.Try, ast.TryStar)):
                body_env = {k: set(v) for k, v in env.items()}
                walk(stmt.body, body_env)
                else_env = {k: set(v) for k, v in body_env.items()}
                walk(stmt.orelse, else_env)
                arm_envs = [else_env]
                for handler in stmt.handlers:
                    h_env = {k: set(v) for k, v in env.items()}
                    walk(handler.body, h_env)
                    arm_envs.append(h_env)
                env.clear()
                merge(env, *arm_envs)
                walk(stmt.finalbody, env)  # always runs
            elif isinstance(stmt, ast.Assign):
                record(stmt, env)
                bind(stmt.targets, stmt.value, env)
            elif isinstance(stmt, ast.AnnAssign):
                record(stmt, env)
                if stmt.value is not None:
                    bind([stmt.target], stmt.value, env)
            else:
                record(stmt, env)

    body = getattr(func, "body", None)
    if isinstance(body, list):
        walk(body, {})
    return candidates_at_call


def build_call_edges(
    *,
    entities: Sequence[Entity],
    class_qualnames: frozenset[str],
    alias_map: dict[str, str],
    module_prefix: str,
    project_fqns: frozenset[str],
) -> tuple[
    dict[str, frozenset[str]],
    dict[str, int],
    dict[str, int],
    dict[int, str],
    dict[int, str],
    dict[int, frozenset[str]],
]:
    """Resolve intra-/inter-module call edges for one module's entities.

    Returns ``(edges, resolved_counts, unresolved_counts, call_site_callees,
    call_site_implicit_receivers, call_site_candidate_callees)`` keyed by caller
    qualname. ``edges[caller]`` is the set of resolved project callee FQNs; counts
    are per-call-site (a callee reached twice counts twice toward ``resolved_counts``
    but appears once in the edge set). ``call_site_implicit_receivers`` records
    resolved call sites whose explicit positional arguments start after an implicit
    receiver parameter; values are ``"instance"`` or ``"class"``.
    ``call_site_candidate_callees`` records, for a branch-conditional receiver assigned
    a project class in more than one arm, the FULL set of candidate callee FQNs (a
    superset of the single ``call_site_callees`` entry) so a sink rule can fire on any
    trusted-sink candidate regardless of AST order (wardline-499c22bbdd).
    """
    edges: dict[str, frozenset[str]] = {}
    resolved_counts: dict[str, int] = {}
    unresolved_counts: dict[str, int] = {}
    call_site_callees: dict[int, str] = {}
    call_site_implicit_receivers: dict[int, str] = {}
    call_site_candidate_callees: dict[int, frozenset[str]] = {}
    entity_by_fqn = {entity.qualname: entity for entity in entities}
    # Hoisted out of _candidate_receiver_classes: the union is O(project) and was
    # rebuilt once PER FUNCTION, an O(n^2) whole-scan term on large trees.
    known_fqns = project_fqns | class_qualnames  # resolve_call_fqn resolves constructors here

    def _decorator_name(decorator: ast.expr) -> str | None:
        if isinstance(decorator, ast.Call):
            return _decorator_name(decorator.func)
        if isinstance(decorator, ast.Name):
            return decorator.id
        if isinstance(decorator, ast.Attribute):
            return decorator.attr
        return None

    def _has_decorator(entity: Entity, name: str) -> bool:
        return any(_decorator_name(decorator) == name for decorator in entity.node.decorator_list)

    def _resolve_classmethod_call(call: ast.Call) -> str | None:
        if not isinstance(call.func, ast.Attribute) or not isinstance(call.func.value, ast.Name):
            return None
        receiver_name = call.func.value.id
        receiver_fqn = alias_map.get(receiver_name, f"{module_prefix}.{receiver_name}")
        if receiver_fqn not in class_qualnames:
            return None
        candidate = f"{receiver_fqn}.{call.func.attr}"
        entity = entity_by_fqn.get(candidate)
        if entity is None or not _has_decorator(entity, "classmethod"):
            return None
        return candidate

    for entity in entities:
        caller_class_fqn: str | None = entity.qualname.rsplit(".", 1)[0]
        if caller_class_fqn not in class_qualnames:
            caller_class_fqn = None

        # Flow-sensitive reaching-definitions pass: the SET of project classes each receiver
        # name MAY hold AT a given call site (branch arms unioned at joins, straight-line
        # reassignment REPLACES — so a linear kill o=A();o=B() does NOT widen, and an in-arm
        # call sees only that arm's binding). This is the SINGLE source for var-type call
        # resolution, replacing the former flat last-write-wins pre-pass which was itself
        # AST-order-dependent (the root of wardline-499c22bbdd, FP on trusted-last shapes).
        call_candidate_classes = _candidate_receiver_classes(
            entity.node,
            alias_map=alias_map,
            module_prefix=module_prefix,
            class_qualnames=class_qualnames,
            known_fqns=known_fqns,
        )

        callees: set[str] = set()
        resolved = 0
        unresolved = 0
        for call in iter_calls_in_function_body(entity.node):
            implicit_receiver: str | None = None
            target = resolve_call_fqn(call, alias_map, project_fqns, module_prefix)
            if target is not None and target in project_fqns:
                if _resolve_classmethod_call(call) is not None:
                    implicit_receiver = "class"
            else:
                target = resolve_self_method_fqn(
                    call,
                    caller_class_fqn=caller_class_fqn,
                    project_fqns=project_fqns,
                )
                if target is not None:
                    target_entity = entity_by_fqn.get(target)
                    if target_entity is not None and not _has_decorator(target_entity, "staticmethod"):
                        implicit_receiver = "class" if _has_decorator(target_entity, "classmethod") else "instance"
            if target is None or target not in project_fqns:
                target = _resolve_classmethod_call(call)
                if target is not None:
                    implicit_receiver = "class"
            if (
                (target is None or target not in project_fqns)
                and isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name)
            ):
                # Flow-sensitive var-type dispatch: resolve against the project classes the
                # receiver MAY hold AT this call site (reaching definitions). One class →
                # single resolution; >= 2 → record the full candidate callee set so a sink
                # rule fires on any trusted-sink candidate regardless of AST order, and pick
                # a deterministic representative for the single-valued edge/count/param-meet
                # (wardline-499c22bbdd). A linear reassignment or in-arm call yields exactly
                # the class live there, so neither over-fires.
                reaching = call_candidate_classes.get(id(call))
                cand_callees = (
                    sorted({f"{cls}.{call.func.attr}" for cls in reaching} & project_fqns) if reaching else []
                )
                if len(cand_callees) >= 2:
                    call_site_candidate_callees[id(call)] = frozenset(cand_callees)
                if cand_callees:
                    target = cand_callees[0]  # deterministic single-valued representative
                    target_entity = entity_by_fqn.get(target)
                    if target_entity is not None and _has_decorator(target_entity, "staticmethod"):
                        implicit_receiver = None
                    elif target_entity is not None and _has_decorator(target_entity, "classmethod"):
                        implicit_receiver = "class"
                    else:
                        implicit_receiver = "instance"
            if target is not None and target in project_fqns:
                callees.add(target)
                resolved += 1
                call_site_callees[id(call)] = target
                if implicit_receiver is not None:
                    call_site_implicit_receivers[id(call)] = implicit_receiver
            else:
                unresolved += 1

        edges[entity.qualname] = frozenset(callees)
        resolved_counts[entity.qualname] = resolved
        unresolved_counts[entity.qualname] = unresolved

    return (
        edges,
        resolved_counts,
        unresolved_counts,
        call_site_callees,
        call_site_implicit_receivers,
        call_site_candidate_callees,
    )
