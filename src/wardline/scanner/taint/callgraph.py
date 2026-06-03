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
constructors, dynamic dispatch, closure-captured self) counts as unresolved —
the unresolved count raises the caller's pessimistic floor in the kernel.

Nested-scope calls are excluded via ``iter_calls_in_function_body`` (they belong
to the nested entity). Module-scope header/decorator calls are not attributed to
any entity by construction (no module entity exists) — correct, since a
decorator call's taint does not flow into the decorated body.
"""

from __future__ import annotations

import ast
from collections.abc import Sequence

from wardline.scanner.ast_primitives import (
    iter_calls_in_function_body,
    resolve_call_fqn,
    resolve_self_method_fqn,
)
from wardline.scanner.index import Entity


def build_call_edges(
    *,
    entities: Sequence[Entity],
    class_qualnames: frozenset[str],
    alias_map: dict[str, str],
    module_prefix: str,
    project_fqns: frozenset[str],
) -> tuple[dict[str, frozenset[str]], dict[str, int], dict[str, int], dict[int, str], dict[int, str]]:
    """Resolve intra-/inter-module call edges for one module's entities.

    Returns ``(edges, resolved_counts, unresolved_counts, call_site_callees,
    call_site_implicit_receivers)`` keyed by caller qualname. ``edges[caller]``
    is the set of resolved project callee FQNs; counts are per-call-site (a
    callee reached twice counts twice toward ``resolved_counts`` but appears
    once in the edge set). ``call_site_implicit_receivers`` records resolved
    call sites whose explicit positional arguments start after an implicit
    receiver parameter; values are ``"instance"`` or ``"class"``.
    """
    edges: dict[str, frozenset[str]] = {}
    resolved_counts: dict[str, int] = {}
    unresolved_counts: dict[str, int] = {}
    call_site_callees: dict[int, str] = {}
    call_site_implicit_receivers: dict[int, str] = {}
    entity_by_fqn = {entity.qualname: entity for entity in entities}

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

    return edges, resolved_counts, unresolved_counts, call_site_callees, call_site_implicit_receivers
