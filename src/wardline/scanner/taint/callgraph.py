# src/wardline/scanner/taint/callgraph.py
"""Call-edge extraction for the L3 project graph.

For each function entity, resolve its body's call sites to project FQNs and
count resolved/unresolved sites. Resolution order per call:
  1. ``resolve_call_fqn`` — local bare-name functions + imported aliases;
  2. ``resolve_self_method_fqn`` — ``self``/``cls`` method calls against the
     caller's enclosing class (recovers the SP1c self-method under-taint gap).
A call resolving to a project FQN becomes an edge; everything else (externals,
constructors, dynamic dispatch, closure-captured self) counts as unresolved —
the unresolved count raises the caller's pessimistic floor in the kernel.

Nested-scope calls are excluded via ``iter_calls_in_function_body`` (they belong
to the nested entity). Module-scope header/decorator calls are not attributed to
any entity by construction (no module entity exists) — correct, since a
decorator call's taint does not flow into the decorated body.
"""

from __future__ import annotations

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
) -> tuple[dict[str, frozenset[str]], dict[str, int], dict[str, int]]:
    """Resolve intra-/inter-module call edges for one module's entities.

    Returns ``(edges, resolved_counts, unresolved_counts)`` keyed by caller
    qualname. ``edges[caller]`` is the set of resolved project callee FQNs;
    counts are per-call-site (a callee reached twice counts twice toward
    ``resolved_counts`` but appears once in the edge set).
    """
    edges: dict[str, frozenset[str]] = {}
    resolved_counts: dict[str, int] = {}
    unresolved_counts: dict[str, int] = {}

    for entity in entities:
        caller_class_fqn: str | None = entity.qualname.rsplit(".", 1)[0]
        if caller_class_fqn not in class_qualnames:
            caller_class_fqn = None

        callees: set[str] = set()
        resolved = 0
        unresolved = 0
        for call in iter_calls_in_function_body(entity.node):
            target = resolve_call_fqn(call, alias_map, project_fqns, module_prefix)
            if target is None or target not in project_fqns:
                target = resolve_self_method_fqn(
                    call,
                    caller_class_fqn=caller_class_fqn,
                    project_fqns=project_fqns,
                )
            if target is not None and target in project_fqns:
                callees.add(target)
                resolved += 1
            else:
                unresolved += 1

        edges[entity.qualname] = frozenset(callees)
        resolved_counts[entity.qualname] = resolved
        unresolved_counts[entity.qualname] = unresolved

    return edges, resolved_counts, unresolved_counts
