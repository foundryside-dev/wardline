# src/wardline/scanner/taint/project_resolver.py
"""Project-scope L3 resolver — cold path.

Assembles per-module parsed data + L1 seeds into the inter-module call graph,
runs the SCC fixed-point kernel, and returns a ``ResolverResult``. This is the
cold path only: there is no summary cache (SP1e) and no ``Finding`` emission
(SP1f) — kernel diagnostics ride on the result as ``(code, message)`` data.
Star imports are not yet materialised for edge resolution (deferred); the
multi-module graph resolves explicit imports + local + self/cls method calls.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING

from wardline.scanner.taint.callgraph import build_call_edges
from wardline.scanner.taint.module_summariser import summarise_module
from wardline.scanner.taint.propagation import propagate_callgraph_taints
from wardline.scanner.taint.resolver_metadata import ResolverResult, ResolverRunMetadata
from wardline.scanner.taint.summary import TaintSourceClass

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from wardline.core.taints import TaintState
    from wardline.scanner.index import Entity
    from wardline.scanner.taint.function_level import FunctionSeed

_RESOLVER_VERSION = "sp1d"


@dataclass(frozen=True, slots=True)
class ModuleInput:
    """Everything the resolver needs from one parsed module."""

    module_path: str
    entities: tuple[Entity, ...]
    class_qualnames: frozenset[str]
    alias_map: dict[str, str]
    seeds: Mapping[str, FunctionSeed]
    source_bytes: bytes


def resolve_project_taints(
    *,
    modules: Sequence[ModuleInput],
    provider_fingerprint: str,
) -> ResolverResult:
    """Run whole-project transitive taint resolution over ``modules``."""
    project_fqns = frozenset(
        e.qualname for m in modules for e in m.entities
    )
    all_classes = frozenset(c for m in modules for c in m.class_qualnames)

    edges: dict[str, frozenset[str]] = {}
    resolved_counts: dict[str, int] = {}
    unresolved_counts: dict[str, int] = {}
    for m in modules:
        m_edges, m_resolved, m_unresolved = build_call_edges(
            entities=m.entities,
            class_qualnames=all_classes,
            alias_map=m.alias_map,
            module_prefix=m.module_path,
            project_fqns=project_fqns,
        )
        edges.update(m_edges)
        resolved_counts.update(m_resolved)
        unresolved_counts.update(m_unresolved)

    # Summaries (the cacheable unit + cold-path intermediate).
    summaries = tuple(
        s
        for m in modules
        for s in summarise_module(
            seeds=m.seeds,
            unresolved_counts=unresolved_counts,
            source_bytes=m.source_bytes,
            resolver_version=_RESOLVER_VERSION,
            provider_fingerprint=provider_fingerprint,
        )
    )

    taint_map: dict[str, TaintState] = {s.fqn: s.body_taint for s in summaries}
    return_taint_map: dict[str, TaintState] = {s.fqn: s.return_taint for s in summaries}
    taint_sources: dict[str, TaintSourceClass] = {s.fqn: s.taint_source for s in summaries}

    refined, provenance, diagnostics, scc_iteration_counts = propagate_callgraph_taints(
        edges={k: set(v) for k, v in edges.items()},
        taint_map=taint_map,
        taint_sources=taint_sources,
        resolved_counts=resolved_counts,
        unresolved_counts=unresolved_counts,
        return_taint_map=return_taint_map,
    )

    scc_size_distribution = tuple(
        sorted(Counter(len(k) for k in scc_iteration_counts).items())
    )
    convergence_iterations_histogram = tuple(
        sorted(Counter(scc_iteration_counts.values()).items())
    )
    convergence_iterations_max = max(scc_iteration_counts.values(), default=0)
    taint_source_counts = Counter(taint_sources.values())
    metadata = ResolverRunMetadata(
        scc_size_distribution=scc_size_distribution,
        convergence_iterations_max=convergence_iterations_max,
        convergence_iterations_histogram=convergence_iterations_histogram,
        taint_source_counts={
            "anchored": taint_source_counts.get("anchored", 0),
            "module_default": taint_source_counts.get("module_default", 0),
            "fallback": taint_source_counts.get("fallback", 0),
        },
    )

    return ResolverResult(
        taint_map=MappingProxyType(refined),
        project_edges=MappingProxyType(
            {fqn: frozenset(callees) for fqn, callees in edges.items()}
        ),
        taint_provenance=MappingProxyType(dict(provenance)),
        diagnostics=tuple(diagnostics),
        metadata=metadata,
    )
