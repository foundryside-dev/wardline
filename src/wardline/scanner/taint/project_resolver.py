# src/wardline/scanner/taint/project_resolver.py
"""Project-scope L3 resolver.

Assembles per-module parsed data + L1 seeds into the inter-module call graph,
runs the SCC fixed-point kernel, and returns a ``ResolverResult``. Diagnostics
ride on the result as ``(code, message)`` data (SP1f maps them to Findings);
the resolver emits no ``Finding`` itself.

An optional in-memory ``SummaryCache`` memoizes per-module summaries across
calls. The call graph (edges + resolved/unresolved counts) is ALWAYS recomputed
fresh and fed to the kernel; the cache stores only the source-determined taint
contract (body/return/source), which ``cache_key`` fully captures. Therefore a
warm run is byte-identical to a cold run — the ``cache_key`` is the correctness
gate, and the reverse-edge dirty frontier is a performance over-approximation
that only bounds which clean modules skip provider re-invocation (it cannot
affect taint correctness). Star imports are not yet materialised for edge
resolution (deferred).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from wardline.scanner.taint.callgraph import build_call_edges
from wardline.scanner.taint.module_summariser import summarise_module
from wardline.scanner.taint.propagation import propagate_callgraph_taints
from wardline.scanner.taint.resolver_metadata import ResolverResult, ResolverRunMetadata
from wardline.scanner.taint.reverse_edge_index import ReverseModuleIndex
from wardline.scanner.taint.summary import SUMMARY_SCHEMA_VERSION, TaintSourceClass, compute_cache_key
from wardline.scanner.taint.summary_cache import SummaryCache

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from wardline.core.taints import TaintState
    from wardline.scanner.index import Entity
    from wardline.scanner.taint.function_level import FunctionSeed
    from wardline.scanner.taint.summary import FunctionSummary

# Bumped sp1d→sp1e: engine taint behaviour changed (DB-fetch source seed, container-mutator
# write-back, loop fixpoint convergence, branch-conditional candidate callees) — invalidates
# persisted/warm summary caches so they cannot serve stale-CLEAN results (cf. wardline-9d6a81b9e7).
_RESOLVER_VERSION = "sp1e"


@dataclass(frozen=True, slots=True)
class ModuleInput:
    """Everything the resolver needs from one parsed module."""

    module_path: str
    entities: tuple[Entity, ...]
    class_qualnames: frozenset[str]
    alias_map: dict[str, str]
    seeds: Mapping[str, FunctionSeed]
    source_bytes: bytes


def _cached_summaries_match_module(
    module: ModuleInput,
    cache_key: str,
    summaries: tuple[FunctionSummary, ...],
) -> bool:
    if any(s.cache_key != cache_key for s in summaries):
        return False
    actual = tuple(s.fqn for s in summaries)
    if len(set(actual)) != len(actual):
        return False
    expected = frozenset(e.qualname for e in module.entities)
    return frozenset(actual) == expected


def resolve_project_taints(
    *,
    modules: Sequence[ModuleInput],
    provider_fingerprint: str,
    summary_cache: SummaryCache | None = None,
    dirty_modules: frozenset[str] | None = None,
    config: Any = None,
) -> ResolverResult:
    """Run whole-project transitive taint resolution over ``modules``.

    When ``summary_cache`` is supplied, ``dirty_modules`` MUST also be supplied
    (pass ``frozenset()`` for "nothing declared dirty"); the cache reuses
    summaries for clean, cache-hit modules and recomputes the rest. The result
    is identical to a cold run regardless — the cache only saves provider
    re-invocation.
    """
    if (summary_cache is None) != (dirty_modules is None):
        raise ValueError(
            "summary_cache and dirty_modules must be supplied together; pass "
            "dirty_modules=frozenset() explicitly if nothing has changed"
        )

    project_fqns = frozenset(e.qualname for m in modules for e in m.entities)
    all_classes = frozenset(c for m in modules for c in m.class_qualnames)

    edges: dict[str, frozenset[str]] = {}
    resolved_counts: dict[str, int] = {}
    unresolved_counts: dict[str, int] = {}
    call_site_callees: dict[int, str] = {}
    call_site_implicit_receivers: dict[int, str] = {}
    call_site_candidate_callees: dict[int, frozenset[str]] = {}
    for m in modules:
        (
            m_edges,
            m_resolved,
            m_unresolved,
            m_callees,
            m_implicit_receivers,
            m_candidate_callees,
        ) = build_call_edges(
            entities=m.entities,
            class_qualnames=all_classes,
            alias_map=m.alias_map,
            module_prefix=m.module_path,
            project_fqns=project_fqns,
        )
        edges.update(m_edges)
        resolved_counts.update(m_resolved)
        unresolved_counts.update(m_unresolved)
        call_site_callees.update(m_callees)
        call_site_implicit_receivers.update(m_implicit_receivers)
        call_site_candidate_callees.update(m_candidate_callees)

    # Transitive dirty frontier (performance over-approximation — bounds which
    # clean modules skip provider re-invocation; NOT a correctness gate).
    if summary_cache is not None and dirty_modules is not None:
        fqn_to_module = {e.qualname: m.module_path for m in modules for e in m.entities}
        frontier = ReverseModuleIndex.from_forward_edges(
            {k: set(v) for k, v in edges.items()},
            fqn_to_module=fqn_to_module,
        ).transitive_callers(dirty_modules)
    else:
        frontier = frozenset()

    # The effective-scan-policy identity (untrusted_sources / sanitisers / provenance_clash
    # shape summaries without changing source bytes). MUST match the dirty-detection key the
    # parse stage computed from the same config, exactly as provider_fingerprint must — else a
    # summary computed under one policy could be served under another (wardline-9d6a81b9e7).
    from wardline.core.attest import ruleset_hash
    from wardline.core.config import WardlineConfig

    scan_policy_hash = ruleset_hash(config if config is not None else WardlineConfig())

    # Per-module summaries: reuse cached for clean cache-hit modules, else fresh.
    summaries: list[FunctionSummary] = []
    for m in modules:
        cache_key = compute_cache_key(
            module_path=m.module_path,
            source_bytes=m.source_bytes,
            schema_version=SUMMARY_SCHEMA_VERSION,
            resolver_version=_RESOLVER_VERSION,
            provider_fingerprint=provider_fingerprint,
            scan_policy_hash=scan_policy_hash,
        )
        cached: tuple[FunctionSummary, ...] | None = None
        if summary_cache is not None and m.module_path not in frontier:
            cached = summary_cache.get(cache_key)
            if cached is not None and not _cached_summaries_match_module(m, cache_key, cached):
                summary_cache.invalidate(cache_key)
                cached = None
        if cached is not None:
            summaries.extend(cached)
            continue
        fresh = summarise_module(
            module_path=m.module_path,
            seeds=m.seeds,
            unresolved_counts=unresolved_counts,
            source_bytes=m.source_bytes,
            resolver_version=_RESOLVER_VERSION,
            provider_fingerprint=provider_fingerprint,
            scan_policy_hash=scan_policy_hash,
        )
        summaries.extend(fresh)
        if summary_cache is not None:
            summary_cache.put(cache_key, fresh)

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
        config=config,
    )

    # Effective return taint: anchored functions surface their DECLARED return
    # tier (L3 never refines anchored taints — see the post-fixed-point
    # assertions); non-anchored functions have body == return, so the refined
    # body taint is also their return. Callers building L2 call-resolution maps
    # must read THIS, not the body ``refined`` map, or a @trust_boundary's
    # validated output is mis-read as its raw body taint (an over-taint that
    # false-positives PY-WL-101).
    effective_return: dict[str, TaintState] = {
        fqn: (return_taint_map[fqn] if taint_sources.get(fqn) == "anchored" else refined[fqn]) for fqn in refined
    }

    scc_size_distribution = tuple(sorted(Counter(len(k) for k in scc_iteration_counts).items()))
    convergence_iterations_histogram = tuple(sorted(Counter(scc_iteration_counts.values()).items()))
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
        return_taint_map=MappingProxyType(effective_return),
        project_edges=MappingProxyType({fqn: frozenset(callees) for fqn, callees in edges.items()}),
        call_site_callees=MappingProxyType(call_site_callees),
        call_site_implicit_receivers=MappingProxyType(call_site_implicit_receivers),
        call_site_candidate_callees=MappingProxyType(call_site_candidate_callees),
        taint_provenance=MappingProxyType(dict(provenance)),
        diagnostics=tuple(diagnostics),
        metadata=metadata,
    )
