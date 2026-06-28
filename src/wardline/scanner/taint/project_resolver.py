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

from wardline.core.config import WardlineConfig
from wardline.core.ruleset import ruleset_hash
from wardline.core.taints import combine
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
# Bumped sp1e→sp1f: FastAPI/starlette request-type SOURCE seeding (Part C, wardline-bd9d1e65cb)
# — a new taint-seeding behaviour, so warm/persisted summaries of a project's request-handler
# modules must recompute rather than serve their stale-CLEAN pre-upgrade results.
_RESOLVER_VERSION = "sp1f"


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


def _duplicate_fqn_diagnostics(modules: Sequence[ModuleInput]) -> tuple[tuple[str, str], ...]:
    locations_by_fqn: dict[str, list[str]] = {}
    for module in modules:
        for entity in module.entities:
            line = entity.location.line_start if entity.location.line_start is not None else 1
            locations_by_fqn.setdefault(entity.qualname, []).append(
                f"{module.module_path} ({entity.location.path}:{line})"
            )

    diagnostics: list[tuple[str, str]] = []
    for fqn in sorted(locations_by_fqn):
        locations = locations_by_fqn[fqn]
        if len(locations) < 2:
            continue
        preview = ", ".join(locations[:5])
        if len(locations) > 5:
            preview += f", ... ({len(locations)} total)"
        diagnostics.append(
            (
                "DUPLICATE_FQN",
                (
                    f"Duplicate function qualname {fqn!r} across {len(locations)} entities: {preview}; "
                    "project taint summaries are keyed by qualname and cannot disambiguate these definitions"
                ),
            )
        )
    return tuple(diagnostics)


def _merge_edges(target: dict[str, frozenset[str]], new: dict[str, frozenset[str]]) -> None:
    for fqn, callees in new.items():
        existing = target.get(fqn)
        target[fqn] = callees if existing is None else frozenset((*existing, *callees))


def _add_counts(target: dict[str, int], new: dict[str, int]) -> None:
    for fqn, count in new.items():
        target[fqn] = target.get(fqn, 0) + count


def _merge_taint_source(existing: TaintSourceClass, incoming: TaintSourceClass) -> TaintSourceClass:
    if existing == incoming:
        return existing
    return "fallback"


def _merge_summary_maps(
    summaries: Sequence[FunctionSummary],
) -> tuple[dict[str, TaintState], dict[str, TaintState], dict[str, TaintSourceClass]]:
    taint_map: dict[str, TaintState] = {}
    return_taint_map: dict[str, TaintState] = {}
    taint_sources: dict[str, TaintSourceClass] = {}
    for summary in summaries:
        if summary.fqn in taint_map:
            taint_map[summary.fqn] = combine(taint_map[summary.fqn], summary.body_taint)
            return_taint_map[summary.fqn] = combine(return_taint_map[summary.fqn], summary.return_taint)
            taint_sources[summary.fqn] = _merge_taint_source(taint_sources[summary.fqn], summary.taint_source)
            continue
        taint_map[summary.fqn] = summary.body_taint
        return_taint_map[summary.fqn] = summary.return_taint
        taint_sources[summary.fqn] = summary.taint_source
    return taint_map, return_taint_map, taint_sources


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

    resolver_diagnostics = list(_duplicate_fqn_diagnostics(modules))
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
        _merge_edges(edges, m_edges)
        _add_counts(resolved_counts, m_resolved)
        _add_counts(unresolved_counts, m_unresolved)
        call_site_callees.update(m_callees)
        call_site_implicit_receivers.update(m_implicit_receivers)
        call_site_candidate_callees.update(m_candidate_callees)

    # Transitive dirty frontier (performance over-approximation — bounds which
    # clean modules skip provider re-invocation; NOT a correctness gate).
    if summary_cache is not None and dirty_modules is not None:
        fqn_to_module: dict[str, str] = {}
        for m in modules:
            for e in m.entities:
                fqn_to_module.setdefault(e.qualname, m.module_path)
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

    taint_map, return_taint_map, taint_sources = _merge_summary_maps(summaries)

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
        diagnostics=(*resolver_diagnostics, *diagnostics),
        metadata=metadata,
    )
