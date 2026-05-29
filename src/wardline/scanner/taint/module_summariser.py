# src/wardline/scanner/taint/module_summariser.py
"""Per-module FunctionSummary emission.

Maps each L1 ``FunctionSeed`` + the callgraph's unresolved-call count into a
``FunctionSummary``. The seed's 2-valued source (``provider``/``default``) maps
onto the kernel's 3-valued taint-source class: ``provider -> anchored``,
``default -> fallback``. The ``module_default`` class is dormant in SP1 (no
provider expresses a module-wide default yet); SP2's richer provider populates
it. The cache key is computed once and shared by all functions in the module
(module-granular invalidation).
"""

from __future__ import annotations

from collections.abc import Mapping

from wardline.scanner.taint.function_level import FunctionSeed
from wardline.scanner.taint.summary import (
    SUMMARY_SCHEMA_VERSION,
    FunctionSummary,
    TaintSourceClass,
    compute_cache_key,
)

_SEED_SOURCE_TO_CLASS: dict[str, TaintSourceClass] = {
    "provider": "anchored",
    "default": "fallback",
}


def summarise_module(
    *,
    module_path: str,
    seeds: Mapping[str, FunctionSeed],
    unresolved_counts: Mapping[str, int],
    source_bytes: bytes,
    resolver_version: str,
    provider_fingerprint: str,
) -> tuple[FunctionSummary, ...]:
    """Emit one FunctionSummary per seeded function in this module."""
    cache_key = compute_cache_key(
        module_path=module_path,
        source_bytes=source_bytes,
        schema_version=SUMMARY_SCHEMA_VERSION,
        resolver_version=resolver_version,
        provider_fingerprint=provider_fingerprint,
    )
    summaries: list[FunctionSummary] = []
    for fqn, seed in seeds.items():
        summaries.append(
            FunctionSummary(
                fqn=fqn,
                body_taint=seed.body_taint,
                return_taint=seed.return_taint,
                taint_source=_SEED_SOURCE_TO_CLASS[seed.source],
                unresolved_calls=unresolved_counts.get(fqn, 0),
                schema_version=SUMMARY_SCHEMA_VERSION,
                cache_key=cache_key,
            )
        )
    return tuple(summaries)
