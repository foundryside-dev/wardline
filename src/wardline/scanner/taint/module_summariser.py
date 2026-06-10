# src/wardline/scanner/taint/module_summariser.py
"""Per-module FunctionSummary emission + module-global taint seeds.

Maps each L1 ``FunctionSeed`` + the callgraph's unresolved-call count into a
``FunctionSummary``. The seed's 2-valued source (``provider``/``default``) maps
onto the kernel's 3-valued taint-source class: ``provider -> anchored``,
``default -> fallback``. The ``module_default`` class is dormant in SP1 (no
provider expresses a module-wide default yet); SP2's richer provider populates
it. The cache key is computed once and shared by all functions in the module
(module-granular invalidation).

Also hosts the MODULE-GLOBAL TAINT CHANNEL's two collection helpers
(wardline-66b2c91470): :func:`collect_module_global_raw_seeds` (the read
direction's import-time seeds) and :func:`own_scope_global_names` (the write
direction's ``global g`` declarations). The analyzer threads both into the L2
walk — see ``analyzer._with_module_global_params`` for how the seeds enter a
function's variable map.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping

from wardline.core.taints import RAW_ZONE, TaintState
from wardline.scanner.ast_primitives import resolve_call_fqn
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
    scan_policy_hash: str,
) -> tuple[FunctionSummary, ...]:
    """Emit one FunctionSummary per seeded function in this module."""
    cache_key = compute_cache_key(
        module_path=module_path,
        source_bytes=source_bytes,
        schema_version=SUMMARY_SCHEMA_VERSION,
        resolver_version=resolver_version,
        provider_fingerprint=provider_fingerprint,
        scan_policy_hash=scan_policy_hash,
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


def collect_module_global_raw_seeds(
    tree: ast.Module,
    *,
    module: str,
    alias_map: Mapping[str, str],
    return_taints: Mapping[str, TaintState],
    local_fqns: frozenset[str],
    untrusted_sources: frozenset[str] = frozenset(),
) -> dict[str, TaintState]:
    """Module-level simple names assigned RAW at import time → ``{name: taint}``.

    The READ direction of the module-global taint channel (wardline-66b2c91470):
    a module-level ``RAW = read_raw(...)`` — a direct call whose FQN resolves
    (through the import alias map or as a module-local function) to either

      * a ``config.untrusted_sources`` entry (seeded ``EXTERNAL_RAW``), or
      * a project function whose RESOLVED RETURN TAINT is in ``RAW_ZONE``
        (an ``@external_boundary`` producer — its return taint, ``EXTERNAL_RAW``,
        is the seed),

    marks ``RAW`` as a raw module global. The analyzer then presents these names
    to every function's L2 walk as implicit raw parameters.

    Scope (documented v1 approximation): only DIRECT top-level statements are
    considered (no descent into module-level ``if``/``try`` bodies), single-Name
    ``=``/annotated-``=`` targets only, LAST-BINDING-WINS in source order — a
    later rebind whose RHS is not a resolvable raw call CLEARS the name (the
    same discipline as ``collect_sink_bindings``). This under-approximates
    (bounded FN on conditional module init), never over-approximates a clean
    module constant into a raw seed.
    """
    aliases = dict(alias_map)

    def raw_taint_of(value: ast.expr) -> TaintState | None:
        if not isinstance(value, ast.Call):
            return None
        fqn = resolve_call_fqn(value, aliases, local_fqns, module)
        if fqn is None:
            return None
        if fqn in untrusted_sources:
            return TaintState.EXTERNAL_RAW
        taint = return_taints.get(fqn)
        return taint if taint is not None and taint in RAW_ZONE else None

    seeds: dict[str, TaintState] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign):
            if len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                taint = raw_taint_of(stmt.value)
                if taint is not None:
                    seeds[stmt.targets[0].id] = taint
                else:
                    seeds.pop(stmt.targets[0].id, None)
            else:  # tuple/multi-target rebind — clear every touched name
                for target in stmt.targets:
                    for sub in ast.walk(target):
                        if isinstance(sub, ast.Name):
                            seeds.pop(sub.id, None)
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            taint = raw_taint_of(stmt.value) if stmt.value is not None else None
            if taint is not None:
                seeds[stmt.target.id] = taint
            else:
                seeds.pop(stmt.target.id, None)
    return seeds


def own_scope_global_names(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> frozenset[str]:
    """Names a function declares ``global`` in its OWN scope.

    The WRITE direction of the module-global taint channel: the analyzer reads
    each declared name's final L2 variable taint as the function's write to the
    module global. Nested def/class bodies are skipped — they are their own
    entities and carry their own ``global`` declarations.
    """
    names: set[str] = set()

    def visit(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(child, ast.Global):
                names.update(child.names)
            visit(child)

    visit(func_node)
    return frozenset(names)
