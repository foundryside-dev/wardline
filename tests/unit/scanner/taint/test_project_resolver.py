from __future__ import annotations

import ast

import pytest

from wardline.core.taints import TaintState as T
from wardline.scanner.ast_primitives import build_import_alias_map
from wardline.scanner.index import discover_class_qualnames, discover_file_entities
from wardline.scanner.taint.function_level import seed_function_taints
from wardline.scanner.taint.project_resolver import ModuleInput, resolve_project_taints
from wardline.scanner.taint.provider import (
    DefaultTaintSourceProvider,
    FunctionTaint,
    SeedContext,
)
from wardline.scanner.taint.summary_cache import SummaryCache


class _RawLeafProvider:
    """Declares any function whose qualname ends in '.read_raw' as an anchored
    MIXED_RAW source; silent on everything else (fallback)."""

    def taint_for(self, entity, ctx):  # noqa: ANN001, ANN201
        if entity.qualname.endswith(".read_raw"):
            return FunctionTaint(body_taint=T.MIXED_RAW, return_taint=T.MIXED_RAW)
        return None

    def fingerprint(self) -> str:
        return "rawleaf-v1"


_IO = "def read_raw(p):\n    return p\n"
_SERVICE = "from pkg.io_layer import read_raw\ndef fetch(p):\n    return read_raw(p)\n"
_HANDLER = (
    "from pkg.service import fetch\n"
    "class Handler:\n"
    "    def process(self, p):\n"
    "        return self.fetch_wrap(p)\n"
    "    def fetch_wrap(self, p):\n"
    "        return fetch(p)\n"
)


def _module_input(module: str, src: str, provider) -> ModuleInput:
    tree = ast.parse(src)
    entities = tuple(discover_file_entities(tree, module=module, path=f"{module}.py"))
    seeds = seed_function_taints(entities, ctx=SeedContext(module=module), provider=provider)
    return ModuleInput(
        module_path=module,
        entities=entities,
        class_qualnames=discover_class_qualnames(tree, module=module),
        alias_map=build_import_alias_map(tree, module_path=module),
        seeds=seeds,
        source_bytes=src.encode("utf-8"),
    )


def test_transitive_raw_flows_across_modules_and_self_method() -> None:
    provider = _RawLeafProvider()
    inputs = [
        _module_input("pkg.io_layer", _IO, provider),
        _module_input("pkg.service", _SERVICE, provider),
        _module_input("pkg.handler", _HANDLER, provider),
    ]
    result = resolve_project_taints(modules=inputs, provider_fingerprint=provider.fingerprint())
    tm = result.taint_map
    # Raw leaf flows 3 hops up; the process->fetch_wrap edge is the self.method().
    assert tm["pkg.io_layer.read_raw"] == T.MIXED_RAW
    assert tm["pkg.service.fetch"] == T.MIXED_RAW
    assert tm["pkg.handler.Handler.fetch_wrap"] == T.MIXED_RAW
    assert tm["pkg.handler.Handler.process"] == T.MIXED_RAW
    # The self.method() edge is present in the project graph.
    assert "pkg.handler.Handler.fetch_wrap" in result.project_edges["pkg.handler.Handler.process"]
    assert "pkg.service.fetch" in result.project_edges["pkg.handler.Handler.fetch_wrap"]


def test_default_provider_leaves_everything_unknown_raw() -> None:
    provider = DefaultTaintSourceProvider()
    inputs = [
        _module_input("pkg.io_layer", _IO, provider),
        _module_input("pkg.service", _SERVICE, provider),
        _module_input("pkg.handler", _HANDLER, provider),
    ]
    result = resolve_project_taints(modules=inputs, provider_fingerprint=provider.fingerprint())
    # With the trivial provider, every function is fallback UNKNOWN_RAW and the
    # floor keeps them there — the kernel is sound but a no-op on taint values.
    assert set(result.taint_map.values()) == {T.UNKNOWN_RAW}


def test_metadata_records_scc_distribution() -> None:
    provider = _RawLeafProvider()
    inputs = [
        _module_input("pkg.io_layer", _IO, provider),
        _module_input("pkg.service", _SERVICE, provider),
        _module_input("pkg.handler", _HANDLER, provider),
    ]
    result = resolve_project_taints(modules=inputs, provider_fingerprint=provider.fingerprint())
    # 3 non-anchored singleton SCCs are recorded (the anchored read_raw SCC is
    # skipped by the kernel).
    assert result.metadata.scc_size_distribution == ((1, 3),)
    assert result.metadata.taint_source_counts["anchored"] == 1
    assert result.metadata.taint_source_counts["fallback"] == 3


def _inputs(provider):
    return [
        _module_input("pkg.io_layer", _IO, provider),
        _module_input("pkg.service", _SERVICE, provider),
        _module_input("pkg.handler", _HANDLER, provider),
    ]


def test_cache_and_dirty_must_be_supplied_together() -> None:
    provider = _RawLeafProvider()
    inputs = _inputs(provider)
    with pytest.raises(ValueError, match="together"):
        resolve_project_taints(
            modules=inputs, provider_fingerprint=provider.fingerprint(),
            summary_cache=SummaryCache(),  # dirty_modules omitted
        )
    with pytest.raises(ValueError, match="together"):
        resolve_project_taints(
            modules=inputs, provider_fingerprint=provider.fingerprint(),
            dirty_modules=frozenset(),  # summary_cache omitted
        )


def test_warm_run_equals_cold_run() -> None:
    provider = _RawLeafProvider()
    inputs = _inputs(provider)
    fp = provider.fingerprint()

    cold = resolve_project_taints(modules=inputs, provider_fingerprint=fp)

    cache = SummaryCache()
    run1 = resolve_project_taints(
        modules=inputs, provider_fingerprint=fp,
        summary_cache=cache, dirty_modules=frozenset(),
    )
    run2 = resolve_project_taints(
        modules=inputs, provider_fingerprint=fp,
        summary_cache=cache, dirty_modules=frozenset(),
    )

    # cached ≡ cold, byte-for-byte on taint and provenance
    assert dict(run1.taint_map) == dict(cold.taint_map)
    assert dict(run2.taint_map) == dict(cold.taint_map)
    assert {k: v.source for k, v in run2.taint_provenance.items()} == {
        k: v.source for k, v in cold.taint_provenance.items()
    }
    # run2 served entirely from cache
    assert cache.hit_rate() > 0.0


def test_dirty_frontier_recompute_still_equals_cold() -> None:
    # Behavioural end-to-end check. NOTE: this passes regardless of whether
    # transitive_callers is correct (cached summaries equal fresh, edges are
    # always recomputed) — the closure itself is verified directly in
    # test_reverse_edge_index.py. This guards the wiring, not the closure.
    provider = _RawLeafProvider()
    inputs = _inputs(provider)
    fp = provider.fingerprint()
    cold = resolve_project_taints(modules=inputs, provider_fingerprint=fp)

    cache = SummaryCache()
    resolve_project_taints(
        modules=inputs, provider_fingerprint=fp,
        summary_cache=cache, dirty_modules=frozenset({"pkg.io_layer"}),
    )
    # Mark the leaf's module dirty; its callers are in the frontier.
    warm = resolve_project_taints(
        modules=inputs, provider_fingerprint=fp,
        summary_cache=cache, dirty_modules=frozenset({"pkg.io_layer"}),
    )
    assert dict(warm.taint_map) == dict(cold.taint_map)


def test_identical_source_modules_do_not_collide_in_cache() -> None:
    # Regression: two modules with byte-identical source must each keep their
    # own functions through a warm run (no false cache hit dropping the second).
    provider = DefaultTaintSourceProvider()
    fp = provider.fingerprint()
    same_src = "def f(p):\n    return p\n"
    inputs = [
        _module_input("pkg.a", same_src, provider),
        _module_input("pkg.b", same_src, provider),
    ]
    cold = resolve_project_taints(modules=inputs, provider_fingerprint=fp)
    cache = SummaryCache()
    resolve_project_taints(
        modules=inputs, provider_fingerprint=fp,
        summary_cache=cache, dirty_modules=frozenset(),
    )
    warm = resolve_project_taints(
        modules=inputs, provider_fingerprint=fp,
        summary_cache=cache, dirty_modules=frozenset(),
    )
    assert set(cold.taint_map) == {"pkg.a.f", "pkg.b.f"}
    assert dict(warm.taint_map) == dict(cold.taint_map)


def test_resolver_exposes_effective_return_taint_map() -> None:
    # An anchored @trust_boundary-shaped function: body EXTERNAL_RAW, return ASSURED.
    # Its effective return taint must be the DECLARED return (ASSURED), while its
    # body taint (taint_map) stays EXTERNAL_RAW. A non-anchored function's effective
    # return must equal its refined body taint.
    import ast

    from wardline.core.taints import TaintState as T
    from wardline.scanner.ast_primitives import build_import_alias_map
    from wardline.scanner.index import discover_class_qualnames, discover_file_entities
    from wardline.scanner.taint.function_level import seed_function_taints
    from wardline.scanner.taint.provider import FunctionTaint, SeedContext

    src = (
        "def validate(p):\n"
        "    if not p:\n        raise ValueError\n"
        "    return p\n"
        "def plain(p):\n    return p\n"
    )
    tree = ast.parse(src)
    module = "m"
    entities = tuple(discover_file_entities(tree, module=module, path="m.py"))
    classes = frozenset(discover_class_qualnames(tree, module=module))
    alias_map = build_import_alias_map(tree, module_path=module)

    class _Provider:
        def taint_for(self, entity, ctx):  # noqa: ANN001, ANN201
            if entity.qualname.endswith(".validate"):
                return FunctionTaint(body_taint=T.EXTERNAL_RAW, return_taint=T.ASSURED)
            return None

        def fingerprint(self) -> str:
            return "test-effret-v1"

    provider = _Provider()
    seeds = seed_function_taints(
        entities, ctx=SeedContext(module=module, alias_map=alias_map), provider=provider
    )
    modules = [
        ModuleInput(
            module_path=module,
            entities=entities,
            class_qualnames=classes,
            alias_map=alias_map,
            seeds=seeds,
            source_bytes=src.encode("utf-8"),
        )
    ]
    result = resolve_project_taints(modules=modules, provider_fingerprint=provider.fingerprint())

    assert result.taint_map["m.validate"] == T.EXTERNAL_RAW          # body unchanged
    assert result.return_taint_map["m.validate"] == T.ASSURED         # declared return
    # non-anchored: effective return == refined body taint
    assert result.return_taint_map["m.plain"] == result.taint_map["m.plain"]


def test_cache_miss_on_changed_source_recomputes() -> None:
    # A module whose source changes gets a different cache_key -> miss ->
    # fresh summary, even if the caller forgets to mark it dirty.
    provider = _RawLeafProvider()
    fp = provider.fingerprint()
    cache = SummaryCache()

    inputs_v1 = _inputs(provider)
    resolve_project_taints(
        modules=inputs_v1, provider_fingerprint=fp,
        summary_cache=cache, dirty_modules=frozenset(),
    )
    len_after_v1 = len(cache)

    # Change pkg.service's source (add a comment) -> new cache_key.
    service_v2 = "# changed\n" + _SERVICE
    inputs_v2 = [
        _module_input("pkg.io_layer", _IO, provider),
        _module_input("pkg.service", service_v2, provider),
        _module_input("pkg.handler", _HANDLER, provider),
    ]
    warm = resolve_project_taints(
        modules=inputs_v2, provider_fingerprint=fp,
        summary_cache=cache, dirty_modules=frozenset(),
    )
    cold_v2 = resolve_project_taints(modules=inputs_v2, provider_fingerprint=fp)
    assert dict(warm.taint_map) == dict(cold_v2.taint_map)
    # The changed module added a new key (old one is still present, unused).
    assert len(cache) == len_after_v1 + 1
