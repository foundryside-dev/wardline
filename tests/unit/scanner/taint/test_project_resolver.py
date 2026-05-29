from __future__ import annotations

import ast

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
