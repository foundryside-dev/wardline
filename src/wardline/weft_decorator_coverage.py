"""Live wiring for the decorator coverage report."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from wardline.core.decorator_coverage import BindingProvider, DecoratorCoverageReport, build_decorator_coverage
from wardline.core.identity import EntityBinding
from wardline.filigree.config import load_filigree_token
from wardline.filigree.dossier_client import FiligreeWorkProvider
from wardline.filigree.dossier_client import Transport as FiligreeTransport
from wardline.loomweave.dossier_sources import resolve_entity_binding
from wardline.loomweave.identity import SeiCapability, SeiResolver


class LoomweaveBindingProvider:
    def __init__(self, loomweave_client: Any) -> None:
        capabilities = loomweave_client.capabilities()
        self._client = loomweave_client
        self._resolver = SeiResolver(loomweave_client, SeiCapability.from_capabilities(capabilities))

    def binding_for(self, qualname: str) -> EntityBinding | None:
        # Decorator coverage is a Python-surface report (@trust_boundary/@trusted
        # decorators), so the producer is known — send the ADR-036 plugin hint.
        return resolve_entity_binding(self._client, self._resolver, qualname, plugin="python")


def build_weft_decorator_coverage(
    root: Path,
    *,
    loomweave_client: Any = None,
    filigree_url: str | None = None,
    filigree_transport: FiligreeTransport | None = None,
    config_path: Path | None = None,
    confine_to_root: bool = True,
) -> DecoratorCoverageReport:
    binding_provider: BindingProvider | None = None
    if loomweave_client is not None:
        binding_provider = LoomweaveBindingProvider(loomweave_client)
    work_provider = (
        FiligreeWorkProvider(filigree_url, transport=filigree_transport, token=load_filigree_token(root))
        if filigree_url
        else None
    )
    return build_decorator_coverage(
        root,
        config_path=config_path,
        confine_to_root=confine_to_root,
        binding_provider=binding_provider,
        work_provider=work_provider,
    )
