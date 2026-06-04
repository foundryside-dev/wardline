"""Live wiring for the decorator coverage report."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from wardline.clarion.dossier_sources import resolve_entity_binding
from wardline.clarion.identity import SeiCapability, SeiResolver
from wardline.core.decorator_coverage import BindingProvider, DecoratorCoverageReport, build_decorator_coverage
from wardline.core.identity import EntityBinding
from wardline.filigree.dossier_client import FiligreeWorkProvider
from wardline.filigree.dossier_client import Transport as FiligreeTransport


class ClarionBindingProvider:
    def __init__(self, clarion_client: Any) -> None:
        capabilities = clarion_client.capabilities()
        self._client = clarion_client
        self._resolver = SeiResolver(clarion_client, SeiCapability.from_capabilities(capabilities))

    def binding_for(self, qualname: str) -> EntityBinding | None:
        return resolve_entity_binding(self._client, self._resolver, qualname)


def build_loom_decorator_coverage(
    root: Path,
    *,
    clarion_client: Any = None,
    filigree_url: str | None = None,
    filigree_transport: FiligreeTransport | None = None,
    config_path: Path | None = None,
    confine_to_root: bool = True,
) -> DecoratorCoverageReport:
    binding_provider: BindingProvider | None = None
    if clarion_client is not None:
        binding_provider = ClarionBindingProvider(clarion_client)
    work_provider = FiligreeWorkProvider(filigree_url, transport=filigree_transport) if filigree_url else None
    return build_decorator_coverage(
        root,
        config_path=config_path,
        confine_to_root=confine_to_root,
        binding_provider=binding_provider,
        work_provider=work_provider,
    )
