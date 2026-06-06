# src/wardline/weft_dossier.py
"""Track 4 (T4.3) — the live Weft dossier orchestrator.

Ties the three sources together into one call: Wardline's own trust posture (the
source-agnostic core assembler), Loomweave structure/linkages, and Filigree open work —
joined on the opaque SEI. This is the wiring the CLI/MCP surfaces will call; the core
``build_dossier`` stays source-agnostic (providers are injected), so this module is the
only place that knows about live Loomweave/Filigree clients.

Everything degrades honestly: no Loomweave → self-only with an UNAVAILABLE identity axis;
a pre-SEI / pre-linkage Loomweave → those sections unavailable; no Filigree → work
unavailable. The SEI is resolved via the Track-3 ``SeiResolver`` (Track 4 never mints
or parses it) and is carried verbatim as the binding key.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from wardline.core.dossier import (
    DOSSIER_TOKEN_BUDGET,
    EntityDossier,
    LinkageProvider,
    WorkProvider,
    build_dossier,
)
from wardline.core.errors import DossierError
from wardline.core.identity import ContentStatus, EntityBinding, IdentityStatus
from wardline.core.sei_resolution import locator_to_qualname
from wardline.filigree.config import load_filigree_token
from wardline.filigree.dossier_client import FiligreeWorkProvider
from wardline.filigree.dossier_client import Transport as FiligreeTransport
from wardline.loomweave.client import LinkageResult
from wardline.loomweave.dossier_sources import LoomweaveLinkageProvider, resolve_entity_binding
from wardline.loomweave.identity import SeiCapability, SeiResolver


class _LoomweaveClient(Protocol):
    """The Loomweave surface the orchestrator needs — the SEI + linkage methods of
    ``LoomweaveClient``. Declared structurally so a test double satisfies it (and so it
    composes with the narrower provider/resolver Protocols downstream)."""

    def capabilities(self) -> dict[str, Any] | None: ...
    def resolve(self, qualnames: list[str]) -> Any: ...
    def resolve_identity(self, locator: str) -> dict[str, Any] | None: ...
    def resolve_sei(self, sei: str) -> dict[str, Any] | None: ...
    def get_callers(self, entity_id: str, *, limit: int = ...) -> LinkageResult | None: ...
    def get_callees(self, entity_id: str, *, limit: int = ...) -> LinkageResult | None: ...


def _linkages_http(capabilities: dict[str, Any] | None) -> bool:
    """Whether Loomweave advertises the HTTP call-graph linkage routes
    (``_capabilities.linkages.http``). Fail-closed: a missing/malformed cap → False."""
    if not isinstance(capabilities, dict):
        return False
    linkages = capabilities.get("linkages")
    return isinstance(linkages, dict) and linkages.get("http") is True


def build_weft_dossier(
    entity: str,
    *,
    root: Path,
    loomweave_client: _LoomweaveClient | None = None,
    filigree_url: str | None = None,
    filigree_transport: FiligreeTransport | None = None,
    config_path: Path | None = None,
    confine_to_root: bool = True,
    budget: int = DOSSIER_TOKEN_BUDGET,
) -> EntityDossier:
    """Assemble the one-call Weft dossier for ``entity`` against live sources.

    With ``loomweave_client``: probe capabilities ONCE, resolve the entity's opaque SEI
    binding (Track-3 ``SeiResolver``), and wire the Loomweave linkage provider. With
    ``filigree_url``: wire the Filigree work provider. Both are optional and degrade to
    honest ``unavailable`` sections; the self/trust posture is always computed for real.
    """
    binding: EntityBinding | None = None
    linkage_provider: LinkageProvider | None = None
    work_provider: WorkProvider | None = None

    if entity.startswith("sei:"):
        if loomweave_client is None:
            raise DossierError(f"no Loomweave URL configured; cannot resolve SEI: {entity}")
        capabilities = loomweave_client.capabilities()
        resolver = SeiResolver(loomweave_client, SeiCapability.from_capabilities(capabilities))
        if not resolver.capability.supported:
            raise DossierError(f"Loomweave instance does not support SEI; cannot resolve SEI: {entity}")
        data = loomweave_client.resolve_sei(entity)
        if data is None or data.get("alive") is not True or data.get("current_locator") is None:
            raise DossierError(f"cannot resolve SEI to a qualname: {entity}")
        current_locator = data["current_locator"]
        input_sei = entity
        entity = locator_to_qualname(current_locator)
        binding = EntityBinding(
            locator=current_locator,
            sei=data.get("sei") or input_sei,
            identity=IdentityStatus.ALIVE,
            content_hash=data.get("content_hash"),
            content=ContentStatus.UNKNOWN,
        )
        linkage_provider = LoomweaveLinkageProvider(loomweave_client, linkages_http=_linkages_http(capabilities))
    elif loomweave_client is not None:
        capabilities = loomweave_client.capabilities()
        resolver = SeiResolver(loomweave_client, SeiCapability.from_capabilities(capabilities))
        binding = resolve_entity_binding(loomweave_client, resolver, entity)
        linkage_provider = LoomweaveLinkageProvider(loomweave_client, linkages_http=_linkages_http(capabilities))

    if filigree_url is not None:
        work_provider = FiligreeWorkProvider(
            filigree_url, transport=filigree_transport, token=load_filigree_token(root)
        )

    return build_dossier(
        entity,
        root=root,
        config_path=config_path,
        confine_to_root=confine_to_root,
        binding=binding,
        linkage_provider=linkage_provider,
        work_provider=work_provider,
        budget=budget,
    )
