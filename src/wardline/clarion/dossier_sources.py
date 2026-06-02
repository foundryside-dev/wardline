# src/wardline/clarion/dossier_sources.py
"""Track 4 (T4.3) — the live Clarion source for the dossier's linkages section.

Wraps the SP9/Track-3 ``ClarionClient`` call-graph reads behind the
``LinkageProvider`` seam (``core/dossier.py``) and resolves a Wardline qualname to
its opaque SEI binding via the Track-3 ``SeiResolver``. Stays fail-soft: a
pre-linkage Clarion, an unknown entity, or an outage yields an honest
``unavailable`` section, never a crash and never fabricated edges.

The two freshness axes stay orthogonal (SEI conformance §2.1): the IDENTITY axis is
carried verbatim from the resolved binding (alive / orphaned / unavailable), and the
CONTENT axis is ``FRESH`` because linkages are read live from Clarion's current index
at call time. Neither is inferred from the other.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from wardline.clarion.identity import ContentStatus, EntityBinding
from wardline.core.dossier import LinkagesSection

if TYPE_CHECKING:
    from wardline.clarion.client import LinkageResult


class _LinkageClient(Protocol):
    """The narrow ``ClarionClient`` surface this provider needs (so a test double need
    only implement these two; ``ClarionClient`` satisfies it structurally)."""

    def get_callers(self, entity_id: str, *, limit: int = ...) -> LinkageResult | None: ...
    def get_callees(self, entity_id: str, *, limit: int = ...) -> LinkageResult | None: ...


class _ResolveClient(Protocol):
    def resolve(self, qualnames: list[str]) -> object | None: ...


class _Resolver(Protocol):
    def resolve_locator(self, locator: str) -> EntityBinding: ...


class ClarionLinkageProvider:
    """A ``LinkageProvider`` (``core/dossier.py``) backed by a live ``ClarionClient``.

    ``linkages_http`` is the capability flag (``_capabilities.linkages.http``) detected
    once by the orchestrator — when False, Clarion does not serve linkages over HTTP
    and the section is honestly ``unavailable`` without a wire call."""

    def __init__(self, client: _LinkageClient, *, linkages_http: bool, limit: int = 50) -> None:
        self._client = client
        self._linkages_http = linkages_http
        self._limit = limit

    def linkages(self, binding: EntityBinding) -> LinkagesSection:
        if not self._linkages_http:
            return LinkagesSection.unavailable("clarion does not serve HTTP linkages")
        callers = self._client.get_callers(binding.locator, limit=self._limit)
        callees = self._client.get_callees(binding.locator, limit=self._limit)
        if callers is None and callees is None:
            return LinkagesSection.unavailable("clarion linkages unreachable or entity unknown")
        truncated = (callers.truncated if callers is not None else False) or (
            callees.truncated if callees is not None else False
        )
        reason = "clarion truncated the linkage list (more neighbours available)" if truncated else None
        return LinkagesSection(
            available=True,
            callers=list(callers.neighbours) if callers is not None else [],
            callees=list(callees.neighbours) if callees is not None else [],
            scc_peers=[],  # SCC membership is not served over HTTP yet — honest empty
            identity_status=binding.identity,  # SEI axis, from the resolved binding
            content_status=ContentStatus.FRESH,  # read live from the current Clarion index
            reason=reason,
        )


def resolve_entity_binding(client: _ResolveClient, resolver: _Resolver, qualname: str) -> EntityBinding | None:
    """Resolve a Wardline qualname to its opaque SEI :class:`EntityBinding`.

    Two hops, both via existing Track-3 surfaces: ``resolve`` maps the qualname to its
    Clarion locator, then the ``SeiResolver`` maps the locator to its SEI binding (the
    identity axis). Returns None when the qualname cannot be resolved to a locator (the
    caller degrades to a no-binding, honest-unavailable dossier — never a guessed key)."""
    rr = client.resolve([qualname])
    resolved = getattr(rr, "resolved", None)
    locator = resolved.get(qualname) if isinstance(resolved, dict) else None
    if not locator:
        return None
    return resolver.resolve_locator(locator)
