# src/wardline/clarion/identity.py
"""Track 3 (T3.1/T3.2): the SEI-client abstraction.

Carry Clarion's Stable Entity Identity (SEI) as the OPAQUE handle for cross-tool
bindings, with an honest two-axis status, and degrade gracefully when a Clarion
instance does not serve SEI. Built against the spec'd wire contract (SEI standard §4 +
Clarion ADR-038 + the normative fixtures). A real ``clarion serve`` (the local 1.0.1+
build) already serves SEI end-to-end — ``_capabilities`` advertises
``sei:{supported,version:1}`` and ``/api/v1/identity/resolve`` returns a real
``clarion:eid:<hex>`` token — so this client is verified against a live SEI-serving
Clarion (the ``clarion_e2e`` test exercises the ALIVE + opacity path), not only mocks.
A pre-SEI Clarion (no ``sei`` capability) is the graceful-degrade case.

Stdlib-only by contract: this module MUST NOT import blake3 or any extra, so importing
it never forces the [clarion] extra and the base package stays zero-dependency.

OPACITY: the SEI is an opaque token (``clarion:eid:<hex>``). This module NEVER parses,
pattern-matches, or derives meaning from it — it is carried verbatim and compared by
equality only. The two status axes are kept ORTHOGONAL and never collapsed:
  - identity axis (IdentityStatus): "is this the SAME entity?"  alive / orphaned / unavailable
  - content axis  (ContentStatus):  "has its CODE changed?"     fresh / stale / unknown
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from wardline.core.identity import ContentStatus, EntityBinding, IdentityStatus, content_status

__all__ = [
    "ContentStatus",
    "EntityBinding",
    "IdentityStatus",
    "SeiCapability",
    "SeiClient",
    "SeiResolver",
    "TaintStoreCapability",
    "content_status",
]


@dataclass(frozen=True, slots=True)
class SeiCapability:
    """Whether a Clarion instance serves SEI (from GET /api/v1/_capabilities)."""

    supported: bool
    version: int | None = None

    @classmethod
    def from_capabilities(cls, body: Mapping[str, Any] | None) -> SeiCapability:
        """Parse the ``_capabilities`` body, fail-closed. Absent / non-mapping /
        malformed / ``supported`` not exactly True → unsupported (honest degrade);
        never raises."""
        if not isinstance(body, Mapping):
            return cls(supported=False)
        sei = body.get("sei")
        if not isinstance(sei, Mapping) or sei.get("supported") is not True:
            return cls(supported=False)
        version = sei.get("version")
        return cls(supported=True, version=version if isinstance(version, int) else None)


@dataclass(frozen=True, slots=True)
class TaintStoreCapability:
    """Whether a Clarion instance serves the T3.4 read-by-SEI taint route
    (from GET /api/v1/_capabilities → ``taint_store.read_by_sei``).

    DISTINCT from :class:`SeiCapability`: an older SEI-capable Clarion (``sei.supported``
    True) predates migration 0006's ``POST /api/wardline/taint-facts/by-sei`` route, so a
    consumer MUST gate on this flag, never infer the route from ``sei.supported`` (Clarion's
    own capability comment makes the same point)."""

    read_by_sei: bool

    @classmethod
    def from_capabilities(cls, body: Mapping[str, Any] | None) -> TaintStoreCapability:
        """Parse the ``_capabilities`` body, fail-closed. Absent / non-mapping /
        ``read_by_sei`` not exactly True → unsupported (honest degrade); never raises."""
        if not isinstance(body, Mapping):
            return cls(read_by_sei=False)
        ts = body.get("taint_store")
        if not isinstance(ts, Mapping) or ts.get("read_by_sei") is not True:
            return cls(read_by_sei=False)
        return cls(read_by_sei=True)


class SeiClient(Protocol):
    """The narrow ClarionClient surface :class:`SeiResolver` depends on (so mypy checks
    the calls and a test double need only implement these three). ``ClarionClient``
    satisfies it structurally; no import cycle (``client.py`` does not import this)."""

    def capabilities(self) -> dict[str, Any] | None: ...
    def resolve_identity(self, locator: str) -> dict[str, Any] | None: ...
    def resolve_sei(self, sei: str) -> dict[str, Any] | None: ...


class SeiResolver:
    """Resolves locators → :class:`EntityBinding` via a ClarionClient, honoring
    capability detection and degrading gracefully. The SEI is treated strictly opaque.

    DEFERRED (no T3.1–T3.3 consumer): ``lineage(sei)`` — Clarion serves it (SEI std §4)
    but no Wardline groundwork path consumes the event log yet (it is a Track 4 dossier
    / legis-audit concern). ``resolve_sei`` IS used because the ORPHANED identity status
    is part of this track's two-axis model. This split is intentional, not an
    omission."""

    def __init__(self, client: SeiClient, capability: SeiCapability) -> None:
        self._client = client
        self._capability = capability

    @property
    def capability(self) -> SeiCapability:
        return self._capability

    @classmethod
    def detect(cls, client: SeiClient) -> SeiResolver:
        """Probe ``_capabilities`` once and bind the resolver to the result. A probe
        that fails for ANY reason (outage / a pre-SEI Clarion's 404 / malformed body →
        ``client.capabilities()`` returns None) yields an unsupported capability, so the
        resolver degrades."""
        return cls(client, SeiCapability.from_capabilities(client.capabilities()))

    def resolve_locator(self, locator: str) -> EntityBinding:
        """Resolve a locator to its binding. When SEI is unsupported, return an
        UNAVAILABLE binding WITHOUT touching the wire. When supported: ``alive:true``
        with a usable opaque SEI → ALIVE (SEI carried verbatim, ``current_locator``
        adopted); ``alive:false`` / soft outage / malformed → UNAVAILABLE (no live
        identity for this locator — honest, never a guess)."""
        if not self._capability.supported:
            return EntityBinding(locator=locator)
        data = self._client.resolve_identity(locator)
        if not isinstance(data, dict) or data.get("alive") is not True:
            return EntityBinding(locator=locator)
        sei = data.get("sei")
        if not isinstance(sei, str) or not sei:
            return EntityBinding(locator=locator)
        current = data.get("current_locator")
        chash = data.get("content_hash")
        return EntityBinding(
            locator=current if isinstance(current, str) and current else locator,
            sei=sei,  # opaque — carried verbatim, never parsed
            identity=IdentityStatus.ALIVE,
            content_hash=chash if isinstance(chash, str) else None,
        )

    def resolve_identity_status(self, sei: str) -> IdentityStatus:
        """The identity axis for a held SEI, via resolve_sei. ``alive:true`` → ALIVE;
        ``alive:false`` → ORPHANED; anything else (capability absent, soft outage, or a
        2xx body that does not carry a boolean ``alive``) → UNAVAILABLE. ORPHANED is an
        actionable positive verdict, so it is asserted ONLY on an explicit ``alive:false``
        — never guessed from a malformed/indefinite body (no false-green; mirrors
        ``resolve_locator``). ``sei`` is opaque — passed verbatim, never parsed.

        (Named for what it returns — a 3-valued :class:`IdentityStatus`, NOT a bool.)"""
        if not self._capability.supported:
            return IdentityStatus.UNAVAILABLE
        data = self._client.resolve_sei(sei)
        if not isinstance(data, dict):
            return IdentityStatus.UNAVAILABLE
        alive = data.get("alive")
        if alive is True:
            return IdentityStatus.ALIVE
        if alive is False:
            return IdentityStatus.ORPHANED
        return IdentityStatus.UNAVAILABLE  # malformed / alive-absent — never guess ORPHANED
