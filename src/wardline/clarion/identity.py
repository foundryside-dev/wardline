# src/wardline/clarion/identity.py
"""Track 3 (T3.1/T3.2): the SEI-client abstraction.

Carry Clarion's Stable Entity Identity (SEI) as the OPAQUE handle for cross-tool
bindings, with an honest two-axis status, and degrade gracefully when Clarion does
not (yet) serve SEI. Built against the spec'd wire contract (SEI standard §4 +
Clarion ADR-038 + the normative fixtures); Clarion's runtime does not serve SEI yet,
so the live path degrades and the SEI-present path is exercised with mocks.

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
from enum import Enum
from typing import Any


class IdentityStatus(Enum):
    """Identity axis — 'is this the same entity?' Never inferred from content."""

    ALIVE = "alive"  # SEI resolves to a live binding
    ORPHANED = "orphaned"  # SEI exists but is orphaned/superseded (resolve_sei alive:false)
    UNAVAILABLE = "unavailable"  # no SEI obtainable — capability absent, or locator does not resolve


class ContentStatus(Enum):
    """Content axis — 'has its code changed?' Never inferred from identity."""

    FRESH = "fresh"
    STALE = "stale"
    UNKNOWN = "unknown"


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
class EntityBinding:
    """A cross-tool binding handle for one entity, carrying both status axes.

    The SEI (when present) is the durable identity and the PREFERRED binding key;
    the locator is the mutable address. When no SEI is available the binding degrades
    honestly (``identity=UNAVAILABLE``) and the consumer keeps working on the locator —
    but the fallback is EXPLICIT (``keyed_on_sei`` is False), never a silent treatment
    of a locator as a stable identity.

    ``content_hash`` (when set) is Clarion's ENTITY-BODY hash from resolve. It is NOT
    the same granularity as Wardline's whole-file ``content_hash_at_compute``; never
    compare across the two (see :func:`content_status`)."""

    locator: str
    sei: str | None = None
    identity: IdentityStatus = IdentityStatus.UNAVAILABLE
    content: ContentStatus = ContentStatus.UNKNOWN
    content_hash: str | None = None  # Clarion entity-body granularity

    @property
    def keyed_on_sei(self) -> bool:
        """True iff the stable identity (SEI) is the binding key."""
        return self.sei is not None

    @property
    def binding_key(self) -> str:
        """The key to bind on: the SEI when present (the stable identity), else the
        locator. Prefer-SEI per SEI standard §4 / REQ-C-04. When this returns the
        locator, ``keyed_on_sei`` is False and ``identity`` is UNAVAILABLE — the caller
        must surface that the binding is on a mutable address, not an identity."""
        return self.sei if self.sei is not None else self.locator


def content_status(stored_hash: str | None, current_hash: str | None) -> ContentStatus:
    """Compare two content hashes OF THE SAME GRANULARITY.

    The caller GUARANTEES both hashes are the same granularity (both entity-body, OR
    both whole-file). Do NOT pass Clarion's entity-body ``content_hash`` against
    Wardline's whole-file ``content_hash_at_compute`` — different spans hash differently
    and the result would be a permanent false-STALE. Cross-granularity harmonisation
    is out of scope here (SEI standard §2 note; deferred to T4.3).

    Unknown on either side → UNKNOWN (honest; never guess FRESH)."""
    if stored_hash is None or current_hash is None:
        return ContentStatus.UNKNOWN
    return ContentStatus.FRESH if stored_hash == current_hash else ContentStatus.STALE


class SeiResolver:
    """Resolves locators → :class:`EntityBinding` via a ClarionClient, honoring
    capability detection and degrading gracefully. The SEI is treated strictly opaque.

    DEFERRED (no T3.1–T3.3 consumer): ``lineage(sei)`` — Clarion serves it (SEI std §4)
    but no Wardline groundwork path consumes the event log yet (it is a Track 4 dossier
    / legis-audit concern). ``resolve_sei`` IS implemented because the ORPHANED identity
    status is part of this track's two-axis model. This split is intentional, not an
    omission."""

    def __init__(self, client: Any, capability: SeiCapability) -> None:
        self._client = client
        self._capability = capability

    @property
    def capability(self) -> SeiCapability:
        return self._capability

    @classmethod
    def detect(cls, client: Any) -> SeiResolver:
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

    def is_orphaned(self, sei: str) -> IdentityStatus:
        """The identity axis for a held SEI, via resolve_sei. ALIVE / ORPHANED, or
        UNAVAILABLE when the capability is absent or the read soft-fails (never guess).
        ``sei`` is opaque — passed verbatim to the client, never parsed."""
        if not self._capability.supported:
            return IdentityStatus.UNAVAILABLE
        data = self._client.resolve_sei(sei)
        if not isinstance(data, dict):
            return IdentityStatus.UNAVAILABLE
        return IdentityStatus.ALIVE if data.get("alive") is True else IdentityStatus.ORPHANED
