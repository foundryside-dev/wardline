"""Neutral cross-tool identity and freshness types.

These types are provider-agnostic: Loomweave may resolve them, Filigree may bind work
to them, and the dossier core may report them, but none of those consumers owns the
model.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class IdentityStatus(Enum):
    """Identity axis: is this the same entity? Never inferred from content."""

    ALIVE = "alive"
    ORPHANED = "orphaned"
    UNAVAILABLE = "unavailable"


class ContentStatus(Enum):
    """Content axis: has the entity's code changed? Never inferred from identity."""

    FRESH = "fresh"
    STALE = "stale"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class EntityBinding:
    """A cross-tool binding handle for one entity, carrying both status axes.

    The SEI, when present, is the durable identity and preferred binding key. Without
    one, the binding degrades honestly to the locator and marks identity unavailable.
    """

    locator: str
    sei: str | None = None
    identity: IdentityStatus = IdentityStatus.UNAVAILABLE
    content: ContentStatus = ContentStatus.UNKNOWN
    content_hash: str | None = None

    def __post_init__(self) -> None:
        if self.sei is not None and not self.sei:
            raise ValueError("sei must be None or a non-empty opaque string")

    @property
    def keyed_on_sei(self) -> bool:
        return self.sei is not None

    @property
    def binding_key(self) -> str:
        return self.sei if self.sei is not None else self.locator


def content_status(stored_hash: str | None, current_hash: str | None) -> ContentStatus:
    """Compare two content hashes of the same granularity."""
    if stored_hash is None or current_hash is None:
        return ContentStatus.UNKNOWN
    return ContentStatus.FRESH if stored_hash == current_hash else ContentStatus.STALE
