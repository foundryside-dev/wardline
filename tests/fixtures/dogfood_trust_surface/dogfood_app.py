"""Annotated trust-surface fixture used by Wardline's assure/attest dogfood test."""

from __future__ import annotations

from wardline.decorators.trust import external_boundary, trusted


@external_boundary
def inbound_account_header(headers: dict[str, str]) -> str:
    """Boundary: caller-supplied account identity from an HTTP-like header map."""
    return headers["X-Account-ID"]


@trusted(level="INTEGRAL")
def validate_account_id(raw: str) -> str:
    """Reject malformed account IDs before they become trusted account keys."""
    cleaned = raw.strip()
    if not cleaned or not cleaned.replace("-", "").isalnum():
        raise ValueError("invalid account id")
    return cleaned


@trusted(level="INTEGRAL")
def account_key(headers: dict[str, str]) -> str:
    """A trusted producer composed from an explicit boundary and validator."""
    return validate_account_id(inbound_account_header(headers))
