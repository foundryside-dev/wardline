"""Wardline trust-boundary corpus for the Loom integration sandbox."""

from __future__ import annotations

from collections.abc import Sequence

from wardline.decorators import external_boundary, trust_boundary, trusted


@external_boundary
def read_raw_username(argv: Sequence[str]) -> str:
    """Model a raw username crossing in from a CLI or request boundary."""

    return argv[0] if argv else ""


@trust_boundary(to_level="ASSURED")
def validate_username(raw: str) -> str:
    """Reject obviously invalid usernames and return a normalized value."""

    value = raw.strip().lower()
    if not value or not value.replace("-", "").replace("_", "").isalnum():
        raise ValueError("username must be non-empty and contain only letters, numbers, '-' or '_'")
    return value


@trusted(level="ASSURED")
def build_account_key(username: str) -> str:
    """Trusted producer that expects a validated username."""

    return f"user:{username}"


def safe_account_key(argv: Sequence[str]) -> str:
    """Raw input passes through a trust boundary before reaching a producer."""

    return build_account_key(validate_username(read_raw_username(argv)))


@trusted(level="ASSURED")
def unsafe_account_key(argv: Sequence[str]) -> str:
    """Intentional integration fixture: raw input reaches a trusted producer."""

    return read_raw_username(argv)
