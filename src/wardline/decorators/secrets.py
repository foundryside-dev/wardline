"""Group 8 decorators — Secrets handling."""

from __future__ import annotations

from wardline.decorators._base import wardline_decorator

__all__ = [
    "handles_secrets",
]

handles_secrets = wardline_decorator(
    8,
    "handles_secrets",
    _wardline_handles_secrets=True,
)
"""Mark a function that handles secret material (keys, tokens, credentials). Enforced by SUP-001, SCN-021."""
