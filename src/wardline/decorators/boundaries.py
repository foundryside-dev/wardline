"""Group 6 decorators — Trust Boundaries.

These decorators mark functions at trust boundary crossings
for the wardline scanner.
"""

from __future__ import annotations

from wardline.decorators._base import wardline_decorator

__all__ = [
    "tier_transition",
    "trust_boundary",
]

trust_boundary = wardline_decorator(
    6,
    "trust_boundary",
    _wardline_trust_boundary=True,
)
"""Mark a function at a trust boundary crossing. Enforced by SCN-021."""

tier_transition = wardline_decorator(
    6,
    "tier_transition",
    _wardline_tier_transition=True,
)
"""Mark a function that transitions data between tiers. Enforced by SCN-021."""
