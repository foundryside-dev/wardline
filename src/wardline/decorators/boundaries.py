"""Groups 6 and 16 decorators — Trust Boundaries and Data Flow.

Group 6 decorators mark functions at trust boundary crossings.
Group 16 decorators annotate data flow characteristics (tier consumed
and tier produced) for documentation and advisory analysis.
"""

from __future__ import annotations

from typing import Any

from wardline.decorators._base import wardline_decorator

__all__ = [
    "data_flow",
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


def data_flow(*, consumes: int, produces: int) -> Any:
    """Annotate data flow: tier consumed as input and tier produced as output.

    Advisory decorator — no enforcement at L1.  At L2+, conflict with
    ``@external_boundary`` is detectable when ``produces != 4`` (spec
    entry #25).

    Args:
        consumes: Input tier (1=INTEGRAL … 4=EXTERNAL_RAW).
        produces: Output tier (1=INTEGRAL … 4=EXTERNAL_RAW).
    """
    return wardline_decorator(
        16,
        "data_flow",
        _wardline_data_flow=True,
        _wardline_consumes=consumes,
        _wardline_produces=produces,
    )
