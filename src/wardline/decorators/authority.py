"""Group 1 decorators — Authority Tier Flow.

These decorators mark functions with taint state transitions and
tier source annotations for the wardline scanner.
"""

from __future__ import annotations

from wardline.core.taints import TaintState
from wardline.decorators._base import wardline_decorator

__all__ = [
    "integral_writer",
    "integral_construction",
    "external_boundary",
    "integral_read",
    "validates_external",
    "validates_semantic",
    "validates_shape",
]

external_boundary = wardline_decorator(
    1,
    "external_boundary",
    _wardline_tier_source=TaintState.EXTERNAL_RAW,
)
"""Mark an entry point receiving untrusted external data (Tier 4 → EXTERNAL_RAW). Enforced by SCN-021."""

validates_shape = wardline_decorator(
    1,
    "validates_shape",
    _wardline_transition=(TaintState.EXTERNAL_RAW, TaintState.GUARDED),
)
"""Mark a structural validation boundary (EXTERNAL_RAW → GUARDED). Enforced by PY-WL-008, SCN-021."""

validates_semantic = wardline_decorator(
    1,
    "validates_semantic",
    _wardline_transition=(TaintState.GUARDED, TaintState.ASSURED),
)
"""Mark a semantic validation boundary (GUARDED → ASSURED). Enforced by PY-WL-009, SCN-021."""

validates_external = wardline_decorator(
    1,
    "validates_external",
    _wardline_transition=(TaintState.EXTERNAL_RAW, TaintState.ASSURED),
)
"""Mark a combined shape+semantic validation boundary (EXTERNAL_RAW → ASSURED). Enforced by SCN-021."""

integral_read = wardline_decorator(
    1,
    "integral_read",
    _wardline_tier_source=TaintState.INTEGRAL,
)
"""Mark a function that reads from an integral data source (Tier 1). Enforced by SCN-021."""

integral_writer = wardline_decorator(
    1,
    "integral_writer",
    _wardline_tier_source=TaintState.INTEGRAL,
    _wardline_integral_writer=True,
)
"""Mark a function that writes to an integral data store (Tier 1, audit-critical). Enforced by PY-WL-006, SCN-021."""

integral_construction = wardline_decorator(
    1,
    "integral_construction",
    _wardline_transition=(TaintState.ASSURED, TaintState.INTEGRAL),
)
"""Mark a function that constructs integral data from assured inputs (ASSURED → INTEGRAL). Enforced by SCN-021."""
