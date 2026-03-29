"""Group 14 decorators — Access and attribution."""

from __future__ import annotations

from wardline.decorators._base import wardline_decorator

__all__ = [
    "requires_identity",
    "privileged_operation",
]

requires_identity = wardline_decorator(
    14,
    "requires_identity",
    _wardline_requires_identity=True,
)
"""Assert a function requires a verified caller identity before execution. Enforced by SUP-001, SCN-021."""

privileged_operation = wardline_decorator(
    14,
    "privileged_operation",
    _wardline_privileged_operation=True,
)
"""Mark a function that performs a privileged operation requiring elevated access. Enforced by SUP-001, SCN-021."""
